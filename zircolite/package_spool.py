"""Stage one of a ``--package`` run: each working database spooled to disk.

A package carries every event of the run, so each working database is copied
out as soon as ingestion has filled it, before the rules widen ``logs`` with
all-NULL columns, and the rules' hits are recorded as they arrive. This runs
wherever the database lives, process workers included, so it needs only the
standard library and orjson: duckdb is loaded by stage two
(``zircolite.package``), in the main process only. A large part in a database
file is copied by processes of its own, each over a range of row_id.
"""

import contextlib
import glob
import math
import multiprocessing
import os
import shutil
import signal
import sqlite3
import string
import sys
import zlib
from collections.abc import Callable, Generator, Iterable, Iterator
from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from operator import itemgetter
from pathlib import Path
from typing import Any, BinaryIO

import orjson

try:
    from compression import zstd as _zstd
except ImportError:  # Python before 3.14
    _zstd = None

from .fulltext import FIELD as FULLTEXT_FIELD
from .utils import parse_timestamp

RESERVED_PREFIX = "_zl_"
# Stage two reads several spool files at once, so a part is cut into pieces.
ROWS_PER_SPOOL_FILE = 100_000
SPOOL_FILE_BYTES = 64 << 20
# Lines are compressed and written in blocks: a compressor call per line costs
# more than the compression itself.
SPOOL_WRITE_BYTES = 1 << 20
# Leave room for events/index Parquet, their wrapped ZIP, and scratch files.
SPOOL_DISK_RESERVE = 6 << 30
# Rows read per batch; each batch selects the columns the one before filled.
FETCH_ROWS = 2_000
# A large part is copied by processes, each over a range of row_id with its own
# read-only connection: building the values of every fetched row in the sqlite3
# module is most of the time, and no single process can avoid it. Starting a
# process costs about half a second, and copying a row 15 to 20 µs.
PARALLEL_MIN_ROWS = 200_000
PARALLEL_MAX_WORKERS = 8
# Inside a container, the CPU quota of its cgroup ("max 100000" when unlimited).
CGROUP_CPU_MAX = Path("/sys/fs/cgroup/cpu.max")
# Rows differ in cost, so each process takes several ranges, one at a time.
RANGES_PER_WORKER = 4
# What a pass remembers of the columns rows fill: guessed patterns, and the
# type combinations seen with each one (see _copy_rows).
GUESS_LIMIT = 4_096
KINDS_LIMIT = 64
# The viewer names an event part * 2**32 + row_id, which has to stay below
# 2**53 to be an exact JavaScript number.
UID_PART_SHIFT = 32
ROW_ID_LIMIT = 1 << UID_PART_SHIFT
PART_LIMIT = 1 << 21

TYPE_BITS: dict[type, int] = {int: 1, float: 2, str: 4, bytes: 8}
TIMESTAMP_SCALES = {"unix": 1_000_000, "unix_ms": 1_000, "unix_us": 1}

_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MICROSECOND = timedelta(microseconds=1)
_FIRST_US = (datetime(1, 1, 1, tzinfo=UTC) - _EPOCH) // _MICROSECOND
_LAST_US = (datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC) - _EPOCH) // _MICROSECOND


class PackageError(Exception):
    """A package the user asked for cannot be written faithfully."""


def ascii_lower(name: str) -> str:
    """Fold a column name the way SQLite and DuckDB compare them: ASCII letters only."""
    return name.translate(_ASCII_LOWER)


def time_microseconds(value: Any, timestamp_format: str) -> int | None:
    """``value`` as microseconds since the epoch, or None when it is not a time.

    ISO text goes through the parser ``--after`` and ``--before`` use, so the
    timeline places an event where the time filter saw it.
    """
    if timestamp_format == "iso":
        moment = parse_timestamp(value)
        return None if moment is None else (moment - _EPOCH) // _MICROSECOND
    scale = TIMESTAMP_SCALES.get(timestamp_format)
    if scale is None:
        raise PackageError(f"unknown timestamp format {timestamp_format!r}")
    if isinstance(value, str):
        try:
            value = float(value) if "." in value else int(value)
        except ValueError:
            return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    microseconds = round(value * scale)
    return microseconds if _FIRST_US <= microseconds <= _LAST_US else None


def rule_key(rule: dict[str, Any]) -> str:
    """What a rule and its results are matched on: the key ``collapse_results_by_rule`` gives the result.

    A result carries ``title`` with the default ``_rule_result`` applies, so a
    rule without one keys as "Unnamed Rule", and an empty title keys as ''.
    """
    title = rule.get("title", "Unnamed Rule")
    return str(rule.get("id") or title or "")


def rule_title(rule: dict[str, Any]) -> str | None:
    """The title a rule's results carry: ``_rule_result`` copies it with this default."""
    title = rule.get("title", "Unnamed Rule")
    return None if title is None else str(title)


def _variant(level: Any, sigmafile: Any) -> tuple[str, str]:
    return (str(level if level is not None else "unknown"), str(sigmafile or ""))


RuleIndex = dict[str, dict[str | None, dict[tuple[str, str], int]]]


def rule_index(rulesets: list[dict[str, Any]]) -> RuleIndex:
    """Each ruleset entry's position, by rule key, title, then level and Sigma file.

    The merged rulesets ship most Sigma rules twice under one id, as their
    "- Sysmon" and "- Generic" variants, and the title tells those apart.
    Combined rulesets also repeat id and title with another level or file,
    which only the result's ``rule_level`` and ``sigmafile`` tell apart. The
    first entry wins an exact duplicate. Empty entries never run, so they are
    skipped without shifting the positions after them.
    """
    index: RuleIndex = {}
    for position, rule in enumerate(rulesets):
        if not rule:
            continue
        variants = index.setdefault(rule_key(rule), {}).setdefault(rule_title(rule), {})
        variants.setdefault(_variant(rule.get("level", "unknown"), rule.get("filename", "")), position)
    return index


def rule_position(index: RuleIndex, result: dict[str, Any]) -> int | None:
    """The ruleset entry ``result`` came from, falling back to its title, then its key."""
    titles = index.get(rule_key(result))
    if not titles:
        return None
    variants = titles.get(rule_title(result))
    if variants is None:
        variants = next(iter(titles.values()))
    position = variants.get(_variant(result.get("rule_level", "unknown"), result.get("sigmafile", "")))
    return next(iter(variants.values())) if position is None else position


def _integer(value: Any) -> int:
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float) and math.isfinite(value):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return 0


def _float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _row_id(value: Any) -> int | None:
    """A match's row_id, given as an int or as its decimal text."""
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if type(value) is int and 0 <= value < ROW_ID_LIMIT:
        return value
    return None


def _json_value(value: Any) -> Any:
    """A list or object, given as itself or as its JSON text."""
    return orjson.loads(value) if isinstance(value, str) else value


def _json_text(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return orjson.dumps(value).decode()


@dataclass
class PartRecord:
    """What stage two needs to know about one spooled part.

    Plain data only: a process worker returns it to the main process.
    """

    part: int
    sources: list[str]
    # Sources the reader could read only in part or not at all: their events
    # here are what survived, so the part is no complete copy of them.
    unreadable: list[str] = field(default_factory=list)
    events: int = 0
    event_files: list[str] = field(default_factory=list)
    longest_line: int = 0
    columns: list[dict[str, Any]] = field(default_factory=list)
    families: list[dict[str, Any]] = field(default_factory=list)
    time: dict[str, Any] = field(default_factory=dict)
    hits_file: str | None = None
    alerts_file: str | None = None
    rules: dict[int, dict[str, int]] = field(default_factory=dict)


@dataclass
class PackageSpool:
    """Where a run's parts are spooled, and what every part has to agree on.

    It reaches process workers inside the ProcessingContext payload, so it
    holds plain data only.
    """

    directory: str
    time_field: str
    timestamp_format: str = "iso"
    rule_keys: RuleIndex = field(default_factory=dict)
    # Parallel workers are handed a path, not a position; this restores it.
    part_of: dict[str, int] = field(default_factory=dict)
    concurrent_writers: int = 1
    # At most this many processes copy one part: 1 under --no-parallel, the
    # --parallel-workers value when given, otherwise up to PARALLEL_MAX_WORKERS.
    max_processes: int | None = None

    def open_part(self, part: int, sources: list[str], *, unreadable: Iterable[str] = ()) -> "PartWriter":
        return PartWriter(self, part, sources, unreadable)


class _SpoolFiles:
    """Bounded NDJSON chunks.

    With zstd (Python 3.14 and later) every chunk is compressed: a 64 MiB
    chunk shrinks about thirty times in a few hundredths of a second, and
    duckdb reads it back as fast as plain text. Without it a chunk stays plain
    unless the destination is short of space, and is then gzipped.
    """

    def __init__(self, prefix: Path, concurrent_writers: int = 1) -> None:
        self.prefix = prefix
        self.concurrent_writers = max(1, concurrent_writers)
        self.paths: list[str] = []
        self.longest = 0
        self._handle: BinaryIO | None = None
        self._compressor: Any = None
        self._buffer = bytearray()
        self._rows = 0
        self._bytes = 0

    def add(self, line: bytes) -> None:
        size = len(line) + 1
        if self._handle is None or self._rows == ROWS_PER_SPOOL_FILE or self._bytes + size > SPOOL_FILE_BYTES:
            self._rotate(size)
        buffer = self._buffer
        buffer += line
        buffer += b"\n"
        if len(buffer) >= SPOOL_WRITE_BYTES:
            self._write_buffer()
        self._rows += 1
        self._bytes += size
        self.longest = max(self.longest, len(line))

    def _write_buffer(self) -> None:
        if self._handle is not None and self._buffer:
            block = self._buffer
            self._handle.write(self._compressor.compress(block) if self._compressor is not None else block)
            block.clear()

    def _rotate(self, next_size: int) -> None:
        self.close()
        if _zstd is not None:
            suffix, compressor = ".ndjson.zst", _zstd.ZstdCompressor(level=1)
        else:
            allowance = max(SPOOL_FILE_BYTES, next_size) * self.concurrent_writers
            try:
                compressed = shutil.disk_usage(self.prefix.parent).free < SPOOL_DISK_RESERVE + allowance
            except OSError:
                compressed = True
            suffix, compressor = (".ndjson.gz", zlib.compressobj(1, zlib.DEFLATED, 31)) if compressed else (".ndjson", None)
        path = Path(f"{self.prefix}-{len(self.paths):04d}{suffix}")
        self.paths.append(str(path))
        self._handle = open(path, "wb")  # noqa: SIM115 -- closed by close()
        self._compressor = compressor
        self._rows = 0
        self._bytes = 0

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._write_buffer()
                if self._compressor is not None:
                    self._handle.write(self._compressor.flush())
            finally:
                handle, self._handle = self._handle, None
                handle.close()

    def abandon(self) -> None:
        """Close after a failure without raising, so the original error is the one reported."""
        self._buffer.clear()
        handle, self._handle = self._handle, None
        if handle is not None:
            with contextlib.suppress(OSError):
                handle.close()


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def _row_spellings(connection: sqlite3.Connection,
                   bounds: tuple[int, int] | None = None) -> Generator[tuple[int, str], None, None]:
    """``(row_id, names)`` for each row spelled unlike its column, in row_id order.

    ``bounds`` limits them to ``low <= row_id < high``.
    """
    tables = {name for (name,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' "
        "AND name IN ('field_spellings', 'logs_spelling')")}
    if len(tables) < 2:
        return
    if bounds is None:
        cursor = connection.execute(
            "SELECT s.row_id, f.names FROM logs_spelling AS s "
            "JOIN field_spellings AS f ON f.id = s.spelling ORDER BY s.row_id")
    else:
        cursor = connection.execute(
            "SELECT s.row_id, f.names FROM logs_spelling AS s "
            "JOIN field_spellings AS f ON f.id = s.spelling "
            "WHERE s.row_id >= ? AND s.row_id < ? ORDER BY s.row_id", bounds)
    try:
        yield from cursor
    finally:
        cursor.close()


class PartWriter:
    """Spools one working database: its events now, its hits as rules report them."""

    def __init__(self, spool: PackageSpool, part: int, sources: list[str], unreadable: Iterable[str] = ()) -> None:
        if not 0 <= part < PART_LIMIT:
            raise PackageError(f"part {part} is outside 0..{PART_LIMIT - 1}")
        self.spool = spool
        self.record = PartRecord(part=part, sources=list(sources), unreadable=list(unreadable))
        self._prefix = Path(spool.directory) / f"part-{part:07d}"
        self._hits: BinaryIO | None = None
        self._alerts: BinaryIO | None = None
        self._alert_seq = 0
        self._error: str | None = None

    def export_events(self, connection: sqlite3.Connection,
                      progress: Callable[[int, int], None] | None = None) -> None:
        """Copy every row of ``logs`` to the spool, with what stage two needs to type it.

        Whatever fails, ``record.event_files`` lists the files written so far,
        so a discard can remove them. ``progress`` gets the last row_id copied
        and the highest one, batch by batch; in a parallel copy, range by range.
        """
        try:
            layout = _layout(connection, self.spool.time_field)
            plan = self._parallel_plan(connection)
            census = self._copy_parallel(plan, layout, progress) if plan is not None else None
            if census is None:
                census = self._copy_serial(connection, layout, progress)
        except (sqlite3.Error, OSError) as exc:
            raise PackageError(f"cannot spool the events of part {self.record.part}: {exc}") from exc
        keys = layout.keys
        self.record.columns = [
            {"name": layout.names[i], "key": keys[i], "mask": census.masks[i], "count": census.counts[i]}
            for i in range(len(keys)) if census.counts[i]
        ]
        self.record.families = [
            {"channel": channel, "eventid": eventid, "keys": sorted(keys[i] for i in indexes)}
            for (channel, eventid), indexes in census.families.items()
        ]
        self.record.time = census.time

    def _copy_serial(self, connection: sqlite3.Connection, layout: "_Layout",
                     progress: Callable[[int, int], None] | None) -> "_Census":
        spool = _SpoolFiles(self._prefix, self.spool.concurrent_writers)
        census = _Census.start(layout)
        try:
            _copy_rows(connection, layout, spool, self.record.part, self.spool.timestamp_format, census,
                       progress=progress)
            spool.close()
        except BaseException:
            spool.abandon()
            raise
        finally:
            self.record.event_files = spool.paths
            self.record.longest_line = spool.longest
            self.record.events = census.events
        return census

    def _parallel_plan(self, connection: sqlite3.Connection) -> "_Plan | None":
        """How to split this part over processes, or None to copy it in this one.

        Other processes can read only a committed database file, and only this
        process starts them: a part spooled inside a worker, or beside other
        writers, stays in one. Anything a fresh read-only connection would see
        differently also keeps the copy here, and so does any doubt about the
        rows: the serial copy then refuses them as it always has.
        """
        if self.spool.concurrent_writers != 1 or multiprocessing.parent_process() is not None:
            return None
        workers = min(PARALLEL_MAX_WORKERS, _usable_cpus())
        if self.spool.max_processes is not None:
            workers = min(workers, self.spool.max_processes)
        if workers < 2 or connection.in_transaction:
            return None
        try:
            path = next((file for _, name, file in connection.execute("PRAGMA database_list")
                         if name == "main"), "")
            if not path or not _rowid_keyed(connection):
                return None
            first, last, rows = connection.execute(
                "SELECT min(row_id), max(row_id), count(*) FROM logs").fetchone()
        except sqlite3.Error:
            return None
        if rows < PARALLEL_MIN_ROWS or type(first) is not int or type(last) is not int:
            return None
        if first < 0 or last >= ROW_ID_LIMIT:
            return None
        try:
            uri = Path(path).as_uri() + "?mode=ro"
        except ValueError:
            return None
        if not _same_rows_apart(uri, connection, (first, last, rows)):
            return None
        return _Plan(uri=uri, workers=workers, rows=rows, first=first, last=last,
                     ranges=_ranges(first, last, workers * RANGES_PER_WORKER))

    def _copy_parallel(self, plan: "_Plan", layout: "_Layout",
                       progress: Callable[[int, int], None] | None) -> "_Census | None":
        """Copy the part's ranges in parallel, or return None if the processes cannot run.

        Each range is spooled to files of its own, listed in range order, so
        stage two reads the rows in row_id order as from a serial copy. When
        ranges fail, the first one's error is raised: the error a serial copy
        would have met first.
        """
        settings = _worker_settings()
        tasks = [
            _RangeTask(uri=plan.uri, prefix=f"{self._prefix}-r{index:03d}",
                       writers=self.spool.concurrent_writers * plan.workers, part=self.record.part,
                       timestamp_format=self.spool.timestamp_format, layout=layout, low=low, high=high,
                       settings=settings)
            for index, (low, high) in enumerate(plan.ranges)
        ]
        results: list[_RangeResult | None] = [None] * len(tasks)
        errors: dict[int, BaseException] = {}
        broken = False
        try:
            pool = ProcessPoolExecutor(max_workers=plan.workers, mp_context=multiprocessing.get_context("spawn"),
                                       initializer=_ignore_sigint)
        except (OSError, NotImplementedError):
            # Without named semaphores (no /dev/shm, for one) no process can
            # start; nothing has been written yet.
            return None
        try:
            futures: dict[Future, int] = {}
            try:
                with _sigint_held():
                    for index, task in enumerate(tasks):
                        futures[pool.submit(_export_range, task)] = index
            except (OSError, RuntimeError, BrokenProcessPool):
                broken = True
            covered = 0
            for future in [] if broken else as_completed(futures):
                index = futures[future]
                if future.cancelled():
                    continue
                try:
                    result = future.result()
                except BrokenProcessPool:
                    broken = True
                    break
                except Exception as exc:
                    errors[index] = exc
                else:
                    results[index] = result
                    if result.error is not None:
                        errors[index] = _range_error(self.record.part, result.error)
                    elif progress is not None:
                        covered += tasks[index].high - tasks[index].low
                        progress(min(plan.last, plan.first - 1 + covered), plan.last)
                if errors:
                    # A later range cannot change which error is reported.
                    first_failed = min(errors)
                    for other, position in futures.items():
                        if position > first_failed:
                            other.cancel()
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
            self.record.event_files = [path for index, task in enumerate(tasks)
                                       for path in _range_files(task, results[index])]
            self.record.longest_line = max((result.longest for result in results if result), default=0)
        if broken:
            # Processes could not start or died: copy here instead, from scratch.
            for path in self.record.event_files:
                Path(path).unlink(missing_ok=True)
            self.record.event_files = []
            self.record.longest_line = 0
            return None
        if errors:
            raise errors[min(errors)]
        census = _Census.start(layout)
        for result in results:
            if result is None or result.census is None:
                raise PackageError(f"a range of part {self.record.part} returned no events")
            census.merge(result.census)
        self.record.events = census.events
        if census.events != plan.rows:
            raise PackageError(f"part {self.record.part} has {plan.rows:,} events, "
                               f"but its ranges held {census.events:,}")
        return census

    def sink(self, result: dict[str, Any]) -> None:
        """Record which events ``result`` matched: a result sink for ``execute_ruleset``.

        A write or data failure is kept rather than raised: an exception here
        would stop the rule loop and lose the detections output with it. After
        the first one nothing more is recorded, and ``finish`` raises it.
        """
        if self._error is not None:
            return
        try:
            self._record_result(result)
        except (PackageError, OSError, ValueError, TypeError) as exc:
            self._error = str(exc)

    def finish(self) -> PartRecord:
        close_error = self._close()
        if self._error is not None:
            raise PackageError(self._error) from close_error
        if close_error is not None:
            raise PackageError(f"cannot write the hits of part {self.record.part}: {close_error}") from close_error
        return self.record

    def discard(self) -> None:
        self._close()
        for path in [*self.record.event_files, self.record.hits_file, self.record.alerts_file]:
            if path:
                Path(path).unlink(missing_ok=True)

    def _close(self) -> OSError | None:
        """Close both files whatever happens; a buffered write fails here when the disk is full."""
        first: OSError | None = None
        for handle in (self._hits, self._alerts):
            if handle is not None:
                try:
                    handle.close()
                except OSError as exc:
                    first = first or exc
        self._hits = self._alerts = None
        return first

    def _record_result(self, result: dict[str, Any]) -> None:
        rule_idx = rule_position(self.spool.rule_keys, result)
        if rule_idx is None:
            raise PackageError(f"a result names rule {rule_key(result)!r}, which the run did not load")
        counts = self.record.rules.setdefault(
            rule_idx, {"count": 0, "linked": 0, "unlinked": 0, "alert_count": 0, "event_count": 0})
        counts["count"] += _integer(result.get("count"))
        if result.get("result_type") == "correlation":
            counts["alert_count"] += _integer(result.get("alert_count"))
            counts["event_count"] += _integer(result.get("event_count"))
            for alert in result.get("matches") or ():
                self._add_alert(rule_idx, alert)
            return
        for match in result.get("matches") or ():
            row_id = _row_id(match.get("row_id"))
            if row_id is None:
                counts["unlinked"] += 1
            else:
                self._add_hit(rule_idx, row_id)
                counts["linked"] += 1

    def _add_hit(self, rule_idx: int, row_id: int) -> None:
        if self._hits is None:
            path = f"{self._prefix}.hits.csv"
            self._hits = open(path, "wb")  # noqa: SIM115 -- closed by finish() or discard()
            self.record.hits_file = path
        self._hits.write(f"{rule_idx},{self.record.part},{row_id}\n".encode())

    def _add_alert(self, rule_idx: int, alert: dict[str, Any]) -> None:
        tables = {item.get("event_id"): item.get("source_table")
                  for item in _json_value(alert.get("evidence")) or () if isinstance(item, dict)}
        row_ids: list[int] = []
        for identity in _json_value(alert.get("event_ids")) or ():
            table = tables.get(identity)
            if table != "logs":
                raise PackageError(
                    f"correlation alert {alert.get('alert_id')!r} cites event {identity!r} "
                    f"from {table!r}; a package links events from logs only")
            row_id = _row_id(str(identity).partition(":")[2])
            if row_id is None:
                raise PackageError(
                    f"correlation alert {alert.get('alert_id')!r} cites an unreadable event id {identity!r}")
            row_ids.append(row_id)
            self._add_hit(rule_idx, row_id)
        line = {
            "rule_idx": rule_idx,
            "part": self.record.part,
            "seq": self._alert_seq,
            "alert_id": _text(alert.get("alert_id")),
            "group_keys": _json_text(alert.get("group_keys")),
            "occurrence_us": time_microseconds(alert.get("occurrence_time"), "unix"),
            "window_start_us": time_microseconds(alert.get("window_start"), "unix"),
            "window_end_us": time_microseconds(alert.get("window_end"), "unix"),
            "metric_name": _text(alert.get("metric_name")),
            "metric_value": _float(alert.get("metric_value")),
            "event_count": _integer(alert.get("event_count")),
            "child_alert_ids": _json_text(alert.get("child_alert_ids")),
            "rids": row_ids,
        }
        self._alert_seq += 1
        if self._alerts is None:
            path = f"{self._prefix}.alerts.ndjson"
            self._alerts = open(path, "wb")  # noqa: SIM115 -- closed by finish() or discard()
            self.record.alerts_file = path
        self._alerts.write(orjson.dumps(line) + b"\n")


@dataclass
class _Layout:
    """Where one part's columns sit in a fetched row, where row_id is column 0.

    Plain data only: a parallel copy hands it to every process.
    """

    projection: str
    names: list[str]
    keys: list[str]
    time_key: str
    time_at: int | None
    channel_at: int | None
    eventid_at: int | None


def _layout(connection: sqlite3.Connection, time_field: str) -> _Layout:
    columns = [row[1] for row in connection.execute("PRAGMA table_info(logs)")]
    if not columns or columns[0] != "row_id":
        raise PackageError("the working database has no logs table keyed by row_id")
    # Keyword search text is private to the rules that need it.
    private = [name for name in columns if ascii_lower(name) == FULLTEXT_FIELD]
    if private:
        columns = [name for name in columns if name not in private]
    projection = ", ".join(_quoted(name) for name in columns) if private else "*"
    names = columns[1:]
    keys = [ascii_lower(name) for name in names]
    for name, key in zip(names, keys, strict=True):
        if key.startswith(RESERVED_PREFIX):
            raise PackageError(
                f"field {name!r} starts with {RESERVED_PREFIX!r}, which packages reserve "
                "for their own columns; rename it in the field mappings")
    time_key = ascii_lower(time_field)
    return _Layout(
        projection=projection, names=names, keys=keys, time_key=time_key,
        time_at=keys.index(time_key) + 1 if time_key in keys else None,
        channel_at=keys.index("channel") + 1 if "channel" in keys else None,
        eventid_at=keys.index("eventid") + 1 if "eventid" in keys else None,
    )


@dataclass
class _Census:
    """What copying some rows learnt: each column's types and count, the families, the time range.

    Censuses of consecutive ranges merge, in row_id order, into the census of
    their union: families keep the order in which a serial copy meets them.
    """

    masks: list[int]
    counts: list[int]
    families: dict[tuple[str | None, str | None], set[int]]
    time: dict[str, Any]
    events: int = 0

    @classmethod
    def start(cls, layout: _Layout) -> "_Census":
        width = len(layout.keys)
        return cls(masks=[0] * width, counts=[0] * width, families={}, time={
            "column": layout.names[layout.time_at - 1] if layout.time_at else None,
            "min": None, "max": None, "unparsed": 0, "missing": 0,
        })

    def merge(self, later: "_Census") -> None:
        """Add the census of rows that all come after these."""
        self.masks = [a | b for a, b in zip(self.masks, later.masks, strict=True)]
        self.counts = [a + b for a, b in zip(self.counts, later.counts, strict=True)]
        for family, indexes in later.families.items():
            self.families.setdefault(family, set()).update(indexes)
        for bound, better in (("min", min), ("max", max)):
            values = [value for value in (self.time[bound], later.time[bound]) if value is not None]
            self.time[bound] = better(values) if values else None
        self.time["unparsed"] += later.time["unparsed"]
        self.time["missing"] += later.time["missing"]
        self.events += later.events


class _Guess:
    """The columns a family's rows with a given number of NULLs were last seen to fill."""

    __slots__ = ("get", "indexes", "keys", "kinds", "rows", "window")

    def __init__(self, indexes: tuple[int, ...], positions: tuple[int, ...], keys: list[str]) -> None:
        # Columns as layout indexes, and where a row read through the view holds them.
        self.indexes = indexes
        self.keys = [keys[i] for i in indexes]
        self.get = _getter(positions)
        self.rows = 0
        # Each combination of value types seen, and whether it holds bytes.
        self.kinds: dict[tuple[type, ...], bool] = {}
        # The last batch whose columns this guess was added to.
        self.window = -1

    def retire(self, counts: list[int]) -> None:
        for index in self.indexes:
            counts[index] += self.rows
        self.rows = 0


def _getter(positions: tuple[int, ...]) -> Callable[[tuple[Any, ...]], tuple[Any, ...]]:
    """The values at ``positions`` of a row, always as a tuple."""
    if len(positions) >= 2:
        return itemgetter(*positions)
    if positions:
        (only,) = positions
        return lambda row: (row[only],)
    return lambda row: ()


def _quoted(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _any_value(names: list[str]) -> str:
    """SQL that is 1 when any of the columns holds a value, in nested groups SQLite accepts."""
    terms = [_quoted(name) for name in names]
    while len(terms) > 1:
        terms = [f"coalesce({', '.join(group)})" if len(group) > 1 else group[0]
                 for group in (terms[i:i + 100] for i in range(0, len(terms), 100))]
    return f"({terms[0]} IS NOT NULL)"


class _View:
    """The columns one statement selects from ``logs``, and the guesses for rows read through it.

    A narrow view selects some columns and ends each row with a flag, set when
    a column it leaves out holds a value; such a row is read again in full.
    """

    __slots__ = ("channel_at", "eventid_at", "flagged", "guesses", "indexes", "statement", "time_at")

    def __init__(self, layout: _Layout, indexes: tuple[int, ...] | None = None) -> None:
        width = len(layout.keys)
        self.flagged = indexes is not None
        self.indexes = tuple(range(width)) if indexes is None else indexes
        at = {index: position for position, index in enumerate(self.indexes, 1)}
        self.channel_at = at.get(layout.channel_at - 1) if layout.channel_at else None
        self.eventid_at = at.get(layout.eventid_at - 1) if layout.eventid_at else None
        self.time_at = at.get(layout.time_at - 1) if layout.time_at else None
        if indexes is None:
            select = layout.projection
        else:
            kept = set(indexes)
            select = ", ".join(["row_id", *(_quoted(layout.names[i]) for i in indexes),
                                _any_value([name for i, name in enumerate(layout.names) if i not in kept])])
        self.statement = (f"SELECT {select} FROM logs WHERE row_id >= ? AND row_id <= ? "  # noqa: S608 -- quoted column names
                          "ORDER BY row_id LIMIT ?")
        self.guesses: dict[tuple[str | None, str | None, int], _Guess] = {}

    def retire(self, counts: list[int]) -> None:
        for guess in self.guesses.values():
            guess.retire(counts)
        self.guesses.clear()


def _copy_rows(connection: sqlite3.Connection, layout: _Layout, spool: _SpoolFiles, part: int,
               timestamp_format: str, census: _Census, *, bounds: tuple[int, int] | None = None,
               progress: Callable[[int, int], None] | None = None) -> None:
    """Spool every row of ``logs`` in row_id order, or those with ``low <= row_id < high``.

    Building every column of every row is most of the cost, and a row holds
    a few dozen values among hundreds of columns. So when row_id is the rowid,
    rows are read in batches, each selecting the columns the batch before
    filled, plus a flag for a row that has a value elsewhere, read again in
    full; a batch with many such rows makes the next one read every column.

    Nor is a row walked column by column. Its family and NULL count pick the
    columns the last such row filled; when those all hold a value, they are
    exactly the row's values, since no other column can. Otherwise the row is
    walked once and becomes the guess. Types are recorded once per
    combination, and counts once per guess, which gives the census a full
    walk would.
    """
    keys = layout.keys
    masks, counts, families, time_stats = census.masks, census.counts, census.families, census.time
    spellings: dict[str, str | None] = {}
    add = spool.add
    dumps = orjson.dumps
    events = 0
    whole = _View(layout)
    view = whole
    # Batches by row_id need it to be the rowid: every row an integer, once.
    windowed = bounds is not None or _rowid_keyed(connection)
    low, high = (bounds[0], bounds[1] - 1) if bounds is not None else (-(1 << 63), (1 << 63) - 1)
    full_row = f"SELECT {layout.projection} FROM logs WHERE row_id = ?"  # noqa: S608 -- quoted column names
    spelled = _row_spellings(connection, bounds)
    cursor = connection.cursor()
    # The last row read, which names where an unreadable batch starts.
    row_id: Any = None if bounds is None else bounds[0] - 1
    window = 0
    try:
        pending = next(spelled, None)
        last = connection.execute("SELECT max(row_id) FROM logs").fetchone()[0] if progress else None
        if not windowed:
            cursor.execute(f"SELECT {layout.projection} FROM logs ORDER BY row_id")  # noqa: S608 -- quoted column names
        while True:
            try:
                rows = (cursor.execute(view.statement, (low, high, FETCH_ROWS)).fetchall() if windowed
                        else cursor.fetchmany(FETCH_ROWS))
            except sqlite3.Error as exc:
                raise _unreadable_row(connection, row_id, exc) from exc
            if not rows:
                break
            if progress is not None and type(last) is int and type(rows[-1][0]) is int:
                progress(rows[-1][0], last)
            window += 1
            filled: set[int] = set()
            reread = 0
            flagged = view.flagged
            for row in rows:
                if type(row[0]) is not int or not 0 <= row[0] < ROW_ID_LIMIT:
                    raise PackageError(
                        f"row_id {row[0]!r} is outside 0..{ROW_ID_LIMIT - 1}, "
                        "so the viewer cannot address that event")
                through = view
                if flagged and row[-1]:
                    reread += 1
                    try:
                        row = connection.execute(full_row, (row[0],)).fetchone()
                    except sqlite3.Error as exc:
                        raise _unreadable_row(connection, row_id, exc) from exc
                    through = whole
                row_id = row[0]
                # The family as the manifest prints it: values that compare
                # equal, such as 1 and 1.0, are still two families.
                channel = row[through.channel_at] if through.channel_at else None
                if channel is not None and type(channel) is not str:
                    channel = str(channel)
                eventid = row[through.eventid_at] if through.eventid_at else None
                if eventid is not None and type(eventid) is not str:
                    eventid = str(eventid)
                key = (channel, eventid, row.count(None))
                guesses = through.guesses
                guess = guesses.get(key)
                if guess is None or None in (values := guess.get(row)):
                    if guess is not None:
                        guess.retire(counts)
                    elif len(guesses) >= GUESS_LIMIT:
                        through.retire(counts)
                    positions = tuple(at for at in range(1, len(through.indexes) + 1) if row[at] is not None)
                    guess = _Guess(tuple(through.indexes[at - 1] for at in positions), positions, keys)
                    guesses[key] = guess
                    families.setdefault((channel, eventid), set()).update(guess.indexes)
                    values = guess.get(row)
                if guess.window != window:
                    guess.window = window
                    filled.update(guess.indexes)
                guess.rows += 1
                kinds = tuple(map(type, values))
                has_bytes = guess.kinds.get(kinds)
                if has_bytes is None:
                    for index, kind in zip(guess.indexes, kinds, strict=True):
                        masks[index] |= TYPE_BITS[kind]
                    if len(guess.kinds) >= KINDS_LIMIT:
                        guess.kinds.clear()
                    has_bytes = guess.kinds[kinds] = bytes in kinds
                record: dict[str, Any] = {"_zl_part": part, "_zl_rid": row_id}
                if has_bytes:
                    record.update(zip(guess.keys, [value.hex() if type(value) is bytes else value
                                                   for value in values], strict=True))
                else:
                    record.update(zip(guess.keys, values, strict=True))
                record["_zl_time"] = _event_time(row, through.time_at, timestamp_format, time_stats)
                while pending is not None and pending[0] < row_id:
                    pending = next(spelled, None)
                if pending is not None and pending[0] == row_id:
                    spelling = _spelling_without(pending[1], layout.time_key, spellings, row_id)
                    if spelling is not None:
                        record["_zl_spelling"] = spelling
                try:
                    add(dumps(record))
                except orjson.JSONEncodeError as exc:
                    raise PackageError(f"event row {row_id} cannot be written: {exc}") from exc
                events += 1
            if windowed:
                low = row_id + 1
                indexes = tuple(sorted(filled))
                # Many rows read twice cost more than reading every column.
                wanted = None if reread * 4 > len(rows) or len(indexes) == len(keys) else indexes
                if wanted != (None if view is whole else view.indexes):
                    if view is not whole:
                        view.retire(counts)
                    view = whole if wanted is None else _View(layout, wanted)
    finally:
        census.events += events
        cursor.close()
        spelled.close()
    whole.retire(counts)
    view.retire(counts)


@dataclass
class _Plan:
    uri: str
    workers: int
    rows: int
    first: int
    last: int
    ranges: list[tuple[int, int]]


@dataclass
class _RangeTask:
    """One range of a part for a process to spool: plain data, sent to it."""

    uri: str
    prefix: str
    writers: int
    part: int
    timestamp_format: str
    layout: _Layout
    low: int
    high: int
    settings: dict[str, Any]


@dataclass
class _RangeResult:
    paths: list[str]
    longest: int
    census: _Census | None
    # A failure as (message, whether it is a database or file error that the
    # part wraps), since the exception itself may not survive pickling.
    error: tuple[str, bool] | None = None


def _range_error(part: int, error: tuple[str, bool]) -> PackageError:
    """The error a serial copy raises for what failed in a range."""
    message, wrapped = error
    return PackageError(f"cannot spool the events of part {part}: {message}" if wrapped else message)


# Module settings a process copies from its parent, so that both spool alike.
_SETTINGS = ("ROWS_PER_SPOOL_FILE", "SPOOL_FILE_BYTES", "SPOOL_WRITE_BYTES", "SPOOL_DISK_RESERVE",
             "FETCH_ROWS", "GUESS_LIMIT", "KINDS_LIMIT")


def _worker_settings() -> dict[str, Any]:
    settings = {name: globals()[name] for name in _SETTINGS}
    settings["zstd"] = _zstd is not None
    return settings


def _export_range(task: _RangeTask) -> _RangeResult:
    """Spool one range of a part, in a process of a parallel copy."""
    global _zstd
    settings = dict(task.settings)
    if not settings.pop("zstd"):
        _zstd = None
    globals().update(settings)
    spool = _SpoolFiles(Path(task.prefix), task.writers)
    census = _Census.start(task.layout)
    error: tuple[str, bool] | None = None
    try:
        connection = sqlite3.connect(task.uri, uri=True)
        try:
            _copy_rows(connection, task.layout, spool, task.part, task.timestamp_format, census,
                       bounds=(task.low, task.high))
        finally:
            connection.close()
        spool.close()
    except PackageError as exc:
        spool.abandon()
        error = (str(exc), False)
    except (sqlite3.Error, OSError) as exc:
        spool.abandon()
        error = (str(exc), True)
    except BaseException:
        spool.abandon()
        raise
    return _RangeResult(paths=spool.paths, longest=spool.longest,
                        census=None if error else census, error=error)


def _range_files(task: _RangeTask, result: _RangeResult | None) -> list[str]:
    """The files a range wrote: those it reported, then any that a failure left unreported."""
    reported = list(result.paths) if result is not None else []
    prefix = Path(task.prefix)
    known = set(reported)
    try:
        found = sorted(str(path) for path in prefix.parent.glob(glob.escape(prefix.name) + "-*"))
    except OSError:
        found = []
    return reported + [path for path in found if path not in known]


def _usable_cpus() -> int:
    counter = getattr(os, "process_cpu_count", None)  # Python 3.13 and later
    if counter is not None:
        cpus = counter() or 1
    elif hasattr(os, "sched_getaffinity"):
        cpus = len(os.sched_getaffinity(0))
    else:
        cpus = os.cpu_count() or 1
    quota = _cgroup_cpus()
    return min(cpus, quota) if quota is not None else cpus


def _cgroup_cpus() -> int | None:
    """The whole CPUs a cgroup v2 quota allows (``docker run --cpus``), or None without one.

    Neither the CPU count nor the affinity mask reflects the quota, and
    processes beyond it only wait for their turn while holding memory.
    """
    try:
        quota, period = CGROUP_CPU_MAX.read_text().split()
        return max(1, math.ceil(int(quota) / int(period)))
    except (OSError, ValueError, ZeroDivisionError):
        return None


def _rowid_keyed(connection: sqlite3.Connection) -> bool:
    """True when main.logs is the table read and row_id is its rowid.

    Then ranges of row_id hold every row exactly once: a rowid is an integer,
    never NULL.
    """
    shadowed = connection.execute(
        "SELECT count(*) FROM sqlite_temp_master WHERE name = 'logs' COLLATE NOCASE").fetchone()[0]
    if shadowed:
        return False
    keyed = [row for row in connection.execute("PRAGMA main.table_info(logs)") if row[5]]
    if len(keyed) != 1 or keyed[0][1] != "row_id" or keyed[0][2].upper() != "INTEGER":
        return False
    # A WITHOUT ROWID table, or INTEGER PRIMARY KEY DESC, keeps a separate key index.
    return not any(row[3] == "pk" for row in connection.execute("PRAGMA main.index_list(logs)"))


def _same_rows_apart(uri: str, connection: sqlite3.Connection, expected: tuple[int, int, int]) -> bool:
    """True when a fresh read-only connection sees the rows and columns this one does."""
    try:
        probe = sqlite3.connect(uri, uri=True, timeout=1.0)
    except sqlite3.Error:
        return False
    try:
        seen = probe.execute("SELECT min(row_id), max(row_id), count(*) FROM logs").fetchone()
        return (tuple(seen) == expected and probe.execute("PRAGMA table_info(logs)").fetchall()
                == connection.execute("PRAGMA table_info(logs)").fetchall())
    except sqlite3.Error:
        return False
    finally:
        probe.close()


def _ranges(first: int, last: int, count: int) -> list[tuple[int, int]]:
    """``[low, high)`` ranges of near-equal width that together cover ``first..last``."""
    span = last - first + 1
    bounds = [first + span * index // count for index in range(count + 1)]
    return [(low, high) for low, high in pairwise(bounds) if low < high]


def _ignore_sigint() -> None:
    """A process of a parallel copy leaves Ctrl+C to the main one, which stops the copy."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if sys.platform != "win32":
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})


@contextlib.contextmanager
def _sigint_held() -> Iterator[None]:
    """Hold SIGINT while processes start, until they ignore it (as ``parallel.py`` does)."""
    if sys.platform == "win32":
        yield
        return
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _spelling_without(text: str, time_key: str, cache: dict[str, str | None], row_id: int) -> str | None:
    """A row's recorded spellings minus the time field's, or None when no other is left.

    The time column always prints under its --timefield name, as in
    detected_events.json, so a row's own spelling of it must not reach the viewer.
    """
    if text not in cache:
        try:
            names = orjson.loads(text)
            kept = [name for name in names if ascii_lower(name) != time_key]
        except (orjson.JSONDecodeError, TypeError, AttributeError) as exc:
            raise PackageError(f"event row {row_id} has an unreadable spelling record {text!r}") from exc
        cache[text] = text if len(kept) == len(names) else orjson.dumps(kept).decode() if kept else None
    return cache[text]


def _unreadable_row(connection: sqlite3.Connection, last_good: Any, exc: sqlite3.Error) -> PackageError:
    """Name the row a failed batch fetch choked on.

    A batch fails as a whole, so the last row read says little; reading the
    following rows one by one finds the real culprit.
    """
    start = last_good if type(last_good) is int else -1
    try:
        ids = [row_id for (row_id,) in connection.execute(
            "SELECT row_id FROM logs WHERE row_id > ? ORDER BY row_id LIMIT ?", (start, FETCH_ROWS))]
        for row_id in ids:
            try:
                connection.execute("SELECT * FROM logs WHERE row_id = ?", (row_id,)).fetchall()
            except sqlite3.Error as single:
                return PackageError(f"event row {row_id} cannot be read: {single}")
    except sqlite3.Error:
        pass
    return PackageError(f"cannot read the events after row {last_good!r}: {exc}")


def _event_time(row: tuple[Any, ...], at: int | None, timestamp_format: str,
                stats: dict[str, Any]) -> int | None:
    value = row[at] if at else None
    if value is None:
        stats["missing"] += 1
        return None
    moment = time_microseconds(value, timestamp_format)
    if moment is None:
        stats["unparsed"] += 1
        return None
    if stats["min"] is None or moment < stats["min"]:
        stats["min"] = moment
    if stats["max"] is None or moment > stats["max"]:
        stats["max"] = moment
    return moment
