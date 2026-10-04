"""Stage one of a ``--package`` run: each working database spooled to disk.

A package carries every event of the run, so each working database is copied
out as soon as ingestion has filled it, before the rules widen ``logs`` with
all-NULL columns, and the rules' hits are recorded as they arrive. This runs
wherever the database lives, process workers included, so it needs only the
standard library and orjson: duckdb is loaded by stage two
(``zircolite.package``), in the main process only.
"""

import contextlib
import math
import sqlite3
import string
import zlib
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO

import orjson

from .utils import parse_timestamp

RESERVED_PREFIX = "_zl_"
# Stage two reads several spool files at once, so a part is cut into pieces.
ROWS_PER_SPOOL_FILE = 100_000
FETCH_ROWS = 2_000
# The viewer names an event part * 2**32 + row_id, which has to stay below
# 2**53 to be an exact JavaScript number.
UID_PART_SHIFT = 32
ROW_ID_LIMIT = 1 << UID_PART_SHIFT
PART_LIMIT = 1 << 21

TYPE_BITS: dict[type, int] = {int: 1, float: 2, str: 4, bytes: 8}
TIMESTAMP_SCALES = {"unix": 1_000_000, "unix_ms": 1_000, "unix_us": 1}

_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MICROSECOND = timedelta(microseconds=1)
_FIRST_US = (datetime(1, 1, 1, tzinfo=timezone.utc) - _EPOCH) // _MICROSECOND
_LAST_US = (datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc) - _EPOCH) // _MICROSECOND


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
    """What a rule and its results are matched on, as ``collapse_results_by_rule`` does."""
    return str(rule.get("id") or rule.get("title") or "Unnamed Rule")


def rule_index(rulesets: list[dict[str, Any]]) -> dict[str, int]:
    """Each rule's position in the run's ruleset; the first rule wins a shared key."""
    index: dict[str, int] = {}
    for position, rule in enumerate(rulesets):
        index.setdefault(rule_key(rule), position)
    return index


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
    """A match's row_id; ``--csv`` hands rows to sinks with every value as text."""
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if type(value) is int and 0 <= value < ROW_ID_LIMIT:
        return value
    return None


def _json_value(value: Any) -> Any:
    """A list or object that ``--csv`` may already have turned into its JSON text."""
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
    rule_keys: dict[str, int] = field(default_factory=dict)
    # Parallel workers are handed a path, not a position; this restores it.
    part_of: dict[str, int] = field(default_factory=dict)

    def open_part(self, part: int, sources: list[str]) -> "PartWriter":
        return PartWriter(self, part, sources)


class _SpoolFiles:
    """Gzip-compressed NDJSON, cut every ROWS_PER_SPOOL_FILE rows."""

    def __init__(self, prefix: Path) -> None:
        self.prefix = prefix
        self.paths: list[str] = []
        self.longest = 0
        self._handle: BinaryIO | None = None
        self._compressor: Any = None
        self._rows = 0

    def add(self, line: bytes) -> None:
        handle = self._handle
        if handle is None or self._rows == ROWS_PER_SPOOL_FILE:
            handle = self._rotate()
        handle.write(self._compressor.compress(line + b"\n"))
        self._rows += 1
        self.longest = max(self.longest, len(line))

    def _rotate(self) -> BinaryIO:
        self.close()
        path = Path(f"{self.prefix}-{len(self.paths):04d}.ndjson.gz")
        self.paths.append(str(path))
        handle = open(path, "wb")  # noqa: SIM115 -- closed by close()
        self._handle = handle
        # Level 1: the spool is read once, minutes later, and level 1 already
        # brings EVTX-derived JSON down to about 7% of its size.
        self._compressor = zlib.compressobj(1, zlib.DEFLATED, 31)
        self._rows = 0
        return handle

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.write(self._compressor.flush())
            finally:
                self._handle.close()
                self._handle = None

    def abandon(self) -> None:
        """Close after a failure without raising, so the original error is the one reported."""
        handle, self._handle = self._handle, None
        if handle is not None:
            with contextlib.suppress(OSError):
                handle.close()


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def _row_spellings(connection: sqlite3.Connection) -> Generator[tuple[int, str], None, None]:
    """``(row_id, names)`` for each row spelled unlike its column, in row_id order."""
    tables = {name for (name,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' "
        "AND name IN ('field_spellings', 'logs_spelling')")}
    if len(tables) < 2:
        return
    cursor = connection.execute(
        "SELECT s.row_id, f.names FROM logs_spelling AS s "
        "JOIN field_spellings AS f ON f.id = s.spelling ORDER BY s.row_id")
    try:
        yield from cursor
    finally:
        cursor.close()


class PartWriter:
    """Spools one working database: its events now, its hits as rules report them."""

    def __init__(self, spool: PackageSpool, part: int, sources: list[str]) -> None:
        if not 0 <= part < PART_LIMIT:
            raise PackageError(f"part {part} is outside 0..{PART_LIMIT - 1}")
        self.spool = spool
        self.record = PartRecord(part=part, sources=list(sources))
        self._prefix = Path(spool.directory) / f"part-{part:07d}"
        self._hits: BinaryIO | None = None
        self._alerts: BinaryIO | None = None
        self._alert_seq = 0
        self._error: str | None = None

    def export_events(self, connection: sqlite3.Connection) -> None:
        """Copy every row of ``logs`` to the spool, with what stage two needs to type it.

        Whatever fails, ``record.event_files`` lists the files written so far,
        so a discard can remove them.
        """
        spool = _SpoolFiles(self._prefix)
        try:
            self._copy_events(connection, spool)
            spool.close()
        except (sqlite3.Error, OSError) as exc:
            spool.abandon()
            raise PackageError(f"cannot spool the events of part {self.record.part}: {exc}") from exc
        except BaseException:
            spool.abandon()
            raise
        finally:
            self.record.event_files = spool.paths
            self.record.longest_line = spool.longest

    def sink(self, result: dict[str, Any]) -> None:
        """Record which events ``result`` matched: a result sink for ``execute_ruleset``.

        It never raises. An exception here would stop the rule loop and lose
        the detections output with it, so ``finish`` reports the first failure.
        """
        if self._error is not None:
            return
        try:
            self._record_result(result)
        except (PackageError, OSError, ValueError, TypeError) as exc:
            self._error = str(exc)

    def finish(self) -> PartRecord:
        self._close()
        if self._error is not None:
            raise PackageError(self._error)
        return self.record

    def discard(self) -> None:
        self._close()
        for path in [*self.record.event_files, self.record.hits_file, self.record.alerts_file]:
            if path:
                Path(path).unlink(missing_ok=True)

    def _close(self) -> None:
        for handle in (self._hits, self._alerts):
            if handle is not None:
                handle.close()
        self._hits = self._alerts = None

    def _record_result(self, result: dict[str, Any]) -> None:
        key = rule_key(result)
        rule_idx = self.spool.rule_keys.get(key)
        if rule_idx is None:
            raise PackageError(f"a result names rule {key!r}, which the run did not load")
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

    def _copy_events(self, connection: sqlite3.Connection, spool: "_SpoolFiles") -> None:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(logs)")]
        if not columns or columns[0] != "row_id":
            raise PackageError("the working database has no logs table keyed by row_id")
        names = columns[1:]
        keys = [ascii_lower(name) for name in names]
        for name, key in zip(names, keys, strict=True):
            if key.startswith(RESERVED_PREFIX):
                raise PackageError(
                    f"field {name!r} starts with {RESERVED_PREFIX!r}, which packages reserve "
                    "for their own columns; rename it in the field mappings")
        # Positions in a fetched row, where row_id is column 0.
        time_key = ascii_lower(self.spool.time_field)
        time_at = keys.index(time_key) + 1 if time_key in keys else None
        channel_at = keys.index("channel") + 1 if "channel" in keys else None
        eventid_at = keys.index("eventid") + 1 if "eventid" in keys else None
        masks = [0] * len(keys)
        counts = [0] * len(keys)
        families: dict[tuple[str | None, str | None], set[int]] = {}
        time_stats: dict[str, Any] = {
            "column": names[time_at - 1] if time_at else None,
            "min": None, "max": None, "unparsed": 0, "missing": 0,
        }
        part = self.record.part
        timestamp_format = self.spool.timestamp_format
        spelled = _row_spellings(connection)
        cursor = connection.cursor()
        row_id: Any = None
        try:
            pending = next(spelled, None)
            cursor.execute("SELECT * FROM logs ORDER BY row_id")
            while True:
                try:
                    rows = cursor.fetchmany(FETCH_ROWS)
                except sqlite3.Error as exc:
                    raise _unreadable_row(connection, row_id, exc) from exc
                if not rows:
                    break
                for row in rows:
                    row_id = row[0]
                    if type(row_id) is not int or not 0 <= row_id < ROW_ID_LIMIT:
                        raise PackageError(
                            f"row_id {row_id!r} is outside 0..{ROW_ID_LIMIT - 1}, "
                            "so the viewer cannot address that event")
                    record: dict[str, Any] = {"_zl_part": part, "_zl_rid": row_id}
                    present: list[int] = []
                    for index in range(1, len(row)):
                        value = row[index]
                        if value is None:
                            continue
                        kind = type(value)
                        masks[index - 1] |= TYPE_BITS[kind]
                        counts[index - 1] += 1
                        record[keys[index - 1]] = value.hex() if kind is bytes else value
                        present.append(index - 1)
                    record["_zl_time"] = _event_time(row, time_at, timestamp_format, time_stats)
                    while pending is not None and pending[0] < row_id:
                        pending = next(spelled, None)
                    if pending is not None and pending[0] == row_id:
                        record["_zl_spelling"] = pending[1]
                    family = (_text(row[channel_at]) if channel_at else None,
                              _text(row[eventid_at]) if eventid_at else None)
                    families.setdefault(family, set()).update(present)
                    try:
                        spool.add(orjson.dumps(record))
                    except orjson.JSONEncodeError as exc:
                        raise PackageError(f"event row {row_id} cannot be written: {exc}") from exc
                    self.record.events += 1
        finally:
            cursor.close()
            spelled.close()
        self.record.columns = [
            {"name": names[i], "key": keys[i], "mask": masks[i], "count": counts[i]}
            for i in range(len(keys)) if counts[i]
        ]
        self.record.families = [
            {"channel": channel, "eventid": eventid, "keys": sorted(keys[i] for i in indexes)}
            for (channel, eventid), indexes in families.items()
        ]
        self.record.time = time_stats


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
