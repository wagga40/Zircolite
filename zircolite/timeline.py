"""``--timeline``: one row per detection, in time order, alike in every database layout.

Rows are rendered where the event is. Each working database's results pass
through a :class:`TimelinePart` sink in the process that owns the database (a
worker, in parallel runs), which makes one line per match: a fixed-width sort
key, the source file and the finished row.
Each part sorts its lines as plain bytes, in runs of a bounded size; the main
process merges every run, drops duplicates and copies the rows into the CSV or
JSONL file (:func:`build_timeline`). Only finished rows cross process
boundaries, and the order comes from the key alone, never from the layout or the
worker that produced a row.

The key is ``<unparsed flag><instant><ruleset position><identity kind><identity>``.
Times sort first and unparseable ones last; the ruleset position orders the
rules matching one instant; the identity tells events apart and finds the copies
of one event.
"""

import hashlib
import heapq
import os
import re
import sys
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import ExitStack, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO

import orjson

from .attack import extract_attack_tactics, extract_attack_techniques
from .package_spool import RuleIndex, rule_position, time_microseconds
from .utils import sanitize_value_for_csv

TIMELINE_FORMATS = {".csv": "csv", ".jsonl": "jsonl", ".ndjson": "jsonl"}
DEFAULT_TIMELINE = "timeline.csv"

COLUMNS = (
    "Timestamp", "Computer", "Channel", "EventID", "RecordID", "Level", "RuleTitle", "RuleID",
    "Tactics", "Techniques", "Details", "ExtraFields", "AllFields", "SourceFile",
)
# Read from the event, through the field names the configuration lists for them.
ALIASED_COLUMNS = ("Computer", "Channel", "EventID", "RecordID")
SEPARATOR = " ¦ "

# What one part holds in memory before writing a sorted run: per worker, so small
PART_BUDGET = 16 * 1024 * 1024
MERGE_FAN_IN = 64

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_FIRST_US = (datetime(1, 1, 1, tzinfo=UTC) - _EPOCH) // timedelta(microseconds=1)
_NO_POSITION = 0xFFFFFFFF
_KEY_LENGTH = 1 + 16 + 8 + 1 + 32
_KIND_AT = 1 + 16 + 8
_RECORD, _CONTENT = "r", "c"
_FIELD_COLUMN = re.compile(r"%([^%]+)%")
# The primary key of a working database: it differs between layouts.
_INTERNAL = "row_id"
# Whole events and row IDs: what an alert is about, not what tells it apart.
_ALERT_BULK = frozenset({"evidence", "event_ids", "child_alert_ids"})
# Shown by Details itself, or by the Timestamp column.
_ALERT_SHOWN = frozenset({"result_type", "group_keys", "occurrence_time", "event_count",
                          "metric_name", "metric_value"})


class TimelineError(Exception):
    """A timeline the user asked for cannot be written faithfully."""


class TimelineConfigError(ValueError):
    """The timeline configuration cannot be used; the message names the key."""


@dataclass(frozen=True)
class Presentation:
    """What ``config/timeline.yaml`` says about columns, profiles and Details."""

    aliases: dict[str, tuple[str, ...]]
    profiles: dict[str, tuple[str, ...]]
    skip: frozenset[str]


def load_presentation(path: str | Path) -> Presentation:
    import yaml

    try:
        with open(path, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise TimelineConfigError(f"{path}: {exc}") from exc
    return parse_presentation(raw, str(path))


def parse_presentation(raw: Any, source: str) -> Presentation:
    """Validate a timeline configuration, naming the first key that is wrong."""

    def fail(key: str, problem: str) -> TimelineConfigError:
        return TimelineConfigError(f"{source}: {key} {problem}")

    def mapping(value: Any, key: str, known: Iterable[str] | None = None) -> dict:
        if not isinstance(value, dict):
            raise fail(key, "must be a mapping")
        if known is not None:
            for name in value:
                if name not in known:
                    raise fail(f"{key}.{name}" if key else str(name), "is not a timeline setting")
        return value

    def names(value: Any, key: str) -> tuple[str, ...]:
        if not isinstance(value, list) or not value:
            raise fail(key, "must be a non-empty list")
        for index, item in enumerate(value):
            if not isinstance(item, str) or not item.strip():
                raise fail(f"{key}[{index}]", "must be a field name")
        return tuple(value)

    document = mapping(raw, "", ("columns", "profiles", "details"))
    for section in ("columns", "profiles", "details"):
        if section not in document:
            raise fail(section, "is missing")

    columns = mapping(document["columns"], "columns", ALIASED_COLUMNS)
    aliases = {}
    for column in ALIASED_COLUMNS:
        if column not in columns:
            raise fail(f"columns.{column}", "is missing")
        aliases[column] = names(columns[column], f"columns.{column}")

    profiles: dict[str, tuple[str, ...]] = {}
    for name, entries in mapping(document["profiles"], "profiles").items():
        key = f"profiles.{name}"
        listed = names(entries, key)
        seen: set[str] = set()
        for index, entry in enumerate(listed):
            match = _FIELD_COLUMN.fullmatch(entry)
            if match is None and entry not in COLUMNS:
                raise fail(f"{key}[{index}]", f"is neither a column ({', '.join(COLUMNS)}) nor a %Field%")
            header = match.group(1) if match else entry
            if header.lower() in seen:
                raise fail(f"{key}[{index}]", f"repeats the column {header}")
            seen.add(header.lower())
        profiles[str(name)] = listed
    if not profiles:
        raise fail("profiles", "must name at least one profile")

    details = mapping(document["details"], "details", ("skip",))
    skip = names(details.get("skip"), "details.skip") if "skip" in details else ()
    return Presentation(aliases=aliases, profiles=profiles, skip=frozenset(name.lower() for name in skip))


def timeline_format(destination: str) -> str | None:
    """``csv`` or ``jsonl`` for a destination, ``-`` being JSONL on stdout; None when unknown."""
    if destination == "-":
        return "jsonl"
    return TIMELINE_FORMATS.get(Path(destination).suffix.lower())


def format_instant(microseconds: int) -> str:
    """ISO 8601 with microseconds and an explicit offset."""
    return (_EPOCH + timedelta(microseconds=microseconds)).isoformat(timespec="microseconds")


def _timestamp_text(raw: Any, instant: int | None) -> str | None:
    """The Timestamp column: the instant in ISO 8601, or the value as it is when it is not a time.

    Windows writes UTC as ``2017-06-09T19:21:26.968669Z`` (or with a seventh
    digit), which already reads as the formatted instant once it has parsed:
    cutting it costs a tenth of formatting it again.
    """
    if instant is None:
        return None if raw is None else str(raw)
    if raw.__class__ is str and len(raw) in (27, 28) and raw[-1] == "Z" and raw[10] == "T" and raw[19] == ".":
        return raw[:26] + "+00:00"
    return format_instant(instant)


def _text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return orjson.dumps(value, option=orjson.OPT_SORT_KEYS).decode()
    return str(value)


# What SQLite hands back for an event field; anything else is written as JSON
_SCALARS = (str, int, float)


def _joined(pairs: Iterable[tuple[str, Any]]) -> str | None:
    text = SEPARATOR.join(f"{name}: {_text(value)}" for name, value in pairs if value is not None)
    return text or None


def _lookup(row: dict[str, Any], names: Iterable[str]) -> Any:
    """The value of the first of ``names`` the row carries, ignoring case: logs columns do."""
    folded = {key.lower(): key for key in row}
    for name in names:
        key = folded.get(name.lower())
        if key is not None and row[key] is not None:
            return row[key]
    return None


def _identity(kind: str, text: str) -> str:
    return kind + hashlib.blake2b(text.encode("utf-8", "surrogatepass"), digest_size=16).hexdigest()


def _csv_cell(value: Any) -> str:
    """One CSV field, defused and quoted.

    Quoted as the csv module's QUOTE_MINIMAL would, by hand: defusing has
    already turned line breaks into spaces, which leaves only the comma and
    the quote, and two scans in C cost a third of a csv.writer call per row.
    """
    if value is None:
        return "-"
    if isinstance(value, list):
        value = SEPARATOR.join(_text(item) for item in value)
    elif isinstance(value, dict):
        value = _joined(value.items()) or ""
    text = sanitize_value_for_csv(value)
    if '"' in text:
        return '"' + text.replace('"', '""') + '"'
    return f'"{text}"' if "," in text else text


def csv_header(headers: list[str]) -> bytes:
    return (",".join(_csv_cell(header) for header in headers) + "\r\n").encode("utf-8")


@dataclass
class TimelinePartRecord:
    """One finished part, as a worker returns it: plain data only."""

    runs: list[str]
    rows: int


@dataclass
class TimelineSpool:
    """Where a run's timeline parts are spooled, and how every part renders a row.

    It reaches process workers inside the ProcessingContext payload, so it
    holds plain data only.
    """

    directory: str
    columns: tuple[str, ...]
    presentation: Presentation
    fmt: str = "csv"
    time_field: str = "SystemTime"
    timestamp_format: str = "iso"
    rule_keys: RuleIndex = field(default_factory=dict)

    def open_part(self) -> "TimelinePart":
        return TimelinePart(self)

    @property
    def headers(self) -> list[str]:
        return [match.group(1) if (match := _FIELD_COLUMN.fullmatch(column)) else column
                for column in self.columns]


class _Plan:
    """Where a row with one set of field names finds each column: worked out once per set."""

    __slots__ = ("aliases", "all", "content", "details", "fields", "record", "time")

    time: str | None
    aliases: dict[str, str | None]
    fields: dict[str, str | None]
    details: tuple[str, ...]
    all: tuple[str, ...]
    content: tuple[tuple[str, str], ...]
    record: bool


class _Renderer:
    """Turns one rule result into finished timeline lines.

    Rows of one rule, or of one event type, carry the same field names, so
    what depends on the names alone is planned once per set of names.
    """

    PLANS = 4096

    def __init__(self, spool: TimelineSpool) -> None:
        self.spool = spool
        self.columns = spool.columns
        self.headers = spool.headers
        self.aliases = spool.presentation.aliases
        self.skip = spool.presentation.skip
        self.fields = {column: match.group(1) for column in spool.columns
                       if (match := _FIELD_COLUMN.fullmatch(column))}
        self.wants_details = "Details" in spool.columns or "ExtraFields" in spool.columns
        self.wants_all = "AllFields" in spool.columns
        self.csv = spool.fmt == "csv"
        self.end = b"\r\n" if self.csv else b"\n"
        self._plans: dict[tuple[str, ...], _Plan] = {}

    def lines(self, result: dict[str, Any]) -> Iterator[bytes]:
        position = rule_position(self.spool.rule_keys, result)
        tags = result.get("tags") or []
        rule = {
            "Level": result.get("rule_level", "unknown"),
            "RuleTitle": result.get("title"),
            "RuleID": result.get("id") or None,
            "Tactics": extract_attack_tactics(tags),
            "Techniques": extract_attack_techniques(tags),
        }
        position = _NO_POSITION if position is None else position
        if self.csv:
            # Alike on every row of the result, so written for CSV once
            rule = {column: _csv_cell(value) for column, value in rule.items()}
        alert = result.get("result_type") == "correlation"
        for row in result.get("matches") or ():
            yield self._alert(row, rule, position) if alert else self._event(row, rule, position)

    def _plan(self, names: tuple[str, ...]) -> _Plan:
        plan = self._plans.get(names)
        if plan is not None:
            return plan
        folded: dict[str, str] = {}
        for name in names:
            folded.setdefault(name.lower(), name)

        def find(candidates: Iterable[str]) -> str | None:
            return next((folded[c.lower()] for c in candidates if c.lower() in folded), None)

        plan = _Plan()
        plan.time = find((self.spool.time_field,))
        plan.aliases = {column: find(self.aliases[column]) for column in ALIASED_COLUMNS}
        plan.fields = {column: find((name,)) for column, name in self.fields.items()}
        shown = {_INTERNAL}
        shown.update(name.lower() for column, name in plan.aliases.items() if name and column in self.columns)
        shown.update(name.lower() for name in (plan.time, *plan.fields.values()) if name)
        if "SourceFile" in self.columns:
            shown.add("originallogfile")
        # Column order follows each database's first sighting of a field, so a
        # unified run and a per-file run list the same event's fields differently.
        ordered = sorted(names, key=str.lower)
        plan.details = tuple(name for name in ordered if name.lower() not in shown and name.lower() not in self.skip)
        plan.all = tuple(name for name in ordered if name != _INTERNAL)
        plan.content = tuple((name.lower(), name) for name in ordered
                             if name != _INTERNAL and name.lower() != "originallogfile")
        plan.record = all(plan.aliases[column] for column in ("Computer", "Channel", "RecordID"))
        if len(self._plans) < self.PLANS:
            self._plans[names] = plan
        return plan

    def _event(self, row: dict[str, Any], rule: dict[str, Any], position: int) -> bytes:
        plan = self._plan(tuple(row))
        get = row.get
        raw_time = get(plan.time) if plan.time else None
        instant = None if raw_time is None else time_microseconds(raw_time, self.spool.timestamp_format)
        values = {column: get(name) if name else None for column, name in plan.aliases.items()}
        for column, name in plan.fields.items():
            values[column] = get(name) if name else None
        if self.wants_details:
            details = [f"{name}: {value}" if value.__class__ in _SCALARS else f"{name}: {_text(value)}"
                       for name in plan.details if (value := row[name]) is not None]
            values["Details"] = SEPARATOR.join(details) or None
            values["ExtraFields"] = None
        if self.wants_all:
            values["AllFields"] = {name: row[name] for name in plan.all}
        source = values["SourceFile"] = get("OriginalLogfile")

        computer, channel, record = values["Computer"], values["Channel"], values["RecordID"]
        if plan.record and computer is not None and channel is not None and record is not None:
            identity = _identity(_RECORD, f"{computer}\x1f{channel}\x1f{record}")
        else:
            identity = _identity(_CONTENT, "\x1e".join([
                f"{folded}\x1f{value}" if (value := row[name]).__class__ in _SCALARS else f"{folded}\x1f{_text(value)}"
                for folded, name in plan.content]))
        return self._line(values, rule, instant, raw_time, position, identity, source)

    def _alert(self, row: dict[str, Any], rule: dict[str, Any], position: int) -> bytes:
        occurrence = row.get("occurrence_time")
        instant = None
        if isinstance(occurrence, (int, float)) and not isinstance(occurrence, bool):
            instant = time_microseconds(occurrence, "unix")
        raw_time = row.get(self.spool.time_field, occurrence)
        group_keys = row.get("group_keys")
        group: dict[str, Any] = group_keys if isinstance(group_keys, dict) else {}
        values: dict[str, Any] = {column: _lookup(group, self.aliases[column]) for column in ALIASED_COLUMNS}
        for column, name in self.fields.items():
            found = _lookup(group, (name,))
            values[column] = found if found is not None else _lookup(row, (name,))
        if self.wants_details:
            details = [("Events", row.get("event_count")), *sorted(group.items(), key=lambda item: item[0].lower())]
            if row.get("metric_name"):
                details.append((str(row["metric_name"]), row.get("metric_value")))
            values["Details"] = _joined(details)
            values["ExtraFields"] = _joined(
                (name, value) for name, value in sorted(row.items(), key=lambda item: item[0].lower())
                if name not in _ALERT_SHOWN and name not in _ALERT_BULK and name != self.spool.time_field)
        if self.wants_all:
            values["AllFields"] = {name: row[name] for name in sorted(row, key=str.lower) if name != _INTERNAL}
        values["SourceFile"] = None
        identity = _identity(_CONTENT, "\x1e".join(
            f"{name.lower()}\x1f{_text(row[name])}" for name in sorted(row, key=str.lower)
            if name not in _ALERT_BULK and name != _INTERNAL))
        return self._line(values, rule, instant, raw_time, position, identity, None)

    def _line(self, values: dict[str, Any], rule: dict[str, Any], instant: int | None, raw_time: Any,
              position: int, identity: str, source: Any) -> bytes:
        """``<key>\\t<source>\\t<row as it is written><line end>``: the main process only sorts and copies it."""
        values["Timestamp"] = _timestamp_text(raw_time, instant)
        if self.csv:
            payload = ",".join([rule[column] if column in rule else _csv_cell(values.get(column))
                                for column in self.columns]).encode("utf-8")
        else:
            values.update(rule)
            payload = orjson.dumps({header: values.get(column) for header, column in zip(self.headers, self.columns, strict=True)})
        key = (f"0{instant - _FIRST_US:016x}" if instant is not None else "1" + "0" * 16) + f"{position:08x}{identity}"
        return b"".join((key.encode("ascii"), b"\t", orjson.dumps(source or ""), b"\t", payload, self.end))


class _SortedRuns:
    """Lines sorted within a memory budget, each full buffer written out as one sorted run."""

    def __init__(self, directory: str, budget: int | None = None) -> None:
        self.directory = directory
        self.budget = PART_BUDGET if budget is None else budget
        self.paths: list[str] = []
        self._lines: list[bytes] = []
        self._size = 0

    def add(self, line: bytes) -> None:
        self._lines.append(line)
        self._size += len(line)
        if self._size >= self.budget:
            self.flush()

    def flush(self) -> None:
        if self._lines:
            self._lines.sort()
            self.paths.append(_write_run(self.directory, self._lines))
            self._lines = []
            self._size = 0

    def discard(self) -> None:
        self._lines = []
        for path in self.paths:
            Path(path).unlink(missing_ok=True)


def _write_run(directory: str, lines: Iterable[bytes]) -> str:
    fd, path = tempfile.mkstemp(dir=directory, prefix="run-", suffix=".tl")
    with os.fdopen(fd, "wb", buffering=1 << 20) as handle:
        handle.writelines(lines)
    return path


def _merge(runs: list[str]) -> Iterator[bytes]:
    with ExitStack() as stack:
        handles = [stack.enter_context(open(run, "rb")) for run in runs]
        yield from heapq.merge(*handles)


def merge_runs(runs: list[str], directory: str, fan_in: int = MERGE_FAN_IN) -> Iterator[bytes]:
    """Every line of the sorted runs, in order; each run is removed once merged.

    Never more than ``fan_in`` runs are open at once: a per-file run over
    hundreds of files would exceed the descriptors a process may hold, so
    batches are merged into longer runs first.
    """
    runs = list(runs)
    while len(runs) > fan_in:
        batch, runs = runs[:fan_in], runs[fan_in:]
        runs.append(_write_run(directory, _merge(batch)))
        for run in batch:
            Path(run).unlink(missing_ok=True)
    try:
        yield from _merge(runs)
    finally:
        for run in runs:
            Path(run).unlink(missing_ok=True)


class TimelinePart:
    """One working database's timeline rows, sorted as rules report them.

    Sorting here, in runs, spreads the work over the workers and leaves the
    main process a merge.
    """

    def __init__(self, spool: TimelineSpool) -> None:
        self._render = _Renderer(spool)
        self._runs = _SortedRuns(spool.directory)
        self.rows = 0
        self._error: str | None = None

    def sink(self, result: dict[str, Any]) -> None:
        """A result sink for ``execute_ruleset``.

        A failure is kept rather than raised: an exception here would stop the
        rule loop and lose the detections output with it. After the first one
        nothing more is written, and ``finish`` raises it.
        """
        if self._error is not None:
            return
        try:
            for line in self._render.lines(result):
                self._runs.add(line)
                self.rows += 1
        except (OSError, ValueError, TypeError) as exc:
            self._error = str(exc)

    def finish(self) -> TimelinePartRecord:
        if self._error is None:
            try:
                self._runs.flush()
            except OSError as exc:
                self._error = f"cannot write a timeline part: {exc}"
        if self._error is not None:
            self.discard()
            raise TimelineError(self._error)
        return TimelinePartRecord(runs=list(self._runs.paths), rows=self.rows)

    def discard(self) -> None:
        self._runs.discard()


@dataclass
class TimelineStats:
    rows: int = 0
    duplicates: int = 0
    unparsed: int = 0


def _kept(group: list[bytes]) -> list[bytes]:
    """The lines of a duplicate group that stay.

    A Windows record (computer, channel and record ID) exists once, so any
    other copy of it came from a second copy of the log. An event without
    one is only a copy when it comes from another file: identical lines in
    one log are events of their own. Of those, the file holding the most
    keeps its lines, the first in order winning a tie.
    """
    if group[0][_KIND_AT:_KIND_AT + 1] == _RECORD.encode():
        return group[:1]
    by_source: dict[bytes, list[bytes]] = {}
    for line in group:
        by_source.setdefault(line.split(b"\t", 2)[1], []).append(line)
    return max(by_source.values(), key=len)


def build_timeline(spool: TimelineSpool, parts: list[TimelinePartRecord], destination: str, *,
                   keep_duplicates: bool = False) -> TimelineStats:
    """Sort every part's lines, drop the copies and write the timeline.

    The file is written beside the destination and moved over it once
    complete, so a failure leaves neither a partial timeline nor a damaged
    earlier one. ``-`` writes to stdout.
    """
    if timeline_format(destination) != spool.fmt:
        raise TimelineError(f"{destination}: the extension must be one of {', '.join(TIMELINE_FORMATS)}, "
                            f"and the parts were written as {spool.fmt}")
    lines = merge_runs([run for part in parts for run in part.runs], spool.directory)

    stats = TimelineStats()
    header = csv_header(spool.headers) if spool.fmt == "csv" else b""
    if destination == "-":
        _write(sys.stdout.buffer, header, lines, keep_duplicates, stats)
        sys.stdout.buffer.flush()
        return stats

    target = Path(destination)
    # Opened rather than made with mkstemp, so the file gets the umask's
    # permissions like every other output, not mkstemp's owner-only ones.
    temporary = target.resolve().parent / f".{target.name}.{os.urandom(4).hex()}.tmp"
    handle = open(temporary, "xb")  # noqa: SIM115
    try:
        with handle:
            _write(handle, header, lines, keep_duplicates, stats)
        os.replace(temporary, target)
    except BaseException:
        with suppress(OSError):
            temporary.unlink()
        raise
    return stats


def _write(handle: BinaryIO, header: bytes, lines: Iterator[bytes], keep_duplicates: bool, stats: TimelineStats) -> None:
    handle.write(header)
    group: list[bytes] = []
    for line in lines:
        # Lines sharing a key are one event matched by one rule, and its copies
        if group and line[:_KEY_LENGTH] != group[0][:_KEY_LENGTH]:
            _write_group(handle, group, keep_duplicates, stats)
            group = []
        group.append(line)
    if group:
        _write_group(handle, group, keep_duplicates, stats)


def _write_group(handle: BinaryIO, group: list[bytes], keep_duplicates: bool, stats: TimelineStats) -> None:
    kept = group if keep_duplicates or len(group) == 1 else _kept(group)
    stats.duplicates += len(group) - len(kept)
    stats.rows += len(kept)
    if group[0][:1] == b"1":
        stats.unparsed += len(kept)
    handle.writelines(line.split(b"\t", 2)[2] for line in kept)
