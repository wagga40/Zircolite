"""Stage one of a ``--package`` run: each working database spooled to disk.

A package carries every event of the run, so each working database is copied
out as soon as ingestion has filled it, before the rules widen ``logs`` with
all-NULL columns, and the rules' hits are recorded as they arrive. This runs
wherever the database lives, process workers included, so it needs only the
standard library and orjson: duckdb is loaded by stage two
(``zircolite.package``), in the main process only.
"""

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

    def export_events(self, connection: sqlite3.Connection) -> None:
        """Copy every row of ``logs`` to the spool, with what stage two needs to type it."""
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
        spool = _SpoolFiles(self._prefix)
        spelled = _row_spellings(connection)
        pending = next(spelled, None)
        row_id: Any = None
        cursor = connection.execute("SELECT * FROM logs ORDER BY row_id")
        try:
            while rows := cursor.fetchmany(FETCH_ROWS):
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
        except sqlite3.Error as exc:
            raise PackageError(f"cannot read the events after row {row_id!r}: {exc}") from exc
        finally:
            cursor.close()
            spelled.close()
            spool.close()
            self.record.event_files = spool.paths
            self.record.longest_line = spool.longest
        self.record.columns = [
            {"name": names[i], "key": keys[i], "mask": masks[i], "count": counts[i]}
            for i in range(len(keys)) if counts[i]
        ]
        self.record.families = [
            {"channel": channel, "eventid": eventid, "keys": sorted(keys[i] for i in indexes)}
            for (channel, eventid), indexes in families.items()
        ]
        self.record.time = time_stats


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
