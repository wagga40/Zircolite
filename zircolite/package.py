"""Stage two of a ``--package`` run: the spooled parts become a viewer package.

The main process turns every part's spool into Parquet with duckdb, then
writes a zip of the viewer, its query engine and the data. The engine and the
data travel as JavaScript: a page opened from ``file://`` may run the scripts
beside it but may not fetch files, so ``<script src>`` is the one way in that
every browser allows.
"""

import base64
import hashlib
import logging
import os
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import pairwise
from pathlib import Path
from typing import Any

import duckdb
import orjson

from .assets import bundled_asset
from .attack import TACTIC_ORDER, extract_attack_tactics, extract_attack_techniques
from .config import RULE_LEVELS
from .correlations import is_correlation_plan_rule
from .package_spool import (
    UID_PART_SHIFT,
    PackageError,
    PackageSpool,
    PartRecord,
    ascii_lower,
    rule_key,
)
from .utils import random_suffix

PACKAGE_FORMAT = 1
DATA_TABLES = ("events", "rules", "hits", "alerts", "alert_events")
REQUIRED_EXTENSIONS = ("json", "parquet")
# The Parquet writer holds a row group of every column per thread: at 386 EVTX
# columns, 20k rows on one thread stays near 1.6 GB, where 100k rows needs
# 6-7 GB and spills to disk for minutes below that.
ROW_GROUP_SIZE = 20_000
DUCKDB_SETTINGS: dict[str, Any] = {
    "autoinstall_known_extensions": False,
    "autoload_known_extensions": False,
    "memory_limit": "2GB",
    "threads": 1,
    "preserve_insertion_order": True,
}
# The viewer holds the events file in WebAssembly memory, which stops at 4 GB.
EVENTS_PARQUET_LIMIT = 1 << 30
UID_FACTOR = 1 << UID_PART_SHIFT
CHUNK_BYTES = 3 * 1024 * 1024  # a multiple of 3: base64 pads only the last chunk
README_TEXT = """Zircolite package
=================

Extract this archive, then open index.html in a web browser. Opening it from
inside the archive does not work: the page loads the files beside it.

Everything runs on this computer, and the page makes no network requests. The
package holds every event of the run, so share it as you would the logs.
"""

EVENT_SPOOL_COLUMNS = {"_zl_part": "INTEGER", "_zl_rid": "BIGINT", "_zl_time": "BIGINT", "_zl_spelling": "VARCHAR"}
EVENT_COLUMNS = {"_zl_uid": "BIGINT", "_zl_part": "INTEGER", "_zl_time": "TIMESTAMP", "_zl_spelling": "VARCHAR"}
RULE_COLUMNS = {
    "rule_idx": "INTEGER", "key": "VARCHAR", "id": "VARCHAR", "title": "VARCHAR", "level": "VARCHAR",
    "level_rank": "TINYINT", "description": "VARCHAR", "falsepositives": "VARCHAR[]", "tags": "VARCHAR[]",
    "tactics": "VARCHAR[]", "techniques": "VARCHAR[]", "sigmafile": "VARCHAR", "result_type": "VARCHAR",
    "count": "BIGINT", "linked": "BIGINT", "unlinked": "BIGINT", "alert_count": "BIGINT", "event_count": "BIGINT",
}
HIT_SPOOL_COLUMNS = {"rule_idx": "INTEGER", "part": "INTEGER", "rid": "BIGINT"}
HIT_COLUMNS = {"rule_idx": "INTEGER", "_zl_uid": "BIGINT"}
ALERT_SPOOL_COLUMNS = {
    "rule_idx": "INTEGER", "part": "INTEGER", "seq": "BIGINT", "alert_id": "VARCHAR", "group_keys": "VARCHAR",
    "occurrence_us": "BIGINT", "window_start_us": "BIGINT", "window_end_us": "BIGINT", "metric_name": "VARCHAR",
    "metric_value": "DOUBLE", "event_count": "BIGINT", "child_alert_ids": "VARCHAR", "rids": "BIGINT[]",
}
ALERT_COLUMNS = {
    "alert_idx": "INTEGER", "rule_idx": "INTEGER", "_zl_part": "INTEGER", "alert_id": "VARCHAR",
    "group_keys": "VARCHAR", "occurrence_time": "TIMESTAMP", "window_start": "TIMESTAMP",
    "window_end": "TIMESTAMP", "metric_name": "VARCHAR", "metric_value": "DOUBLE", "event_count": "BIGINT",
    "child_alert_ids": "VARCHAR",
}
ALERT_EVENT_COLUMNS = {"alert_idx": "INTEGER", "_zl_uid": "BIGINT", "ord": "INTEGER"}


def sql_string(text: str) -> str:
    """A SQL string literal. DuckDB reads backslashes literally, so only quotes double."""
    return "'" + text.replace("'", "''") + "'"


def sql_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def check_duckdb() -> None:
    """Refuse a duckdb build that would have to download what a package needs.

    Packages are built where logs are analysed, often without a network, and
    an extension downloaded on one machine but not another would make the
    same run succeed or fail by where it ran.
    """
    connection = duckdb.connect(":memory:", config={
        "autoinstall_known_extensions": False, "autoload_known_extensions": False})
    try:
        modes = dict(connection.execute(
            "SELECT extension_name, install_mode FROM duckdb_extensions()").fetchall())
    finally:
        connection.close()
    missing = [name for name in REQUIRED_EXTENSIONS if modes.get(name) != "STATICALLY_LINKED"]
    if missing:
        raise PackageError(
            f"this duckdb build does not include {', '.join(missing)}; packages are built "
            "offline and cannot download it (reinstall duckdb from PyPI)")


@dataclass
class Column:
    key: str
    name: str
    mask: int
    count: int

    @property
    def sql_type(self) -> str:
        # Anything mixed stays text: forcing integer and real values into
        # DOUBLE would round integers above 2**53.
        if self.mask == 1:
            return "BIGINT"
        if self.mask == 2:
            return "DOUBLE"
        return "VARCHAR"


def merge_columns(parts: list[PartRecord], time_field: str) -> list[Column]:
    """Every column of the run, named after the lowest-numbered part that has it.

    DuckDB, like SQLite, folds ASCII case, so one column can carry only one
    name; each part's own spelling travels in the manifest instead. The time
    field always prints under its --timefield name, as in detected_events.json.
    """
    merged: dict[str, Column] = {}
    for record in sorted(parts, key=lambda r: r.part):
        for column in record.columns:
            existing = merged.get(column["key"])
            if existing is None:
                merged[column["key"]] = Column(column["key"], column["name"], column["mask"], column["count"])
            else:
                existing.mask |= column["mask"]
                existing.count += column["count"]
    time_key = ascii_lower(time_field)
    if time_field and time_key in merged:
        merged[time_key].name = time_field
    return list(merged.values())


@dataclass(frozen=True)
class RunInfo:
    zircolite_version: str
    mode: str
    executor: str
    timestamp_format: str
    after: str
    before: str
    limit: int
    rules_loaded: int


@dataclass
class PackageData:
    tables: dict[str, Path]
    manifest: dict[str, Any]


def _struct(spec: dict[str, str]) -> str:
    return "{" + ", ".join(f"{sql_string(name)}: {sql_string(kind)}" for name, kind in spec.items()) + "}"


def _paths(paths: list[str]) -> str:
    return "[" + ", ".join(sql_string(path) for path in paths) + "]"


def _empty(spec: dict[str, str]) -> str:
    """Typed columns and no rows, for a table nothing filled."""
    columns = ", ".join(f"CAST(NULL AS {kind}) AS {sql_identifier(name)}" for name, kind in spec.items())
    return f"SELECT {columns} WHERE false"


def _copy(connection: duckdb.DuckDBPyConnection, query: str, target: Path) -> Path:
    connection.execute(
        f"COPY ({query}) TO {sql_string(str(target))} "
        f"(FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE {ROW_GROUP_SIZE})")
    return target


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def write_events(connection: duckdb.DuckDBPyConnection, work: Path,
                 parts: list[PartRecord], columns: list[Column]) -> Path:
    target = work / "events.parquet"
    files = [path for record in parts for path in record.event_files]
    if not files:
        return _copy(connection, _empty(EVENT_COLUMNS), target)
    spec = {**EVENT_SPOOL_COLUMNS, **{column.key: column.sql_type for column in columns}}
    longest = max(record.longest_line for record in parts)
    projection = ", ".join([
        f"CAST(_zl_part AS BIGINT) * {UID_FACTOR} + _zl_rid AS _zl_uid",
        "_zl_part",
        "make_timestamp(_zl_time) AS _zl_time",
        "_zl_spelling",
        *(f"{sql_identifier(column.key)} AS {sql_identifier(column.name)}" for column in columns),
    ])
    source = (f"read_json({_paths(files)}, format = 'newline_delimited', compression = 'gzip', "
              f"columns = {_struct(spec)}, maximum_object_size = {max(16 << 20, longest + 1)})")
    return _copy(connection, f"SELECT {projection} FROM {source}", target)  # noqa: S608 -- names and paths are quoted by sql_identifier/sql_string


def rule_rows(parts: list[PartRecord], rulesets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per ruleset entry that matched anywhere in the run, its counts summed over parts.

    Variants of one rule are separate entries with their own title and hits;
    ``key`` groups them, as the run summary does.
    """
    totals: dict[int, dict[str, int]] = {}
    for record in parts:
        for rule_idx, counts in record.rules.items():
            total = totals.setdefault(rule_idx, dict.fromkeys(counts, 0))
            for name, value in counts.items():
                total[name] += value
    rows = []
    for rule_idx in sorted(totals):
        rule = rulesets[rule_idx]
        tags = _strings(rule.get("tags"))
        level = str(rule.get("level") or "unknown")
        rows.append({
            "rule_idx": rule_idx,
            "key": rule_key(rule),
            "id": str(rule.get("id") or ""),
            "title": str(rule.get("title") or "Unnamed Rule"),
            "level": level,
            "level_rank": RULE_LEVELS.index(level) if level in RULE_LEVELS else -1,
            "description": str(rule.get("description") or ""),
            "falsepositives": _strings(rule.get("falsepositives")),
            "tags": tags,
            "tactics": extract_attack_tactics(tags),
            "techniques": extract_attack_techniques(tags),
            "sigmafile": str(rule.get("filename") or ""),
            "result_type": "correlation" if is_correlation_plan_rule(rule) else "match",
            **totals[rule_idx],
        })
    return rows


def write_rules(connection: duckdb.DuckDBPyConnection, work: Path, rows: list[dict[str, Any]]) -> Path:
    target = work / "rules.parquet"
    if not rows:
        return _copy(connection, _empty(RULE_COLUMNS), target)
    source = work / "rules.ndjson"
    source.write_bytes(b"".join(orjson.dumps(row) + b"\n" for row in rows))
    names = ", ".join(sql_identifier(name) for name in RULE_COLUMNS)
    query = f"SELECT {names} FROM read_json({sql_string(str(source))}, format = 'newline_delimited', columns = {_struct(RULE_COLUMNS)})"  # noqa: S608 -- names and paths are quoted by sql_identifier/sql_string
    return _copy(connection, query, target)


def write_hits(connection: duckdb.DuckDBPyConnection, work: Path, parts: list[PartRecord]) -> Path:
    target = work / "hits.parquet"
    files = [record.hits_file for record in parts if record.hits_file]
    if not files:
        return _copy(connection, _empty(HIT_COLUMNS), target)
    source = (f"read_csv({_paths(files)}, header = false, delim = ',', auto_detect = false, "
              f"columns = {_struct(HIT_SPOOL_COLUMNS)})")
    # A correlation's evidence and the rule's own match can name one event twice.
    query = f"SELECT DISTINCT rule_idx, CAST(part AS BIGINT) * {UID_FACTOR} + rid AS _zl_uid FROM {source} ORDER BY rule_idx, _zl_uid"  # noqa: S608 -- names and paths are quoted by sql_identifier/sql_string
    return _copy(connection, query, target)


def write_alerts(connection: duckdb.DuckDBPyConnection, work: Path, parts: list[PartRecord]) -> dict[str, Path]:
    alerts, links = work / "alerts.parquet", work / "alert_events.parquet"
    files = [record.alerts_file for record in parts if record.alerts_file]
    if not files:
        return {"alerts": _copy(connection, _empty(ALERT_COLUMNS), alerts),
                "alert_events": _copy(connection, _empty(ALERT_EVENT_COLUMNS), links)}
    spool_query = f"CREATE TEMP TABLE alert_spool AS SELECT CAST(row_number() OVER (ORDER BY part, seq) - 1 AS INTEGER) AS alert_idx, * FROM read_json({_paths(files)}, format = 'newline_delimited', columns = {_struct(ALERT_SPOOL_COLUMNS)})"  # noqa: S608 -- names and paths are quoted by sql_identifier/sql_string
    connection.execute(spool_query)
    _copy(connection, "SELECT alert_idx, rule_idx, part AS _zl_part, alert_id, group_keys, "
                      "make_timestamp(occurrence_us) AS occurrence_time, make_timestamp(window_start_us) AS window_start, "
                      "make_timestamp(window_end_us) AS window_end, metric_name, metric_value, event_count, "
                      "child_alert_ids FROM alert_spool ORDER BY alert_idx", alerts)
    link_query = f"SELECT alert_idx, CAST(part AS BIGINT) * {UID_FACTOR} + rid AS _zl_uid, CAST(ord AS INTEGER) AS ord FROM (SELECT alert_idx, part, unnest(rids) AS rid, generate_subscripts(rids, 1) AS ord FROM alert_spool) ORDER BY alert_idx, ord"  # noqa: S608 -- names and paths are quoted by sql_identifier/sql_string
    _copy(connection, link_query, links)
    return {"alerts": alerts, "alert_events": links}


def _some(names: list[str]) -> str:
    return ", ".join(names[:3]) + (" ..." if len(names) > 3 else "")


def build_manifest(*, parts: list[PartRecord], columns: list[Column], run: RunInfo, time_field: str,
                   failed_sources: list[str], totals: dict[str, int]) -> dict[str, Any]:
    canonical = {column.key: column.name for column in columns}
    time_key = ascii_lower(time_field)
    families: dict[tuple[str | None, str | None], set[str]] = {}
    for record in parts:
        for family in record.families:
            families.setdefault((family["channel"], family["eventid"]), set()).update(family["keys"])
    unparsed = sum(record.time.get("unparsed", 0) for record in parts)
    timeless = [source for record in parts if record.events and record.time.get("column") is None
                for source in record.sources]
    # A part without the time column counts every event as missing; it is
    # reported once, as timeless, instead.
    missing = sum(record.time.get("missing", 0) for record in parts if record.time.get("column") is not None)
    unlinked = sum(counts.get("unlinked", 0) for record in parts for counts in record.rules.values())
    unreadable = [source for record in parts for source in record.unreadable]
    warnings = []
    if unparsed:
        warnings.append(f"{unparsed:,} event(s) have a {time_field} value that is not a time; "
                        "they are kept but have no place on the timeline")
    if missing:
        warnings.append(f"{missing:,} event(s) have no {time_field} value; "
                        "they are kept but have no place on the timeline")
    if timeless:
        warnings.append(f"{len(timeless):,} input(s) have no {time_field} field, so their events have no time: "
                        f"{_some(timeless)}")
    if unreadable:
        warnings.append(f"{len(unreadable):,} input(s) could be read only in part or not at all: {_some(unreadable)}")
    if unlinked:
        warnings.append(f"{unlinked:,} match(es) from custom SQL rules carry no event id and are not linked to events")
    if failed_sources:
        warnings.append(f"{len(failed_sources):,} input(s) failed to process and are not in this package")
    return {
        "format": PACKAGE_FORMAT,
        "zircolite": run.zircolite_version,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run": {
            "mode": run.mode, "executor": run.executor, "time_field": time_field,
            "timestamp_format": run.timestamp_format, "event_filter": "off: --package keeps every event",
            "after": run.after, "before": run.before, "limit": run.limit, "rules_loaded": run.rules_loaded,
        },
        "tactics": list(TACTIC_ORDER),
        "levels": list(RULE_LEVELS),
        "totals": {"events": totals["events"], "parts": len(parts), "rules_matched": totals["rules"],
                   "hits": totals["hits"], "alerts": totals["alerts"]},
        "columns": [{"name": c.name, "key": c.key, "type": c.sql_type, "count": c.count} for c in columns],
        "families": [
            {"channel": channel, "eventid": eventid,
             "columns": sorted(canonical[key] for key in keys if key in canonical)}
            for (channel, eventid), keys in sorted(families.items(), key=lambda item: (item[0][0] or "", item[0][1] or ""))
        ],
        "parts": [
            {"part": record.part, "sources": record.sources, "events": record.events,
             "status": "partial" if record.unreadable else "complete", "unreadable": record.unreadable,
             "spellings": {c["key"]: c["name"] for c in record.columns
                           if c["key"] != time_key and c["name"] != canonical.get(c["key"])},
             "time": record.time}
            for record in parts
        ],
        "failed_sources": list(failed_sources),
        "warnings": warnings,
    }


def _count(connection: duckdb.DuckDBPyConnection, query: str, table: Path) -> int:
    row = connection.execute(query, [str(table)]).fetchone()
    if row is None:
        raise PackageError(f"duckdb returned no count for {table.name}")
    return int(row[0])


@dataclass(frozen=True)
class Viewer:
    directory: Path
    version: str
    copy: tuple[str, ...]
    wrap: tuple[str, ...]


def _file_names(value: Any, label: str, descriptor: Path) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
            isinstance(name, str) and name and name == Path(name).name and name not in (".", "..")
            for name in value):
        raise PackageError(f"{descriptor}: {label} must list plain file names")
    return tuple(value)


def find_viewer() -> Viewer:
    """The packaged viewer, checked whole: a package built from half a viewer opens blank."""
    descriptor = bundled_asset("gui", "viewer", "viewer.json")
    try:
        meta = orjson.loads(descriptor.read_bytes())
    except (OSError, orjson.JSONDecodeError) as exc:
        raise PackageError(f"cannot read the viewer description {descriptor}: {exc}") from exc
    if not isinstance(meta, dict):
        raise PackageError(f"{descriptor} is not a viewer description")
    if meta.get("data_format") != PACKAGE_FORMAT:
        raise PackageError(
            f"{descriptor} reads package format {meta.get('data_format')!r}, but this Zircolite "
            f"writes format {PACKAGE_FORMAT}; rebuild the viewer")
    copy = _file_names(meta.get("copy"), "copy", descriptor)
    wrap = _file_names(meta.get("wrap"), "wrap", descriptor)
    if "index.html" not in copy:
        raise PackageError(f"{descriptor} does not ship index.html")
    missing = [name for name in (*copy, *wrap) if not (descriptor.parent / name).is_file()]
    if missing:
        raise PackageError(f"the viewer in {descriptor.parent} is missing {', '.join(missing)}")
    return Viewer(descriptor.parent, str(meta.get("version", "")), copy, wrap)


def _wrap(archive: zipfile.ZipFile, source: Path, name: str, folder: str, kind: str) -> dict[str, Any]:
    """Write ``source`` into the archive as ``__zircolite.chunk`` scripts."""
    digest = hashlib.sha256()
    chunks: list[str] = []
    size = 0
    label = orjson.dumps(name)
    with open(source, "rb") as handle:
        while block := handle.read(CHUNK_BYTES):
            entry = f"{folder}/{name}.{len(chunks):04d}.js"
            with archive.open(entry, "w") as out:
                out.write(b"__zircolite.chunk(" + label + b"," + str(len(chunks)).encode() + b',"')
                out.write(base64.b64encode(block))
                out.write(b'");\n')
            chunks.append(entry)
            digest.update(block)
            size += len(block)
    return {"name": name, "kind": kind, "bytes": size, "sha256": digest.hexdigest(), "chunks": chunks}


def _fresh_name(directory: Path) -> Path:
    while True:
        candidate = directory / f"zircolite-package-{random_suffix(4)}.zip"
        if not candidate.exists():
            return candidate


def write_package(viewer: Viewer, data: PackageData, destination: Path, work: Path) -> Path:
    """Write the zip beside the spool, then move it into place under a fresh name.

    The spool lives in the destination directory, so the move is a rename: a
    failed write leaves no half package where the user looks for one.
    """
    temporary = work / "package.zip"
    files: list[dict[str, Any]] = []
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name in viewer.copy:
            archive.write(viewer.directory / name, name)
        for name in viewer.wrap:
            files.append(_wrap(archive, viewer.directory / name, name, "assets", "engine"))
        for table in DATA_TABLES:
            files.append(_wrap(archive, data.tables[table], f"{table}.parquet", "data", "data"))
        archive.writestr("README.txt", README_TEXT)
        manifest = orjson.dumps({**data.manifest, "files": files})
        archive.writestr("data/manifest.js", b"__zircolite.manifest(" + manifest + b");\n")
    target = _fresh_name(destination)
    os.replace(temporary, target)
    return target


class PackageBuilder:
    """Turns the spooled parts of a run into Parquet tables and a manifest."""

    def __init__(self, spool: PackageSpool, *, logger: logging.Logger | None = None) -> None:
        self.spool = spool
        self.logger = logger or logging.getLogger(__name__)
        self.work = Path(spool.directory) / "build"

    def build_data(self, *, parts: list[PartRecord], rulesets: list[dict[str, Any]], run: RunInfo,
                   failed_sources: list[str], expected_events: int) -> PackageData:
        """``expected_events`` is what the run ingested: a package holds every event or is not written."""
        parts = sorted(parts, key=lambda record: record.part)
        for previous, record in pairwise(parts):
            if previous.part == record.part:
                raise PackageError(f"part {record.part} was spooled twice; each working database is one part")
        spooled = sum(record.events for record in parts)
        if spooled != expected_events:
            raise PackageError(f"the spooled parts hold {spooled:,} events where the run ingested {expected_events:,}")
        self.work.mkdir(parents=True, exist_ok=True)
        columns = merge_columns(parts, self.spool.time_field)
        connection = duckdb.connect(":memory:", config={**DUCKDB_SETTINGS, "temp_directory": str(self.work / "duckdb")})
        try:
            tables = {
                "events": write_events(connection, self.work, parts, columns),
                "rules": write_rules(connection, self.work, rule_rows(parts, rulesets)),
                "hits": write_hits(connection, self.work, parts),
                **write_alerts(connection, self.work, parts),
            }
            totals = {name: _count(connection, "SELECT count(*) FROM read_parquet(?)", tables[name])
                      for name in ("events", "hits", "alerts")}
            # Counted like the run summary, which collapses a rule's variants into one.
            totals["rules"] = _count(connection, "SELECT count(DISTINCT key) FROM read_parquet(?)", tables["rules"])
        except duckdb.Error as exc:
            raise PackageError(f"duckdb could not write the package data: {exc}") from exc
        finally:
            connection.close()
        expected = sum(record.events for record in parts)
        if totals["events"] != expected:
            raise PackageError(f"the events table holds {totals['events']:,} events where the spool held {expected:,}")
        size = tables["events"].stat().st_size
        if size > EVENTS_PARQUET_LIMIT:
            raise PackageError(
                f"the events take {size / 2**20:,.0f} MiB, more than the {EVENTS_PARQUET_LIMIT // 2**20:,} MiB "
                "a browser can hold; narrow the run with --after/--before or -s")
        manifest = build_manifest(parts=parts, columns=columns, run=run, time_field=self.spool.time_field,
                                  failed_sources=failed_sources, totals=totals)
        return PackageData(tables=tables, manifest=manifest)

    def build(self, *, viewer: Viewer, parts: list[PartRecord], rulesets: list[dict[str, Any]], run: RunInfo,
              failed_sources: list[str], expected_events: int, destination: Path) -> Path:
        data = self.build_data(parts=parts, rulesets=rulesets, run=run, failed_sources=failed_sources,
                               expected_events=expected_events)
        return write_package(viewer, data, destination, self.work)
