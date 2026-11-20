"""Measure full SQLite and projected event storage against one freshly ingested EVTX stage.

Both workers use the same committed rows, rule SQL and default detection indexes.
The compact worker retains a bounded, compressed copy of every canonical event.
Neither the stage nor its private scratch files are persistent package formats.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import math
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zlib
from contextlib import closing
from dataclasses import dataclass
from functools import lru_cache
from itertools import islice
from pathlib import Path

import orjson
import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from zircolite.config import ProcessingConfig  # noqa: E402
from zircolite.core import ZircoliteCore, _uncompilable_regex  # noqa: E402
from zircolite.fulltext import FIELD  # noqa: E402
from zircolite.spellings import FieldSpellings  # noqa: E402
from zircolite.sqlscan import SQL_RESERVED_WORDS, _unquote, normalize_rule_sql, scan_query  # noqa: E402
from zircolite.streaming import StreamingEventProcessor, _quote_identifier  # noqa: E402

CONFIG = str(ROOT / "config/config.yaml")
HEAD = re.compile(r"\s*SELECT\s+\*\s+FROM\s+logs\s+WHERE\s+", re.IGNORECASE | re.ASCII)
IDENT = r'(?:[a-zA-Z_][a-zA-Z_0-9]*|`(?:[^`]|``)+`|"(?:[^"]|"")+"|\[[^\]]+\])'
STRING = r"'(?:[^']|'')*'"
VALUE = rf"(?:{STRING}|[0-9]+)"
# Every comparison names its fields explicitly. SQLite independently
# checks the complete expression and confirms its resolved column reads.
ATOM = re.compile(
    rf"(?P<name>{IDENT})\s*(?:"
    rf"(?:<>|!=|<=|>=|=|<|>)\s*(?:{VALUE}|(?P<other>{IDENT}))(?:\s+COLLATE\s+NOCASE\b)?"
    rf"|(?:NOT\s+)?LIKE\s+{STRING}(?:\s+ESCAPE\s+{STRING})?"
    rf"|REGEXP\s+{STRING}"
    rf"|(?:NOT\s+)?IN\s*\(\s*{VALUE}(?:\s*,\s*{VALUE})*\s*\)"
    rf"|IS\s+(?:NOT\s+)?NULL\b)", re.IGNORECASE | re.ASCII,
)
STRUCTURE = re.compile(r"(?:AND\b|OR\b|NOT\b|COALESCE\s*\(|,\s*0\s*\)|[()]|\s+)", re.IGNORECASE | re.ASCII)
ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
RESERVED = SQL_RESERVED_WORDS | {"current_time", "current_date", "current_timestamp"}
BLOCK_BYTES = 1 << 20
BLOCK_ROWS = 512
MIB = 1 << 20


class Ineligible(ValueError):
    """The complete workload must use the ordinary detector."""


@dataclass(frozen=True)
class Statement:
    query: str
    ids_query: str
    fields: frozenset[str]
    channels: frozenset[str] | None
    eventids: frozenset[int] | None


def statements(rules):
    if not isinstance(rules, list):
        raise Ineligible("expected a list of converted rules")
    plans = []
    for rule in rules:
        if (not isinstance(rule, dict) or rule.get("result_type") != "event" or rule.get("source_table") != "logs"
                or rule.get("correlation") or rule.get("correlation_plan") is not None
                or not isinstance(rule.get("required_fields"), list)
                or not all(isinstance(field, str) for field in rule["required_fields"])
                or not isinstance(rule.get("rule"), list) or not rule["rule"]
                or not all(isinstance(sql, str) for sql in rule["rule"])):
            raise Ineligible("requires simple converted event rules with declared fields")
        title = rule.get("title", "unnamed rule")
        declared = {field.lower() for field in rule["required_fields"]}
        for sql in rule["rule"]:
            head = HEAD.match(sql)
            if head is None:
                raise Ineligible(f"unsupported SELECT in {title}")
            fields = set()
            position = head.end()
            while position < len(sql):
                atom = ATOM.match(sql, position)
                if atom:
                    for name in (atom["name"], atom["other"]):
                        if name is None:
                            continue
                        if name[0] in '"`[':
                            name = _unquote(name)
                        elif name.lower() in RESERVED:
                            raise Ineligible(f"ambiguous SQL name in {title}")
                        if not name.isascii() or name.lower() in (FIELD, "_rowid_", "oid", "rowid"):
                            raise Ineligible(f"unsupported field in {title}")
                        fields.add(name.lower())
                    position = atom.end()
                else:
                    syntax = STRUCTURE.match(sql, position)
                    if not syntax:
                        raise Ineligible(f"unsupported predicate in {title}")
                    position = syntax.end()
            if not fields or not fields <= declared:
                raise Ineligible(f"unproven predicate fields in {title}")
            if reason := _uncompilable_regex(sql):
                raise Ineligible(f"{title}: {reason}")
            normalized = normalize_rule_sql(sql)
            scan = scan_query(sql)
            channels = scan.channels
            # Only ordinary ASCII, non-numeric text is a safe Python shortcut
            # across SQLite's NOCASE and numeric affinities.
            if channels is not None:
                channels = (frozenset(c.lower() for c in channels)
                            if all(c.isascii() and c and c[0].isalpha() and "\0" not in c for c in channels)
                            else None)
            # Normalization only changes the predicate.
            predicate = normalized[head.end():]
            plans.append(Statement(sql, "SELECT row_id FROM logs WHERE " + predicate,  # noqa: S608
                                   frozenset(fields), channels, scan.eventids))
    if not plans:
        raise Ineligible("empty ruleset")
    return plans


def evidence_bytes(event):
    # SQLite has scalar values only, so a tagged object is unambiguous. orjson
    # otherwise refuses BLOBs and represents infinity as null.
    encoded = {}
    for key, value in event.items():
        if isinstance(value, bytes):
            value = {"blob": base64.b64encode(value).decode("ascii")}
        elif isinstance(value, float) and not math.isfinite(value):
            value = {"real": value.hex()}
        encoded[key] = value
    return orjson.dumps(encoded, option=orjson.OPT_SORT_KEYS)


def decode_event(line):
    event = orjson.loads(line)
    for key, value in event.items():
        if isinstance(value, dict):
            event[key] = (base64.b64decode(value["blob"], validate=True) if "blob" in value
                          else float.fromhex(value["real"]))
    return event


def all_events(connection, time_field):
    spellings = FieldSpellings.load(connection, time_field)
    cursor = connection.execute("SELECT * FROM logs ORDER BY row_id")
    columns = [item[0] for item in cursor.description]
    private = next((column for column in columns if column.lower() == FIELD), None)
    for row in cursor:
        physical = {key: value for key, value in zip(columns, row, strict=True) if value is not None}
        public = physical if private not in physical else {k: v for k, v in physical.items() if k != private}
        yield physical, spellings.restore(public) if spellings else public


def cap_disk(connection, database, path, budget):
    free = shutil.disk_usage(path.parent).free - 64 * MIB
    pages = min(budget, free) // connection.execute(f"PRAGMA {database}.page_size").fetchone()[0]
    if pages < 8:
        raise ValueError("scratch budget or available disk space too small")
    connection.execute(f"PRAGMA {database}.max_page_count={pages}")


class Evidence:
    def __init__(self, db, directory, budget):
        self.db = db
        path = directory / "evidence.db"
        db.execute("ATTACH DATABASE ? AS evidence", (str(path),))
        cap_disk(db, "evidence", path, budget)
        db.execute("PRAGMA evidence.journal_mode=MEMORY")
        db.execute("CREATE TABLE IF NOT EXISTS evidence.blocks(part INTEGER, first_id INTEGER, last_id INTEGER, "
                   "payload BLOB NOT NULL, PRIMARY KEY(part, first_id)) WITHOUT ROWID")
        self.cached = None

    def events(self, part):
        """Sequential complete events suitable for a package writer."""
        for (payload,) in self.db.execute("SELECT payload FROM evidence.blocks WHERE part=? ORDER BY first_id", (part,)):
            yield from map(decode_event, zlib.decompress(payload).splitlines())

    def get(self, part, row_id):
        if self.cached is None or self.cached[0] != part or not self.cached[1] <= row_id <= self.cached[2]:
            block = self.db.execute("SELECT first_id, last_id, payload FROM evidence.blocks "
                                    "WHERE part=? AND first_id<=? ORDER BY first_id DESC LIMIT 1", (part, row_id)).fetchone()
            if block is None or row_id > block[1]:
                raise KeyError((part, row_id))
            rows = [decode_event(line) for line in zlib.decompress(block[2]).splitlines()]
            self.cached = (part, block[0], block[1], {event["row_id"]: event for event in rows})
        return self.cached[3][row_id]


def verify_reads(db, plan):
    """SQLite must resolve every read to a vetted field on the native logs table."""
    allowed = plan.fields | {"row_id"}

    def authorize(action, table, column, database, _trigger):
        if action == sqlite3.SQLITE_READ:
            valid = database == "main" and table == "logs" and column.translate(ASCII_FOLD) in allowed
        elif action == sqlite3.SQLITE_FUNCTION:
            valid = column in {"coalesce", "like", "regexp"}
        else:
            valid = action == sqlite3.SQLITE_SELECT
        return sqlite3.SQLITE_OK if valid else sqlite3.SQLITE_DENY

    db.set_authorizer(authorize)
    try:
        db.execute("EXPLAIN " + plan.ids_query)
    except sqlite3.DatabaseError as exc:
        raise Ineligible(f"SQLite could not prove the predicate read set: {exc}") from exc
    finally:
        db.set_authorizer(None)


def project(source, core, plans, evidence, part=0):
    db = core.db_connection
    # Only freshly staged native logs are accepted. Copy their actual affinity
    # and collation declarations, including those of every projected column.
    schema = source.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='logs'").fetchone()[0]
    db.execute(schema)
    for plan in plans:
        core._widen_logs_table(plan.query, sorted(plan.fields))
        verify_reads(db, plan)
    columns = {name.translate(ASCII_FOLD): name for _, name, *_ in source.execute("PRAGMA table_info(logs)")}
    required = sorted({"row_id", "channel", "eventid"}.union(*(p.fields for p in plans)) & columns.keys())
    names = [columns[key] for key in required]
    insert = ("INSERT INTO logs (" + ", ".join(map(_quote_identifier, names))  # noqa: S608
              + ") VALUES (" + ", ".join("?" for _ in names) + ")")

    @lru_cache(maxsize=1024)
    def retained(channel, eventid):
        keep = {"row_id", "channel", "eventid"}
        for plan in plans:
            if channel is not None and plan.channels is not None and channel not in plan.channels:
                continue
            if eventid is not None and plan.eventids is not None and eventid not in plan.eventids:
                continue
            keep.update(plan.fields)
        return tuple(columns[name] if name in keep else None for name in required)

    batch: list[tuple] = []
    lines: list[bytes] = []
    size = 0

    def flush():
        # Only publish evidence and projected keys together. A failed insert,
        # a full scratch device, or interruption discards this entire block.
        with db:
            db.execute("BEGIN")
            db.executemany(insert, batch)
            row_position = required.index("row_id")
            db.execute("INSERT INTO evidence.blocks VALUES (?,?,?,?)",
                       (part, batch[0][row_position], batch[-1][row_position],
                        zlib.compress(b"\n".join(lines), 1)))
        lines.clear()
        batch.clear()

    for physical, public in all_events(source, core.time_field):
        line = evidence_bytes(public)
        if len(line) + 1 > BLOCK_BYTES:
            raise Ineligible("canonical event exceeds bounded evidence block")
        if batch and (len(batch) >= BLOCK_ROWS or size + len(line) + 1 > BLOCK_BYTES):
            flush()
            size = 0
        channel = physical.get(columns.get("channel"))
        eventid = physical.get(columns.get("eventid"))
        # Unknown or unusually large keys keep the union of possibly needed
        # fields and cannot fill the bounded plan cache with large event values.
        channel_key = (channel.lower() if isinstance(channel, str) and len(channel) <= 256
                       and channel.isascii() and "\0" not in channel else None)
        event_key = eventid if type(eventid) is int else None
        if isinstance(eventid, str) and len(eventid) <= 18 and eventid.isascii() and eventid.isdecimal():
            # Equality of two decimal spellings implies equality of their
            # integers. Leading zeros can admit extra rows, which SQLite checks.
            event_key = int(eventid)
        keys = retained(channel_key, event_key)
        batch.append(tuple(physical.get(key) for key in keys))
        lines.append(line)
        size += len(line) + 1
    if batch:
        flush()


def digest(events):
    """Order-independent multiset of full evidence, including committed IDs and exact types."""
    count = total = 0
    for event in events:
        total += int.from_bytes(hashlib.sha256(evidence_bytes(event)).digest(), "big")
        count += 1
    return [count, f"{total % (1 << 256):064x}"]


def stage_events(args, directory):
    path = directory / "canonical.db"
    with closing(sqlite3.connect(path, isolation_level=None)) as db:
        db.execute("PRAGMA page_size=65536")  # Match ZircoliteCore's working DB page size.
        cap_disk(db, "main", path, args.disk_mib * MIB)
        db.execute("PRAGMA journal_mode=MEMORY")
        processor = StreamingEventProcessor(CONFIG, argparse.Namespace(), ProcessingConfig(
            time_field="SystemTime", evtx_threads=1, strict_evtx=True))
        processor.create_initial_table(db)
        with closing(db.cursor()) as cursor:
            for name in args.events:
                with closing(processor.stream_evtx_events(str(name))) as stream:
                    records = islice(stream, args.rows_per_file) if args.rows_per_file else stream
                    while batch := list(islice(records, processor.batch_size)):
                        processor._insert_batch(db, cursor, batch)
        return {"events": db.execute("SELECT count(*) FROM logs").fetchone()[0],
                "bytes": path.stat().st_size, "columns": len(db.execute("PRAGMA table_info(logs)").fetchall())}


class HydratingCore(ZircoliteCore):
    """Benchmark-only adapter after the normal executor's final SQLite check."""

    evidence: Evidence

    def _iter_select_query(self, *args, **kwargs):
        with closing(super()._iter_select_query(*args, **kwargs)) as matched:
            for row in matched:
                yield self.evidence.get(0, row["row_id"])


def normal_rules(core, rules):
    signatures = []
    matches = 0

    def consume(result):
        nonlocal matches
        identity = {key: value for key, value in result.items() if key != "matches"}
        count, fingerprint = digest(result["matches"])
        if count != identity["count"]:
            raise ValueError("result count differs from complete evidence")
        matches += count
        signatures.append([identity, fingerprint])

    core.load_ruleset_from_var(rules)
    core.execute_ruleset("", disable_progress=True, show_table=False, result_sink=consume, stream_results=True)
    return {"matches": matches, "matched_rules": len(signatures),
            "by_rule_digest": hashlib.sha256(orjson.dumps(signatures, option=orjson.OPT_SORT_KEYS)).hexdigest(),
            "prefilter": core.metrics.data["prefilter"], "engine_stage_s": core.metrics.data["seconds"]}


def plain_statements(mode, core, queries, evidence):
    results = []
    started = time.perf_counter()
    for position, sql in enumerate(queries, 1):
        if evidence:
            events = (evidence.get(0, row_id) for (row_id,) in core.db_connection.execute(sql))
        else:
            events = core._iter_select_query(sql)
        results.append(digest(events))
        if position % 1000 == 0:
            print(f"{mode} evaluated {position:,} of {len(queries):,} statements in "
                  f"{time.perf_counter() - started:.1f}s", file=sys.stderr, flush=True)
    return {"matches": sum(row[0] for row in results),
            "by_statement_digest": hashlib.sha256(orjson.dumps(results)).hexdigest()}


def measure(mode, directory, rules, budget, detector):
    stage = directory / "canonical.db"
    automatic = detector == "auto"
    config = ProcessingConfig(time_field="SystemTime", no_output=True, rule_prefilter="auto" if automatic else "off")
    worker_class = HydratingCore if mode == "compact" and automatic else ZircoliteCore
    with (closing(sqlite3.connect(stage.as_uri() + "?mode=ro", uri=True)) as source,
          closing(worker_class(CONFIG, config)) as core):
        db = core.db_connection
        if db is None:
            raise RuntimeError("working database unavailable")
        start = time.perf_counter()
        evidence = None
        queries = [sql for rule in rules for sql in rule["rule"]]
        if mode == "reference":
            source.backup(db)
            if not automatic:
                for rule in rules:
                    for sql in rule["rule"]:
                        core._widen_logs_table(sql, rule["required_fields"])
        else:
            plans = statements(rules)
            evidence = Evidence(db, directory, budget - stage.stat().st_size)
            project(source, core, plans, evidence)
            if isinstance(core, HydratingCore):
                core.evidence = evidence
            else:
                queries = [plan.ids_query for plan in plans]
        core.create_index()
        if not automatic:
            db.execute("ANALYZE")
        built = time.perf_counter()
        results = normal_rules(core, rules) if automatic else plain_statements(mode, core, queries, evidence)
        diagnostics = {"rule_errors": core.rules_in_error, "regex_timeouts": core.regex_timeouts,
                       "correlations": core.metrics.data["correlation_diagnostics"],
                       "pruned_rules": core.metrics.data["pruned_rules"]}
        if core.rules_in_error or core.regex_timeouts:
            raise Ineligible(f"query diagnostics require the reference detector: {diagnostics}")
        detected = time.perf_counter()
        detection_peak = peak_rss_bytes()
        # Also exercise sequential package-style replay. Include every unmatched
        # row and its canonical ID, but keep this check out of detection timings.
        everything = digest(evidence.events(0) if evidence else (e for _, e in all_events(db, core.time_field)))
        return {**results, "diagnostics": diagnostics, "build_index_s": built - start,
                "query_hydrate_digest_s": detected - built, "total_s": detected - start,
                "full_replay_digest_s": time.perf_counter() - detected,
                "sqlite_bytes": db.execute("PRAGMA main.page_count").fetchone()[0] * db.execute(
                    "PRAGMA main.page_size").fetchone()[0],
                "evidence_bytes": (directory / "evidence.db").stat().st_size if evidence else 0,
                "detection_peak_rss_bytes": detection_peak, "statements": len(queries),
                "all_events": everything}


def peak_rss_bytes():
    """OS high-water mark including Python, SQLite and native heaps."""
    if sys.platform == "win32":
        return psutil.Process().memory_info()._asdict()["peak_wset"]
    import resource

    maximum = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return maximum if sys.platform == "darwin" else maximum * 1024


def run_worker(args, mode, directory):
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", mode,
               "--directory", str(directory), "--ruleset", str(args.ruleset), "--detector", args.detector,
               "--disk-mib", str(args.disk_mib), "--rows-per-file", str(args.rows_per_file),
               "--events", *map(str, args.events)]
    started = time.perf_counter()
    subprocess.run(command, check=True)  # noqa: S603 -- fixed interpreter and local script
    result = orjson.loads((directory / f"{mode}.json").read_bytes())
    result["worker_wall_s"] = time.perf_counter() - started
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path, nargs="+", help="one or more EVTX sources, in order")
    parser.add_argument("--detector", choices=["auto", "sql"], default="auto",
                        help="production automatic rule executor (default), or individual SQL statements")
    parser.add_argument("--ruleset", type=Path, default=ROOT / "rules/rules_windows_merged.json")
    parser.add_argument("--rows-per-file", type=int, default=10000, help="0 reads all records from each file")
    parser.add_argument("--disk-mib", type=int, default=2048, help="combined canonical and evidence SQLite page budget")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--scratch-dir", type=Path, help="parent directory for temporary stage and workers")
    parser.add_argument("--worker", choices=["stage", "reference", "compact"], help=argparse.SUPPRESS)
    parser.add_argument("--directory", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.repeat < 1 or args.disk_mib < 1 or args.rows_per_file < 0:
        parser.error("positive repeats and disk budget required; row limit must be nonnegative")
    if any(path.suffix.lower() != ".evtx" or not path.is_file() for path in args.events):
        parser.error("this experiment accepts fresh EVTX sources only")
    try:
        rules = orjson.loads(args.ruleset.read_bytes()) if args.worker != "stage" else []
        if args.worker:
            directory = args.directory.resolve()
            result = (stage_events(args, directory) if args.worker == "stage" else
                      measure(args.worker, directory, rules, args.disk_mib * MIB, args.detector))
            result["worker_peak_rss_bytes"] = peak_rss_bytes()
            result["worker_cpu_s"] = time.process_time()
            (directory / f"{args.worker}.json").write_bytes(orjson.dumps(result))
            return
        statements(rules)  # Reject the whole experiment before staging any input.
        with tempfile.TemporaryDirectory(dir=args.scratch_dir) as temporary:
            directory = Path(temporary).resolve()
            stage = run_worker(args, "stage", directory)
            runs = []
            for iteration in range(args.repeat):
                modes = ["reference", "compact"] if iteration % 2 == 0 else ["compact", "reference"]
                current = {}
                for mode in modes:
                    current[mode] = run_worker(args, mode, directory)
                    if mode == "compact":
                        (directory / "evidence.db").unlink()
                signature = "by_rule_digest" if args.detector == "auto" else "by_statement_digest"
                for key in ("statements", "matches", signature, "all_events", "diagnostics"):
                    if current["reference"][key] != current["compact"][key]:
                        raise RuntimeError(f"evidence parity failed: {key}")
                if current["compact"]["all_events"][0] != stage["events"]:
                    raise RuntimeError("evidence replay lost staged rows")
                runs.append(current)
            inputs = [{"name": path.name, "bytes": path.stat().st_size} for path in args.events]
            report = {"detector": args.detector, "inputs": inputs, "rows_per_file": args.rows_per_file,
                      "ruleset_sha256": hashlib.sha256(args.ruleset.read_bytes()).hexdigest(),
                      "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                      "platform": platform.platform(), "stage": stage, "runs": runs}
            sys.stdout.buffer.write(orjson.dumps(report, option=orjson.OPT_INDENT_2) + b"\n")
    except Ineligible as exc:
        parser.exit(2, f"Reference detector required: {exc}\n")


if __name__ == "__main__":
    main()
