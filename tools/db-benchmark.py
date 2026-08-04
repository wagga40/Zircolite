#!/usr/bin/env python3
"""
Measure Zircolite's ingest and rule-execution throughput on a fixed corpus.

Flattening has its own harness; this one covers everything after it -- the
SQLite insert, the indexes, the widening a ruleset forces on the table, and the
rule queries themselves. It ingests a corpus once, then runs the whole ruleset
twice, before and after ANALYZE, reporting the wall time of each and how many
rule queries the planner put on the narrowest index available to them.

That last number is the point. Widening adds an all-NULL column for every field
a rule names and the dataset never produced, and with no statistics SQLite
prices a row by its column count, so a wide table quietly moves every query off
its selective index -- same rules, same detections, several times the wall
clock. Wall time alone blames the machine; the plan count names the cause.

"Selective" is not a fixed index name. Each query is judged against its own
options: whichever of the indexes it was ever planned on returns the fewest rows
per key, as ANALYZE measured it. A query that can only ever be a full scan is
counted apart rather than held against the planner.

An external EVTX corpus is required: every capture tracked in this repository
holds a single event, so pointing this at tests/fixtures/ runs but measures
noise. Use a real capture set such as EVTX-ATTACK-SAMPLES.

Example:
  pdm run python tools/db-benchmark.py --evtx /path/to/EVTX-ATTACK-SAMPLES \
      --ruleset rules/rules_windows_generic.json
  pdm run python tools/db-benchmark.py --evtx /path/to/captures \
      --ruleset rules/rules_windows_merged.json --rule-passes 3 --index-delta
"""

from __future__ import annotations

import argparse
import logging
import re
import sqlite3
import sys
import time
from argparse import Namespace
from collections import Counter
from pathlib import Path

import orjson

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zircolite import ProcessingConfig, ZircoliteCore
from zircolite.console import set_quiet_mode
from zircolite.sqlscan import rebalance_sql

# A transient index carries no name, so it is deliberately not captured here:
# building one per query is what the planner does when nothing usable exists.
_INDEX_RE = re.compile(r"USING (?:AUTOMATIC )?(?:COVERING )?INDEX ([A-Za-z_][^\s(]*)")


def collect_evtx_files(path: Path, max_files: int) -> list[Path]:
    """The EVTX files to ingest, capped at *max_files* when that is positive."""
    candidates = sorted(path.rglob("*.evtx")) if path.is_dir() else [path]
    files = [f for f in candidates if f.is_file()]
    return files[:max_files] if max_files > 0 else files


def load_ruleset(path: Path) -> list[dict]:
    """Read a Zircolite JSON ruleset, returning [] when the file is not one."""
    try:
        ruleset = orjson.loads(path.read_bytes())
    except (OSError, orjson.JSONDecodeError):
        return []
    if not isinstance(ruleset, list):
        return []
    return [rule for rule in ruleset if isinstance(rule, dict) and rule.get("rule")]


def plan_for(core: ZircoliteCore, query: str) -> list[str]:
    """The detail column of EXPLAIN QUERY PLAN, one entry per plan row.

    Runs on the core's own connection, never a fresh one: SQLite resolves
    function names when it prepares a statement, so every rule using REGEXP
    fails to plan at all without the UDF Zircolite registers per connection.
    """
    cursor = core.db_connection.execute(f"EXPLAIN QUERY PLAN {query}")
    return [row[3] for row in cursor.fetchall()]


def preparable(core: ZircoliteCore, query: str) -> str | None:
    """The query in a form SQLite will prepare, or None if it stays broken.

    Mirrors the two repairs ``execute_select_query`` makes rather than
    reimplementing them. Widening has to happen before anything can be planned,
    and it is the very thing this harness measures the consequences of.
    """
    sql = query
    for _ in range(3):
        try:
            plan_for(core, sql)
            return sql
        except sqlite3.Error as exc:
            message = str(exc).lower()
            if "no such column" in message and core._widen_logs_table(sql):
                continue
            if "expression tree is too large" in message:
                rebalanced = rebalance_sql(sql)
                if rebalanced != sql:
                    sql = rebalanced
                    continue
            return None
    return None


def prepare_queries(core: ZircoliteCore, ruleset: list[dict]) -> tuple[list[str], list[str]]:
    """Split every rule query into the ones that plan and the ones that cannot."""
    prepared: list[str] = []
    unpreparable: list[str] = []
    for rule in ruleset:
        for query in rule.get("rule", []):
            repaired = preparable(core, query)
            if repaired is None:
                unpreparable.append(query)
            else:
                prepared.append(repaired)
    return prepared, unpreparable


def indexes_used(details: list[str]) -> set[str]:
    """The named indexes a plan drives from."""
    return {match.group(1) for detail in details for match in _INDEX_RE.finditer(detail)}


def plan_label(details: list[str]) -> str:
    """One printable name for what a plan drove from."""
    used = indexes_used(details)
    if used:
        return ", ".join(sorted(used))
    if any("AUTOMATIC" in detail for detail in details):
        return "AUTOMATIC INDEX"
    return "SCAN"


def rows_per_key(conn: sqlite3.Connection) -> dict[str, float]:
    """How many rows a lookup on each index returns, as ANALYZE measured it."""
    stats: dict[str, float] = {}
    for idx, stat in conn.execute("SELECT idx, stat FROM sqlite_stat1 WHERE tbl = 'logs'"):
        if not idx or not stat:
            continue
        parts = stat.split()
        if len(parts) > 1:
            stats[idx] = float(parts[1])
    return stats


def narrowest(candidates: set[str], stats: dict[str, float]) -> set[str]:
    """Whichever candidate indexes return the fewest rows per lookup."""
    if not candidates:
        return set()
    measured = {name: stats.get(name, float("inf")) for name in candidates}
    floor = min(measured.values())
    return {name for name, value in measured.items() if value == floor}


def plan_verdict(details: list[str], candidates: set[str], best: set[str]) -> str:
    """How well the planner did on one query, judged against its own options."""
    if not candidates:
        return "unindexable"
    used = indexes_used(details)
    if not used:
        return "scan"
    return "selective" if used & best else "broad"


def run_ruleset(core: ZircoliteCore) -> tuple[float, dict[str, int]]:
    """Execute every loaded rule, returning the wall time and the hit counts.

    Deliberately not ``execute_ruleset``: that analyses the table itself, which
    would leave this harness structurally unable to measure a run without
    statistics -- the whole point of the comparison.
    """
    counts: dict[str, int] = {}
    start = time.perf_counter()
    for rule in core.ruleset:
        results = core.execute_rule(rule)
        if results:
            counts[results["title"]] = results["count"]
    return time.perf_counter() - start, counts


def best_of(core: ZircoliteCore, passes: int) -> tuple[float, dict[str, int]]:
    """The fastest of *passes* ruleset runs, with the hits it found."""
    best = float("inf")
    counts: dict[str, int] = {}
    for _ in range(max(1, passes)):
        elapsed, counts = run_ruleset(core)
        best = min(best, elapsed)
    return best, counts


def drop_indexes(core: ZircoliteCore) -> list[str]:
    """Drop the indexes Zircolite created, so a pass can measure life without them."""
    names = [
        row[0]
        for row in core.db_connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
        )
    ]
    for name in names:
        core.db_connection.execute(f'DROP INDEX "{core.escape_identifier(name)}"')
    core.db_connection.commit()
    return names


def print_histogram(title: str, counts: Counter) -> None:
    """One plan-shape tally, widest first."""
    print(title)
    for label, count in counts.most_common():
        print(f"  {label:<28} {count:>5,}")


# What Zircolite builds, what it used to build, and the floor. Each entry is a
# label and the index definitions to create; the columns are resolved against
# the corpus, so a set naming one the dataset lacks is skipped rather than faked.
_INDEX_SETS: list[tuple[str, list[tuple[str, tuple[str, ...]]]]] = [
    ("none", []),
    ("eventid only", [("idx_eventid", ("eventid",))]),
    (
        "eventid + channel",
        [("idx_eventid", ("eventid",)), ("idx_channel", ("channel",))],
    ),
    (
        "eventid + composite",
        [
            ("idx_eventid", ("eventid",)),
            ("idx_channel_eventid", ("channel", "eventid")),
        ],
    ),
]


def build_index_set(
    core: ZircoliteCore, definitions: list[tuple[str, tuple[str, ...]]]
) -> tuple[list[str], float]:
    """Drop every index, build *definitions*, ANALYZE. Returns names and build time.

    Column names are matched case-insensitively against the corpus, the way
    ``create_index`` does: a dataset whose channel arrives as ``winlog.channel``
    flattens to a lowercase column, and an exact-case test would silently build
    nothing. A definition naming an absent column is skipped, because SQLite
    would otherwise accept the quoted name as a string literal and index a
    constant.
    """
    drop_indexes(core)
    by_lower = {c.lower(): c for c in core._get_table_columns()}
    built: list[str] = []
    start = time.perf_counter()
    for name, columns in definitions:
        resolved = [by_lower.get(c) for c in columns]
        if any(c is None for c in resolved):
            continue
        keys = ", ".join(f'"{core.escape_identifier(c)}"' for c in resolved)
        core.db_connection.execute(f'CREATE INDEX "{name}" ON "logs" ({keys})')
        built.append(name)
    core.db_connection.execute("ANALYZE logs")
    core.db_connection.commit()
    return built, time.perf_counter() - start


def compare_index_sets(core: ZircoliteCore, prepared: list[str], args) -> int:
    """Time the ruleset under each index set, and refuse to differ on detections.

    Wall time is only half the answer: an index set that is faster because it
    found less is a regression, not a win. Detections are compared as
    ``{title: count}`` rather than by row order, since driving a query from a
    different index returns the same rows in a different order.
    """
    print(f"index sets (best of {max(1, args.rule_passes)} rule passes each)")
    baseline: dict[str, int] | None = None
    baseline_label = ""
    slowest = 0.0
    rows: list[tuple[str, str, float, float, int]] = []

    for label, definitions in _INDEX_SETS:
        built, build_seconds = build_index_set(core, definitions)
        elapsed, counts = best_of(core, args.rule_passes)
        slowest = max(slowest, elapsed)
        selective = 0
        stats = rows_per_key(core.db_connection)
        for query in prepared:
            plan = plan_for(core, query)
            candidates = indexes_used(plan)
            if plan_verdict(plan, candidates, narrowest(candidates, stats)) == "selective":
                selective += 1
        rows.append(
            (label, ", ".join(built) or "-", build_seconds, elapsed, selective)
        )

        if baseline is None:
            baseline, baseline_label = counts, label
        elif counts != baseline:
            moved = sorted(set(counts.items()) ^ set(baseline.items()))
            print(
                f"Detections under '{label}' differ from '{baseline_label}': "
                f"{moved[:10]}",
                file=sys.stderr,
            )
            return 1

    print(f"{'set':<22}{'rules':>10}{'vs slowest':>12}{'build':>10}{'selective':>11}")
    for label, built, build_seconds, elapsed, selective in rows:
        print(
            f"{label:<22}{elapsed * 1000:>9,.0f}ms"
            f"{slowest / elapsed:>11.2f}x"
            f"{build_seconds * 1000:>8,.0f}ms"
            f"{selective:>11,}"
        )
        print(f"  {built}")
    print(f"\ndetections identical across every set: {len(baseline or {}):,} rules")
    return 0


def benchmark(core: ZircoliteCore, files: list[Path], ruleset: list[dict], args) -> int:
    """Ingest once, then run the ruleset either side of ANALYZE and report."""
    start = time.perf_counter()
    events = core.run_streaming(
        [str(path) for path in files],
        input_type="evtx",
        args_config=Namespace(
            evtx_input=True, all_transforms=False, transform_categories=None
        ),
        disable_progress=True,
    )
    ingest = time.perf_counter() - start
    if not events:
        print("No events ingested; check the --evtx path.", file=sys.stderr)
        return 1

    columns_before = len(core._get_table_columns())
    core.load_ruleset_from_var(ruleset, rule_filters=None)
    core.apply_auto_index()

    prepared, unpreparable = prepare_queries(core, core.ruleset)
    columns_after = len(core._get_table_columns())
    if not prepared:
        print("No rule query could be planned against this corpus.", file=sys.stderr)
        return 1

    if args.index_sets:
        return compare_index_sets(core, prepared, args)

    plans_cold = {query: plan_for(core, query) for query in prepared}
    cold, counts_cold = best_of(core, args.rule_passes)

    start = time.perf_counter()
    core.db_connection.execute("ANALYZE logs")
    analyze = time.perf_counter() - start

    plans_warm = {query: plan_for(core, query) for query in prepared}
    warm, counts_warm = best_of(core, args.rule_passes)

    stats = rows_per_key(core.db_connection)
    verdicts_cold: Counter = Counter()
    verdicts_warm: Counter = Counter()
    shapes_cold: Counter = Counter()
    shapes_warm: Counter = Counter()
    for query in prepared:
        candidates = indexes_used(plans_cold[query]) | indexes_used(plans_warm[query])
        best = narrowest(candidates, stats)
        verdicts_cold[plan_verdict(plans_cold[query], candidates, best)] += 1
        verdicts_warm[plan_verdict(plans_warm[query], candidates, best)] += 1
        shapes_cold[plan_label(plans_cold[query])] += 1
        shapes_warm[plan_label(plans_warm[query])] += 1

    dropped: list[str] = []
    no_index = 0.0
    if args.index_delta:
        dropped = drop_indexes(core)
        no_index, _ = best_of(core, args.rule_passes)

    indexed = sorted(stats) or ["none"]
    hits = sum(counts_warm.values())
    print(f"files:         {len(files):,}")
    print(f"events:        {events:,}")
    print(f"ingest:        {ingest * 1000:,.2f} ms  ({events / ingest:,.0f} events/s)")
    print(
        f"columns:       {columns_before:,} -> {columns_after:,} "
        f"({columns_after - columns_before:,} added by widening)"
    )
    print(f"queries:       {len(prepared):,} prepared, {len(unpreparable):,} unpreparable")
    print(f"indexes:       {', '.join(indexed)}")
    print(f"no stats:      {cold * 1000:,.2f} ms")
    print(f"analyze:       {analyze * 1000:,.2f} ms")
    print(f"analyzed:      {warm * 1000:,.2f} ms  ({cold / warm:.2f}x)")
    if args.index_delta:
        print(f"no index:      {no_index * 1000:,.2f} ms  ({len(dropped)} dropped)")
    print(
        f"selective:     {verdicts_cold['selective']:,}/{len(prepared):,} -> "
        f"{verdicts_warm['selective']:,}/{len(prepared):,} "
        f"({verdicts_warm['unindexable']:,} unindexable)"
    )
    print(f"detections:    {len(counts_warm):,} rules, {hits:,} events")
    print()
    print_histogram("plans (no stats)", shapes_cold)
    print_histogram("plans (analyzed)", shapes_warm)

    if counts_cold != counts_warm:
        moved = sorted(set(counts_cold) ^ set(counts_warm))
        print(
            f"Detections changed across the two passes: {moved[:10]}",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--evtx", required=True, help="Path to an EVTX file or a directory of them"
    )
    ap.add_argument(
        "--ruleset", required=True, help="Zircolite JSON ruleset to execute"
    )
    ap.add_argument(
        "--config", default="config/config.yaml", help="Field mappings config file"
    )
    ap.add_argument(
        "--max-files", type=int, default=0, help="Ingest at most this many files (0 = all)"
    )
    ap.add_argument(
        "--rule-passes", type=int, default=1, help="Ruleset runs per pass; the best is reported"
    )
    ap.add_argument(
        "--auto-index", type=int, default=0, help="Index the top-N columns the ruleset references"
    )
    ap.add_argument(
        "--index-delta", action="store_true", help="Add a third rule pass with the indexes dropped"
    )
    ap.add_argument(
        "--index-sets",
        action="store_true",
        help="Time the ruleset under each candidate index set instead of either side of ANALYZE",
    )
    args = ap.parse_args()

    logging.disable(logging.CRITICAL)
    set_quiet_mode(True)

    ruleset = load_ruleset(Path(args.ruleset).expanduser())
    if not ruleset:
        print("No rules loaded; --ruleset must be a Zircolite JSON ruleset.", file=sys.stderr)
        return 1

    files = collect_evtx_files(Path(args.evtx).expanduser(), args.max_files)
    if not files:
        print("No EVTX files found; check the --evtx path.", file=sys.stderr)
        return 1

    core = ZircoliteCore(
        config=args.config,
        processing_config=ProcessingConfig(
            disable_progress=True, no_output=True, auto_index_top_n=args.auto_index
        ),
    )
    try:
        return benchmark(core, files, ruleset, args)
    finally:
        core.close()


if __name__ == "__main__":
    raise SystemExit(main())
