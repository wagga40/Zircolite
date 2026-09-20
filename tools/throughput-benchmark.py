#!/usr/bin/env python3
"""Compare complete CLI runs, process-tree RSS, and normalized detections.

Use --events/--ruleset for a real corpus, or --scenario for generated JSON/CSV
workloads. Generation and result comparison are outside the timed region.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import importlib.metadata
import json
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from copy import deepcopy
from pathlib import Path

import orjson
import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zircolite import jsonstream  # noqa: E402
from zircolite.streaming import select_flatten_kernel  # noqa: E402

VARIANTS = {
    "baseline": [],
    "reference": ["--flatten-backend", "python", "--rule-prefilter", "off"],
    "python-auto": ["--flatten-backend", "python", "--rule-prefilter", "auto"],
    "python-literal": ["--flatten-backend", "python", "--rule-prefilter", "literal"],
    "cython-off": ["--flatten-backend", "cython", "--rule-prefilter", "off"],
    "cython-auto": ["--flatten-backend", "cython", "--rule-prefilter", "auto"],
    "cython-literal": ["--flatten-backend", "cython", "--rule-prefilter", "literal"],
    "current": [],
    "disk": ["--working-db", "disk"],
}


def make_corpus(directory, scenario, events, files):
    directory.mkdir()
    files = 1 if scenario == "large" else min(events, files)
    array_mode = scenario in ("array", "array-gzip")
    sample = None
    if scenario == "evtx-derived":
        from evtx import PyEvtxParser

        record = next(iter(PyEvtxParser(str(ROOT / "tests/fixtures/sample_bitsadmin.evtx")).records_json()))
        sample = orjson.loads(record["data"])
    for index in range(files):
        count = events // files + (index < events % files)
        suffix = ".json" if array_mode else ".csv" if scenario == "csv" else ".jsonl"
        if scenario in ("gzip", "array-gzip"):
            suffix += ".gz"
        path = directory / f"events{index}{suffix}"
        opener = gzip.open if scenario in ("gzip", "array-gzip") else open
        with opener(path, "wt", encoding="utf-8", newline="") as output:
            writer = None
            if array_mode:
                output.write("[")
            for n in range(count):
                row = {
                    "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "CommandLine": "cmd.exe /c whoami" if n % 100 == 0 else "cmd.exe /c echo hello",
                    "Image": "C:\\Windows\\System32\\cmd.exe", "RecordNum": n,
                    "Computer": "HOST", "User": "DOMAIN\\User",
                }
                if scenario == "mixed":
                    row[f"Extra{index % 8}"] = str(n)
                if scenario == "sparse" and n % 100:
                    row["CommandLine"] = None
                if scenario == "linux":
                    row.update(Channel="Linux-Sysmon/Operational",
                               Image="/usr/bin/uname" if n % 100 == 0 else "/usr/bin/printf",
                               CommandLine="uname -a" if n % 100 == 0 else "printf hello")
                if sample is not None:
                    row = deepcopy(sample)
                    row["Event"]["System"]["EventRecordID"] = n + 1
                    data = row["Event"]["EventData"]
                    data["ProcessId"] = n + 1000
                    if n % 100:
                        data.update(Image="C:\\Windows\\System32\\cmd.exe",
                                    CommandLine="cmd.exe /c echo hello",
                                    OriginalFileName="Cmd.Exe", Description="Windows Command Processor",
                                    CurrentDirectory="C:\\Windows\\System32\\")
                if scenario == "csv":
                    if writer is None:
                        writer = csv.DictWriter(output, fieldnames=list(row))
                        writer.writeheader()
                    writer.writerow(row)
                else:
                    if array_mode and n:
                        output.write(",")
                    output.write(orjson.dumps(row).decode() + "\n")
            if array_mode:
                output.write("]")
    rules = directory.parent / "rules.json"
    query = "SELECT * FROM logs WHERE EventID=1"
    if scenario != "noisy":
        needle = {"evtx-derived": "bitsadmin", "linux": "uname"}.get(scenario, "whoami")
        query += f" AND CommandLine LIKE '%{needle}%' ESCAPE '\\'"
    rules.write_bytes(orjson.dumps([{"id": "benchmark", "title": "Benchmark rule", "level": "high", "rule": [query]}]))
    return rules


def fingerprint(path):
    """Order-independent event multiset fingerprint, including duplicate counts."""
    count, digest_sum = 0, 0
    # Verification runs in the harness after the measured CLI exits. A noisy
    # rule can hold far more than the ingestion parser's per-event size cap.
    for result in orjson.loads(path.read_bytes()):
        for match in result.get("matches", []):
            canonical = [result.get("id"), result.get("title"),
                         {k: v for k, v in match.items() if k != "row_id"}]
            digest = hashlib.sha256(orjson.dumps(canonical, option=orjson.OPT_SORT_KEYS)).digest()
            digest_sum = (digest_sum + int.from_bytes(digest, "big")) % (1 << 256)
            count += 1
    return count, f"{digest_sum:064x}"


def source_fingerprint(root):
    digest = hashlib.sha256()
    for path in sorted((root / "zircolite").glob("*.py")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def run_sampled(command, log, *, cwd=ROOT, temp_dir=None):
    """Run a command to completion, sampling the RSS of its whole process tree.

    Returns (exit code, wall seconds, peak RSS bytes, RSS scope, peak bytes
    visible under temp_dir). The scope is "parent-only" when child processes
    could not be inspected, so worker memory is missing from the peak.
    """
    peak = 0
    disk_peak = 0
    tree_access = True
    start = time.perf_counter()
    with log.open("wb") as transcript, subprocess.Popen(  # noqa: S603
        command, cwd=cwd, stdout=transcript, stderr=subprocess.STDOUT
    ) as child:
        process = psutil.Process(child.pid)
        while child.poll() is None:
            try:
                rss = process.memory_info().rss
                try:
                    for descendant in process.children(recursive=True):
                        try:
                            rss += descendant.memory_info().rss
                        except psutil.NoSuchProcess:
                            pass
                        except (psutil.Error, OSError):
                            tree_access = False
                except (psutil.Error, OSError):
                    tree_access = False
                peak = max(peak, rss)
            except (psutil.Error, OSError):
                pass
            if temp_dir is not None:
                visible_bytes = 0
                for path in temp_dir.rglob("*"):
                    with suppress(OSError):
                        if path.is_file():
                            visible_bytes += path.stat().st_size
                disk_peak = max(disk_peak, visible_bytes)
            time.sleep(0.02)
        code = child.wait()
    elapsed = time.perf_counter() - start
    return code, elapsed, peak, "process-tree" if tree_access else "parent-only", disk_peak


def measure(command, output, log, *, temp_dir=None, performance_path=None):
    code, elapsed, peak, rss_scope, disk_peak = run_sampled(command, log, temp_dir=temp_dir)
    if code:
        raise RuntimeError(f"CLI exited {code}: {log.read_text(errors='replace')[-4000:]}")
    count, digest = fingerprint(output)
    # Quiet mode suppresses worker presentation, but failure summaries still
    # identify broken rules and incomplete ingestion.
    transcript = log.read_text(errors="replace")
    if any(message in transcript for message in ("could not be evaluated", "failed to process", "Partial ingest")):
        raise RuntimeError(f"Incomplete benchmark run: {transcript[-4000:]}")
    metrics = json.loads(performance_path.read_text()) if performance_path else None
    if metrics and metrics["status"] != "complete":
        raise RuntimeError(f"Incomplete benchmark run: {metrics['status']}")
    return {"seconds": elapsed, "peak_rss_mib": peak / 1024**2,
            "visible_temp_peak_mib": disk_peak / 1024**2,
            "matches": count, "fingerprint": digest,
            "rss_scope": rss_scope, "performance": metrics}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path)
    parser.add_argument("--ruleset", type=Path)
    parser.add_argument("--config", type=Path, default=ROOT / "config/config.yaml")
    parser.add_argument("--scenario", choices=("many-small", "large", "mixed", "sparse", "gzip", "array", "array-gzip", "csv", "noisy", "transforms", "evtx-derived", "linux"), default="mixed")
    parser.add_argument("--event-count", type=int, default=100000)
    parser.add_argument("--files", type=int, default=4)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--passes", type=int, default=3)
    parser.add_argument("--modes", nargs="+", choices=("auto", "sequential", "thread", "process"), default=["sequential", "thread", "process"])
    parser.add_argument("--variants", nargs="+", choices=tuple(VARIANTS), default=["reference", "current"])
    parser.add_argument("--baseline-root", type=Path, help="Preserved checkout for the baseline variant")
    parser.add_argument("--rule-count", type=int, default=1, help="Distinct generated literal queries; use 32+ to exercise automatic filtering")
    parser.add_argument("--sqlite-cache-mib", type=int, default=64, help="Cache budget for disk variant")
    parser.add_argument("--report", type=Path, help="JSON report (default: a new file in the system temporary directory)")
    args = parser.parse_args()
    if any(n < 1 for n in (args.event_count, args.files, args.workers, args.passes, args.rule_count)):
        parser.error("counts must be positive")
    if args.events and not args.ruleset:
        parser.error("--events requires --ruleset")
    if args.sqlite_cache_mib < 1:
        parser.error("--sqlite-cache-mib must be positive")
    if "baseline" in args.variants and (args.baseline_root is None or not (args.baseline_root / "zircolite.py").is_file()):
        parser.error("baseline requires --baseline-root with zircolite.py")
    with tempfile.TemporaryDirectory(prefix="zircolite-benchmark-") as directory:
        temp = Path(directory)
        if args.events:
            events, rules = args.events.resolve(), args.ruleset.resolve()
        else:
            events = temp / "inputs"
            files = max(32, args.files) if args.scenario == "many-small" else args.files
            rules = make_corpus(events, args.scenario, args.event_count, files)
            if args.rule_count > 1:
                generated = orjson.loads(rules.read_bytes())
                generated.extend({"id": f"negative-{i}", "title": f"Absent literal {i}", "level": "high",
                                  "rule": [f"SELECT * FROM logs WHERE CommandLine LIKE '%absent-needle-{i}%'"]}  # noqa: S608 -- generated integer identifiers
                                 for i in range(args.rule_count - 1))
                rules.write_bytes(orjson.dumps(generated))
            if args.ruleset:
                rules = args.ruleset.resolve()
        combinations = [(variant, mode) for variant in args.variants for mode in args.modes]
        def result_key(variant, mode):
            return mode if args.variants == ["current"] else f"{variant}/{mode}"
        results = {result_key(variant, mode): [] for variant, mode in combinations}
        expected = None
        # Interleave modes to reduce bias from run order and warmed filesystem caches.
        for repeat in range(args.passes):
            offset = repeat % len(combinations)
            for variant, mode in combinations[offset:] + combinations[:offset]:
                output, log = temp / "output.json", temp / "console.txt"
                cli_root = args.baseline_root.resolve() if variant == "baseline" else ROOT
                prefix = [sys.executable, str(cli_root / "zircolite.py")]
                command = [*prefix, "-e", str(events),
                           "-r", str(rules), "-c", str(args.config.resolve()), "-o", str(output),
                           "--logfile", str(temp / "run.log"), "--quiet"]
                if mode != "auto":
                    command.append("--no-auto-mode")
                baseline_cli = cli_root / "zircolite" / "cli.py"
                supports_metrics = variant != "baseline" or (
                    baseline_cli.is_file() and "--performance-json" in baseline_cli.read_text()
                )
                metrics_path = temp / "performance.json" if supports_metrics else None
                if metrics_path:
                    command.extend(["--performance-json", str(metrics_path)])
                command.extend(VARIANTS[variant])
                working = temp / "working"
                working.mkdir(exist_ok=True)
                command.extend(["--working-db-dir", str(working)])
                if variant == "disk":
                    command.extend(["--sqlite-cache-mib", str(args.sqlite_cache_mib)])
                if mode == "sequential":
                    command.append("--no-parallel")
                elif mode != "auto":
                    command.extend(["--executor", mode, "--parallel-workers", str(args.workers)])
                if args.scenario == "transforms" and not args.events:
                    command.append("--all-transforms")
                run = measure(command, output, log, temp_dir=working, performance_path=metrics_path)
                if args.scenario in ("evtx-derived", "linux") and not args.events and not run["matches"]:
                    raise RuntimeError("Known-positive generated corpus produced no detections")
                identity = run["matches"], run["fingerprint"]
                if expected is not None and identity != expected:
                    raise RuntimeError(f"Detection mismatch in {variant}/{mode}: {identity} != {expected}")
                expected = identity
                key = result_key(variant, mode)
                results[key].append(run)
                print(f"{key:24} {run['seconds']:.3f}s  {run['peak_rss_mib']:.1f} MiB  {run['matches']} matches", flush=True)
                if any(working.iterdir()):
                    raise RuntimeError(f"Working database leaked after {key}")
        report = {"python": sys.version, "platform": platform.platform(), "cpus": os.cpu_count(),
                  "flattening": select_flatten_kernel("auto").__name__,
                  "sqlite": sqlite3.sqlite_version, "scenario": "external" if args.events else args.scenario,
                  "workers": args.workers, "results": results,
                  "event_count_requested": args.event_count, "files_requested": args.files,
                  "modes": args.modes,
                  "source_sha256": source_fingerprint(ROOT),
                  "baseline_sha256": source_fingerprint(args.baseline_root) if args.baseline_root else None,
                  "rule_count_requested": args.rule_count,
                  "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
                  "variants": args.variants, "sqlite_cache_mib": args.sqlite_cache_mib,
                  "ruleset_sha256": hashlib.sha256(rules.read_bytes()).hexdigest(),
                  "temp_scope": "visible working database files only; excludes unlinked result spools and SQLite scratch files",
                  "json_array_backend": getattr(jsonstream.ijson, "backend", "stdlib"),
                  "median_seconds": {mode: statistics.median(r["seconds"] for r in runs) for mode, runs in results.items()}}
        try:
            report["ijson"] = importlib.metadata.version("ijson")
        except importlib.metadata.PackageNotFoundError:
            report["ijson"] = None
        report["libraries"] = {}
        for name in ("PyYAML", "pyahocorasick", "pyroaring", "evtx", "orjson"):
            try:
                report["libraries"][name] = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                report["libraries"][name] = None
        report_path = args.report
        if report_path is None:
            with tempfile.NamedTemporaryFile(prefix="zircolite-benchmark-", suffix=".json", delete=False) as saved:
                report_path = Path(saved.name)
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Report: {report_path}")
        print(json.dumps(report["median_seconds"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
