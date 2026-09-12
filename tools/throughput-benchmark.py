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
from pathlib import Path

import orjson
import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zircolite import jsonstream  # noqa: E402


def make_corpus(directory, scenario, events, files):
    directory.mkdir()
    files = 1 if scenario == "large" else min(events, files)
    array_mode = scenario in ("array", "array-gzip")
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
        query += " AND CommandLine LIKE '%whoami%' ESCAPE '\\'"
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


def measure(command, output, log):
    peak = 0
    tree_access = True
    start = time.perf_counter()
    with log.open("wb") as transcript, subprocess.Popen(  # noqa: S603
        command, cwd=ROOT, stdout=transcript, stderr=subprocess.STDOUT
    ) as child:
        process = psutil.Process(child.pid)
        while child.poll() is None:
            try:
                rss = process.memory_info().rss
                try:
                    for descendant in process.children(recursive=True):
                        with suppress(psutil.Error, OSError):
                            rss += descendant.memory_info().rss
                except (psutil.Error, OSError):
                    tree_access = False
                peak = max(peak, rss)
            except (psutil.Error, OSError):
                pass
            time.sleep(0.02)
        code = child.wait()
    elapsed = time.perf_counter() - start
    if code:
        raise RuntimeError(f"CLI exited {code}: {log.read_text(errors='replace')[-4000:]}")
    count, digest = fingerprint(output)
    # Quiet mode suppresses worker presentation, but failure summaries still
    # identify broken rules and incomplete ingestion.
    transcript = log.read_text(errors="replace")
    if any(message in transcript for message in ("could not be evaluated", "failed to process", "Partial ingest")):
        raise RuntimeError(f"Incomplete benchmark run: {transcript[-4000:]}")
    return {"seconds": elapsed, "peak_rss_mib": peak / 1024**2,
            "matches": count, "fingerprint": digest,
            "rss_scope": "process-tree" if tree_access else "parent-only"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path)
    parser.add_argument("--ruleset", type=Path)
    parser.add_argument("--config", type=Path, default=ROOT / "config/config.yaml")
    parser.add_argument("--scenario", choices=("many-small", "large", "mixed", "gzip", "array", "array-gzip", "csv", "noisy", "transforms"), default="mixed")
    parser.add_argument("--event-count", type=int, default=100000)
    parser.add_argument("--files", type=int, default=4)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--passes", type=int, default=3)
    parser.add_argument("--modes", nargs="+", choices=("sequential", "thread", "process"), default=["sequential", "thread", "process"])
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if any(n < 1 for n in (args.event_count, args.files, args.workers, args.passes)):
        parser.error("counts must be positive")
    if args.events and not args.ruleset:
        parser.error("--events requires --ruleset")
    with tempfile.TemporaryDirectory(prefix="zircolite-benchmark-") as directory:
        temp = Path(directory)
        if args.events:
            events, rules = args.events.resolve(), args.ruleset.resolve()
        else:
            events = temp / "inputs"
            files = max(32, args.files) if args.scenario == "many-small" else args.files
            rules = make_corpus(events, args.scenario, args.event_count, files)
        results = {mode: [] for mode in args.modes}
        expected = None
        # Interleave modes to reduce bias from run order and warmed filesystem caches.
        for repeat in range(args.passes):
            for mode in args.modes[repeat % len(args.modes):] + args.modes[:repeat % len(args.modes)]:
                output, log = temp / "output.json", temp / "console.txt"
                command = [sys.executable, str(ROOT / "zircolite.py"), "-e", str(events),
                           "-r", str(rules), "-c", str(args.config.resolve()), "-o", str(output),
                           "--logfile", str(temp / "run.log"), "--quiet", "--no-auto-mode"]
                if mode == "sequential":
                    command.append("--no-parallel")
                else:
                    command.extend(["--executor", mode, "--parallel-workers", str(args.workers)])
                if args.scenario == "transforms" and not args.events:
                    command.append("--all-transforms")
                run = measure(command, output, log)
                identity = run["matches"], run["fingerprint"]
                if expected is not None and identity != expected:
                    raise RuntimeError(f"Detection mismatch in {mode}: {identity} != {expected}")
                expected = identity
                results[mode].append(run)
                print(f"{mode:10} {run['seconds']:.3f}s  {run['peak_rss_mib']:.1f} MiB  {run['matches']} matches", flush=True)
        report = {"python": sys.version, "platform": platform.platform(), "cpus": os.cpu_count(),
                  "sqlite": sqlite3.sqlite_version, "scenario": "external" if args.events else args.scenario,
                  "workers": args.workers, "results": results,
                  "json_array_backend": getattr(jsonstream.ijson, "backend", "stdlib"),
                  "median_seconds": {mode: statistics.median(r["seconds"] for r in runs) for mode, runs in results.items()}}
        try:
            report["ijson"] = importlib.metadata.version("ijson")
        except importlib.metadata.PackageNotFoundError:
            report["ijson"] = None
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report["median_seconds"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
