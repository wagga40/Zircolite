#!/usr/bin/env python3
"""Time Zircolite, Hayabusa and Chainsaw on the same logs.

Each tool runs at its own defaults with its own rules, so this measures what a
user gets out of the box, not rule-for-rule engine speed. Runs are interleaved
and their order rotates every pass; warm-up passes fill the page cache and are
not recorded. Detections are counted after each run, outside the timed region.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

import orjson
import psutil

ROOT = Path(__file__).resolve().parent.parent
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# What each tool prints about the rules it loaded, read from its console
# output (and Zircolite's log file). Counts may carry thousands separators.
RULE_COUNT_PATTERNS = {
    "zircolite": {"loaded": r"\[\+\] ([\d,]+) rules loaded"},
    "hayabusa": {"loaded": r"Total detection rules: ([\d,]+)",
                 "after channel filter": r"Detection rules enabled after channel filter: ([\d,]+)"},
    "chainsaw": {"loaded": r"Loaded ([\d,]+) detection rules"},
}


def load_run_sampled():
    """throughput-benchmark.py owns the process-tree RSS sampler; share it."""
    path = Path(__file__).with_name("throughput-benchmark.py")
    spec = importlib.util.spec_from_file_location("throughput_benchmark", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module.run_sampled


def zircolite_prefix(args):
    if args.zircolite:
        return [str(args.zircolite)], args.zircolite.parent
    return [sys.executable, str(ROOT / "zircolite.py")], ROOT


def zircolite_command(args, out):
    output = out / "zircolite.json"
    prefix, cwd = zircolite_prefix(args)
    command = [*prefix, "-e", str(args.events), "-r", str(args.zircolite_ruleset),
               "-o", str(output), "-l", str(out / "zircolite.log")]
    return command, cwd, output


def hayabusa_command(args, out):
    output = out / "hayabusa.jsonl"
    source = "-d" if args.events.is_dir() else "-f"
    # -w skips the interactive rule wizard and keeps every default it would
    # offer; -q, -Q and -K only drop the banner, error log files and colour.
    command = [str(args.hayabusa), "dfir-timeline", source, str(args.events),
               "-w", "-q", "-Q", "-K", "-C", "-t", "jsonl", "-o", str(output)]
    return command, args.hayabusa.parent, output


def chainsaw_command(args, out):
    output = out / "chainsaw.jsonl"
    command = [str(args.chainsaw), "--no-banner", "hunt", str(args.events)]
    for directory in args.chainsaw_sigma:
        command.extend(["-s", str(directory)])
    if args.chainsaw_rules:
        command.extend(["-r", str(args.chainsaw_rules)])
    command.extend(["--mapping", str(args.chainsaw_mapping), "--jsonl", "-o", str(output)])
    return command, args.chainsaw.parent, output


def count_zircolite(path):
    """(detections, distinct rules) from Zircolite's JSON array of rule results.

    A merged ruleset ships one Sigma rule once per log source, under one id, so
    rules are counted by id to stay comparable with the other tools.
    """
    results = orjson.loads(path.read_bytes())
    detections = sum(len(result.get("matches", [])) for result in results)
    return detections, len({result.get("id") or result.get("title") for result in results})


def count_jsonl(path, rule_key, fallback_key):
    """(detections, distinct rules) from one-hit-per-line JSON output."""
    detections, rules = 0, set()
    with path.open("rb") as handle:
        for line in handle:
            if line.strip():
                record = orjson.loads(line)
                detections += 1
                rules.add(record.get(rule_key) or record.get(fallback_key))
    return detections, len(rules)


COUNTERS = {
    "zircolite": count_zircolite,
    "hayabusa": lambda path: count_jsonl(path, "RuleID", "RuleTitle"),
    "chainsaw": lambda path: count_jsonl(path, "id", "name"),
}

COMMANDS = {"zircolite": zircolite_command, "hayabusa": hayabusa_command, "chainsaw": chainsaw_command}


def rules_loaded(tool, text):
    text = ANSI.sub("", text)
    counts = {}
    for label, pattern in RULE_COUNT_PATTERNS[tool].items():
        match = re.search(pattern, text)
        if match:
            counts[label] = int(match.group(1).replace(",", ""))
    return counts


def tool_version(tool, args):
    if tool == "zircolite":
        prefix, cwd = zircolite_prefix(args)
        command = [*prefix, "-v"]
    elif tool == "hayabusa":
        command, cwd = [str(args.hayabusa), "help"], args.hayabusa.parent
    else:
        command, cwd = [str(args.chainsaw), "--version"], args.chainsaw.parent
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True,  # noqa: S603
                               errors="replace", timeout=120, check=False)
    match = re.search(rf"{tool}\s*(?:-\s*)?v?(\d+(?:\.\d+)+)", ANSI.sub("", completed.stdout + completed.stderr),
                      re.IGNORECASE)
    return match.group(1) if match else None


def git_head(path):
    """Commit and date of the checkout holding path, when it is one."""
    try:
        completed = subprocess.run(["git", "-C", str(path), "log", "-1", "--format=%H %cI"],  # noqa: S603, S607
                                   capture_output=True, text=True, check=False)
    except OSError:
        return None
    return completed.stdout.strip() or None


def events_summary(events):
    # Hidden files (.DS_Store and the like) are not logs any tool would read.
    files = [events] if events.is_file() else sorted(
        p for p in events.rglob("*") if p.is_file() and not p.name.startswith("."))
    return {"path": str(events), "files": len(files), "bytes": sum(p.stat().st_size for p in files)}


def markdown_table(tools):
    lines = ["| Tool | Version | Rules loaded | Wall time (median, min-max) | Peak RSS | Detections | Rules matched |",
             "|---|---|---:|---:|---:|---:|---:|"]
    for name, data in tools.items():
        seconds = [run["seconds"] for run in data["runs"]]
        peak = statistics.median(run["peak_rss_mib"] for run in data["runs"])
        loaded = " / ".join(f"{count:,}" for count in data["rules_loaded"].values()) or "?"
        lines.append(f"| {name} | {data['version'] or '?'} | {loaded} "
                     f"| {statistics.median(seconds):.1f} s ({min(seconds):.1f}-{max(seconds):.1f}) "
                     f"| {peak:,.0f} MiB | {data['detections']:,} | {data['rules_matched']:,} |")
    return "\n".join(lines)


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True, help="Log file or directory every tool reads")
    parser.add_argument("--zircolite", type=Path,
                        help="Zircolite executable (default: this checkout under the current interpreter)")
    parser.add_argument("--zircolite-ruleset", type=Path, default=ROOT / "rules" / "rules_windows_merged.json")
    parser.add_argument("--hayabusa", type=Path, help="Hayabusa binary; its rules/ and config/ are read beside it")
    parser.add_argument("--chainsaw", type=Path, help="Chainsaw binary")
    parser.add_argument("--chainsaw-sigma", type=Path, action="append", default=[],
                        help="Sigma rules directory for Chainsaw (repeatable)")
    parser.add_argument("--chainsaw-mapping", type=Path, help="Chainsaw mapping file for Sigma rules")
    parser.add_argument("--chainsaw-rules", type=Path, help="Chainsaw's own rules directory")
    parser.add_argument("--runs", type=int, default=3, help="Timed passes")
    parser.add_argument("--warmup", type=int, default=1, help="Unrecorded passes run first")
    parser.add_argument("--report", type=Path,
                        help="JSON report (default: a new file in the system temporary directory)")
    args = parser.parse_args(argv)
    if args.runs < 1 or args.warmup < 0:
        parser.error("--runs must be positive and --warmup not negative")
    if args.chainsaw and (args.chainsaw_mapping is None or not (args.chainsaw_sigma or args.chainsaw_rules)):
        parser.error("--chainsaw needs --chainsaw-mapping and --chainsaw-sigma or --chainsaw-rules")
    args.events = args.events.resolve()
    for name in ("zircolite", "zircolite_ruleset", "hayabusa", "chainsaw", "chainsaw_mapping", "chainsaw_rules"):
        if getattr(args, name) is not None:
            setattr(args, name, getattr(args, name).resolve())
    args.chainsaw_sigma = [directory.resolve() for directory in args.chainsaw_sigma]
    return args


def main(argv=None):
    args = parse_arguments(argv)
    run_sampled = load_run_sampled()
    names = ["zircolite"] + [name for name in ("hayabusa", "chainsaw") if getattr(args, name)]
    tools = {name: {"version": tool_version(name, args), "rules_loaded": {}, "runs": []} for name in names}
    expected = {}
    with tempfile.TemporaryDirectory(prefix="tool-benchmark-") as directory:
        out = Path(directory)
        for index in range(args.warmup + args.runs):
            offset = index % len(names)
            for name in names[offset:] + names[:offset]:
                command, cwd, output = COMMANDS[name](args, out)
                log = out / "zircolite.log"
                for stale in (output, log):
                    stale.unlink(missing_ok=True)
                console = out / f"{name}.console"
                code, seconds, peak, scope, _ = run_sampled(command, console, cwd=cwd)
                transcript = console.read_text(errors="replace")
                if code:
                    raise RuntimeError(f"{name} exited {code}: {transcript[-4000:]}")
                detections, rules = COUNTERS[name](output)
                if expected.setdefault(name, (detections, rules)) != (detections, rules):
                    raise RuntimeError(f"{name} changed its result between passes: "
                                       f"{(detections, rules)} != {expected[name]}")
                label = "warm-up" if index < args.warmup else f"pass {index - args.warmup + 1}"
                print(f"{label:8} {name:10} {seconds:8.2f}s {peak / 1024**2:9.1f} MiB {detections:>10,} detections",
                      flush=True)
                if index < args.warmup:
                    continue
                if name == "zircolite" and log.exists():
                    transcript += log.read_text(errors="replace")
                tools[name]["rules_loaded"] = rules_loaded(name, transcript)
                tools[name]["runs"].append({"seconds": seconds, "peak_rss_mib": peak / 1024**2, "rss_scope": scope})
                tools[name]["command"] = command
                tools[name]["detections"], tools[name]["rules_matched"] = detections, rules
    for data in tools.values():
        data["median_seconds"] = statistics.median(run["seconds"] for run in data["runs"])
    sources = {"zircolite_ruleset_sha256": hashlib.sha256(args.zircolite_ruleset.read_bytes()).hexdigest(),
               "zircolite_commit": git_head(ROOT)}
    if args.hayabusa:
        sources["hayabusa_rules"] = git_head(args.hayabusa.parent / "rules")
    for directory in args.chainsaw_sigma:
        sources[f"chainsaw_sigma:{directory.name}"] = git_head(directory)
    report = {"platform": platform.platform(), "machine": platform.machine(), "cpus": os.cpu_count(),
              "memory_gib": round(psutil.virtual_memory().total / 1024**3, 1),
              "events": events_summary(args.events), "runs": args.runs, "warmup": args.warmup,
              "sources": sources, "tools": tools}
    report_path = args.report
    if report_path is None:
        with tempfile.NamedTemporaryFile(prefix="tool-benchmark-", suffix=".json", delete=False) as saved:
            report_path = Path(saved.name)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Report: {report_path}")
    print(markdown_table(tools))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
