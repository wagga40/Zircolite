#!/usr/bin/env python3
"""
Measure Zircolite's event-flattening throughput on a fixed corpus.

Flattening (turning nested EVTX/JSON events into flat rows) is the dominant
cost when ingesting logs, so this harness isolates it from EVTX parsing, the
SQLite insert, and rule execution. It reads raw events once, then repeatedly
calls ``StreamingEventProcessor._flatten_event`` and reports events/second.

The first pass warms schema discovery and the seen-key cache, so the reported
numbers reflect steady-state flattening (the common case for a large file).

Example:
  pdm run python tools/flatten-benchmark.py --evtx sample.evtx
  pdm run python tools/flatten-benchmark.py --evtx /path/to/EVTX-ATTACK-SAMPLES \
      --max-events 20000 --passes 11 --config config/config.yaml
"""

from __future__ import annotations

import argparse
import logging
import statistics
import sys
import time
from argparse import Namespace
from pathlib import Path

import orjson
from evtx import PyEvtxParser

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zircolite import ProcessingConfig, StreamingEventProcessor


def collect_raw_events(path: Path, limit: int) -> list:
    """Parse up to *limit* raw (pre-flatten) event dicts from EVTX file(s)."""
    files = sorted(path.rglob("*.evtx")) if path.is_dir() else [path]

    raws: list = []
    for evtx_file in files:
        try:
            parser = PyEvtxParser(str(evtx_file))
            for record in parser.records_json():
                if not record:
                    continue
                raws.append(orjson.loads(record["data"]))
                if len(raws) >= limit:
                    return raws
        except Exception:
            # Skip unreadable/non-record captures and keep collecting.
            continue
    return raws


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--evtx", required=True, help="Path to an EVTX file or a directory of them"
    )
    ap.add_argument(
        "--config", default="config/config.yaml", help="Field mappings config file"
    )
    ap.add_argument(
        "--max-events", type=int, default=20000, help="Max events to load and flatten"
    )
    ap.add_argument(
        "--passes", type=int, default=11, help="Timed passes over the loaded events"
    )
    args = ap.parse_args()

    logging.disable(logging.CRITICAL)

    raws = collect_raw_events(Path(args.evtx).expanduser(), args.max_events)
    if not raws:
        print("No events collected; check the --evtx path.", file=sys.stderr)
        return 1

    processor = StreamingEventProcessor(
        config_file=args.config,
        args_config=Namespace(
            evtx_input=True, all_transforms=False, transform_categories=None
        ),
        processing_config=ProcessingConfig(),
    )
    flatten = processor._flatten_event

    # Warm up so we measure steady-state flattening, not first-sighting work.
    for event in raws:
        flatten(event, "benchmark.evtx")

    durations = []
    for _ in range(args.passes):
        start = time.perf_counter()
        for event in raws:
            flatten(event, "benchmark.evtx")
        durations.append(time.perf_counter() - start)

    count = len(raws)
    median = statistics.median(durations)
    best = min(durations)
    print(f"events:        {count:,}")
    print(f"passes:        {args.passes}")
    print(f"median:        {median * 1000:.2f} ms  ({count / median:,.0f} events/s)")
    print(f"best:          {best * 1000:.2f} ms  ({count / best:,.0f} events/s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
