"""Low-overhead, exclusive stage timings and serializable run diagnostics."""

import json
import os
import tempfile
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from time import perf_counter
from typing import Any

STAGES = ("setup", "ingestion", "indexes", "prefilter", "detection", "output", "finalization")
STAGE_LABELS = {
    "setup": "Setup / rules", "ingestion": "Ingestion", "indexes": "SQLite indexes",
    "prefilter": "Literal index", "detection": "Detection", "output": "Output",
    "finalization": "Finalization",
}


class FileMetrics:
    """Owned by one core; only ``data`` crosses a worker boundary.

    Nested stages pause their parent, so indexing inside ingestion and output
    inside detection are counted exactly once. No timers run per event.
    """

    def __init__(self):
        self.data: dict[str, Any] = {
            "sources": [], "seconds": dict.fromkeys(STAGES, 0.0),
            "flattening": {"requested": "auto", "selected": "unused", "reason": "database input"},
            "prefilter": [], "events": 0, "filtered_events": 0, "time_filtered_events": 0,
            "status": "running", "pruned_rules": 0,
            "rule_errors": {},
        }
        self._stack: list[list] = []

    @contextmanager
    def stage(self, name):
        started = perf_counter()
        frame = [started, 0.0]
        self._stack.append(frame)
        try:
            yield
        finally:
            elapsed = perf_counter() - started
            self._stack.pop()
            self.data["seconds"][name] += max(0.0, elapsed - frame[1])
            if self._stack:
                self._stack[-1][1] += elapsed


def timed_stage(name):
    """Time a synchronous core method, including exceptional exits."""
    def decorate(method):
        @wraps(method)
        def wrapped(self, *args, **kwargs):
            try:
                with self.metrics.stage(name):
                    return method(self, *args, **kwargs)
            except BaseException:
                from .shutdown import is_shutdown_requested

                self.metrics.data["status"] = "interrupted" if is_shutdown_requested() else "failed"
                raise
        return wrapped
    return decorate


def aggregate_stages(records):
    return {name: sum(record["seconds"].get(name, 0.0) for record in records) for name in STAGES}


def write_performance_report(path, report):
    """Replace a complete report atomically; leave no partial JSON on failure."""
    destination = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".zircolite-metrics-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, ensure_ascii=False)
            output.write("\n")
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
