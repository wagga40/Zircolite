#!python3
"""
Processing modes for Zircolite.

This module centralises every file-processing path so that the CLI entry
point (``zircolite.py``) stays focused on argument parsing, validation,
and orchestration.

Contents
--------
- ``ProcessingContext`` – dataclass holding all runtime configuration
- Factory helpers: ``create_zircolite_core``, ``create_worker_core``,
  ``create_extractor``
- Processing modes:
    - ``process_unified_streaming`` / ``process_perfile_streaming``
    - ``process_parallel_streaming`` (multi-threaded per-file)
    - ``process_db_input``
"""

import csv
import logging
import random
import string
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

import orjson

from .config import ProcessingConfig, ExtractorConfig
from .console import (
    console,
    is_quiet,
    print_section,
    print_no_detections,
    build_file_tree,
    build_detection_table,
    LEVEL_PRIORITY,
)
from .core import ZircoliteCore
from .extractor import EvtxExtractor
from .parallel import ParallelConfig, MemoryAwareParallelProcessor
from .utils import MemoryTracker, create_silent_logger, load_field_mappings

if TYPE_CHECKING:
    from .rules import EventFilter


# ============================================================================
# PROCESSING CONTEXT
# ============================================================================

@dataclass
class ProcessingContext:
    """Holds all configuration needed for processing.

    The ``time_after_str`` and ``time_before_str`` attributes are computed
    once in ``__post_init__`` so that factory functions never repeat the
    ``time.strftime`` conversion.
    """

    config: str
    logger: logging.Logger
    no_output: bool
    events_after: time.struct_time
    events_before: time.struct_time
    limit: int
    csv_mode: bool
    time_field: str
    hashes: bool
    db_location: str
    delimiter: str
    rulesets: list
    rule_filters: Optional[list]
    outfile: str
    ready_for_templating: bool
    package: bool
    dbfile: Optional[str]
    keepflat: bool
    memory_tracker: MemoryTracker
    event_filter: Optional["EventFilter"] = None
    file_stats: Optional[list] = None
    total_filtered_events: int = 0
    total_events: int = 0
    workers_used: int = 1

    # Cached formatted time strings (computed in __post_init__)
    time_after_str: str = field(init=False, repr=False)
    time_before_str: str = field(init=False, repr=False)

    def __post_init__(self):
        self.time_after_str = time.strftime("%Y-%m-%dT%H:%M:%S", self.events_after)
        self.time_before_str = time.strftime("%Y-%m-%dT%H:%M:%S", self.events_before)


# ============================================================================
# FACTORY HELPERS
# ============================================================================

def create_zircolite_core(
    ctx: ProcessingContext,
    db_location: Optional[str] = None,
    disable_progress: bool = False,
) -> ZircoliteCore:
    """Create a ``ZircoliteCore`` instance with standard configuration."""
    proc_config = ProcessingConfig(
        time_after=ctx.time_after_str,
        time_before=ctx.time_before_str,
        time_field=ctx.time_field,
        hashes=ctx.hashes,
        disable_progress=disable_progress,
        db_location=db_location or ctx.db_location,
        no_output=ctx.no_output,
        csv_mode=ctx.csv_mode,
        delimiter=ctx.delimiter,
        limit=ctx.limit,
    )
    return ZircoliteCore(ctx.config, proc_config, logger=ctx.logger)


def create_worker_core(ctx: ProcessingContext, worker_id: int) -> ZircoliteCore:
    """Create a ``ZircoliteCore`` with a silent logger for parallel workers."""
    silent_logger = create_silent_logger(f"zircolite_worker_{worker_id}")
    proc_config = ProcessingConfig(
        time_after=ctx.time_after_str,
        time_before=ctx.time_before_str,
        time_field=ctx.time_field,
        hashes=ctx.hashes,
        disable_progress=True,
        db_location=":memory:",
        no_output=True,
        csv_mode=ctx.csv_mode,
        delimiter=ctx.delimiter,
        limit=ctx.limit,
    )
    return ZircoliteCore(ctx.config, proc_config, logger=silent_logger)


def create_extractor(args, logger, input_type: str) -> Optional[EvtxExtractor]:
    """Create extractor for formats that need conversion."""
    if input_type in ("xml", "sysmon_linux", "auditd", "evtxtract"):
        extractor_config = ExtractorConfig(
            xml_logs=(input_type == "xml"),
            sysmon4linux=(input_type == "sysmon_linux"),
            auditd_logs=(input_type == "auditd"),
            evtxtract=(input_type == "evtxtract"),
            csv_input=(input_type == "csv"),
            encoding=args.logs_encoding,
        )
        return EvtxExtractor(extractor_config, logger=logger)
    return None


# ============================================================================
# HELPERS
# ============================================================================

def _unpack_streaming_result(result) -> tuple:
    """Safely unpack (total_events, filtered_count) from run_streaming."""
    return result if isinstance(result, tuple) else (result, 0)


def _sort_key_severity(result: dict) -> tuple:
    """Sort key: critical first, then by descending event count."""
    level = result.get("rule_level", "unknown").lower()
    return (LEVEL_PRIORITY.get(level, 5), -result.get("count", 0))


class _ThreadSafeWriter:
    """Wraps a binary file handle with a lock for concurrent writes.

    Each ``write`` call is atomic so that JSONL lines from parallel
    workers don't interleave.
    """

    __slots__ = ('_fh', '_lock')

    def __init__(self, fh):
        self._fh = fh
        self._lock = threading.Lock()

    def write(self, data):
        with self._lock:
            self._fh.write(data)


@contextmanager
def _keepflat_context(ctx: 'ProcessingContext', *, thread_safe: bool = False):
    """Open a single keepflat JSONL file if requested, else yield ``None``.

    The caller never needs to manage the file lifecycle — this context
    manager handles creation, logging, and closing.

    Args:
        ctx: Processing context (checks ``ctx.keepflat``).
        thread_safe: If True, yield a ``_ThreadSafeWriter`` wrapper
                     instead of the raw file handle (for parallel mode).
    """
    if not ctx.keepflat:
        yield None
        return
    filename = "flattened_events_{}.json".format(
        ''.join(random.SystemRandom().choice(
            string.ascii_uppercase + string.digits) for _ in range(4))
    )
    ctx.logger.info(f"[+] Saving flattened events to: [cyan]{filename}[/]")
    fh = open(filename, 'wb', buffering=1048576)
    try:
        yield _ThreadSafeWriter(fh) if thread_safe else fh
    finally:
        fh.close()


# ============================================================================
# UNIFIED STREAMING
# ============================================================================

def process_unified_streaming(
    ctx: ProcessingContext,
    file_list: List[Path],
    input_type: str,
    extractor,
    args,
) -> tuple:
    """Process all files into a single database using streaming mode."""
    ctx.logger.info(
        f"[+] Loading all [yellow]{len(file_list)}[/] file(s) into a single unified database"
    )

    disable_nested = len(file_list) > 1 or is_quiet()
    zircolite_core = create_zircolite_core(ctx, disable_progress=disable_nested)

    with _keepflat_context(ctx) as kf:
        result = zircolite_core.run_streaming(
            file_list,
            input_type=input_type,
            args_config=args,
            extractor=extractor,
            disable_progress=disable_nested,
            event_filter=ctx.event_filter,
            return_filtered_count=True,
            keepflat_file=kf,
        )
    total_events, filtered_count = _unpack_streaming_result(result)
    ctx.total_filtered_events += filtered_count
    ctx.total_events += total_events
    ctx.memory_tracker.sample()

    if ctx.dbfile:
        zircolite_core.save_db_to_disk(ctx.dbfile)
        ctx.logger.info(f"[+] Saved unified database to: [cyan]{ctx.dbfile}[/]")
        ctx.memory_tracker.sample()

    zircolite_core.load_ruleset_from_var(
        ruleset=ctx.rulesets, rule_filters=ctx.rule_filters
    )

    if ctx.limit > 0:
        ctx.logger.info(
            f"[+] Limited mode: detections with more than [yellow]{ctx.limit}[/] events will be discarded"
        )

    ctx.logger.info(
        f"[+] Executing ruleset against unified database "
        f"([magenta]{total_events:,}[/] events) - "
        f"[yellow]{len(zircolite_core.ruleset)}[/] rules"
    )
    zircolite_core.execute_ruleset(
        ctx.outfile,
        write_mode="w",
        keep_results=True,
        last_ruleset=True,
    )
    ctx.memory_tracker.sample()

    results = list(zircolite_core.full_results) if zircolite_core.full_results else []
    return zircolite_core, results


# ============================================================================
# PER-FILE STREAMING
# ============================================================================

def process_perfile_streaming(
    ctx: ProcessingContext,
    file_list: List[Path],
    input_type: str,
    extractor,
    args,
) -> tuple:
    """Process each file separately using streaming mode."""
    ctx.logger.info(
        f"[+] Processing [yellow]{len(file_list)}[/] file(s) separately in streaming mode"
    )

    disable_nested = len(file_list) > 1 or is_quiet()
    all_results = []
    first_file = True
    file_stats = []

    # Always accumulate results – they are needed for the ATT&CK Coverage
    # panel in the summary dashboard, not only for templates/packaging.

    with _keepflat_context(ctx) as kf:
        for file_idx, log_file in enumerate(file_list):
            file_name = Path(log_file).name
            if len(file_list) > 1:
                ctx.logger.info(
                    f"[+] Processing file [cyan]{file_idx + 1}[/]/[cyan]{len(file_list)}[/]: [cyan]{file_name}[/]"
                )
            else:
                ctx.logger.info(f"[+] Processing file: [cyan]{file_name}[/]")

            zircolite_core = create_zircolite_core(
                ctx, db_location=":memory:", disable_progress=disable_nested
            )

            result = zircolite_core.run_streaming(
                [log_file],
                input_type=input_type,
                args_config=args,
                extractor=extractor,
                disable_progress=disable_nested,
                event_filter=ctx.event_filter,
                return_filtered_count=True,
                keepflat_file=kf,
            )
            event_count, filtered_count = _unpack_streaming_result(result)
            ctx.total_filtered_events += filtered_count
            ctx.total_events += event_count
            ctx.memory_tracker.sample()

            if ctx.dbfile:
                file_db_name = (
                    f"{Path(ctx.dbfile).stem}_{file_name}{Path(ctx.dbfile).suffix}"
                )
                zircolite_core.save_db_to_disk(file_db_name)
                ctx.logger.info(
                    f"[+] Saved database for [cyan]{file_name}[/] to: [cyan]{file_db_name}[/]"
                )
                ctx.memory_tracker.sample()

            zircolite_core.load_ruleset_from_var(
                ruleset=ctx.rulesets, rule_filters=ctx.rule_filters
            )

            if ctx.limit > 0 and first_file:
                ctx.logger.info(
                    f"[+] Limited mode: detections with more than [yellow]{ctx.limit}[/] events will be discarded"
                )

            is_last_file = file_idx == len(file_list) - 1
            write_mode = "w" if first_file else "a"

            ctx.logger.info(
                f"[+] Executing ruleset for [cyan]{file_name}[/] - "
                f"[yellow]{len(zircolite_core.ruleset)}[/] rules"
            )
            zircolite_core.execute_ruleset(
                ctx.outfile,
                write_mode=write_mode,
                keep_results=True,
                last_ruleset=is_last_file,
                source_label=file_name,
            )
            ctx.memory_tracker.sample()

            file_detection_count = (
                len(zircolite_core.full_results) if zircolite_core.full_results else 0
            )
            file_stats.append(
                {
                    "name": file_name,
                    "events": event_count,
                    "detections": file_detection_count,
                    "filtered": filtered_count,
                }
            )

            if zircolite_core.full_results:
                all_results.extend(zircolite_core.full_results)

            zircolite_core.close()
            first_file = False

    if len(file_list) > 1 and file_stats and not is_quiet():
        console.print()
        tree = build_file_tree(f"Processed {len(file_list)} files", file_stats)
        console.print(tree)
        console.print()

    ctx.file_stats = file_stats
    return None, all_results


# ============================================================================
# DATABASE INPUT
# ============================================================================

def process_db_input(ctx: ProcessingContext, args) -> tuple:
    """Process from an existing database file."""
    ctx.logger.info(f"[+] Creating model from disk: [cyan]{args.evtx}[/]")

    zircolite_core = create_zircolite_core(ctx, disable_progress=is_quiet())
    zircolite_core.load_db_in_memory(args.evtx)
    ctx.memory_tracker.sample()

    zircolite_core.load_ruleset_from_var(
        ruleset=ctx.rulesets, rule_filters=ctx.rule_filters
    )

    if ctx.limit > 0:
        ctx.logger.info(
            f"[+] Limited mode: detections with more than [yellow]{ctx.limit}[/] events will be discarded"
        )

    ctx.logger.info(
        f"[+] Executing ruleset - [yellow]{len(zircolite_core.ruleset)}[/] rules"
    )
    zircolite_core.execute_ruleset(
        ctx.outfile,
        write_mode="w",
        keep_results=True,
        last_ruleset=True,
    )
    ctx.memory_tracker.sample()

    results = list(zircolite_core.full_results) if zircolite_core.full_results else []
    return zircolite_core, results


# ============================================================================
# PARALLEL PROCESSING – worker function (extracted from closure)
# ============================================================================

def process_single_file_worker(
    log_file: Path,
    ctx: ProcessingContext,
    input_type: str,
    extractor,
    args,
    *,
    counter_lock: threading.Lock,
    worker_counter: list,
    total_filtered_count: list,
    thread_local: threading.local,
    raw_config: Optional[dict] = None,
    keepflat_file=None,
) -> tuple:
    """Process a single file inside a parallel worker thread.

    Returns ``(event_count, file_data_dict)``.  This is a top-level function
    (not a closure) to improve readability and testability.
    """
    file_name = Path(log_file).name
    try:
        # Get or create thread-local ZircoliteCore
        if not hasattr(thread_local, "core"):
            with counter_lock:
                worker_id = worker_counter[0]
                worker_counter[0] += 1
            thread_local.core = create_worker_core(ctx, worker_id)
        else:
            # Reuse table schema across files: DELETE keeps columns intact so
            # _ensure_columns_exist_cached sees them immediately, avoiding
            # redundant ALTER TABLE statements for files with similar structure.
            try:
                thread_local.core.db_connection.execute("DELETE FROM logs")
            except Exception:
                pass  # Table may not exist if previous file failed early
            thread_local.core._cursor = None

        core = thread_local.core

        event_count, filtered_count = core.run_streaming(
            [log_file],
            input_type=input_type,
            args_config=args,
            extractor=extractor,
            disable_progress=True,
            event_filter=ctx.event_filter,
            return_filtered_count=True,
            keepflat_file=keepflat_file,
            _raw_config=raw_config,
        )

        with counter_lock:
            total_filtered_count[0] += filtered_count

        if event_count == 0:
            return (
                0,
                {
                    "name": file_name,
                    "results": [],
                    "events": 0,
                    "filtered": filtered_count,
                },
            )

        core.load_ruleset_from_var(
            ruleset=ctx.rulesets, rule_filters=ctx.rule_filters
        )
        core.full_results = []

        core.execute_ruleset(
            ctx.outfile,
            write_mode="w",
            keep_results=True,
            last_ruleset=True,
            show_table=False,
        )

        file_results = list(core.full_results) if core.full_results else []
        return (
            event_count,
            {
                "name": file_name,
                "results": file_results,
                "events": event_count,
                "filtered": filtered_count,
            },
        )

    except Exception as e:
        return (
            0,
            {
                "name": file_name,
                "results": [],
                "events": 0,
                "filtered": 0,
                "error": str(e),
            },
        )


# ============================================================================
# PARALLEL STREAMING
# ============================================================================

class _IncrementalResultWriter:
    """Thread-safe, incremental writer for parallel detection results.

    Writes each detection result to disk as it arrives rather than buffering
    everything in memory and flushing at the end.  Supports both JSON-array
    and CSV output modes.
    """

    def __init__(self, ctx: ProcessingContext):
        self._ctx = ctx
        self._fh = None
        self._csv_writer = None
        self._first_json = True
        self._lock = threading.Lock()

    def __enter__(self):
        if self._ctx.no_output:
            return self
        if self._ctx.csv_mode:
            self._fh = open(self._ctx.outfile, "w", encoding="utf-8", newline="")
        else:
            self._fh = open(self._ctx.outfile, "wb")
            self._fh.write(b"[")
        return self

    def write_file_results(self, file_data) -> None:
        """Write all detection results from a single file's output dict."""
        if self._fh is None or not isinstance(file_data, dict):
            return
        for result in file_data.get("results", []):
            self._write_one(result)

    def _write_one(self, result: dict) -> None:
        with self._lock:
            if self._ctx.csv_mode:
                self._write_csv(result)
            else:
                self._write_json(result)

    def _write_json(self, result: dict) -> None:
        if not self._first_json:
            self._fh.write(b",\n")
        self._first_json = False
        self._fh.write(orjson.dumps(result, option=orjson.OPT_INDENT_2))

    def _write_csv(self, result: dict) -> None:
        title = result.get("title", "")
        description = (
            (result.get("description") or "").replace("\n", "").replace("\r", "")
        )
        level = result.get("rule_level", "")
        count = result.get("count", 0)
        for row in result.get("matches", []):
            if self._csv_writer is None:
                fieldnames = [
                    "rule_title", "rule_description", "rule_level", "rule_count",
                ] + sorted(row.keys())
                self._csv_writer = csv.DictWriter(
                    self._fh,
                    delimiter=self._ctx.delimiter,
                    fieldnames=fieldnames,
                    extrasaction="ignore",
                )
                self._csv_writer.writeheader()
            clean_row = {
                k: ("" if v is None else str(v)).replace("\n", "").replace("\r", "")
                for k, v in row.items()
            }
            self._csv_writer.writerow({
                "rule_title": title,
                "rule_description": description,
                "rule_level": level,
                "rule_count": count,
                **clean_row,
            })

    def __exit__(self, *args):
        if self._fh is not None:
            if not self._ctx.csv_mode:
                self._fh.write(b"]")
            self._fh.close()
            self._fh = None


def _write_parallel_results(ctx: ProcessingContext, all_results: list) -> None:
    """Write combined parallel results to the output file.

    Uses binary I/O for JSON (avoids an unnecessary decode/encode
    round-trip) and text I/O for CSV.

    .. deprecated::
        Kept for backward compatibility.  New code should use
        :class:`_IncrementalResultWriter` which writes results as they
        arrive instead of buffering in memory.
    """
    if ctx.no_output:
        return

    if ctx.csv_mode:
        all_keys: set = set()
        for result in all_results:
            for row in result.get("matches", []):
                all_keys.update(row.keys())
        fieldnames = [
            "rule_title",
            "rule_description",
            "rule_level",
            "rule_count",
        ] + sorted(all_keys)
        with open(ctx.outfile, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f, delimiter=ctx.delimiter, fieldnames=fieldnames, extrasaction="ignore"
            )
            writer.writeheader()
            for result in all_results:
                title = result.get("title", "")
                description = (
                    (result.get("description") or "")
                    .replace("\n", "")
                    .replace("\r", "")
                )
                level = result.get("rule_level", "")
                count = result.get("count", 0)
                for row in result.get("matches", []):
                    clean_row = {
                        k: ("" if v is None else str(v))
                        .replace("\n", "")
                        .replace("\r", "")
                        for k, v in row.items()
                    }
                    writer.writerow(
                        {
                            "rule_title": title,
                            "rule_description": description,
                            "rule_level": level,
                            "rule_count": count,
                            **clean_row,
                        }
                    )
    else:
        with open(ctx.outfile, "wb") as f:
            f.write(b"[")
            for i, result in enumerate(all_results):
                if i > 0:
                    f.write(b",\n")
                f.write(orjson.dumps(result, option=orjson.OPT_INDENT_2))
            f.write(b"]")


def process_parallel_streaming(
    ctx: ProcessingContext,
    file_list: List[Path],
    input_type: str,
    extractor,
    args,
    recommended_workers: Optional[int] = None,
) -> tuple:
    """Process files in parallel using memory-aware parallel processor."""

    parallel_config = ParallelConfig(
        max_workers=getattr(args, "parallel_workers", None) or recommended_workers,
        memory_limit_percent=getattr(args, "parallel_memory_limit", 75.0),
        adaptive_workers=True,
        sort_by_size=True,
        adaptive_memory=True,
    )

    if len(file_list) < 2:
        return process_perfile_streaming(ctx, file_list, input_type, extractor, args)

    # Pre-parse field mappings once so workers skip redundant disk reads
    raw_config = load_field_mappings(ctx.config)

    # Shared mutable state for workers
    thread_local = threading.local()
    worker_counter = [0]
    counter_lock = threading.Lock()
    total_filtered_count = [0]
    errors: list = []

    processor = MemoryAwareParallelProcessor(
        config=parallel_config, logger=ctx.logger
    )

    all_results: list = []
    file_stats: list = []

    def _on_file_complete(file_data) -> None:
        if not isinstance(file_data, dict):
            return
        file_results = file_data.get("results", [])
        if file_results:
            all_results.extend(file_results)
        file_stats.append({
            "name": file_data.get("name", "unknown"),
            "events": file_data.get("events", 0),
            "detections": len(file_results),
            "filtered": file_data.get("filtered", 0),
        })

    # Incremental writing streams JSON results to disk as files complete.
    # CSV mode is excluded: the CSV DictWriter header is fixed at creation
    # time, so columns from later files would be silently dropped.  CSV
    # falls back to _write_parallel_results which collects all columns first.
    use_incremental = not ctx.csv_mode

    with _keepflat_context(ctx, thread_safe=True) as kf:

        def _process_file(log_file: Path) -> tuple:
            """Thin wrapper adapting the top-level worker to the parallel API."""
            return process_single_file_worker(
                log_file,
                ctx,
                input_type,
                extractor,
                args,
                counter_lock=counter_lock,
                worker_counter=worker_counter,
                total_filtered_count=total_filtered_count,
                thread_local=thread_local,
                raw_config=raw_config,
                keepflat_file=kf,
            )

        if use_incremental:
            with _IncrementalResultWriter(ctx) as writer:

                def _on_result(file_data) -> None:
                    _on_file_complete(file_data)
                    writer.write_file_results(file_data)

                results_list, stats = processor.process_files_parallel(
                    file_list,
                    _process_file,
                    desc="Processing",
                    disable_progress=is_quiet(),
                    on_result=_on_result,
                )
        else:
            results_list, stats = processor.process_files_parallel(
                file_list,
                _process_file,
                desc="Processing",
                disable_progress=is_quiet(),
                on_result=_on_file_complete,
            )
            _write_parallel_results(ctx, all_results)

    # Collect errors
    for file_data in results_list:
        if isinstance(file_data, dict) and file_data.get("error"):
            errors.append((file_data.get("name", "unknown"), file_data["error"]))

    if errors:
        ctx.logger.error(f"[!] {len(errors)} file(s) failed to process:")
        for fname, err in errors[:5]:
            ctx.logger.error(f"    \u2192 {fname}: {err}")
        if len(errors) > 5:
            ctx.logger.error(f"    \u2192 ... and {len(errors) - 5} more")

    ctx.memory_tracker.sample()
    ctx.file_stats = file_stats
    ctx.workers_used = stats.workers_used

    # Display detection table
    print_section("Detection Results")
    if all_results:
        rule_summary: dict = {}
        for result in all_results:
            title = result.get("title", "Unknown Rule")
            level = result.get("rule_level", "unknown")
            count = result.get("count", 0)
            tags = result.get("tags", [])
            if title in rule_summary:
                rule_summary[title]["count"] += count
            else:
                rule_summary[title] = {"level": level, "count": count, "tags": tags}

        aggregated_results = [
            {
                "title": title,
                "rule_level": info["level"],
                "count": info["count"],
                "tags": info.get("tags", []),
            }
            for title, info in sorted(
                rule_summary.items(), key=lambda item: _sort_key_severity(
                    {"rule_level": item[1]["level"], "count": item[1]["count"]}
                )
            )
        ]

        if not is_quiet() and aggregated_results:
            console.print()
            console.print(build_detection_table(aggregated_results))
            console.print()
    elif not is_quiet():
        print_no_detections()

    # File tree
    if len(file_list) > 1 and file_stats and not is_quiet():
        tree = build_file_tree(f"Processed {len(file_list)} files", file_stats)
        console.print(tree)
        console.print()

    # Propagate stats
    filtered_count = total_filtered_count[0]
    ctx.total_filtered_events += filtered_count
    total_events = stats.total_events
    ctx.total_events += total_events
    if filtered_count > 0:
        ctx.logger.info(
            f"[+] Total events processed: [magenta]{total_events:,}[/] "
            f"([dim]{filtered_count:,} events filtered out[/])"
        )

    return None, all_results
