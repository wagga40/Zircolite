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

import argparse
import csv
import logging
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, TYPE_CHECKING

import orjson

from .config import ProcessingConfig, ExtractorConfig
from .console import (
    console,
    is_quiet,
    make_file_link,
    print_section,
    print_no_detections,
    build_file_tree,
    build_detection_table,
    sort_key_severity,
)
from .core import ZircoliteCore
from .extractor import EvtxExtractor
from .formats import format_by_name
from .parallel import ParallelConfig, MemoryAwareParallelProcessor
from .shutdown import is_shutdown_requested
from .utils import (
    MemoryTracker,
    create_silent_logger,
    load_field_mappings,
    quit_on_error,
    random_suffix,
    sanitize_row_for_csv,
    sanitize_value_for_csv,
)

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
    total_filtered_events: int = 0
    total_events: int = 0
    workers_used: int = 1
    profile_rules: bool = False
    archive_password: Optional[str] = None
    add_index: list = field(default_factory=list)
    remove_index: list = field(default_factory=list)
    auto_index_top_n: int = 0
    strict_evtx: bool = False
    # Inputs that failed to ingest; --remove-events skips these
    failed_files: set = field(default_factory=set)

    # Cached formatted time strings (computed in __post_init__)
    time_after_str: str = field(init=False, repr=False)
    time_before_str: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
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
        profile_rules=ctx.profile_rules,
        archive_password=ctx.archive_password,
        add_index=ctx.add_index,
        remove_index=ctx.remove_index,
        auto_index_top_n=ctx.auto_index_top_n,
        strict_evtx=ctx.strict_evtx,
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
        archive_password=ctx.archive_password,
        add_index=ctx.add_index,
        remove_index=ctx.remove_index,
        auto_index_top_n=ctx.auto_index_top_n,
        strict_evtx=ctx.strict_evtx,
    )
    return ZircoliteCore(ctx.config, proc_config, logger=silent_logger)


def create_extractor(
    args: argparse.Namespace, logger: logging.Logger, input_type: str
) -> Optional[EvtxExtractor]:
    """Create extractor for formats that need conversion."""
    spec = format_by_name(input_type)
    if spec is None or spec.extractor_flag is None:
        return None
    # ExtractorConfig derives its default encoding from the format flags in
    # __post_init__, so the flag has to go through the constructor rather than
    # being set afterwards.
    flags: Dict[str, Any] = {spec.extractor_flag: True}
    extractor_config = ExtractorConfig(encoding=args.logs_encoding, **flags)
    return EvtxExtractor(extractor_config, logger=logger)


# ============================================================================
# HELPERS
# ============================================================================

def _unpack_streaming_result(
    result: Union[int, Tuple[int, int]]
) -> Tuple[int, int]:
    """Safely unpack (total_events, filtered_count) from run_streaming."""
    return result if isinstance(result, tuple) else (result, 0)


class _ThreadSafeWriter:
    """Wraps a binary file handle with a lock for concurrent writes.

    Each ``write`` call is atomic so that JSONL lines from parallel
    workers don't interleave.
    """

    __slots__ = ('_fh', '_lock')

    def __init__(self, fh: Any) -> None:
        self._fh = fh
        self._lock = threading.Lock()

    def write(self, data: bytes) -> None:
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
    filename = "flattened_events_{}.json".format(random_suffix(4))
    ctx.logger.info(f"[+] Saving flattened events to: {make_file_link(filename)}")
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
    extractor: Optional[EvtxExtractor],
    args: argparse.Namespace,
) -> Tuple[Any, ...]:
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
        ctx.logger.info(f"[+] Saved unified database to: {make_file_link(ctx.dbfile)}")
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
        disable_progress=is_quiet(),
    )
    ctx.memory_tracker.sample()

    ctx.failed_files |= zircolite_core.failed_files
    results = list(zircolite_core.full_results) if zircolite_core.full_results else []
    return zircolite_core, results


# ============================================================================
# PER-FILE STREAMING
# ============================================================================

def process_perfile_streaming(
    ctx: ProcessingContext,
    file_list: List[Path],
    input_type: str,
    extractor: Optional[EvtxExtractor],
    args: argparse.Namespace,
) -> Tuple[Any, ...]:
    """Process each file separately using streaming mode."""
    ctx.logger.info(
        f"[+] Processing [yellow]{len(file_list)}[/] file(s) separately in streaming mode"
    )

    disable_nested = len(file_list) > 1 or is_quiet()
    all_results = []
    first_file = True
    file_stats = []
    profiling_core = create_zircolite_core(ctx, disable_progress=disable_nested) if ctx.profile_rules else None

    # Always accumulate results – they are needed for the ATT&CK Coverage
    # panel in the summary dashboard, not only for templates/packaging.

    zircolite_core = create_zircolite_core(
        ctx, db_location=":memory:", disable_progress=disable_nested
    )
    try:
        with _keepflat_context(ctx) as kf:
            for file_idx, log_file in enumerate(file_list):
                if is_shutdown_requested():
                    break
                file_name = Path(log_file).name
                file_link = make_file_link(str(log_file), file_name)
                if len(file_list) > 1:
                    ctx.logger.info(
                        f"[+] Processing file [cyan]{file_idx + 1}[/]/[cyan]{len(file_list)}[/]: {file_link}"
                    )
                else:
                    ctx.logger.info(f"[+] Processing file: {file_link}")

                if file_idx > 0:
                    try:
                        if zircolite_core.db_connection is not None:
                            zircolite_core.db_connection.execute("DELETE FROM logs")
                    except Exception as exc:
                        ctx.logger.debug(
                            f"Failed to clear 'logs' table between files: {exc}"
                        )
                    zircolite_core._cursor = None

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
                    dbfile_path = Path(ctx.dbfile)
                    parent = dbfile_path.parent
                    if parent != Path("."):
                        parent.mkdir(parents=True, exist_ok=True)
                    file_db_name = str(
                        parent / f"{dbfile_path.stem}_{file_name}{dbfile_path.suffix}"
                    )
                    if Path(file_db_name).exists():
                        # Two input files share the same basename: add the
                        # file index to keep the DB path unique
                        file_db_name = str(
                            parent / f"{dbfile_path.stem}_{file_idx + 1}_{file_name}{dbfile_path.suffix}"
                        )
                    zircolite_core.save_db_to_disk(file_db_name)
                    ctx.logger.info(
                        f"[+] Saved database for {file_link} to: {make_file_link(file_db_name)}"
                    )
                    ctx.memory_tracker.sample()

                zircolite_core.load_ruleset_from_var(
                    ruleset=ctx.rulesets, rule_filters=ctx.rule_filters
                )
                zircolite_core.full_results = []

                if ctx.limit > 0 and first_file:
                    ctx.logger.info(
                        f"[+] Limited mode: detections with more than [yellow]{ctx.limit}[/] events will be discarded"
                    )

                write_mode = "w" if first_file else "a"

                ctx.logger.info(
                    f"[+] Executing ruleset for {file_link} - "
                    f"[yellow]{len(zircolite_core.ruleset)}[/] rules"
                )
                zircolite_core.execute_ruleset(
                    ctx.outfile,
                    write_mode=write_mode,
                    keep_results=True,
                    last_ruleset=False,
                    source_label=file_name,
                    disable_progress=is_quiet(),
                )
                ctx.memory_tracker.sample()

                file_detection_count = (
                    len(zircolite_core.full_results)
                    if zircolite_core.full_results
                    else 0
                )
                file_stats.append(
                    {
                        "name": file_name,
                        "path": str(log_file),
                        "events": event_count,
                        "detections": file_detection_count,
                        "filtered": filtered_count,
                    }
                )

                if zircolite_core.full_results:
                    all_results.extend(zircolite_core.full_results)

                if profiling_core is not None:
                    profiling_core.merge_profiling_data(zircolite_core)
                first_file = False
    finally:
        # Close the JSON array even when the loop was interrupted (Ctrl+C):
        # every execute_ruleset call above used last_ruleset=False
        if file_stats and not ctx.csv_mode and not zircolite_core.no_output:
            try:
                with open(ctx.outfile, 'a', encoding='utf-8', newline='') as fh:
                    fh.write(']')
            except OSError as exc:
                ctx.logger.debug(f"Could not finalize JSON output: {exc}")
        ctx.failed_files |= zircolite_core.failed_files
        zircolite_core.close()
        if profiling_core is not None:
            profiling_core.close()

    if len(file_list) > 1 and file_stats and not is_quiet():
        console.print()
        tree = build_file_tree(f"Processed {len(file_stats)} files", file_stats)
        console.print(tree)
        console.print()

    return profiling_core, all_results


# ============================================================================
# DATABASE INPUT
# ============================================================================

_DB_EXTENSIONS = ("db", "sqlite", "sqlite3")


def expand_db_path(
    path: Path, args: argparse.Namespace, logger: logging.Logger
) -> List[Path]:
    """Resolve a -D argument to a list of database files.

    A database is normally named explicitly, but pointing -D at a directory
    used to fail with "Database file does not exist: <dir>" while the
    auto-detected route handled the same input.
    """
    if not path.is_dir():
        return [path]

    patterns = (
        [f"*.{args.fileext.lstrip('.')}"]
        if getattr(args, "fileext", None)
        else [f"*.{ext}" for ext in _DB_EXTENSIONS]
    )
    walk = path.glob if getattr(args, "no_recursion", False) else path.rglob
    found = sorted({p for pattern in patterns for p in walk(pattern) if p.is_file()})
    if not found:
        # Fatal, like a single missing database: a run that analysed nothing
        # must not exit 0 while the summary advertises an output file
        quit_on_error(
            f"[red]    [-] No database file found in {path} "
            f"(looked for {', '.join(patterns)}); use [cyan]--fileext[/] to "
            "name a different extension[/]",
            logger,
        )
    return found


def process_db_input(
    ctx: ProcessingContext,
    args: argparse.Namespace,
    file_list: Optional[List[Path]] = None,
) -> Tuple[Any, ...]:
    """Process from existing database file(s).

    When *file_list* is provided (directory of DB files), each file is
    loaded, rules are executed, and results are aggregated — similar to
    per-file streaming mode.  When *file_list* is ``None`` (the ``-D`` path),
    ``args.evtx`` is used, and a directory there is expanded the same way the
    auto-detected path expands it.
    """
    if file_list:
        db_files = [Path(f) for f in file_list]
    else:
        db_files = expand_db_path(Path(args.evtx), args, ctx.logger)
    all_results: list = []
    first_file = True
    processed_any = False
    file_stats: list = []
    zircolite_core = create_zircolite_core(ctx, disable_progress=is_quiet())

    try:
        for file_idx, db_path in enumerate(db_files):
            file_name = db_path.name
            file_link = make_file_link(str(db_path), file_name)
            if len(db_files) > 1:
                ctx.logger.info(
                    f"[+] Loading database [cyan]{file_idx + 1}[/]/"
                    f"[cyan]{len(db_files)}[/]: {file_link}"
                )
            else:
                ctx.logger.info(f"[+] Creating model from disk: {file_link}")

            try:
                zircolite_core.load_db_in_memory(str(db_path))
            except (RuntimeError, sqlite3.Error) as e:
                if file_list is None:
                    quit_on_error(f"[red]    [-] {e}[/]", ctx.logger)
                ctx.logger.warning(
                    f"[yellow]    [!] Could not load database '{file_name}': {e}. Skipping.[/]"
                )
                continue
            ctx.memory_tracker.sample()

            # Warn and skip if the DB cannot be used (no connection, no 'logs' table)
            if zircolite_core.db_connection is None:
                ctx.logger.warning(
                    f"[yellow]    [!] Could not open database '{file_name}'. Skipping.[/]"
                )
                continue
            try:
                _cur = zircolite_core.db_connection.cursor()
                _cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
                _has_logs_table = _cur.fetchone() is not None
                _cur.close()
            except Exception as e:
                ctx.logger.warning(
                    f"[yellow]    [!] Cannot inspect database '{file_name}': {e}. Skipping.[/]"
                )
                continue
            if not _has_logs_table:
                ctx.logger.warning(
                    f"[yellow]    [!] Database '{file_name}' has no 'logs' table. "
                    f"The file may be damaged (e.g. missing WAL journal). Skipping.[/]"
                )
                continue

            # The summary reports events too when analysing saved databases
            try:
                _cur = zircolite_core.db_connection.cursor()
                _cur.execute("SELECT COUNT(*) FROM logs")
                ctx.total_events += _cur.fetchone()[0]
                _cur.close()
            except sqlite3.Error as e:
                ctx.logger.debug(f"Could not count events in '{file_name}': {e}")

            zircolite_core.load_ruleset_from_var(
                ruleset=ctx.rulesets, rule_filters=ctx.rule_filters
            )
            zircolite_core.full_results = []

            if ctx.limit > 0 and first_file:
                ctx.logger.info(
                    f"[+] Limited mode: detections with more than "
                    f"[yellow]{ctx.limit}[/] events will be discarded"
                )

            write_mode = "w" if first_file else "a"

            ctx.logger.info(
                f"[+] Executing ruleset - [yellow]{len(zircolite_core.ruleset)}[/] rules"
            )
            zircolite_core.execute_ruleset(
                ctx.outfile,
                write_mode=write_mode,
                keep_results=True,
                last_ruleset=False,
                source_label=file_name if len(db_files) > 1 else None,
                disable_progress=is_quiet(),
            )
            ctx.memory_tracker.sample()

            file_detection_count = len(zircolite_core.full_results) if zircolite_core.full_results else 0
            file_stats.append({
                "name": file_name,
                "path": str(db_path),
                "events": 0,
                "detections": file_detection_count,
                "filtered": 0,
            })

            if zircolite_core.full_results:
                all_results.extend(zircolite_core.full_results)

            first_file = False
            processed_any = True
    finally:
        # The closing ']' is written here (not via last_ruleset) so skipped DB
        # files or a failure on a later file cannot leave the JSON output
        # unterminated.
        if processed_any and not ctx.csv_mode and not zircolite_core.no_output:
            try:
                with open(ctx.outfile, 'a', encoding='utf-8', newline='') as fh:
                    fh.write(']')
            except OSError as exc:
                # Never let this replace the exception that unwound the loop
                ctx.logger.error(f"[red]    [-] Could not finalize output: {exc}[/]")

    if not processed_any:
        # Every database was unreadable or skipped: nothing was analysed, so the
        # run must not exit 0 while the summary advertises an output file
        quit_on_error(
            "[red]    [-] No database could be analysed[/]", ctx.logger
        )

    if len(db_files) > 1 and file_stats and not is_quiet():
        console.print()
        tree = build_file_tree(f"Processed {len(db_files)} database files", file_stats)
        console.print(tree)
        console.print()

    return zircolite_core, all_results


# ============================================================================
# PARALLEL PROCESSING – worker function (extracted from closure)
# ============================================================================

def process_single_file_worker(
    log_file: Path,
    ctx: ProcessingContext,
    input_type: str,
    extractor: Optional[EvtxExtractor],
    args: argparse.Namespace,
    *,
    counter_lock: threading.Lock,
    worker_counter: List[int],
    total_filtered_count: List[int],
    thread_local: Any,
    raw_config: Optional[dict] = None,
    keepflat_file: Optional[Any] = None,
    rule_progress_queue: Optional[queue.Queue] = None,
) -> Tuple[int, Dict[str, Any]]:
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
            thread_local.worker_id = worker_id
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

        _streaming_result = core.run_streaming(
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
        event_count, filtered_count = _unpack_streaming_result(_streaming_result)

        with counter_lock:
            total_filtered_count[0] += filtered_count

        # The worker's logger is silent, so a file Zircolite could only read in
        # part is indistinguishable from a clean one unless it is reported here
        degraded = str(log_file) in core.failed_files
        core.failed_files.discard(str(log_file))

        if event_count == 0:
            summary = {
                "name": file_name,
                "path": str(log_file),
                "results": [],
                "events": 0,
                "filtered": filtered_count,
            }
            if degraded:
                summary["error"] = "no event could be read (see the log for details)"
            return (0, summary)

        core.load_ruleset_from_var(
            ruleset=ctx.rulesets, rule_filters=ctx.rule_filters
        )
        core.full_results = []

        worker_id = getattr(thread_local, "worker_id", 0)
        progress_callback = (
            (lambda cur, tot: rule_progress_queue.put((worker_id, file_name, cur, tot)))
            if rule_progress_queue is not None
            else None
        )
        core.execute_ruleset(
            ctx.outfile,
            write_mode="w",
            keep_results=True,
            last_ruleset=True,
            show_table=False,
            progress_callback=progress_callback,
        )

        file_results = list(core.full_results) if core.full_results else []
        summary = {
            "name": file_name,
            "path": str(log_file),
            "results": file_results,
            "events": event_count,
            "filtered": filtered_count,
        }
        if degraded:
            summary["error"] = (
                f"only part of the file could be read; {event_count:,} event(s) kept"
            )
        return (event_count, summary)

    except Exception as e:
        return (
            0,
            {
                "name": file_name,
                "path": str(log_file),
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
    """Incremental writer for parallel JSON detection results.

    Writes each detection result to disk as it arrives rather than buffering
    everything in memory and flushing at the end. JSON only: CSV needs the
    full field set up front, so it goes through ``_write_parallel_results``.

    Not thread-safe by design -- ``on_result`` is invoked from the main
    scheduling loop as futures complete, never from a worker.
    """

    _fh: Any

    def __init__(self, ctx: ProcessingContext):
        self._ctx = ctx
        self._fh = None
        self._first_json = True

    def __enter__(self):
        if self._ctx.no_output:
            return self
        self._fh = open(self._ctx.outfile, "wb")
        self._fh.write(b"[")
        return self

    def write_file_results(self, file_data) -> None:
        """Write all detection results from a single file's output dict."""
        if self._fh is None or not isinstance(file_data, dict):
            return
        for result in file_data.get("results", []):
            self._write_json(result)

    def _write_json(self, result: dict) -> None:
        if self._fh is None:
            return
        if not self._first_json:
            self._fh.write(b",\n")
        self._first_json = False
        self._fh.write(orjson.dumps(result, option=orjson.OPT_INDENT_2))

    def __exit__(self, *args):
        if self._fh is not None:
            try:
                self._fh.write(b"]")
            finally:
                self._fh.close()
                self._fh = None


def _write_parallel_results(
    ctx: ProcessingContext, all_results: List[Dict[str, Any]]
) -> None:
    """Write combined parallel results as CSV.

    CSV needs the full field set up front, so parallel results are buffered and
    written here; JSON streams out through :class:`_IncrementalResultWriter` as
    each file completes.
    """
    if ctx.no_output:
        return

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
            description = sanitize_value_for_csv(result.get("description") or "")
            level = result.get("rule_level", "")
            count = result.get("count", 0)
            for row in result.get("matches", []):
                clean_row = sanitize_row_for_csv(row)
                writer.writerow(
                    {
                        "rule_title": title,
                        "rule_description": description,
                        "rule_level": level,
                        "rule_count": count,
                        **clean_row,
                    }
                )


def process_parallel_streaming(
    ctx: ProcessingContext,
    file_list: List[Path],
    input_type: str,
    extractor: Optional[EvtxExtractor],
    args: argparse.Namespace,
    recommended_workers: Optional[int] = None,
) -> Tuple[Any, ...]:
    """Process files in parallel using memory-aware parallel processor."""

    parallel_config = ParallelConfig(
        max_workers=getattr(args, "parallel_workers", None) or recommended_workers,
        min_workers=getattr(args, "parallel_min_workers", 1),
        memory_limit_percent=getattr(args, "parallel_memory_limit", 85.0),
        sort_by_size=True,
        adaptive_memory=getattr(args, "parallel_adaptive", True),
    )

    if len(file_list) < 2:
        return process_perfile_streaming(ctx, file_list, input_type, extractor, args)

    # Pre-parse field mappings once so workers skip redundant disk reads
    # Parsed once, then deep-copied per worker: _resolve_file_transforms
    # writes the loaded source back into the transform dicts, so sharing one
    # object across threads lets a failed read in one worker install the no-op
    # fallback into a dict another worker is still baking.
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
            "path": file_data.get("path", ""),
            "events": file_data.get("events", 0),
            "detections": len(file_results),
            "filtered": file_data.get("filtered", 0),
        })

    # Incremental writing streams JSON results to disk as files complete.
    # CSV mode is excluded: the CSV DictWriter header is fixed at creation
    # time, so columns from later files would be silently dropped.  CSV
    # falls back to _write_parallel_results which collects all columns first.
    use_incremental = not ctx.csv_mode
    rule_progress_queue = queue.Queue() if not is_quiet() else None

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
                raw_config=deepcopy(raw_config),
                keepflat_file=kf,
                rule_progress_queue=rule_progress_queue,
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
                    rule_progress_queue=rule_progress_queue,
                )
        else:
            results_list, stats = processor.process_files_parallel(
                file_list,
                _process_file,
                desc="Processing",
                disable_progress=is_quiet(),
                on_result=_on_file_complete,
                rule_progress_queue=rule_progress_queue,
            )
            _write_parallel_results(ctx, all_results)

    # Collect errors
    for file_data in results_list:
        if isinstance(file_data, dict) and file_data.get("error"):
            errors.append((file_data.get("name", "unknown"), file_data["error"]))
            if file_data.get("path"):
                ctx.failed_files.add(file_data["path"])

    if errors:
        ctx.logger.error(f"[!] {len(errors)} file(s) failed to process:")
        for fname, err in errors[:5]:
            ctx.logger.error(f"    \u2192 {fname}: {err}")
        if len(errors) > 5:
            ctx.logger.error(f"    \u2192 ... and {len(errors) - 5} more")

    ctx.memory_tracker.sample()
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
                rule_summary.items(), key=lambda item: sort_key_severity(
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
        tree = build_file_tree(f"Processed {len(file_stats)} files", file_stats)
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
