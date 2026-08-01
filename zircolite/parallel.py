"""
Parallel processing module for Zircolite.

This module provides memory-aware parallel file processing capabilities:
- Dynamic worker count based on available memory
- Memory monitoring during processing
- Graceful degradation when memory is low
- LPT (Longest Processing Time) scheduling for better load balancing
- Adaptive memory estimation with runtime calibration
- Thread-based parallelism
"""

import logging
import os
import queue
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil
from rich.console import Group
from rich.live import Live
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .console import console
from .shutdown import is_shutdown_requested

# Refresh interval for draining rule-progress queue (matches Live refresh_per_second=10)
_RULE_PROGRESS_POLL_SECONDS = 0.1

# Max length for file name in per-file progress bar (truncate with ellipsis)
_FILE_PROGRESS_NAME_MAX_LEN = 40


def _truncate_filename(name: str) -> str:
    """Truncate file name for progress bar description if needed."""
    max_len = _FILE_PROGRESS_NAME_MAX_LEN
    if len(name) <= max_len:
        return name
    return name[: max_len - 1] + "…"


def _file_size(path: Path) -> int:
    """Size of *path* in bytes, 0 when it cannot be read."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


# ============================================================================
# CONSOLIDATED WORKER CALCULATION
# ============================================================================


def memory_multiplier_for(avg_file_size_mb: float) -> float:
    """Peak RSS expected per MB of input, by average file size.

    Smaller files carry proportionally more per-event overhead; larger ones
    amortise it. Single source of truth for the estimate used by the worker
    count, the per-file estimate and the mode recommendation.
    """
    if avg_file_size_mb < 10:
        return 5.0
    if avg_file_size_mb < 50:
        return 4.0
    return 3.5


def calculate_optimal_workers(
    file_sizes: list[int],
    available_memory_mb: float,
    cpu_count: int,
    *,
    min_workers: int = 1,
    max_workers: int | None = None,
    max_cap: int = 32,
) -> int:
    """
    Calculate optimal number of parallel workers.

    This is the single source of truth for worker-count heuristics, used
    by both :class:`MemoryAwareParallelProcessor` and the mode-recommendation
    logic in ``utils.py``.

    Args:
        file_sizes: List of file sizes in bytes.
        available_memory_mb: Available system RAM in megabytes.
        cpu_count: Number of logical CPUs.
        min_workers: Minimum worker count floor.
        max_workers: If set, returned directly (after clamping to file count).
        max_cap: Hard ceiling to avoid context-switching overhead.

    Returns:
        Optimal worker count (always >= 1).
    """
    file_count = len(file_sizes)
    if file_count == 0:
        return 1

    if max_workers is not None:
        # Clamped to file count so no idle workers are spawned
        return max(1, min(max_workers, file_count))

    avg_file_size_mb = (sum(file_sizes) / file_count) / (1024 * 1024)
    memory_per_file_mb = avg_file_size_mb * memory_multiplier_for(avg_file_size_mb)
    usable_memory_mb = available_memory_mb * 0.85

    memory_based = (
        max(1, int(usable_memory_mb / memory_per_file_mb))
        if memory_per_file_mb > 0
        else cpu_count
    )
    cpu_based = cpu_count * 2  # I/O-bound workloads benefit from >1x CPU count
    file_based = min(file_count, cpu_count * 3)

    optimal = min(memory_based, cpu_based, file_based)

    # Apply a CPU-based floor only when memory is NOT the constraining factor.
    # Without this guard, the floor would override a genuine memory limit and
    # risk OOM when files are large relative to available RAM.
    if memory_based >= cpu_count // 2:
        optimal = max(optimal, min(cpu_count // 2, file_count))

    optimal = max(min_workers, optimal)
    optimal = min(optimal, file_count, max_cap)

    return optimal


# ============================================================================
# CONFIGURATION DATACLASSES
# ============================================================================


@dataclass
class ParallelConfig:
    """Configuration for parallel processing."""

    max_workers: int | None = None
    min_workers: int = 1
    memory_limit_percent: float = 85.0
    sort_by_size: bool = True  # LPT scheduling – process largest files first
    adaptive_memory: bool = True  # Calibrate memory estimates after first file


@dataclass
class ParallelStats:
    """Statistics from parallel processing."""

    processed_files: int = 0
    total_events: int = 0
    processing_time_seconds: float = 0.0
    workers_used: int = 0
    throttle_events: int = 0  # Times a submission was deferred under memory pressure


# ============================================================================
# PROCESSOR
# ============================================================================


class MemoryAwareParallelProcessor:
    """
    Parallel processor that monitors and adapts to available memory.

    Features:
    - Auto-calculates optimal worker count based on file sizes and available RAM
    - Monitors memory during processing and throttles if needed
    - Real throttling: pauses new task submissions when memory is high
    - LPT scheduling: processes largest files first for better load balancing
    - Adaptive memory estimation: calibrates after first file completion
    - Per-result and per-event callbacks for incremental progress/output

    """

    def __init__(
        self,
        config: ParallelConfig | None = None,
        *,
        logger: logging.Logger | None = None,
    ):
        self.config = config or ParallelConfig()
        self.logger = logger or logging.getLogger(__name__)
        self.stats = ParallelStats()
        self._process = psutil.Process(os.getpid())
        self._calibrated_memory_per_file_mb: float | None = None
        self._first_file_memory_before: float | None = None

    # ------------------------------------------------------------------
    # Memory helpers
    # ------------------------------------------------------------------

    def get_available_memory_mb(self) -> float:
        """Get available system memory in MB."""
        try:
            return psutil.virtual_memory().available / (1024 * 1024)
        except Exception:
            return 4096

    def get_current_memory_mb(self) -> float:
        """Get current process memory usage in MB."""
        try:
            return self._process.memory_info().rss / (1024 * 1024)
        except Exception:
            return 0

    def get_memory_percent(self) -> float:
        """Get current memory usage as percentage of total."""
        try:
            return psutil.virtual_memory().percent
        except Exception:
            return 50.0

    def should_throttle(self) -> bool:
        """Check if we should reduce workers due to high memory usage."""
        return self.get_memory_percent() > self.config.memory_limit_percent

    def _would_exceed_memory_budget(self) -> bool:
        """Predictive throttle based on the calibrated per-file estimate.

        Returns True when submitting one more file would likely push the
        process RSS past the configured memory budget. Inert until adaptive
        calibration has produced an estimate.
        """
        if self._calibrated_memory_per_file_mb is None:
            return False
        try:
            vm = psutil.virtual_memory()
        except Exception:
            return False
        total_mb = vm.total / (1024 * 1024)
        if total_mb <= 0:
            return False
        used_mb = (vm.total - vm.available) / (1024 * 1024)
        projected_percent = (
            (used_mb + self._calibrated_memory_per_file_mb) / total_mb * 100.0
        )
        return projected_percent > self.config.memory_limit_percent

    # ------------------------------------------------------------------
    # Estimation & calibration
    # ------------------------------------------------------------------

    def estimate_memory_per_file(self, file_list: list[Path]) -> float:
        """
        Estimate memory required per file in MB.

        Returns a calibrated value if adaptive estimation has run,
        otherwise falls back to a file-size-based heuristic.
        """
        if self._calibrated_memory_per_file_mb is not None:
            return self._calibrated_memory_per_file_mb

        if not file_list:
            return 50

        total_size = 0
        for f in file_list[:10]:
            try:
                total_size += os.path.getsize(f)
            except OSError:
                total_size += 10 * 1024 * 1024

        avg_file_size_mb = (total_size / min(len(file_list), 10)) / (1024 * 1024)
        return avg_file_size_mb * memory_multiplier_for(avg_file_size_mb)

    def calibrate_memory(
        self,
        file_path: Path,
        memory_after_mb: float,
        resident_bytes: int | None = None,
    ):
        """
        Calibrate memory-per-file estimate using the actual memory delta
        observed after processing the first file.

        The snapshot is taken before any file is submitted, so by the time the
        first one completes the delta covers every worker still in flight.
        *resident_bytes* is the total input size those workers hold, and the
        ratio has to be taken against it -- dividing an aggregate delta by a
        single file's size overestimated by roughly the worker count, which
        left the predictive throttle permanently on and serialised the run.

        The result blends 70 % actual measurement with 30 % heuristic to
        avoid over-correcting on a single sample.
        """
        if self._first_file_memory_before is None:
            return

        memory_delta = memory_after_mb - self._first_file_memory_before
        if memory_delta <= 0:
            return

        try:
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        except OSError:
            return

        if file_size_mb < 0.01:
            return

        resident_mb = (
            resident_bytes / (1024 * 1024)
            if resident_bytes and resident_bytes > 0
            else file_size_mb
        )
        actual_ratio = memory_delta / max(resident_mb, 0.01)
        heuristic = self.estimate_memory_per_file([file_path])
        heuristic_ratio = heuristic / max(file_size_mb, 0.01)
        blended_ratio = 0.7 * actual_ratio + 0.3 * heuristic_ratio

        self._calibrated_memory_per_file_mb = file_size_mb * blended_ratio
        self.logger.debug(
            f"Memory calibrated: {actual_ratio:.1f}x actual, "
            f"{blended_ratio:.1f}x blended (file: {file_size_mb:.1f}MB, "
            f"delta: {memory_delta:.1f}MB)"
        )

    # ------------------------------------------------------------------
    # Worker calculation
    # ------------------------------------------------------------------

    def calculate_optimal_workers(self, file_list: list[Path]) -> int:
        """Calculate optimal workers, delegating to the module-level function."""
        file_sizes = []
        for f in file_list:
            try:
                file_sizes.append(os.path.getsize(f))
            except OSError:
                file_sizes.append(10 * 1024 * 1024)

        return calculate_optimal_workers(
            file_sizes=file_sizes,
            available_memory_mb=self.get_available_memory_mb(),
            cpu_count=os.cpu_count() or 4,
            min_workers=self.config.min_workers,
            max_workers=self.config.max_workers,
        )

    # ------------------------------------------------------------------
    # LPT scheduling
    # ------------------------------------------------------------------

    @staticmethod
    def sort_files_by_size(file_list: list[Path]) -> list[Path]:
        """Sort files largest-first (Longest Processing Time scheduling)."""

        def _safe_size(f):
            try:
                return os.path.getsize(f)
            except OSError:
                return 0

        return sorted(file_list, key=_safe_size, reverse=True)

    # ------------------------------------------------------------------
    # Main processing loop
    # ------------------------------------------------------------------

    def process_files_parallel(
        self,
        file_list: list[Path],
        process_func: Callable[[Path], tuple[int, Any]],
        desc: str = "Processing",
        disable_progress: bool = False,
        on_result: Callable[[Any], None] | None = None,
        rule_progress_queue: queue.Queue | None = None,
    ) -> tuple[list[Any], ParallelStats]:
        """
        Process files in parallel with memory awareness.

        Args:
            file_list: List of files to process.
            process_func: ``(Path) -> (event_count, result)``
            desc: Progress bar label.
            disable_progress: Suppress Rich progress bar.
            on_result: Called with each non-None result as it arrives
                       (useful for incremental writes to disk).
            rule_progress_queue: If set, workers put (worker_id, file_name, rules_done, total_rules)
                                 here; this method adds one progress task per file (description =
                                 truncated file_name), updates it, and removes it when the file
                                 finishes to free console space.

        Returns:
            ``(results_list, stats)``
        """
        if not file_list:
            return [], self.stats

        start_time = time.time()
        self.stats = ParallelStats()
        # Reset calibration state so a reused processor instance does not
        # inherit estimates from a previous run
        self._calibrated_memory_per_file_mb = None
        self._first_file_memory_before = None

        # LPT scheduling
        if self.config.sort_by_size:
            file_list = self.sort_files_by_size(file_list)

        num_workers = self.calculate_optimal_workers(file_list)
        self.stats.workers_used = num_workers

        # Snapshot memory before first file for adaptive calibration
        if self.config.adaptive_memory:
            self._first_file_memory_before = self.get_current_memory_mb()

        results: list[Any] = []
        failed_files: list[tuple[Path, str]] = []
        first_file_calibrated = False
        inflight_bytes = 0

        # Use a deque so throttled files remain available for later submission
        file_queue: deque = deque(file_list)

        # Global progress: files M/N, event count, worker count
        progress_main = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("•"),
            TextColumn("[magenta]{task.fields[events]:,}[/] events"),
            TextColumn("•"),
            TextColumn("[yellow]{task.fields[workers]}[/] workers"),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            disable=disable_progress,
        )

        # Per-file rule progress: filename and rules X/Y only (no events/workers)
        progress_files = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            disable=disable_progress,
        )

        def run_parallel_loop() -> None:
            nonlocal first_file_calibrated, inflight_bytes
            task_id = progress_main.add_task(
                desc,
                total=len(file_list),
                events=0,
                workers=num_workers,
            )
            worker_file_task_ids: dict[int, Any] = {}

            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                active_futures: dict = {}

                def submit(path: Path) -> None:
                    nonlocal inflight_bytes
                    inflight_bytes += _file_size(path)
                    active_futures[executor.submit(process_func, path)] = path

                for _ in range(min(num_workers, len(file_queue))):
                    submit(file_queue.popleft())

                while active_futures:
                    if is_shutdown_requested():
                        file_queue.clear()
                    if rule_progress_queue is not None:
                        while True:
                            try:
                                w_id, file_name, rules_done, total_rules = (
                                    rule_progress_queue.get_nowait()
                                )
                                if total_rules <= 0:
                                    continue
                                if w_id not in worker_file_task_ids:
                                    worker_file_task_ids[w_id] = (
                                        progress_files.add_task(
                                            _truncate_filename(str(file_name)),
                                            total=total_rules,
                                            completed=0,
                                        )
                                    )
                                progress_files.update(
                                    worker_file_task_ids[w_id],
                                    completed=rules_done,
                                    total=total_rules,
                                )
                                if rules_done >= total_rules:
                                    task_id_to_remove = worker_file_task_ids.get(w_id)
                                    if task_id_to_remove is not None:
                                        try:
                                            progress_files.remove_task(
                                                task_id_to_remove
                                            )
                                        finally:
                                            del worker_file_task_ids[w_id]
                            except queue.Empty:
                                break
                    done, _ = wait(
                        active_futures,
                        return_when=FIRST_COMPLETED,
                        timeout=_RULE_PROGRESS_POLL_SECONDS,
                    )

                    for future in done:
                        file_path = active_futures.pop(future)

                        try:
                            event_count, result = future.result()
                            self.stats.total_events += event_count
                            self.stats.processed_files += 1
                            if result is not None:
                                results.append(result)
                                if on_result is not None:
                                    on_result(result)

                            progress_main.update(
                                task_id,
                                advance=1,
                                events=self.stats.total_events,
                            )

                        except Exception as e:
                            failed_files.append((file_path, str(e)))
                            progress_main.update(task_id, advance=1)

                        # Calibrate on the first file to COMPLETE (not the LPT-first
                        # file, which typically finishes last): the estimate is only
                        # useful if it exists early enough to gate submissions.
                        if not first_file_calibrated and self.config.adaptive_memory:
                            first_file_calibrated = True
                            self.calibrate_memory(
                                file_path,
                                self.get_current_memory_mb(),
                                resident_bytes=inflight_bytes,
                            )

                        inflight_bytes -= _file_size(file_path)

                        if file_queue and not is_shutdown_requested():
                            if self.should_throttle() or self._would_exceed_memory_budget():
                                self.stats.throttle_events += 1
                            else:
                                submit(file_queue.popleft())

                    if not active_futures and file_queue and not is_shutdown_requested():
                        submit(file_queue.popleft())

        if rule_progress_queue is not None:
            with Live(
                Group(progress_main, progress_files),
                console=console,
                refresh_per_second=10,
                transient=True,
            ):
                run_parallel_loop()
        else:
            with progress_main:
                run_parallel_loop()

        # Final statistics
        self.stats.processing_time_seconds = time.time() - start_time

        self._log_summary(failed_files)

        return results, self.stats

    def _log_summary(self, failed_files: list[tuple[Path, str]]):
        """Log processing summary with clean formatting using Rich markup."""
        files_str = f"[cyan]{self.stats.processed_files}[/] files"
        events_str = f"[magenta]{self.stats.total_events:,}[/] events"
        time_str = f"[yellow]{self.stats.processing_time_seconds:.1f}s[/]"
        summary_parts = [files_str, events_str, time_str]

        if self.stats.processing_time_seconds > 1:
            events_per_sec = (
                self.stats.total_events / self.stats.processing_time_seconds
            )
            throughput_str = f"[green]{events_per_sec:,.0f}[/] events/s"
            summary_parts.append(throughput_str)

        self.logger.info(f"[+] Processed: {' │ '.join(summary_parts)}")

        if failed_files:
            self.logger.warning(
                f"[!] [yellow]{len(failed_files)}[/] file(s) failed to process:"
            )
            for path, error in failed_files[:5]:
                self.logger.warning(f"    [-] {path.name}: {error}")
            if len(failed_files) > 5:
                self.logger.warning(
                    f"    ... and [yellow]{len(failed_files) - 5}[/] more"
                )

        if self.stats.throttle_events > 0:
            self.logger.warning(
                f"[!] Memory pressure deferred [yellow]{self.stats.throttle_events}[/] "
                "submission(s)"
            )
