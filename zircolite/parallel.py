#!python3
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
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, Any

import psutil

from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    MofNCompleteColumn, TimeElapsedColumn
)
from .console import console


# ============================================================================
# CONSOLIDATED WORKER CALCULATION
# ============================================================================

def calculate_optimal_workers(
    file_sizes: List[int],
    available_memory_mb: float,
    cpu_count: int,
    *,
    min_workers: int = 1,
    max_workers: Optional[int] = None,
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
        return max(min_workers, min(max_workers, file_count))

    avg_file_size_mb = (sum(file_sizes) / file_count) / (1024 * 1024)

    if avg_file_size_mb < 10:
        memory_multiplier = 5.0
    elif avg_file_size_mb < 50:
        memory_multiplier = 4.0
    else:
        memory_multiplier = 3.5

    memory_per_file_mb = avg_file_size_mb * memory_multiplier
    usable_memory_mb = available_memory_mb * 0.85

    memory_based = max(1, int(usable_memory_mb / memory_per_file_mb)) if memory_per_file_mb > 0 else cpu_count
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
    max_workers: Optional[int] = None
    min_workers: int = 1
    memory_limit_percent: float = 75.0
    memory_check_interval: int = 5
    adaptive_workers: bool = True
    batch_size: int = 10
    sort_by_size: bool = True  # LPT scheduling – process largest files first
    adaptive_memory: bool = True  # Calibrate memory estimates after first file


@dataclass
class ParallelStats:
    """Statistics from parallel processing."""
    total_files: int = 0
    processed_files: int = 0
    failed_files: int = 0
    total_events: int = 0
    peak_memory_mb: float = 0.0
    avg_memory_mb: float = 0.0
    processing_time_seconds: float = 0.0
    workers_used: int = 0
    throttle_events: int = 0
    submissions_paused: int = 0  # Times new work was deferred due to memory pressure
    memory_calibrated: bool = False
    calibrated_ratio: float = 0.0


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

    **Why threads, not processes:** Zircolite's heavy lifting (EVTX parsing
    via Rust, JSON parsing via orjson/C, SQLite queries via C) all release
    the GIL, so ``ThreadPoolExecutor`` already achieves real parallelism for
    these I/O-bound workloads.  ``ProcessPoolExecutor`` would add process
    creation overhead, pickle serialization costs, and higher memory usage
    (full Python interpreter per worker) for marginal CPU-parallelism on the
    remaining pure-Python flattening code -- a net loss in practice.
    """

    def __init__(
        self,
        config: Optional[ParallelConfig] = None,
        *,
        logger: Optional[logging.Logger] = None
    ):
        self.config = config or ParallelConfig()
        self.logger = logger or logging.getLogger(__name__)
        self.stats = ParallelStats()
        self._memory_samples: List[float] = []
        self._current_workers = 0
        self._process = psutil.Process(os.getpid())
        self._calibrated_memory_per_file_mb: Optional[float] = None
        self._first_file_memory_before: Optional[float] = None

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

    # ------------------------------------------------------------------
    # Estimation & calibration
    # ------------------------------------------------------------------

    def estimate_memory_per_file(self, file_list: List[Path]) -> float:
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

        if avg_file_size_mb < 10:
            memory_multiplier = 5.0
        elif avg_file_size_mb < 50:
            memory_multiplier = 4.0
        else:
            memory_multiplier = 3.5

        return avg_file_size_mb * memory_multiplier

    def calibrate_memory(self, file_path: Path, memory_after_mb: float):
        """
        Calibrate memory-per-file estimate using the actual memory delta
        observed after processing the first file.

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

        actual_ratio = memory_delta / file_size_mb
        heuristic = self.estimate_memory_per_file([file_path])
        heuristic_ratio = heuristic / max(file_size_mb, 0.01)
        blended_ratio = 0.7 * actual_ratio + 0.3 * heuristic_ratio

        self._calibrated_memory_per_file_mb = file_size_mb * blended_ratio
        self.stats.memory_calibrated = True
        self.stats.calibrated_ratio = blended_ratio
        self.logger.debug(
            f"Memory calibrated: {actual_ratio:.1f}x actual, "
            f"{blended_ratio:.1f}x blended (file: {file_size_mb:.1f}MB, "
            f"delta: {memory_delta:.1f}MB)"
        )

    # ------------------------------------------------------------------
    # Worker calculation
    # ------------------------------------------------------------------

    def calculate_optimal_workers(self, file_list: List[Path], quiet: bool = False) -> int:
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
    def sort_files_by_size(file_list: List[Path]) -> List[Path]:
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
        file_list: List[Path],
        process_func: Callable[[Path], Tuple[int, Any]],
        desc: str = "Processing",
        disable_progress: bool = False,
        on_result: Optional[Callable[[Any], None]] = None,
        event_count_callback: Optional[Callable[[int], None]] = None,
    ) -> Tuple[List[Any], ParallelStats]:
        """
        Process files in parallel with memory awareness.

        Args:
            file_list: List of files to process.
            process_func: ``(Path) -> (event_count, result)``
            desc: Progress bar label.
            disable_progress: Suppress Rich progress bar.
            on_result: Called with each non-None result as it arrives
                       (useful for incremental writes to disk).
            event_count_callback: Called with cumulative event total after
                                  each file for granular progress reporting.

        Returns:
            ``(results_list, stats)``
        """
        if not file_list:
            return [], self.stats

        start_time = time.time()
        self.stats = ParallelStats(total_files=len(file_list))
        self._memory_samples = []

        # LPT scheduling
        if self.config.sort_by_size:
            file_list = self.sort_files_by_size(file_list)

        num_workers = self.calculate_optimal_workers(file_list, quiet=True)
        self._current_workers = num_workers
        self.stats.workers_used = num_workers

        # Snapshot memory before first file for adaptive calibration
        if self.config.adaptive_memory:
            self._first_file_memory_before = self.get_current_memory_mb()

        results: List[Any] = []
        failed_files: List[Tuple[Path, str]] = []
        first_file_path = file_list[0] if file_list else None
        first_file_calibrated = False

        # Use a deque so throttled files remain available for later submission
        file_queue: deque = deque(file_list)

        progress = Progress(
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
            disable=disable_progress
        )

        with progress:
            task_id = progress.add_task(
                desc,
                total=len(file_list),
                events=0,
                workers=num_workers
            )

            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                active_futures: dict = {}

                # Seed initial batch
                for _ in range(min(num_workers, len(file_queue))):
                    f = file_queue.popleft()
                    active_futures[executor.submit(process_func, f)] = f

                while active_futures:
                    done, _ = wait(active_futures, return_when=FIRST_COMPLETED)

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

                            progress.update(
                                task_id, advance=1,
                                events=self.stats.total_events
                            )

                            if event_count_callback is not None:
                                event_count_callback(self.stats.total_events)

                        except Exception as e:
                            self.stats.failed_files += 1
                            failed_files.append((file_path, str(e)))
                            progress.update(task_id, advance=1)

                        # Adaptive memory calibration after first file
                        if (
                            not first_file_calibrated
                            and self.config.adaptive_memory
                            and file_path == first_file_path
                        ):
                            first_file_calibrated = True
                            self.calibrate_memory(
                                file_path, self.get_current_memory_mb()
                            )

                        # Periodic memory sampling
                        total_done = self.stats.processed_files + self.stats.failed_files
                        if total_done % self.config.memory_check_interval == 0:
                            current_mem = self.get_current_memory_mb()
                            self._memory_samples.append(current_mem)
                            self.stats.peak_memory_mb = max(
                                self.stats.peak_memory_mb, current_mem
                            )

                        # Submit next file with real throttling
                        if file_queue:
                            if self.should_throttle():
                                self.stats.throttle_events += 1
                                self.stats.submissions_paused += 1
                            else:
                                f = file_queue.popleft()
                                active_futures[executor.submit(process_func, f)] = f

                    # Safety valve: if all futures drained during throttling
                    # but the queue still has files, force-submit one to keep
                    # making forward progress.
                    if not active_futures and file_queue:
                        f = file_queue.popleft()
                        active_futures[executor.submit(process_func, f)] = f

        # Final statistics
        self.stats.processing_time_seconds = time.time() - start_time
        if self._memory_samples:
            self.stats.avg_memory_mb = sum(self._memory_samples) / len(self._memory_samples)

        self._log_summary(failed_files)

        return results, self.stats

    def _log_summary(self, failed_files: List[Tuple[Path, str]]):
        """Log processing summary with clean formatting using Rich markup."""
        files_str = f"[cyan]{self.stats.processed_files}[/] files"
        events_str = f"[magenta]{self.stats.total_events:,}[/] events"
        time_str = f"[yellow]{self.stats.processing_time_seconds:.1f}s[/]"
        summary_parts = [files_str, events_str, time_str]

        if self.stats.processing_time_seconds > 1:
            events_per_sec = self.stats.total_events / self.stats.processing_time_seconds
            throughput_str = f"[green]{events_per_sec:,.0f}[/] events/s"
            summary_parts.append(throughput_str)

        self.logger.info(f"[+] Processed: {' │ '.join(summary_parts)}")

        if self.stats.throttle_events > 0:
            self.logger.warning(
                f"[!] Memory pressure detected [yellow]{self.stats.throttle_events}[/] times "
                f"([yellow]{self.stats.submissions_paused}[/] submissions deferred)"
            )


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def process_files_with_memory_awareness(
    file_list: List[Path],
    process_func: Callable[[Path], Tuple[int, Any]],
    config: Optional[ParallelConfig] = None,
    logger: Optional[logging.Logger] = None,
    desc: str = "Processing files",
    disable_progress: bool = False
) -> Tuple[List[Any], ParallelStats]:
    """
    Convenience function for parallel processing with memory awareness.

    Args:
        file_list: List of files to process
        process_func: Function that processes a single file, returns (event_count, result)
        config: Parallel processing configuration
        logger: Logger instance
        desc: Description for progress bar
        disable_progress: Whether to disable progress bar

    Returns:
        Tuple of (results list, statistics)
    """
    processor = MemoryAwareParallelProcessor(config=config, logger=logger)
    return processor.process_files_parallel(
        file_list, process_func, desc=desc, disable_progress=disable_progress
    )


def estimate_parallel_viability(
    file_list: List[Path],
    logger: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """
    Estimate whether parallel processing would be beneficial.

    Returns dict with recommendation and reasoning.
    """
    logger = logger or logging.getLogger(__name__)

    file_count = len(file_list)
    if file_count < 2:
        return {
            "recommended": False,
            "reason": "Single file - parallel processing not beneficial",
            "suggested_workers": 1
        }

    processor = MemoryAwareParallelProcessor(logger=logger)
    available_mem = processor.get_available_memory_mb()
    mem_per_file = processor.estimate_memory_per_file(file_list)
    optimal_workers = processor.calculate_optimal_workers(file_list)

    total_size_mb = sum(
        os.path.getsize(f) / (1024 * 1024)
        for f in file_list
        if os.path.exists(f)
    )

    if optimal_workers <= 1:
        return {
            "recommended": False,
            "reason": f"Insufficient memory for parallel processing ({available_mem:.0f}MB available, ~{mem_per_file:.0f}MB needed per file)",
            "suggested_workers": 1,
            "available_memory_mb": available_mem,
            "estimated_memory_per_file_mb": mem_per_file
        }

    estimated_speedup = min(optimal_workers * 0.7, file_count)

    return {
        "recommended": True,
        "reason": f"Parallel processing recommended with {optimal_workers} workers",
        "suggested_workers": optimal_workers,
        "estimated_speedup": f"{estimated_speedup:.1f}x",
        "available_memory_mb": available_mem,
        "estimated_memory_per_file_mb": mem_per_file,
        "total_files": file_count,
        "total_size_mb": total_size_mb
    }
