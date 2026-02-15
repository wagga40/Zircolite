#!python3
"""
Parallel processing module for Zircolite.

This module provides memory-aware parallel file processing capabilities:
- Dynamic worker count based on available memory
- Memory monitoring during processing
- Graceful degradation when memory is low
"""

import logging
import os
import time
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


@dataclass
class ParallelConfig:
    """Configuration for parallel processing."""
    max_workers: Optional[int] = None  # None = auto-detect based on CPU/memory
    min_workers: int = 1
    memory_limit_percent: float = 75.0  # Max memory usage before throttling
    memory_check_interval: int = 5  # Check memory every N files
    use_processes: bool = False  # Deprecated: always uses threads (processes have issues)
    adaptive_workers: bool = True  # Dynamically adjust workers based on memory
    batch_size: int = 10  # Number of files per batch for memory checks


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
    throttle_events: int = 0  # Number of times workers were reduced due to memory


class MemoryAwareParallelProcessor:
    """
    Parallel processor that monitors and adapts to available memory.
    
    Features:
    - Auto-calculates optimal worker count based on file sizes and available RAM
    - Monitors memory during processing and throttles if needed
    - Supports both thread-based and process-based parallelism
    - Provides detailed statistics on processing
    """

    def __init__(
        self,
        config: Optional[ParallelConfig] = None,
        *,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the parallel processor.
        
        Args:
            config: Parallel processing configuration
            logger: Logger instance
        """
        self.config = config or ParallelConfig()
        self.logger = logger or logging.getLogger(__name__)
        self.stats = ParallelStats()
        self._memory_samples: List[float] = []
        self._current_workers = 0
        self._process = psutil.Process(os.getpid())

    def get_available_memory_mb(self) -> float:
        """Get available system memory in MB."""
        try:
            return psutil.virtual_memory().available / (1024 * 1024)
        except Exception:
            return 4096  # Fallback to 4GB assumption

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
            return 50.0  # Assume 50% if we can't determine

    def estimate_memory_per_file(self, file_list: List[Path]) -> float:
        """
        Estimate memory required per file based on file sizes.
        
        Heuristic: EVTX files typically expand 3-4x when parsed to JSON,
        plus SQLite overhead. Using 4x multiplier (balanced).
        """
        if not file_list:
            return 50  # Default 50MB estimate
        
        total_size = 0
        for f in file_list[:10]:  # Sample first 10 files
            try:
                total_size += os.path.getsize(f)
            except OSError:
                total_size += 10 * 1024 * 1024  # Assume 10MB if can't read
        
        avg_file_size_mb = (total_size / min(len(file_list), 10)) / (1024 * 1024)
        
        # Memory multiplier based on file size (smaller files = higher overhead ratio)
        if avg_file_size_mb < 10:
            memory_multiplier = 5.0  # Small files have more overhead
        elif avg_file_size_mb < 50:
            memory_multiplier = 4.0  # Medium files
        else:
            memory_multiplier = 3.5  # Large files are more memory efficient
        
        return avg_file_size_mb * memory_multiplier

    def calculate_optimal_workers(self, file_list: List[Path], quiet: bool = False) -> int:
        """
        Calculate optimal number of workers based on:
        - Available memory
        - File sizes
        - CPU count
        - Number of files
        - Configuration limits
        
        Uses aggressive scaling to maximize parallelism while staying safe.
        """
        if self.config.max_workers is not None:
            return max(self.config.min_workers, self.config.max_workers)
        
        # Get system resources
        cpu_count = os.cpu_count() or 4
        available_memory_mb = self.get_available_memory_mb()
        memory_per_file_mb = self.estimate_memory_per_file(file_list)
        file_count = len(file_list)
        
        # Use 85% of available memory (15% reserved for system)
        usable_memory_mb = available_memory_mb * 0.85
        
        # Calculate max workers based on memory
        memory_based_workers = max(1, int(usable_memory_mb / memory_per_file_mb))
        
        # CPU-based limit: allow up to 2x CPU count for I/O bound workloads
        # (EVTX parsing is often I/O bound, not CPU bound)
        cpu_based_workers = cpu_count * 2
        
        # Scale workers based on file count (more files = more potential parallelism)
        # but don't exceed sensible limits
        file_based_workers = min(file_count, cpu_count * 3)
        
        # Take the minimum of all constraints, but ensure we use at least half CPU count
        optimal_workers = min(memory_based_workers, cpu_based_workers, file_based_workers)
        optimal_workers = max(optimal_workers, min(cpu_count // 2, file_count))
        
        # Apply configuration limits
        optimal_workers = max(self.config.min_workers, optimal_workers)
        
        # Don't use more workers than files
        optimal_workers = min(optimal_workers, file_count)
        
        # Cap at reasonable maximum to avoid context switching overhead
        optimal_workers = min(optimal_workers, 32)
        
        return optimal_workers

    def should_throttle(self) -> bool:
        """Check if we should reduce workers due to high memory usage."""
        memory_percent = self.get_memory_percent()
        return memory_percent > self.config.memory_limit_percent

    def process_files_parallel(
        self,
        file_list: List[Path],
        process_func: Callable[[Path], Tuple[int, Any]],
        desc: str = "Processing",
        disable_progress: bool = False
    ) -> Tuple[List[Any], ParallelStats]:
        """
        Process files in parallel with memory awareness.
        
        Args:
            file_list: List of files to process
            process_func: Function that processes a single file and returns (event_count, result)
            desc: Description for progress bar
            disable_progress: Whether to disable progress bar
            
        Returns:
            Tuple of (list of results, processing statistics)
        """
        if not file_list:
            return [], self.stats
        
        start_time = time.time()
        self.stats = ParallelStats(total_files=len(file_list))
        self._memory_samples = []
        
        # Calculate optimal workers
        num_workers = self.calculate_optimal_workers(file_list, quiet=True)
        self._current_workers = num_workers
        self.stats.workers_used = num_workers
        
        # Always use ThreadPoolExecutor (ProcessPoolExecutor has issues with certain objects)
        ExecutorClass = ThreadPoolExecutor
        
        results = []
        failed_files = []
        
        # Create Rich progress bar
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
            
            with ExecutorClass(max_workers=num_workers) as executor:
                # Lazy submission with backpressure (opt #14) – only
                # ``num_workers`` tasks are in-flight at any time, allowing
                # memory to be reclaimed between file completions.
                file_iter = iter(file_list)
                active_futures: dict = {}
                
                # Seed initial batch of work
                for _ in range(num_workers):
                    try:
                        f = next(file_iter)
                        active_futures[executor.submit(process_func, f)] = f
                    except StopIteration:
                        break
                
                while active_futures:
                    # Wait for at least one task to finish
                    done, _ = wait(active_futures, return_when=FIRST_COMPLETED)
                    
                    for future in done:
                        file_path = active_futures.pop(future)
                        
                        try:
                            event_count, result = future.result()
                            self.stats.total_events += event_count
                            self.stats.processed_files += 1
                            if result is not None:
                                results.append(result)
                            
                            progress.update(
                                task_id, advance=1,
                                events=self.stats.total_events
                            )
                        except Exception as e:
                            self.stats.failed_files += 1
                            failed_files.append((file_path, str(e)))
                            progress.update(task_id, advance=1)
                        
                        # Memory check at intervals
                        total_done = self.stats.processed_files + self.stats.failed_files
                        if total_done % self.config.memory_check_interval == 0:
                            current_mem = self.get_current_memory_mb()
                            self._memory_samples.append(current_mem)
                            self.stats.peak_memory_mb = max(
                                self.stats.peak_memory_mb, current_mem
                            )
                            
                            # Backpressure: pause briefly when memory is high
                            # to let GC reclaim before submitting more work
                            if self.should_throttle():
                                self.stats.throttle_events += 1
                                time.sleep(0.2)
                        
                        # Submit next file (keeps exactly num_workers in-flight)
                        try:
                            next_file = next(file_iter)
                            active_futures[executor.submit(process_func, next_file)] = next_file
                        except StopIteration:
                            pass
        
        # Calculate final statistics
        self.stats.processing_time_seconds = time.time() - start_time
        if self._memory_samples:
            self.stats.avg_memory_mb = sum(self._memory_samples) / len(self._memory_samples)
        
        # Log summary
        self._log_summary(failed_files)
        
        return results, self.stats

    def _log_summary(self, failed_files: List[Tuple[Path, str]]):
        """Log processing summary with clean formatting using Rich markup."""
        # Single line summary with Rich markup
        files_str = f"[cyan]{self.stats.processed_files}[/] files"
        events_str = f"[magenta]{self.stats.total_events:,}[/] events"
        time_str = f"[yellow]{self.stats.processing_time_seconds:.1f}s[/]"
        summary_parts = [files_str, events_str, time_str]
        
        # Add throughput if processing took significant time
        if self.stats.processing_time_seconds > 1:
            events_per_sec = self.stats.total_events / self.stats.processing_time_seconds
            throughput_str = f"[green]{events_per_sec:,.0f}[/] events/s"
            summary_parts.append(throughput_str)
        
        self.logger.info(f"[+] Processed: {' │ '.join(summary_parts)}")
        
        if self.stats.throttle_events > 0:
            self.logger.warning(
                f"[!] Memory pressure detected [yellow]{self.stats.throttle_events}[/] times"
            )
        
        # Don't log failed files here - the caller will do it with context


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
    
    # Estimate resources
    processor = MemoryAwareParallelProcessor(logger=logger)
    available_mem = processor.get_available_memory_mb()
    mem_per_file = processor.estimate_memory_per_file(file_list)
    optimal_workers = processor.calculate_optimal_workers(file_list)
    
    # Calculate total file size
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
    
    # Estimate speedup (not linear due to I/O and memory contention)
    estimated_speedup = min(optimal_workers * 0.7, file_count)  # 70% efficiency estimate
    
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
