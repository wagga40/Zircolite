#!python3
"""
Utility functions and helper classes for Zircolite.

This module contains:
- Logging initialization
- File selection/filtering utilities
- Memory tracking
- Processing mode heuristics
- Field mappings configuration loader (JSON/YAML support)
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import orjson
import psutil
import yaml

# Rich-based console - import with fallback for compatibility
try:
    from .console import console, get_rich_logger
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None


def load_field_mappings(config_file: str, *, logger: Optional[logging.Logger] = None) -> Dict[str, Any]:
    """
    Load field mappings configuration from JSON or YAML file.
    
    Supports both JSON (.json) and YAML (.yaml, .yml) formats.
    The file format is auto-detected based on file extension.
    
    Args:
        config_file: Path to the field mappings configuration file
        logger: Optional logger instance for error messages
        
    Returns:
        Dictionary containing field mappings configuration with keys:
        - exclusions: List of field name patterns to exclude
        - useless: List of values to filter out (e.g., null, empty)
        - mappings: Dict mapping raw field names to simplified names
        - alias: Dict mapping field names to alias names
        - split: Dict defining field splitting rules
        - transforms: Dict defining field value transformations
        - transforms_enabled: Boolean flag for enabling transforms
        
    Raises:
        FileNotFoundError: If configuration file doesn't exist
        ValueError: If file format is unsupported or parsing fails
    """
    logger = logger or logging.getLogger(__name__)
    config_path = Path(config_file)
    
    # Deprecation: prefer config/config.yaml over fieldMappings.yaml
    path_lower = config_path.name.lower()
    if path_lower in ("fieldmappings.yaml", "fieldmappings.yml"):
        logger.warning(
            "fieldMappings.yaml is deprecated; use config/config.yaml instead. "
            "Support for fieldMappings.yaml may be removed in a future version."
        )
    
    if not config_path.exists():
        raise FileNotFoundError(f"Field mappings configuration file not found: {config_file}")
    
    # Determine format from file extension
    suffix = config_path.suffix.lower()
    
    if suffix == '.json':
        # JSON format - use orjson for speed
        with open(config_path, 'rb') as f:
            try:
                config = orjson.loads(f.read())
            except orjson.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in field mappings file: {e}")
    elif suffix in ('.yaml', '.yml'):
        # YAML format
        with open(config_path, 'r', encoding='utf-8') as f:
            try:
                config = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ValueError(f"Invalid YAML in field mappings file: {e}")
    else:
        # Try to auto-detect based on content
        with open(config_path, 'rb') as f:
            content = f.read()
        
        # Try JSON first (most common)
        try:
            config = orjson.loads(content)
        except orjson.JSONDecodeError:
            # Try YAML as fallback
            try:
                config = yaml.safe_load(content.decode('utf-8'))
            except yaml.YAMLError:
                raise ValueError(
                    f"Unable to parse field mappings file: {config_file}. "
                    f"Supported formats: .json, .yaml, .yml"
                )
    
    if config is None:
        config = {}
    
    # Ensure config is a dictionary
    if not isinstance(config, dict):
        raise ValueError(
            f"Invalid field mappings file format: {config_file}. "
            f"Expected a dictionary/object at root level."
        )
    
    # Validate required keys and provide defaults
    required_keys = ['exclusions', 'useless', 'mappings', 'alias', 'split', 'transforms', 'transforms_enabled']
    defaults = {
        'exclusions': [],
        'useless': [None, ""],
        'mappings': {},
        'alias': {},
        'split': {},
        'transforms': {},
        'transforms_enabled': False
    }
    
    for key in required_keys:
        if key not in config:
            logger.debug(f"Field mappings config missing '{key}', using default")
            config[key] = defaults[key]
    
    # Add event_filter section with minimal fallback defaults
    # (Full defaults are in config/config.yaml)
    if 'event_filter' not in config:
        config['event_filter'] = {
            'enabled': True,
            'channel_fields': ["Event.System.Channel", "Channel"],
            'eventid_fields': ["Event.System.EventID", "EventID"],
        }
    
    # Add timestamp_detection section with minimal fallback defaults
    # (Full defaults are in config/config.yaml)
    if 'timestamp_detection' not in config:
        config['timestamp_detection'] = {
            'default_field': 'SystemTime',
            'auto_detect': True,
            'detection_fields': ["SystemTime", "UtcTime", "@timestamp", "timestamp"],
        }
    
    return config


def quit_on_error(message, logger=None):
    """Log error message and exit with error code."""
    logger = logger or logging.getLogger(__name__)
    logger.error(message)
    sys.exit(1)


def check_if_exists(path, error_message, logger=None):
    """Check if the provided path is a file."""
    if not Path(path).is_file():
        quit_on_error(error_message, logger)


def init_logger(debug_mode, log_file=None, name='zircolite', use_rich=True):
    """Initialize logger with appropriate configuration.
    
    Args:
        debug_mode: Enable debug-level logging with verbose format
        log_file: Optional path to log file for persistent logging
        name: Logger name (default: 'zircolite')
        use_rich: Use Rich-based console output (default: True)
    
    Returns:
        Configured logger instance
    """
    # Use Rich logger if available and requested
    if use_rich and HAS_RICH:
        return get_rich_logger(name=name, debug=debug_mode, log_file=log_file)
    
    # Fallback to standard logging
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    
    # Clear any existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Prevent propagation to root logger to avoid duplicate messages
    logger.propagate = False
    
    # Console handler - always present with simple format
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(console_handler)
    
    # File handler (if requested)
    if log_file is not None:
        file_log_format = "%(asctime)s %(levelname)-8s %(message)s"
        if debug_mode:
            file_log_format = "%(asctime)s %(levelname)-8s %(module)s:%(lineno)s %(funcName)s %(message)s"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG if debug_mode else logging.INFO)
        file_handler.setFormatter(logging.Formatter(file_log_format, datefmt='%Y-%m-%d %H:%M:%S'))
        logger.addHandler(file_handler)

    return logger


def create_silent_logger(name='zircolite_worker'):
    """Create a logger that suppresses all output (for parallel workers).
    
    Args:
        name: Logger name (should be unique per worker)
    
    Returns:
        Logger instance that discards all messages
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.CRITICAL + 1)  # Above all levels - nothing gets logged
    logger.handlers.clear()
    logger.propagate = False
    # Add a null handler to prevent "no handler" warnings
    logger.addHandler(logging.NullHandler())
    return logger


def select_files(path_list, select_files_list):
    """Select files from path list based on filter criteria."""
    if select_files_list is None:
        return path_list

    paths = list(path_list)
    filters = [file_filters[0].lower() for file_filters in select_files_list]
    selected = []
    for element in paths:
        path_str = str(element)
        path_str_lower = path_str.lower()
        if any(file_filter in path_str_lower for file_filter in filters):
            selected.append(path_str)
    return selected


def avoid_files(path_list, avoid_files_list):
    """Filter out files from path list based on exclusion criteria."""
    if avoid_files_list is None:
        return path_list

    paths = list(path_list)
    filters = [file_filters[0].lower() for file_filters in avoid_files_list]
    filtered = []
    for element in paths:
        path_str = str(element)
        path_str_lower = path_str.lower()
        if all(file_filter not in path_str_lower for file_filter in filters):
            filtered.append(path_str)
    return filtered


class MemoryTracker:
    """Track memory usage during execution with optional rate limiting."""
    
    def __init__(self, *, logger: Optional[logging.Logger] = None,
                 min_sample_interval: float = 0.0):
        """
        Initialize MemoryTracker.
        
        Args:
            logger: Logger instance (creates default if None)
            min_sample_interval: Minimum seconds between samples (0 = no limit).
                When positive, rapid ``sample()`` calls are silently skipped
                to reduce syscall overhead (opt #13).
        """
        self.logger = logger or logging.getLogger(__name__)
        self.memory_samples = []
        self.peak_memory = 0
        self.process = psutil.Process(os.getpid())
        self._min_sample_interval = min_sample_interval
        self._last_sample_time = 0.0
    
    def get_memory_usage(self):
        """Get current memory usage in MB."""
        try:
            # Get RSS (Resident Set Size) in bytes, convert to MB
            return self.process.memory_info().rss / (1024 * 1024)
        except Exception:
            return 0
    
    def sample(self, *, force: bool = False):
        """Take a memory usage sample.
        
        Args:
            force: If True, bypass the rate limit and always sample.
        """
        # Rate limiting (opt #13) – skip if called too soon after last sample
        if self._min_sample_interval > 0 and not force:
            import time as _time
            now = _time.monotonic()
            if now - self._last_sample_time < self._min_sample_interval:
                return
            self._last_sample_time = now
        
        memory_mb = self.get_memory_usage()
        if memory_mb > 0:
            self.memory_samples.append(memory_mb)
            if memory_mb > self.peak_memory:
                self.peak_memory = memory_mb
    
    def get_stats(self):
        """Get peak and average memory usage."""
        if not self.memory_samples:
            return 0, 0
        
        peak = self.peak_memory
        average = sum(self.memory_samples) / len(self.memory_samples)
        
        return peak, average
    
    def format_memory(self, memory_mb):
        """Format memory value for display."""
        if memory_mb >= 1024:
            return f"{memory_mb / 1024:.2f} GB"
        else:
            return f"{memory_mb:.2f} MB"


################################################################
# HEURISTICS FOR OPTIMAL PROCESSING MODE
################################################################
def format_size(size):
    """Format byte size for human-readable display."""
    if size >= 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024 * 1024):.1f} GB"
    elif size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    elif size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} bytes"


def analyze_files_and_recommend_mode(file_list, logger=None):
    """
    Analyze files and available RAM to recommend optimal processing settings.
    
    Returns a tuple: (recommended_mode, reason, stats)
    - recommended_mode: 'unified' or 'per-file'
    - reason: Human-readable explanation
    - stats: Dictionary with analysis statistics including parallel recommendation
    
    Heuristics for database mode:
    - Many small files (>10 files, avg <5MB) → unified mode (less overhead, cross-file correlation)
    - Few large files (<5 files, avg >50MB) → per-file mode (memory efficient)
    - Low available RAM (<2GB) → per-file mode (safer for memory)
    - High RAM + many files → per-file mode (enables parallel processing)
    - Very large total size (>available RAM) → per-file mode (avoid OOM)
    - Single file → per-file mode (no benefit from unified)
    
    Heuristics for parallel processing:
    - Multiple files (>1) + sufficient RAM → enable parallel
    - Per-file mode (not unified) + multiple files → parallel beneficial
    - Estimated memory per file < available_ram / num_workers → parallel safe
    """
    try:
        available_ram = psutil.virtual_memory().available
        total_ram = psutil.virtual_memory().total
        cpu_count = os.cpu_count() or 4
        has_psutil = True
    except Exception:
        available_ram = 4 * 1024 * 1024 * 1024  # Assume 4GB if psutil not available
        total_ram = 8 * 1024 * 1024 * 1024
        cpu_count = 4
        has_psutil = False
    
    # Calculate file statistics
    file_count = len(file_list)
    file_sizes = []
    for f in file_list:
        try:
            file_sizes.append(os.path.getsize(f))
        except OSError:
            file_sizes.append(0)
    
    total_size = sum(file_sizes)
    avg_size = total_size / file_count if file_count > 0 else 0
    max_size = max(file_sizes) if file_sizes else 0
    min_size = min(file_sizes) if file_sizes else 0
    
    # Estimate memory usage per file (dynamic multiplier based on file size)
    if avg_size < 10 * 1024 * 1024:  # < 10MB
        memory_multiplier = 5.0  # Small files have more overhead
    elif avg_size < 50 * 1024 * 1024:  # < 50MB
        memory_multiplier = 4.0  # Medium files
    else:
        memory_multiplier = 3.5  # Large files are more memory efficient
    
    memory_per_file = avg_size * memory_multiplier
    
    # Calculate optimal parallel workers (aggressive scaling)
    usable_memory = available_ram * 0.85  # Use 85% of available RAM
    memory_based_workers = max(1, int(usable_memory / memory_per_file)) if memory_per_file > 0 else cpu_count
    
    # Allow up to 2x CPU count for I/O bound workloads
    cpu_based_workers = cpu_count * 2
    
    # Scale with file count (more files = more parallelism potential)
    file_based_workers = min(file_count, cpu_count * 3)
    
    # Take minimum of constraints, but ensure we use at least half CPU count
    optimal_workers = min(memory_based_workers, cpu_based_workers, file_based_workers)
    optimal_workers = max(optimal_workers, min(cpu_count // 2, file_count))
    optimal_workers = min(optimal_workers, file_count, 32)  # Cap at 32 workers
    
    # Parallel processing recommendation
    parallel_recommended = False
    parallel_reason = ""
    parallel_workers = 1
    
    if file_count <= 1:
        parallel_reason = "Single file - parallel not applicable"
    elif available_ram < 1 * 1024 * 1024 * 1024:  # < 1GB (lowered from 2GB)
        parallel_reason = "Very low RAM - parallel disabled for safety"
    elif optimal_workers <= 1:
        parallel_reason = "Insufficient resources for parallel processing"
    elif memory_per_file > usable_memory * 0.6:  # Single file uses >60% of usable RAM
        parallel_reason = "Very large files - sequential processing safer"
    else:
        parallel_recommended = True
        parallel_workers = optimal_workers
        # Estimate speedup (I/O bound tasks typically see 60-80% efficiency)
        efficiency = 0.75 if file_count >= optimal_workers else 0.65
        speedup = min(optimal_workers * efficiency, file_count)
        parallel_reason = f"{optimal_workers} workers, ~{speedup:.1f}x speedup"
    
    stats = {
        'file_count': file_count,
        'total_size': total_size,
        'total_size_fmt': format_size(total_size),
        'avg_size': avg_size,
        'avg_size_fmt': format_size(avg_size),
        'max_size': max_size,
        'max_size_fmt': format_size(max_size),
        'min_size': min_size,
        'min_size_fmt': format_size(min_size),
        'available_ram': available_ram,
        'available_ram_fmt': format_size(available_ram),
        'total_ram': total_ram,
        'total_ram_fmt': format_size(total_ram),
        'has_psutil': has_psutil,
        'cpu_count': cpu_count,
        # Parallel processing recommendations
        'parallel_recommended': parallel_recommended,
        'parallel_reason': parallel_reason,
        'parallel_workers': parallel_workers,
        'memory_per_file': memory_per_file,
        'memory_per_file_fmt': format_size(int(memory_per_file)),
    }
    
    # Thresholds (can be tuned)
    MANY_FILES_THRESHOLD = 10
    SMALL_FILE_THRESHOLD = 5 * 1024 * 1024       # 5 MB
    LARGE_FILE_THRESHOLD = 50 * 1024 * 1024      # 50 MB
    LOW_RAM_THRESHOLD = 2 * 1024 * 1024 * 1024   # 2 GB
    HIGH_RAM_THRESHOLD = 8 * 1024 * 1024 * 1024  # 8 GB
    RAM_SAFETY_FACTOR = 3  # Total data should be < available_ram / factor for unified mode
    
    # Decision logic for database mode
    
    # Rule 1: Single file - no benefit from unified mode
    if file_count == 1:
        return ('per-file', "Single file detected", stats)
    
    # Rule 2: Very low RAM - always use per-file to be safe
    if available_ram < LOW_RAM_THRESHOLD:
        return ('per-file', f"Low available RAM ({format_size(available_ram)})", stats)
    
    # Rule 3: Total size exceeds safe RAM threshold - use per-file
    if total_size > available_ram / RAM_SAFETY_FACTOR:
        return ('per-file', f"Total data size ({format_size(total_size)}) is large compared to available RAM ({format_size(available_ram)})", stats)
    
    # Rule 4: Many small files - unified mode is more efficient
    if file_count >= MANY_FILES_THRESHOLD and avg_size <= SMALL_FILE_THRESHOLD:
        return ('unified', f"Many small files detected ({file_count} files, avg {format_size(avg_size)})", stats)
    
    # Rule 5: Few very large files - per-file mode is safer
    if file_count < 5 and avg_size >= LARGE_FILE_THRESHOLD:
        return ('per-file', f"Few large files detected ({file_count} files, avg {format_size(avg_size)})", stats)
    
    # Rule 6: High RAM + moderate number of files - per-file mode (enables parallel processing)
    if available_ram >= HIGH_RAM_THRESHOLD and file_count >= 3:
        return ('per-file', f"Sufficient RAM available ({format_size(available_ram)}) with {file_count} files - parallel processing enabled", stats)
    
    # Rule 7: Many files (even if not tiny) - unified mode for correlation benefits
    if file_count >= MANY_FILES_THRESHOLD:
        return ('unified', f"Multiple files detected ({file_count})", stats)
    
    # Default: per-file mode (safer default)
    return ('per-file', f"Default mode - {file_count} files, {format_size(total_size)} total", stats)


def print_mode_recommendation(recommended_mode, reason, stats, logger, show_parallel=True):
    """Print the mode recommendation to the user with clean formatting."""
    # Check if we have the Rich console available
    if HAS_RICH and console is not None:
        _print_mode_recommendation_rich(recommended_mode, reason, stats, show_parallel)
    else:
        _print_mode_recommendation_plain(recommended_mode, reason, stats, logger, show_parallel)


def _print_mode_recommendation_rich(recommended_mode, reason, stats, show_parallel=True):
    """Print mode recommendation using Rich console."""
    from rich.table import Table
    from .console import is_quiet

    if is_quiet():
        return

    console.print("[bold white]\\[+][/] Analyzing workload...")

    # Create a nice table for workload info
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Label", style="dim")
    table.add_column("Value")

    # File stats
    file_count = stats['file_count']
    total_size = stats['total_size_fmt']
    avg_size = stats['avg_size_fmt']
    table.add_row(
        "[>] Files", 
        f"[yellow]{file_count}[/] ([cyan]{total_size}[/] total, avg [cyan]{avg_size}[/])"
    )

    if stats['has_psutil']:
        table.add_row(
            "[>] System",
            f"[green]{stats['available_ram_fmt']}[/] RAM available, [yellow]{stats['cpu_count']}[/] CPUs"
        )

    # Database mode
    mode_style = "green" if recommended_mode == 'unified' else "cyan"
    mode_label = "UNIFIED" if recommended_mode == 'unified' else "PER-FILE"
    table.add_row(
        "[>] DB Mode",
        f"[{mode_style}]{mode_label}[/]"
    )
    table.add_row("", f"[dim]{reason}[/]")

    # Parallel processing (only for per-file mode)
    if show_parallel and recommended_mode != 'unified':
        if stats.get('parallel_recommended', False):
            workers = stats.get('parallel_workers', '?')
            table.add_row(
                "[>] Parallel",
                f"[green]ENABLED[/] ([yellow]{workers}[/] workers)"
            )
        else:
            p_reason = stats.get('parallel_reason', 'Not recommended')
            table.add_row("[>] Parallel", f"[dim]disabled - {p_reason}[/]")

    console.print(table)
    console.print()


def _print_mode_recommendation_plain(recommended_mode, reason, stats, logger, show_parallel=True):
    """Print mode recommendation using plain logger (fallback)."""
    # Header
    logger.info("[+] Analyzing workload...")
    
    # File statistics
    file_count = stats['file_count']
    total_size = stats['total_size_fmt']
    avg_size = stats['avg_size_fmt']
    logger.info(f"    [>] Files: {file_count} ({total_size} total, avg {avg_size})")
    
    if stats['has_psutil']:
        ram = stats['available_ram_fmt']
        cpus = stats['cpu_count']
        logger.info(f"    [>] System: {ram} RAM available, {cpus} CPUs")
    
    # Database mode recommendation
    mode_icon = "🔗" if recommended_mode == 'unified' else "📁"
    mode_label = "UNIFIED" if recommended_mode == 'unified' else "PER-FILE"
    
    logger.info(f"    [>] {mode_icon} Database mode: {mode_label}")
    logger.info(f"        [i] {reason}")
    
    # Parallel processing recommendation (only show for per-file mode)
    if show_parallel and recommended_mode != 'unified':
        if stats.get('parallel_recommended', False):
            workers = stats.get('parallel_workers', '?')
            logger.info(f"    [>] ⚡ Parallel: ENABLED ({workers} workers)")
        else:
            p_reason = stats.get('parallel_reason', 'Not recommended')
            logger.info(f"    [>] ⚡ Parallel: disabled - {p_reason}")
    
    logger.info("")
