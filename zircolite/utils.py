"""
Utility functions and helper classes for Zircolite.

This module contains:
- Logging initialization
- File selection/filtering utilities
- Memory tracking
- Processing mode heuristics
- Field mappings configuration loader (JSON/YAML support)
"""

import csv
import logging
import os
import random
import string
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    NoReturn,
    cast,
)

import orjson
import psutil
import yaml

from .console import console, get_rich_logger

# Above this, an epoch number is milliseconds rather than seconds (1973-03-03).
_EPOCH_MS_THRESHOLD = 100_000_000_000


def parse_timestamp(value: Any) -> datetime | None:
    """Parse a log timestamp into an aware UTC datetime, or None if it is not one.

    Log producers do not agree on a spelling, and comparing the spellings instead
    of the instants silently mis-filters: an epoch number sorts below every ISO
    string, and a space separator sorts below a ``T``. So this accepts what they
    actually emit -- epoch seconds or milliseconds, a trailing ``Z``, an explicit
    offset, a space instead of ``T``, fractional seconds, a bare date -- and
    returns one comparable type. Naive values are read as UTC, which is what
    Windows and auditd both write.
    """
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        seconds = value / 1000 if abs(value) >= _EPOCH_MS_THRESHOLD else value
        try:
            return datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None

    # Only the two standard epoch widths: "20240615" is a date, not an instant
    digits = text[1:] if text[0] == "-" else text
    if digits.isdigit():
        return parse_timestamp(int(text)) if len(digits) in (10, 13) else None

    if text[-1] in "Zz":
        text = text[:-1] + "+00:00"
    if len(text) > 10 and text[10] == " ":
        text = text[:10] + "T" + text[11:]
    # Python 3.10's fromisoformat accepts only 3 or 6 fractional digits; Windows
    # writes 7
    dot = text.find(".")
    if dot != -1:
        end = dot + 1
        while end < len(text) and text[end].isdigit():
            end += 1
        text = f"{text[:dot]}.{text[dot + 1:end][:6].ljust(6, '0')}{text[end:]}"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_field_mappings(
    config_file: str, *, logger: logging.Logger | None = None
) -> dict[str, Any]:
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
        raise FileNotFoundError(
            f"Field mappings configuration file not found: {config_file}"
        )

    # Determine format from file extension
    suffix = config_path.suffix.lower()

    if suffix == ".json":
        # JSON format - use orjson for speed (tolerate a UTF-8 BOM)
        with open(config_path, "rb") as f:
            try:
                config = orjson.loads(f.read().lstrip(b"\xef\xbb\xbf"))
            except orjson.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in field mappings file: {e}") from e
    elif suffix in (".yaml", ".yml"):
        # YAML format
        with open(config_path, encoding="utf-8") as f:
            try:
                config = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ValueError(f"Invalid YAML in field mappings file: {e}") from e
    else:
        # Try to auto-detect based on content
        with open(config_path, "rb") as f:
            content = f.read()

        # Try JSON first (most common; tolerate a UTF-8 BOM)
        try:
            config = orjson.loads(content.lstrip(b"\xef\xbb\xbf"))
        except orjson.JSONDecodeError:
            # Try YAML as fallback
            try:
                config = yaml.safe_load(content.decode("utf-8-sig"))
            except (yaml.YAMLError, UnicodeDecodeError) as e:
                raise ValueError(
                    f"Unable to parse field mappings file: {config_file}. "
                    f"Supported formats: .json, .yaml, .yml"
                ) from e

    if config is None:
        config = {}

    # Ensure config is a dictionary
    if not isinstance(config, dict):
        raise ValueError(
            f"Invalid field mappings file format: {config_file}. "
            f"Expected a dictionary/object at root level."
        )

    # Validate required keys and provide defaults
    required_keys = [
        "exclusions",
        "useless",
        "mappings",
        "alias",
        "split",
        "transforms",
        "transforms_enabled",
    ]
    defaults = {
        "exclusions": [],
        "useless": [None, ""],
        "mappings": {},
        "alias": {},
        "split": {},
        "transforms": {},
        "transforms_enabled": False,
    }

    for key in required_keys:
        if key not in config:
            logger.debug(f"Field mappings config missing '{key}', using default")
            config[key] = defaults[key]

    # Add event_filter section with minimal fallback defaults
    # (Full defaults are in config/config.yaml)
    if "event_filter" not in config:
        config["event_filter"] = {
            "enabled": True,
            "channel_fields": ["Event.System.Channel", "Channel"],
            "eventid_fields": ["Event.System.EventID", "EventID"],
        }

    # Add timestamp_detection section with minimal fallback defaults
    # (Full defaults are in config/config.yaml)
    if "timestamp_detection" not in config:
        config["timestamp_detection"] = {
            "default_field": "SystemTime",
            "auto_detect": True,
            "detection_fields": ["SystemTime", "UtcTime", "@timestamp", "timestamp"],
        }

    return config


# ---------------------------------------------------------------------------
# Compressed and archive handling
# ---------------------------------------------------------------------------

# Suffixes that indicate a compressed/archived file (inner format detected separately).
COMPRESSED_SUFFIXES = frozenset((".gz", ".bz2", ".zip", ".7z"))

# Shown when decompression fails due to wrong or missing archive password.
ARCHIVE_PASSWORD_ERROR_MESSAGE = (
    "Wrong or missing archive password. "  # noqa: S105 - a message, not a credential
    "Use --archive-password with the correct password."
)


def open_maybe_compressed(
    path: Path | str,
    mode: str = "rb",
    encoding: str | None = None,
    password: str | bytes | None = None,
    errors: str = "replace",
) -> Any:
    """Open a file, transparently decompressing gz/bz2 or extracting from a zip/7z archive.

    Args:
        path: Path-like object or string pointing to the file.
        mode: Open mode.  ``'rb'`` for binary reads; ``'rt'`` for text reads.
        encoding: Character encoding for text-mode opens (defaults to ``'utf-8'``).
        password: Archive password for encrypted ZIP or 7-Zip archives.
                  May be a ``str`` or ``bytes``.  Ignored for non-archive formats.
        errors: Decoding error policy for text-mode opens.  Defaults to
                ``'replace'`` so a single undecodable byte cannot abort a whole
                log file.

    Returns:
        A file-like object.  For ZIP and 7-Zip archives the member is buffered
        in memory and returned as ``io.BytesIO`` / ``io.TextIOWrapper``.

    Raises:
        ValueError: If an archive contains zero or more than one member, or if
            decompression fails (e.g. wrong password).
        ImportError: If ``py7zr`` is not installed and a ``.7z`` file is opened.
    """
    import io

    p = Path(path)
    suffix = p.suffix.lower()
    text_mode = "t" in mode

    if suffix == ".gz":
        import gzip

        if text_mode:
            return gzip.open(p, mode, encoding=encoding or "utf-8", errors=errors)
        return gzip.open(p, "rb")

    if suffix == ".bz2":
        import bz2

        if text_mode:
            return bz2.open(p, mode, encoding=encoding or "utf-8", errors=errors)
        return bz2.open(p, "rb")

    if suffix == ".zip":
        import zipfile

        pwd = password.encode() if isinstance(password, str) else password
        try:
            with zipfile.ZipFile(p, "r") as zf:
                # Ignore directory entries and macOS resource-fork metadata so a
                # single real file in a macOS-created zip is still accepted
                members = [
                    m for m in zf.namelist()
                    if not m.endswith("/") and not m.startswith("__MACOSX/")
                ]
                if not members:
                    raise ValueError(f"ZIP archive '{p}' contains no files")
                if len(members) > 1:
                    raise ValueError(
                        f"ZIP archive '{p}' contains {len(members)} files; "
                        "only single-file archives are supported"
                    )
                data = zf.read(members[0], pwd=pwd)
        except NotImplementedError as e:
            # WinZip AES-encrypted members are unsupported by zipfile; this
            # clause must precede RuntimeError, its parent class
            raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from e
        except RuntimeError as e:
            # ZIP raises RuntimeError for wrong/missing password
            if "password" in str(e).lower() or "decrypt" in str(e).lower():
                raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from e
            raise
        if text_mode:
            return io.TextIOWrapper(io.BytesIO(data), encoding=encoding or "utf-8", errors=errors)
        return io.BytesIO(data)

    if suffix == ".7z":
        try:
            import lzma

            import py7zr
            from py7zr.exceptions import (
                Bad7zFile,
                CrcError,
                DecompressionError,
                PasswordRequired,
            )
        except ImportError as e:
            raise ImportError(
                "The 'py7zr' package is required to read .7z files. "
                "Install it with: pip install py7zr"
            ) from e
        pwd_7z: str | None = (
            password.decode() if isinstance(password, bytes) else password
        )

        class _NonClosingBytesIO(io.BytesIO):
            """BytesIO that survives close().

            py7zr's MemIO closes the writer after extraction, which would
            otherwise invalidate the buffer before we can read it back.
            """

            def close(self) -> None:
                self.flush()

        class _MemFactory:
            """Factory for py7zr in-memory extraction (create() is called per member)."""

            def __init__(self):
                self._buf = None

            def create(self, fname):
                self._buf = _NonClosingBytesIO()
                return self._buf

        try:
            with py7zr.SevenZipFile(p, "r", password=pwd_7z) as szf:
                names = szf.getnames()
                if not names:
                    raise ValueError(f"7-Zip archive '{p}' contains no files")
                if len(names) > 1:
                    raise ValueError(
                        f"7-Zip archive '{p}' contains {len(names)} files; "
                        "only single-file archives are supported"
                    )
                factory = _MemFactory()
                szf.extract(path=None, targets=names, factory=factory)  # type: ignore[arg-type]
                if factory._buf is None:
                    raise RuntimeError("7z extract produced no data")
                data = factory._buf.getvalue()
        except PasswordRequired:
            raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from None
        except Bad7zFile as e:
            # Wrong password often yields "invalid block data" at CRC check
            if "invalid" in str(e).lower():
                raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from e
            raise
        except (CrcError, DecompressionError, lzma.LZMAError) as e:
            # Wrong 7z password often yields LZMAError/CrcError during decompression
            raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from e
        except EOFError as e:
            # Which of these a wrong key produces is not stable: decrypting with
            # it yields garbage, and whether that garbage trips the CRC or simply
            # runs out before the declared size varies per archive and per py7zr
            # backend. Without a password the same exception means the archive
            # really is short, and calling that a password problem would send the
            # user looking for the wrong thing.
            if pwd_7z is not None:
                raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from e
            raise ValueError(
                f"7-Zip archive '{p}' is truncated or corrupt"
            ) from e
        if text_mode:
            return io.TextIOWrapper(io.BytesIO(data), encoding=encoding or "utf-8", errors=errors)
        return io.BytesIO(data)

    # Plain file fallback
    if text_mode:
        return open(p, mode, encoding=encoding or "utf-8", errors=errors)
    return open(p, mode)


# ---------------------------------------------------------------------------
# CSV and string helpers
# ---------------------------------------------------------------------------


CSV_DELIMITER_CANDIDATES = ",;\t|"


def sniff_csv_delimiter(sample: str, *, default: str = ",") -> str:
    """Pick the delimiter of a CSV sample, restricted to plausible candidates.

    ``csv.Sniffer`` can latch onto a recurring data letter (e.g. the 'y' in
    "Security"), so candidates are limited to ``CSV_DELIMITER_CANDIDATES`` and
    the result is only accepted when it actually splits the header line.
    Otherwise the first candidate that appears consistently across the first two
    lines wins, and *default* is the last resort.
    """
    lines = [line for line in sample.splitlines() if line.strip()]
    if not lines:
        return default

    try:
        sniffed = csv.Sniffer().sniff(sample, delimiters=CSV_DELIMITER_CANDIDATES)
        if lines[0].count(sniffed.delimiter) >= 1:
            return sniffed.delimiter
    except csv.Error:
        pass

    header = lines[0]
    for candidate in CSV_DELIMITER_CANDIDATES:
        count = header.count(candidate)
        if count < 1:
            continue
        if len(lines) < 2 or abs(count - lines[1].count(candidate)) <= 2:
            return candidate

    return default


# Spreadsheets treat a value starting with one of these as a formula, so an
# attacker-controlled command line or filename becomes code in the report.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_value_for_csv(value: Any) -> str:
    """Normalize a value for CSV output (None -> empty string).

    Newlines become spaces rather than disappearing: deleting them glued the
    adjacent lines of a multi-line PowerShell block or command line into tokens
    that never existed in the log, breaking IOC searches over the report.
    """
    if value is None:
        return ""
    text = str(value).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    if text[:1] in _CSV_FORMULA_PREFIXES:
        text = "'" + text
    return text


def sanitize_row_for_csv(row: dict[str, Any]) -> dict[str, str]:
    """Return a new dict with all values sanitized for CSV output."""
    return {k: sanitize_value_for_csv(v) for k, v in row.items()}


def random_suffix(length: int = 4) -> str:
    """Return a random alphanumeric string (uppercase + digits) of given length."""
    return "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(length)
    )


def quit_on_error(message: str, logger: logging.Logger | None = None) -> NoReturn:
    """Log error message and exit with error code.

    Declared NoReturn so callers do not have to convince a type checker that
    the value they validated is still set on the line after the check.
    """
    logger = logger or logging.getLogger(__name__)
    logger.error(message)
    sys.exit(1)


def check_if_exists(
    path: Path | str,
    error_message: str,
    logger: logging.Logger | None = None,
) -> None:
    """Check if the provided path is a file."""
    if not Path(path).is_file():
        quit_on_error(error_message, logger)


def init_logger(
    debug_mode: bool,
    log_file: str | None = None,
    name: str = "zircolite",
) -> logging.Logger:
    """Initialize logger with appropriate configuration.

    Args:
        debug_mode: Enable debug-level logging with verbose format
        log_file: Optional path to log file for persistent logging
        name: Logger name (default: 'zircolite')

    Returns:
        Configured logger instance
    """
    return get_rich_logger(name=name, debug=debug_mode, log_file=log_file)


def create_silent_logger(name: str = "zircolite_worker") -> logging.Logger:
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


def select_files(
    path_list: Sequence[Path | str],
    select_files_list: list[list[str]] | None,
) -> list[Path | str]:
    """Select files from path list based on filter criteria."""
    if select_files_list is None:
        return list(path_list)

    paths = list(path_list)
    filters = [term.lower() for group in select_files_list for term in group if group]
    selected: list[str] = []
    for element in paths:
        path_str = str(element)
        name_lower = Path(path_str).name.lower()
        if any(file_filter in name_lower for file_filter in filters):
            selected.append(path_str)
    return cast(list[Path | str], selected)


def avoid_files(
    path_list: Sequence[Path | str],
    avoid_files_list: list[list[str]] | None,
) -> list[Path | str]:
    """Filter out files from path list based on exclusion criteria."""
    if avoid_files_list is None:
        return list(path_list)

    paths = list(path_list)
    filters = [term.lower() for group in avoid_files_list for term in group if group]
    filtered: list[str] = []
    for element in paths:
        path_str = str(element)
        name_lower = Path(path_str).name.lower()
        if all(file_filter not in name_lower for file_filter in filters):
            filtered.append(path_str)
    return cast(list[Path | str], filtered)


class MemoryTracker:
    """Track memory usage during execution."""

    def __init__(self, *, logger: logging.Logger | None = None):
        """
        Initialize MemoryTracker.

        Args:
            logger: Logger instance (creates default if None)
        """
        self.logger = logger or logging.getLogger(__name__)
        self.memory_samples: list[float] = []
        self.peak_memory: float = 0.0
        self.process = psutil.Process(os.getpid())

    def get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            # Get RSS (Resident Set Size) in bytes, convert to MB
            return self.process.memory_info().rss / (1024 * 1024)
        except Exception:
            return 0

    def sample(self):
        """Take a memory usage sample."""
        memory_mb = self.get_memory_usage()
        if memory_mb > 0:
            self.memory_samples.append(memory_mb)
            if memory_mb > self.peak_memory:
                self.peak_memory = memory_mb

    def get_stats(self) -> tuple[float, float]:
        """Get peak and average memory usage."""
        if not self.memory_samples:
            return 0, 0

        peak = self.peak_memory
        average = sum(self.memory_samples) / len(self.memory_samples)

        return peak, average

    def format_memory(self, memory_mb: float) -> str:
        """Format memory value for display."""
        if memory_mb >= 1024:
            return f"{memory_mb / 1024:.2f} GB"
        else:
            return f"{memory_mb:.2f} MB"


################################################################
# HEURISTICS FOR OPTIMAL PROCESSING MODE
################################################################
def format_size(size: float) -> str:
    """Format byte size for human-readable display."""
    if size >= 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024 * 1024):.1f} GB"
    elif size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    elif size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} bytes"


def analyze_files_and_recommend_mode(
    file_list: Sequence[Path | str],
) -> tuple[str, str, dict[str, Any]]:
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

    # Delegate to the consolidated helpers so the heuristics stay in sync
    # with MemoryAwareParallelProcessor.
    from .parallel import (
        calculate_optimal_workers as _calc_workers,
    )
    from .parallel import (
        memory_multiplier_for,
    )

    # Estimate memory usage per file (dynamic multiplier based on file size)
    memory_multiplier = memory_multiplier_for(avg_size / (1024 * 1024))
    memory_per_file = avg_size * memory_multiplier

    optimal_workers = _calc_workers(
        file_sizes=file_sizes,
        available_memory_mb=available_ram / (1024 * 1024),
        cpu_count=cpu_count,
    )

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
    elif (
        max_size * memory_multiplier > (available_ram * 0.85) * 0.6
    ):  # Largest single file uses >60% of usable RAM
        parallel_reason = "Very large files - sequential processing safer"
    else:
        parallel_recommended = True
        parallel_workers = optimal_workers
        # Estimate speedup (I/O bound tasks typically see 60-80% efficiency)
        efficiency = 0.75 if file_count >= optimal_workers else 0.65
        speedup = min(optimal_workers * efficiency, file_count)
        parallel_reason = f"{optimal_workers} workers, ~{speedup:.1f}x speedup"

    stats = {
        "file_count": file_count,
        "total_size": total_size,
        "total_size_fmt": format_size(total_size),
        "avg_size": avg_size,
        "avg_size_fmt": format_size(avg_size),
        "max_size": max_size,
        "max_size_fmt": format_size(max_size),
        "min_size": min_size,
        "min_size_fmt": format_size(min_size),
        "available_ram": available_ram,
        "available_ram_fmt": format_size(available_ram),
        "total_ram": total_ram,
        "total_ram_fmt": format_size(total_ram),
        "has_psutil": has_psutil,
        "cpu_count": cpu_count,
        # Parallel processing recommendations
        "parallel_recommended": parallel_recommended,
        "parallel_reason": parallel_reason,
        "parallel_workers": parallel_workers,
        "memory_per_file": memory_per_file,
        "memory_per_file_fmt": format_size(int(memory_per_file)),
    }

    # Thresholds (can be tuned)
    MANY_FILES_THRESHOLD = 10
    SMALL_FILE_THRESHOLD = 5 * 1024 * 1024  # 5 MB
    LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB
    LOW_RAM_THRESHOLD = 2 * 1024 * 1024 * 1024  # 2 GB
    HIGH_RAM_THRESHOLD = 8 * 1024 * 1024 * 1024  # 8 GB

    # Decision logic for database mode

    # Rule 1: Single file - no benefit from unified mode
    if file_count == 1:
        return ("per-file", "Single file detected", stats)

    # Rule 2: Very low RAM - always use per-file to be safe
    if available_ram < LOW_RAM_THRESHOLD:
        return ("per-file", f"Low available RAM ({format_size(available_ram)})", stats)

    # Rule 3: Estimated in-memory footprint exceeds safe RAM threshold - use per-file.
    # The in-memory SQLite DB expands file size by up to memory_multiplier, so
    # comparing raw total size against RAM would underestimate the footprint.
    if total_size * memory_multiplier > available_ram * 0.85:
        return (
            "per-file",
            f"Total data size ({format_size(total_size)}) is large compared to available RAM ({format_size(available_ram)})",
            stats,
        )

    # Rule 4: Many small files - unified mode is more efficient
    if file_count >= MANY_FILES_THRESHOLD and avg_size <= SMALL_FILE_THRESHOLD:
        return (
            "unified",
            f"Many small files detected ({file_count} files, avg {format_size(avg_size)})",
            stats,
        )

    # Rule 5: Few very large files - per-file mode is safer
    if file_count < 5 and avg_size >= LARGE_FILE_THRESHOLD:
        return (
            "per-file",
            f"Few large files detected ({file_count} files, avg {format_size(avg_size)})",
            stats,
        )

    # Rule 6: High RAM + moderate number of files - per-file mode (enables parallel processing)
    if available_ram >= HIGH_RAM_THRESHOLD and file_count >= 3:
        if parallel_recommended:
            reason = (
                f"Sufficient RAM available ({format_size(available_ram)}) "
                f"with {file_count} files - parallel processing enabled"
            )
        else:
            reason = (
                f"Sufficient RAM available ({format_size(available_ram)}) "
                f"with {file_count} files"
            )
        return ("per-file", reason, stats)

    # Rule 7: Many files (even if not tiny) - unified mode for correlation benefits
    if file_count >= MANY_FILES_THRESHOLD:
        return ("unified", f"Multiple files detected ({file_count})", stats)

    # Default: per-file mode (safer default)
    return (
        "per-file",
        f"Default mode - {file_count} files, {format_size(total_size)} total",
        stats,
    )


def print_mode_recommendation(
    recommended_mode: str,
    reason: str,
    stats: dict[str, Any],
    show_parallel: bool = True,
    forced_workers: int | None = None,
) -> None:
    """Print the mode recommendation to the user with clean formatting."""
    _print_mode_recommendation_rich(
        recommended_mode, reason, stats, show_parallel, forced_workers
    )


def _print_mode_recommendation_rich(
    recommended_mode: str,
    reason: str,
    stats: dict[str, Any],
    show_parallel: bool = True,
    forced_workers: int | None = None,
) -> None:
    """Print mode recommendation using Rich console."""
    from rich.table import Table

    from .console import is_quiet

    if is_quiet():
        return
    if console is None:
        return

    console.print("[bold white]\\[+][/] Analyzing workload...")

    # Create a nice table for workload info
    table = Table(show_header=False, box=None, padding=(0, 4))
    table.add_column("Label", style="dim")
    table.add_column("Value")

    # File stats
    file_count = stats["file_count"]
    total_size = stats["total_size_fmt"]
    avg_size = stats["avg_size_fmt"]
    table.add_row(
        "[>] Files",
        f"[yellow]{file_count}[/] ([cyan]{total_size}[/] total, avg [cyan]{avg_size}[/])",
    )

    if stats["has_psutil"]:
        table.add_row(
            "[>] System",
            f"[green]{stats['available_ram_fmt']}[/] RAM available, [yellow]{stats['cpu_count']}[/] CPUs",
        )

    # Database mode
    mode_style = "green" if recommended_mode == "unified" else "cyan"
    mode_label = "UNIFIED" if recommended_mode == "unified" else "PER-FILE"
    table.add_row("[>] DB Mode", f"[{mode_style}]{mode_label}[/]")
    table.add_row("", f"[dim]{reason}[/]")

    # Parallel processing (only for per-file mode)
    if show_parallel and recommended_mode != "unified":
        is_forced = forced_workers is not None and forced_workers > 0
        parallel_will_run = stats.get("parallel_recommended", False) or is_forced

        if is_forced and parallel_will_run:
            auto_workers = stats.get("parallel_workers", "?")
            table.add_row(
                "[>] Parallel",
                f"[green]ENABLED[/] ([yellow]{forced_workers}[/] workers) "
                f"[magenta]forced via --parallel-workers[/] "
                f"[dim](auto-detected: {auto_workers})[/]",
            )
        elif stats.get("parallel_recommended", False):
            workers = stats.get("parallel_workers", "?")
            table.add_row(
                "[>] Parallel", f"[green]ENABLED[/] ([yellow]{workers}[/] workers)"
            )
        else:
            p_reason = stats.get("parallel_reason", "Not recommended")
            table.add_row("[>] Parallel", f"[dim]disabled - {p_reason}[/]")

    console.print(table)
    console.print()
