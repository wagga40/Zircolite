"""
Automatic log type and timestamp detection for Zircolite.

This module provides content-based detection of log formats to reduce
the need for explicit CLI flags. It examines file extension, magic bytes,
and content structure to determine the log type and suggest appropriate
processing parameters.

Supported detections:
- EVTX binary files (magic bytes)
- SQLite database files (magic bytes)
- Windows EVTX exported as JSON/JSONL
- Windows EVTX exported as XML
- Sysmon for Linux logs (syslog with embedded XML)
- Auditd logs (key=value format)
- Sysmon for Windows JSON exports (via channel detection)
- ECS/Elastic format JSON
- EVTXtract output
- CSV log files
- Generic JSON/JSONL
"""

import csv
import io
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import orjson as json

from zircolite.utils import (
    ARCHIVE_PASSWORD_ERROR_MESSAGE,
    COMPRESSED_SUFFIXES,
    sniff_csv_delimiter,
)

from .formats import EXTENSION_FALLBACKS

# =========================================================================
# Pre-compiled module-level constants
# =========================================================================

# EVTX magic bytes: "ElfFile\x00"
EVTX_MAGIC = b"ElfFile\x00"

# SQLite database file header (first 16 bytes)
SQLITE_MAGIC = b"SQLite format 3\x00"

# ---- Regex patterns for raw-content timestamp detection ----
# Each tuple: (compiled_regex, human-readable format name, example)
# Order matters: more specific patterns first to avoid false positives.
TIMESTAMP_RAW_PATTERNS = [
    # ISO 8601 full: 2024-06-15T10:30:00.123456Z or +00:00
    (
        re.compile(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
        ),
        "ISO 8601",
        "2024-06-15T10:30:00.123Z",
    ),
    # ISO 8601 with space separator: 2024-06-15 10:30:00
    (
        re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?"),
        "ISO 8601 (space)",
        "2024-06-15 10:30:00",
    ),
    # US/EU date format: 06/15/2024 10:30:00
    (
        re.compile(r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}"),
        "US date-time",
        "06/15/2024 10:30:00",
    ),
    # Syslog: Jun 15 10:30:00  (month name + day + time)
    (
        re.compile(
            r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
        ),
        "Syslog",
        "Jun 15 10:30:00",
    ),
    # Windows FileTime / LDAP: 18-digit integer (e.g. 133627842000000000)
    (re.compile(r"(?<!\d)1\d{17}(?!\d)"), "Windows FileTime", "133627842000000000"),
    # Epoch seconds: 10-digit integer (standalone)
    (re.compile(r"(?<!\d)\d{10}(?!\d)"), "Epoch seconds", "1718442600"),
    # Epoch milliseconds: 13-digit integer (standalone)
    (re.compile(r"(?<!\d)\d{13}(?!\d)"), "Epoch milliseconds", "1718442600000"),
]

# Auditd line pattern: [node=HOST] type=XXXX msg=audit(TIMESTAMP.NNN:SEQ):
AUDITD_LINE_PATTERN = re.compile(r"^(?:node=\S+\s+)?type=\w+\s+msg=audit\(\d+\.\d+:\d+\):")

# Sysmon for Linux: syslog header before XML
SYSMON_LINUX_SYSLOG_PATTERN = re.compile(r"^\w+\s+\d+\s+[\d:]+\s+\S+\s+\S+.*<Event>")

# Windows Event XML namespace
WINDOWS_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# EVTXtract markers
EVTXTRACT_MARKERS = (
    "Found at offset",
    "Valid header",
    "Record number",
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"',
)

# Auditd type values (most common)
AUDITD_TYPES = frozenset(
    {
        "SYSCALL",
        "EXECVE",
        "PATH",
        "CWD",
        "PROCTITLE",
        "USER_AUTH",
        "USER_ACCT",
        "CRED_ACQ",
        "CRED_DISP",
        "USER_START",
        "USER_END",
        "USER_LOGIN",
        "USER_CMD",
        "LOGIN",
        "SERVICE_START",
        "SERVICE_STOP",
        "ANOM_PROMISCUOUS",
        "NETFILTER_CFG",
        "SYSTEM_BOOT",
        "SYSTEM_SHUTDOWN",
        "DAEMON_START",
        "DAEMON_END",
        "CONFIG_CHANGE",
        "AVC",
        "SELINUX_ERR",
        "CRYPTO_KEY_USER",
        "CRYPTO_SESSION",
    }
)

# Sysmon channel names
SYSMON_CHANNELS = frozenset(
    {
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-Sysmon",
    }
)

# ---- Pre-compiled regexes for _looks_like_timestamp ----
_RE_ISO8601 = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_RE_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RE_SLASH_DATE = re.compile(r"^\d{2}/\d{2}/\d{4}")
_RE_SYSLOG_TS = re.compile(
    r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)

# ---- Pre-computed sets for _timestamp_field_score ----
_EXACT_TS_NAMES = frozenset(
    {
        "systemtime",
        "utctime",
        "@timestamp",
        "timestamp",
        "timecreated",
        "eventtime",
        "_time",
        "datetime",
    }
)
_SHORT_TS_NAMES = frozenset({"ts", "dt"})


@dataclass
class DetectionResult:
    """Result of automatic log type detection."""

    # Processing format for Zircolite ('evtx', 'json', 'json_array', 'xml',
    # 'sysmon_linux', 'auditd', 'csv', 'evtxtract')
    input_type: str

    # More specific log source identifier
    # ('windows_evtx', 'windows_evtx_json', 'windows_evtx_xml',
    #  'sysmon_windows', 'sysmon_linux', 'auditd', 'ecs_elastic',
    #  'generic_json', 'generic_csv', 'evtxtract')
    log_source: str

    # Detection confidence: 'high', 'medium', 'low'
    confidence: str

    # Suggested timestamp field name (None if unknown)
    timestamp_field: str | None = None

    # Suggested Sigma pipeline (None if unknown)
    suggested_pipeline: str | None = None

    # Human-readable description of the detection
    details: str = ""

    # Additional metadata from detection
    metadata: dict = field(default_factory=dict)


def _first_balanced_object(text: str) -> str | None:
    """The first complete top-level ``{...}`` in *text*, or None.

    Quote- and escape-aware, so a brace inside a string value does not throw
    the count off. This is what makes array recovery independent of layout: a
    compact array has no line to parse, and a pretty-printed one has no
    *complete* object on any single line, so both defeated the line-by-line
    fallback once the array outgrew the sample.
    """
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


class LogTypeDetector:
    """
    Automatic log type detector for Zircolite.

    Analyzes files by examining their extension, magic bytes, and content
    structure to determine the log format and source type.

    Usage:
        detector = LogTypeDetector(logger=logger)
        result = detector.detect(Path("logs/security.evtx"))
        print(result.input_type)       # 'evtx'
        print(result.log_source)       # 'windows_evtx'
        print(result.timestamp_field)  # 'SystemTime'
    """

    # Number of lines/bytes to sample for content analysis
    SAMPLE_LINES = 20
    SAMPLE_BYTES = 65536  # 64KB

    def __init__(
        self,
        logger: logging.Logger | None = None,
        timestamp_detection_fields: list[str] | None = None,
        archive_password: str | None = None,
    ):
        """
        Initialize LogTypeDetector.

        Args:
            logger: Logger instance (creates default if None)
            timestamp_detection_fields: Ordered list of timestamp field names
                to try during auto-detection. If None, uses built-in defaults.
            archive_password: Password for encrypted ZIP/7-Zip archives when
                sampling content for detection. Enables opening protected
                archives to determine inner log format.
        """
        self.logger = logger or logging.getLogger(__name__)
        self._timestamp_fields = tuple(
            timestamp_detection_fields
            or [
                "SystemTime",
                "UtcTime",
                "TimeCreated",
                "@timestamp",
                "timestamp",
                "Timestamp",
                "EventTime",
                "event_time",
                "datetime",
                "DateTime",
                "_time",
                "ts",
            ]
        )
        self._archive_password = archive_password

    # ----------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------

    def detect(self, file_path: Path) -> DetectionResult:
        """
        Detect the log type of a file.

        Performs detection in phases:
        1. Magic bytes check (for binary formats)
        2. Content sampling and structured analysis
        3. Extension-based fallback, enriched with raw timestamp regex scan

        Args:
            file_path: Path to the log file to analyze

        Returns:
            DetectionResult with detected type and metadata
        """
        file_path = Path(file_path)

        if not file_path.is_file():
            self.logger.debug(f"Detection: file not found: {file_path}")
            return self._unknown_result(f"File not found: {file_path}")

        # Phase 0: Compressed/archived file? Resolve inner extension and sample first.
        resolved = self._resolve_compressed(file_path)
        if resolved is not None:
            _base_ext, sample_bytes, sample_text, sample_lines = resolved
            if not sample_bytes:
                return self._fallback_by_extension(
                    _base_ext,
                    "File is empty or could not decompress (e.g. password-protected)",
                )
            content_result = self._detect_from_content(
                sample_bytes, sample_text, sample_lines, _base_ext
            )
            if content_result:
                if content_result.timestamp_field is None:
                    self._enrich_timestamp_from_raw(
                        content_result, sample_text, sample_bytes
                    )
                return content_result
            fallback = self._fallback_by_extension(
                _base_ext, "Could not determine format from content"
            )
            if fallback.timestamp_field is None:
                self._enrich_timestamp_from_raw(fallback, sample_text, sample_bytes)
            return fallback

        # Phase 1: Plain file — magic bytes then content
        magic_result = self._check_magic_bytes(file_path)
        if magic_result:
            return magic_result

        try:
            sample_bytes, sample_text, sample_lines = self._read_sample(file_path)
        except Exception as e:
            self.logger.debug(f"Detection: cannot read file {file_path}: {e}")
            return self._fallback_by_extension(
                file_path.suffix.lower(), f"Cannot read file: {e}"
            )

        if not sample_bytes:
            return self._fallback_by_extension(
                file_path.suffix.lower(), "File is empty"
            )

        content_result = self._detect_from_content(
            sample_bytes, sample_text, sample_lines, file_path.suffix.lower()
        )
        if content_result:
            if content_result.timestamp_field is None:
                self._enrich_timestamp_from_raw(
                    content_result, sample_text, sample_bytes
                )
            return content_result

        fallback = self._fallback_by_extension(
            file_path.suffix.lower(), "Could not determine format from content"
        )
        if fallback.timestamp_field is None:
            self._enrich_timestamp_from_raw(fallback, sample_text, sample_bytes)
        return fallback

    def detect_batch(self, file_paths: list[Path]) -> DetectionResult:
        """
        Detect the log type from a batch of files.

        Analyzes the first few files and returns the most confident
        detection result. Useful when processing a directory of log files.

        Args:
            file_paths: List of file paths to analyze

        Returns:
            DetectionResult representing the consensus detection
        """
        if not file_paths:
            return self._unknown_result("No files to analyze")

        # Sample up to 3 files for consistency
        results = [self.detect(fp) for fp in file_paths[:3]]

        # Return highest confidence result
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        results.sort(key=lambda r: confidence_order.get(r.confidence, 3))
        best = results[0]

        # If all files agree on input_type, boost confidence
        if (
            len(results) > 1
            and best.confidence == "medium"
            and all(r.input_type == best.input_type for r in results)
        ):
            best.confidence = "high"
            best.details += " (confirmed across multiple files)"

        return best

    def detect_timestamp_field(self, event: dict) -> str | None:
        """
        Detect the timestamp field from a parsed event dictionary.

        Tries known timestamp field names in priority order, then falls
        back to heuristic detection based on value format.

        Args:
            event: A parsed (optionally flattened) event dictionary

        Returns:
            The detected timestamp field name, or None if not found
        """
        looks_like = self._looks_like_timestamp  # local ref

        # Phase 1: Try known field names in priority order
        for field_name in self._timestamp_fields:
            if field_name in event and looks_like(event[field_name]):
                return field_name

        # Phase 2: Scan all fields for timestamp-like values, scored by name.
        # The name has to carry some signal: any large integer or 10/13-digit
        # string looks like an epoch, so an unscored field (a byte count, a
        # serial number) would otherwise be picked as the time field and then
        # drive correlation windows and -A/-B filtering.
        best_key = None
        best_score = 0
        for key, value in event.items():
            if looks_like(value):
                score = self._timestamp_field_score(key)
                if score > best_score:
                    best_score = score
                    best_key = key

        return best_key

    # ----------------------------------------------------------------
    # Internal: compressed file resolution, then sampling and magic bytes
    # ----------------------------------------------------------------

    def _archive_password_bytes(self) -> bytes | None:
        """Return archive password as bytes for ZIP/7z APIs, or None."""
        if self._archive_password is None:
            return None
        if isinstance(self._archive_password, str):
            return self._archive_password.encode()
        return self._archive_password

    def _sevenzip_inner_extension(self, file_path: Path) -> str:
        """Extension of the archive's first member, or the file name's own.

        The import is guarded separately from the archive read on purpose:
        naming ``PasswordRequired`` in an except clause that the import itself
        can reach makes a missing py7zr raise ``UnboundLocalError`` out of the
        handler, where no later clause catches it.
        """
        fallback = Path(file_path.stem).suffix.lower()
        try:
            import py7zr
            from py7zr.exceptions import PasswordRequired
        except ImportError:
            return fallback

        try:
            with py7zr.SevenZipFile(
                file_path, "r", password=self._archive_password
            ) as szf:
                names = szf.getnames()
                return Path(names[0]).suffix.lower() if names else fallback
        except PasswordRequired:
            raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from None
        except Exception:
            return fallback

    def _sevenzip_sample(self, file_path: Path) -> bytes:
        """First bytes of the archive's first member, empty when unreadable.

        The import is guarded separately for the same reason as in
        :meth:`_sevenzip_inner_extension`.
        """
        try:
            import io as _io

            import py7zr
            from py7zr.exceptions import PasswordRequired
        except ImportError:
            return b""

        class _NonClosingBytesIO(_io.BytesIO):
            """py7zr closes the writer after extraction; keep it readable."""

            def close(self) -> None:
                self.flush()

        class _MemFactory:
            def __init__(self):
                self._buf: _NonClosingBytesIO | None = None

            def create(self, fname):
                self._buf = _NonClosingBytesIO()
                return self._buf

        try:
            with py7zr.SevenZipFile(
                file_path, "r", password=self._archive_password
            ) as szf:
                names = szf.getnames()
                if not names:
                    return b""
                factory = _MemFactory()
                szf.extract(path=None, targets=[names[0]], factory=factory)  # type: ignore[arg-type]
                if factory._buf is None:
                    return b""
                return factory._buf.getvalue()[: self.SAMPLE_BYTES]
        except PasswordRequired:
            raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from None
        except Exception:
            # e.g. corrupt or wrong password (LZMAError) -- fall back to an
            # empty sample and let detection work from the file name
            return b""

    def _resolve_compressed(
        self, file_path: Path
    ) -> tuple[str, bytes, str, list[str]] | None:
        """
        If the file is a compressed/archived type (.gz, .bz2, .zip, .7z), resolve
        the inner extension and decompressed sample for format detection.

        Returns:
            None if the file is not compressed; otherwise
            (base_ext, sample_bytes, sample_text, sample_lines) for the inner content.
            Uses archive_password for ZIP/7-Zip when set.
        """
        suffix = file_path.suffix.lower()
        if suffix not in COMPRESSED_SUFFIXES:
            return None

        # Step 1: Resolve inner extension (from archive when openable, else from filename)
        if suffix in (".gz", ".bz2"):
            base_ext = Path(file_path.stem).suffix.lower()
        elif suffix == ".zip":
            try:
                import zipfile

                with zipfile.ZipFile(file_path, "r") as zf:
                    members = [m for m in zf.namelist() if not m.endswith("/")]
                    if members:
                        base_ext = Path(members[0]).suffix.lower()
                    else:
                        base_ext = Path(file_path.stem).suffix.lower()
            except Exception:
                base_ext = Path(file_path.stem).suffix.lower()
        elif suffix == ".7z":
            base_ext = self._sevenzip_inner_extension(file_path)
        else:
            # Unreachable while COMPRESSED_SUFFIXES holds only the four handled
            # above, but a new suffix must degrade to the filename rather than
            # leave base_ext unbound.
            base_ext = Path(file_path.stem).suffix.lower()

        # Step 2: Decompress and sample (same password used for ZIP/7z)
        sample_bytes = b""
        if suffix == ".gz":
            import gzip

            try:
                with gzip.open(file_path, "rb") as f:
                    sample_bytes = f.read(self.SAMPLE_BYTES)
            except Exception:
                pass
        elif suffix == ".bz2":
            import bz2

            try:
                with bz2.open(file_path, "rb") as bz2_file:
                    sample_bytes = bz2_file.read(self.SAMPLE_BYTES)
            except Exception:
                pass
        elif suffix == ".zip":
            try:
                import zipfile

                with zipfile.ZipFile(file_path, "r") as zf:
                    members = [
                        m for m in zf.namelist()
                        if not m.endswith("/") and not m.startswith("__MACOSX/")
                    ]
                    if members:
                        # zf.open() streams: only the sample is decompressed
                        with zf.open(
                            members[0], pwd=self._archive_password_bytes()
                        ) as member:
                            sample_bytes = member.read(self.SAMPLE_BYTES)
            except NotImplementedError:
                # WinZip AES encryption is unsupported by zipfile; this clause
                # must precede RuntimeError, its parent class
                raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from None
            except RuntimeError as e:
                # Encrypted ZIP without (or with a wrong) password
                if "password" in str(e).lower() or "decrypt" in str(e).lower():
                    raise ValueError(ARCHIVE_PASSWORD_ERROR_MESSAGE) from None
            except Exception:
                pass
        elif suffix == ".7z":
            sample_bytes = self._sevenzip_sample(file_path) or sample_bytes

        text = self._decode_sample(sample_bytes)
        lines = text.splitlines()[: self.SAMPLE_LINES]
        return (base_ext, sample_bytes, text, lines)

    def _check_magic_bytes(self, file_path: Path) -> DetectionResult | None:
        """Check file magic bytes for binary format detection.

        Only ever called on plain files: ``detect`` resolves every compressed
        suffix to its inner member before the magic-byte phase.
        """
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)

            if len(header) >= 8 and header[:8] == EVTX_MAGIC:
                return DetectionResult(
                    input_type="evtx",
                    log_source="windows_evtx",
                    confidence="high",
                    timestamp_field="SystemTime",
                    suggested_pipeline="sysmon",
                    details="EVTX binary file detected via magic bytes (ElfFile header)",
                )
            if len(header) >= 16 and header[:16] == SQLITE_MAGIC:
                return DetectionResult(
                    input_type="sqlite",
                    log_source="sqlite_db",
                    confidence="high",
                    timestamp_field=None,
                    suggested_pipeline=None,
                    details="SQLite database file detected via magic bytes",
                )
        except Exception as e:
            self.logger.debug(f"Detection: magic bytes check failed: {e}")

        return None

    @staticmethod
    def _decode_sample(sample_bytes: bytes) -> str:
        """Decode a content sample, honoring BOMs before plain UTF-8/Latin-1.

        Windows tooling often emits UTF-16 (with BOM) and editors add a UTF-8
        BOM; without this, no pattern can match the NUL-laden or BOM-prefixed
        content and detection silently degrades to extension fallback.
        """
        if sample_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
            try:
                return sample_bytes.decode("utf-16")
            except UnicodeDecodeError:
                pass
        try:
            return sample_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            return sample_bytes.decode("iso-8859-1")

    def _read_sample(self, file_path: Path) -> tuple[bytes, str, list[str]]:
        """
        Read a sample of a plain (non-compressed) file for content analysis.

        Compressed files are handled earlier by _resolve_compressed().

        Returns:
            (raw_bytes, decoded_text, first_N_lines)
        """
        with open(file_path, "rb") as f:
            sample_bytes = f.read(self.SAMPLE_BYTES)

        text = self._decode_sample(sample_bytes)

        lines = text.splitlines()[: self.SAMPLE_LINES]
        return sample_bytes, text, lines

    # ----------------------------------------------------------------
    # Internal: content-based dispatch
    # ----------------------------------------------------------------

    def _detect_from_content(
        self,
        sample_bytes: bytes,
        sample_text: str,
        sample_lines: list[str],
        ext: str,
    ) -> DetectionResult | None:
        """Detect format from file content."""
        # Binary formats can arrive here after decompression (e.g. .evtx.gz):
        # re-check magic bytes on the (possibly decompressed) sample first.
        if len(sample_bytes) >= 8 and sample_bytes[:8] == EVTX_MAGIC:
            return DetectionResult(
                input_type="evtx",
                log_source="windows_evtx",
                confidence="high",
                timestamp_field="SystemTime",
                suggested_pipeline="sysmon",
                details="EVTX binary detected via magic bytes after decompression",
            )
        if len(sample_bytes) >= 16 and sample_bytes[:16] == SQLITE_MAGIC:
            return DetectionResult(
                input_type="sqlite",
                log_source="sqlite_db",
                confidence="high",
                timestamp_field=None,
                suggested_pipeline=None,
                details="SQLite database detected via magic bytes after decompression",
            )

        if not sample_lines:
            return None

        # Skip leading blank lines (and BOM-only lines) when picking the family
        first_line = next((ln for ln in sample_lines if ln.strip()), "")
        first_char = first_line.lstrip()[:1]

        # Fast-path: first non-whitespace character determines the family
        if first_char in ("{", "["):
            return self._check_json(first_line, sample_bytes)

        if first_char == "<":
            # Could be XML, but first rule out Sysmon-for-Linux (syslog + XML)
            # and EVTXtract (text markers + XML)
            sysmon = self._check_sysmon_linux(sample_lines)
            if sysmon:
                return sysmon
            evtxtract = self._check_evtxtract(sample_text)
            if evtxtract:
                return evtxtract
            return self._check_xml(sample_text)

        # Plain-text formats: auditd, sysmon-linux, evtxtract, CSV
        auditd = self._check_auditd(sample_lines)
        if auditd:
            return auditd

        sysmon = self._check_sysmon_linux(sample_lines)
        if sysmon:
            return sysmon

        evtxtract = self._check_evtxtract(sample_text)
        if evtxtract:
            return evtxtract

        csv_result = self._check_csv(sample_lines, ext)
        if csv_result:
            return csv_result

        return None

    # ----------------------------------------------------------------
    # Internal: format-specific checks
    # ----------------------------------------------------------------

    def _check_auditd(self, lines: list[str]) -> DetectionResult | None:
        """Check if content matches auditd log format."""
        match = AUDITD_LINE_PATTERN.match  # local ref
        auditd_matches = sum(
            1 for line in lines[:10] if line.strip() and match(line.strip())
        )

        if auditd_matches >= 2:
            return DetectionResult(
                input_type="auditd",
                log_source="auditd",
                confidence="high",
                timestamp_field="timestamp",
                details=f"Auditd log format detected ({auditd_matches} matching lines)",
                metadata={"matched_lines": auditd_matches},
            )
        if auditd_matches == 1:
            return DetectionResult(
                input_type="auditd",
                log_source="auditd",
                confidence="medium",
                timestamp_field="timestamp",
                details="Auditd log format detected (1 matching line)",
                metadata={"matched_lines": 1},
            )

        return None

    def _check_sysmon_linux(self, lines: list[str]) -> DetectionResult | None:
        """Check if content matches Sysmon for Linux log format."""
        sysmon_matches = 0
        has_syslog_header = False
        syslog_match = SYSMON_LINUX_SYSLOG_PATTERN.match  # local ref

        for line in lines[:10]:
            stripped = line.strip()
            if not stripped:
                continue

            if syslog_match(stripped):
                has_syslog_header = True
                sysmon_matches += 1
            elif "<Event>" in stripped and "<EventID>" in stripped:
                if (
                    "RuleName" in stripped
                    or "ProcessGuid" in stripped
                    or "UtcTime" in stripped
                ):
                    sysmon_matches += 1

        if sysmon_matches >= 2:
            return DetectionResult(
                input_type="sysmon_linux",
                log_source="sysmon_linux",
                confidence="high",
                timestamp_field="UtcTime",
                suggested_pipeline="sysmon",
                details=f"Sysmon for Linux log format detected ({sysmon_matches} matching lines)",
                metadata={"has_syslog_header": has_syslog_header},
            )
        if sysmon_matches == 1 and has_syslog_header:
            return DetectionResult(
                input_type="sysmon_linux",
                log_source="sysmon_linux",
                confidence="medium",
                timestamp_field="UtcTime",
                suggested_pipeline="sysmon",
                details="Sysmon for Linux log format detected (1 matching line)",
            )

        # A single namespace-less XML line without a syslog header is more
        # likely a Windows Sysmon/Event XML file: let _check_xml decide.
        return None

    def _check_evtxtract(self, text: str) -> DetectionResult | None:
        """Check if content matches EVTXtract output format."""
        marker_count = sum(1 for m in EVTXTRACT_MARKERS if m in text)

        if marker_count >= 2:
            return DetectionResult(
                input_type="evtxtract",
                log_source="evtxtract",
                confidence="high",
                timestamp_field="SystemTime",
                details=f"EVTXtract output detected ({marker_count} markers found)",
                metadata={"markers_found": marker_count},
            )

        return None

    def _check_xml(self, text: str) -> DetectionResult | None:
        """Analyze XML content to determine the specific log source."""
        has_windows_ns = WINDOWS_EVENT_NS in text
        has_event_tag = "<Event " in text or "<Event>" in text

        if has_windows_ns and has_event_tag:
            return DetectionResult(
                input_type="xml",
                log_source="windows_evtx_xml",
                confidence="high",
                timestamp_field="SystemTime",
                suggested_pipeline="sysmon",
                details="Windows Event Log XML format detected (Microsoft namespace found)",
            )

        if has_event_tag:
            return DetectionResult(
                input_type="xml",
                log_source="windows_evtx_xml",
                confidence="medium",
                timestamp_field="SystemTime",
                details="XML with Event tags detected (no Microsoft namespace)",
            )

        return DetectionResult(
            input_type="xml",
            log_source="generic_xml",
            confidence="low",
            details="Generic XML file detected, assuming Event Log XML format",
        )

    def _check_json(
        self, first_line: str, sample_bytes: bytes
    ) -> DetectionResult | None:
        """Analyze JSON content to determine the specific log source.

        *first_line* is the first non-blank line, as chosen by the caller: a
        leading blank line used to make an array look like JSONL here, and the
        line-by-line reader then dropped every line of the file.
        """
        is_json_array = first_line.lstrip().startswith("[")

        first_event = self._parse_first_json_event(sample_bytes, is_json_array)
        if first_event is None:
            input_type = "json"
            if is_json_array:
                input_type = "json_array"
            return DetectionResult(
                input_type=input_type,
                log_source="generic_json",
                confidence="low",
                details="JSON file detected but could not parse first event",
            )

        return self._classify_json_event(first_event, is_json_array)

    def _parse_first_json_event(
        self, sample_bytes: bytes, is_json_array: bool
    ) -> dict | None:
        """Parse the first JSON event from a sample.

        Decoded first: parsing the raw bytes meant a UTF-8 BOM poisoned the
        first line and UTF-16 defeated the parse entirely, degrading a
        perfectly ordinary PowerShell export to generic_json with no timestamp
        field.
        """
        text = self._decode_sample(sample_bytes)
        try:
            if is_json_array:
                data = json.loads(text)
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    return data[0]
                return None
            for line in text.split("\n"):
                line = line.strip()
                if line:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        return event
            return None
        except Exception:
            # The sample stops wherever 64 KB ran out, so an array larger than
            # it never parses whole. Recover one event from it instead.
            for line in text.split("\n"):
                line = line.strip()
                if not line or line in ("[", "]", ","):
                    continue
                line = line.removesuffix(",")
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        return event
                except Exception:
                    continue

            candidate = _first_balanced_object(text)
            if candidate is not None:
                try:
                    event = json.loads(candidate)
                    if isinstance(event, dict):
                        return event
                except Exception:
                    pass

        return None

    def _classify_json_event(
        self, event: dict, is_json_array: bool
    ) -> DetectionResult:
        """Classify a JSON event based on its structure and fields."""
        flat_keys: set = set()
        self._collect_keys(event, flat_keys)

        input_type = "json_array" if is_json_array else "json"

        # --- Windows EVTX JSON (nested Event.System.*) ---
        event_obj = event.get("Event")
        if isinstance(event_obj, dict):
            system_obj = event_obj.get("System")
            if isinstance(system_obj, dict) and (
                "Channel" in system_obj or "EventID" in system_obj
            ):
                channel = system_obj.get("Channel", "")
                event_data_obj = event_obj.get("EventData")

                if channel in SYSMON_CHANNELS:
                    return DetectionResult(
                        input_type=input_type,
                        log_source="sysmon_windows",
                        confidence="high",
                        timestamp_field="UtcTime",
                        suggested_pipeline="sysmon",
                        details=f"Sysmon Windows JSON detected (channel: {channel})",
                        metadata={
                            "channel": channel,
                            "has_event_data": bool(event_data_obj),
                        },
                    )

                return DetectionResult(
                    input_type=input_type,
                    log_source="windows_evtx_json",
                    confidence="high",
                    timestamp_field="SystemTime",
                    suggested_pipeline="sysmon",
                    details="Windows Event Log JSON detected"
                    + (f" (channel: {channel})" if channel else ""),
                    metadata={
                        "channel": channel,
                        "has_event_data": bool(event_data_obj),
                    },
                )

        # --- Pre-flattened Windows events ---
        if "Channel" in event and "EventID" in event:
            channel = str(event.get("Channel", ""))

            if channel in SYSMON_CHANNELS:
                return DetectionResult(
                    input_type=input_type,
                    log_source="sysmon_windows",
                    confidence="high",
                    timestamp_field="UtcTime",
                    suggested_pipeline="sysmon",
                    details=f"Pre-flattened Sysmon Windows JSON detected (channel: {channel})",
                    metadata={"channel": channel, "pre_flattened": True},
                )

            ts_field = self.detect_timestamp_field(event)
            return DetectionResult(
                input_type=input_type,
                log_source="windows_evtx_json",
                confidence="high",
                timestamp_field=ts_field or "SystemTime",
                suggested_pipeline="sysmon",
                details="Pre-flattened Windows Event Log JSON detected"
                + (f" (channel: {channel})" if channel else ""),
                metadata={"channel": channel, "pre_flattened": True},
            )

        # --- ECS / Elastic Common Schema ---
        if "@timestamp" in event or "event.module" in flat_keys:
            winlog = event.get("winlog")
            if isinstance(winlog, dict) and winlog.get("channel"):
                channel = winlog["channel"]
                return DetectionResult(
                    input_type=input_type,
                    log_source="ecs_elastic",
                    confidence="high",
                    timestamp_field="@timestamp",
                    details=f"Elastic/ECS format detected (winlog.channel: {channel})",
                    metadata={"channel": channel, "format": "ecs"},
                )

            return DetectionResult(
                input_type=input_type,
                log_source="ecs_elastic",
                confidence="medium",
                timestamp_field="@timestamp",
                details="Elastic/ECS format detected (@timestamp field present)",
                metadata={"format": "ecs"},
            )

        # --- Auditd JSON ---
        if "type" in event:
            event_type = str(event["type"]).upper()
            if event_type in AUDITD_TYPES:
                ts_field = self.detect_timestamp_field(event)
                return DetectionResult(
                    input_type=input_type,
                    log_source="auditd",
                    confidence="high",
                    timestamp_field=ts_field or "timestamp",
                    details=f"Auditd JSON format detected (type: {event_type})",
                    metadata={"auditd_type": event_type},
                )

        # --- Sysmon fields in any JSON structure ---
        sysmon_fields = {"RuleName", "ProcessGuid", "ProcessId", "Image", "UtcTime"}
        matched_sysmon = sysmon_fields & flat_keys
        if len(matched_sysmon) >= 3:
            return DetectionResult(
                input_type=input_type,
                log_source="sysmon_windows",
                confidence="medium",
                timestamp_field="UtcTime",
                suggested_pipeline="sysmon",
                details="Sysmon JSON detected (Sysmon-specific fields present)",
                metadata={"sysmon_fields_found": sorted(matched_sysmon)},
            )

        # --- Generic JSON ---
        ts_field = self.detect_timestamp_field(event)
        return DetectionResult(
            input_type=input_type,
            log_source="generic_json",
            confidence="medium" if ts_field else "low",
            timestamp_field=ts_field,
            details="Generic JSON format detected"
            + (
                f" (timestamp field: {ts_field})"
                if ts_field
                else " (no timestamp field detected)"
            ),
            metadata={"sample_keys": list(event.keys())[:20]},
        )

    def _check_csv(self, lines: list[str], ext: str) -> DetectionResult | None:
        """Check if content is CSV format and classify it."""
        heuristic_delim: str | None = None
        if ext not in (".csv", ".tsv"):
            if len(lines) < 2:
                return None
            # Quick heuristic: consistent delimiter count across first two lines
            first = lines[0]
            for delimiter in (",", ";", "\t", "|"):
                count = first.count(delimiter)
                if count >= 2:
                    second_count = lines[1].count(delimiter)
                    if abs(count - second_count) <= 2:
                        heuristic_delim = delimiter
                        break
            else:
                return None
        elif ext == ".tsv":
            heuristic_delim = "\t"

        try:
            sample_text = "\n".join(lines[:5])
            delimiter = sniff_csv_delimiter(
                sample_text, default=heuristic_delim or ","
            )
            reader = csv.DictReader(io.StringIO(sample_text), delimiter=delimiter)
            first_row = next(reader, None)

            if first_row is None:
                return None

            # Ragged rows store extra fields under the None restkey — drop it
            headers = {h for h in first_row if h is not None}
            if not headers:
                return None

            # Detect timestamp field from headers
            ts_field = next((c for c in self._timestamp_fields if c in headers), None)

            if "Channel" in headers and "EventID" in headers:
                return DetectionResult(
                    input_type="csv",
                    log_source="windows_evtx_csv",
                    confidence="high",
                    timestamp_field=ts_field or "SystemTime",
                    details="Windows Event Log CSV format detected",
                    metadata={
                        "headers": sorted(headers)[:20],
                        "delimiter": delimiter,
                    },
                )

            return DetectionResult(
                input_type="csv",
                log_source="generic_csv",
                confidence="medium",
                timestamp_field=ts_field,
                details="CSV format detected"
                + (f" (timestamp field: {ts_field})" if ts_field else ""),
                metadata={
                    "headers": sorted(headers)[:20],
                    "delimiter": delimiter,
                },
            )

        except Exception:
            if ext in (".csv", ".tsv"):
                return DetectionResult(
                    input_type="csv",
                    log_source="generic_csv",
                    confidence="low",
                    details="CSV file detected by extension (could not parse sample)",
                )

        return None

    # ----------------------------------------------------------------
    # Internal: helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _collect_keys(obj: dict, keys: set, prefix: str = ""):
        """Recursively collect all keys from a nested dict (dot-notation)."""
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            keys.add(key)
            keys.add(full_key)
            if isinstance(value, dict):
                LogTypeDetector._collect_keys(value, keys, full_key)

    def _fallback_by_extension(self, ext: str, reason: str) -> DetectionResult:
        """Fall back to extension-based detection when content analysis fails."""
        fallback = EXTENSION_FALLBACKS.get(ext)
        if fallback is None:
            return self._unknown_result(f"Unknown extension '{ext}' ({reason})")

        return DetectionResult(
            input_type=fallback.format_name,
            log_source=fallback.log_source,
            confidence="low",
            timestamp_field=fallback.timestamp_field,
            suggested_pipeline=fallback.pipeline,
            details=f"Detected by extension '{ext}' ({reason})",
        )

    def _enrich_timestamp_from_raw(
        self,
        result: DetectionResult,
        sample_text: str,
        sample_bytes: bytes,
    ) -> None:
        """
        Enrich a DetectionResult in-place with a timestamp field found via
        regex scanning of the raw file content.

        If a timestamp pattern is found and the content is JSON, tries to
        match the hit back to a specific event key.
        """
        ts_info = self._detect_timestamp_from_raw_content(sample_text)
        if ts_info is None:
            return

        matched_value = ts_info["match"]

        # Try to tie the raw hit to a JSON key. A date-shaped hit speaks for
        # itself, but an all-digit one does not: the epoch and FileTime patterns
        # match any 10/13/18-digit number, so a byte counter or a serial number
        # would be promoted to the time field and then drive -A/-B filtering and
        # correlation windows. There the name has to carry the signal, exactly as
        # detect_timestamp_field requires.
        matched_key = None
        first_char = sample_text.lstrip()[:1]
        if first_char in ("{", "["):
            event = self._parse_first_json_event(sample_bytes, first_char == "[")
            if event:
                # A field whose whole value is the timestamp speaks for itself,
                # whatever it is called -- `logged_at` scores nothing by name.
                candidate = self._find_key_for_value(
                    event, matched_value, exact=True
                )
                if candidate is None:
                    # Found inside a longer string: only a field named like a
                    # timestamp earns that, or a prose message mentioning a
                    # date becomes the time field and -A/-B filter on prose.
                    loose = self._find_key_for_value(
                        event, matched_value, exact=False
                    )
                    if loose and self._timestamp_field_score(loose) > 0:
                        candidate = loose
                if candidate and (
                    not matched_value.isdigit()
                    or self._timestamp_field_score(candidate) > 0
                ):
                    matched_key = candidate

        if matched_key:
            result.timestamp_field = matched_key
            result.details += (
                f" | Timestamp field '{matched_key}' detected via regex "
                f"({ts_info['format']}, e.g. {matched_value!r})"
            )
        else:
            result.metadata["raw_timestamp_format"] = ts_info["format"]
            result.metadata["raw_timestamp_example"] = matched_value
            result.details += (
                f" | Timestamp format detected via regex: {ts_info['format']} "
                f"(e.g. {matched_value!r})"
            )

    @staticmethod
    def _find_key_for_value(
        event: dict, needle: str, *, exact: bool = False
    ) -> str | None:
        """The key in *event* (one level deep) whose value carries *needle*.

        With ``exact``, the value must *be* the timestamp. Without it, the
        needle only has to appear somewhere inside -- which is how a free-text
        message that happens to mention a date became the time field.

        Numeric values are compared via their string form so epoch/FileTime
        timestamps stored as JSON numbers can be tied back to their key.
        """
        def carries(value: Any) -> bool:
            if isinstance(value, str):
                return value.strip() == needle if exact else needle in value
            if isinstance(value, (int, float)):
                return needle == str(value)
            return False

        for key, value in event.items():
            if carries(value):
                return key
            if isinstance(value, dict):
                for sub_key, sub_val in value.items():
                    if carries(sub_val):
                        return sub_key
        return None

    def _unknown_result(self, reason: str) -> DetectionResult:
        """Return an unknown detection result."""
        return DetectionResult(
            input_type="json",
            log_source="unknown",
            confidence="low",
            details=f"Could not determine log type: {reason}",
        )

    # ----------------------------------------------------------------
    # Timestamp detection helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _detect_timestamp_from_raw_content(text: str) -> dict | None:
        """
        Scan raw file content with regex to find timestamp patterns.

        Returns a dict with 'format', 'example', 'match', 'pattern_name'
        or None if no timestamp pattern was found.
        """
        for pattern, name, example in TIMESTAMP_RAW_PATTERNS:
            m = pattern.search(text)
            if m:
                return {
                    "format": name,
                    "example": example,
                    "match": m.group(0),
                    "pattern_name": name,
                }
        return None

    @staticmethod
    def _looks_like_timestamp(value) -> bool:
        """
        Check if a value looks like a timestamp.

        Supports ISO 8601, US/EU date-time, syslog, epoch seconds/millis,
        Windows FileTime, and date-only strings.
        """
        if value is None:
            return False

        if isinstance(value, (int, float)):
            # Epoch seconds (2000-01-01 … 2100-01-01)
            if 946_684_800 <= value <= 4_102_444_800:
                return True
            # Epoch millis
            if 946_684_800_000 <= value <= 4_102_444_800_000:
                return True
            # Windows FileTime (18-digit)
            return 100000000000000000 <= value <= 200000000000000000

        if not isinstance(value, str):
            return False

        length = len(value)
        if length < 8 or length > 40:
            return False

        # ISO 8601: YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS
        if _RE_ISO8601.match(value):
            return True

        # Date only: YYYY-MM-DD
        if _RE_DATE_ONLY.match(value):
            return True

        # US/EU: MM/DD/YYYY or DD/MM/YYYY (with optional time)
        if _RE_SLASH_DATE.match(value):
            return True

        # Syslog: "Jun 15 10:30:00"
        if _RE_SYSLOG_TS.match(value):
            return True

        # Pure-digit fast path: epoch seconds (10), epoch millis (13),
        # or Windows FileTime (18) strings. Lengths 11-12 are neither.
        if value.isdigit():
            if length in (10, 13):
                return True
            if length == 18 and value[0] == "1":
                return True

        return False

    @staticmethod
    def _timestamp_field_score(field_name: str) -> int:
        """
        Score a field name for how likely it is to be a timestamp field.
        Higher scores = more likely.
        """
        name_lower = field_name.lower()

        if name_lower in _EXACT_TS_NAMES:
            return 100

        if "timestamp" in name_lower:
            return 90
        if "time" in name_lower and "timeout" not in name_lower:
            return 80

        if "date" in name_lower and "update" not in name_lower:
            return 70

        if name_lower in _SHORT_TS_NAMES:
            return 60

        if "created" in name_lower:
            return 50
        if "when" in name_lower:
            return 40

        return 0
