#!python3
"""
Automatic log type and timestamp detection for Zircolite.

This module provides content-based detection of log formats to reduce
the need for explicit CLI flags. It examines file extension, magic bytes,
and content structure to determine the log type and suggest appropriate
processing parameters.

Supported detections:
- EVTX binary files (magic bytes)
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
from typing import Dict, List, Optional, Tuple

import orjson as json


# =========================================================================
# Pre-compiled module-level constants
# =========================================================================

# EVTX magic bytes: "ElfFile\x00"
EVTX_MAGIC = b"ElfFile\x00"

# ---- Regex patterns for raw-content timestamp detection ----
# Each tuple: (compiled_regex, human-readable format name, example)
# Order matters: more specific patterns first to avoid false positives.
TIMESTAMP_RAW_PATTERNS = [
    # ISO 8601 full: 2024-06-15T10:30:00.123456Z or +00:00
    (re.compile(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?'
    ), "ISO 8601", "2024-06-15T10:30:00.123Z"),
    # ISO 8601 with space separator: 2024-06-15 10:30:00
    (re.compile(
        r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?'
    ), "ISO 8601 (space)", "2024-06-15 10:30:00"),
    # US/EU date format: 06/15/2024 10:30:00
    (re.compile(
        r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}'
    ), "US date-time", "06/15/2024 10:30:00"),
    # Syslog: Jun 15 10:30:00  (month name + day + time)
    (re.compile(
        r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    ), "Syslog", "Jun 15 10:30:00"),
    # Windows FileTime / LDAP: 18-digit integer (e.g. 133627842000000000)
    (re.compile(
        r'(?<!\d)1[23]\d{16}(?!\d)'
    ), "Windows FileTime", "133627842000000000"),
    # Epoch seconds: 10-digit integer (standalone)
    (re.compile(
        r'(?<!\d)\d{10}(?!\d)'
    ), "Epoch seconds", "1718442600"),
    # Epoch milliseconds: 13-digit integer (standalone)
    (re.compile(
        r'(?<!\d)\d{13}(?!\d)'
    ), "Epoch milliseconds", "1718442600000"),
]

# Auditd line pattern: type=XXXX msg=audit(TIMESTAMP.NNN:SEQ):
AUDITD_LINE_PATTERN = re.compile(
    r'^type=\w+\s+msg=audit\(\d+\.\d+:\d+\):'
)

# Sysmon for Linux: syslog header before XML
SYSMON_LINUX_SYSLOG_PATTERN = re.compile(
    r'^\w+\s+\d+\s+[\d:]+\s+\S+\s+\S+.*<Event>'
)

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
AUDITD_TYPES = frozenset({
    "SYSCALL", "EXECVE", "PATH", "CWD", "PROCTITLE",
    "USER_AUTH", "USER_ACCT", "CRED_ACQ", "CRED_DISP",
    "USER_START", "USER_END", "USER_LOGIN", "USER_CMD",
    "LOGIN", "SERVICE_START", "SERVICE_STOP",
    "ANOM_PROMISCUOUS", "NETFILTER_CFG", "SYSTEM_BOOT",
    "SYSTEM_SHUTDOWN", "DAEMON_START", "DAEMON_END",
    "CONFIG_CHANGE", "AVC", "SELINUX_ERR",
    "CRYPTO_KEY_USER", "CRYPTO_SESSION",
})

# Sysmon channel names
SYSMON_CHANNELS = frozenset({
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Sysmon",
})

# ---- Pre-compiled regexes for _looks_like_timestamp ----
_RE_ISO8601 = re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')
_RE_DATE_ONLY = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_RE_SLASH_DATE = re.compile(r'^\d{2}/\d{2}/\d{4}')
_RE_SYSLOG_TS = re.compile(
    r'^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
)

# ---- Pre-computed sets for _timestamp_field_score ----
_EXACT_TS_NAMES = frozenset({
    "systemtime", "utctime", "@timestamp", "timestamp",
    "timecreated", "eventtime", "_time", "datetime",
})
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
    timestamp_field: Optional[str] = None

    # Suggested Sigma pipeline (None if unknown)
    suggested_pipeline: Optional[str] = None

    # Human-readable description of the detection
    details: str = ""

    # Additional metadata from detection
    metadata: Dict = field(default_factory=dict)

    def __str__(self) -> str:
        parts = [f"{self.log_source} ({self.input_type})"]
        parts.append(f"confidence={self.confidence}")
        if self.timestamp_field:
            parts.append(f"timestamp={self.timestamp_field}")
        if self.suggested_pipeline:
            parts.append(f"pipeline={self.suggested_pipeline}")
        return ", ".join(parts)


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
        logger: Optional[logging.Logger] = None,
        timestamp_detection_fields: Optional[List[str]] = None,
    ):
        """
        Initialize LogTypeDetector.

        Args:
            logger: Logger instance (creates default if None)
            timestamp_detection_fields: Ordered list of timestamp field names
                to try during auto-detection. If None, uses built-in defaults.
        """
        self.logger = logger or logging.getLogger(__name__)
        self._timestamp_fields = tuple(timestamp_detection_fields or [
            "SystemTime", "UtcTime", "TimeCreated", "@timestamp",
            "timestamp", "Timestamp", "EventTime", "event_time",
            "datetime", "DateTime", "_time", "ts",
        ])

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

        ext = file_path.suffix.lower()

        # Phase 1: Check magic bytes for binary formats
        magic_result = self._check_magic_bytes(file_path)
        if magic_result:
            return magic_result

        # Phase 2: Content-based detection
        try:
            sample_bytes, sample_text, sample_lines = self._read_sample(file_path)
        except Exception as e:
            self.logger.debug(f"Detection: cannot read file {file_path}: {e}")
            return self._fallback_by_extension(ext, f"Cannot read file: {e}")

        if not sample_bytes:
            return self._fallback_by_extension(ext, "File is empty")

        # Phase 2a: Try structured format detection
        content_result = self._detect_from_content(
            sample_bytes, sample_text, sample_lines, ext
        )
        if content_result:
            if content_result.timestamp_field is None:
                self._enrich_timestamp_from_raw(content_result, sample_text, sample_bytes)
            return content_result

        # Phase 3: Fallback to extension, enriched with raw timestamp scan
        fallback = self._fallback_by_extension(ext, "Could not determine format from content")
        if fallback.timestamp_field is None:
            self._enrich_timestamp_from_raw(fallback, sample_text, sample_bytes)
        return fallback

    def detect_batch(self, file_paths: List[Path]) -> DetectionResult:
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

        if not results:
            return self._unknown_result("All files failed detection")

        # Return highest confidence result
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        results.sort(key=lambda r: confidence_order.get(r.confidence, 3))
        best = results[0]

        # If all files agree on input_type, boost confidence
        if len(results) > 1 and best.confidence == "medium":
            if all(r.input_type == best.input_type for r in results):
                best.confidence = "high"
                best.details += " (confirmed across multiple files)"

        return best

    def detect_timestamp_field(self, event: dict) -> Optional[str]:
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

        # Phase 2: Scan all fields for timestamp-like values, scored by name
        best_key = None
        best_score = -1
        for key, value in event.items():
            if looks_like(value):
                score = self._timestamp_field_score(key)
                if score > best_score:
                    best_score = score
                    best_key = key

        return best_key

    # ----------------------------------------------------------------
    # Internal: sampling and magic bytes
    # ----------------------------------------------------------------

    def _check_magic_bytes(self, file_path: Path) -> Optional[DetectionResult]:
        """Check file magic bytes for binary format detection."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)

            if header[:7] == EVTX_MAGIC[:7]:
                return DetectionResult(
                    input_type="evtx",
                    log_source="windows_evtx",
                    confidence="high",
                    timestamp_field="SystemTime",
                    suggested_pipeline="sysmon",
                    details="EVTX binary file detected via magic bytes (ElfFile header)",
                )
        except Exception as e:
            self.logger.debug(f"Detection: magic bytes check failed: {e}")

        return None

    def _read_sample(self, file_path: Path) -> Tuple[bytes, str, List[str]]:
        """
        Read a sample of the file for content analysis.

        Returns:
            (raw_bytes, decoded_text, first_N_lines)
        """
        with open(file_path, "rb") as f:
            sample_bytes = f.read(self.SAMPLE_BYTES)

        # Decode once — reused by all downstream methods
        try:
            text = sample_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = sample_bytes.decode("iso-8859-1")

        lines = text.splitlines()[:self.SAMPLE_LINES]
        return sample_bytes, text, lines

    # ----------------------------------------------------------------
    # Internal: content-based dispatch
    # ----------------------------------------------------------------

    def _detect_from_content(
        self,
        sample_bytes: bytes,
        sample_text: str,
        sample_lines: List[str],
        ext: str,
    ) -> Optional[DetectionResult]:
        """Detect format from file content."""
        if not sample_lines:
            return None

        first_char = sample_lines[0].lstrip()[:1]

        # Fast-path: first non-whitespace character determines the family
        if first_char in ("{", "["):
            return self._check_json(sample_lines, sample_bytes, ext)

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

    def _check_auditd(self, lines: List[str]) -> Optional[DetectionResult]:
        """Check if content matches auditd log format."""
        match = AUDITD_LINE_PATTERN.match  # local ref
        auditd_matches = sum(
            1 for line in lines[:10]
            if line.strip() and match(line.strip())
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

    def _check_sysmon_linux(self, lines: List[str]) -> Optional[DetectionResult]:
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
                if "RuleName" in stripped or "ProcessGuid" in stripped or "UtcTime" in stripped:
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
        if sysmon_matches == 1:
            return DetectionResult(
                input_type="sysmon_linux",
                log_source="sysmon_linux",
                confidence="medium",
                timestamp_field="UtcTime",
                suggested_pipeline="sysmon",
                details="Sysmon for Linux log format detected (1 matching line)",
            )

        return None

    def _check_evtxtract(self, text: str) -> Optional[DetectionResult]:
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

    def _check_xml(self, text: str) -> Optional[DetectionResult]:
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
        self, lines: List[str], sample_bytes: bytes, ext: str
    ) -> Optional[DetectionResult]:
        """Analyze JSON content to determine the specific log source."""
        first_line = lines[0].strip()
        is_json_array = first_line.startswith("[")

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

        return self._classify_json_event(first_event, is_json_array, ext)

    def _parse_first_json_event(
        self, sample_bytes: bytes, is_json_array: bool
    ) -> Optional[dict]:
        """Parse the first JSON event from a sample."""
        try:
            if is_json_array:
                data = json.loads(sample_bytes)
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    return data[0]
                return None
            else:
                for line in sample_bytes.split(b"\n"):
                    line = line.strip()
                    if line:
                        event = json.loads(line)
                        if isinstance(event, dict):
                            return event
                return None
        except (json.JSONDecodeError, Exception):
            # For truncated JSON arrays, try line-by-line recovery
            for line in sample_bytes.split(b"\n"):
                line = line.strip()
                if not line or line in (b"[", b"]", b","):
                    continue
                if line.endswith(b","):
                    line = line[:-1]
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        return event
                except Exception:
                    continue

        return None

    def _classify_json_event(
        self, event: dict, is_json_array: bool, ext: str
    ) -> DetectionResult:
        """Classify a JSON event based on its structure and fields."""
        flat_keys: set = set()
        self._collect_keys(event, flat_keys)

        input_type = "json_array" if is_json_array else "json"

        # --- Windows EVTX JSON (nested Event.System.*) ---
        event_obj = event.get("Event")
        if isinstance(event_obj, dict):
            system_obj = event_obj.get("System")
            if isinstance(system_obj, dict) and ("Channel" in system_obj or "EventID" in system_obj):
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
                        metadata={"channel": channel, "has_event_data": bool(event_data_obj)},
                    )

                return DetectionResult(
                    input_type=input_type,
                    log_source="windows_evtx_json",
                    confidence="high",
                    timestamp_field="SystemTime",
                    suggested_pipeline="sysmon",
                    details="Windows Event Log JSON detected"
                           + (f" (channel: {channel})" if channel else ""),
                    metadata={"channel": channel, "has_event_data": bool(event_data_obj)},
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
                   + (f" (timestamp field: {ts_field})" if ts_field else
                      " (no timestamp field detected)"),
            metadata={"sample_keys": list(event.keys())[:20]},
        )

    def _check_csv(self, lines: List[str], ext: str) -> Optional[DetectionResult]:
        """Check if content is CSV format and classify it."""
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
                        break
            else:
                return None

        try:
            sample_text = "\n".join(lines[:5])
            dialect = csv.Sniffer().sniff(sample_text)
            reader = csv.DictReader(io.StringIO(sample_text), dialect=dialect)
            first_row = next(reader, None)

            if first_row is None:
                return None

            headers = set(first_row.keys())

            # Detect timestamp field from headers
            ts_field = next(
                (c for c in self._timestamp_fields if c in headers), None
            )

            if "Channel" in headers and "EventID" in headers:
                return DetectionResult(
                    input_type="csv",
                    log_source="windows_evtx_csv",
                    confidence="high",
                    timestamp_field=ts_field or "SystemTime",
                    details="Windows Event Log CSV format detected",
                    metadata={"headers": sorted(headers)[:20], "delimiter": dialect.delimiter},
                )

            return DetectionResult(
                input_type="csv",
                log_source="generic_csv",
                confidence="medium",
                timestamp_field=ts_field,
                details="CSV format detected"
                       + (f" (timestamp field: {ts_field})" if ts_field else ""),
                metadata={"headers": sorted(headers)[:20], "delimiter": dialect.delimiter},
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
        ext_map = {
            ".evtx": ("evtx", "windows_evtx", "SystemTime", "sysmon"),
            ".json": ("json", "generic_json", None, None),
            ".jsonl": ("json", "generic_json", None, None),
            ".ndjson": ("json", "generic_json", None, None),
            ".xml": ("xml", "windows_evtx_xml", "SystemTime", "sysmon"),
            ".csv": ("csv", "generic_csv", None, None),
            ".tsv": ("csv", "generic_csv", None, None),
            ".log": ("json", "generic_json", None, None),
        }

        if ext in ext_map:
            input_type, log_source, ts_field, pipeline = ext_map[ext]
            return DetectionResult(
                input_type=input_type,
                log_source=log_source,
                confidence="low",
                timestamp_field=ts_field,
                suggested_pipeline=pipeline,
                details=f"Detected by extension '{ext}' ({reason})",
            )

        return self._unknown_result(f"Unknown extension '{ext}' ({reason})")

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

        # Try to tie the raw hit to a JSON key
        matched_key = None
        first_char = sample_text.lstrip()[:1]
        if first_char in ("{", "["):
            event = self._parse_first_json_event(
                sample_bytes, first_char == "["
            )
            if event:
                matched_key = self._find_key_for_value(event, matched_value)

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
    def _find_key_for_value(event: dict, needle: str) -> Optional[str]:
        """Find the key in *event* (one level deep) whose value contains *needle*."""
        for key, value in event.items():
            if isinstance(value, str) and needle in value:
                return key
            if isinstance(value, dict):
                for sub_key, sub_val in value.items():
                    if isinstance(sub_val, str) and needle in sub_val:
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
    def _detect_timestamp_from_raw_content(text: str) -> Optional[dict]:
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
            if 100_000_000_000_000_000 <= value <= 200_000_000_000_000_000:
                return True
            return False

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

        # Pure-digit fast path: epoch or Windows FileTime strings
        if value.isdigit():
            if 10 <= length <= 13:
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
