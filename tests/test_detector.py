"""
Tests for LogTypeDetector - automatic log type and timestamp detection.

Tests cover:
- EVTX binary detection via magic bytes
- Windows EVTX JSON detection (nested and flattened)
- Sysmon Windows JSON detection (via channel)
- Auditd log detection (key=value format)
- Sysmon for Linux detection (syslog + XML)
- XML log detection (with/without Windows namespace)
- CSV log detection
- EVTXtract output detection
- ECS/Elastic format detection
- Timestamp field auto-detection
- Batch detection across multiple files
- Edge cases: empty files, unknown formats, binary junk
"""

import gzip
import json
import logging
import os
import pytest
from pathlib import Path
from unittest.mock import patch

from zircolite.detector import (
    LogTypeDetector,
    DetectionResult,
    EVTX_MAGIC,
    SQLITE_MAGIC,
    AUDITD_LINE_PATTERN,
)


# =============================================================================
# Fixtures
# =============================================================================

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def detector():
    """Create a LogTypeDetector with a test logger."""
    logger = logging.getLogger("test_detector")
    logger.setLevel(logging.DEBUG)
    return LogTypeDetector(logger=logger)


@pytest.fixture
def evtx_file(tmp_path):
    """Create a fake EVTX file with correct magic bytes."""
    f = tmp_path / "test.evtx"
    # Write EVTX magic header followed by some padding
    f.write_bytes(EVTX_MAGIC + b"\x00" * 100)
    return f


@pytest.fixture
def windows_evtx_json_file(tmp_path):
    """Create a JSONL file with Windows EVTX events."""
    f = tmp_path / "security.json"
    events = [
        {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Channel": "Security",
                    "Computer": "DC01.contoso.local",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-06-15T08:30:00.123Z"}},
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                },
                "EventData": {
                    "TargetUserName": "admin",
                    "LogonType": "10",
                    "IpAddress": "192.168.1.50",
                },
            }
        },
        {
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Channel": "Security",
                    "Computer": "DC01.contoso.local",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-06-15T08:31:00.456Z"}},
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                },
                "EventData": {
                    "TargetUserName": "unknown",
                    "LogonType": "3",
                },
            }
        },
    ]
    with open(f, "w") as fp:
        for event in events:
            fp.write(json.dumps(event) + "\n")
    return f


@pytest.fixture
def sysmon_windows_json_file(tmp_path):
    """Create a JSONL file with Sysmon Windows events."""
    f = tmp_path / "sysmon.json"
    events = [
        {
            "Event": {
                "System": {
                    "EventID": 1,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": "WORKSTATION01",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-06-15T10:30:00.000Z"}},
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}},
                },
                "EventData": {
                    "RuleName": "-",
                    "UtcTime": "2024-06-15 10:30:00.000",
                    "ProcessGuid": "{12345678-abcd-ef01-2345-678901234567}",
                    "ProcessId": "1234",
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                },
            }
        },
    ]
    with open(f, "w") as fp:
        for event in events:
            fp.write(json.dumps(event) + "\n")
    return f


@pytest.fixture
def sysmon_windows_json_array_file(tmp_path):
    """Create a JSON array file with Sysmon Windows events."""
    f = tmp_path / "sysmon_array.json"
    events = [
        {
            "Event": {
                "System": {
                    "EventID": 1,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": "WORKSTATION01",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-06-15T10:30:00.000Z"}},
                },
                "EventData": {
                    "CommandLine": "powershell.exe -c whoami",
                    "Image": "C:\\Windows\\System32\\powershell.exe",
                },
            }
        },
        {
            "Event": {
                "System": {
                    "EventID": 3,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": "WORKSTATION01",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-06-15T10:31:00.000Z"}},
                },
                "EventData": {
                    "DestinationIp": "10.0.0.1",
                    "DestinationPort": "443",
                },
            }
        },
    ]
    f.write_text(json.dumps(events))
    return f


@pytest.fixture
def flattened_windows_json_file(tmp_path):
    """Create a JSONL file with pre-flattened Windows events."""
    f = tmp_path / "flattened.jsonl"
    events = [
        {
            "EventID": "4688",
            "Channel": "Security",
            "Computer": "DC01",
            "SystemTime": "2024-06-15T08:30:00.123Z",
            "CommandLine": "net user /domain",
            "Image": "C:\\Windows\\System32\\net.exe",
        },
        {
            "EventID": "4624",
            "Channel": "Security",
            "Computer": "DC01",
            "SystemTime": "2024-06-15T08:31:00.456Z",
            "TargetUserName": "admin",
        },
    ]
    with open(f, "w") as fp:
        for event in events:
            fp.write(json.dumps(event) + "\n")
    return f


@pytest.fixture
def auditd_file(tmp_path):
    """Create an auditd log file."""
    f = tmp_path / "audit.log"
    lines = [
        'type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7f1234567890 a1=7f1234567890 a2=7f1234567890 a3=0 items=2 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/bin/bash" key="commands"\n',
        'type=EXECVE msg=audit(1705318200.123:456): argc=3 a0="bash" a1="-c" a2="whoami"\n',
        'type=PATH msg=audit(1705318200.123:456): item=0 name="/bin/bash" inode=12345 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00\n',
        'type=SYSCALL msg=audit(1705318201.456:457): arch=c000003e syscall=59 success=yes exit=0 pid=5679 uid=0 comm="ls" exe="/bin/ls"\n',
    ]
    f.write_text("".join(lines))
    return f


@pytest.fixture
def sysmon_linux_file(tmp_path):
    """Create a Sysmon for Linux log file (syslog with embedded XML)."""
    f = tmp_path / "sysmon.log"
    lines = [
        'Jun 15 10:30:00 server01 sysmon: <Event><EventID>1</EventID><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2024-06-15 10:30:00.000</Data><Data Name="ProcessGuid">{12345678-abcd}</Data><Data Name="ProcessId">1234</Data><Data Name="Image">/usr/bin/bash</Data><Data Name="CommandLine">bash -c whoami</Data></EventData></Event>\n',
        'Jun 15 10:31:00 server01 sysmon: <Event><EventID>3</EventID><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2024-06-15 10:31:00.000</Data><Data Name="ProcessGuid">{12345678-efgh}</Data><Data Name="DestinationIp">10.0.0.1</Data></EventData></Event>\n',
        'Jun 15 10:32:00 server01 sysmon: <Event><EventID>11</EventID><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2024-06-15 10:32:00.000</Data><Data Name="ProcessGuid">{12345678-ijkl}</Data><Data Name="TargetFilename">/tmp/malware</Data></EventData></Event>\n',
    ]
    f.write_text("".join(lines))
    return f


@pytest.fixture
def xml_windows_file(tmp_path):
    """Create an XML file with Windows Event Log format."""
    f = tmp_path / "events.xml"
    content = '''<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
        <EventID>1</EventID>
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>WORKSTATION01</Computer>
        <TimeCreated SystemTime="2024-06-15T10:30:00.000Z"/>
    </System>
    <EventData>
        <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass</Data>
        <Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>
    </EventData>
</Event>
</Events>'''
    f.write_text(content)
    return f


@pytest.fixture
def csv_windows_file(tmp_path):
    """Create a CSV file with Windows event data."""
    f = tmp_path / "events.csv"
    content = """EventID,Channel,Computer,CommandLine,Image,User,SystemTime
1,Microsoft-Windows-Sysmon/Operational,WORKSTATION01,cmd.exe /c whoami,C:\\Windows\\System32\\cmd.exe,admin,2024-06-15T10:30:00Z
3,Microsoft-Windows-Sysmon/Operational,WORKSTATION01,,C:\\Windows\\System32\\firefox.exe,user,2024-06-15T10:31:00Z
"""
    f.write_text(content)
    return f


@pytest.fixture
def csv_generic_file(tmp_path):
    """Create a generic CSV file without Windows event structure."""
    f = tmp_path / "generic.csv"
    content = """timestamp,source_ip,dest_ip,action,bytes
2024-06-15T10:30:00Z,192.168.1.10,10.0.0.1,ALLOW,1234
2024-06-15T10:31:00Z,192.168.1.11,10.0.0.2,DENY,0
"""
    f.write_text(content)
    return f


@pytest.fixture
def ecs_json_file(tmp_path):
    """Create a JSONL file with ECS/Elastic format."""
    f = tmp_path / "elastic.json"
    events = [
        {
            "@timestamp": "2024-06-15T10:30:00.000Z",
            "event": {"module": "sysmon", "code": "1"},
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
            },
            "process": {
                "name": "cmd.exe",
                "command_line": "cmd.exe /c whoami",
            },
        },
    ]
    with open(f, "w") as fp:
        for event in events:
            fp.write(json.dumps(event) + "\n")
    return f


@pytest.fixture
def evtxtract_file(tmp_path):
    """Create an EVTXtract output file."""
    f = tmp_path / "evtxtract.log"
    content = '''Found at offset 0x12345
Valid header at offset 0x12345
Record number: 1
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <EventID>1</EventID>
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <TimeCreated SystemTime="2024-06-15T10:30:00.000Z"/>
    </System>
    <EventData>
        <Data Name="CommandLine">powershell.exe</Data>
    </EventData>
</Event>
'''
    f.write_text(content)
    return f


@pytest.fixture
def empty_file(tmp_path):
    """Create an empty file."""
    f = tmp_path / "empty.log"
    f.write_text("")
    return f


@pytest.fixture
def binary_junk_file(tmp_path):
    """Create a file with random binary content."""
    f = tmp_path / "junk.bin"
    f.write_bytes(os.urandom(512))
    return f


@pytest.fixture
def generic_json_file(tmp_path):
    """Create a generic JSON file without known log structure."""
    f = tmp_path / "generic.json"
    events = [
        {"id": 1, "message": "Hello", "timestamp": "2024-06-15T10:30:00Z", "level": "info"},
        {"id": 2, "message": "World", "timestamp": "2024-06-15T10:31:00Z", "level": "warn"},
    ]
    with open(f, "w") as fp:
        for event in events:
            fp.write(json.dumps(event) + "\n")
    return f


@pytest.fixture
def auditd_json_file(tmp_path):
    """Create a JSONL file with auditd-style events (already converted to JSON)."""
    f = tmp_path / "auditd.json"
    events = [
        {"type": "SYSCALL", "timestamp": "2024-06-15 10:30:00", "pid": "1234", "uid": "0", "comm": "bash", "exe": "/bin/bash"},
        {"type": "EXECVE", "timestamp": "2024-06-15 10:30:00", "argc": "3", "a0": "bash"},
    ]
    with open(f, "w") as fp:
        for event in events:
            fp.write(json.dumps(event) + "\n")
    return f


# =============================================================================
# EVTX Binary Detection Tests
# =============================================================================

class TestEvtxBinaryDetection:
    """Tests for EVTX binary file detection via magic bytes."""

    def test_detect_evtx_by_magic_bytes(self, detector, evtx_file):
        """EVTX files should be detected with high confidence via magic bytes."""
        result = detector.detect(evtx_file)
        assert result.input_type == "evtx"
        assert result.log_source == "windows_evtx"
        assert result.confidence == "high"
        assert result.timestamp_field == "SystemTime"

    def test_detect_evtx_ignores_extension(self, detector, tmp_path):
        """EVTX detection should work even with wrong extension."""
        f = tmp_path / "renamed.log"
        f.write_bytes(EVTX_MAGIC + b"\x00" * 100)
        result = detector.detect(f)
        assert result.input_type == "evtx"
        assert result.confidence == "high"


class TestSqliteDatabaseDetection:
    """Tests for SQLite database file detection via magic bytes."""

    def test_detect_sqlite_by_magic_bytes(self, detector, tmp_path):
        """SQLite database files should be detected with high confidence via magic bytes."""
        db_file = tmp_path / "events.db"
        db_file.write_bytes(SQLITE_MAGIC + b"\x00" * 100)
        result = detector.detect(db_file)
        assert result.input_type == "sqlite"
        assert result.log_source == "sqlite_db"
        assert result.confidence == "high"

    def test_detect_sqlite_ignores_extension(self, detector, tmp_path):
        """SQLite detection should work regardless of file extension."""
        f = tmp_path / "data.bin"
        f.write_bytes(SQLITE_MAGIC + b"\x00" * 100)
        result = detector.detect(f)
        assert result.input_type == "sqlite"
        assert result.confidence == "high"


# =============================================================================
# Windows EVTX JSON Detection Tests
# =============================================================================

class TestWindowsEvtxJsonDetection:
    """Tests for Windows Event Log JSON format detection."""

    def test_detect_windows_evtx_json(self, detector, windows_evtx_json_file):
        """Windows EVTX JSON (nested Event.System structure) should be detected."""
        result = detector.detect(windows_evtx_json_file)
        assert result.input_type == "json"
        assert result.log_source == "windows_evtx_json"
        assert result.confidence == "high"
        assert result.timestamp_field == "SystemTime"

    def test_detect_sysmon_windows_json(self, detector, sysmon_windows_json_file):
        """Sysmon Windows JSON should be detected by channel name."""
        result = detector.detect(sysmon_windows_json_file)
        assert result.input_type == "json"
        assert result.log_source == "sysmon_windows"
        assert result.confidence == "high"
        assert result.timestamp_field == "UtcTime"
        assert result.suggested_pipeline == "sysmon"

    def test_detect_sysmon_windows_json_array(self, detector, sysmon_windows_json_array_file):
        """Sysmon Windows JSON array should be detected with json_array type."""
        result = detector.detect(sysmon_windows_json_array_file)
        assert result.input_type == "json_array"
        assert result.log_source in ("sysmon_windows", "windows_evtx_json")
        assert result.confidence == "high"

    def test_detect_flattened_windows_json(self, detector, flattened_windows_json_file):
        """Pre-flattened Windows JSON (Channel + EventID at top level) should be detected."""
        result = detector.detect(flattened_windows_json_file)
        assert result.input_type == "json"
        assert result.log_source == "windows_evtx_json"
        assert result.confidence == "high"
        assert result.timestamp_field == "SystemTime"


# =============================================================================
# Auditd Detection Tests
# =============================================================================

class TestAuditdDetection:
    """Tests for Auditd log format detection."""

    def test_detect_auditd_raw(self, detector, auditd_file):
        """Raw auditd logs (type=XXXX msg=audit(...):) should be detected."""
        result = detector.detect(auditd_file)
        assert result.input_type == "auditd"
        assert result.log_source == "auditd"
        assert result.confidence == "high"
        assert result.timestamp_field == "timestamp"

    def test_detect_auditd_json(self, detector, auditd_json_file):
        """Auditd events converted to JSON should be detected by type field."""
        result = detector.detect(auditd_json_file)
        assert result.log_source == "auditd"
        assert result.confidence == "high"

    def test_auditd_line_pattern(self):
        """The auditd regex pattern should match valid auditd lines."""
        valid_lines = [
            'type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e',
            'type=EXECVE msg=audit(1705318200.123:456): argc=3',
            'type=PATH msg=audit(1705318200.123:456): item=0',
            'type=USER_AUTH msg=audit(1705318200.123:456): pid=1234',
        ]
        for line in valid_lines:
            assert AUDITD_LINE_PATTERN.match(line), f"Pattern should match: {line}"

    def test_auditd_line_pattern_no_match(self):
        """The auditd regex pattern should not match non-auditd lines."""
        invalid_lines = [
            '{"type": "SYSCALL", "msg": "audit"}',
            '<Event><EventID>1</EventID></Event>',
            'Jun 15 10:30:00 server sysmon: <Event>',
            'EventID,Channel,Computer',
        ]
        for line in invalid_lines:
            assert not AUDITD_LINE_PATTERN.match(line), f"Pattern should not match: {line}"

    def test_detect_auditd_single_line_medium_confidence(self, detector, tmp_path):
        """Single auditd line yields medium confidence."""
        f = tmp_path / "single_auditd.log"
        f.write_text(
            'type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e syscall=59 success=yes\n'
            'some other line that does not match\n'
        )
        result = detector.detect(f)
        assert result.input_type == "auditd"
        assert result.log_source == "auditd"
        assert result.confidence == "medium"
        assert "1 matching" in result.details or "1 matching line" in result.details

    def test_detect_auditd_from_fixture(self, detector):
        """Real auditd fixture (audit_sample.log) is detected as auditd."""
        fixture = FIXTURES_DIR / "audit_sample.log"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "auditd"
        assert result.log_source == "auditd"


# =============================================================================
# Sysmon for Linux Detection Tests
# =============================================================================

class TestSysmonLinuxDetection:
    """Tests for Sysmon for Linux log format detection."""

    def test_detect_sysmon_linux(self, detector, sysmon_linux_file):
        """Sysmon for Linux logs (syslog with embedded XML) should be detected."""
        result = detector.detect(sysmon_linux_file)
        assert result.input_type == "sysmon_linux"
        assert result.log_source == "sysmon_linux"
        assert result.confidence == "high"
        assert result.timestamp_field == "UtcTime"

    def test_detect_sysmon_linux_single_line(self, detector, tmp_path):
        """Even a single Sysmon Linux line should be detected (medium confidence)."""
        f = tmp_path / "sysmon_single.log"
        f.write_text(
            'Jun 15 10:30:00 server01 sysmon: <Event><EventID>1</EventID><EventData>'
            '<Data Name="RuleName">-</Data><Data Name="UtcTime">2024-06-15 10:30:00.000</Data>'
            '<Data Name="ProcessGuid">{12345678-abcd}</Data></EventData></Event>\n'
        )
        result = detector.detect(f)
        assert result.input_type == "sysmon_linux"
        assert result.confidence in ("medium", "high")

    def test_detect_sysmon_linux_from_fixture(self, detector):
        """Real Sysmon for Linux fixture (sysmon_linux_sample.log) is detected."""
        fixture = FIXTURES_DIR / "sysmon_linux_sample.log"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "sysmon_linux"
        assert result.log_source == "sysmon_linux"


# =============================================================================
# XML Detection Tests
# =============================================================================

class TestXmlDetection:
    """Tests for XML log format detection."""

    def test_detect_windows_xml(self, detector, xml_windows_file):
        """Windows Event Log XML with Microsoft namespace should be detected."""
        result = detector.detect(xml_windows_file)
        assert result.input_type == "xml"
        assert result.log_source == "windows_evtx_xml"
        assert result.confidence == "high"
        assert result.timestamp_field == "SystemTime"

    def test_detect_xml_without_namespace(self, detector, tmp_path):
        """XML with Event tags but no Microsoft namespace should still be detected."""
        f = tmp_path / "events_no_ns.xml"
        content = '''<Events>
<Event>
    <System>
        <EventID>1</EventID>
        <Channel>Security</Channel>
    </System>
</Event>
</Events>'''
        f.write_text(content)
        result = detector.detect(f)
        assert result.input_type == "xml"
        assert result.confidence in ("medium", "low")

    def test_detect_generic_xml_no_event_tag(self, detector, tmp_path):
        """XML without Event tag is classified as generic_xml with low confidence."""
        f = tmp_path / "generic.xml"
        f.write_text('<?xml version="1.0"?><root><item>data</item></root>')
        result = detector.detect(f)
        assert result.input_type == "xml"
        assert result.log_source == "generic_xml"
        assert result.confidence == "low"


# =============================================================================
# CSV Detection Tests
# =============================================================================

class TestCsvDetection:
    """Tests for CSV log format detection."""

    def test_detect_windows_csv(self, detector, csv_windows_file):
        """CSV with Windows event columns should be detected."""
        result = detector.detect(csv_windows_file)
        assert result.input_type == "csv"
        assert "csv" in result.log_source
        assert result.confidence in ("high", "medium")

    def test_detect_windows_evtx_csv_high_confidence(self, detector, tmp_path):
        """CSV with Channel and EventID headers should be windows_evtx_csv with high confidence."""
        f = tmp_path / "evtx.csv"
        f.write_text(
            "EventID,Channel,Computer,SystemTime,CommandLine\n"
            "1,Microsoft-Windows-Sysmon/Operational,PC01,2024-06-15T10:30:00Z,cmd.exe\n"
            "2,Microsoft-Windows-Sysmon/Operational,PC01,2024-06-15T10:31:00Z,powershell.exe\n"
        )
        result = detector.detect(f)
        assert result.input_type == "csv"
        assert result.log_source == "windows_evtx_csv"
        assert result.confidence == "high"

    def test_detect_csv_extension_fallback_when_sniffer_fails(self, detector, tmp_path):
        """When CSV content cannot be parsed by sniffer, extension fallback is used."""
        f = tmp_path / "bad.csv"
        f.write_bytes(b"\x00\x01\x02\x03\x04\x05\n\x00\x01\x02")
        result = detector.detect(f)
        assert result.input_type == "csv"
        assert result.log_source == "generic_csv"
        assert result.confidence in ("low", "medium")

    def test_detect_generic_csv(self, detector, csv_generic_file):
        """Generic CSV should be detected with timestamp field."""
        result = detector.detect(csv_generic_file)
        assert result.input_type == "csv"
        assert result.log_source == "generic_csv"
        assert result.timestamp_field == "timestamp"


# =============================================================================
# ECS/Elastic Format Detection Tests
# =============================================================================

class TestEcsDetection:
    """Tests for ECS/Elastic Common Schema format detection."""

    def test_detect_ecs_format(self, detector, ecs_json_file):
        """ECS format JSON with @timestamp and winlog should be detected."""
        result = detector.detect(ecs_json_file)
        assert result.log_source == "ecs_elastic"
        assert result.confidence == "high"
        assert result.timestamp_field == "@timestamp"

    def test_detect_ecs_without_winlog(self, detector, tmp_path):
        """ECS format with just @timestamp should be detected."""
        f = tmp_path / "ecs_minimal.json"
        events = [
            {"@timestamp": "2024-06-15T10:30:00.000Z", "message": "test event"},
        ]
        with open(f, "w") as fp:
            for event in events:
                fp.write(json.dumps(event) + "\n")
        result = detector.detect(f)
        assert result.log_source == "ecs_elastic"
        assert result.timestamp_field == "@timestamp"

    def test_detect_winlogbeat_sysmon_from_fixture(self, detector):
        """Real Winlogbeat Sysmon JSONL fixture is detected as ECS/Elastic."""
        fixture = FIXTURES_DIR / "winlogbeat_sysmon_sample.json"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "json"
        assert result.log_source == "ecs_elastic"
        assert result.timestamp_field == "@timestamp"


# =============================================================================
# EVTXtract Detection Tests
# =============================================================================

class TestEvtxtractDetection:
    """Tests for EVTXtract output format detection."""

    def test_detect_evtxtract(self, detector, evtxtract_file):
        """EVTXtract output should be detected by marker strings."""
        result = detector.detect(evtxtract_file)
        assert result.input_type == "evtxtract"
        assert result.log_source == "evtxtract"
        assert result.confidence == "high"

    def test_detect_evtxtract_from_fixture(self, detector):
        """Real EVTXtract fixture (evtxtract_sample.log) is detected as xml or evtxtract."""
        fixture = FIXTURES_DIR / "evtxtract_sample.log"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        # EVTXtract output is concatenated Event XML; detector may report xml or evtxtract
        assert result.input_type in ("xml", "evtxtract")
        assert result.log_source in ("windows_evtx_xml", "evtxtract", "generic_xml")


# =============================================================================
# Generic JSON Detection Tests
# =============================================================================

class TestGenericJsonDetection:
    """Tests for generic JSON format detection."""

    def test_detect_generic_json(self, detector, generic_json_file):
        """Generic JSON without known structure should be classified as generic."""
        result = detector.detect(generic_json_file)
        assert result.input_type == "json"
        assert result.log_source == "generic_json"
        assert result.timestamp_field == "timestamp"

    def test_detect_sysmon_fields_in_flat_json(self, detector, tmp_path):
        """JSON with Sysmon-specific fields should be identified as Sysmon."""
        f = tmp_path / "sysmon_flat.json"
        events = [
            {
                "RuleName": "-",
                "ProcessGuid": "{12345678-abcd}",
                "ProcessId": "1234",
                "Image": "/usr/bin/bash",
                "UtcTime": "2024-06-15 10:30:00.000",
                "CommandLine": "bash -c whoami",
            },
        ]
        with open(f, "w") as fp:
            for event in events:
                fp.write(json.dumps(event) + "\n")
        result = detector.detect(f)
        assert result.log_source == "sysmon_windows"
        assert result.timestamp_field == "UtcTime"

    def test_detect_json_unparseable_first_event_returns_generic(self, detector, tmp_path):
        """JSON array with first element not a dict yields generic_json with parse message."""
        f = tmp_path / "bad_first.json"
        f.write_text('["not", "a", "dict"]')
        result = detector.detect(f)
        assert result.input_type == "json_array"
        assert result.log_source == "generic_json"
        assert result.confidence == "low"
        assert "could not parse" in result.details.lower()

    def test_detect_json_array_first_element_not_dict(self, detector, tmp_path):
        """JSON array with first element not a dict yields generic_json."""
        f = tmp_path / "array_primitives.json"
        f.write_text('[1, 2, 3]')
        result = detector.detect(f)
        assert result.input_type == "json_array"
        assert result.log_source == "generic_json"
        assert result.confidence == "low"


# =============================================================================
# Timestamp Detection Tests
# =============================================================================

class TestTimestampDetection:
    """Tests for automatic timestamp field detection."""

    def test_detect_systemtime(self, detector):
        """SystemTime should be detected as a timestamp field."""
        event = {"EventID": 1, "SystemTime": "2024-06-15T10:30:00.000Z", "Channel": "Security"}
        assert detector.detect_timestamp_field(event) == "SystemTime"

    def test_detect_utctime(self, detector):
        """UtcTime should be detected as a timestamp field."""
        event = {"UtcTime": "2024-06-15 10:30:00.000", "Image": "/usr/bin/bash"}
        assert detector.detect_timestamp_field(event) == "UtcTime"

    def test_detect_at_timestamp(self, detector):
        """@timestamp (ECS) should be detected."""
        event = {"@timestamp": "2024-06-15T10:30:00.000Z", "message": "test"}
        assert detector.detect_timestamp_field(event) == "@timestamp"

    def test_detect_lowercase_timestamp(self, detector):
        """Lowercase 'timestamp' should be detected."""
        event = {"timestamp": "2024-06-15T10:30:00Z", "data": "test"}
        assert detector.detect_timestamp_field(event) == "timestamp"

    def test_detect_timestamp_from_value_heuristic(self, detector):
        """When no known field name matches, detect by value format."""
        event = {"event_created_at": "2024-06-15T10:30:00Z", "data": "test"}
        result = detector.detect_timestamp_field(event)
        assert result == "event_created_at"

    def test_no_timestamp_detected(self, detector):
        """Return None when no timestamp field is found."""
        event = {"id": 1, "message": "hello", "count": 42}
        assert detector.detect_timestamp_field(event) is None

    def test_epoch_timestamp_detection(self, detector):
        """Epoch timestamps (numeric) should be detected."""
        event = {"ts": 1718442600, "message": "test"}
        assert detector.detect_timestamp_field(event) == "ts"

    def test_timestamp_priority_order(self, detector):
        """Higher-priority timestamp fields should be preferred."""
        event = {
            "timestamp": "2024-06-15T10:30:00Z",
            "SystemTime": "2024-06-15T10:30:00.000Z",
            "date": "2024-06-15",
        }
        # SystemTime has higher priority than timestamp in the default list
        result = detector.detect_timestamp_field(event)
        assert result == "SystemTime"

    def test_looks_like_timestamp_iso(self):
        """ISO 8601 strings should be recognized as timestamps."""
        assert LogTypeDetector._looks_like_timestamp("2024-06-15T10:30:00Z")
        assert LogTypeDetector._looks_like_timestamp("2024-06-15T10:30:00.123456Z")
        assert LogTypeDetector._looks_like_timestamp("2024-06-15T10:30:00+00:00")
        assert LogTypeDetector._looks_like_timestamp("2024-06-15 10:30:00")

    def test_looks_like_timestamp_negative(self):
        """Non-timestamp strings should not be recognized."""
        assert not LogTypeDetector._looks_like_timestamp("hello")
        assert not LogTypeDetector._looks_like_timestamp(None)
        assert not LogTypeDetector._looks_like_timestamp("")
        assert not LogTypeDetector._looks_like_timestamp(42)
        assert not LogTypeDetector._looks_like_timestamp("short")

    def test_looks_like_timestamp_epoch(self):
        """Epoch timestamps should be recognized."""
        assert LogTypeDetector._looks_like_timestamp(1718442600)  # seconds
        assert LogTypeDetector._looks_like_timestamp(1718442600000)  # millis
        assert not LogTypeDetector._looks_like_timestamp(42)  # too small


# =============================================================================
# Batch Detection Tests
# =============================================================================

class TestBatchDetection:
    """Tests for batch detection across multiple files."""

    def test_batch_consistent_detection(self, detector, tmp_path):
        """Multiple files of the same type should produce consistent detection."""
        files = []
        for i in range(3):
            f = tmp_path / f"security_{i}.json"
            event = {
                "Event": {
                    "System": {
                        "EventID": 4624 + i,
                        "Channel": "Security",
                        "TimeCreated": {"#attributes": {"SystemTime": f"2024-06-15T10:3{i}:00Z"}},
                    },
                    "EventData": {"User": "admin"},
                }
            }
            with open(f, "w") as fp:
                fp.write(json.dumps(event) + "\n")
            files.append(f)

        result = detector.detect_batch(files)
        assert result.input_type == "json"
        assert result.log_source == "windows_evtx_json"
        assert result.confidence == "high"

    def test_batch_empty_list(self, detector):
        """Empty file list should return unknown result."""
        result = detector.detect_batch([])
        assert result.log_source == "unknown"

    def test_batch_single_file(self, detector, auditd_file):
        """Single file batch should work correctly."""
        result = detector.detect_batch([auditd_file])
        assert result.input_type == "auditd"

    def test_batch_confidence_boost_when_all_agree(self, detector, tmp_path):
        """When multiple files agree on type and confidence is medium, boost to high."""
        for i in range(2):
            f = tmp_path / f"auditd_{i}.log"
            f.write_text("type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e syscall=59 success=yes\n")
        result = detector.detect_batch([tmp_path / "auditd_0.log", tmp_path / "auditd_1.log"])
        assert result.input_type == "auditd"
        assert result.confidence == "high"


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, detector, empty_file):
        """Empty files should return a low-confidence fallback."""
        result = detector.detect(empty_file)
        assert result.confidence == "low"

    def test_detect_fallback_when_read_raises(self, detector, tmp_path):
        """When file cannot be read (e.g. path is a directory), fallback is used."""
        result = detector.detect(tmp_path)
        assert result is not None
        assert "Cannot read" in result.details or result.log_source == "unknown"

    def test_nonexistent_file(self, detector, tmp_path):
        """Non-existent files should be handled gracefully."""
        result = detector.detect(tmp_path / "nonexistent.json")
        assert result.log_source == "unknown"
        assert "File not found" in result.details

    def test_detect_directory_returns_file_not_found(self, detector, tmp_path):
        """When path is a directory (not a file), return unknown with File not found."""
        result = detector.detect(tmp_path)
        assert result.log_source == "unknown"
        assert "File not found" in result.details

    def test_compressed_empty_gz_fallback(self, detector, tmp_path):
        """Empty .gz decompresses to empty; fallback by inner extension."""
        empty_gz = tmp_path / "empty.json.gz"
        with gzip.open(empty_gz, "wb") as f:
            f.write(b"")
        result = detector.detect(empty_gz)
        assert "empty" in result.details.lower() or "could not decompress" in result.details.lower()
        assert result.input_type == "json" or result.log_source == "unknown"

    def test_compressed_corrupt_gz_fallback(self, detector, tmp_path):
        """Corrupt .gz falls back to inner extension (decompress exception)."""
        bad_gz = tmp_path / "bad.json.gz"
        bad_gz.write_bytes(b"not valid gzip content")
        result = detector.detect(bad_gz)
        assert "empty" in result.details.lower() or "could not decompress" in result.details.lower()
        assert result.input_type == "json" or result.log_source == "unknown"

    def test_compressed_corrupt_zip_fallback(self, detector, tmp_path):
        """Corrupt .zip uses stem extension and empty sample; fallback by extension."""
        bad_zip = tmp_path / "data.json.zip"
        bad_zip.write_text("not a zip file")
        result = detector.detect(bad_zip)
        assert result.input_type == "json" or "empty" in result.details.lower()

    def test_detect_read_sample_raises_returns_fallback(self, detector, tmp_path):
        """When _read_sample raises (e.g. permission), detect returns extension fallback."""
        f = tmp_path / "readable.log"
        f.write_text("plain text so no magic bytes")
        with patch.object(detector, "_read_sample", side_effect=OSError("Permission denied")):
            result = detector.detect(f)
        assert "Cannot read" in result.details
        assert result.input_type == "json"
        assert result.confidence == "low"

    def test_detect_read_sample_unicode_fallback_iso8859(self, detector, tmp_path):
        """Content that is not valid UTF-8 is decoded with iso-8859-1 fallback."""
        f = tmp_path / "latin1.json"
        raw = b'{"msg": "caf\xe9", "timestamp": "2024-06-15T10:30:00Z"}\n'
        f.write_bytes(raw)
        result = detector.detect(f)
        assert result is not None
        assert result.log_source in ("generic_json", "ecs_elastic", "auditd")

    def test_binary_junk(self, detector, binary_junk_file):
        """Random binary content should not crash detection."""
        result = detector.detect(binary_junk_file)
        assert result is not None
        assert isinstance(result.log_source, str)

    def test_malformed_json(self, detector, tmp_path):
        """Malformed JSON should be handled gracefully."""
        f = tmp_path / "malformed.json"
        f.write_text('{"broken": true, no_quotes: bad}\n')
        result = detector.detect(f)
        assert result is not None
        assert isinstance(result.log_source, str)

    def test_extension_fallback_json(self, detector, tmp_path):
        """Files with .json extension but unreadable content should fall back."""
        f = tmp_path / "weird.json"
        f.write_bytes(b"\x00\x01\x02\x03" * 100)
        result = detector.detect(f)
        assert result is not None
        assert isinstance(result.log_source, str)

    def test_extension_fallback_xml(self, detector, tmp_path):
        """Files with .xml extension but non-XML content should fall back."""
        f = tmp_path / "not_xml.xml"
        f.write_text("This is not XML at all\nJust plain text\n")
        result = detector.detect(f)
        assert result is not None
        assert isinstance(result.log_source, str)

    def test_extension_fallback_evtx(self, detector, tmp_path):
        """Empty file with .evtx extension should fall back to evtx by extension."""
        f = tmp_path / "empty.evtx"
        f.write_text("")
        result = detector.detect(f)
        assert result.input_type == "evtx"
        assert result.confidence == "low"

    def test_extension_fallback_tsv(self, detector, tmp_path):
        """File with .tsv extension and no content match should fall back."""
        f = tmp_path / "junk.tsv"
        f.write_text("x\ty\tz\n")
        result = detector.detect(f)
        assert result.input_type == "csv"
        assert result.log_source == "generic_csv"

    def test_extension_fallback_log(self, detector, tmp_path):
        """File with .log extension should fall back to json/generic_json."""
        f = tmp_path / "out.log"
        f.write_text("")
        result = detector.detect(f)
        assert result.input_type == "json"
        assert result.log_source == "generic_json"
        assert result.confidence == "low"

    def test_extension_unknown(self, detector, tmp_path):
        """Unknown extension should return unknown result."""
        f = tmp_path / "file.xyz"
        f.write_text("some content")
        result = detector.detect(f)
        assert result.log_source == "unknown"
        assert "Unknown extension" in result.details


# =============================================================================
# Archive password and internal helpers
# =============================================================================

class TestArchivePasswordBytes:
    """Tests for _archive_password_bytes used when opening protected archives."""

    def test_archive_password_none(self, test_logger):
        """When archive_password is None, _archive_password_bytes returns None."""
        det = LogTypeDetector(logger=test_logger)
        assert det._archive_password_bytes() is None

    def test_archive_password_str_encoded_to_bytes(self, test_logger):
        """When archive_password is str, _archive_password_bytes returns utf-8 bytes."""
        det = LogTypeDetector(logger=test_logger, archive_password="secret")
        assert det._archive_password_bytes() == b"secret"

    def test_archive_password_bytes_passthrough(self, test_logger):
        """When archive_password is bytes, _archive_password_bytes returns it as-is."""
        det = LogTypeDetector(logger=test_logger, archive_password=b"bytes\x00")
        assert det._archive_password_bytes() == b"bytes\x00"


class TestMagicBytesException:
    """Tests for _check_magic_bytes when file read fails."""

    def test_magic_bytes_open_raises_returns_none(self, detector, tmp_path):
        """When opening the file for magic bytes raises, _check_magic_bytes returns None."""
        f = tmp_path / "evtx.evtx"
        f.write_bytes(EVTX_MAGIC + b"\x00" * 50)
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            result = detector._check_magic_bytes(f)
        assert result is None


# =============================================================================
# DetectionResult Tests
# =============================================================================

class TestDetectionResult:
    """Tests for the DetectionResult dataclass."""

    def test_str_representation(self):
        """String representation should include key fields."""
        result = DetectionResult(
            input_type="json",
            log_source="sysmon_windows",
            confidence="high",
            timestamp_field="UtcTime",
            suggested_pipeline="sysmon",
        )
        s = str(result)
        assert "sysmon_windows" in s
        assert "json" in s
        assert "high" in s
        assert "UtcTime" in s

    def test_defaults(self):
        """Default values should be set correctly."""
        result = DetectionResult(
            input_type="json",
            log_source="generic_json",
            confidence="low",
        )
        assert result.timestamp_field is None
        assert result.suggested_pipeline is None
        assert result.details == ""
        assert result.metadata == {}


# =============================================================================
# Custom Timestamp Fields Configuration Tests
# =============================================================================

class TestCustomTimestampFields:
    """Tests for custom timestamp field configuration."""

    def test_custom_timestamp_fields(self):
        """Detector should use custom timestamp fields when provided."""
        custom_fields = ["my_time", "event_ts", "log_date"]
        detector = LogTypeDetector(timestamp_detection_fields=custom_fields)

        event = {"my_time": "2024-06-15T10:30:00Z", "SystemTime": "2024-06-15T10:30:00Z"}
        result = detector.detect_timestamp_field(event)
        assert result == "my_time"

    def test_custom_fields_priority(self):
        """Custom fields should be tried in order."""
        custom_fields = ["first_choice", "second_choice"]
        detector = LogTypeDetector(timestamp_detection_fields=custom_fields)

        # Only second choice present
        event = {"second_choice": "2024-06-15T10:30:00Z", "other": "data"}
        result = detector.detect_timestamp_field(event)
        assert result == "second_choice"


# =============================================================================
# Raw-Content Regex Timestamp Fallback Tests
# =============================================================================

class TestRawTimestampPatterns:
    """Tests for the TIMESTAMP_RAW_PATTERNS regexes."""

    def test_iso8601_full(self):
        """ISO 8601 with fractional seconds and Z should match."""
        text = 'some prefix 2024-06-15T10:30:00.123456Z some suffix'
        info = LogTypeDetector._detect_timestamp_from_raw_content(text)
        assert info is not None
        assert info["format"] == "ISO 8601"
        assert "2024-06-15T10:30:00.123456Z" in info["match"]

    def test_iso8601_with_offset(self):
        """ISO 8601 with timezone offset should match."""
        text = '{"ts": "2024-06-15T10:30:00+02:00"}'
        info = LogTypeDetector._detect_timestamp_from_raw_content(text)
        assert info is not None
        assert info["format"] == "ISO 8601"

    def test_iso8601_space_separator(self):
        """ISO 8601 with space instead of T should match."""
        text = 'event at 2024-06-15 10:30:00.999'
        info = LogTypeDetector._detect_timestamp_from_raw_content(text)
        assert info is not None
        assert info["format"] in ("ISO 8601", "ISO 8601 (space)")

    def test_us_date_format(self):
        """US date-time format should match."""
        text = 'logged 06/15/2024 10:30:00 by system'
        info = LogTypeDetector._detect_timestamp_from_raw_content(text)
        assert info is not None
        assert "US" in info["format"] or "ISO" in info["format"]

    def test_syslog_format(self):
        """Syslog month-day-time format should match."""
        text = 'Jun 15 10:30:00 myhost sshd[1234]: message'
        info = LogTypeDetector._detect_timestamp_from_raw_content(text)
        assert info is not None
        assert info["format"] == "Syslog"

    def test_epoch_seconds(self):
        """10-digit epoch seconds should match."""
        text = 'timestamp=1718442600 action=login'
        info = LogTypeDetector._detect_timestamp_from_raw_content(text)
        assert info is not None
        assert "Epoch" in info["format"]
        assert "1718442600" in info["match"]

    def test_epoch_milliseconds(self):
        """13-digit epoch millis should match."""
        text = '{"ts": 1718442600000, "msg": "test"}'
        info = LogTypeDetector._detect_timestamp_from_raw_content(text)
        assert info is not None
        assert "Epoch" in info["format"] or "ISO" not in info["format"]

    def test_no_timestamp_in_content(self):
        """Content without any timestamps should return None."""
        text = 'just some random text without any dates or numbers of interest'
        info = LogTypeDetector._detect_timestamp_from_raw_content(text)
        assert info is None


class TestRawTimestampFallbackIntegration:
    """Tests that the regex fallback enriches detection results."""

    def test_generic_json_gets_timestamp_from_raw(self, detector, tmp_path):
        """Generic JSON with an unusual timestamp field should be enriched."""
        f = tmp_path / "custom.json"
        events = [
            {"id": 1, "event_logged_at": "2024-06-15T10:30:00Z", "action": "login"},
            {"id": 2, "event_logged_at": "2024-06-15T10:31:00Z", "action": "logout"},
        ]
        with open(f, "w") as fp:
            for e in events:
                fp.write(json.dumps(e) + "\n")

        result = detector.detect(f)
        assert result.input_type == "json"
        # The heuristic phase 2 in detect_timestamp_field should already
        # catch this via _looks_like_timestamp on the value, but if it doesn't,
        # the raw fallback should still find the ISO pattern.
        assert result.timestamp_field is not None

    def test_fallback_extension_gets_raw_timestamp(self, detector, tmp_path):
        """Extension-only fallback should still detect timestamp format from content."""
        f = tmp_path / "mystery.log"
        # Content that doesn't match any structured format but has timestamps
        content = (
            "INFO 2024-06-15T10:30:00.000Z Starting application\n"
            "WARN 2024-06-15T10:30:01.123Z Memory usage high\n"
            "ERROR 2024-06-15T10:30:02.456Z Connection refused\n"
        )
        f.write_text(content)

        result = detector.detect(f)
        # Extension .log falls back, but raw scan should spot ISO 8601
        assert "ISO 8601" in result.details or result.timestamp_field is not None
        assert "raw_timestamp_format" in result.metadata or result.timestamp_field is not None

    def test_csv_without_known_headers_gets_timestamp(self, detector, tmp_path):
        """A CSV with no known headers should still detect a timestamp column."""
        f = tmp_path / "firewall.csv"
        content = """src_ip,dst_ip,action,logged_at
192.168.1.10,10.0.0.1,ALLOW,2024-06-15T10:30:00Z
192.168.1.11,10.0.0.2,DENY,2024-06-15T10:31:00Z
"""
        f.write_text(content)

        result = detector.detect(f)
        assert result.input_type == "csv"
        # No "timestamp" header, but _detect_timestamp_field + raw fallback
        # should still find the ISO value in the 'logged_at' column
        assert result.timestamp_field is not None or "ISO" in result.details

    def test_syslog_plain_text_gets_timestamp(self, detector, tmp_path):
        """Plain syslog text should have its timestamp format reported."""
        f = tmp_path / "syslog.log"
        content = (
            "Jun 15 10:30:00 myhost sshd[1234]: Accepted publickey for user\n"
            "Jun 15 10:30:01 myhost sshd[1235]: session opened for user\n"
        )
        f.write_text(content)

        result = detector.detect(f)
        # Not auditd, not sysmon-linux => falls back to extension
        # Raw scan should spot the syslog timestamp format
        assert "Syslog" in result.details or "raw_timestamp_format" in result.metadata

    def test_enrich_timestamp_matched_key_from_json(self, detector, tmp_path):
        """Raw timestamp enrichment sets timestamp_field when JSON key contains the matched value."""
        f = tmp_path / "custom_ts.json"
        f.write_text('{"logged_at": "2024-06-15T10:30:00Z", "msg": "test"}\n')
        result = detector.detect(f)
        assert result.timestamp_field == "logged_at"

    def test_enrich_timestamp_metadata_only_when_no_json_key(self, detector, tmp_path):
        """Raw timestamp enrichment sets only metadata when content has timestamp but no JSON key."""
        f = tmp_path / "text.log"
        f.write_text("plain text 2024-06-15T10:30:00 more text\n")
        result = detector.detect(f)
        assert "raw_timestamp_format" in result.metadata or "2024" in result.details


class TestLooksLikeTimestampExtended:
    """Tests for extended _looks_like_timestamp patterns."""

    def test_syslog_string(self):
        """Syslog-style timestamps should be recognized."""
        assert LogTypeDetector._looks_like_timestamp("Jun 15 10:30:00")
        assert LogTypeDetector._looks_like_timestamp("Dec  1 08:00:00")
        assert not LogTypeDetector._looks_like_timestamp("Foo 99 10:30:00")

    def test_us_date_string(self):
        """US-style date strings should be recognized."""
        assert LogTypeDetector._looks_like_timestamp("06/15/2024 10:30:00")
        assert LogTypeDetector._looks_like_timestamp("12/31/2024")

    def test_windows_filetime_int(self):
        """Windows FileTime integers should be recognized."""
        assert LogTypeDetector._looks_like_timestamp(133627842000000000)
        assert not LogTypeDetector._looks_like_timestamp(99)

    def test_windows_filetime_string(self):
        """Windows FileTime as string should be recognized."""
        assert LogTypeDetector._looks_like_timestamp("133627842000000000")

    def test_looks_like_timestamp_none_and_non_string(self):
        """None and non-string types should return False."""
        assert not LogTypeDetector._looks_like_timestamp(None)
        assert not LogTypeDetector._looks_like_timestamp([])
        assert not LogTypeDetector._looks_like_timestamp({})

    def test_looks_like_timestamp_int_out_of_range(self):
        """Integers outside epoch/FileTime range should return False."""
        assert not LogTypeDetector._looks_like_timestamp(1)
        assert not LogTypeDetector._looks_like_timestamp(946684799)
        assert not LogTypeDetector._looks_like_timestamp(4102444801)

    def test_looks_like_timestamp_float_epoch_millis(self):
        """Float epoch milliseconds should be recognized."""
        assert LogTypeDetector._looks_like_timestamp(1718442600000.0)

    def test_looks_like_timestamp_string_length_bounds(self):
        """Strings too short or too long should return False."""
        assert not LogTypeDetector._looks_like_timestamp("1234567")
        assert not LogTypeDetector._looks_like_timestamp("a" * 41)

    def test_looks_like_timestamp_date_only(self):
        """Date-only YYYY-MM-DD should be recognized."""
        assert LogTypeDetector._looks_like_timestamp("2024-06-15")

    def test_looks_like_timestamp_digit_18_starts_with_one(self):
        """18-digit string starting with 1 (Windows FileTime) should be recognized."""
        assert LogTypeDetector._looks_like_timestamp("133627842000000000")
        assert not LogTypeDetector._looks_like_timestamp("233627842000000000")


class TestTimestampFieldScore:
    """Tests for _timestamp_field_score."""

    def test_exact_timestamp_names(self):
        """Exact timestamp names should score 100."""
        assert LogTypeDetector._timestamp_field_score("SystemTime") == 100
        assert LogTypeDetector._timestamp_field_score("UtcTime") == 100
        assert LogTypeDetector._timestamp_field_score("timestamp") == 100

    def test_contains_timestamp(self):
        """Field names containing 'timestamp' should score 90."""
        assert LogTypeDetector._timestamp_field_score("event_timestamp") == 90

    def test_contains_time_not_timeout(self):
        """Field names containing 'time' but not 'timeout' should score 80."""
        assert LogTypeDetector._timestamp_field_score("event_time") == 80
        assert LogTypeDetector._timestamp_field_score("timeout") == 0

    def test_contains_date_not_update(self):
        """Field names containing 'date' but not 'update' should score 70."""
        assert LogTypeDetector._timestamp_field_score("birth_date") == 70
        assert LogTypeDetector._timestamp_field_score("last_update") == 0

    def test_short_ts_names(self):
        """Short names ts and dt should score 60."""
        assert LogTypeDetector._timestamp_field_score("ts") == 60
        assert LogTypeDetector._timestamp_field_score("dt") == 60

    def test_contains_created(self):
        """Field names containing 'created' should score 50."""
        assert LogTypeDetector._timestamp_field_score("created_at") == 50

    def test_contains_when(self):
        """Field names containing 'when' should score 40."""
        assert LogTypeDetector._timestamp_field_score("occurred_when") == 40

    def test_unknown_returns_zero(self):
        """Unknown field names should score 0."""
        assert LogTypeDetector._timestamp_field_score("message") == 0
        assert LogTypeDetector._timestamp_field_score("payload") == 0


# =============================================================================
# _collect_keys and _find_key_for_value
# =============================================================================


class TestCollectKeysAndFindKeyForValue:
    """Tests for _collect_keys and _find_key_for_value helpers."""

    def test_collect_keys_recursive(self):
        """_collect_keys should collect top-level and nested keys with dot notation."""
        keys = set()
        obj = {"a": 1, "b": {"c": 2, "d": {"e": 3}}}
        LogTypeDetector._collect_keys(obj, keys)
        assert "a" in keys
        assert "b" in keys
        assert "b.c" in keys
        assert "b.d" in keys
        assert "b.d.e" in keys

    def test_find_key_for_value_nested_dict(self):
        """_find_key_for_value returns sub_key when needle is in inner dict (one level deep)."""
        event = {"Event": {"SystemTime": "2024-06-15T10:30:00Z"}}
        assert LogTypeDetector._find_key_for_value(event, "2024-06-15T10:30:00Z") == "SystemTime"

    def test_find_key_for_value_three_levels_returns_none(self):
        """_find_key_for_value only looks one level deep; three-level nesting is not found."""
        event = {"Event": {"System": {"SystemTime": "2024-06-15T10:30:00Z"}}}
        assert LogTypeDetector._find_key_for_value(event, "2024-06-15T10:30:00Z") is None

    def test_find_key_for_value_top_level(self):
        """_find_key_for_value should return key when needle is in top-level string value."""
        event = {"timestamp": "2024-06-15T10:30:00Z", "msg": "hello"}
        assert LogTypeDetector._find_key_for_value(event, "2024-06-15T10:30:00Z") == "timestamp"

    def test_find_key_for_value_not_found(self):
        """_find_key_for_value should return None when needle is not in any string value."""
        event = {"a": "x", "b": {"c": "y"}}
        assert LogTypeDetector._find_key_for_value(event, "z") is None


# =============================================================================
# CSV edge cases: delimiter heuristic, parse exception, return None
# =============================================================================


class TestCsvEdgeCases:
    """Tests for _check_csv edge paths."""

    def test_csv_delimiter_heuristic_plain_txt(self, detector, tmp_path):
        """Content with consistent delimiter but non-.csv extension can be detected as CSV."""
        f = tmp_path / "data.txt"
        f.write_text("col1,col2,col3\n1,2,3\n4,5,6\n")
        result = detector.detect(f)
        assert result.input_type == "csv"
        assert result.log_source == "generic_csv"

    def test_csv_extension_parse_failure_returns_low_confidence(self, detector, tmp_path):
        """When extension is .csv but sniffer/parse fails, return low-confidence CSV."""
        f = tmp_path / "bad.csv"
        f.write_text("not,enough\n")
        result = detector.detect(f)
        assert result.input_type == "csv"
        assert result.log_source == "generic_csv"
        assert result.confidence in ("low", "medium")

    def test_no_delimiter_match_returns_none_from_content(self, detector, tmp_path):
        """Content with no consistent delimiter and non-csv extension returns None from _detect_from_content."""
        f = tmp_path / "single_col.txt"
        f.write_text("only one column\nand another line\n")
        result = detector.detect(f)
        assert result is not None
        assert result.log_source in ("generic_json", "unknown") or "extension" in result.details.lower()


# =============================================================================
# _check_evtxtract single marker returns None
# =============================================================================


class TestEvtxtractSingleMarker:
    """EVTXtract with fewer than 2 markers should not be detected as evtxtract."""

    def test_evtxtract_one_marker_returns_none(self, detector, tmp_path):
        """Content with only one EVTXtract marker should not be classified as evtxtract."""
        f = tmp_path / "one_marker.log"
        f.write_text('Found at offset 0x100\n<Event><EventID>1</EventID></Event>\n')
        result = detector.detect(f)
        assert result.input_type != "evtxtract" or result.log_source != "evtxtract"


# =============================================================================
# JSON classification: Event.System without Channel/EventID, type not in AUDITD, ECS no winlog
# =============================================================================


class TestJsonClassificationEdgeCases:
    """Tests for _classify_json_event edge branches."""

    def test_json_event_system_without_channel_or_eventid(self, detector, tmp_path):
        """JSON with Event.System but no Channel/EventID keys falls through to other checks."""
        f = tmp_path / "minimal_event.json"
        event = {
            "Event": {
                "System": {"Provider": {"#attributes": {"Name": "Custom"}}},
                "EventData": {},
            }
        }
        f.write_text(json.dumps(event) + "\n")
        result = detector.detect(f)
        assert result is not None
        assert result.input_type == "json"

    def test_json_type_not_in_auditd_types(self, detector, tmp_path):
        """JSON with type field but value not in AUDITD_TYPES is not classified as auditd."""
        f = tmp_path / "custom_type.json"
        event = {"type": "CUSTOM_TYPE", "timestamp": "2024-06-15T10:30:00Z"}
        f.write_text(json.dumps(event) + "\n")
        result = detector.detect(f)
        assert result.log_source != "auditd"

    def test_json_ecs_without_winlog_channel(self, detector, tmp_path):
        """ECS-style JSON with @timestamp but no winlog.channel gets medium confidence ecs_elastic."""
        f = tmp_path / "ecs_no_winlog.json"
        event = {"@timestamp": "2024-06-15T10:30:00.000Z", "event": {"module": "sysmon"}, "message": "test"}
        f.write_text(json.dumps(event) + "\n")
        result = detector.detect(f)
        assert result.log_source == "ecs_elastic"
        assert result.confidence in ("high", "medium")

    def test_json_sysmon_fields_medium_confidence(self, detector, tmp_path):
        """JSON with 3+ Sysmon-like fields (no Event wrapper) is classified as sysmon_windows medium."""
        f = tmp_path / "sysmon_flat.json"
        event = {
            "RuleName": "-",
            "ProcessGuid": "{abc}",
            "ProcessId": "1234",
            "Image": "C:\\cmd.exe",
            "UtcTime": "2024-06-15 10:30:00.000",
            "CommandLine": "cmd.exe",
        }
        f.write_text(json.dumps(event) + "\n")
        result = detector.detect(f)
        assert result.log_source == "sysmon_windows"
        assert result.confidence in ("high", "medium")


# =============================================================================
# Compressed detection: .gz with JSON, _check_magic_bytes skips compressed
# =============================================================================


class TestCompressedDetection:
    """Tests for compressed file detection paths."""

    def test_detect_gz_with_json_content(self, detector, tmp_path):
        """Compressed .gz containing JSON is detected from decompressed content."""
        import gzip
        raw = b'{"Event":{"System":{"EventID":1,"Channel":"Security"}}}\n'
        f = tmp_path / "events.json.gz"
        with gzip.open(f, "wb") as gz:
            gz.write(raw)
        result = detector.detect(f)
        assert result.input_type == "json"
        assert result.log_source in ("windows_evtx_json", "sysmon_windows", "generic_json")

    def test_check_magic_bytes_skips_compressed(self, detector, tmp_path):
        """_check_magic_bytes returns None for compressed suffix so content is sampled instead."""
        f = tmp_path / "data.evtx.gz"
        f.write_bytes(b"\x1f\x8b")  # gzip magic
        result = detector._check_magic_bytes(f)
        assert result is None

    def test_detect_zip_with_one_member(self, detector, tmp_path):
        """ZIP archive with one JSON member is detected from extracted content."""
        import zipfile
        zip_path = tmp_path / "logs.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("events.json", b'{"id":1,"timestamp":"2024-06-15T10:30:00Z"}\n')
        result = detector.detect(zip_path)
        assert result.input_type == "json"
        assert result.log_source in ("generic_json", "ecs_elastic")

    def test_read_sample_unicode_fallback(self, detector, tmp_path):
        """_read_sample decodes with iso-8859-1 when UTF-8 fails."""
        f = tmp_path / "latin1.txt"
        f.write_bytes(b"type=SYSCALL msg=audit(1705318200.123:456): caf\xe9\n")
        sample_bytes, text, lines = detector._read_sample(f)
        assert "caf" in text
        assert len(lines) >= 1


# =============================================================================
# _parse_first_json_event truncated array recovery
# =============================================================================


class TestParseFirstJsonEventRecovery:
    """Tests for line-by-line JSON recovery in _parse_first_json_event."""

    def test_truncated_json_array_line_recovery(self, detector):
        """Truncated JSON array can yield first event via line-by-line recovery."""
        sample = b'[\n{"id":1,"timestamp":"2024-06-15T10:30:00Z"},\n'
        event = detector._parse_first_json_event(sample, is_json_array=True)
        assert event is not None
        assert event.get("id") == 1
        assert "timestamp" in event


# =============================================================================
# Real Fixture Single-File Detection Tests
# =============================================================================


class TestRealFixtureSingleFile:
    """Systematic detection tests against every log fixture in tests/fixtures/.

    Each test runs detector.detect() on a real fixture file and verifies the
    full DetectionResult: input_type, log_source, confidence, timestamp_field,
    and a non-empty details string.
    """

    def test_sample_events_json(self, detector):
        """sample_events.json: Windows Sysmon JSONL should be detected."""
        fixture = FIXTURES_DIR / "sample_events.json"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "json"
        assert result.log_source in ("windows_evtx_json", "sysmon_windows")
        assert result.confidence == "high"
        assert result.timestamp_field in ("SystemTime", "UtcTime")
        assert result.details

    def test_winlogbeat_sysmon_json(self, detector):
        """winlogbeat_sysmon_sample.json: ECS/Winlogbeat format detection."""
        fixture = FIXTURES_DIR / "winlogbeat_sysmon_sample.json"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "json"
        assert result.log_source == "ecs_elastic"
        assert result.confidence == "high"
        assert result.timestamp_field == "@timestamp"
        assert result.details

    def test_xml_events_sample(self, detector):
        """xml_events_sample.xml: Windows Event XML with MS namespace."""
        fixture = FIXTURES_DIR / "xml_events_sample.xml"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "xml"
        assert result.log_source == "windows_evtx_xml"
        assert result.confidence == "high"
        assert result.timestamp_field == "SystemTime"
        assert result.details

    def test_audit_sample_log(self, detector):
        """audit_sample.log: Linux Auditd key=value format."""
        fixture = FIXTURES_DIR / "audit_sample.log"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "auditd"
        assert result.log_source == "auditd"
        assert result.confidence == "high"
        assert result.details

    def test_sysmon_linux_sample_log(self, detector):
        """sysmon_linux_sample.log: Sysmon for Linux (syslog + embedded XML)."""
        fixture = FIXTURES_DIR / "sysmon_linux_sample.log"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "sysmon_linux"
        assert result.log_source == "sysmon_linux"
        assert result.confidence == "high"
        assert result.timestamp_field == "UtcTime"
        assert result.details

    def test_evtxtract_sample_log(self, detector):
        """evtxtract_sample.log: EVTXtract output (concatenated Event XML)."""
        fixture = FIXTURES_DIR / "evtxtract_sample.log"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type in ("xml", "evtxtract")
        assert result.log_source in ("windows_evtx_xml", "evtxtract", "generic_xml")
        assert result.confidence in ("high", "medium")
        assert result.details

    def test_sample_bitsadmin_evtx(self, detector):
        """sample_bitsadmin.evtx: EVTX binary detected via magic bytes."""
        fixture = FIXTURES_DIR / "sample_bitsadmin.evtx"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "evtx"
        assert result.log_source == "windows_evtx"
        assert result.confidence == "high"
        assert result.details

    def test_sample_bitsadmin_db(self, detector):
        """sample_bitsadmin.db: SQLite database detected via magic bytes."""
        fixture = FIXTURES_DIR / "sample_bitsadmin.db"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect(fixture)
        assert result.input_type == "sqlite"
        assert result.log_source == "sqlite_db"
        assert result.confidence == "high"
        assert result.details


# =============================================================================
# Real Fixture Batch / Directory Detection Tests
# =============================================================================


class TestRealFixtureBatchDetection:
    """Batch detection tests using real fixture files.

    Tests simulate directory processing by copying fixture files into temp
    directories and passing the file lists to detect_batch().
    """

    def _copy_fixtures(self, names, dest_dir):
        """Copy named fixtures into dest_dir and return their new paths."""
        import shutil
        paths = []
        for name in names:
            src = FIXTURES_DIR / name
            if not src.exists():
                pytest.skip(f"Fixture not found: {src}")
            dst = dest_dir / name
            shutil.copy2(src, dst)
            paths.append(dst)
        return paths

    def test_batch_same_type_windows_json(self, detector, tmp_path):
        """Batch of identical Windows EVTX JSON files agrees on type."""
        import shutil
        src = FIXTURES_DIR / "sample_events.json"
        if not src.exists():
            pytest.skip(f"Fixture not found: {src}")
        files = []
        for i in range(3):
            dst = tmp_path / f"events_{i}.json"
            shutil.copy2(src, dst)
            files.append(dst)

        result = detector.detect_batch(files)
        assert result.input_type == "json"
        assert result.log_source in ("windows_evtx_json", "sysmon_windows")
        assert result.confidence == "high"

    def test_batch_same_type_auditd(self, detector, tmp_path):
        """Batch of identical auditd files agrees on type."""
        import shutil
        src = FIXTURES_DIR / "audit_sample.log"
        if not src.exists():
            pytest.skip(f"Fixture not found: {src}")
        files = []
        for i in range(3):
            dst = tmp_path / f"audit_{i}.log"
            shutil.copy2(src, dst)
            files.append(dst)

        result = detector.detect_batch(files)
        assert result.input_type == "auditd"
        assert result.log_source == "auditd"
        assert result.confidence == "high"

    def test_batch_same_type_sysmon_linux(self, detector, tmp_path):
        """Batch of identical Sysmon Linux files agrees on type."""
        import shutil
        src = FIXTURES_DIR / "sysmon_linux_sample.log"
        if not src.exists():
            pytest.skip(f"Fixture not found: {src}")
        files = []
        for i in range(3):
            dst = tmp_path / f"sysmon_{i}.log"
            shutil.copy2(src, dst)
            files.append(dst)

        result = detector.detect_batch(files)
        assert result.input_type == "sysmon_linux"
        assert result.log_source == "sysmon_linux"
        assert result.confidence == "high"

    def test_batch_mixed_json_formats(self, detector, tmp_path):
        """Batch of different JSON formats returns a valid high-confidence result."""
        files = self._copy_fixtures(
            ["sample_events.json", "winlogbeat_sysmon_sample.json"],
            tmp_path,
        )
        result = detector.detect_batch(files)
        assert result.input_type == "json"
        assert result.confidence == "high"
        assert result.log_source in ("windows_evtx_json", "sysmon_windows", "ecs_elastic")

    def test_batch_mixed_types(self, detector, tmp_path):
        """Batch of different log types still returns the best-confidence result."""
        files = self._copy_fixtures(
            ["sample_events.json", "audit_sample.log", "xml_events_sample.xml"],
            tmp_path,
        )
        result = detector.detect_batch(files)
        assert result.confidence == "high"
        assert result.input_type in ("json", "auditd", "xml")
        assert result.log_source != "unknown"

    def test_batch_single_evtx(self, detector):
        """Single EVTX file in a batch list is handled correctly."""
        fixture = FIXTURES_DIR / "sample_bitsadmin.evtx"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect_batch([fixture])
        assert result.input_type == "evtx"
        assert result.log_source == "windows_evtx"
        assert result.confidence == "high"

    def test_batch_single_sqlite(self, detector):
        """Single SQLite file in a batch list is handled correctly."""
        fixture = FIXTURES_DIR / "sample_bitsadmin.db"
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        result = detector.detect_batch([fixture])
        assert result.input_type == "sqlite"
        assert result.log_source == "sqlite_db"
        assert result.confidence == "high"

    def test_batch_all_log_fixtures(self, detector, tmp_path):
        """Batch with all log fixture types returns a valid result."""
        log_fixtures = [
            "sample_events.json",
            "winlogbeat_sysmon_sample.json",
            "xml_events_sample.xml",
            "audit_sample.log",
            "sysmon_linux_sample.log",
            "evtxtract_sample.log",
        ]
        files = self._copy_fixtures(log_fixtures, tmp_path)
        result = detector.detect_batch(files)
        assert result.confidence in ("high", "medium")
        assert result.log_source != "unknown"
        assert result.details
