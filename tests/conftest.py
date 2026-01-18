"""
Shared pytest fixtures for Zircolite test suite.
"""

import json
import os
import pytest
import shutil
import sqlite3
import sys
import tempfile
import yaml
from pathlib import Path
from unittest.mock import MagicMock, patch
from argparse import Namespace

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import (
    JSONFlattener,
    ZircoliteCore,
    EvtxExtractor,
    TemplateEngine,
    MemoryTracker,
    StreamingEventProcessor,
    init_logger,
    load_field_mappings,
    # Config dataclasses
    ProcessingConfig,
    ExtractorConfig,
    RulesetConfig,
    TemplateConfig,
    GuiConfig,
)

# For backwards compatibility, also import these
from zircolite import (
    quit_on_error,
    check_if_exists,
    select_files,
    avoid_files,
)


# =============================================================================
# Field Mappings Configuration Fixtures
# =============================================================================

@pytest.fixture
def minimal_field_mappings():
    """Minimal field mappings configuration for testing."""
    return {
        "exclusions": ["xmlns"],
        "useless": [None, ""],
        "mappings": {
            "Event.System.EventID": "EventID",
            "Event.System.Channel": "Channel",
            "Event.System.Computer": "Computer",
            "Event.System.TimeCreated.#attributes.SystemTime": "SystemTime",
            "Event.EventData.CommandLine": "CommandLine",
            "Event.EventData.Image": "Image",
            "Event.EventData.User": "User",
            "Event.EventData.TargetFilename": "TargetFileName",
            "Event.EventData.ParentImage": "ParentImage",
        },
        "alias": {},
        "split": {
            "Hashes": {"separator": ",", "equal": "="}
        },
        "transforms_enabled": False,
        "transforms": {}
    }


@pytest.fixture
def field_mappings_with_transforms():
    """Field mappings with transforms enabled for testing."""
    return {
        "exclusions": ["xmlns"],
        "useless": [None, ""],
        "mappings": {
            "Event.System.EventID": "EventID",
            "Event.EventData.CommandLine": "CommandLine",
        },
        "alias": {
            "CommandLine": "cmd"
        },
        "split": {},
        "transforms_enabled": True,
        "transforms": {
            "proctitle": [{
                "info": "Proctitle HEX to ASCII",
                "type": "python",
                "code": "def transform(param):\n\treturn param.upper()",
                "alias": False,
                "alias_name": "",
                "source_condition": ["auditd_input"],
                "enabled": True
            }]
        }
    }


@pytest.fixture
def field_mappings_file(tmp_path, minimal_field_mappings):
    """Create a temporary field mappings JSON file."""
    config_file = tmp_path / "fieldMappings.json"
    config_file.write_text(json.dumps(minimal_field_mappings))
    return str(config_file)


@pytest.fixture
def field_mappings_file_with_transforms(tmp_path, field_mappings_with_transforms):
    """Create a temporary field mappings JSON file with transforms."""
    config_file = tmp_path / "fieldMappings_transforms.json"
    config_file.write_text(json.dumps(field_mappings_with_transforms))
    return str(config_file)


@pytest.fixture
def field_mappings_yaml_file(tmp_path, minimal_field_mappings):
    """Create a temporary field mappings YAML file."""
    config_file = tmp_path / "fieldMappings.yaml"
    config_file.write_text(yaml.dump(minimal_field_mappings, default_flow_style=False))
    return str(config_file)


@pytest.fixture
def field_mappings_yml_file(tmp_path, minimal_field_mappings):
    """Create a temporary field mappings YAML file with .yml extension."""
    config_file = tmp_path / "fieldMappings.yml"
    config_file.write_text(yaml.dump(minimal_field_mappings, default_flow_style=False))
    return str(config_file)


@pytest.fixture
def field_mappings_yaml_with_transforms(tmp_path, field_mappings_with_transforms):
    """Create a temporary field mappings YAML file with transforms."""
    config_file = tmp_path / "fieldMappings_transforms.yaml"
    config_file.write_text(yaml.dump(field_mappings_with_transforms, default_flow_style=False))
    return str(config_file)


@pytest.fixture
def field_mappings_yaml_with_comments(tmp_path, minimal_field_mappings):
    """Create a YAML config with comments to verify parsing."""
    yaml_content = """# Field mappings configuration
# This is a test file with comments

exclusions:
  - xmlns  # Exclude XML namespace attributes

useless:
  - null
  - ""

# Map nested fields to simple names
mappings:
  Event.System.EventID: EventID
  Event.System.Channel: Channel
  Event.System.Computer: Computer
  Event.System.TimeCreated.#attributes.SystemTime: SystemTime
  Event.EventData.CommandLine: CommandLine
  Event.EventData.Image: Image
  Event.EventData.User: User
  Event.EventData.TargetFilename: TargetFileName
  Event.EventData.ParentImage: ParentImage

alias: {}

split:
  Hashes:
    separator: ","
    equal: "="

transforms_enabled: false
transforms: {}
"""
    config_file = tmp_path / "fieldMappings_commented.yaml"
    config_file.write_text(yaml_content)
    return str(config_file)


# =============================================================================
# Sample Event Data Fixtures
# =============================================================================

@pytest.fixture
def sample_windows_event():
    """Sample Windows Event log entry (flattened JSON structure)."""
    return {
        "Event": {
            "System": {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Computer": "WORKSTATION01",
                "TimeCreated": {
                    "#attributes": {
                        "SystemTime": "2024-01-15T10:30:00.000Z"
                    }
                },
                "Provider": {
                    "#attributes": {
                        "Name": "Microsoft-Windows-Sysmon"
                    }
                }
            },
            "EventData": {
                "CommandLine": "powershell.exe -encodedCommand SGVsbG8gV29ybGQ=",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "User": "WORKSTATION01\\admin",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ProcessId": "1234",
                "ParentProcessId": "5678",
                "Hashes": "MD5=abc123,SHA256=def456"
            }
        }
    }


@pytest.fixture
def sample_windows_events_list():
    """List of sample Windows events for batch testing."""
    return [
        {
            "Event": {
                "System": {
                    "EventID": 1,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": "WORKSTATION01",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:30:00.000Z"}}
                },
                "EventData": {
                    "CommandLine": "cmd.exe /c whoami",
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "User": "WORKSTATION01\\admin"
                }
            }
        },
        {
            "Event": {
                "System": {
                    "EventID": 3,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": "WORKSTATION01",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:31:00.000Z"}}
                },
                "EventData": {
                    "DestinationIp": "192.168.1.100",
                    "DestinationPort": "443",
                    "Image": "C:\\Windows\\System32\\cmd.exe"
                }
            }
        },
        {
            "Event": {
                "System": {
                    "EventID": 11,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": "WORKSTATION01",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:32:00.000Z"}}
                },
                "EventData": {
                    "TargetFilename": "C:\\Users\\admin\\malware.exe",
                    "Image": "C:\\Windows\\explorer.exe"
                }
            }
        }
    ]


@pytest.fixture
def sample_auditd_log_line():
    """Sample Auditd log line for testing."""
    return 'type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7f1234567890 a1=7f1234567890 a2=7f1234567890 a3=0 items=2 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/bin/bash" key="commands"'


@pytest.fixture
def sample_xml_event():
    """Sample XML Windows Event for testing."""
    return '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
        <EventID>1</EventID>
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>WORKSTATION01</Computer>
        <TimeCreated SystemTime="2024-01-15T10:30:00.000Z"/>
    </System>
    <EventData>
        <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass</Data>
        <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
        <Data Name="User">WORKSTATION01\\admin</Data>
    </EventData>
</Event>'''


# =============================================================================
# Sample Rules and Rulesets Fixtures
# =============================================================================

@pytest.fixture
def sample_ruleset():
    """Sample Zircolite ruleset for testing."""
    return [
        {
            "title": "Suspicious PowerShell Command",
            "id": "test-rule-001",
            "status": "test",
            "description": "Detects suspicious PowerShell commands",
            "author": "Test Author",
            "tags": ["attack.execution", "attack.t1059.001"],
            "falsepositives": ["Unknown"],
            "level": "high",
            "rule": [
                "SELECT * FROM logs WHERE CommandLine LIKE '%powershell%' ESCAPE '\\'"
            ],
            "filename": "test_rule_powershell.yml"
        },
        {
            "title": "CMD Whoami Execution",
            "id": "test-rule-002",
            "status": "test",
            "description": "Detects whoami command execution",
            "author": "Test Author",
            "tags": ["attack.discovery", "attack.t1033"],
            "falsepositives": ["Legitimate admin"],
            "level": "medium",
            "rule": [
                "SELECT * FROM logs WHERE CommandLine LIKE '%whoami%' ESCAPE '\\'"
            ],
            "filename": "test_rule_whoami.yml"
        },
        {
            "title": "Suspicious File Creation",
            "id": "test-rule-003",
            "status": "test",
            "description": "Detects suspicious file creation",
            "author": "Test Author",
            "tags": ["attack.persistence"],
            "falsepositives": ["Unknown"],
            "level": "low",
            "rule": [
                "SELECT * FROM logs WHERE TargetFileName LIKE '%.exe' ESCAPE '\\'"
            ],
            "filename": "test_rule_file.yml"
        }
    ]


@pytest.fixture
def sample_ruleset_file(tmp_path, sample_ruleset):
    """Create a temporary ruleset JSON file."""
    ruleset_file = tmp_path / "test_ruleset.json"
    ruleset_file.write_text(json.dumps(sample_ruleset))
    return str(ruleset_file)


@pytest.fixture
def empty_ruleset():
    """Empty ruleset for edge case testing."""
    return []


@pytest.fixture
def malformed_ruleset():
    """Malformed ruleset for error handling tests."""
    return [
        {"title": "Missing Rule Key"},  # Missing 'rule' key
        None,  # Null entry
        {},  # Empty dict
    ]


# =============================================================================
# Temporary Directory and File Fixtures
# =============================================================================

@pytest.fixture
def tmp_json_file(tmp_path, sample_windows_event):
    """Create a temporary JSON file with sample event data."""
    json_file = tmp_path / "sample_events.json"
    json_file.write_text(json.dumps(sample_windows_event) + "\n")
    return str(json_file)


@pytest.fixture
def tmp_json_file_multiple(tmp_path, sample_windows_events_list):
    """Create a temporary JSON file with multiple events (JSONL format)."""
    json_file = tmp_path / "sample_events_multi.json"
    with open(json_file, 'w') as f:
        for event in sample_windows_events_list:
            f.write(json.dumps(event) + "\n")
    return str(json_file)


@pytest.fixture
def tmp_json_array_file(tmp_path, sample_windows_events_list):
    """Create a temporary JSON array file with multiple events."""
    json_file = tmp_path / "sample_events_array.json"
    json_file.write_text(json.dumps(sample_windows_events_list))
    return str(json_file)


@pytest.fixture
def tmp_csv_file(tmp_path):
    """Create a temporary CSV file with sample data."""
    csv_file = tmp_path / "sample_events.csv"
    csv_content = """EventID,Channel,Computer,CommandLine,Image,User
1,Microsoft-Windows-Sysmon/Operational,WORKSTATION01,powershell.exe -c whoami,C:\\Windows\\System32\\powershell.exe,admin
3,Microsoft-Windows-Sysmon/Operational,WORKSTATION01,,C:\\Windows\\System32\\cmd.exe,admin
11,Microsoft-Windows-Sysmon/Operational,WORKSTATION01,,C:\\Windows\\explorer.exe,admin
"""
    csv_file.write_text(csv_content)
    return str(csv_file)


@pytest.fixture
def tmp_auditd_file(tmp_path):
    """Create a temporary auditd log file."""
    auditd_file = tmp_path / "audit.log"
    auditd_content = """type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e syscall=59 success=yes exit=0 pid=5678 uid=0 comm="bash" exe="/bin/bash"
type=SYSCALL msg=audit(1705318201.456:457): arch=c000003e syscall=59 success=yes exit=0 pid=5679 uid=0 comm="ls" exe="/bin/ls"
"""
    auditd_file.write_text(auditd_content)
    return str(auditd_file)


@pytest.fixture
def tmp_xml_file(tmp_path, sample_xml_event):
    """Create a temporary XML file with sample event."""
    xml_file = tmp_path / "sample_events.xml"
    xml_content = f'''<?xml version="1.0" encoding="utf-8"?>
<Events>
{sample_xml_event}
</Events>'''
    xml_file.write_text(xml_content)
    return str(xml_file)


@pytest.fixture
def tmp_output_dir(tmp_path):
    """Create a temporary output directory."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return str(output_dir)


# =============================================================================
# Template Fixtures
# =============================================================================

@pytest.fixture
def simple_template(tmp_path):
    """Create a simple Jinja2 template for testing."""
    template_file = tmp_path / "simple.tmpl"
    template_content = """{% for elem in data %}
Rule: {{ elem.title }}
Level: {{ elem.rule_level }}
Count: {{ elem.count }}
{% endfor %}
"""
    template_file.write_text(template_content)
    return str(template_file)


@pytest.fixture
def json_template(tmp_path):
    """Create a JSON export template for testing."""
    template_file = tmp_path / "json_export.tmpl"
    template_content = """[{% for elem in data %}
{
    "title": {{ elem.title | tojson }},
    "level": {{ elem.rule_level | tojson }},
    "count": {{ elem.count }}
}{{ "," if not loop.last }}{% endfor %}
]"""
    template_file.write_text(template_content)
    return str(template_file)


@pytest.fixture
def sample_detection_results():
    """Sample detection results for template testing."""
    return [
        {
            "title": "Suspicious PowerShell Command",
            "id": "test-rule-001",
            "description": "Detects suspicious PowerShell commands",
            "sigmafile": "test_rule.yml",
            "sigma": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"],
            "rule_level": "high",
            "tags": ["attack.execution", "attack.t1059.001"],
            "count": 2,
            "matches": [
                {"CommandLine": "powershell.exe -c whoami", "Computer": "WORKSTATION01"},
                {"CommandLine": "powershell.exe -encodedCommand abc", "Computer": "WORKSTATION02"}
            ]
        },
        {
            "title": "CMD Execution",
            "id": "test-rule-002",
            "description": "Detects CMD execution",
            "sigmafile": "test_rule_cmd.yml",
            "sigma": ["SELECT * FROM logs WHERE Image LIKE '%cmd.exe%'"],
            "rule_level": "medium",
            "tags": ["attack.discovery"],
            "count": 1,
            "matches": [
                {"CommandLine": "cmd.exe /c dir", "Computer": "WORKSTATION01"}
            ]
        }
    ]


# =============================================================================
# Args Configuration Fixtures
# =============================================================================

@pytest.fixture
def default_args_config():
    """Default args configuration simulating command line arguments."""
    return Namespace(
        evtx=None,
        select=None,
        avoid=None,
        fileext=None,
        file_pattern=None,
        no_recursion=False,
        after="1970-01-01T00:00:00",
        before="9999-12-12T23:59:59",
        json_input=False,
        json_array_input=False,
        db_input=False,
        sysmon_linux_input=False,
        auditd_input=False,
        xml_input=False,
        evtxtract_input=False,
        csv_input=False,
        logs_encoding=None,
        ruleset=["rules/rules_windows_generic.json"],
        combine_rulesets=False,
        save_ruleset=False,
        pipeline=None,
        pipeline_list=False,
        rulefilter=None,
        outfile="detected_events.json",
        csv=False,
        csv_delimiter=";",
        tmpdir=None,
        keeptmp=False,
        keepflat=False,
        dbfile=None,
        logfile="zircolite.log",
        hashes=False,
        limit=-1,
        config="config/fieldMappings.json",
        fieldlist=False,
        debug=False,
        showall=False,
        nolog=True,
        ondiskdb=":memory:",
        remove_events=False,
        update_rules=False,
        version=False,
        timefield="SystemTime",
        template=None,
        templateOutput=None,
        package=False,
        package_dir=""
    )


@pytest.fixture
def args_config_evtx(default_args_config):
    """Args configuration for EVTX input."""
    default_args_config.evtx_input = True
    return default_args_config


@pytest.fixture
def args_config_json(default_args_config):
    """Args configuration for JSON input."""
    default_args_config.json_input = True
    return default_args_config


@pytest.fixture
def args_config_auditd(default_args_config):
    """Args configuration for Auditd input."""
    default_args_config.auditd_input = True
    return default_args_config


# =============================================================================
# Logger Fixture
# =============================================================================

@pytest.fixture
def test_logger():
    """Create a test logger that doesn't write to file."""
    return init_logger(debug_mode=False, log_file=None)


@pytest.fixture
def debug_logger():
    """Create a debug test logger."""
    return init_logger(debug_mode=True, log_file=None)


# =============================================================================
# Mock Fixtures
# =============================================================================

@pytest.fixture
def mock_psutil():
    """Mock psutil for memory tracking tests."""
    with patch('psutil.Process') as mock:
        mock_process = MagicMock()
        mock_process.memory_info.return_value.rss = 100 * 1024 * 1024  # 100 MB
        mock.return_value = mock_process
        yield mock


@pytest.fixture
def mock_requests():
    """Mock requests for network-related tests."""
    with patch('zircolite.rules.requests') as mock:
        mock_response = MagicMock()
        mock_response.iter_content.return_value = [b'test content']
        mock_response.headers = {'content-length': '100'}
        mock.get.return_value = mock_response
        yield mock


# =============================================================================
# Database Fixtures
# =============================================================================

@pytest.fixture
def in_memory_db():
    """Create an in-memory SQLite database for testing."""
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


@pytest.fixture
def populated_db(in_memory_db):
    """Create an in-memory database with sample data."""
    cursor = in_memory_db.cursor()
    cursor.execute('''
        CREATE TABLE logs (
            row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            EventID TEXT,
            Channel TEXT,
            Computer TEXT,
            CommandLine TEXT,
            Image TEXT,
            User TEXT,
            SystemTime TEXT,
            TargetFileName TEXT
        )
    ''')
    
    # Insert sample data
    sample_data = [
        (1, 'Sysmon', 'WORKSTATION01', 'powershell.exe -c whoami', 'C:\\powershell.exe', 'admin', '2024-01-15T10:30:00', None),
        (1, 'Sysmon', 'WORKSTATION01', 'cmd.exe /c whoami', 'C:\\cmd.exe', 'admin', '2024-01-15T10:31:00', None),
        (11, 'Sysmon', 'WORKSTATION01', None, 'C:\\explorer.exe', 'admin', '2024-01-15T10:32:00', 'C:\\malware.exe'),
        (3, 'Sysmon', 'WORKSTATION02', None, 'C:\\firefox.exe', 'user', '2024-01-15T10:33:00', None),
    ]
    
    cursor.executemany('''
        INSERT INTO logs (EventID, Channel, Computer, CommandLine, Image, User, SystemTime, TargetFileName)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', sample_data)
    
    in_memory_db.commit()
    return in_memory_db


# =============================================================================
# Cleanup Fixtures
# =============================================================================

# Store the original working directory at module load
_ORIGINAL_CWD = os.getcwd()

# Artifact patterns to clean up (files and directories)
_CLEANUP_PATTERNS = [
    # Output files
    'detected_events*.json',
    'detected_events*.csv',
    'flattened_events_*.json',
    'ruleset-*.json',
    # Log files
    'zircolite*.log',
    # Database files
    '*.db',
    # Temporary directories
    'tmp-*',
    # GUI output
    'zircogui-output*',
    # Other artifacts
    'fields.json',
]


def _cleanup_artifacts(directory: Path):
    """Remove artifacts matching patterns from the given directory."""
    for pattern in _CLEANUP_PATTERNS:
        for item in directory.glob(pattern):
            try:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
            except (OSError, PermissionError):
                pass


@pytest.fixture(autouse=True)
def cleanup_test_artifacts():
    """
    Automatically clean up any artifacts created during tests.
    
    This fixture runs before and after each test to ensure a clean state.
    It also restores the working directory if a test changes it.
    """
    # Store the current working directory
    test_start_cwd = os.getcwd()
    
    # Clean artifacts before test (in case previous test left any)
    _cleanup_artifacts(Path(_ORIGINAL_CWD))
    if test_start_cwd != _ORIGINAL_CWD:
        _cleanup_artifacts(Path(test_start_cwd))
    
    yield
    
    # Restore working directory if changed during test
    current_cwd = os.getcwd()
    if current_cwd != test_start_cwd:
        try:
            os.chdir(test_start_cwd)
        except (OSError, FileNotFoundError):
            # If the directory no longer exists, go to original
            try:
                os.chdir(_ORIGINAL_CWD)
            except (OSError, FileNotFoundError):
                pass
    
    # Clean artifacts after test
    _cleanup_artifacts(Path(_ORIGINAL_CWD))
    # Also clean from test start directory if different
    if test_start_cwd != _ORIGINAL_CWD:
        _cleanup_artifacts(Path(test_start_cwd))


@pytest.fixture
def clean_test_outputs():
    """
    Clean up test output files (explicit fixture for tests that need it).
    
    This is kept for backwards compatibility but cleanup_test_artifacts
    now handles this automatically.
    """
    yield
    _cleanup_artifacts(Path('.'))
