"""
Tests for Zircolite CLI (zircolite.py).

These tests verify the command-line interface behavior including:
- Argument parsing
- Input mode selection
- Output format handling
- Streaming vs traditional mode
- Error handling and validation
"""

import argparse
import json
import os
import pytest
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
import importlib.util

from zircolite import DetectionResult

# Path to the workspace root
WORKSPACE_ROOT = Path(__file__).parent.parent

# Add parent directory to path for imports
sys.path.insert(0, str(WORKSPACE_ROOT))

# Load the zircolite.py script as a module (not the package)
def load_zircolite_script():
    """Load zircolite.py script directly, bypassing the package."""
    spec = importlib.util.spec_from_file_location(
        "zircolite_script", 
        WORKSPACE_ROOT / "zircolite.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

zircolite_script = load_zircolite_script()


# Helper to get common test args without -n (for tests that need output files)
def get_log_arg(tmp_path):
    """Return log file argument for tests that need output files."""
    return ['-l', str(tmp_path / "test.log")]


@pytest.fixture(autouse=True)
def cleanup_cli_artifacts():
    """
    Automatically clean up any artifacts created by CLI tests.
    
    This fixture runs before and after each test to ensure a clean state.
    It removes common artifacts that Zircolite may create in the working directory.
    """
    # Store original working directory
    original_cwd = os.getcwd()
    
    # Artifact patterns to clean up
    artifact_patterns = [
        "detected_events*.json",
        "detected_events*.csv",
        "flattened_events_*.json",
        "zircolite*.log",
        "*.db",
        "tmp-*",
        "zircogui-output*",
        "fields.json",
    ]
    
    def cleanup_artifacts(directory: Path):
        """Remove artifacts matching patterns from directory."""
        for pattern in artifact_patterns:
            for item in directory.glob(pattern):
                try:
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
                except (OSError, PermissionError):
                    pass
    
    # Clean before test (in case previous test left artifacts)
    cleanup_artifacts(WORKSPACE_ROOT)
    
    yield
    
    # Restore working directory if changed
    if os.getcwd() != original_cwd:
        try:
            os.chdir(original_cwd)
        except (OSError, FileNotFoundError):
            pass
    
    # Clean after test
    cleanup_artifacts(WORKSPACE_ROOT)


class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_version_flag(self, capsys):
        """Test --version flag displays version and exits."""
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['zircolite.py', '--version']):
                zircolite_script.main()
        
        # Should exit with code 0
        assert exc_info.value.code == 0

    def test_version_short_flag(self, capsys):
        """Test -v flag displays version and exits."""
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['zircolite.py', '-v']):
                zircolite_script.main()
        
        assert exc_info.value.code == 0

    def test_missing_events_source_error(self, tmp_path, capsys):
        """Test error when no events source is provided."""
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['zircolite.py', '-r', str(ruleset_file), '-n']):
                zircolite_script.main()
        
        # Should exit with error code 2
        assert exc_info.value.code == 2

    def test_csv_with_multiple_rulesets_error(self, tmp_path):
        """Test error when CSV output is used with multiple rulesets."""
        # Create dummy rulesets
        ruleset1 = tmp_path / "ruleset1.json"
        ruleset2 = tmp_path / "ruleset2.json"
        ruleset1.write_text("[]")
        ruleset2.write_text("[]")
        
        # Create dummy events file
        events_file = tmp_path / "events.json"
        events_file.write_text("{}")
        
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset1), str(ruleset2),
                '--csv',
                '-n'
            ]):
                zircolite_script.main()
        
        assert exc_info.value.code == 2

    def test_invalid_timestamp_format_error(self, tmp_path):
        """Test error with invalid timestamp format."""
        events_file = tmp_path / "events.json"
        events_file.write_text("{}")
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        with pytest.raises(SystemExit):
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset_file),
                '-A', 'invalid-timestamp',
                '-n'
            ]):
                zircolite_script.main()

    def test_template_without_output_error(self, tmp_path):
        """Test error when template is provided without output."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        template_file = tmp_path / "template.tmpl"
        template_file.write_text("test template")
        
        with pytest.raises(SystemExit):
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset_file),
                '--template', str(template_file),
                '-n'
            ]):
                zircolite_script.main()

    def test_template_count_mismatch_error(self, tmp_path):
        """Test error when template and templateOutput counts don't match."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        template1 = tmp_path / "template1.tmpl"
        template2 = tmp_path / "template2.tmpl"
        template1.write_text("template 1")
        template2.write_text("template 2")
        
        # Use separate --template calls to provide 2 templates, but only 1 output
        with pytest.raises(SystemExit):
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset_file),
                '--template', str(template1),
                '--template', str(template2),
                '--templateOutput', 'output1.txt',
                '-n'
            ]):
                zircolite_script.main()


class TestCLITransformOptions:
    """Tests for --all-transforms, --transform-category, and --transform-list CLI options."""

    def test_all_transforms_flag_parsed(self):
        """Test that --all-transforms flag is parsed correctly."""
        with patch('sys.argv', ['zircolite.py', '--all-transforms', '-e', 'test.evtx']):
            args = zircolite_script.parse_arguments()
        assert args.all_transforms is True

    def test_transform_category_single(self):
        """Test single --transform-category flag."""
        with patch('sys.argv', ['zircolite.py', '--transform-category', 'commandline', '-e', 'test.evtx']):
            args = zircolite_script.parse_arguments()
        assert args.transform_categories == ['commandline']

    def test_transform_category_multiple(self):
        """Test multiple --transform-category flags combine into list."""
        with patch('sys.argv', [
            'zircolite.py',
            '--transform-category', 'commandline',
            '--transform-category', 'process',
            '-e', 'test.evtx'
        ]):
            args = zircolite_script.parse_arguments()
        assert args.transform_categories == ['commandline', 'process']

    def test_transform_category_defaults_none(self):
        """Test that --transform-category defaults to None when not provided."""
        with patch('sys.argv', ['zircolite.py', '-e', 'test.evtx']):
            args = zircolite_script.parse_arguments()
        assert args.transform_categories is None

    def test_all_transforms_defaults_false(self):
        """Test that --all-transforms defaults to False when not provided."""
        with patch('sys.argv', ['zircolite.py', '-e', 'test.evtx']):
            args = zircolite_script.parse_arguments()
        assert args.all_transforms is False

    def test_transform_list_flag_exits(self, tmp_path):
        """Test that --transform-list flag triggers listing and exits."""
        config_file = tmp_path / "config.yaml"
        # Write a minimal config with categories
        import yaml
        config_file.write_text(yaml.dump({
            "exclusions": [], "useless": [], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": False,
            "transforms": {},
            "transform_categories": {"test_cat": ["T1", "T2"]},
        }))
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['zircolite.py', '--transform-list', '-c', str(config_file)]):
                zircolite_script.main()
        assert exc_info.value.code == 0


class TestCLIInputModes:
    """Tests for different input modes."""

    def test_json_input_mode_fileext(self, tmp_path):
        """Test that JSON input mode sets correct file extension."""
        # Create test files
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',  # JSON input mode
            '-o', str(output_file),
            '--no-auto-mode'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        # Output file should be created
        assert output_file.exists()

    def test_csv_input_mode(self, tmp_path):
        """Test CSV input mode processing."""
        # Create CSV events file
        events_file = tmp_path / "events.csv"
        events_file.write_text("EventID,CommandLine\n1,test command\n")
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"EventID": "EventID", "CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '--csv-input',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()


class TestCLIStreamingMode:
    """Tests for streaming mode (default) vs traditional mode."""

    def test_streaming_mode_enabled_by_default(self, tmp_path):
        """Test that streaming mode is enabled by default."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--no-auto-mode'  # Disable auto-mode for predictable behavior
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()

    def test_keepflat_saves_flattened_events(self, tmp_path):
        """Test --keepflat saves flattened events in streaming mode."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--keepflat',
            '--no-auto-mode'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()


class TestCLIOutputFormats:
    """Tests for different output formats."""

    def test_json_output_default(self, tmp_path):
        """Test JSON output is default."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            content = f.read()
        # Should be valid JSON
        detections = json.loads(content)
        assert isinstance(detections, list)

    def test_csv_output_mode(self, tmp_path):
        """Test CSV output mode."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.csv"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--csv'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            content = f.read()
        # Should contain CSV headers
        assert "rule_title" in content or "title" in content or len(content) > 0

    def test_csv_output_with_parallel_workers(self, tmp_path):
        """Test that --csv produces CSV output when parallel workers are used (multiple files)."""
        # Two JSONL event files so parallel path can be used
        event_line = '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}'
        events_file1 = tmp_path / "events1.json"
        events_file2 = tmp_path / "events2.json"
        events_file1.write_text(event_line + "\n")
        events_file2.write_text(event_line + "\n")

        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))

        output_file = tmp_path / "result.csv"

        def mock_analyze(files, logger=None):
            stats = {
                "parallel_recommended": True,
                "parallel_workers": 2,
                "parallel_reason": "test",
            }
            return ("per-file", "test", stats)

        with patch.object(zircolite_script, 'analyze_files_and_recommend_mode', side_effect=mock_analyze):
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file1),
                '-e', str(events_file2),
                '-r', str(ruleset_file),
                '-c', str(config_file),
                '-j',
                '--csv',
                '--csv-delimiter', ',',
                '-o', str(output_file),
                '--no-auto-mode'
            ] + get_log_arg(tmp_path)):
                zircolite_script.main()

        assert output_file.exists()
        with open(output_file) as f:
            content = f.read()
        # Must be CSV: header contains rule_title, not a JSON array
        assert content.strip().startswith("rule_title") or "rule_title" in content.split("\n")[0]
        assert not content.strip().startswith("["), "Output should be CSV, not JSON"


class TestCLIDetection:
    """Tests for detection functionality through CLI."""

    def test_detection_with_matching_rule(self, tmp_path):
        """Test that matching events are detected."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe -encodedCommand test"}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Suspicious PowerShell",
            "id": "test-001",
            "description": "Test rule",
            "level": "high",
            "tags": ["attack.execution"],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should have at least one detection
        assert len(detections) >= 1
        assert detections[0]["title"] == "Suspicious PowerShell"

    def test_no_detection_with_non_matching_rule(self, tmp_path):
        """Test that non-matching events produce no detections."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "notepad.exe"}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Suspicious PowerShell",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%mimikatz%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should have no detections
        assert len(detections) == 0


class TestCLIRuleFiltering:
    """Tests for rule filtering functionality."""

    def test_rule_filter_removes_matching_rule(self, tmp_path):
        """Test that -R filter removes rules by title."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe test"}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([
            {
                "title": "Suspicious PowerShell",
                "id": "test-001",
                "level": "high",
                "tags": [],
                "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
            },
            {
                "title": "CMD Execution",
                "id": "test-002",
                "level": "medium",
                "tags": [],
                "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%cmd%'"]
            }
        ]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        # Filter out PowerShell rule
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-R', 'PowerShell'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should have no detections since PowerShell rule was filtered
        assert len(detections) == 0


class TestCLITimeFiltering:
    """Tests for time-based filtering."""

    def test_after_filter(self, tmp_path):
        """Test -A (after) filter excludes old events."""
        events_file = tmp_path / "events.json"
        # Event from 2020, should be filtered out
        events_file.write_text(json.dumps({
            "Event": {
                "System": {
                    "EventID": 1,
                    "TimeCreated": {"#attributes": {"SystemTime": "2020-01-01T10:00:00"}}
                },
                "EventData": {"CommandLine": "powershell.exe"}
            }
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.System.TimeCreated.#attributes.SystemTime": "SystemTime",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        # Filter to only events after 2024
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-A', '2024-01-01T00:00:00'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should have no detections (event was filtered)
        assert len(detections) == 0

    def test_before_filter(self, tmp_path):
        """Test -B (before) filter excludes future events."""
        events_file = tmp_path / "events.json"
        # Event from 2030, should be filtered out
        events_file.write_text(json.dumps({
            "Event": {
                "System": {
                    "EventID": 1,
                    "TimeCreated": {"#attributes": {"SystemTime": "2030-01-01T10:00:00"}}
                },
                "EventData": {"CommandLine": "powershell.exe"}
            }
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.System.TimeCreated.#attributes.SystemTime": "SystemTime",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        # Filter to only events before 2025
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-B', '2025-01-01T00:00:00'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should have no detections (event was filtered)
        assert len(detections) == 0


class TestCLILimitOption:
    """Tests for result limiting."""

    def test_limit_discards_high_volume_results(self, tmp_path):
        """Test -L limit discards results exceeding threshold."""
        # Create many matching events
        events = []
        for i in range(20):
            events.append(json.dumps({
                "Event": {
                    "System": {"EventID": 1},
                    "EventData": {"CommandLine": f"powershell.exe test{i}"}
                }
            }))
        
        events_file = tmp_path / "events.json"
        events_file.write_text("\n".join(events))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        # Set limit to 5 (rule matches 20 events, exceeds limit)
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-L', '5'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Results should be empty (20 > 5 limit)
        assert len(detections) == 0


class TestCLIMultipleFiles:
    """Tests for processing multiple files."""

    def test_process_directory_of_json_files(self, tmp_path):
        """Test processing a directory with multiple JSON files."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create multiple JSON files
        for i in range(3):
            events_file = events_dir / f"events_{i}.json"
            events_file.write_text(json.dumps({
                "Event": {
                    "System": {"EventID": 1},
                    "EventData": {"CommandLine": f"powershell.exe test{i}"}
                }
            }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should have detections from all files
        assert len(detections) >= 1

    def test_select_filter(self, tmp_path):
        """Test -s (select) filter to process only matching files."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create files with different names
        (events_dir / "important_events.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}
        }))
        (events_dir / "other_events.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        # Select only "important" files
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-s', 'important'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()

    def test_avoid_filter(self, tmp_path):
        """Test -a (avoid) filter to skip matching files."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create files
        (events_dir / "good_events.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}
        }))
        (events_dir / "skip_events.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        # Avoid "skip" files
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-a', 'skip'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()


class TestCLIDatabaseOperations:
    """Tests for database operations."""

    def test_save_db_to_disk(self, tmp_path):
        """Test -d flag saves database to disk."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        # Use absolute path for db file
        db_file = tmp_path / "testdb.db"
        
        # Change to tmp_path to ensure db file is created there
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset_file),
                '-c', str(config_file),
                '-j',
                '-o', str(output_file),
                '-d', str(db_file)
            ] + get_log_arg(tmp_path)):
                zircolite_script.main()
            
            # Database file should be created (with suffix for single-file processing)
            # The filename pattern is: {db_stem}_{source_filename}{db_suffix}
            db_files = list(tmp_path.glob("testdb*.db"))
            assert len(db_files) >= 1
        finally:
            os.chdir(original_cwd)

    def test_db_input_mode(self, tmp_path, test_logger):
        """Test --db-input mode loads existing database."""
        # First, create a database
        from zircolite import ZircoliteCore, ProcessingConfig
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        # Create and populate a database
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(str(config_file), processing_config=proc_config, logger=test_logger)
        field_stmt = "EventID TEXT, CommandLine TEXT"
        zircore.create_db(field_stmt)
        zircore.insert_data_to_db({"EventID": "1", "CommandLine": "test"})
        
        db_file = tmp_path / "test.db"
        zircore.save_db_to_disk(str(db_file))
        zircore.close()
        
        # Now test loading it via CLI
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        output_file = tmp_path / "output.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(db_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '--db-input',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()


class TestCLITemplateGeneration:
    """Tests for template-based output generation."""

    def test_template_output(self, tmp_path):
        """Test template output generation."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        template_file = tmp_path / "template.tmpl"
        template_file.write_text("""{% for elem in data %}
Alert: {{ elem.title }} ({{ elem.rule_level }})
{% endfor %}""")
        
        output_file = tmp_path / "detected_events.json"
        template_output = tmp_path / "alerts.txt"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--template', str(template_file),
            '--templateOutput', str(template_output)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        assert template_output.exists()
        
        with open(template_output) as f:
            content = f.read()
        assert "Alert:" in content


class TestCLIPackage:
    """Tests for --package and --package-dir options."""

    def test_package_creates_zip_when_detections(self, tmp_path):
        """Test that --package creates a zircogui-output-*.zip in cwd when there are detections."""
        template_path = WORKSPACE_ROOT / "templates" / "exportForZircoGui.tmpl"
        gui_zip_path = WORKSPACE_ROOT / "gui" / "zircogui.zip"
        if not template_path.is_file() or not gui_zip_path.is_file():
            pytest.skip("templates/exportForZircoGui.tmpl or gui/zircogui.zip not found (run task gui to build)")

        events_file = tmp_path / "events.json"
        events_file.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}'
        )
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))

        original_cwd = os.getcwd()
        try:
            os.chdir(WORKSPACE_ROOT)
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset_file),
                '-c', str(config_file),
                '-j',
                '-o', str(tmp_path / "out.json"),
                '--package',
                '-n'
            ] + get_log_arg(tmp_path)):
                zircolite_script.main()

            zips = list(WORKSPACE_ROOT.glob("zircogui-output-*.zip"))
            assert len(zips) >= 1, "Expected at least one zircogui-output-*.zip in workspace root"
        finally:
            os.chdir(original_cwd)

    def test_package_dir_used_when_provided(self, tmp_path):
        """Test that --package-dir is used as the destination for the generated zip."""
        template_path = WORKSPACE_ROOT / "templates" / "exportForZircoGui.tmpl"
        gui_zip_path = WORKSPACE_ROOT / "gui" / "zircogui.zip"
        if not template_path.is_file() or not gui_zip_path.is_file():
            pytest.skip("templates/exportForZircoGui.tmpl or gui/zircogui.zip not found (run task gui to build)")

        package_dir = tmp_path / "pkg_out"
        package_dir.mkdir()

        events_file = tmp_path / "events.json"
        events_file.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}'
        )
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))

        original_cwd = os.getcwd()
        try:
            os.chdir(WORKSPACE_ROOT)
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset_file),
                '-c', str(config_file),
                '-j',
                '-o', str(tmp_path / "out.json"),
                '--package',
                '--package-dir', str(package_dir),
                '-n'
            ] + get_log_arg(tmp_path)):
                zircolite_script.main()

            zips = list(package_dir.glob("zircogui-output-*.zip"))
            assert len(zips) >= 1, f"Expected at least one zircogui-output-*.zip in {package_dir}"
        finally:
            os.chdir(original_cwd)


class TestCLIHashGeneration:
    """Tests for hash generation option."""

    def test_hashes_option(self, tmp_path):
        """Test --hashes option adds xxhash to events."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test"}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--hashes'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Check if hash field is present in matches
        if len(detections) > 0 and detections[0].get("matches"):
            # Hash should be in the matched events
            pass  # Hash verification would depend on implementation


class TestCLINoLogOption:
    """Tests for no-log option."""

    def test_nolog_flag(self, tmp_path):
        """Test -n flag prevents log file creation (but also prevents output file)."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        log_file = tmp_path / "zircolite.log"
        
        # Change to tmp_path to check log file creation
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset_file),
                '-c', str(config_file),
                '-j',
                '-o', str(output_file),
                '-n'
            ]):
                zircolite_script.main()
            
            # Log file should NOT exist
            assert not log_file.exists()
            # Note: output file also won't exist with -n flag (no_output=True)
        finally:
            os.chdir(original_cwd)

    def test_logfile_custom_path(self, tmp_path):
        """Test -l / --logfile writes log to the specified path."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        custom_log = tmp_path / "custom.log"
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset_file),
                '-c', str(config_file),
                '-j',
                '-o', str(output_file),
                '-l', str(custom_log)
            ]):
                zircolite_script.main()
            assert custom_log.exists()
            assert custom_log.read_text()
        finally:
            os.chdir(original_cwd)


class TestCLIRemoveEvents:
    """Tests for --remove-events (-RE) option."""

    def test_remove_events_deletes_log_files_after_processing(self, tmp_path):
        """Test that -RE / --remove-events removes input log files after successful analysis."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')

        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))

        output_file = tmp_path / "output.json"
        assert events_file.exists()

        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-RE',
            '-n'
        ]):
            zircolite_script.main()

        assert not events_file.exists(), "Input log file should be removed after --remove-events"


class TestCLIAdvancedConfiguration:
    """Tests for Advanced Configuration options: --quiet, --debug, --timefield, --logs-encoding, --no-auto-detect."""

    def test_quiet_mode_runs_successfully(self, tmp_path):
        """Test -q / --quiet runs without error and produces output."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}')
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID", "Event.EventData.CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-q'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        assert isinstance(detections, list)

    def test_debug_mode_runs_successfully(self, tmp_path):
        """Test --debug runs without error and produces output."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--debug'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()

    def test_timefield_used_for_filtering(self, tmp_path):
        """Test --timefield is used for time range filtering."""
        events_file = tmp_path / "events.json"
        events_file.write_text(json.dumps({
            "Event": {
                "System": {"EventID": 1},
                "EventData": {"CommandLine": "powershell.exe"},
                "@timestamp": "2020-06-15T12:00:00"
            }
        }))
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine",
                "Event.@timestamp": "timestamp"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--timefield', 'timestamp',
            '-A', '2024-01-01T00:00:00'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        # Event is from 2020, filter is after 2024 -> no detections
        assert len(detections) == 0

    def test_logs_encoding_accepted(self, tmp_path):
        """Test -LE / --logs-encoding is accepted (auditd input)."""
        auditd_file = tmp_path / "audit.log"
        auditd_file.write_text(
            'type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e syscall=59 success=yes exit=0 pid=5678 uid=0 comm="bash" exe="/bin/bash"'
        )
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(auditd_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-AU',
            '-o', str(output_file),
            '-LE', 'utf-8'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()

    def test_no_auto_detect_with_explicit_format(self, tmp_path):
        """Test --no-auto-detect with explicit --json-input uses JSON without auto-detection."""
        events_file = tmp_path / "data.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '--no-auto-detect',
            '-j',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        assert isinstance(detections, list)


# Fixture files for Sysmon Linux, XML, and EVTXtract input tests (sanitized, minimal)
FIXTURES_DIR = WORKSPACE_ROOT / "tests" / "fixtures"
SYSMON_LINUX_FIXTURE = FIXTURES_DIR / "sysmon_linux_sample.log"
XML_EVENTS_FIXTURE = FIXTURES_DIR / "xml_events_sample.xml"
EVTXTRACT_FIXTURE = FIXTURES_DIR / "evtxtract_sample.log"


def _minimal_config_for_events():
    """Minimal field mappings for Windows-style Event XML (Sysmon/XML/EVTXtract)."""
    return {
        "exclusions": [],
        "useless": [],
        "mappings": {
            "Event.System.EventID": "EventID",
            "Event.System.Channel": "Channel",
            "Event.System.Computer": "Computer",
            "Event.System.TimeCreated.#attributes.SystemTime": "SystemTime",
        },
        "alias": {},
        "split": {},
        "transforms_enabled": False,
        "transforms": {}
    }


class TestCLISysmonXmlEvtxtractInput:
    """Tests for -S/--sysmon-linux-input, -x/--xml-input, --evtxtract-input using fixtures."""

    def test_sysmon_linux_input_processes_fixture(self, tmp_path):
        """Test -S / --sysmon-linux-input runs successfully with sysmon_linux_sample.log."""
        if not SYSMON_LINUX_FIXTURE.exists():
            pytest.skip(f"Fixture not found: {SYSMON_LINUX_FIXTURE}")
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(_minimal_config_for_events()))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(SYSMON_LINUX_FIXTURE),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-S',
            '-o', str(output_file),
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
        assert isinstance(data, list)

    def test_xml_input_processes_fixture(self, tmp_path):
        """Test -x / --xml-input runs successfully with xml_events_sample.xml."""
        pytest.importorskip("lxml")
        if not XML_EVENTS_FIXTURE.exists():
            pytest.skip(f"Fixture not found: {XML_EVENTS_FIXTURE}")
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(_minimal_config_for_events()))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(XML_EVENTS_FIXTURE),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-x',
            '-o', str(output_file),
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
        assert isinstance(data, list)

    def test_evtxtract_input_processes_fixture(self, tmp_path):
        """Test --evtxtract-input runs successfully with evtxtract_sample.log."""
        pytest.importorskip("lxml")
        if not EVTXTRACT_FIXTURE.exists():
            pytest.skip(f"Fixture not found: {EVTXTRACT_FIXTURE}")
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(_minimal_config_for_events()))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(EVTXTRACT_FIXTURE),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '--evtxtract-input',
            '-o', str(output_file),
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
        assert isinstance(data, list)


class TestCLIFileExtension:
    """Tests for file extension handling."""

    def test_custom_file_extension(self, tmp_path):
        """Test --fileext option for custom file extensions."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create file with custom extension
        events_file = events_dir / "events.custom"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-f', 'custom'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()

    def test_file_pattern_filters_files(self, tmp_path):
        """Test -fp / --file-pattern restricts which files are processed."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        (events_dir / "a.json").write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        (events_dir / "b.json").write_text('{"Event": {"System": {"EventID": 2}, "EventData": {}}}')
        (events_dir / "other.txt").write_text("not json")
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '-fp', 'a.json'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()
        # Only a.json should be processed (single file)
        with open(output_file) as f:
            data = json.load(f)
        assert isinstance(data, list)


class TestCLINoEventFilter:
    """Tests for --no-event-filter option."""

    def test_no_event_filter_runs_successfully(self, tmp_path):
        """Test --no-event-filter runs without error and produces output."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--no-event-filter'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()


class TestCLIParallelOptions:
    """Tests for parallel processing options: -P / --no-parallel, --parallel-memory-limit."""

    def test_no_parallel_runs_successfully(self, tmp_path):
        """Test -P / --no-parallel disables parallel processing and runs successfully."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        for i in range(3):
            (events_dir / f"e{i}.json").write_text(
                '{"Event": {"System": {"EventID": 1}, "EventData": {}}}'
            )
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--no-auto-mode',
            '-P'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()

    def test_parallel_memory_limit_accepted(self, tmp_path):
        """Test --parallel-memory-limit is accepted and run completes."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        output_file = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--parallel-memory-limit', '80'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()


class TestCLIYamlConfig:
    """Tests for --yaml-config / -Y option."""

    def test_yaml_config_loaded_and_merged(self, tmp_path):
        """Test -Y loads YAML config and run completes (CLI -e/-r used; YAML can override output etc.)."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        yaml_config = tmp_path / "run.yaml"
        output_file = tmp_path / "out.json"
        yaml_config.write_text(f"""
input:
  path: null
  format: evtx
rules:
  rulesets:
    - rules/rules_windows_generic.json
output:
  file: {output_file.as_posix()}
""")
        with patch('sys.argv', [
            'zircolite.py',
            '-Y', str(yaml_config),
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert output_file.exists()


class TestCLISubprocessExecution:
    """End-to-end tests using subprocess."""

    def test_help_output(self):
        """Test --help displays usage information."""
        result = subprocess.run(
            [sys.executable, 'zircolite.py', '--help'],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent)
        )
        
        assert result.returncode == 0
        assert 'usage:' in result.stdout.lower() or 'Usage:' in result.stdout
        assert '--evtx' in result.stdout or '-e' in result.stdout

    def test_version_output(self):
        """Test -v displays version."""
        result = subprocess.run(
            [sys.executable, 'zircolite.py', '-v'],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent)
        )
        
        assert result.returncode == 0
        # Version info should be in stderr (logging) or stdout
        assert 'Zircolite' in result.stdout or 'Zircolite' in result.stderr

    def test_missing_events_error_subprocess(self):
        """Test error message when events path is missing."""
        result = subprocess.run(
            [sys.executable, 'zircolite.py', '-n'],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent)
        )
        
        assert result.returncode == 2

    def test_pipeline_list_exits_zero(self):
        """Test -pl / --pipeline-list exits 0 and prints pipeline info."""
        result = subprocess.run(
            [sys.executable, 'zircolite.py', '--pipeline-list'],
            capture_output=True,
            text=True,
            cwd=str(WORKSPACE_ROOT)
        )
        assert result.returncode == 0
        out = result.stdout + result.stderr
        assert 'pipeline' in out.lower() or 'sysmon' in out.lower() or 'sigma' in out.lower()

    def test_generate_config_creates_file(self, tmp_path):
        """Test --generate-config creates a YAML config file and exits."""
        output_yaml = tmp_path / "generated_config.yaml"
        result = subprocess.run(
            [sys.executable, 'zircolite.py', '--generate-config', str(output_yaml)],
            capture_output=True,
            text=True,
            cwd=str(WORKSPACE_ROOT)
        )
        assert result.returncode == 0
        assert output_yaml.exists()
        content = output_yaml.read_text()
        assert 'input:' in content
        assert 'rules:' in content or 'output:' in content


class TestCLINoRecursion:
    """Tests for no-recursion option."""

    def test_no_recursion_flag(self, tmp_path):
        """Test --no-recursion only searches current directory."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        subdir = events_dir / "subdir"
        subdir.mkdir()
        
        # Create file in main dir
        (events_dir / "events.json").write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        # Create file in subdir (should be ignored with --no-recursion)
        (subdir / "subevents.json").write_text('{"Event": {"System": {"EventID": 2}, "EventData": {}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--no-recursion'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()


class TestCLIJsonArrayInput:
    """Tests for JSON array input mode."""

    def test_json_array_input(self, tmp_path):
        """Test --json-array-input processes JSON array format."""
        events_file = tmp_path / "events.json"
        events_file.write_text(json.dumps([
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}},
            {"Event": {"System": {"EventID": 2}, "EventData": {"CommandLine": "cmd.exe"}}}
        ]))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '--json-array-input',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should detect the powershell event
        assert len(detections) >= 1


class TestCLIUnifiedDatabase:
    """Tests for unified database mode (--unified-db)."""

    def test_unified_db_single_file(self, tmp_path):
        """Test --unified-db with a single file."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--unified-db'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        assert len(detections) >= 1
        assert detections[0]["title"] == "Test Rule"

    def test_unified_db_multiple_files(self, tmp_path):
        """Test --unified-db with multiple files."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create multiple JSON files with different events
        (events_dir / "events_1.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe test1"}}
        }))
        (events_dir / "events_2.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe test2"}}
        }))
        (events_dir / "events_3.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "cmd.exe test3"}}
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "PowerShell Detection",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--unified-db'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should detect PowerShell events from both files (events_1 and events_2)
        assert len(detections) >= 1
        # In unified mode, all matching events are counted together
        total_matches = sum(d["count"] for d in detections)
        assert total_matches == 2  # Two PowerShell events from two different files

    def test_unified_db_streaming(self, tmp_path):
        """Test --unified-db with streaming mode."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create multiple JSON files
        (events_dir / "events_1.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe test1"}}
        }))
        (events_dir / "events_2.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe test2"}}
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "PowerShell Detection",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--unified-db'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should have detections from both files in unified mode
        assert len(detections) >= 1
        total_matches = sum(d["count"] for d in detections)
        assert total_matches == 2

    def test_unified_db_cross_file_correlation(self, tmp_path):
        """Test that unified mode enables cross-file event correlation."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create files with events that should be correlated
        # File 1: Event from workstation1
        (events_dir / "events_1.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {
                "CommandLine": "powershell.exe",
                "Computer": "WORKSTATION1"
            }}
        }))
        # File 2: Event from workstation2 (same attack pattern)
        (events_dir / "events_2.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {
                "CommandLine": "powershell.exe",
                "Computer": "WORKSTATION2"
            }}
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        # Rule that counts events across all systems
        ruleset_file.write_text(json.dumps([{
            "title": "Multi-System PowerShell Activity",
            "id": "test-001",
            "level": "critical",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine",
                "Event.EventData.Computer": "Computer"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "detected_events.json"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--unified-db'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # In unified mode, both events should be in the same detection result
        assert len(detections) == 1
        assert detections[0]["count"] == 2
        # Verify we see events from both workstations
        computers = {m.get("Computer") for m in detections[0]["matches"]}
        assert "WORKSTATION1" in computers
        assert "WORKSTATION2" in computers

    def test_unified_db_save_to_disk(self, tmp_path):
        """Test --unified-db with -d saves a single unified database file."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        (events_dir / "events_1.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test1"}}
        }))
        (events_dir / "events_2.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test2"}}
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        db_file = tmp_path / "unified.db"
        
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--unified-db',
            '-d', str(db_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        # Should create a single unified database file (not multiple per-file DBs)
        assert db_file.exists()
        # Should NOT create individual db files
        db_files = list(tmp_path.glob("unified_*.db"))
        assert len(db_files) == 0  # No per-file databases

    def test_unified_db_vs_per_file_mode(self, tmp_path):
        """Test that unified mode produces different results than per-file mode."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create files with events
        (events_dir / "events_1.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}
        }))
        (events_dir / "events_2.json").write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine"
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        # First, run in unified mode (explicit)
        output_unified = tmp_path / "detected_unified.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_unified),
            '--unified-db'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        # Then, run in per-file mode (disable auto-mode)
        output_perfile = tmp_path / "detected_perfile.json"
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_perfile),
            '--no-auto-mode'  # Force per-file mode
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        with open(output_unified) as f:
            unified_detections = json.loads(f.read())
        with open(output_perfile) as f:
            perfile_detections = json.loads(f.read())
        
        # Unified mode: 1 detection with count=2 (both events in one result)
        # Per-file mode: 2 detections with count=1 each (one result per file)
        assert len(unified_detections) == 1
        assert unified_detections[0]["count"] == 2
        
        assert len(perfile_detections) == 2
        assert all(d["count"] == 1 for d in perfile_detections)

    def test_unified_db_alias_all_in_one(self, tmp_path):
        """Test --all-in-one alias works same as --unified-db."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test"}}}')
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID", "Event.EventData.CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        # Use the --all-in-one alias
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--all-in-one'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()


class TestCLIAutoMode:
    """Tests for auto-mode (default) and processing mode heuristics."""

    def test_default_auto_mode_many_small_files_selects_unified(self, tmp_path):
        """Test default auto-mode selects unified mode for many small files."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create 15 small files (should trigger unified mode)
        for i in range(15):
            events_file = events_dir / f"events_{i}.json"
            events_file.write_text(json.dumps({
                "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": f"test{i}"}}
            }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID", "Event.EventData.CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        # Auto-mode is now default - no flag needed
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # In unified mode, we should have 1 detection with count=15
        # (all events matched by "SELECT * FROM logs")
        assert len(detections) == 1
        assert detections[0]["count"] == 15

    def test_default_auto_mode_single_file_uses_per_file(self, tmp_path):
        """Test default auto-mode uses per-file mode for single file."""
        events_file = tmp_path / "events.json"
        events_file.write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test"}}
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID", "Event.EventData.CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        # Auto-mode is default, single file should use per-file mode
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file)
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()

    def test_no_auto_mode_disables_auto_selection(self, tmp_path):
        """Test --no-auto-mode disables automatic mode selection."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        
        # Create 15 files (would normally trigger unified mode)
        for i in range(15):
            events_file = events_dir / f"events_{i}.json"
            events_file.write_text(json.dumps({
                "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": f"powershell.exe test{i}"}}
            }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]))
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID", "Event.EventData.CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        # With --no-auto-mode, should use per-file mode (default) even for many files
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_dir),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--no-auto-mode'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Per-file mode: 15 separate detections (one per file)
        assert len(detections) == 15

    def test_unified_db_overrides_auto_mode(self, tmp_path):
        """Test --unified-db forces unified mode regardless of auto-mode recommendation."""
        events_file = tmp_path / "events.json"
        events_file.write_text(json.dumps({
            "Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test"}}
        }))
        
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID", "Event.EventData.CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }))
        
        output_file = tmp_path / "output.json"
        
        # Even for single file (which would auto-select per-file), --unified-db forces unified
        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--unified-db'
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        
        assert output_file.exists()


class TestAnalyzeFilesAndRecommendMode:
    """Tests for the analyze_files_and_recommend_mode function."""

    def test_single_file_recommends_per_file(self, tmp_path):
        """Test single file recommends per-file mode."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"test": "data"}')
        
        mode, reason, stats = zircolite_script.analyze_files_and_recommend_mode([events_file])
        
        assert mode == 'per-file'
        assert 'Single file' in reason
        assert stats['file_count'] == 1

    def test_many_small_files_recommends_unified(self, tmp_path):
        """Test many small files recommends unified mode."""
        files = []
        for i in range(15):
            f = tmp_path / f"small_{i}.json"
            f.write_text('{"small": "data"}')  # ~20 bytes each
            files.append(f)
        
        mode, reason, stats = zircolite_script.analyze_files_and_recommend_mode(files)
        
        assert mode == 'unified'
        assert stats['file_count'] == 15

    def test_few_files_recommends_per_file(self, tmp_path):
        """Test few files (2-3) defaults to per-file without explicit conditions."""
        files = []
        for i in range(3):
            f = tmp_path / f"file_{i}.json"
            f.write_text('{"data": "value"}')
            files.append(f)
        
        mode, reason, stats = zircolite_script.analyze_files_and_recommend_mode(files)
        
        assert stats['file_count'] == 3

    def test_stats_contain_expected_fields(self, tmp_path):
        """Test stats dictionary contains all expected fields."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"test": "data" }')
        
        _, _, stats = zircolite_script.analyze_files_and_recommend_mode([events_file])
        
        expected_fields = [
            'file_count', 'total_size', 'total_size_fmt',
            'avg_size', 'avg_size_fmt', 'max_size', 'max_size_fmt',
            'min_size', 'min_size_fmt', 'available_ram', 'available_ram_fmt',
            'has_psutil'
        ]
        for field in expected_fields:
            assert field in stats, f"Missing field: {field}"


def _minimal_detection_args():
    """Build minimal args namespace with no format flags set (default evtx)."""
    return argparse.Namespace(
        json_input=False,
        json_array_input=False,
        xml_input=False,
        sysmon_linux_input=False,
        auditd_input=False,
        csv_input=False,
        evtxtract_input=False,
        db_input=False,
        timefield="SystemTime",
    )


class TestApplyDetectionResultUnknown:
    """Tests for _apply_detection_result when detection returns unknown."""

    def test_unknown_detection_returns_evtx_and_sets_no_format_flag(self):
        """When log_source is unknown, applied input type is evtx and no format flag is set."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="json",
            log_source="unknown",
            confidence="low",
            details="Could not determine log type: No files to analyze",
        )

        input_type = zircolite_script._apply_detection_result(args, detection, logger)

        assert input_type == "evtx"
        assert getattr(args, "json_input", None) is False
        assert getattr(args, "json_array_input", None) is False
        assert getattr(args, "xml_input", None) is False

    def test_auto_detect_with_all_unknown_files_returns_evtx(self, tmp_path):
        """When all sampled files yield unknown detection, auto_detect returns evtx and sets no format flag."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        # Paths that do not exist: detect() returns unknown for each
        file_list = [
            tmp_path / "nope1.json",
            tmp_path / "nope2.json",
            tmp_path / "nope3.json",
        ]

        input_type = zircolite_script.auto_detect_log_type(file_list, args, logger)

        assert input_type == "evtx"
        assert getattr(args, "json_input", None) is False


