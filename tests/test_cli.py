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

    def test_add_index_parsed(self):
        """Test that --add-index accepts one or more column names."""
        with patch('sys.argv', ['zircolite.py', '--add-index', 'Channel', 'SystemTime', '-e', 'test.evtx']):
            args = zircolite_script.parse_arguments()
        assert args.add_index == [['Channel', 'SystemTime']]

    def test_remove_index_parsed(self):
        """Test that --remove-index accepts one or more index names."""
        with patch('sys.argv', ['zircolite.py', '--remove-index', 'idx_channel', '-e', 'test.evtx']):
            args = zircolite_script.parse_arguments()
        assert args.remove_index == [['idx_channel']]

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

    def test_keepflat_saves_flattened_events(self, tmp_path, monkeypatch):
        """--keepflat must write the flattened events, not just the detections.

        The flat file lands in the working directory under a random name, so
        the test has to run there and go looking for it; asserting on the
        detection output instead never touched the feature.
        """
        monkeypatch.chdir(tmp_path)
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

        flat_files = list(tmp_path.glob("flattened_events_*.json"))
        assert len(flat_files) == 1, "--keepflat wrote no flattened events file"
        event = json.loads(flat_files[0].read_text().splitlines()[0])
        # Flattened: the nested Event.System.EventID is now a top-level column
        assert event["EventID"] == 1
        assert "Event" not in event


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
        assert content.split("\n")[0].startswith("rule_title")
        assert not content.strip().startswith("[")

    def test_csv_output_with_parallel_workers(self, tmp_path):
        """Test that --csv produces CSV output when parallel workers are used (multiple files)."""
        # -e takes one path, so a directory is how several files get in
        event_line = '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}'
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        (events_dir / "events1.json").write_text(event_line + "\n")
        (events_dir / "events2.json").write_text(event_line + "\n")

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

        analyze_calls = []

        def tracking_analyze(files, logger=None):
            analyze_calls.append(list(files))
            return mock_analyze(files, logger)

        with patch.object(zircolite_script, 'analyze_files_and_recommend_mode', side_effect=tracking_analyze):
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_dir),
                '-r', str(ruleset_file),
                '-c', str(config_file),
                '-j',
                '--csv',
                '--csv-delimiter', ',',
                '-o', str(output_file),
                '--no-auto-mode'
            ] + get_log_arg(tmp_path)):
                zircolite_script.main()

        # Without this the test silently exercised the sequential path
        assert analyze_calls, "parallel analysis never ran"
        assert len(analyze_calls[0]) == 2, "both files must reach the analyser"

        assert output_file.exists()
        with open(output_file) as f:
            content = f.read()
        # Must be CSV: header contains rule_title, not a JSON array
        assert content.split("\n")[0].startswith("rule_title")
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

    def test_template_append_accumulates_across_runs(self, tmp_path):
        """--template-append should append to existing template output across runs."""
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
        template_file.write_text("RUN|")

        output_file = tmp_path / "detected_events.json"
        template_output = tmp_path / "alerts.txt"

        argv_base = [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--template', str(template_file),
            '--templateOutput', str(template_output),
            '--template-append',
        ] + get_log_arg(tmp_path)

        with patch('sys.argv', argv_base):
            zircolite_script.main()
        with patch('sys.argv', argv_base):
            zircolite_script.main()

        assert template_output.read_text() == "RUN|RUN|"

    def test_template_append_disabled_overwrites(self, tmp_path):
        """Without --template-append, repeated runs overwrite the template output."""
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
        template_file.write_text("ONCE")

        output_file = tmp_path / "detected_events.json"
        template_output = tmp_path / "alerts.txt"

        argv_base = [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
            '--template', str(template_file),
            '--templateOutput', str(template_output),
        ] + get_log_arg(tmp_path)

        with patch('sys.argv', argv_base):
            zircolite_script.main()
        with patch('sys.argv', argv_base):
            zircolite_script.main()

        assert template_output.read_text() == "ONCE"

    def test_navigator_output_creates_empty_layer_without_detections(self, tmp_path):
        """--navigator-output should emit a valid empty layer when no rules match."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}}}')

        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")

        nav_output = tmp_path / "navigator.json"
        original_cwd = os.getcwd()
        try:
            os.chdir(WORKSPACE_ROOT)
            with patch('sys.argv', [
                'zircolite.py',
                '-e', str(events_file),
                '-r', str(ruleset_file),
                '-j',
                '--navigator-output', str(nav_output),
            ] + get_log_arg(tmp_path)):
                zircolite_script.main()
        finally:
            os.chdir(original_cwd)

        layer = json.loads(nav_output.read_text())
        assert layer["techniques"] == []
        assert layer["name"] == "Zircolite Detected ATT&CK Techniques"
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["layer"] == "4.5"
        assert isinstance(layer["legendItems"], list) and layer["legendItems"]
        assert isinstance(layer["filters"]["platforms"], list)

    def test_template_with_navigator_output_reports_count_mismatch(self, tmp_path):
        """Shortcut initialization should not crash when templateOutput is absent."""
        events_file = tmp_path / "events.json"
        events_file.write_text('{"Event": {"System": {"EventID": 1}}}')

        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")

        template_file = tmp_path / "template.tmpl"
        template_file.write_text("{{ data | length }}")

        original_cwd = os.getcwd()
        try:
            os.chdir(WORKSPACE_ROOT)
            with pytest.raises(SystemExit) as exc_info:
                with patch('sys.argv', [
                    'zircolite.py',
                    '-e', str(events_file),
                    '-r', str(ruleset_file),
                    '-j',
                    '--template', str(template_file),
                    '--navigator-output', str(tmp_path / "navigator.json"),
                ] + get_log_arg(tmp_path)):
                    zircolite_script.main()
        finally:
            os.chdir(original_cwd)

        assert exc_info.value.code == 1


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

    def test_remove_events_keeps_a_file_that_failed_to_ingest(self, tmp_path):
        """--remove-events must not destroy evidence nothing ever read.

        The help text promises removal "after successful analysis", but every
        discovered path was deleted regardless of whether its events made it
        into the results -- and in parallel mode the failure was not even shown.
        """
        good = tmp_path / "good.json"
        good.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {}}}')
        # Valid UTF-16, so the reader opens it and then fails on every line
        bad = tmp_path / "bad.json"
        bad.write_bytes('{"Event": {"System": {"EventID": 1}}}'.encode("utf-16"))

        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")

        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(tmp_path),
            '-r', str(ruleset_file),
            '-j',
            '-o', str(tmp_path / "output.json"),
            '-RE',
            '-n',
        ]):
            zircolite_script.main()

        assert not good.exists(), "A file that ingested cleanly should be removed"
        assert bad.exists(), "A file Zircolite could not read must survive the run"


class TestCLIAdvancedConfiguration:
    """Tests for Advanced Configuration options: --quiet, --debug, --timefield, --logs-encoding, --no-auto-detect."""

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


class TestCLIStrictEvtxParsing:
    """Tests for --strict EVTX parsing flag."""

    def test_strict_flag_default_false(self):
        """--strict defaults to False when not provided."""
        with patch('sys.argv', ['zircolite.py', '-v']):
            args = zircolite_script.parse_arguments()
            assert args.strict is False

    def test_strict_flag_sets_true(self):
        """--strict sets the strict attribute to True."""
        with patch('sys.argv', ['zircolite.py', '--strict', '-v']):
            args = zircolite_script.parse_arguments()
            assert args.strict is True


# Fixture files for Sysmon Linux, XML, EVTXtract, Auditd, and Winlogbeat (sanitized/cropped)
FIXTURES_DIR = WORKSPACE_ROOT / "tests" / "fixtures"
SYSMON_LINUX_FIXTURE = FIXTURES_DIR / "sysmon_linux_sample.log"
XML_EVENTS_FIXTURE = FIXTURES_DIR / "xml_events_sample.xml"
EVTXTRACT_FIXTURE = FIXTURES_DIR / "evtxtract_sample.log"
AUDITD_FIXTURE = FIXTURES_DIR / "audit_sample.log"
WINLOGBEAT_FIXTURE = FIXTURES_DIR / "winlogbeat_sysmon_sample.json"


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

    @pytest.mark.parametrize(
        "fixture,flag,channel_field,marker",
        [
            (SYSMON_LINUX_FIXTURE, "-S", "Image", "%%"),
            (XML_EVENTS_FIXTURE, "-x", "Computer", "%%"),
            (EVTXTRACT_FIXTURE, "--evtxtract-input", "Computer", "%%"),
            (AUDITD_FIXTURE, "--auditd-input", "type", "%%"),
            (WINLOGBEAT_FIXTURE, "-j", "Computer", "%%"),
        ],
    )
    def test_each_input_format_ingests_and_matches(
        self, tmp_path, fixture, flag, channel_field, marker
    ):
        """Every format must ingest events and let a rule match them.

        These tests used to run with an empty ruleset and assert only that the
        output file existed, so they passed whether the format parsed or not --
        which is exactly how several silent ingestion bugs survived.
        """
        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture}")
        if flag == "-x":
            pytest.importorskip("lxml")

        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Everything",
            "id": "match-all",
            "description": "matches any ingested event",
            "level": "high",
            "tags": [],
            "filename": "match_all.yml",
            "rule": [f'SELECT * FROM logs WHERE "{channel_field}" LIKE \'{marker}\''],
        }]))
        output_file = tmp_path / "out.json"

        with patch('sys.argv', [
            'zircolite.py',
            '-e', str(fixture),
            '-r', str(ruleset_file),
            flag,
            '-o', str(output_file),
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()

        data = json.loads(output_file.read_text())
        assert data, f"{fixture.name} produced no detection: nothing was ingested"
        assert data[0]["count"] > 0
        assert data[0]["matches"], "a detection with no matching event is not a detection"


    def test_real_evtx_file_end_to_end(self, tmp_path):
        """The default format had no end-to-end test at all.

        Every other EVTX test used non-existent files or a mocked parser, so
        nothing exercised the real pyevtx-rs reader through the CLI.
        """
        evtx = FIXTURES_DIR / "sample_bitsadmin.evtx"
        if not evtx.exists():
            pytest.skip(f"Fixture not found: {evtx}")

        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Sysmon process creation",
            "id": "evtx-e2e",
            "description": "",
            "level": "high",
            "tags": [],
            "filename": "e2e.yml",
            "rule": ["SELECT * FROM logs WHERE Channel LIKE '%Sysmon%' AND EventID = 1"],
        }]))
        output_file = tmp_path / "out.json"

        with patch('sys.argv', [
            'zircolite.py',
            '--evtx', str(evtx),
            '-r', str(ruleset_file),
            '-o', str(output_file),
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()

        data = json.loads(output_file.read_text())
        assert data, "the shipped EVTX fixture produced no detection"
        match = data[0]["matches"][0]
        # Real fields from the real parser, not a mock
        assert match["Channel"] == "Microsoft-Windows-Sysmon/Operational"
        assert str(match["EventID"]) == "1"
        assert "CommandLine" in match


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

    def test_perfile_dbfile_multiple_files_respects_directory(self, tmp_path):
        """Per-file mode with -d <dir>/db.db and multiple files writes DBs under that directory."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        (events_dir / "f1.json").write_text(
            json.dumps({"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "a"}}})
        )
        (events_dir / "f2.json").write_text(
            json.dumps({"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "b"}}})
        )
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
        db_dir = tmp_path / "out"
        db_file = db_dir / "db.db"

        with patch("sys.argv", [
            "zircolite.py",
            "-e", str(events_dir),
            "-r", str(ruleset_file),
            "-c", str(config_file),
            "-j",
            "-o", str(output_file),
            "--no-auto-mode",
            "--no-parallel",
            "-d", str(db_file),
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()

        assert db_dir.is_dir()
        assert (db_dir / "db_f1.json.db").exists()
        assert (db_dir / "db_f2.json.db").exists()
        assert not list(tmp_path.glob("db_*.db"))

    def test_parallel_dbfile_fails_fast(self, tmp_path):
        """Parallel mode with multiple files and --dbfile exits with clear error (no silent failure)."""
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        (events_dir / "a.json").write_text(
            json.dumps({"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "x"}}})
        )
        (events_dir / "b.json").write_text(
            json.dumps({"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "y"}}})
        )
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
        db_file = tmp_path / "out.db"

        def fake_recommend(_file_list):
            return ("per-file", "Multiple files", {"parallel_recommended": True, "parallel_workers": 2})

        with patch.object(zircolite_script, "analyze_files_and_recommend_mode", side_effect=fake_recommend):
            with pytest.raises(SystemExit) as exc_info:
                with patch("sys.argv", [
                    "zircolite.py",
                    "-e", str(events_dir),
                    "-r", str(ruleset_file),
                    "-c", str(config_file),
                    "-j",
                    "-o", str(output_file),
                    "--no-auto-mode",
                    "-d", str(db_file),
                ] + get_log_arg(tmp_path)):
                    zircolite_script.main()
        assert exc_info.value.code == 2
        assert not db_file.exists()

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

    def test_unknown_detection_with_known_input_type_uses_it(self):
        """When log_source is unknown but input_type is a known format (e.g. json), use it."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="json",
            log_source="unknown",
            confidence="low",
            details="Could not determine log type: No files to analyze",
        )

        input_type = zircolite_script._apply_detection_result(args, detection, logger)

        assert input_type == "json"
        assert getattr(args, "json_input", None) is True

    def test_unknown_detection_with_unknown_input_type_returns_evtx(self):
        """When log_source is unknown and input_type is not a known format, default to evtx."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="evtx",
            log_source="unknown",
            confidence="low",
            details="Could not determine log type",
        )

        input_type = zircolite_script._apply_detection_result(args, detection, logger)

        assert input_type == "evtx"
        assert getattr(args, "json_input", None) is not True

    def test_auto_detect_with_all_unknown_files_uses_unknown_result_input_type(self, tmp_path):
        """When all sampled files yield unknown detection, we still use the unknown result's input_type (json)."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        # Paths that do not exist: detect() returns unknown for each (_unknown_result gives input_type=json)
        file_list = [
            tmp_path / "nope1.json",
            tmp_path / "nope2.json",
            tmp_path / "nope3.json",
        ]

        input_type = zircolite_script.auto_detect_log_type(file_list, args, logger)

        assert input_type == "json"
        assert getattr(args, "json_input", None) is True


class TestApplyDetectionResultTimefieldSanitization:
    """Tests for timefield sanitization in _apply_detection_result.

    The streaming processor strips non-alphanumeric characters from field
    names when storing events in SQLite (e.g. '@timestamp' -> 'timestamp').
    _apply_detection_result must apply the same sanitization so that the
    timefield used for template rendering matches the actual column name.
    """

    def test_at_timestamp_sanitized(self):
        """@timestamp from ECS/Elastic detection must be sanitized to 'timestamp'."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="json",
            log_source="ecs_elastic",
            confidence="high",
            timestamp_field="@timestamp",
        )

        zircolite_script._apply_detection_result(args, detection, logger)

        assert args.timefield == "timestamp"

    def test_at_time_sanitized(self):
        """'@time' field should be sanitized to 'time'."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="json",
            log_source="generic_json",
            confidence="medium",
            timestamp_field="@time",
        )

        zircolite_script._apply_detection_result(args, detection, logger)

        assert args.timefield == "time"

    def test_plain_field_unchanged(self):
        """Plain alphanumeric fields like 'UtcTime' remain unchanged."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="json",
            log_source="sysmon_windows",
            confidence="high",
            timestamp_field="UtcTime",
        )

        zircolite_script._apply_detection_result(args, detection, logger)

        assert args.timefield == "UtcTime"

    def test_systemtime_unchanged(self):
        """SystemTime stays SystemTime (no-op when detection matches default)."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="evtx",
            log_source="windows_evtx",
            confidence="high",
            timestamp_field="SystemTime",
        )

        zircolite_script._apply_detection_result(args, detection, logger)

        assert args.timefield == "SystemTime"

    def test_underscore_field_sanitized(self):
        """'_time' (Splunk format) should be sanitized to 'time'."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="json",
            log_source="generic_json",
            confidence="medium",
            timestamp_field="_time",
        )

        zircolite_script._apply_detection_result(args, detection, logger)

        assert args.timefield == "time"

    def test_user_override_not_clobbered(self):
        """When user explicitly sets --timefield, detection should not override it."""
        args = _minimal_detection_args()
        args.timefield = "MyCustomField"
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="json",
            log_source="ecs_elastic",
            confidence="high",
            timestamp_field="@timestamp",
        )

        zircolite_script._apply_detection_result(args, detection, logger)

        assert args.timefield == "MyCustomField"

    def test_none_timestamp_field_leaves_default(self):
        """When detection has no timestamp_field, the default is preserved."""
        args = _minimal_detection_args()
        logger = zircolite_script.init_logger(debug_mode=False)
        detection = DetectionResult(
            input_type="json",
            log_source="generic_json",
            confidence="low",
            timestamp_field=None,
        )

        zircolite_script._apply_detection_result(args, detection, logger)

        assert args.timefield == "SystemTime"




class TestFormatFlagExtension:
    """Tests for _format_flag_extension / get_file_extension (re-discovery fix)."""

    def _args(self, **kw):
        defaults = dict(
            fileext=None, json_input=False, json_array_input=False,
            sysmon_linux_input=False, auditd_input=False, xml_input=False,
            csv_input=False,
        )
        defaults.update(kw)
        return argparse.Namespace(**defaults)

    def test_flag_extension_ignores_fileext(self):
        """_format_flag_extension reflects format flags only, not args.fileext."""
        args = self._args(fileext="evtx", json_input=True)
        assert zircolite_script._format_flag_extension(args) == "json"
        # get_file_extension still honors the explicit/auto-derived fileext
        assert zircolite_script.get_file_extension(args) == "evtx"

    def test_flag_extension_defaults(self):
        assert zircolite_script._format_flag_extension(self._args()) == "evtx"
        assert zircolite_script._format_flag_extension(self._args(xml_input=True)) == "xml"
        assert zircolite_script._format_flag_extension(self._args(auditd_input=True)) == "log"
        assert zircolite_script._format_flag_extension(self._args(csv_input=True)) == "csv"


class TestTestRulesCLI:
    """Tests for --test-rules CLI flow."""

    def _write_ruleset(self, tmp_path, rules):
        ruleset_file = tmp_path / "rules.json"
        ruleset_file.write_text(json.dumps(rules))
        return str(ruleset_file)

    def test_test_rules_with_rulefilter_does_not_crash(self, tmp_path):
        """--test-rules combined with -R must not raise TypeError (flatten ordering)."""
        ruleset = self._write_ruleset(tmp_path, [
            {"title": "Noisy Rule", "id": "1", "rule": ["SELECT 1"]},
        ])
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps([]))

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-r', ruleset,
                '--test-rules', str(test_file),
                '-R', 'Noisy', '-n',
            ]):
                zircolite_script.main()
        # The only rule is filtered out -> no results -> success
        assert exc_info.value.code == 0

    def test_test_rules_exit_zero_on_pass(self, tmp_path):
        ruleset = self._write_ruleset(tmp_path, [
            {"title": "R", "id": "1",
             "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%cmd%' ESCAPE '\\'"]},
        ])
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps([
            {"title": "R",
             "true_positive": [{"CommandLine": "cmd.exe /c whoami"}],
             "true_negative": [{"CommandLine": "powershell.exe"}]},
        ]))

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-r', ruleset,
                '--test-rules', str(test_file), '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 0

    def test_test_rules_exit_nonzero_on_failure(self, tmp_path):
        """Failing rule tests must produce a non-zero exit code (CI usage)."""
        ruleset = self._write_ruleset(tmp_path, [
            {"title": "R", "id": "1",
             "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%cmd%' ESCAPE '\\'"]},
        ])
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps([
            {"title": "R",
             "true_positive": [{"CommandLine": "definitely not matching"}],
             "true_negative": []},
        ]))

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-r', ruleset,
                '--test-rules', str(test_file), '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 1


class TestCLIValidation:
    """Regression tests for CLI argument validation fixes."""

    def test_template_output_without_template_errors(self, tmp_path):
        """-T without -t must exit with an error, not be silently ignored."""
        ruleset_file = tmp_path / "rules.json"
        ruleset_file.write_text(json.dumps([
            {"title": "R", "id": "1", "rule": ["SELECT 1"]}
        ]))
        events = tmp_path / "events.json"
        events.write_text(json.dumps({"EventID": 1}) + "\n")

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-e', str(events), '-j',
                '-r', str(ruleset_file),
                '-T', str(tmp_path / "out.json"), '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 1

    def test_limit_zero_rejected(self, tmp_path):
        """--limit 0 would discard every detection: reject it."""
        ruleset_file = tmp_path / "rules.json"
        ruleset_file.write_text(json.dumps([
            {"title": "R", "id": "1", "rule": ["SELECT 1"]}
        ]))
        events = tmp_path / "events.json"
        events.write_text(json.dumps({"EventID": 1}) + "\n")

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-e', str(events), '-j',
                '-r', str(ruleset_file),
                '--limit', '0', '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 1

    def test_multiple_templates_per_flag_rejected(self, tmp_path):
        """-t a.tmpl b.tmpl must error (second template would be ignored)."""
        ruleset_file = tmp_path / "rules.json"
        ruleset_file.write_text(json.dumps([
            {"title": "R", "id": "1", "rule": ["SELECT 1"]}
        ]))
        events = tmp_path / "events.json"
        events.write_text(json.dumps({"EventID": 1}) + "\n")
        tmpl = tmp_path / "a.tmpl"
        tmpl.write_text("{{ data }}")
        tmpl2 = tmp_path / "b.tmpl"
        tmpl2.write_text("{{ data }}")

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-e', str(events), '-j',
                '-r', str(ruleset_file),
                '-t', str(tmpl), str(tmpl2),
                '-T', str(tmp_path / "out.json"), '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 1

    def test_transform_list_missing_config_exits_nonzero(self, tmp_path):
        """--transform-list with a missing config must exit non-zero."""
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '--transform-list',
                '-c', str(tmp_path / "nope.yaml"), '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 1

    def test_transform_list_ok_exits_zero(self):
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['zircolite.py', '--transform-list', '-n']):
                zircolite_script.main()
        assert exc_info.value.code == 0


class TestDbfileCollision:
    """Same-named input files in different dirs must not crash --dbfile."""

    def test_perfile_dbfile_same_basename_both_saved(self, tmp_path):
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()
        for d, cmd in ((dir1, "a"), (dir2, "b")):
            (d / "same.json").write_text(
                json.dumps({"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": cmd}}})
            )
        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text("[]")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [], "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.EventData.CommandLine": "CommandLine",
            },
            "alias": {}, "split": {}, "transforms_enabled": False, "transforms": {},
        }))
        db_file = tmp_path / "out" / "db.db"

        with patch("sys.argv", [
            "zircolite.py",
            "-e", str(tmp_path),
            "-r", str(ruleset_file),
            "-c", str(config_file),
            "-j",
            "-o", str(tmp_path / "output.json"),
            "--no-auto-mode",
            "--no-parallel",
            "-d", str(db_file),
            "--file-pattern", "dir*/same.json",
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()

        db_dir = tmp_path / "out"
        saved = sorted(p.name for p in db_dir.glob("*.db"))
        assert len(saved) == 2  # no FileExistsError crash, no overwrite


class TestCLIRegressionFixes:
    """Regressions for CLI/code alignment defects."""

    @staticmethod
    def _fixture(tmp_path, *, events_name="events.json"):
        """Write a matching ruleset/config/event triplet and return the paths."""
        ruleset = tmp_path / "rules.json"
        ruleset.write_text(json.dumps([{
            "title": "Test Rule", "id": "test-001", "level": "high", "tags": [],
            "rule": ["SELECT * FROM logs WHERE EventID = 4688"],
        }]))
        config = tmp_path / "config.json"
        config.write_text(json.dumps({
            "exclusions": [], "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.System.Channel": "Channel",
                "Event.EventData.CommandLine": "CommandLine",
            },
            "alias": {}, "split": {}, "transforms_enabled": False, "transforms": {},
        }))
        events = tmp_path / events_name
        events.write_text(json.dumps({
            "Event": {
                "System": {"EventID": 4688, "Channel": "Security"},
                "EventData": {"CommandLine": "powershell.exe"},
            }
        }) + "\n")
        return ruleset, config, events

    def test_limit_below_minus_one_rejected(self, tmp_path):
        """--limit -5 silently discarded every detection: reject it like 0."""
        ruleset, config, events = self._fixture(tmp_path)
        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-e', str(events), '-j',
                '-r', str(ruleset), '-c', str(config), '--limit', '-5', '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 1

    def test_limit_minus_one_still_allowed(self, tmp_path):
        """-1 is the documented 'no limit' value and must keep working."""
        ruleset, config, events = self._fixture(tmp_path)
        out = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py', '-e', str(events), '-j', '-r', str(ruleset),
            '-c', str(config), '-o', str(out), '--limit', '-1',
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()
        assert len(json.loads(out.read_text())) == 1

    def test_directory_of_json_autodetects_without_fileext(self, tmp_path):
        """A directory of non-EVTX logs must not abort with 'No file found'."""
        ruleset, config, _ = self._fixture(tmp_path)
        events_dir = tmp_path / "logs"
        events_dir.mkdir()
        for name in ("a.json", "b.json"):
            (events_dir / name).write_text(json.dumps({
                "Event": {
                    "System": {"EventID": 4688, "Channel": "Security"},
                    "EventData": {"CommandLine": "powershell.exe"},
                }
            }) + "\n")

        out = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py', '-e', str(events_dir), '-r', str(ruleset),
            '-c', str(config), '-o', str(out),
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()

        assert out.exists()
        assert len(json.loads(out.read_text())) >= 1

    def test_explicit_fileext_still_wins_over_detection(self, tmp_path):
        """--fileext must not be overridden by the auto-detected extension."""
        ruleset, config, _ = self._fixture(tmp_path)
        events_dir = tmp_path / "logs"
        events_dir.mkdir()
        (events_dir / "a.ndjson").write_text(json.dumps({
            "Event": {
                "System": {"EventID": 4688, "Channel": "Security"},
                "EventData": {"CommandLine": "powershell.exe"},
            }
        }) + "\n")
        (events_dir / "ignored.json").write_text("{}\n")

        out = tmp_path / "out.json"
        with patch('sys.argv', [
            'zircolite.py', '-e', str(events_dir), '-f', 'ndjson',
            '-r', str(ruleset), '-c', str(config), '-o', str(out),
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()

        detections = json.loads(out.read_text())
        assert len(detections) == 1
        assert detections[0]["count"] == 1

    def test_bundled_templates_resolve_from_any_cwd(self, tmp_path, monkeypatch):
        """--timesketch/--navigator-output must not depend on the working directory."""
        ruleset, config, events = self._fixture(tmp_path)
        workdir = tmp_path / "elsewhere"
        workdir.mkdir()
        monkeypatch.chdir(workdir)

        with patch('sys.argv', [
            'zircolite.py', '-e', str(events), '-j', '-r', str(ruleset),
            '-c', str(config), '-o', str(tmp_path / "out.json"),
            '--timesketch', '--navigator-output',
        ] + get_log_arg(tmp_path)):
            zircolite_script.main()

        assert list(workdir.glob("timesketch-*.json"))
        assert list(workdir.glob("navigator-*.json"))

    def test_default_config_and_ruleset_resolve_from_any_cwd(self, tmp_path, monkeypatch):
        """The bundled default config/ruleset must be found outside the repo."""
        workdir = tmp_path / "elsewhere"
        workdir.mkdir()
        monkeypatch.chdir(workdir)

        resolved_config = zircolite_script._resolve_default_path(
            "config/config.yaml", "config", "config.yaml"
        )
        assert Path(resolved_config).is_file()
        resolved_rules = zircolite_script._resolve_default_path(
            "rules/rules_windows_generic.json", "rules", "rules_windows_generic.json"
        )
        assert Path(resolved_rules).is_file()

    def test_local_file_still_wins_over_bundled_default(self, tmp_path, monkeypatch):
        """A config/config.yaml in the CWD keeps priority over the bundled one."""
        workdir = tmp_path / "elsewhere"
        (workdir / "config").mkdir(parents=True)
        local = workdir / "config" / "config.yaml"
        local.write_text("mappings: {}\n")
        monkeypatch.chdir(workdir)

        resolved = zircolite_script._resolve_default_path(
            "config/config.yaml", "config", "config.yaml"
        )
        assert resolved == "config/config.yaml"

    def test_warn_ignored_db_flags_lists_inert_flags(self):
        """DB-input mode must report every flag it silently ignores."""
        import logging
        from unittest.mock import MagicMock
        logger = MagicMock(spec=logging.Logger)
        args = argparse.Namespace(
            unified_db=False, no_auto_mode=False, no_parallel=False,
            add_index=[], remove_index=[], hashes=False,
            keepflat=True, dbfile="x.db", strict=True,
            archive_password="pw", no_event_filter=True, logs_encoding="utf-8",
            after="2024-01-01T00:00:00", before="2024-12-31T23:59:59",
        )
        zircolite_script._warn_ignored_db_flags(args, logger)

        assert logger.warning.called
        message = logger.warning.call_args[0][0]
        for flag in ("--keepflat", "--dbfile", "--strict",
                     "--archive-password", "--no-event-filter", "--logs-encoding",
                     "--after", "--before"):
            assert flag in message

    def test_warn_ignored_db_flags_ignores_default_time_range(self):
        """The default time range is not a user request, so it is not reported."""
        import logging
        from unittest.mock import MagicMock
        from zircolite.run_config import DEFAULTS
        logger = MagicMock(spec=logging.Logger)
        args = argparse.Namespace(
            unified_db=False, no_auto_mode=False, no_parallel=False,
            add_index=[], remove_index=[], hashes=False,
            keepflat=False, dbfile=None, strict=False,
            archive_password=None, no_event_filter=False, logs_encoding=None,
            after=DEFAULTS['after'], before=DEFAULTS['before'],
        )
        zircolite_script._warn_ignored_db_flags(args, logger)

        assert not logger.warning.called


class TestTestRulesOrphanCases:
    """A test case naming a rule that is not in the ruleset must fail the run."""

    @staticmethod
    def _ruleset(tmp_path):
        ruleset = tmp_path / "rules.json"
        ruleset.write_text(json.dumps([{
            "title": "Detect PowerShell", "id": "ps-001", "level": "high", "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"],
        }]))
        return ruleset

    def test_matching_test_case_exits_zero(self, tmp_path):
        ruleset = self._ruleset(tmp_path)
        tests = tmp_path / "tests.json"
        tests.write_text(json.dumps([{
            "title": "Detect PowerShell",
            "true_positive": [{"CommandLine": "powershell.exe -c x"}],
            "true_negative": [{"CommandLine": "notepad.exe"}],
        }]))

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-r', str(ruleset),
                '--test-rules', str(tests), '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 0

    def test_test_case_matching_no_rule_exits_nonzero(self, tmp_path):
        """A typo in the test file's rule title would otherwise pass CI silently."""
        ruleset = self._ruleset(tmp_path)
        tests = tmp_path / "tests.json"
        tests.write_text(json.dumps([{
            "title": "Detect PowerShel",  # typo: matches no rule
            "true_positive": [{"CommandLine": "powershell.exe -c x"}],
            "true_negative": [],
        }]))

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-r', str(ruleset),
                '--test-rules', str(tests), '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 1

    def test_failing_true_positive_exits_nonzero(self, tmp_path):
        ruleset = self._ruleset(tmp_path)
        tests = tmp_path / "tests.json"
        tests.write_text(json.dumps([{
            "title": "Detect PowerShell",
            "true_positive": [{"CommandLine": "notepad.exe"}],
            "true_negative": [],
        }]))

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', [
                'zircolite.py', '-r', str(ruleset),
                '--test-rules', str(tests), '-n',
            ]):
                zircolite_script.main()
        assert exc_info.value.code == 1


class TestYamlConfigTemplateValidation:
    """A malformed output.templates entry must fail with the validation message."""

    def test_template_entry_missing_output_is_fatal(self, tmp_path):
        ruleset = tmp_path / "rules.json"
        ruleset.write_text(json.dumps([
            {"title": "R", "id": "1", "level": "high", "tags": [], "rule": ["SELECT 1"]}
        ]))
        events = tmp_path / "events.json"
        events.write_text(json.dumps({"EventID": 1}) + "\n")
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text(
            "input:\n"
            f"  path: {events}\n"
            "  format: json\n"
            "rules:\n"
            f"  rulesets: [{ruleset}]\n"
            "output:\n"
            "  templates:\n"
            "    - template: templates/exportForSplunk.tmpl\n"
        )

        with pytest.raises(SystemExit) as exc_info:
            with patch('sys.argv', ['zircolite.py', '-Y', str(cfg), '-n']):
                zircolite_script.main()
        assert exc_info.value.code == 1


class TestGenerateConfigDoesNotClobber:
    """--dbfile already refuses to overwrite; --generate-config did not."""

    def test_refuses_to_overwrite_an_existing_file(self, tmp_path):
        from zircolite.config_loader import create_default_config_file

        target = tmp_path / "mine.yaml"
        target.write_text("# hand-written, do not lose me\n")

        with pytest.raises(FileExistsError):
            create_default_config_file(str(target))

        assert target.read_text() == "# hand-written, do not lose me\n"

    def test_writes_when_the_path_is_free(self, tmp_path):
        from zircolite.config_loader import create_default_config_file

        target = tmp_path / "fresh.yaml"
        create_default_config_file(str(target))

        assert target.exists()
        assert "input:" in target.read_text()

    def test_cli_exits_2_instead_of_clobbering(self, tmp_path):
        target = tmp_path / "existing.yaml"
        target.write_text("keep me\n")

        result = subprocess.run(
            [sys.executable, str(WORKSPACE_ROOT / "zircolite.py"),
             "--generate-config", str(target)],
            capture_output=True, text=True, cwd=str(WORKSPACE_ROOT),
        )

        assert result.returncode == 2
        assert target.read_text() == "keep me\n"


class TestFlagsThatMustNotChangeDetections:
    """Flags that alter plumbing, not results.

    These replace eight near-identical tests whose only assertion was that
    the output file existed -- true even if nothing was detected. Each case
    now asserts the detection actually fired, plus whatever is specific to
    the flag.
    """

    EVENT = ('{"Event": {"System": {"EventID": 1}, '
             '"EventData": {"CommandLine": "powershell.exe"}}}')

    def _run(self, tmp_path, extra_args):
        events_file = tmp_path / "events.json"
        events_file.write_text(self.EVENT)

        ruleset_file = tmp_path / "ruleset.json"
        ruleset_file.write_text(json.dumps([{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"],
        }]))

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "exclusions": [], "useless": [],
            "mappings": {"Event.System.EventID": "EventID",
                         "Event.EventData.CommandLine": "CommandLine"},
            "alias": {}, "split": {},
            "transforms_enabled": False, "transforms": {},
        }))

        output_file = tmp_path / "out.json"
        argv = [
            'zircolite.py',
            '-e', str(events_file),
            '-r', str(ruleset_file),
            '-c', str(config_file),
            '-j',
            '-o', str(output_file),
        ] + extra_args + get_log_arg(tmp_path)
        with patch('sys.argv', argv):
            zircolite_script.main()
        return output_file

    @pytest.mark.parametrize("extra_args", [
        pytest.param([], id="baseline"),
        pytest.param(['-f', 'json'], id="fileext"),
        pytest.param(['-q'], id="quiet"),
        pytest.param(['--debug'], id="debug"),
        pytest.param(['-LE', 'utf-8'], id="logs-encoding"),
        pytest.param(['--no-event-filter'], id="no-event-filter"),
        pytest.param(['-P'], id="no-parallel"),
        pytest.param(['--parallel-memory-limit', '50'], id="memory-limit"),
        pytest.param(['--no-auto-mode'], id="no-auto-mode"),
    ])
    def test_detection_is_unaffected(self, tmp_path, extra_args):
        output_file = self._run(tmp_path, extra_args)

        assert output_file.exists()
        detections = json.loads(output_file.read_text())
        assert len(detections) == 1
        assert detections[0]["title"] == "Test Rule"

    def test_debug_writes_debug_records_to_the_log(self, tmp_path):
        self._run(tmp_path, ['--debug'])

        log_files = list(tmp_path.glob("*.log"))
        assert log_files, "no log file was written"
        assert "DEBUG" in log_files[0].read_text()

    def test_quiet_suppresses_the_banner(self, tmp_path, capsys):
        self._run(tmp_path, ['-q'])

        assert "Zircolite" not in capsys.readouterr().out


def test_version_has_a_single_source():
    """The Taskfile greps zircolite/__init__.py, so nothing may duplicate it."""
    from zircolite import __version__

    cli_source = (WORKSPACE_ROOT / "zircolite.py").read_text()
    assert 'version = "' not in cli_source, (
        "zircolite.py must read __version__, not carry its own literal"
    )

    taskfile = (WORKSPACE_ROOT / "Taskfile.yml").read_text()
    assert "zircolite/__init__.py" in taskfile

    result = subprocess.run(
        [sys.executable, str(WORKSPACE_ROOT / "zircolite.py"), "-v"],
        capture_output=True, text=True, cwd=str(WORKSPACE_ROOT),
    )
    assert __version__ in result.stdout
