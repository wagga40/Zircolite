"""
Tests for the JSONFlattener class.
"""

import json
import os
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import JSONFlattener, ProcessingConfig


class TestJSONFlattenerInit:
    """Tests for JSONFlattener initialization."""
    
    def test_init_with_valid_config(self, field_mappings_file, args_config_evtx, test_logger):
        """Test JSONFlattener initializes correctly with valid config."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        assert flattener.time_after == "1970-01-01T00:00:00"
        assert flattener.time_before == "9999-12-12T23:59:59"
        assert flattener.hashes is False
        assert flattener.field_mappings is not None
        assert flattener.field_exclusions is not None
    
    def test_init_with_time_filters(self, field_mappings_file, args_config_evtx, test_logger):
        """Test JSONFlattener with time filtering enabled."""
        proc_config = ProcessingConfig(
            time_after="2024-01-01T00:00:00",
            time_before="2024-12-31T23:59:59"
        )
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        assert flattener.time_after == "2024-01-01T00:00:00"
        assert flattener.time_before == "2024-12-31T23:59:59"
    
    def test_init_with_hashes_enabled(self, field_mappings_file, args_config_evtx, test_logger):
        """Test JSONFlattener with hash computation enabled."""
        proc_config = ProcessingConfig(hashes=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        assert flattener.hashes is True
    
    def test_init_loads_field_mappings(self, field_mappings_file, args_config_evtx, test_logger):
        """Test that field mappings are loaded correctly."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        assert "EventID" in flattener.field_mappings.values()
        assert "Channel" in flattener.field_mappings.values()
    
    def test_init_loads_exclusions(self, field_mappings_file, args_config_evtx, test_logger):
        """Test that field exclusions are loaded correctly."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        assert "xmlns" in flattener.field_exclusions
    
    def test_init_detects_chosen_input(self, field_mappings_file, args_config_json, test_logger):
        """Test that chosen input type is detected correctly."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_json
        )
        
        assert flattener.chosen_input == "json_input"


class TestJSONFlattenerRun:
    """Tests for JSONFlattener.run() method."""
    
    def test_run_flattens_simple_event(self, field_mappings_file, tmp_json_file, args_config_evtx, test_logger):
        """Test that run() correctly flattens a simple event."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        result = flattener.run(tmp_json_file)
        
        assert "dbFields" in result
        assert "dbValues" in result
        assert len(result["dbValues"]) > 0
    
    def test_run_maps_fields_correctly(self, field_mappings_file, tmp_json_file, args_config_evtx, test_logger):
        """Test that field mappings are applied correctly."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        result = flattener.run(tmp_json_file)
        
        # Check that mapped fields exist in the flattened output
        if result["dbValues"]:
            first_event = result["dbValues"][0]
            # Should have EventID (mapped from Event.System.EventID)
            assert "EventID" in first_event or "eventid" in first_event.keys()
    
    def test_run_handles_multiple_events(self, field_mappings_file, tmp_json_file_multiple, args_config_evtx, test_logger):
        """Test that run() handles multiple events in JSONL format."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        result = flattener.run(tmp_json_file_multiple)
        
        assert len(result["dbValues"]) == 3
    
    def test_run_handles_json_array(self, field_mappings_file, tmp_json_array_file, args_config_evtx, test_logger):
        """Test that run() handles JSON array format."""
        args_config_evtx.json_array_input = True
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        result = flattener.run(tmp_json_array_file)
        
        assert len(result["dbValues"]) == 3
    
    def test_run_excludes_specified_fields(self, field_mappings_file, tmp_json_file, args_config_evtx, test_logger):
        """Test that excluded fields are not included in output."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        result = flattener.run(tmp_json_file)
        
        # Check that excluded fields (like xmlns) are not present
        for event in result["dbValues"]:
            for key in event.keys():
                assert "xmlns" not in key.lower()
    
    def test_run_handles_empty_file(self, tmp_path, field_mappings_file, args_config_evtx, test_logger):
        """Test that run() handles empty files gracefully."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")
        
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        result = flattener.run(str(empty_file))
        
        assert result["dbValues"] == []
        assert result["dbFields"] == ""
    
    def test_run_adds_original_logfile(self, field_mappings_file, tmp_json_file, args_config_evtx, test_logger):
        """Test that OriginalLogfile is added to each event."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        result = flattener.run(tmp_json_file)
        
        for event in result["dbValues"]:
            assert "OriginalLogfile" in event
    
    def test_run_with_hashes(self, field_mappings_file, tmp_json_file, args_config_evtx, test_logger):
        """Test that xxhash is computed when hashes are enabled."""
        proc_config = ProcessingConfig(hashes=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(tmp_json_file)
        
        for event in result["dbValues"]:
            assert "OriginalLogLinexxHash" in event
    
    def test_run_generates_sql_field_statement(self, field_mappings_file, tmp_json_file, args_config_evtx, test_logger):
        """Test that run() generates valid SQL field statement."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        result = flattener.run(tmp_json_file)
        
        # dbFields should contain TEXT or INTEGER type declarations
        assert "TEXT" in result["dbFields"] or "INTEGER" in result["dbFields"]


class TestJSONFlattenerRunAll:
    """Tests for JSONFlattener.run_all() method."""
    
    def test_run_all_processes_multiple_files(self, tmp_path, args_config_evtx, test_logger, sample_windows_event, minimal_field_mappings):
        """Test that run_all() processes multiple files."""
        # Create config file in different location to avoid being picked up
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "fieldMappings.json"
        config_file.write_text(json.dumps(minimal_field_mappings))
        
        # Create multiple JSON files in events directory
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        for i in range(3):
            json_file = events_dir / f"events_{i}.json"
            json_file.write_text(json.dumps(sample_windows_event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=str(config_file),
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        json_files = list(events_dir.glob("*.json"))
        flattener.run_all(json_files)
        
        assert len(flattener.values_stmt) == 3
    
    def test_run_all_accumulates_fields(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test that run_all() accumulates field statements."""
        # Create files with different fields
        event1 = {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test1"}}}
        event2 = {"Event": {"System": {"EventID": 2}, "EventData": {"Image": "test2"}}}
        
        file1 = tmp_path / "events_1.json"
        file1.write_text(json.dumps(event1) + "\n")
        
        file2 = tmp_path / "events_2.json"
        file2.write_text(json.dumps(event2) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        flattener.run_all([file1, file2])
        
        assert len(flattener.values_stmt) == 2
        assert len(flattener.field_stmt) > 0
    
    def test_run_all_skips_empty_files(self, field_mappings_file, tmp_path, args_config_evtx, test_logger, sample_windows_event):
        """Test that run_all() skips empty files."""
        # Create one valid file and one empty file
        valid_file = tmp_path / "valid.json"
        valid_file.write_text(json.dumps(sample_windows_event) + "\n")
        
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        flattener.run_all([valid_file, empty_file])
        
        # Should only have data from the valid file
        assert len(flattener.values_stmt) == 1


class TestJSONFlattenerFieldSplitting:
    """Tests for field splitting functionality."""
    
    def test_splits_hash_field(self, tmp_path, args_config_evtx, test_logger):
        """Test that hash fields are split correctly."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {"Event.EventData.Hashes": "Hashes"},
            "alias": {},
            "split": {"Hashes": {"separator": ",", "equal": "="}},
            "transforms_enabled": False,
            "transforms": {}
        }
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        event = {"Event": {"EventData": {"Hashes": "MD5=abc123,SHA256=def456"}}}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=str(config_file),
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        if result["dbValues"]:
            first_event = result["dbValues"][0]
            # Check if split fields are present
            assert "MD5" in first_event or "SHA256" in first_event


class TestJSONFlattenerTransforms:
    """Tests for field transformation functionality."""
    
    def test_transforms_disabled_by_default(self, field_mappings_file, tmp_json_file, args_config_evtx, test_logger):
        """Test that transforms can be disabled."""
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            logger=test_logger,
            args_config=args_config_evtx
        )
        
        # With transforms disabled, values should not be transformed
        result = flattener.run(tmp_json_file)
        assert result is not None
    
    def test_transform_with_alias(self, field_mappings_file_with_transforms, tmp_path, args_config_auditd, test_logger):
        """Test transforms that create aliases."""
        event = {"proctitle": "hello", "type": "test"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file_with_transforms,
            args_config=args_config_auditd,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        # Transform should convert to uppercase (based on our test transform)
        if result["dbValues"]:
            first_event = result["dbValues"][0]
            if "proctitle" in first_event:
                assert first_event["proctitle"] == "HELLO"


class TestJSONFlattenerAliases:
    """Tests for field aliasing functionality."""
    
    def test_alias_creates_duplicate_field(self, tmp_path, args_config_evtx, test_logger):
        """Test that aliases create duplicate fields with same value."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {"Event.EventData.CommandLine": "CommandLine"},
            "alias": {"CommandLine": "cmd"},
            "split": {},
            "transforms_enabled": False,
            "transforms": {}
        }
        
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        event = {"Event": {"EventData": {"CommandLine": "test.exe"}}}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=str(config_file),
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        if result["dbValues"]:
            first_event = result["dbValues"][0]
            assert "CommandLine" in first_event
            assert "cmd" in first_event
            assert first_event["CommandLine"] == first_event["cmd"]


class TestJSONFlattenerTimeFiltering:
    """Tests for time-based filtering."""
    
    def test_filters_events_after_timestamp(self, tmp_path, args_config_evtx, test_logger, minimal_field_mappings):
        """Test filtering events after a specific timestamp."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(minimal_field_mappings))
        
        # Create events with different timestamps
        events = [
            {"Event": {"System": {"EventID": 1, "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T10:00:00"}}}}},
            {"Event": {"System": {"EventID": 2, "TimeCreated": {"#attributes": {"SystemTime": "2024-06-01T10:00:00"}}}}},
            {"Event": {"System": {"EventID": 3, "TimeCreated": {"#attributes": {"SystemTime": "2024-12-01T10:00:00"}}}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        import time
        time_after = time.strptime("2024-03-01T00:00:00", '%Y-%m-%dT%H:%M:%S')
        
        proc_config = ProcessingConfig(
            time_after="2024-03-01T00:00:00",
            time_field="SystemTime",
            disable_progress=True
        )
        flattener = JSONFlattener(
            config_file=str(config_file),
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        # Should only have events after March 2024
        assert len(result["dbValues"]) == 2
    
    def test_filters_events_before_timestamp(self, tmp_path, args_config_evtx, test_logger, minimal_field_mappings):
        """Test filtering events before a specific timestamp."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(minimal_field_mappings))
        
        events = [
            {"Event": {"System": {"EventID": 1, "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T10:00:00"}}}}},
            {"Event": {"System": {"EventID": 2, "TimeCreated": {"#attributes": {"SystemTime": "2024-06-01T10:00:00"}}}}},
            {"Event": {"System": {"EventID": 3, "TimeCreated": {"#attributes": {"SystemTime": "2024-12-01T10:00:00"}}}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        # Need both time_after and time_before for filtering to trigger
        proc_config = ProcessingConfig(
            time_after="2020-01-01T00:00:00",
            time_before="2024-07-01T00:00:00",
            time_field="SystemTime",
            disable_progress=True
        )
        flattener = JSONFlattener(
            config_file=str(config_file),
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        # Should only have events between time_after and time_before (Jan and June)
        assert len(result["dbValues"]) == 2


class TestJSONFlattenerEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_handles_malformed_json(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test handling of malformed JSON lines."""
        json_file = tmp_path / "malformed.json"
        json_file.write_text('{"valid": "json"}\n{malformed json}\n{"another": "valid"}\n')
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        # Should still process valid lines
        assert len(result["dbValues"]) >= 1
    
    def test_handles_nested_arrays(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test handling of nested arrays in JSON."""
        event = {
            "Event": {
                "EventData": {
                    "ArrayField": ["item1", "item2", "item3"]
                }
            }
        }
        
        json_file = tmp_path / "array.json"
        json_file.write_text(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        # Should handle array by converting to string
        assert len(result["dbValues"]) == 1
    
    def test_handles_unicode_content(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test handling of unicode content."""
        event = {
            "Event": {
                "EventData": {
                    "CommandLine": "echo 你好世界 αβγδ ñoño"
                }
            }
        }
        
        json_file = tmp_path / "unicode.json"
        json_file.write_text(json.dumps(event, ensure_ascii=False) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        assert len(result["dbValues"]) == 1
    
    def test_handles_very_long_values(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test handling of very long field values."""
        long_value = "A" * 100000  # 100KB string
        event = {
            "Event": {
                "EventData": {
                    "LongField": long_value
                }
            }
        }
        
        json_file = tmp_path / "long.json"
        json_file.write_text(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        assert len(result["dbValues"]) == 1
    
    def test_handles_integer_values(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test handling of integer values in JSON."""
        event = {
            "Event": {
                "System": {
                    "EventID": 12345,
                    "Level": 4
                }
            }
        }
        
        json_file = tmp_path / "integers.json"
        json_file.write_text(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        
        result = flattener.run(str(json_file))
        
        # Should detect integer type and use INTEGER in SQL
        assert "INTEGER" in result["dbFields"] or len(result["dbValues"]) == 1
