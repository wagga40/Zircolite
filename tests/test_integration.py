"""
Integration tests for Zircolite.

These tests verify end-to-end workflows and component interactions.
"""

import json
import os
import pytest
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import (
    JSONFlattener,
    ZircoliteCore,
    EvtxExtractor,
    TemplateEngine,
    ProcessingConfig,
    ExtractorConfig,
    TemplateConfig,
)


class TestFullPipelineJSON:
    """Integration tests for complete JSON processing pipeline."""
    
    def test_json_to_detection(self, field_mappings_file, sample_ruleset, tmp_path, args_config_evtx, test_logger):
        """Test complete pipeline: JSON file -> flattening -> detection."""
        # Create sample JSON events file
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe -c whoami", "Image": "C:\\powershell.exe"}}},
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "cmd.exe /c dir", "Image": "C:\\cmd.exe"}}},
            {"Event": {"System": {"EventID": 11}, "EventData": {"TargetFilename": "C:\\malware.exe", "Image": "C:\\explorer.exe"}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        # Step 1: Flatten JSON
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        assert len(result["dbValues"]) == 3
        
        # Step 2: Create ZircoliteCore and insert data
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        zircore.create_db(result["dbFields"])
        zircore.insert_flattened_json_to_db(result["dbValues"])
        
        # Step 3: Load and execute ruleset
        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)
        
        output_file = str(tmp_path / "detections.json")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)
        
        # Verify detections
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        # Should have at least one detection
        assert len(detections) >= 1
        
        # Check for expected detections
        titles = [d["title"] for d in detections]
        assert any("PowerShell" in t for t in titles)
        
        zircore.close()
    
    def test_json_array_to_detection(self, field_mappings_file, sample_ruleset, tmp_path, default_args_config, test_logger):
        """Test pipeline with JSON array input."""
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe test"}}},
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "whoami"}}},
        ]
        
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(events))
        
        # Configure for JSON array input
        default_args_config.json_array_input = True
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        assert len(result["dbValues"]) == 2
        
        # Process through ZircoliteCore
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        zircore.create_db(result["dbFields"])
        zircore.insert_flattened_json_to_db(result["dbValues"])
        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)
        
        output_file = str(tmp_path / "detections.json")
        zircore.execute_ruleset(output_file, write_mode='w', keep_results=True, last_ruleset=True)
        
        # Should have detections
        assert len(zircore.full_results) >= 1
        
        zircore.close()


class TestFullPipelineCSV:
    """Integration tests for CSV input processing."""
    
    def test_csv_to_detection(self, tmp_path, test_logger, minimal_field_mappings, sample_ruleset, default_args_config):
        """Test complete pipeline with CSV input."""
        # Create config file
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(minimal_field_mappings))
        
        # Create CSV file
        csv_file = tmp_path / "events.csv"
        csv_content = """EventID,CommandLine,Image,Computer
1,powershell.exe -encodedCommand abc,C:\\Windows\\powershell.exe,PC1
1,whoami,C:\\Windows\\cmd.exe,PC1
3,,C:\\Windows\\firefox.exe,PC2
"""
        csv_file.write_text(csv_content)
        
        # Extract CSV to JSON
        ext_config = ExtractorConfig(csv_input=True)
        extractor = EvtxExtractor(
            extractor_config=ext_config,
            logger=test_logger
        )
        extractor.run(str(csv_file))
        
        # Get the converted JSON file
        json_files = list(Path(extractor.tmpDir).glob("*.json"))
        assert len(json_files) == 1
        
        # Flatten and process
        default_args_config.csv_input = True
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=str(config_file),
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_files[0]))
        
        assert len(result["dbValues"]) == 3
        
        extractor.cleanup()


class TestFullPipelineAuditd:
    """Integration tests for Auditd log processing."""
    
    def test_auditd_to_detection(self, tmp_path, test_logger, default_args_config):
        """Test processing Auditd logs."""
        # Create auditd log file
        auditd_file = tmp_path / "audit.log"
        auditd_content = """type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e syscall=59 success=yes exit=0 pid=5678 uid=0 comm="bash" exe="/bin/bash"
type=SYSCALL msg=audit(1705318201.456:457): arch=c000003e syscall=59 success=yes exit=0 pid=5679 uid=0 comm="ls" exe="/bin/ls"
type=SYSCALL msg=audit(1705318202.789:458): arch=c000003e syscall=59 success=yes exit=0 pid=5680 uid=0 comm="curl" exe="/usr/bin/curl"
"""
        auditd_file.write_text(auditd_content)
        
        # Extract to JSON
        ext_config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(
            extractor_config=ext_config,
            logger=test_logger
        )
        extractor.run(str(auditd_file))
        
        # Get converted JSON
        json_files = list(Path(extractor.tmpDir).glob("*.json"))
        assert len(json_files) == 1
        
        # Read and verify JSON content
        with open(json_files[0]) as f:
            lines = f.readlines()
        
        assert len(lines) == 3
        
        # Verify JSON structure
        first_event = json.loads(lines[0])
        assert "type" in first_event
        assert first_event["type"] == "SYSCALL"
        assert "timestamp" in first_event
        
        extractor.cleanup()


class TestMultipleFileProcessing:
    """Integration tests for processing multiple files."""
    
    def test_process_multiple_json_files(self, sample_ruleset, tmp_path, args_config_evtx, test_logger, minimal_field_mappings):
        """Test processing multiple JSON files."""
        # Create config file in separate location
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "fieldMappings.json"
        config_file.write_text(json.dumps(minimal_field_mappings))
        
        # Create multiple JSON files in events directory
        events_dir = tmp_path / "events"
        events_dir.mkdir()
        for i in range(3):
            events = [
                {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": f"powershell.exe test{i}"}}}
            ]
            json_file = events_dir / f"events_{i}.json"
            with open(json_file, 'w') as f:
                for event in events:
                    f.write(json.dumps(event) + "\n")
        
        # Process all files (only from events dir to avoid picking up config)
        json_files = list(events_dir.glob("*.json"))
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=str(config_file),
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        flattener.run_all(json_files)
        
        # Should have events from all files
        assert len(flattener.values_stmt) == 3
        
        # Process through ZircoliteCore
        zircore = ZircoliteCore(
            config=str(config_file),
            processing_config=proc_config,
            logger=test_logger
        )
        zircore.create_db(flattener.field_stmt)
        zircore.insert_flattened_json_to_db(flattener.values_stmt)
        
        # Verify all events are in database
        results = zircore.execute_select_query("SELECT COUNT(*) as cnt FROM logs")
        assert results[0]['cnt'] == 3
        
        zircore.close()


class TestDetectionToTemplate:
    """Integration tests for detection to template pipeline."""
    
    def test_detection_to_template_output(self, field_mappings_file, sample_ruleset, tmp_path, args_config_evtx, test_logger):
        """Test generating template output from detections."""
        # Create events
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe whoami"}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        # Process events
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        zircore.create_db(result["dbFields"])
        zircore.insert_flattened_json_to_db(result["dbValues"])
        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)
        
        output_file = str(tmp_path / "detections.json")
        zircore.execute_ruleset(output_file, write_mode='w', keep_results=True, last_ruleset=True)
        
        # Create template
        template_content = """{% for elem in data %}
Alert: {{ elem.title }} ({{ elem.rule_level }})
{% endfor %}"""
        
        template_file = tmp_path / "alert.tmpl"
        template_file.write_text(template_content)
        
        template_output = str(tmp_path / "alerts.txt")
        
        # Generate template output
        tmpl_config = TemplateConfig(
            template=[[str(template_file)]],
            template_output=[[template_output]]
        )
        engine = TemplateEngine(
            template_config=tmpl_config,
            logger=test_logger
        )
        engine.run(zircore.full_results)
        
        # Verify template output
        assert Path(template_output).exists()
        
        with open(template_output) as f:
            content = f.read()
        
        assert "Alert:" in content
        
        zircore.close()


class TestDatabasePersistence:
    """Integration tests for database persistence."""
    
    def test_save_and_load_database(self, field_mappings_file, sample_ruleset, tmp_path, args_config_evtx, test_logger):
        """Test saving database to disk and reloading."""
        # Create and populate database
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe test"}}},
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "whoami"}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        zircore.create_db(result["dbFields"])
        zircore.insert_flattened_json_to_db(result["dbValues"])
        
        # Save to disk
        db_file = str(tmp_path / "events.db")
        zircore.save_db_to_disk(db_file)
        zircore.close()
        
        # Load from disk in new instance
        zircore2 = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        zircore2.load_db_in_memory(db_file)
        
        # Verify data was loaded
        results = zircore2.execute_select_query("SELECT COUNT(*) as cnt FROM logs")
        assert results[0]['cnt'] == 2
        
        # Execute rules on loaded data
        zircore2.load_ruleset_from_var(sample_ruleset, rule_filters=None)
        
        output_file = str(tmp_path / "detections.json")
        zircore2.execute_ruleset(output_file, write_mode='w', last_ruleset=True)
        
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        assert len(detections) >= 1
        
        zircore2.close()


class TestCSVOutput:
    """Integration tests for CSV output."""
    
    def test_json_to_csv_detection(self, field_mappings_file, sample_ruleset, tmp_path, args_config_evtx, test_logger):
        """Test complete pipeline with CSV output."""
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe test"}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        # Use CSV mode
        csv_proc_config = ProcessingConfig(
            disable_progress=True,
            csv_mode=True,
            delimiter=","
        )
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=csv_proc_config,
            logger=test_logger
        )
        zircore.create_db(result["dbFields"])
        zircore.insert_flattened_json_to_db(result["dbValues"])
        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)
        
        output_file = str(tmp_path / "detections.csv")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)
        
        # Verify CSV output
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            content = f.read()
        
        # Should have CSV headers
        assert "rule_title" in content
        assert "rule_description" in content
        assert "rule_level" in content
        
        zircore.close()


class TestRuleFiltering:
    """Integration tests for rule filtering."""
    
    def test_filter_rules_by_title(self, field_mappings_file, sample_ruleset, tmp_path, args_config_evtx, test_logger):
        """Test filtering rules by title during execution."""
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe test"}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        zircore.create_db(result["dbFields"])
        zircore.insert_flattened_json_to_db(result["dbValues"])
        
        # Filter out PowerShell rule
        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=["PowerShell"])
        
        # Verify PowerShell rule was filtered
        assert all("PowerShell" not in rule["title"] for rule in zircore.ruleset)
        
        zircore.close()


class TestTimeFiltering:
    """Integration tests for time-based filtering."""
    
    def test_filter_events_by_time(self, tmp_path, args_config_evtx, test_logger, minimal_field_mappings):
        """Test filtering events by timestamp."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(minimal_field_mappings))
        
        # Create events with different timestamps
        events = [
            {"Event": {"System": {"EventID": 1, "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T10:00:00"}}}, "EventData": {"CommandLine": "old event"}}},
            {"Event": {"System": {"EventID": 1, "TimeCreated": {"#attributes": {"SystemTime": "2024-06-01T10:00:00"}}}, "EventData": {"CommandLine": "middle event"}}},
            {"Event": {"System": {"EventID": 1, "TimeCreated": {"#attributes": {"SystemTime": "2024-12-01T10:00:00"}}}, "EventData": {"CommandLine": "new event"}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        # Filter to only include events after March 2024
        proc_config = ProcessingConfig(
            time_after="2024-03-01T00:00:00",
            time_before="2024-09-01T00:00:00",
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
        
        # Should only have the middle event
        assert len(result["dbValues"]) == 1
        assert "middle" in str(result["dbValues"][0])


class TestHashGeneration:
    """Integration tests for hash generation."""
    
    def test_events_with_hashes(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test that xxhash is computed for events."""
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test1"}}},
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test2"}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(hashes=True, disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        # Each event should have a hash
        for event in result["dbValues"]:
            assert "OriginalLogLinexxHash" in event
            # Hash should be a non-empty string
            assert len(event["OriginalLogLinexxHash"]) > 0


class TestResultLimiting:
    """Integration tests for result limiting."""
    
    def test_limit_high_volume_detections(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test that results over limit are discarded."""
        # Create many matching events
        events = []
        for i in range(100):
            events.append({
                "Event": {
                    "System": {"EventID": 1},
                    "EventData": {"CommandLine": f"powershell.exe test{i}"}
                }
            })
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        # Create ZircoliteCore with limit
        limit_proc_config = ProcessingConfig(limit=10, disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=limit_proc_config,
            logger=test_logger
        )
        zircore.create_db(result["dbFields"])
        zircore.insert_flattened_json_to_db(result["dbValues"])
        
        ruleset = [{
            "title": "High Volume Rule",
            "id": "test",
            "level": "medium",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]
        
        zircore.load_ruleset_from_var(ruleset, rule_filters=None)
        
        output_file = str(tmp_path / "detections.json")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)
        
        # Results should be empty (100 > limit of 10)
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        assert len(detections) == 0
        
        zircore.close()


class TestErrorHandling:
    """Integration tests for error handling."""
    
    def test_handles_malformed_events(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test handling of malformed events in input."""
        # Mix valid and invalid JSON
        content = '''{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "valid1"}}}
{malformed json line
{"Event": {"System": {"EventID": 2}, "EventData": {"CommandLine": "valid2"}}}
'''
        
        json_file = tmp_path / "events.json"
        json_file.write_text(content)
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        # Should have processed valid events
        assert len(result["dbValues"]) >= 1
    
    def test_handles_empty_ruleset(self, field_mappings_file, tmp_path, args_config_evtx, test_logger):
        """Test handling of empty ruleset."""
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test"}}},
        ]
        
        json_file = tmp_path / "events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        flattener = JSONFlattener(
            config_file=field_mappings_file,
            args_config=args_config_evtx,
            processing_config=proc_config,
            logger=test_logger
        )
        result = flattener.run(str(json_file))
        
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        zircore.create_db(result["dbFields"])
        zircore.insert_flattened_json_to_db(result["dbValues"])
        zircore.load_ruleset_from_var([], rule_filters=None)
        
        output_file = str(tmp_path / "detections.json")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)
        
        # Should create empty output
        with open(output_file) as f:
            detections = json.loads(f.read())
        
        assert detections == []
        
        zircore.close()
