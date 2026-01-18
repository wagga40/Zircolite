"""
Tests for the StreamingEventProcessor class.
"""

import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import StreamingEventProcessor, ZircoliteCore, ProcessingConfig


class TestStreamingEventProcessorInit:
    """Tests for StreamingEventProcessor initialization."""
    
    def test_init_basic(self, field_mappings_file, test_logger, default_args_config):
        """Test basic initialization."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        assert processor.config_file == field_mappings_file
        assert processor.batch_size == 5000
        assert processor.hashes is False
    
    def test_init_with_custom_batch_size(self, field_mappings_file, test_logger, default_args_config):
        """Test initialization with custom batch size."""
        proc_config = ProcessingConfig(batch_size=1000)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        
        assert processor.batch_size == 1000
    
    def test_init_with_time_filters(self, field_mappings_file, test_logger, default_args_config):
        """Test initialization with time filters."""
        proc_config = ProcessingConfig(
            time_after="2024-01-01T00:00:00",
            time_before="2024-12-31T23:59:59"
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        
        assert processor._has_time_filter is True
        assert processor._time_after_parsed is not None
        assert processor._time_before_parsed is not None
    
    def test_init_with_hashes(self, field_mappings_file, test_logger, default_args_config):
        """Test initialization with hash generation enabled."""
        proc_config = ProcessingConfig(hashes=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        
        assert processor.hashes is True
    
    def test_config_loaded(self, field_mappings_file, test_logger, default_args_config):
        """Test that configuration is properly loaded."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        assert processor.field_exclusions is not None
        assert processor.field_mappings is not None
        assert processor.useless_values is not None


class TestStreamingEventProcessorFlattening:
    """Tests for event flattening functionality."""
    
    def test_flatten_simple_event(self, field_mappings_file, test_logger, default_args_config, sample_windows_event):
        """Test flattening a simple Windows event."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        flattened = processor._flatten_event(sample_windows_event, "test.evtx")
        
        assert flattened is not None
        assert "OriginalLogfile" in flattened
        assert flattened["OriginalLogfile"] == "test.evtx"
        assert "EventID" in flattened or "eventid" in flattened.keys()
    
    def test_flatten_tracks_fields(self, field_mappings_file, test_logger, default_args_config, sample_windows_event):
        """Test that flattening tracks discovered fields."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        # Initially empty
        assert len(processor.discovered_fields) == 0
        
        processor._flatten_event(sample_windows_event, "test.evtx")
        
        # Should have discovered fields
        assert len(processor.discovered_fields) > 0
        assert len(processor.field_types) > 0
    
    def test_flatten_with_hash(self, field_mappings_file, test_logger, default_args_config, sample_windows_event):
        """Test flattening with hash generation."""
        proc_config = ProcessingConfig(hashes=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        
        raw_bytes = json.dumps(sample_windows_event).encode('utf-8')
        flattened = processor._flatten_event(sample_windows_event, "test.evtx", raw_bytes)
        
        assert "OriginalLogLinexxHash" in flattened
    
    def test_flatten_excludes_fields(self, field_mappings_file, test_logger, default_args_config):
        """Test that excluded fields are not included."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        # Event with xmlns field (should be excluded)
        event = {
            "Event": {
                "#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
                "System": {"EventID": 1}
            }
        }
        
        flattened = processor._flatten_event(event, "test.evtx")
        
        # xmlns should not appear in flattened output
        for key in flattened.keys():
            assert "xmlns" not in key.lower()


class TestStreamingEventProcessorSchemaGeneration:
    """Tests for SQL schema generation."""
    
    def test_get_field_statement(self, field_mappings_file, test_logger, default_args_config, sample_windows_event):
        """Test SQL field statement generation."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        # Flatten an event to populate field_types
        processor._flatten_event(sample_windows_event, "test.evtx")
        
        field_stmt = processor.get_field_statement()
        
        assert len(field_stmt) > 0
        assert "TEXT COLLATE NOCASE" in field_stmt or "INTEGER" in field_stmt
    
    def test_create_initial_table(self, field_mappings_file, test_logger, default_args_config):
        """Test initial table creation."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        
        # Verify table exists
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        result = cursor.fetchone()
        
        assert result is not None
        assert result[0] == 'logs'
        
        conn.close()


class TestStreamingEventProcessorJSONStreaming:
    """Tests for JSON file streaming."""
    
    def test_stream_json_events(self, field_mappings_file, test_logger, default_args_config, tmp_json_file):
        """Test streaming events from a JSON file."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        events = list(processor.stream_json_events(tmp_json_file, json_array=False))
        
        assert len(events) > 0
        assert "OriginalLogfile" in events[0]
    
    def test_stream_json_array_events(self, field_mappings_file, test_logger, default_args_config, tmp_json_array_file):
        """Test streaming events from a JSON array file."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        events = list(processor.stream_json_events(tmp_json_array_file, json_array=True))
        
        assert len(events) > 0
    
    def test_stream_json_multiple_events(self, field_mappings_file, test_logger, default_args_config, tmp_json_file_multiple):
        """Test streaming multiple events from a JSONL file."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        events = list(processor.stream_json_events(tmp_json_file_multiple, json_array=False))
        
        # Should have 3 events from sample_windows_events_list
        assert len(events) == 3


class TestStreamingEventProcessorDatabaseInsertion:
    """Tests for database insertion during streaming."""
    
    def test_process_file_streaming_json(self, field_mappings_file, test_logger, default_args_config, tmp_json_file_multiple):
        """Test processing a JSON file with streaming into database."""
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        
        event_count = processor.process_file_streaming(
            conn,
            tmp_json_file_multiple,
            input_type='json',
            json_array=False
        )
        
        assert event_count == 3
        
        # Verify data in database
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        db_count = cursor.fetchone()[0]
        
        assert db_count == 3
        
        conn.close()
    
    def test_batch_insertion(self, field_mappings_file, test_logger, default_args_config, tmp_path):
        """Test batch insertion with multiple events."""
        proc_config = ProcessingConfig(batch_size=2, disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        
        # Create a file with 5 events
        events = [
            {"Event": {"System": {"EventID": i}, "EventData": {"Value": f"test{i}"}}}
            for i in range(5)
        ]
        
        json_file = tmp_path / "batch_test.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        
        event_count = processor.process_file_streaming(
            conn,
            str(json_file),
            input_type='json',
            json_array=False
        )
        
        assert event_count == 5
        
        # Verify all events were inserted
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        db_count = cursor.fetchone()[0]
        
        assert db_count == 5
        
        conn.close()


class TestZircoliteCoreRunStreaming:
    """Tests for ZircoliteCore.run_streaming() method."""
    
    def test_run_streaming_json_input(self, field_mappings_file, test_logger, default_args_config, tmp_json_file_multiple):
        """Test run_streaming with JSON input."""
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        
        total_events = zircore.run_streaming(
            [tmp_json_file_multiple],
            input_type='json',
            args_config=default_args_config,
            disable_progress=True
        )
        
        assert total_events == 3
        
        # Verify data in database
        results = zircore.execute_select_query("SELECT COUNT(*) as cnt FROM logs")
        assert results[0]['cnt'] == 3
        
        zircore.close()
    
    def test_run_streaming_creates_index(self, field_mappings_file, test_logger, default_args_config, tmp_json_file):
        """Test that run_streaming creates indexes."""
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        
        zircore.run_streaming(
            [tmp_json_file],
            input_type='json',
            args_config=default_args_config,
            disable_progress=True
        )
        
        # Verify index exists
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_eventid'")
        result = cursor.fetchone()
        
        assert result is not None
        
        zircore.close()
    
    def test_run_streaming_multiple_files(self, field_mappings_file, test_logger, default_args_config, tmp_path):
        """Test run_streaming with multiple files."""
        # Create two JSON files
        created_files = []
        for i in range(2):
            events = [
                {"Event": {"System": {"EventID": j}, "EventData": {"Value": f"file{i}_event{j}"}}}
                for j in range(3)
            ]
            json_file = tmp_path / f"test_file_{i}.json"
            with open(json_file, 'w') as f:
                for event in events:
                    f.write(json.dumps(event) + "\n")
            created_files.append(json_file)
        
        # Use explicit file list to avoid picking up fieldMappings.json from tmp_path
        json_files = created_files
        
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        
        total_events = zircore.run_streaming(
            json_files,
            input_type='json',
            args_config=default_args_config,
            disable_progress=True
        )
        
        assert total_events == 6  # 2 files × 3 events each
        
        zircore.close()
    
    def test_run_streaming_then_execute_ruleset(self, field_mappings_file, test_logger, default_args_config, sample_ruleset, tmp_path):
        """Test that run_streaming works with rule execution."""
        # Create a JSON file with matching events
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe whoami"}}},
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "notepad.exe"}}},
        ]
        
        json_file = tmp_path / "test_events.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        
        # Run streaming
        zircore.run_streaming(
            [str(json_file)],
            input_type='json',
            args_config=default_args_config,
            disable_progress=True
        )
        
        # Load and execute rules
        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)
        
        output_file = str(tmp_path / "output.json")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)
        
        # Verify output
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            results = json.load(f)
        
        # Should have at least one detection (powershell rule)
        assert len(results) > 0
        
        zircore.close()
    
    def test_run_streaming_empty_file(self, field_mappings_file, test_logger, default_args_config, tmp_path):
        """Test run_streaming with an empty file."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")
        
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        
        total_events = zircore.run_streaming(
            [str(empty_file)],
            input_type='json',
            args_config=default_args_config,
            disable_progress=True
        )
        
        assert total_events == 0
        
        zircore.close()


class TestStreamingEventProcessorTransforms:
    """Tests for transform functionality in streaming mode."""
    
    def test_transform_value(self, field_mappings_file_with_transforms, test_logger, args_config_auditd):
        """Test that transforms are applied during streaming."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_with_transforms,
            args_config=args_config_auditd,
            logger=test_logger
        )
        
        # Test transform function
        result = processor._transform_value(
            "def transform(param):\n\treturn param.upper()",
            "hello"
        )
        
        assert result == "HELLO"
    
    def test_get_transform_func_caching(self, field_mappings_file_with_transforms, test_logger, args_config_auditd):
        """Test that transform functions are cached."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_with_transforms,
            args_config=args_config_auditd,
            logger=test_logger
        )
        
        code = "def transform(param):\n\treturn param.upper()"
        
        # First call - compiles and caches
        func1 = processor._get_transform_func(code)
        
        # Second call - should return cached function
        func2 = processor._get_transform_func(code)
        
        assert func1 is func2  # Same object (cached)


class TestStreamingEventProcessorCSV:
    """Tests for CSV file streaming."""
    
    def test_stream_csv_events(self, field_mappings_file, test_logger, default_args_config, tmp_csv_file):
        """Test streaming events from a CSV file."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        events = list(processor.stream_csv_events(tmp_csv_file))
        
        assert len(events) == 3  # 3 data rows in the CSV
        assert "OriginalLogfile" in events[0]
        assert "EventID" in events[0]
    
    def test_stream_csv_preserves_fields(self, field_mappings_file, test_logger, default_args_config, tmp_csv_file):
        """Test that CSV streaming preserves all fields."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        events = list(processor.stream_csv_events(tmp_csv_file))
        
        # Check that expected fields are present
        first_event = events[0]
        assert "Channel" in first_event
        assert "Computer" in first_event
    
    def test_process_file_streaming_csv(self, field_mappings_file, test_logger, default_args_config, tmp_csv_file):
        """Test processing a CSV file with streaming into database."""
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        
        event_count = processor.process_file_streaming(
            conn,
            tmp_csv_file,
            input_type='csv'
        )
        
        assert event_count == 3
        
        # Verify data in database
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        db_count = cursor.fetchone()[0]
        
        assert db_count == 3
        
        conn.close()


class TestStreamingEventProcessorJSONArrayChunked:
    """Tests for chunked JSON array streaming."""
    
    def test_stream_json_array_chunked_small_file(self, field_mappings_file, test_logger, default_args_config, tmp_json_array_file):
        """Test chunked streaming with a small JSON array file."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        events = list(processor.stream_json_array_chunked(tmp_json_array_file))
        
        # Should have 3 events from sample_windows_events_list
        assert len(events) == 3
        assert "OriginalLogfile" in events[0]
    
    def test_process_file_streaming_json_array_chunked(self, field_mappings_file, test_logger, default_args_config, tmp_json_array_file):
        """Test processing a JSON array file with chunked streaming into database."""
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        
        event_count = processor.process_file_streaming(
            conn,
            tmp_json_array_file,
            input_type='json',
            json_array=True,
            use_chunked_json=True
        )
        
        assert event_count == 3
        
        # Verify data in database
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        db_count = cursor.fetchone()[0]
        
        assert db_count == 3
        
        conn.close()


class TestStreamingEventProcessorMemoryEfficiency:
    """Tests for memory efficiency of streaming operations."""
    
    def test_batch_processing_memory(self, field_mappings_file, test_logger, default_args_config, tmp_path):
        """Test that batch processing doesn't accumulate memory excessively."""
        proc_config = ProcessingConfig(batch_size=100, disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        
        # Create a file with many events
        events = [
            {"Event": {"System": {"EventID": i}, "EventData": {"Value": f"test{i}"}}}
            for i in range(500)
        ]
        
        json_file = tmp_path / "large_test.json"
        with open(json_file, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        
        event_count = processor.process_file_streaming(
            conn,
            str(json_file),
            input_type='json',
            json_array=False
        )
        
        assert event_count == 500
        
        # Verify all events were inserted
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        db_count = cursor.fetchone()[0]
        
        assert db_count == 500
        
        conn.close()
    
    def test_generator_based_streaming(self, field_mappings_file, test_logger, default_args_config, tmp_json_file_multiple):
        """Test that streaming uses generators for memory efficiency."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )
        
        # Get stream - should be a generator, not a list
        stream = processor.stream_json_events(tmp_json_file_multiple, json_array=False)
        
        # Verify it's a generator
        import types
        assert isinstance(stream, types.GeneratorType)
        
        # Consume generator
        events = list(stream)
        assert len(events) == 3
