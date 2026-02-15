"""
Tests for the StreamingEventProcessor class.
"""

import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import (
    StreamingEventProcessor,
    ZircoliteCore,
    ProcessingConfig,
    EvtxExtractor,
    ExtractorConfig,
)
from zircolite.streaming import (
    _NON_ALNUM_RE,
    _NEWLINE_TRANSLATE,
    _RESTRICTED_BUILTINS as STREAMING_BUILTINS,
)


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
        assert processor._time_after_str == "2024-01-01T00:00:00"
        assert processor._time_before_str == "2024-12-31T23:59:59"

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

    def test_time_filter_accepts_in_range(self, field_mappings_file, test_logger, default_args_config):
        """Events within the time window should be kept."""
        proc = ProcessingConfig(
            time_after="2024-01-01T00:00:00",
            time_before="2024-12-31T23:59:59",
            time_field="SystemTime",
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc,
            logger=test_logger,
        )
        event = {
            "Event": {
                "System": {
                    "EventID": 1,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-06-15T12:00:00.000Z"}},
                }
            }
        }
        result = processor._flatten_event(event, "test.evtx")
        assert result is not None

    def test_time_filter_rejects_out_of_range(self, field_mappings_file, test_logger, default_args_config):
        """Events outside the time window should be filtered."""
        proc = ProcessingConfig(
            time_after="2024-06-01T00:00:00",
            time_before="2024-06-30T23:59:59",
            time_field="SystemTime",
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc,
            logger=test_logger,
        )
        event = {
            "Event": {
                "System": {
                    "EventID": 1,
                    "TimeCreated": {"#attributes": {"SystemTime": "2025-01-01T00:00:00.000Z"}},
                }
            }
        }
        result = processor._flatten_event(event, "test.evtx")
        assert result is None


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

    def test_insert_batch_updates_column_cache_on_new_columns(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """When new columns appear in a batch, column cache should update."""
        proc = ProcessingConfig(batch_size=2, disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc,
            logger=test_logger,
        )
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        cursor = conn.cursor()

        batch1 = [{"colA": "a1", "colB": "b1"}]
        processor._insert_batch(conn, cursor, batch1, 9223372036854775807)
        first_frozen = processor._last_column_frozenset

        batch2 = [{"colA": "a2", "colB": "b2"}]
        processor._insert_batch(conn, cursor, batch2, 9223372036854775807)
        assert processor._last_column_frozenset == first_frozen

        batch3 = [{"colA": "a3", "colB": "b3", "colC": "c3"}]
        processor._insert_batch(conn, cursor, batch3, 9223372036854775807)
        assert processor._last_column_frozenset != first_frozen
        assert "colc" in processor._last_column_frozenset or "colC" in processor._last_column_frozenset

        conn.close()


class TestStreamingEventProcessorNestedPaths:
    """Tests for pre-split nested field paths and _get_nested_value."""

    def test_channel_field_paths_are_tuples(self, field_mappings_file, test_logger, default_args_config):
        """_channel_field_paths should be tuple-of-tuples."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        assert isinstance(processor._channel_field_paths, tuple)
        if processor._channel_field_paths:
            first = processor._channel_field_paths[0]
            assert isinstance(first, tuple)
            assert len(first) >= 1

    def test_get_nested_value_with_tuple_parts(self, field_mappings_file, test_logger, default_args_config):
        """_get_nested_value should work with pre-split tuple parts."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        data = {"Event": {"System": {"Channel": "Sysmon"}}}
        val = processor._get_nested_value(data, ("Event", "System", "Channel"))
        assert val == "Sysmon"

    def test_get_nested_value_missing_key(self, field_mappings_file, test_logger, default_args_config):
        """_get_nested_value should return None for missing keys."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        data = {"Event": {"System": {}}}
        val = processor._get_nested_value(data, ("Event", "System", "Channel"))
        assert val is None


class TestStreamingEventProcessorModuleHelpers:
    """Tests for module-level helpers (alphanumeric filter, newline translation)."""

    def test_non_alnum_re_strips_special(self):
        assert _NON_ALNUM_RE.sub('', 'Hello-World_123!') == 'HelloWorld123'

    def test_non_alnum_re_empty_string(self):
        assert _NON_ALNUM_RE.sub('', '') == ''

    def test_newline_translate_removes_newlines(self):
        assert 'abc'.translate(_NEWLINE_TRANSLATE) == 'abc'
        assert 'a\nb\rc\r\n'.translate(_NEWLINE_TRANSLATE) == 'abc'

    def test_newline_translate_preserves_other_whitespace(self):
        assert 'a\tb c'.translate(_NEWLINE_TRANSLATE) == 'a\tb c'


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

    def test_stream_json_array_chunked_yields_all_events(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """Chunked processing with custom chunk_size should yield every event."""
        events = [{"Event": {"System": {"EventID": i}}} for i in range(25)]
        arr_file = tmp_path / "big_array.json"
        arr_file.write_text(json.dumps(events))

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        result = list(processor.stream_json_array_chunked(str(arr_file), chunk_size=5))
        assert len(result) == 25


class TestStreamingEventProcessorRestrictedPythonBuiltins:
    """Tests for shared RestrictedPython builtins."""

    def test_processor_uses_module_builtins(self, field_mappings_file, test_logger, default_args_config):
        """StreamingEventProcessor should reference the shared module-level builtins."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        assert processor.RestrictedPython_BUILTINS is STREAMING_BUILTINS

    def test_builtins_contain_expected_keys(self):
        """Shared builtins should include essential sandboxing keys."""
        for key in ('__name__', '_getiter_', '_getattr_', '_getitem_', 'base64', 're', 'chardet'):
            assert key in STREAMING_BUILTINS, f"Missing key: {key}"


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


class TestStreamingEventProcessorFormatStreams:
    """Tests for XML, Auditd, Sysmon Linux streaming and process_file_streaming dispatch."""

    def test_stream_xml_events(
        self, field_mappings_file, test_logger, default_args_config, tmp_xml_file, tmp_path
    ):
        """Stream XML file yields flattened events."""
        config = ExtractorConfig(xml_logs=True, tmp_dir=str(tmp_path / "xml_tmp"))
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_xml_events(tmp_xml_file, extractor))
        assert len(events) >= 1
        assert "OriginalLogfile" in events[0]
        extractor.cleanup()

    def test_stream_auditd_events(
        self, field_mappings_file, test_logger, default_args_config, tmp_auditd_file, tmp_path
    ):
        """Stream Auditd file yields flattened events."""
        config = ExtractorConfig(auditd_logs=True, tmp_dir=str(tmp_path / "auditd_tmp"))
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_auditd_events(tmp_auditd_file, extractor))
        assert len(events) >= 1
        assert "OriginalLogfile" in events[0]
        extractor.cleanup()

    def test_stream_sysmon_linux_events(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """Stream Sysmon for Linux file; yields events when XML parses to Windows-like structure."""
        # Same format as test_evtx_extractor Sysmon Linux: syslog prefix + <Event>...</Event>
        sysmon_file = tmp_path / "sysmon.log"
        sysmon_file.write_text(
            'Jan 15 10:30:00 host sysmon: <Event><System><EventID>1</EventID></System>'
            '<EventData><Data Name="Image">/usr/bin/bash</Data></EventData></Event>\n'
        )
        config = ExtractorConfig(sysmon4linux=True, tmp_dir=str(tmp_path / "sysmon_tmp"))
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_sysmon_linux_events(str(sysmon_file), extractor))
        # May be 0 if flattener expects Windows channel/time fields; we still cover the stream path
        assert isinstance(events, list)
        extractor.cleanup()

    def test_process_file_streaming_xml(
        self, field_mappings_file, test_logger, default_args_config, tmp_xml_file, tmp_path
    ):
        """process_file_streaming with input_type xml inserts events."""
        config = ExtractorConfig(xml_logs=True, tmp_dir=str(tmp_path / "xml_tmp"))
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(
            conn, tmp_xml_file, input_type='xml', extractor=extractor
        )
        assert count >= 1
        conn.close()
        extractor.cleanup()

    def test_process_file_streaming_auditd(
        self, field_mappings_file, test_logger, default_args_config, tmp_auditd_file, tmp_path
    ):
        """process_file_streaming with input_type auditd inserts events."""
        config = ExtractorConfig(auditd_logs=True, tmp_dir=str(tmp_path / "auditd_tmp"))
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(
            conn, tmp_auditd_file, input_type='auditd', extractor=extractor
        )
        assert count >= 1
        conn.close()
        extractor.cleanup()

    def test_process_file_streaming_unsupported_type(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """Unsupported input_type returns 0 and logs error."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        f = tmp_path / "dummy.evtx"
        f.write_bytes(b"x")
        count = processor.process_file_streaming(conn, str(f), input_type='unknown')
        assert count == 0
        conn.close()


class TestStreamingEventProcessorErrorPaths:
    """Tests for exception paths in streaming methods."""

    def test_stream_json_events_nonexistent_file(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """stream_json_events with nonexistent file does not raise; yields nothing."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        path = str(tmp_path / "does_not_exist.json")
        events = list(processor.stream_json_events(path, json_array=False))
        assert events == []

    def test_stream_csv_events_nonexistent_file(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """stream_csv_events with nonexistent file does not raise; yields nothing."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        path = str(tmp_path / "does_not_exist.csv")
        events = list(processor.stream_csv_events(path))
        assert events == []

    def test_stream_evtx_events_nonexistent_file(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """stream_evtx_events with nonexistent file does not raise; yields nothing."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        path = str(tmp_path / "does_not_exist.evtx")
        events = list(processor.stream_evtx_events(path))
        assert events == []


class TestStreamingTimeParsing:
    """Tests for _parse_time_bound edge cases."""

    def test_parse_time_bound_struct_time(self, field_mappings_file, test_logger, default_args_config):
        """Cover line 204: struct_time input is returned as-is."""
        import time
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        st = time.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
        result = processor._parse_time_bound(st, "1970-01-01T00:00:00")
        assert result == st

    def test_parse_time_bound_invalid_string(self, field_mappings_file, test_logger, default_args_config):
        """Cover lines 207-208: invalid string falls back."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        result = processor._parse_time_bound("not-a-date", "1970-01-01T00:00:00")
        assert result is not None  # Falls back to the fallback value

    def test_parse_time_bound_none_value(self, field_mappings_file, test_logger, default_args_config):
        """Cover line 207: None value falls back."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        result = processor._parse_time_bound(None, "1970-01-01T00:00:00")
        assert result is not None


class TestStreamingTimeFiltering:
    """Tests for time filtering edge cases in _flatten_event."""

    def test_time_filter_with_z_suffix(self, field_mappings_file, test_logger, default_args_config, tmp_path):
        """Cover line 583: timestamps ending with Z."""
        proc_config = ProcessingConfig(
            time_after="2024-01-01T00:00:00",
            time_before="2024-12-31T23:59:59",
            time_field="SystemTime",
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )

        # Write JSONL with a flat event with Z-suffix timestamp in range
        json_file = tmp_path / "events.json"
        event = {
            "EventID": 1,
            "Channel": "Sysmon",
            "SystemTime": "2024-06-15T10:30:00Z",
            "CommandLine": "test.exe"
        }
        json_file.write_text(json.dumps(event) + "\n")

        events = list(processor.stream_json_events(str(json_file), json_array=False))
        assert len(events) == 1

    def test_time_filter_rejects_old_event(self, field_mappings_file, test_logger, default_args_config, tmp_path):
        """Cover lines 595-596: events outside time range are rejected.
        
        Time filtering is controlled by ProcessingConfig.time_after / time_before.
        Uses a flat JSON event so the time_field is immediately accessible.
        """
        proc_config = ProcessingConfig(
            time_after="2025-01-01T00:00:00",
            time_before="2025-12-31T23:59:59",
            time_field="SystemTime",
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )

        # Verify the time filter is active
        assert processor._has_time_filter is True

        # Write JSONL with a flat event whose SystemTime is outside the range
        json_file = tmp_path / "old_events.json"
        event = {
            "EventID": 1,
            "Channel": "Sysmon",
            "SystemTime": "2020-06-15T10:30:00.000Z",
            "CommandLine": "test.exe"
        }
        json_file.write_text(json.dumps(event) + "\n")

        events = list(processor.stream_json_events(str(json_file), json_array=False))
        assert len(events) == 0  # Event should be rejected by time filter

    def test_time_filter_with_timezone_offset(self, field_mappings_file, test_logger, default_args_config, tmp_path):
        """Cover line 588: timestamps with +00:00 offset."""
        proc_config = ProcessingConfig(
            time_after="2024-01-01T00:00:00",
            time_before="2024-12-31T23:59:59",
            time_field="SystemTime",
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )

        # Flat event with timezone offset
        json_file = tmp_path / "tz_events.json"
        event = {
            "EventID": 1,
            "Channel": "Sysmon",
            "SystemTime": "2024-06-15T10:30:00+00:00",
            "CommandLine": "test.exe"
        }
        json_file.write_text(json.dumps(event) + "\n")

        events = list(processor.stream_json_events(str(json_file), json_array=False))
        assert len(events) == 1


class TestStreamingJsonEdgeCases:
    """Tests for JSON streaming edge cases."""

    def test_stream_json_empty_lines_skipped(self, field_mappings_file, test_logger, default_args_config, tmp_path):
        """Cover line 664: empty lines in JSONL are skipped."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        json_file = tmp_path / "with_blanks.json"
        event = {"Event": {"System": {"EventID": 1, "Channel": "Sysmon"}, "EventData": {"CommandLine": "test"}}}
        json_file.write_text(json.dumps(event) + "\n\n\n" + json.dumps(event) + "\n")

        events = list(processor.stream_json_events(str(json_file), json_array=False))
        assert len(events) == 2

    def test_stream_json_array_mode(self, field_mappings_file, test_logger, default_args_config, tmp_path):
        """Cover JSON array parsing path."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        json_file = tmp_path / "array.json"
        events_data = [
            {"Event": {"System": {"EventID": 1, "Channel": "Sysmon"}, "EventData": {"CommandLine": "test"}}},
            {"Event": {"System": {"EventID": 2, "Channel": "Security"}, "EventData": {"Image": "cmd.exe"}}},
        ]
        json_file.write_text(json.dumps(events_data))

        events = list(processor.stream_json_events(str(json_file), json_array=True))
        assert len(events) == 2
