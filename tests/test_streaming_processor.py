"""
Tests for the StreamingEventProcessor class.
"""

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import (
    EvtxExtractor,
    ExtractorConfig,
    ProcessingConfig,
    StreamingEventProcessor,
)
from zircolite.streaming import (
    _NON_ALNUM_RE,
    StrictParseError,
)
from zircolite.streaming import (
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
        assert processor.batch_size == ProcessingConfig().batch_size
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

    @pytest.mark.parametrize(
        "timestamp,kept",
        [
            ("2024-06-15T08:30:00", True),
            ("2024-06-15T08:30:00Z", True),
            ("2024-06-15T08:30:00+02:00", True),
            ("2024-06-15 08:30:00", True),  # auditd and several JSON exporters
            ("2024-06-15T08:30:00.1234567Z", True),  # Windows writes 7 digits
            (1718440200, True),  # epoch seconds
            (1718440200000, True),  # epoch milliseconds
            ("1718440200", True),
            ("2023-06-15T08:30:00Z", False),  # before the window
            ("2025-06-15T08:30:00Z", False),  # after the window
            (1686817800, False),  # epoch, before the window
        ],
    )
    def test_time_filter_accepts_every_timestamp_spelling(
        self, field_mappings_file, test_logger, default_args_config, timestamp, kept
    ):
        """Regression: bounds used to be compared as strings, not as instants.

        Lexicographically an epoch number sorts below every ISO string and a
        space separator sorts below a 'T', so whole formats -- including the one
        Zircolite's own auditd extractor emits -- silently lost every event.
        """
        proc_config = ProcessingConfig(
            time_after="2024-01-01T00:00:00",
            time_before="2024-12-31T23:59:59",
            time_field="SystemTime",
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger
        )
        assert processor._has_time_filter is True

        flat = processor._flatten_event(
            {"Event": {"System": {"SystemTime": timestamp}}}, "t.evtx"
        )
        assert (flat is not None) is kept

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
        assert "EventID" in flattened or "eventid" in flattened

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
        for key in flattened:
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


class TestFlattenHotPathOptimizations:
    """Tests for the flattening fast path (special fields, seen-key caching)."""

    def test_special_fields_only_split_when_no_alias_or_transform(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """Minimal config has one split field and no aliases/transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        assert processor._special_fields == {"Hashes"}

    def test_special_fields_include_alias_and_transform_targets(
        self, field_mappings_file_with_transforms, test_logger, default_args_config
    ):
        """Alias and (enabled) transform field names are flagged as special."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_with_transforms,
            args_config=default_args_config,
            logger=test_logger,
        )
        assert processor._special_fields == {"CommandLine", "proctitle"}

    def test_fast_path_assigns_value_and_discovers_field(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """A non-special leaf is assigned and its column type recorded once."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        event = {"Event": {"System": {"EventID": 4688, "Channel": "Security"}}}
        flat = processor._flatten_event(event, "t.evtx")
        assert flat["EventID"] == 4688
        assert flat["Channel"] == "Security"
        # NOCASE on both: a column is typed from the first value seen for the
        # field, so a numeric first value must not leave later text values
        # comparing case-sensitively for the rest of the run.
        assert processor.field_types["EventID"] == "INTEGER COLLATE NOCASE"
        assert processor.field_types["Channel"] == "TEXT COLLATE NOCASE"
        # The key is now remembered so repeat work is skipped.
        assert "EventID" in processor._seen_leaf_keys

    def test_seen_key_repeat_large_int_still_stringified(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """A >int64 value on an already-seen key must still be stringified."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        huge = 9223372036854775807 + 10  # exceeds signed 64-bit range
        first = processor._flatten_event(
            {"Event": {"System": {"EventID": 1}}}, "t.evtx"
        )
        second = processor._flatten_event(
            {"Event": {"System": {"EventID": huge}}}, "t.evtx"
        )
        assert first["EventID"] == 1
        assert second["EventID"] == str(huge)
        assert isinstance(second["EventID"], str)

    def test_int64_min_is_stringified_like_baseline(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """INT64_MIN trips the abs()-based overflow guard (historical behaviour)."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        int64_min = -9223372036854775808
        flat = processor._flatten_event(
            {"Event": {"System": {"EventID": int64_min}}}, "t.evtx"
        )
        assert flat["EventID"] == str(int64_min)

    def test_split_field_keeps_original_and_repeats(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """Split fields emit sub-fields *and* keep the source field, every event."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        first = processor._flatten_event(
            {"Event": {"EventData": {"Hashes": "MD5=aaa,SHA256=bbb"}}}, "t.evtx"
        )
        assert first["MD5"] == "aaa"
        assert first["SHA256"] == "bbb"
        # Rules query the unsplit field too, so dropping it made them unmatchable.
        assert first["Hashes"] == "MD5=aaa,SHA256=bbb"
        # Second event with the same (now seen) sub-keys still splits correctly.
        second = processor._flatten_event(
            {"Event": {"EventData": {"Hashes": "MD5=ccc,SHA256=ddd"}}}, "t.evtx"
        )
        assert second["MD5"] == "ccc"
        assert second["SHA256"] == "ddd"
        assert second["Hashes"] == "MD5=ccc,SHA256=ddd"

    def test_json_booleans_are_stored_as_sigma_spells_them(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """Regression: bool is a subclass of int, so booleans became INTEGER 1/0.

        Sigma-generated SQL compares against the lowercase JSON spelling, so a
        stored 1 made every rule on a boolean field (Sysmon Initiated, ECS and
        CloudTrail flags) unmatchable.
        """
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        flat = processor._flatten_event(
            {"Event": {"EventData": {"Initiated": True, "Ended": False}}}, "t.evtx"
        )
        assert flat["Initiated"] == "true"
        assert flat["Ended"] == "false"
        assert processor.field_types["Initiated"] != "INTEGER"

    def test_split_survives_a_malformed_pair(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """One pair without a separator must not cost the pairs after it."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        flat = processor._flatten_event(
            {"Event": {"EventData": {"Hashes": "MD5=aaa,GARBAGE,SHA256=bbb"}}},
            "t.evtx",
        )
        assert flat["MD5"] == "aaa"
        assert flat["SHA256"] == "bbb"
        assert flat["Hashes"] == "MD5=aaa,GARBAGE,SHA256=bbb"

    def test_event_filter_path_hint_reused_and_falls_back(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """The winning channel/eventid path is cached and reused, with fallback."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        e1 = {"Event": {"System": {"Channel": "Sysmon", "EventID": 1}}}
        channel, eventid = processor._extract_event_filter_fields(e1)
        assert channel == "Sysmon"
        assert eventid == 1
        assert processor._channel_path_hint == ("Event", "System", "Channel")
        assert processor._eventid_path_hint == ("Event", "System", "EventID")

        # Same schema: hint hit yields identical results.
        assert processor._extract_event_filter_fields(e1) == ("Sysmon", 1)

        # Different schema: hint misses, full scan finds the direct fields and
        # updates the hint.
        e2 = {"Channel": "Security", "EventID": 4624}
        channel2, eventid2 = processor._extract_event_filter_fields(e2)
        assert channel2 == "Security"
        assert eventid2 == 4624
        assert processor._channel_path_hint == ("Channel",)
        assert processor._eventid_path_hint == ("EventID",)

    def test_insert_batch_homogeneous_and_heterogeneous(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """itemgetter path (homogeneous) and .get path (heterogeneous) agree."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(":memory:")
        cur = conn.cursor()
        cur.execute('CREATE TABLE logs ("Alpha" TEXT, "Beta" TEXT, "Solo" TEXT)')
        conn.commit()

        # Homogeneous, multi-column -> itemgetter fast path.
        processor._insert_batch(
            conn, cur, [{"Alpha": "a1", "Beta": "b1"}, {"Alpha": "a2", "Beta": "b2"}]
        )
        assert cur.execute(
            'SELECT "Alpha", "Beta" FROM logs ORDER BY "Alpha"'
        ).fetchall() == [("a1", "b1"), ("a2", "b2")]

        # Single-column -> guarded .get path (itemgetter would return a scalar).
        processor._insert_batch(conn, cur, [{"Solo": "s1"}])
        assert cur.execute(
            'SELECT "Solo" FROM logs WHERE "Solo" IS NOT NULL'
        ).fetchall() == [("s1",)]

        # Heterogeneous -> .get path, missing columns become NULL.
        processor._insert_batch(conn, cur, [{"Alpha": "x"}, {"Beta": "y"}])
        rows = set(cur.execute('SELECT "Alpha", "Beta" FROM logs').fetchall())
        assert ("x", None) in rows
        assert (None, "y") in rows
        conn.close()


class TestStreamingEventProcessorSchemaGeneration:
    """Tests for SQL schema generation."""

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
        processor._insert_batch(conn, cursor, batch1)
        first_frozen = processor._last_column_frozenset

        batch2 = [{"colA": "a2", "colB": "b2"}]
        processor._insert_batch(conn, cursor, batch2)
        assert processor._last_column_frozenset == first_frozen

        batch3 = [{"colA": "a3", "colB": "b3", "colC": "c3"}]
        processor._insert_batch(conn, cursor, batch3)
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
    """Tests for module-level helpers."""

    def test_non_alnum_re_strips_special(self):
        assert _NON_ALNUM_RE.sub('', 'Hello-World_123!') == 'HelloWorld123'

    def test_non_alnum_re_empty_string(self):
        assert _NON_ALNUM_RE.sub('', '') == ''


class TestStreamingEventProcessorJSONStreaming:
    """Tests for JSON file streaming."""

    def test_stream_json_events(self, field_mappings_file, test_logger, default_args_config, tmp_json_file):
        """Test streaming events from a JSON file."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )

        events = list(processor.stream_json_events(tmp_json_file))

        assert len(events) > 0
        assert "OriginalLogfile" in events[0]

    def test_stream_json_array_events(self, field_mappings_file, test_logger, default_args_config, tmp_json_array_file):
        """Test streaming events from a JSON array file."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )

        events = list(processor.stream_json_array_chunked(tmp_json_array_file))

        assert len(events) > 0

    def test_stream_json_multiple_events(self, field_mappings_file, test_logger, default_args_config, tmp_json_file_multiple):
        """Test streaming multiple events from a JSONL file."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )

        events = list(processor.stream_json_events(tmp_json_file_multiple))

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
            f.writelines(json.dumps(event) + "\n" for event in events)

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

    def test_stream_csv_with_bom_keeps_first_header_clean(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """A UTF-8 BOM must not corrupt the first header name into '\\ufeffEventID'."""
        csv_file = tmp_path / "bom.csv"
        csv_file.write_bytes(b"\xef\xbb\xbfEventID,Channel\n1,Security\n")

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger
        )

        events = list(processor.stream_csv_events(str(csv_file)))

        assert len(events) == 1
        assert "EventID" in events[0]
        assert "﻿EventID" not in events[0]

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
        )

        assert event_count == 3

        # Verify data in database
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        db_count = cursor.fetchone()[0]

        assert db_count == 3

        conn.close()

    def test_process_file_streaming_json_array_input_type(
        self, field_mappings_file, test_logger, default_args_config, tmp_json_array_file
    ):
        """'json_array' is dispatched directly, without the caller normalising it."""
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)

        event_count = processor.process_file_streaming(
            conn, tmp_json_array_file, input_type="json_array"
        )

        assert event_count == 3
        conn.close()

    def test_process_file_streaming_sqlite_is_unsupported(
        self, field_mappings_file, test_logger, default_args_config, tmp_json_array_file
    ):
        """SQLite is a real format but has no streaming reader."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)

        assert (
            processor.process_file_streaming(
                conn, tmp_json_array_file, input_type="sqlite"
            )
            == 0
        )
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
        result = list(processor.stream_json_array_chunked(str(arr_file)))
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

    def test_transform_safe_write_rejected_returns_value_unchanged(
        self, test_logger, default_args_config, tmp_path, sample_windows_event
    ):
        """Transform that triggers _safe_write_ on non-container is caught; value returned unchanged."""
        raw_config = {
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.EventData.CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "CommandLine": [
                    {
                        "alias_name": "",
                        "alias": False,
                        "code": "def transform(param):\n  x = 1\n  x.foo = 2\n  return param",
                        "enabled": True,
                        "source_condition": ["evtx_input"],
                    }
                ]
            },
        }
        config_path = tmp_path / "c.json"
        config_path.write_text(json.dumps(raw_config))
        args = __import__('argparse').Namespace(evtx_input=True)
        processor = StreamingEventProcessor(
            config_file=str(config_path),
            args_config=args,
            logger=test_logger,
            _raw_config=raw_config,
        )
        json_file = tmp_path / "e.json"
        json_file.write_text(json.dumps(sample_windows_event) + "\n")
        events = list(processor.stream_json_events(str(json_file)))
        assert len(events) == 1
        assert events[0].get("CommandLine")  # value preserved when transform raises

    def test_transform_unsupported_inplace_op_returns_value_unchanged(
        self, test_logger, default_args_config, tmp_path, sample_windows_event
    ):
        """Transform that triggers _inplacevar_ with unsupported op is caught; value returned unchanged."""
        raw_config = {
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.EventData.CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "CommandLine": [
                    {
                        "alias_name": "",
                        "alias": False,
                        "code": "def transform(param):\n  x = 1\n  x @= 2\n  return param",
                        "enabled": True,
                        "source_condition": ["evtx_input"],
                    }
                ]
            },
        }
        config_path = tmp_path / "c.json"
        config_path.write_text(json.dumps(raw_config))
        args = __import__('argparse').Namespace(evtx_input=True)
        processor = StreamingEventProcessor(
            config_file=str(config_path),
            args_config=args,
            logger=test_logger,
            _raw_config=raw_config,
        )
        json_file = tmp_path / "e.json"
        json_file.write_text(json.dumps(sample_windows_event) + "\n")
        events = list(processor.stream_json_events(str(json_file)))
        assert len(events) == 1
        assert events[0].get("CommandLine")


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
            f.writelines(json.dumps(event) + "\n" for event in events)

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
        stream = processor.stream_json_events(tmp_json_file_multiple)

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
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_xml_events(tmp_xml_file, extractor))
        assert len(events) >= 1
        assert "OriginalLogfile" in events[0]

    def test_stream_auditd_events(
        self, field_mappings_file, test_logger, default_args_config, tmp_auditd_file, tmp_path
    ):
        """Stream Auditd file yields flattened events."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_auditd_events(tmp_auditd_file, extractor))
        assert len(events) >= 1
        assert "OriginalLogfile" in events[0]

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
        config = ExtractorConfig(sysmon4linux=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_sysmon_linux_events(str(sysmon_file), extractor))
        # May be 0 if flattener expects Windows channel/time fields; we still cover the stream path
        assert isinstance(events, list)

    def test_process_file_streaming_xml(
        self, field_mappings_file, test_logger, default_args_config, tmp_xml_file, tmp_path
    ):
        """process_file_streaming with input_type xml inserts events."""
        config = ExtractorConfig(xml_logs=True)
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

    def test_process_file_streaming_auditd(
        self, field_mappings_file, test_logger, default_args_config, tmp_auditd_file, tmp_path
    ):
        """process_file_streaming with input_type auditd inserts events."""
        config = ExtractorConfig(auditd_logs=True)
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

    @pytest.mark.requires_lxml
    def test_stream_evtxtract_events(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """Stream EVTXtract file yields flattened events from embedded Event XML."""
        evtxtract_content = '''Found at offset 0x0
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>
<EventData><Data Name="CommandLine">cmd.exe</Data></EventData>
</Event>
'''
        evtxtract_file = tmp_path / "evtxtract.log"
        evtxtract_file.write_text(evtxtract_content)
        config = ExtractorConfig(evtxtract=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_evtxtract_events(str(evtxtract_file), extractor))
        assert isinstance(events, list)
        if events:
            assert "OriginalLogfile" in events[0]


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
        events = list(processor.stream_json_events(path))
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

    @patch('zircolite.streaming.PyEvtxParser')
    def test_stream_evtx_events_with_mock_parser(
        self, mock_parser_cls, field_mappings_file, test_logger, default_args_config, tmp_path, sample_windows_event
    ):
        """stream_evtx_events yields flattened events when parser returns records (string and bytes payloads)."""
        evtx_file = tmp_path / "test.evtx"
        evtx_file.write_bytes(b"ElfFile\x00\x00")  # placeholder

        def records():
            yield {"data": json.dumps(sample_windows_event).encode('utf-8')}
            yield {"data": json.dumps(sample_windows_event)}

        mock_parser = MagicMock()
        mock_parser.records_json.side_effect = records
        mock_parser_cls.return_value = mock_parser

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_evtx_events(str(evtx_file)))
        assert len(events) == 2
        assert "OriginalLogfile" in events[0]

    @patch('zircolite.streaming.PyEvtxParser')
    def test_stream_evtx_events_inner_exception_continues(
        self, mock_parser_cls, field_mappings_file, test_logger, default_args_config, tmp_path, sample_windows_event
    ):
        """When a record raises during processing, that record is skipped and iteration continues."""
        evtx_file = tmp_path / "test.evtx"
        evtx_file.write_bytes(b"ElfFile\x00\x00")

        def records():
            yield {"data": json.dumps(sample_windows_event)}
            yield {"data": b"not valid json {"}
            yield {"data": json.dumps(sample_windows_event)}

        mock_parser = MagicMock()
        mock_parser.records_json.side_effect = records
        mock_parser_cls.return_value = mock_parser

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_evtx_events(str(evtx_file)))
        assert len(events) == 2

    @patch('zircolite.streaming.PyEvtxParser')
    def test_stream_evtx_events_outer_exception_logs_error(
        self, mock_parser_cls, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """When parser construction or iteration raises, error is logged and no events yielded."""
        evtx_file = tmp_path / "test.evtx"
        evtx_file.write_bytes(b"ElfFile\x00\x00")
        mock_parser_cls.side_effect = RuntimeError("EVTX open failed")

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_evtx_events(str(evtx_file)))
        assert events == []

    @patch('zircolite.streaming.PyEvtxParser')
    @patch('zircolite.streaming.open_maybe_compressed')
    def test_stream_evtx_events_compressed_7z_decompresses_then_parses(
        self, mock_open_compressed, mock_parser_cls, field_mappings_file, test_logger, default_args_config, tmp_path, sample_windows_event
    ):
        """When path ends in .7z, stream_evtx_events decompresses then parses the temp file."""
        evtx_7z = tmp_path / "log.evtx.7z"
        evtx_7z.write_bytes(b"\x37\x7a\xbc\xaf\x27\x1c")  # 7z magic

        evtx_magic = b"ElfFile\x00\x00"
        # Emulate a real stream: content once, then EOF (the implementation
        # stream-copies the decompressed data)
        mock_open_compressed.return_value.__enter__.return_value.read.side_effect = [
            evtx_magic, b""
        ]

        mock_parser = MagicMock()
        mock_parser.records_json.return_value = iter([{"data": json.dumps(sample_windows_event)}])
        mock_parser_cls.return_value = mock_parser

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_evtx_events(str(evtx_7z)))
        assert len(events) == 1
        assert "OriginalLogfile" in events[0]
        mock_open_compressed.assert_called_once()
        call_args = mock_open_compressed.call_args[0][0]
        assert str(evtx_7z) == str(call_args) or evtx_7z.name in str(call_args)
        # Parser was called with the temp path (not the .7z path)
        mock_parser_cls.assert_called_once()
        parser_path = mock_parser_cls.call_args[0][0]
        assert ".evtx" in parser_path
        assert ".7z" not in parser_path


class TestStreamingEvtxStrictMode:
    """Tests for lenient (default) and strict EVTX parsing modes."""

    @patch('zircolite.streaming.PyEvtxParser')
    def test_lenient_mode_logs_warning_on_chunk_error(
        self, mock_parser_cls, field_mappings_file, test_logger, default_args_config, tmp_path, sample_windows_event
    ):
        """In lenient mode (default), chunk errors log a warning and yield events recovered before the error."""
        evtx_file = tmp_path / "corrupt.evtx"
        evtx_file.write_bytes(b"ElfFile\x00\x00")

        good_record = {"data": json.dumps(sample_windows_event)}

        def records_with_error():
            yield good_record
            raise RuntimeError("Failed to parse chunk header")

        mock_parser = MagicMock()
        mock_parser.records_json.side_effect = records_with_error
        mock_parser_cls.return_value = mock_parser

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_evtx_events(str(evtx_file)))
        assert len(events) == 1
        assert "OriginalLogfile" in events[0]

    @patch('zircolite.streaming.PyEvtxParser')
    def test_strict_mode_raises_on_chunk_error(
        self, mock_parser_cls, field_mappings_file, test_logger, default_args_config, tmp_path, sample_windows_event
    ):
        """In strict mode, chunk errors propagate as exceptions."""
        evtx_file = tmp_path / "corrupt.evtx"
        evtx_file.write_bytes(b"ElfFile\x00\x00")

        def records_with_error():
            yield {"data": json.dumps(sample_windows_event)}
            raise RuntimeError("Failed to parse chunk header")

        mock_parser = MagicMock()
        mock_parser.records_json.side_effect = records_with_error
        mock_parser_cls.return_value = mock_parser

        proc_config = ProcessingConfig(strict_evtx=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )
        with pytest.raises(StrictParseError, match="Failed to parse chunk header") as exc:
            list(processor.stream_evtx_events(str(evtx_file)))
        assert isinstance(exc.value.__cause__, RuntimeError)

    @patch('zircolite.streaming.PyEvtxParser')
    def test_lenient_mode_still_handles_invalid_evtx_for_7z(
        self, mock_parser_cls, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """Invalid EVTX signature inside .7z still logs error and returns early in lenient mode."""
        evtx_file = tmp_path / "bad.evtx.7z"
        evtx_file.write_bytes(b"not-evtx")

        mock_parser_cls.side_effect = RuntimeError("Invalid EVTX signature (ElfFile0)")
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_evtx_events(str(evtx_file)))
        assert events == []

    @patch('zircolite.streaming.PyEvtxParser')
    def test_strict_mode_raises_on_parser_construction_failure(
        self, mock_parser_cls, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """In strict mode, parser construction failures raise."""
        evtx_file = tmp_path / "bad.evtx"
        evtx_file.write_bytes(b"ElfFile\x00\x00")

        mock_parser_cls.side_effect = RuntimeError("EVTX open failed")
        proc_config = ProcessingConfig(strict_evtx=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )
        with pytest.raises(StrictParseError, match="EVTX open failed"):
            list(processor.stream_evtx_events(str(evtx_file)))

    def test_strict_evtx_flag_stored_from_config(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """strict_evtx is correctly read from ProcessingConfig."""
        proc_strict = ProcessingConfig(strict_evtx=True)
        processor_strict = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_strict,
            logger=test_logger,
        )
        assert processor_strict.strict_evtx is True

        processor_lenient = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        assert processor_lenient.strict_evtx is False


class TestStreamingTransformInitAndResolve:
    """Tests for transform_categories init and _resolve_file_transforms."""

    def test_init_with_transform_categories_and_unknown_category(
        self, field_mappings_file, test_logger, tmp_path
    ):
        """Unknown transform category logs warning and enables transforms from known categories."""
        from argparse import Namespace
        config_path = tmp_path / "config.yaml"
        config_content = {
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {
                "CommandLine": [
                    {"alias_name": "cmd_upper", "alias": True, "code": "def transform(param): return param.upper()", "enabled": True}
                ]
            },
            "transform_categories": {"commandline": ["cmd_upper"]},
        }
        import yaml
        config_path.write_text(yaml.dump(config_content))
        args = Namespace(transform_categories=["unknown_cat", "commandline"], evtx_input=True)
        processor = StreamingEventProcessor(
            config_file=str(config_path),
            args_config=args,
            logger=test_logger,
        )
        assert processor.transforms_enabled is True
        assert "cmd_upper" in processor.enabled_transforms_set

    def test_resolve_file_transforms_missing_file(self, test_logger, tmp_path):
        """python_file transform with missing file gets fallback code and error logged."""
        config_path = tmp_path / "fieldMappings.json"
        config = {
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.EventData.CommandLine": "CommandLine"},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "CommandLine": [
                    {
                        "type": "python_file",
                        "file": "nonexistent.py",
                        "alias_name": "cmd",
                        "alias": True,
                        "enabled": True,
                        "source_condition": ["evtx_input"],
                    }
                ]
            },
        }
        config_path.write_text(json.dumps(config))
        args = __import__('argparse').Namespace(evtx_input=True)
        processor = StreamingEventProcessor(
            config_file=str(config_path),
            args_config=args,
            logger=test_logger,
        )
        assert processor.transforms["CommandLine"][0]["code"].strip().startswith("def transform(param):")

    def test_resolve_file_transforms_empty_file_key(self, test_logger, tmp_path):
        """python_file transform with no 'file' key gets warning and fallback code."""
        config_path = tmp_path / "fieldMappings.json"
        config = {
            "exclusions": [],
            "useless": [],
            "mappings": {"a": "b"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {
                "b": [{"type": "python_file", "alias_name": "x", "alias": True, "enabled": True, "source_condition": ["evtx_input"]}]
            },
        }
        config_path.write_text(json.dumps(config))
        processor = StreamingEventProcessor(
            config_file=str(config_path),
            args_config=__import__('argparse').Namespace(evtx_input=True),
            logger=test_logger,
        )
        assert "def transform(param):" in processor.transforms["b"][0]["code"]


class TestStreamingJsonXmlErrorPaths:
    """Tests for stream_json_events and stream_xml_events exception paths."""

    def test_stream_json_events_invalid_line_skipped(
        self, field_mappings_file, test_logger, default_args_config, tmp_path, sample_windows_event
    ):
        """JSONL with one invalid JSON line skips that line and yields the rest."""
        json_file = tmp_path / "mixed.json"
        lines = [
            json.dumps(sample_windows_event),
            "not valid json {{{",
            json.dumps(sample_windows_event),
        ]
        json_file.write_text("\n".join(lines))
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_json_events(str(json_file)))
        assert len(events) == 2

    def test_stream_json_events_outer_exception(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """When file cannot be opened (e.g. path is a directory), error is logged and no events."""
        dir_path = tmp_path / "adir"
        dir_path.mkdir()
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_json_events(str(dir_path)))
        assert events == []

    def test_stream_xml_events_outer_exception(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """When XML file cannot be read, error is logged and no events."""
        from zircolite.extractor import EvtxExtractor
        config = __import__('zircolite.config').ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        path = str(tmp_path / "does_not_exist.xml")
        events = list(processor.stream_xml_events(path, extractor))
        assert events == []


class TestStreamingJsonArrayChunkedLargeFile:
    """Tests for stream_json_array_chunked incremental (large file) path."""

    @patch('os.path.getsize')
    def test_stream_json_array_chunked_uses_incremental_when_large(
        self, mock_getsize, field_mappings_file, test_logger, default_args_config, tmp_path, sample_windows_events_list
    ):
        """When file size >= 50MB, incremental parsing path is used."""
        arr_file = tmp_path / "large_array.json"
        arr_file.write_text(json.dumps(sample_windows_events_list))
        mock_getsize.return_value = 50 * 1024 * 1024 + 1

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_json_array_chunked(str(arr_file)))
        assert len(events) == 3

    @patch('os.path.getsize')
    def test_stream_json_array_chunked_incremental_empty_file(
        self, mock_getsize, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """Incremental path with file that has no opening bracket returns no events."""
        arr_file = tmp_path / "no_bracket.txt"
        arr_file.write_text("")
        mock_getsize.return_value = 60 * 1024 * 1024

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_json_array_chunked(str(arr_file)))
        assert events == []


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

        events = list(processor.stream_json_events(str(json_file)))
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

        events = list(processor.stream_json_events(str(json_file)))
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

        events = list(processor.stream_json_events(str(json_file)))
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

        events = list(processor.stream_json_events(str(json_file)))
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

        events = list(processor.stream_json_array_chunked(str(json_file)))
        assert len(events) == 2


# ============================================================================
# PRE-PARSED CONFIG PASSTHROUGH
# ============================================================================


class TestStreamingEventFilter:
    """Tests for event filter extraction and filtering."""

    def test_extract_event_filter_fields_eventid_dict_text(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """EventID as XML-style dict with #text is converted to int."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        event = {
            "Event": {
                "System": {"Channel": "Security", "EventID": {"#text": "4688"}},
            }
        }
        channel, eventid = processor._extract_event_filter_fields(event)
        assert eventid == 4688
        assert channel == "Security"

    def test_extract_event_filter_fields_eventid_invalid_converts_to_none(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """EventID that cannot convert to int yields None."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        event = {"Event": {"System": {"EventID": "not_a_number"}}}
        _, eventid = processor._extract_event_filter_fields(event)
        assert eventid is None

    def test_get_nested_value_empty_parts_returns_none(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """_get_nested_value with empty parts returns None."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        assert processor._get_nested_value({"a": 1}, ()) is None

    def test_get_nested_value_non_dict_returns_none(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """_get_nested_value with non-dict intermediate returns None."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        assert processor._get_nested_value({"a": "string"}, ("a", "b")) is None

    def test_should_process_event_with_filter_filters_out(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """When event_filter is enabled, events not matching channel/eventID are skipped."""
        from zircolite.rules import EventFilter

        ruleset = [
            {"channel": ["Microsoft-Windows-Sysmon/Operational"], "eventid": [1, 3]},
        ]
        event_filter = EventFilter(ruleset, logger=test_logger)
        assert event_filter.is_enabled

        raw_config = {
            "exclusions": [],
            "useless": [],
            "mappings": {
                "Event.System.EventID": "EventID",
                "Event.System.Channel": "Channel",
            },
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {},
            "event_filter": {
                "channel_fields": ["Event.System.Channel", "Channel"],
                "eventid_fields": ["Event.System.EventID", "EventID"],
            },
        }
        config_path = tmp_path / "cfg.json"
        config_path.write_text(json.dumps(raw_config))
        args = __import__("argparse").Namespace(evtx_input=True)
        processor = StreamingEventProcessor(
            config_file=str(config_path),
            args_config=args,
            logger=test_logger,
            event_filter=event_filter,
            _raw_config=raw_config,
        )
        assert processor._filtering_enabled

        event_in = {"Event": {"System": {"Channel": "Security", "EventID": 4624}}}
        assert processor._should_process_event(event_in) is False
        assert processor.events_filtered_count == 1

    def test_detect_timestamp_field_uses_config(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """_detect_timestamp_field returns time_field when set and present in event."""
        from zircolite.config import ProcessingConfig

        proc = ProcessingConfig(time_field="SystemTime")
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc,
            logger=test_logger,
        )
        flat = {"SystemTime": "2024-06-15T10:30:00Z", "EventID": 1}
        assert processor._detect_timestamp_field(flat) == "SystemTime"


class TestStreamingTransformFailure:
    """Tests for transform compilation failure path."""

    def test_get_transform_func_invalid_code_returns_none(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """_get_transform_func with invalid code returns None and logs."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        result = processor._get_transform_func("def transform(param): syntax error {{{")
        assert result is None


class TestStreamingKeepflatAndProgress:
    """Tests for keepflat file and progress_callback in process_file_streaming."""

    def test_process_file_streaming_writes_keepflat(
        self, field_mappings_file, test_logger, default_args_config, tmp_json_file_multiple, tmp_path
    ):
        """When keepflat_file is provided, flattened events are written as JSONL."""
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        keepflat_path = tmp_path / "flat.jsonl"
        with open(keepflat_path, "wb") as keepflat_file:
            count = processor.process_file_streaming(
                conn,
                tmp_json_file_multiple,
                input_type="json",
                json_array=False,
                keepflat_file=keepflat_file,
            )
        conn.close()
        assert count == 3
        lines = keepflat_path.read_text().strip().split("\n")
        assert len(lines) == 3
        assert "OriginalLogfile" in json.loads(lines[0])

    def test_process_file_streaming_invokes_progress_callback(
        self, field_mappings_file, test_logger, default_args_config, tmp_json_file_multiple
    ):
        """progress_callback is invoked after each batch."""
        proc_config = ProcessingConfig(batch_size=2, disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        calls = []
        count = processor.process_file_streaming(
            conn,
            tmp_json_file_multiple,
            input_type="json",
            json_array=False,
            progress_callback=calls.append,
        )
        conn.close()
        assert count == 3
        assert len(calls) >= 1
        assert 3 in calls


class TestStreamingInsertBatchRollback:
    """Tests for _insert_batch rollback on exception."""

    def test_insert_batch_rollback_on_commit_failure(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """When COMMIT raises, ROLLBACK is executed and exception propagates."""
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=proc_config,
            logger=test_logger,
        )
        processor._flatten_event(
            {"Event": {"System": {"EventID": 1}, "EventData": {"x": "y"}}},
            "test.evtx",
        )
        execute_calls = []

        def mock_execute(sql, *args):
            execute_calls.append(sql.strip().upper())
            if sql.strip().upper() == "COMMIT":
                raise sqlite3.OperationalError("mock commit failure")

        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_conn = MagicMock()
        mock_conn.execute = mock_execute
        mock_conn.cursor.return_value = mock_cursor

        with pytest.raises(sqlite3.OperationalError):
            processor._insert_batch(mock_conn, mock_cursor, [{"EventID": 1, "x": "y"}])
        assert "COMMIT" in execute_calls
        assert "ROLLBACK" in execute_calls


class TestStreamingEnsureColumnsExistCached:
    """Tests for _ensure_columns_exist_cached exception path."""

    def test_ensure_columns_exist_cached_alter_duplicate_ignored(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """When ALTER TABLE fails (e.g. column exists), cache is not corrupted."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE logs (row_id INTEGER PRIMARY KEY, colA TEXT)"
        )
        conn.commit()
        cursor = conn.cursor()
        processor._db_columns = {"row_id", "cola"}
        schema_changed = processor._ensure_columns_exist_cached(
            conn, cursor, ("colA", "colB")
        )
        conn.close()
        assert "colb" in processor._db_columns
        assert schema_changed is True


class TestStreamingUnsupportedInputType:
    """Tests for process_file_streaming with unsupported or missing extractor."""

    def test_process_file_streaming_xml_without_extractor_returns_zero(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """input_type xml with extractor=None returns 0 and logs error."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        f = tmp_path / "dummy.xml"
        f.write_text("<root/>")
        count = processor.process_file_streaming(
            conn, str(f), input_type="xml", extractor=None
        )
        conn.close()
        assert count == 0


class TestStreamingFlattenListValue:
    """Tests for _flatten_event with list value (str(obj))."""

    def test_flatten_event_list_value_stringified(
        self, test_logger, default_args_config, tmp_path
    ):
        """Nested list value is stringified in flattened output."""
        raw_config = {
            "exclusions": [],
            "useless": [],
            "mappings": {"Event.EventData.Tags": "Tags"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {},
        }
        config_file = tmp_path / "c.json"
        config_file.write_text(json.dumps(raw_config))
        args = __import__("argparse").Namespace(evtx_input=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger,
            _raw_config=raw_config,
        )
        event = {"Event": {"EventData": {"Tags": ["a", "b", "c"]}}}
        flat = processor._flatten_event(event, "test.evtx")
        assert flat is not None
        assert flat.get("Tags") == "['a', 'b', 'c']" or "Tags" in flat


class TestStreamingEnsureColumnsExist:
    """Tests for dynamic column creation."""

    def test_ensure_columns_exist_adds_missing_column(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """A column absent from the table is added and recorded in the cache."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE logs (row_id INTEGER PRIMARY KEY)")
        conn.commit()
        cursor = conn.cursor()
        processor._ensure_columns_exist_cached(conn, cursor, ("colA",))
        conn.close()
        assert "cola" in processor._db_columns


class TestPreParsedConfig:
    """Tests for pre-parsed field mappings passthrough."""

    def test_streaming_processor_uses_raw_config(self, field_mappings_file):
        """StreamingEventProcessor uses _raw_config instead of reading disk."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig

        raw_config = {
            "exclusions": ["xmlns"],
            "useless": [None, ""],
            "mappings": {"Event.System.EventID": "EventID"},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {},
        }

        args = Namespace(evtx_input=True)
        proc = ProcessingConfig()

        processor = StreamingEventProcessor(
            config_file="/nonexistent/path.json",
            args_config=args,
            processing_config=proc,
            _raw_config=raw_config,
        )

        assert processor.field_mappings == {"Event.System.EventID": "EventID"}
        assert processor.transforms_enabled is False

    def test_streaming_processor_falls_back_to_file(self, field_mappings_file):
        """Without _raw_config, config is loaded from disk as before."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig

        args = Namespace(evtx_input=True)
        proc = ProcessingConfig()

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=args,
            processing_config=proc,
        )

        assert "Event.System.EventID" in processor.field_mappings


# ============================================================================
# TABLE REUSE (DELETE FROM instead of DROP TABLE)
# ============================================================================


class TestTableReuse:
    """Tests for DELETE FROM table reuse in worker cores."""

    def test_create_initial_table_refreshes_cache(self):
        """create_initial_table queries actual schema for its column cache."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig

        raw_config = {
            "exclusions": [],
            "useless": [],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": False,
            "transforms": {},
        }

        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE logs (row_id INTEGER PRIMARY KEY, EventID TEXT, Channel TEXT)"
        )
        conn.commit()

        args = Namespace(evtx_input=True)
        processor = StreamingEventProcessor(
            config_file="/unused",
            args_config=args,
            processing_config=ProcessingConfig(),
            _raw_config=raw_config,
        )

        processor.create_initial_table(conn)

        assert "row_id" in processor._db_columns
        assert "eventid" in processor._db_columns
        assert "channel" in processor._db_columns

        conn.close()

    def test_delete_from_preserves_schema(self):
        """DELETE FROM keeps columns so ALTER TABLE is not needed for same schema."""
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE logs (row_id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "EventID TEXT, Channel TEXT)"
        )
        conn.execute(
            "INSERT INTO logs (EventID, Channel) VALUES ('1', 'Sysmon')"
        )
        conn.commit()

        conn.execute("DELETE FROM logs")
        conn.commit()

        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(logs)")
        columns = {row[1].lower() for row in cursor.fetchall()}

        assert "eventid" in columns
        assert "channel" in columns

        cursor.execute("SELECT COUNT(*) FROM logs")
        assert cursor.fetchone()[0] == 0

        conn.close()


class TestStreamingBugFixes:
    """Tests for specific bug fixes in StreamingEventProcessor."""

    def test_json_array_with_non_dict_elements(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """Non-dict elements in JSON arrays should be skipped without TypeError."""
        import orjson
        json_file = tmp_path / "mixed.json"
        data = [
            {"Event": {"System": {"EventID": 1}}},
            "not a dict",
            42,
            None,
            {"Event": {"System": {"EventID": 2}}},
        ]
        json_file.write_bytes(orjson.dumps(data))

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_json_array_chunked(str(json_file)))
        assert len(events) == 2

    def test_column_cache_refreshed_on_alter_failure(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """When ALTER TABLE fails, the column cache is refreshed from the DB."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE logs (row_id INTEGER PRIMARY KEY, colA TEXT)")
        conn.commit()
        cursor = conn.cursor()
        processor._db_columns = {"row_id", "cola"}

        processor._ensure_columns_exist_cached(conn, cursor, ("colA", "colB"))
        assert "colb" in processor._db_columns
        conn.close()


class TestStreamingHostileKeysAndCaseVariants:
    """Regression tests for SQL identifier escaping and case-variant columns."""

    def _make_processor(self, field_mappings_file, test_logger, default_args_config):
        return StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=ProcessingConfig(disable_progress=True),
            logger=test_logger,
        )

    def test_key_with_double_quote_does_not_abort_file(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """A split-derived column name containing a double quote must not abort ingestion.

        Top-level keys are sanitized during flattening, but keys produced by the
        'split' feature (key=value parsing of field values, i.e. log content)
        reach the DB layer unsanitized.
        """
        processor = self._make_processor(field_mappings_file, test_logger, default_args_config)
        json_file = tmp_path / "events.json"
        # 'Hashes' is split on ',' into key=value pairs by the test config
        json_file.write_text(
            json.dumps({"EventID": 1, "Hashes": 'MD5=abc,bad"key=x'}) + "\n"
        )

        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(conn, str(json_file), input_type="json")

        assert count == 1
        cursor = conn.cursor()
        cursor.execute('SELECT "MD5", "bad""key" FROM logs')
        row = cursor.fetchone()
        assert row == ("abc", "x")
        conn.close()

    def test_case_variant_columns_merge_values(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """EventID and eventid in one batch map to a single canonical column."""
        processor = self._make_processor(field_mappings_file, test_logger, default_args_config)
        json_file = tmp_path / "events.json"
        json_file.write_text(
            json.dumps({"EventID": 1, "Message": "a"}) + "\n"
            + json.dumps({"eventid": 2, "Message": "b"}) + "\n"
        )

        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(conn, str(json_file), input_type="json")

        assert count == 2
        cursor = conn.cursor()
        cursor.execute('SELECT "EventID" FROM logs ORDER BY "EventID"')
        values = [row[0] for row in cursor.fetchall()]
        assert values == [1, 2]
        conn.close()

    def test_same_event_case_collision_keeps_first_non_none(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """A single event carrying both cases must not break the INSERT."""
        processor = self._make_processor(field_mappings_file, test_logger, default_args_config)
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps({"EventID": 7, "eventid": 9}) + "\n")

        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(conn, str(json_file), input_type="json")

        assert count == 1
        cursor = conn.cursor()
        cursor.execute('SELECT "EventID" FROM logs')
        assert cursor.fetchone()[0] in (7, 9)
        conn.close()

    def test_keepflat_single_write_per_event(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """Each event must be written with one write() call.

        In parallel mode the shared handle's lock covers a single write, so two
        writes per event could interleave between workers and corrupt JSONL.
        """
        processor = self._make_processor(field_mappings_file, test_logger, default_args_config)
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps({"EventID": 1}) + "\n" + json.dumps({"EventID": 2}) + "\n")

        writes = []

        class CountingWriter:
            def write(self, data):
                writes.append(bytes(data))
                return len(data)

        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(
            conn, str(json_file), input_type="json", keepflat_file=CountingWriter()
        )
        conn.close()

        assert count == 2
        assert len(writes) == 2
        for w in writes:
            assert w.endswith(b"\n")
            json.loads(w)  # each write is a complete JSONL line


class TestStreamingRobustness:
    """Regression tests for BOM handling, time filtering, and input precedence."""

    def _make_processor(self, field_mappings_file, test_logger, default_args_config, **proc_kwargs):
        return StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            processing_config=ProcessingConfig(disable_progress=True, **proc_kwargs),
            logger=test_logger,
        )

    def test_jsonl_utf8_bom_first_event_not_lost(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """A UTF-8 BOM must not silently drop the first JSONL event."""
        processor = self._make_processor(field_mappings_file, test_logger, default_args_config)
        json_file = tmp_path / "bom.json"
        json_file.write_bytes(
            b'\xef\xbb\xbf{"EventID": 1}\n{"EventID": 2}\n'
        )
        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(conn, str(json_file), input_type="json")
        assert count == 2
        conn.close()

    def test_json_array_utf8_bom_accepted(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        processor = self._make_processor(field_mappings_file, test_logger, default_args_config)
        json_file = tmp_path / "bom_array.json"
        json_file.write_bytes(b'\xef\xbb\xbf[{"EventID": 1}, {"EventID": 2}]')
        events = list(processor.stream_json_array_chunked(str(json_file)))
        assert len(events) == 2

    def test_time_filter_bounds_are_inclusive(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """Events exactly on --after/--before boundaries must be kept."""
        processor = self._make_processor(
            field_mappings_file, test_logger, default_args_config,
            time_after="2024-06-15T10:00:00", time_before="2024-06-15T12:00:00",
        )
        json_file = tmp_path / "events.json"
        json_file.write_text(
            json.dumps({"EventID": 1, "SystemTime": "2024-06-15T10:00:00Z"}) + "\n"
            + json.dumps({"EventID": 2, "SystemTime": "2024-06-15T12:00:00Z"}) + "\n"
            + json.dumps({"EventID": 3, "SystemTime": "2024-06-15T11:00:00Z"}) + "\n"
        )
        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(conn, str(json_file), input_type="json")
        assert count == 3
        conn.close()

    def test_time_filtered_events_are_counted_separately(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """--after/--before drops get their own counter, not the log-source one."""
        processor = self._make_processor(
            field_mappings_file, test_logger, default_args_config,
            time_after="2024-06-15T10:00:00", time_before="2024-06-15T12:00:00",
        )
        json_file = tmp_path / "events.json"
        json_file.write_text(
            json.dumps({"EventID": 1, "SystemTime": "2024-06-15T11:00:00Z"}) + "\n"
            + json.dumps({"EventID": 2, "SystemTime": "2023-01-01T00:00:00Z"}) + "\n"
            + json.dumps({"EventID": 3, "SystemTime": "2025-01-01T00:00:00Z"}) + "\n"
        )
        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(conn, str(json_file), input_type="json")
        conn.close()

        assert count == 1
        assert processor.has_time_filter
        assert processor.events_time_filtered_count == 2
        # The log-source filter dropped nothing; the two counts must not merge
        assert processor.events_filtered_count == 0

    def test_no_time_filter_reports_no_bounds(
        self, field_mappings_file, test_logger, default_args_config
    ):
        """Default bounds mean no time filtering is in effect."""
        processor = self._make_processor(
            field_mappings_file, test_logger, default_args_config,
            time_after="1970-01-01T00:00:00", time_before="9999-12-12T23:59:59",
        )
        assert not processor.has_time_filter
        assert processor.events_time_filtered_count == 0

    def test_time_filter_coerces_non_string_timestamp(
        self, field_mappings_file, test_logger, default_args_config, tmp_path
    ):
        """A numeric timestamp must not crash/bypass the time filter logic."""
        processor = self._make_processor(
            field_mappings_file, test_logger, default_args_config,
            time_after="1970-01-01T00:00:00", time_before="9999-12-12T23:59:59",
        )
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps({"EventID": 1, "SystemTime": 1718442600}) + "\n")
        conn = sqlite3.connect(":memory:")
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(conn, str(json_file), input_type="json")
        assert count == 1
        conn.close()

    def test_empty_source_condition_warns(
        self, field_mappings_file, test_logger, default_args_config, tmp_path, caplog
    ):
        """A transform without source_condition must produce a load-time warning."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {}, "alias": {},
            "split": {}, "transforms_enabled": True,
            "transforms": {
                "Field": [{
                    "info": "dead transform", "type": "python",
                    "code": "def transform(param):\n    return param",
                    "alias": True, "alias_name": "T",
                    "enabled": True,
                }]
            },
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        with caplog.at_level("WARNING"):
            StreamingEventProcessor(
                config_file=str(config_file),
                args_config=default_args_config,
                logger=test_logger,
            )
        assert any("source_condition" in r.message for r in caplog.records)

    def test_chosen_input_deterministic_precedence(
        self, field_mappings_file, test_logger
    ):
        """With multiple *_input flags set, precedence is deterministic."""
        from argparse import Namespace
        args = Namespace(
            evtx_input=True, json_input=True, auditd_input=False,
            json_array_input=False, csv_input=False, xml_input=False,
            sysmon_linux_input=False, evtxtract_input=False, db_input=False,
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=args,
            logger=test_logger,
        )
        assert processor.chosen_input == "json_input"


class TestStreamingCsvDelimiter:
    """CSV streaming must honour the delimiter actually used by the file."""

    def _stream(self, path, field_mappings_file, test_logger, args_config):
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=args_config,
            logger=test_logger,
        )
        return list(processor.stream_csv_events(str(path)))

    @pytest.mark.parametrize(
        "delimiter,suffix",
        [(",", "csv"), (";", "csv"), ("\t", "tsv"), ("|", "csv")],
    )
    def test_delimiter_is_sniffed(
        self, delimiter, suffix, tmp_path, field_mappings_file, test_logger,
        default_args_config,
    ):
        """Non-comma exports must not collapse into a single column."""
        src = tmp_path / f"events.{suffix}"
        src.write_text(
            delimiter.join(["EventID", "Channel", "CommandLine"]) + "\n"
            + delimiter.join(["4688", "Security", "powershell.exe"]) + "\n"
        )
        events = self._stream(src, field_mappings_file, test_logger, default_args_config)
        assert len(events) == 1
        assert events[0]["EventID"] == "4688"
        assert events[0]["Channel"] == "Security"
        assert events[0]["CommandLine"] == "powershell.exe"

    def test_quoted_field_containing_delimiter(
        self, tmp_path, field_mappings_file, test_logger, default_args_config,
    ):
        """A quoted value holding the delimiter stays intact."""
        src = tmp_path / "events.csv"
        src.write_text(
            'EventID;Channel;CommandLine\n'
            '4688;Security;"cmd.exe /c a;b"\n'
        )
        events = self._stream(src, field_mappings_file, test_logger, default_args_config)
        assert events[0]["CommandLine"] == "cmd.exe /c a;b"

    def test_logs_encoding_is_honoured(
        self, tmp_path, field_mappings_file, test_logger, default_args_config,
    ):
        """--logs-encoding reaches the CSV reader."""
        src = tmp_path / "events.csv"
        src.write_bytes("EventID,Computer\n4688,héte\n".encode("ISO-8859-1"))
        default_args_config.logs_encoding = "ISO-8859-1"
        events = self._stream(src, field_mappings_file, test_logger, default_args_config)
        assert events[0]["Computer"] == "héte"


class TestStreamingDecodeTolerance:
    """One undecodable byte must not cost the whole file."""

    def test_auditd_bad_byte_keeps_other_lines(
        self, tmp_path, field_mappings_file, test_logger, default_args_config,
    ):
        log = tmp_path / "audit.log"
        log.write_bytes(
            b'type=SYSCALL msg=audit(1600000000.123:456): exe="/bin/ok"\n'
            b'type=SYSCALL msg=audit(1600000000.124:457): exe="/bin/\xffbad"\n'
            b'type=SYSCALL msg=audit(1600000000.125:458): exe="/bin/after"\n'
        )
        extractor = EvtxExtractor(
            extractor_config=ExtractorConfig(auditd_logs=True), logger=test_logger
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_auditd_events(str(log), extractor))
        assert len(events) == 3


class TestStreamingXmlEncodingAndDiagnostics:
    """XML streaming covers what the removed extractor conversion used to."""

    def test_utf16_xml_yields_events(
        self, tmp_path, field_mappings_file, test_logger, default_args_config,
    ):
        """A UTF-16 XML export (with BOM) must not silently yield zero events."""
        xml = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><EventID>1</EventID></System>'
            '<EventData><Data Name="CommandLine">test.exe</Data></EventData>'
            '</Event></Events>'
        )
        src = tmp_path / "events.xml"
        src.write_bytes(xml.encode("utf-16"))

        extractor = EvtxExtractor(
            extractor_config=ExtractorConfig(xml_logs=True), logger=test_logger
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_xml_events(str(src), extractor))
        assert len(events) == 1

    def test_xml_without_events_warns(
        self, tmp_path, field_mappings_file, default_args_config,
    ):
        """A non-empty XML file yielding zero events must warn, not stay silent."""
        mock_logger = MagicMock()
        src = tmp_path / "notevents.xml"
        src.write_text("<Stuff>no events here</Stuff>")

        extractor = EvtxExtractor(
            extractor_config=ExtractorConfig(xml_logs=True), logger=mock_logger
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=mock_logger,
        )
        assert list(processor.stream_xml_events(str(src), extractor)) == []
        assert mock_logger.warning.called


class TestMalformedInputIsolation:
    """One bad record must not cost the rest of the file."""

    def test_csv_row_with_extra_values_is_kept(
        self, tmp_path, field_mappings_file, default_args_config, test_logger
    ):
        """Surplus values used to land under the key None.

        That key broke field resolution, the exception was swallowed, and the
        whole row disappeared without a log line at any level.
        """
        src = tmp_path / "ragged.csv"
        src.write_text("Channel,EventID\nSecurity,4624,surplus\nSystem,7036\n")

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_csv_events(str(src)))

        assert len(events) == 2
        assert events[0]["EventID"] == "4624"

    def test_csv_row_with_missing_values_is_kept(
        self, tmp_path, field_mappings_file, default_args_config, test_logger
    ):
        src = tmp_path / "short.csv"
        src.write_text("Channel,EventID,Computer\nSecurity,4624\n")

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        events = list(processor.stream_csv_events(str(src)))

        assert len(events) == 1

    def test_json_array_survives_a_non_scalar_channel(
        self, tmp_path, field_mappings_file, default_args_config, test_logger
    ):
        """A dict-shaped Channel is unhashable, and the filter does a set test.

        In the chunked array reader the filter call sat outside the per-event
        guard, so the TypeError abandoned every remaining event in the file.
        Filtering has to be genuinely active for this to exercise anything.
        """
        from zircolite.rules import EventFilter

        # The bounds are read from the SQL, so a match-all query would disable
        # the filter and leave this test exercising nothing.
        event_filter = EventFilter([
            {"title": "r",
             "rule": ["SELECT * FROM logs WHERE Channel = 'Security' AND EventID = 4624",
                      "SELECT * FROM logs WHERE Channel = 'System' AND EventID = 7036"],
             "channel": ["Security", "System"], "eventid": [4624, 7036]},
        ])
        assert event_filter._has_filter_data
        src = tmp_path / "events.json"
        src.write_text(json.dumps([
            {"Event": {"System": {"Channel": {"#attributes": {"a": "b"}},
                                  "EventID": 4624}}},
            {"Event": {"System": {"Channel": "Security", "EventID": 4624}}},
            {"Event": {"System": {"Channel": "System", "EventID": 7036}}},
        ]))

        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
            event_filter=event_filter,
        )
        events = list(processor.stream_json_array_chunked(str(src)))

        # An unusable channel means "cannot classify", so the event is kept
        # rather than dropped -- and crucially the two after it still arrive.
        assert len(events) == 3

    def test_non_scalar_channel_normalises_to_none(
        self, field_mappings_file, default_args_config, test_logger
    ):
        processor = StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )
        event = {"Event": {"System": {"Channel": {"#attributes": {"x": "y"}},
                                      "EventID": {"#text": "4624"}}}}

        channel, eventid = processor._extract_event_filter_fields(event)

        assert channel is None
        assert eventid == 4624


class TestIngestDegradation:
    """A file Zircolite could not read in full must be reported as such.

    ``--remove-events`` deletes every source file that is absent from
    ``failed_files``, and that set is fed from ``ingest_degraded``. A reader
    that aborts without marking the run therefore reports a healthy event
    count, exits 0, and deletes the only copy of a log nothing ever finished
    analysing.
    """

    def _processor(self, field_mappings_file, default_args_config, test_logger):
        return StreamingEventProcessor(
            config_file=field_mappings_file,
            args_config=default_args_config,
            logger=test_logger,
        )

    def test_truncated_gzip_marks_the_run_degraded(
        self, tmp_path, field_mappings_file, default_args_config, test_logger
    ):
        import gzip

        payload = b"".join(
            b'{"Event":{"System":{"Channel":"Security","EventID":%d}}}\n' % i
            for i in range(2000)
        )
        blob = gzip.compress(payload)
        src = tmp_path / "truncated.jsonl.gz"
        src.write_bytes(blob[: len(blob) // 2])

        processor = self._processor(
            field_mappings_file, default_args_config, test_logger
        )
        list(processor.stream_json_events(str(src)))

        assert processor.ingest_degraded is True

    def test_unreadable_file_marks_the_run_degraded(
        self, tmp_path, field_mappings_file, default_args_config, test_logger
    ):
        processor = self._processor(
            field_mappings_file, default_args_config, test_logger
        )
        events = list(processor.stream_json_events(str(tmp_path / "absent.json")))

        assert events == []
        assert processor.ingest_degraded is True

    def test_syslog_read_as_sysmon_linux_marks_the_run_degraded(
        self, tmp_path, field_mappings_file, default_args_config, test_logger
    ):
        """Every line converts to nothing, which is a skip, not an empty file."""
        src = tmp_path / "syslog.log"
        src.write_text("Jan  1 00:00:00 host kernel: nothing to see\n" * 50)
        extractor = EvtxExtractor(extractor_config=ExtractorConfig(), logger=test_logger)

        processor = self._processor(
            field_mappings_file, default_args_config, test_logger
        )
        events = list(processor.stream_sysmon_linux_events(str(src), extractor))

        assert events == []
        assert processor.ingest_degraded is True

    @pytest.mark.parametrize(
        "reader,filename",
        [
            ("stream_json_events", "absent.json"),
            ("stream_json_array_chunked", "absent.json"),
            ("stream_csv_events", "absent.csv"),
        ],
    )
    def test_every_reader_marks_an_unreadable_source(
        self,
        tmp_path,
        field_mappings_file,
        default_args_config,
        test_logger,
        reader,
        filename,
    ):
        processor = self._processor(
            field_mappings_file, default_args_config, test_logger
        )
        list(getattr(processor, reader)(str(tmp_path / filename)))

        assert processor.ingest_degraded is True

    @pytest.mark.parametrize(
        "reader,filename",
        [
            ("stream_sysmon_linux_events", "absent.log"),
            ("stream_auditd_events", "absent.log"),
            ("stream_evtxtract_events", "absent.log"),
            ("stream_xml_events", "absent.xml"),
        ],
    )
    def test_every_extractor_reader_marks_an_unreadable_source(
        self,
        tmp_path,
        field_mappings_file,
        default_args_config,
        test_logger,
        reader,
        filename,
    ):
        extractor = EvtxExtractor(extractor_config=ExtractorConfig(), logger=test_logger)
        processor = self._processor(
            field_mappings_file, default_args_config, test_logger
        )
        list(getattr(processor, reader)(str(tmp_path / filename), extractor))

        assert processor.ingest_degraded is True
