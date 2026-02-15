#!python3
"""
Tests for EventFilter functionality.

This module tests the EventFilter class that provides early event filtering
based on channel and eventID from loaded rules.
"""

import pytest
from zircolite.rules import EventFilter


class TestEventFilterInit:
    """Tests for EventFilter initialization."""

    def test_init_empty_rulesets(self):
        """Test initialization with empty rulesets."""
        event_filter = EventFilter([])
        assert not event_filter.is_enabled
        assert not event_filter.has_filter_data
        assert len(event_filter.channels) == 0
        assert len(event_filter.eventids) == 0

    def test_init_with_channel_and_eventid(self):
        """Test initialization with rules containing channel and eventID."""
        rulesets = [
            {
                "title": "Test Rule 1",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1, 2, 3]
            },
            {
                "title": "Test Rule 2",
                "channel": ["Microsoft-Windows-Security-Auditing"],
                "eventid": [4624, 4625]
            }
        ]
        event_filter = EventFilter(rulesets)
        
        assert event_filter.is_enabled
        assert event_filter.has_filter_data
        assert len(event_filter.channels) == 2
        assert len(event_filter.eventids) == 5
        assert "Microsoft-Windows-Sysmon/Operational" in event_filter.channels
        assert "Microsoft-Windows-Security-Auditing" in event_filter.channels
        assert 1 in event_filter.eventids
        assert 4624 in event_filter.eventids

    def test_init_with_channel_only(self):
        """Test initialization with rules containing only channel."""
        rulesets = [
            {
                "title": "Test Rule",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": []
            }
        ]
        event_filter = EventFilter(rulesets)
        
        # Filter not enabled (need BOTH channels AND eventIDs)
        assert not event_filter.is_enabled
        assert len(event_filter.channels) == 1
        assert len(event_filter.eventids) == 0

    def test_init_with_eventid_only(self):
        """Test initialization with rules containing only eventID."""
        rulesets = [
            {
                "title": "Test Rule",
                "channel": [],
                "eventid": [1, 2, 3]
            }
        ]
        event_filter = EventFilter(rulesets)
        
        # Filter not enabled (need BOTH channels AND eventIDs)
        assert not event_filter.is_enabled
        assert len(event_filter.channels) == 0
        assert len(event_filter.eventids) == 3

    def test_init_mixed_rules(self):
        """Test that filtering works even when some rules lack filter data."""
        rulesets = [
            {
                "title": "Rule with filter",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1]
            },
            {
                "title": "Rule without filter",
                "channel": [],
                "eventid": []
            }
        ]
        event_filter = EventFilter(rulesets)
        
        # Should be enabled - has both channels and eventIDs
        assert event_filter.is_enabled
        assert len(event_filter.channels) == 1
        assert len(event_filter.eventids) == 1

    def test_init_all_rules_without_filter(self):
        """Test initialization when all rules lack filter data."""
        rulesets = [
            {"title": "Rule 1", "channel": [], "eventid": []},
            {"title": "Rule 2"}  # Missing channel/eventid fields entirely
        ]
        event_filter = EventFilter(rulesets)
        
        assert not event_filter.is_enabled
        assert not event_filter.has_filter_data


class TestEventFilterShouldProcess:
    """Tests for should_process_event method."""

    @pytest.fixture
    def sysmon_filter(self):
        """Create a filter for Sysmon events."""
        rulesets = [
            {
                "title": "Sysmon Rule",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1, 3, 5, 7]
            }
        ]
        return EventFilter(rulesets)

    @pytest.fixture
    def multi_channel_filter(self):
        """Create a filter for multiple channels."""
        rulesets = [
            {
                "title": "Sysmon Rule",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1, 2]
            },
            {
                "title": "Security Rule",
                "channel": ["Microsoft-Windows-Security-Auditing"],
                "eventid": [4624, 4625]
            }
        ]
        return EventFilter(rulesets)

    def test_should_process_matching_event(self, sysmon_filter):
        """Test that matching events are processed."""
        assert sysmon_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 1
        )
        assert sysmon_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 3
        )

    def test_should_not_process_non_matching_eventid(self, sysmon_filter):
        """Test that events with non-matching eventID are skipped."""
        assert not sysmon_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 999
        )

    def test_should_not_process_non_matching_channel(self, sysmon_filter):
        """Test that events with non-matching channel are skipped."""
        assert not sysmon_filter.should_process_event(
            "Microsoft-Windows-Security-Auditing", 1
        )

    def test_should_process_with_none_channel(self, sysmon_filter):
        """Test that events with None channel are processed (can't filter)."""
        assert sysmon_filter.should_process_event(None, 1)

    def test_should_process_with_none_eventid(self, sysmon_filter):
        """Test that events with None eventID are processed (can't filter)."""
        assert sysmon_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", None
        )

    def test_should_process_multi_channel(self, multi_channel_filter):
        """Test filtering with multiple channels.
        
        With the current logic, channels and eventIDs are checked independently.
        If channel is in known channels AND eventID is in known eventIDs → process.
        """
        # Should process - channel known, eventID known
        assert multi_channel_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 1
        )
        assert multi_channel_filter.should_process_event(
            "Microsoft-Windows-Security-Auditing", 4624
        )
        # Should also process - both channel and eventID are in the known sets
        # (even if they originally came from different rules)
        assert multi_channel_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 4624  # Channel known, EventID known
        )
        assert multi_channel_filter.should_process_event(
            "Microsoft-Windows-Security-Auditing", 1  # Channel known, EventID known
        )
        # Should NOT process - unknown channel
        assert not multi_channel_filter.should_process_event(
            "Unknown-Channel", 1
        )
        # Should NOT process - unknown eventID
        assert not multi_channel_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 9999
        )

    def test_case_insensitive_channel_matching(self, sysmon_filter):
        """Test that channel matching is case-insensitive."""
        assert sysmon_filter.should_process_event(
            "microsoft-windows-sysmon/operational", 1
        )
        assert sysmon_filter.should_process_event(
            "MICROSOFT-WINDOWS-SYSMON/OPERATIONAL", 1
        )

    def test_eventid_string_conversion(self, sysmon_filter):
        """Test that string eventIDs are converted to int."""
        assert sysmon_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", "1"
        )

    def test_invalid_eventid_returns_true(self, sysmon_filter):
        """Invalid eventid (ValueError/TypeError) cannot be filtered; process event."""
        assert sysmon_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", "not_a_number"
        )
        assert sysmon_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", None
        )

    def test_disabled_filter_processes_all(self):
        """Test that disabled filter processes all events."""
        event_filter = EventFilter([])  # Empty = disabled
        assert event_filter.should_process_event("Any-Channel", 9999)
        assert event_filter.should_process_event(None, None)


class TestEventFilterStats:
    """Tests for get_stats method."""

    def test_get_stats(self):
        """Test that stats are returned correctly."""
        rulesets = [
            {
                "title": "Test Rule",
                "channel": ["Channel1", "Channel2"],
                "eventid": [1, 2, 3]
            }
        ]
        event_filter = EventFilter(rulesets)
        stats = event_filter.get_stats()
        
        assert stats['channels_count'] == 2
        assert stats['eventids_count'] == 3
        assert stats['is_enabled']
        assert stats['rules_with_filter'] == 1
        assert stats['rules_without_filter'] == 0


class TestEventFilterExtraction:
    """Tests for channel/eventID extraction."""

    def test_channels_and_eventids_collected(self):
        """Test that channels and eventIDs are collected correctly."""
        rulesets = [
            {
                "title": "Test Rule",
                "channel": ["Ch1", "Ch2"],
                "eventid": [10, 20]
            }
        ]
        event_filter = EventFilter(rulesets)
        
        assert "Ch1" in event_filter.channels
        assert "Ch2" in event_filter.channels
        assert 10 in event_filter.eventids
        assert 20 in event_filter.eventids
        assert len(event_filter.channels) == 2
        assert len(event_filter.eventids) == 2

    def test_duplicate_channels_and_eventids_deduplicated(self):
        """Test that duplicate channels and eventIDs are deduplicated."""
        rulesets = [
            {
                "title": "Rule 1",
                "channel": ["Ch1"],
                "eventid": [1, 2]
            },
            {
                "title": "Rule 2",
                "channel": ["Ch1", "Ch2"],
                "eventid": [1]
            }
        ]
        event_filter = EventFilter(rulesets)
        
        # Should have unique values only
        assert len(event_filter.channels) == 2  # Ch1, Ch2
        assert len(event_filter.eventids) == 2  # 1, 2


class TestEventFilterRealWorldScenarios:
    """Integration tests with realistic rule structures."""

    def test_sysmon_ruleset_structure(self):
        """Test with a Sysmon-like ruleset structure."""
        rulesets = [
            {
                "title": "HackTool - Koh Default Named Pipe",
                "id": "0adc67e0-a68f-4ffd-9c43-28905aad5d6a",
                "status": "test",
                "level": "critical",
                "rule": ["SELECT * FROM logs WHERE Channel='Microsoft-Windows-Sysmon/Operational' AND EventID IN (17, 18)"],
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [17, 18]
            },
            {
                "title": "Process Creation",
                "id": "12345678-1234-1234-1234-123456789012",
                "status": "test",
                "level": "medium",
                "rule": ["SELECT * FROM logs WHERE Channel='Microsoft-Windows-Sysmon/Operational' AND EventID=1"],
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1]
            }
        ]
        event_filter = EventFilter(rulesets)
        
        assert event_filter.is_enabled
        assert len(event_filter.eventids) == 3  # 1, 17, 18
        assert len(event_filter.channels) == 1
        
        # Test filtering
        assert event_filter.should_process_event("Microsoft-Windows-Sysmon/Operational", 1)
        assert event_filter.should_process_event("Microsoft-Windows-Sysmon/Operational", 17)
        assert event_filter.should_process_event("Microsoft-Windows-Sysmon/Operational", 18)
        assert not event_filter.should_process_event("Microsoft-Windows-Sysmon/Operational", 2)
        assert not event_filter.should_process_event("Other-Channel", 1)


class TestStreamingProcessorWithFilter:
    """Tests for StreamingEventProcessor with EventFilter."""

    @pytest.fixture
    def sysmon_filter(self):
        """Create a filter for Sysmon events."""
        rulesets = [
            {
                "title": "Process Creation",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1]
            }
        ]
        return EventFilter(rulesets)

    def test_streaming_processor_filter_counts(self, sysmon_filter, tmp_path):
        """Test that StreamingEventProcessor tracks filtered event counts."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        # Create test JSONL file with mixed events
        test_file = tmp_path / "test_events.json"
        events = [
            # Should be processed (matches filter)
            '{"Event": {"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}}}',
            # Should be filtered (wrong EventID)
            '{"Event": {"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 2}}}',
            # Should be filtered (wrong channel)
            '{"Event": {"System": {"Channel": "Other-Channel", "EventID": 1}}}',
            # Should be processed (matches filter)
            '{"Event": {"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}}}',
        ]
        test_file.write_text('\n'.join(events))
        
        # Create processor with filter
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=sysmon_filter
        )
        
        # Stream events and count
        processed_count = 0
        for event in processor.stream_json_events(str(test_file), json_array=False):
            processed_count += 1
        
        # Should have processed 2 events and filtered 2
        assert processed_count == 2
        assert processor.events_filtered_count == 2

    def test_streaming_processor_no_filter(self, tmp_path):
        """Test that StreamingEventProcessor processes all events without filter."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        # Create test JSONL file
        test_file = tmp_path / "test_events.json"
        events = [
            '{"Event": {"System": {"Channel": "Channel1", "EventID": 1}}}',
            '{"Event": {"System": {"Channel": "Channel2", "EventID": 2}}}',
            '{"Event": {"System": {"Channel": "Channel3", "EventID": 3}}}',
        ]
        test_file.write_text('\n'.join(events))
        
        # Create processor without filter
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=None
        )
        
        # Stream events and count
        processed_count = 0
        for event in processor.stream_json_events(str(test_file), json_array=False):
            processed_count += 1
        
        # Should have processed all 3 events
        assert processed_count == 3
        assert processor.events_filtered_count == 0


class TestConfigurableFieldPaths:
    """Tests for configurable field paths in event filter extraction."""

    @pytest.fixture
    def sysmon_filter(self):
        """Create a filter for Sysmon events."""
        rulesets = [
            {
                "title": "Process Creation",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1]
            }
        ]
        return EventFilter(rulesets)

    def test_extract_from_standard_evtx_structure(self, sysmon_filter, tmp_path):
        """Test extraction from standard Event.System structure."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        test_file = tmp_path / "test_events.json"
        events = [
            '{"Event": {"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}}}',
        ]
        test_file.write_text('\n'.join(events))
        
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=sysmon_filter
        )
        
        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file), json_array=False))
        assert processed_count == 1

    def test_extract_from_flat_structure(self, sysmon_filter, tmp_path):
        """Test extraction from flat pre-flattened structure."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        test_file = tmp_path / "test_events.json"
        events = [
            '{"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}',
        ]
        test_file.write_text('\n'.join(events))
        
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=sysmon_filter
        )
        
        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file), json_array=False))
        assert processed_count == 1

    def test_extract_from_system_top_level(self, sysmon_filter, tmp_path):
        """Test extraction from System at top level structure."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        test_file = tmp_path / "test_events.json"
        events = [
            '{"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}}',
        ]
        test_file.write_text('\n'.join(events))
        
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=sysmon_filter
        )
        
        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file), json_array=False))
        assert processed_count == 1

    def test_extract_eventid_with_text_attribute(self, sysmon_filter, tmp_path):
        """Test extraction when EventID is a dict with #text attribute."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        test_file = tmp_path / "test_events.json"
        events = [
            '{"Event": {"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": {"#text": "1"}}}}',
        ]
        test_file.write_text('\n'.join(events))
        
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=sysmon_filter
        )
        
        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file), json_array=False))
        assert processed_count == 1

    def test_extract_lowercase_fields(self, sysmon_filter, tmp_path):
        """Test extraction from lowercase field names."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        test_file = tmp_path / "test_events.json"
        events = [
            '{"channel": "Microsoft-Windows-Sysmon/Operational", "eventid": 1}',
        ]
        test_file.write_text('\n'.join(events))
        
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=sysmon_filter
        )
        
        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file), json_array=False))
        assert processed_count == 1


class TestTimestampAutoDetection:
    """Tests for timestamp field auto-detection."""

    def test_auto_detect_system_time(self, tmp_path):
        """Test auto-detection of SystemTime field."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        test_file = tmp_path / "test_events.json"
        events = [
            '{"SystemTime": "2024-01-01T10:00:00.000Z", "Channel": "Test", "EventID": 1}',
        ]
        test_file.write_text('\n'.join(events))
        
        # Set up processor with time filter but no explicit time_field
        config = ProcessingConfig(
            time_after="2024-01-01T09:00:00",
            time_before="2024-01-01T11:00:00",
            time_field=None  # No explicit field, should auto-detect
        )
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=config,
            event_filter=None
        )
        
        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file), json_array=False))
        assert processed_count == 1
        assert processor._detected_time_field == "SystemTime"

    def test_auto_detect_timestamp_field(self, tmp_path):
        """Test auto-detection of @timestamp field (ECS format)."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        test_file = tmp_path / "test_events.json"
        events = [
            '{"@timestamp": "2024-01-01T10:00:00.000Z", "Channel": "Test", "EventID": 1}',
        ]
        test_file.write_text('\n'.join(events))
        
        config = ProcessingConfig(
            time_after="2024-01-01T09:00:00",
            time_before="2024-01-01T11:00:00",
            time_field=None
        )
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=config,
            event_filter=None
        )
        
        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file), json_array=False))
        assert processed_count == 1
        # After flattening, @timestamp becomes "timestamp" (@ removed)
        # The detection should find a valid timestamp field
        assert processor._detected_time_field in ["@timestamp", "timestamp"]

    def test_auto_detect_utc_time_field(self, tmp_path):
        """Test auto-detection of UtcTime field (Sysmon format)."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        test_file = tmp_path / "test_events.json"
        events = [
            '{"UtcTime": "2024-01-01T10:00:00.000Z", "Channel": "Test", "EventID": 1}',
        ]
        test_file.write_text('\n'.join(events))
        
        config = ProcessingConfig(
            time_after="2024-01-01T09:00:00",
            time_before="2024-01-01T11:00:00",
            time_field=None
        )
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=config,
            event_filter=None
        )
        
        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file), json_array=False))
        assert processed_count == 1
        assert processor._detected_time_field == "UtcTime"

    def test_time_filter_excludes_events(self, tmp_path):
        """Test that time filtering excludes events outside the range."""
        from zircolite.streaming import StreamingEventProcessor
        from zircolite.config import ProcessingConfig
        from argparse import Namespace
        
        test_file = tmp_path / "test_events.json"
        events = [
            '{"SystemTime": "2024-01-01T08:00:00.000Z", "Channel": "Test", "EventID": 1}',  # Before range
            '{"SystemTime": "2024-01-01T10:00:00.000Z", "Channel": "Test", "EventID": 2}',  # In range
            '{"SystemTime": "2024-01-01T12:00:00.000Z", "Channel": "Test", "EventID": 3}',  # After range
        ]
        test_file.write_text('\n'.join(events))
        
        config = ProcessingConfig(
            time_after="2024-01-01T09:00:00",
            time_before="2024-01-01T11:00:00",
            time_field="SystemTime"
        )
        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file="config/config.yaml",
            args_config=args,
            processing_config=config,
            event_filter=None
        )
        
        processed_events = list(processor.stream_json_events(str(test_file), json_array=False))
        assert len(processed_events) == 1
        assert processed_events[0].get("EventID") == 2


class TestEventFilterFieldMappingsConfig:
    """Tests for event filter and timestamp detection in field mappings config (config/config.yaml)."""

    def test_load_field_mappings_includes_event_filter(self):
        """Test that load_field_mappings includes event_filter section."""
        from zircolite.utils import load_field_mappings
        
        config = load_field_mappings("config/config.yaml")
        
        assert "event_filter" in config
        assert "channel_fields" in config["event_filter"]
        assert "eventid_fields" in config["event_filter"]
        assert len(config["event_filter"]["channel_fields"]) > 0
        assert len(config["event_filter"]["eventid_fields"]) > 0
        
    def test_load_field_mappings_includes_timestamp_detection(self):
        """Test that load_field_mappings includes timestamp_detection section."""
        from zircolite.utils import load_field_mappings
        
        config = load_field_mappings("config/config.yaml")
        
        assert "timestamp_detection" in config
        assert "auto_detect" in config["timestamp_detection"]
        assert "detection_fields" in config["timestamp_detection"]
        assert len(config["timestamp_detection"]["detection_fields"]) > 0
