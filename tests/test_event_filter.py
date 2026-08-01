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
        assert not event_filter.is_enabled
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
        assert event_filter.is_enabled
        assert len(event_filter.channels) == 2
        assert len(event_filter.eventids) == 5
        assert "Microsoft-Windows-Sysmon/Operational" in event_filter.channels
        assert "Microsoft-Windows-Security-Auditing" in event_filter.channels
        assert 1 in event_filter.eventids
        assert 4624 in event_filter.eventids

    def test_init_with_channel_only(self):
        """Every rule constrains the channel, so that axis filters; eventID does not."""
        rulesets = [
            {
                "title": "Test Rule",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": []
            }
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.is_enabled
        assert event_filter._channel_filter
        assert not event_filter._eventid_filter
        assert len(event_filter.channels) == 1
        assert len(event_filter.eventids) == 0
        # The rule matches any EventID on its channel, so none may be discarded.
        assert event_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 4104
        )
        assert not event_filter.should_process_event("Security", 4104)

    def test_init_with_eventid_only(self):
        """Every rule constrains the eventID, so that axis filters; channel does not."""
        rulesets = [
            {
                "title": "Test Rule",
                "channel": [],
                "eventid": [1, 2, 3]
            }
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.is_enabled
        assert not event_filter._channel_filter
        assert event_filter._eventid_filter
        assert len(event_filter.channels) == 0
        assert len(event_filter.eventids) == 3
        assert event_filter.should_process_event("Any-Channel", 1)
        assert not event_filter.should_process_event("Any-Channel", 4624)

    def test_channel_only_rule_does_not_lose_its_events(self):
        """Regression: a channel-only rule must not be filtered by other rules' eventIDs.

        Before, one global "has filter data" flag meant a ruleset mixing a fully
        constrained rule with a channel-only rule judged the latter's events
        against the former's EventIDs, silently dropping events it would match.
        """
        rulesets = [
            {
                "title": "Fully constrained",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1],
            },
            {
                "title": "Channel only",
                "channel": ["Microsoft-Windows-PowerShell/Operational"],
                "eventid": [],
            },
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter._channel_filter
        assert event_filter._eventid_bounded
        # 4104 belongs to no rule's eventid list, but the channel-only rule wants it.
        assert event_filter.should_process_event(
            "Microsoft-Windows-PowerShell/Operational", 4104
        )
        # A channel no rule mentions is still discarded.
        assert not event_filter.should_process_event("Security", 4104)
        # The channel-only rule widens its own channel, not Sysmon's bounds.
        assert not event_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 4104
        )

    def test_init_mixed_rules(self):
        """Test that filtering is disabled when any rule has no log source (issue #117)."""
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

        # Filter must be disabled so the rule without channel/eventid sees all events;
        # otherwise alert counts for that rule would differ between single-rule and
        # full-ruleset runs.
        assert not event_filter.is_enabled
        assert event_filter._rules_without_filter == 1
        assert len(event_filter.channels) == 1
        assert len(event_filter.eventids) == 1

    def test_issue_117_full_ruleset_with_any_logsource_rule_disables_filter(self):
        """Regression for #117: full ruleset including a rule with no channel/eventid must not filter.

        When one rule has empty channel/eventid (any log source), event filtering must be
        disabled so that the same rule yields the same alert count whether run alone or
        with the full ruleset.
        """
        rulesets = [
            {"title": "Usage Of Web Request Commands And Cmdlets", "channel": [], "eventid": []},
            {"title": "External Remote SMB Logon", "channel": ["Security"], "eventid": [5140]},
            {"title": "Process Creation", "channel": ["Microsoft-Windows-Sysmon/Operational"], "eventid": [1]},
        ]
        event_filter = EventFilter(rulesets)
        assert not event_filter.is_enabled
        assert event_filter._rules_without_filter == 1

    def test_init_all_rules_without_filter(self):
        """Test initialization when all rules lack filter data."""
        rulesets = [
            {"title": "Rule 1", "channel": [], "eventid": []},
            {"title": "Rule 2"}  # Missing channel/eventid fields entirely
        ]
        event_filter = EventFilter(rulesets)

        assert not event_filter.is_enabled
        assert not event_filter.is_enabled


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

        EventIDs are bounded per channel, so an eventID only admits events on
        the channels whose rules asked for it.
        """
        # Should process - channel known, eventID known on that channel
        assert multi_channel_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 1
        )
        assert multi_channel_filter.should_process_event(
            "Microsoft-Windows-Security-Auditing", 4624
        )
        # Should NOT process - each eventID belongs to the other channel's rule
        assert not multi_channel_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 4624
        )
        assert not multi_channel_filter.should_process_event(
            "Microsoft-Windows-Security-Auditing", 1
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


class TestPerChannelEventIDBounds:
    """Tests for the per-channel eventID bounds."""

    def test_eventid_bounds_are_per_channel(self):
        """An eventID admits events only on the channels whose rules asked for it."""
        rulesets = [
            {"title": "A", "channel": ["Channel-A"], "eventid": [1]},
            {"title": "B", "channel": ["Channel-B"], "eventid": [2]},
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event("Channel-A", 1)
        assert event_filter.should_process_event("Channel-B", 2)
        assert not event_filter.should_process_event("Channel-A", 2)
        assert not event_filter.should_process_event("Channel-B", 1)

    def test_channel_only_rule_makes_only_its_own_channel_any(self):
        """A rule with no eventID widens its channel, leaving the others bounded."""
        rulesets = [
            {"title": "Bounded", "channel": ["Channel-A"], "eventid": [1]},
            {"title": "Unbounded", "channel": ["Channel-B"], "eventid": []},
        ]
        event_filter = EventFilter(rulesets)

        assert not event_filter.should_process_event("Channel-A", 999)
        assert event_filter.should_process_event("Channel-B", 999)

    def test_second_rule_on_same_channel_with_no_eventid_makes_it_any(self):
        """Once a channel is unbounded it stays unbounded, whatever the rule order."""
        rulesets = [
            {"title": "Bounded", "channel": ["Channel-A"], "eventid": [1]},
            {"title": "Unbounded", "channel": ["Channel-A"], "eventid": []},
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event("Channel-A", 999)
        assert event_filter.should_process_event("Channel-A", 1)

    def test_missing_eventid_on_bounded_channel_is_kept(self):
        """An event with no usable eventID carries too little information to discard."""
        rulesets = [{"title": "Bounded", "channel": ["Channel-A"], "eventid": [1]}]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event("Channel-A", None)

    def test_rule_with_eventid_and_no_channel_falls_back_to_global_axis(self):
        """Per-channel bounds need every rule to name a channel."""
        rulesets = [
            {"title": "No channel", "channel": [], "eventid": [1]},
            {"title": "With channel", "channel": ["Channel-A"], "eventid": [2]},
        ]
        event_filter = EventFilter(rulesets)

        assert not event_filter._channel_filter
        assert event_filter._eventid_filter
        # The channel axis is off, so any channel carrying a known eventID passes
        assert event_filter.should_process_event("Any-Channel", 1)
        assert event_filter.should_process_event("Channel-A", 2)
        assert not event_filter.should_process_event("Any-Channel", 999)

    def test_channel_map_merges_case_variants(self):
        """Two spellings of one channel merge their bounds instead of overwriting."""
        rulesets = [
            {"title": "A", "channel": ["Security"], "eventid": [1]},
            {"title": "B", "channel": ["SECURITY"], "eventid": [2]},
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event("Security", 1)
        assert event_filter.should_process_event("Security", 2)
        assert event_filter.should_process_event("security", 1)
        assert not event_filter.should_process_event("Security", 3)

    def test_correlation_rule_keeps_its_own_channel_alive(self):
        """A channel only a correlation rule needs must survive the filter.

        Correlation rules carry no channel/eventid metadata, so their channel
        has to be read out of the SQL that embeds the base rule. Miss it and
        every event on that channel is dropped at ingest and the correlation
        can never fire.
        """
        rulesets = [
            {
                "title": "Sysmon",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1],
                "rule": [
                    "SELECT * FROM logs WHERE "
                    "Channel='Microsoft-Windows-Sysmon/Operational' AND EventID=1"
                ],
            },
            {
                "title": "Correlation",
                "correlation": True,
                "channel": [],
                "eventid": [],
                "rule": [
                    "SELECT u, COUNT(*) AS c FROM (SELECT * FROM logs WHERE "
                    "Channel='Security' AND EventID=4625) AS subquery "
                    "GROUP BY u HAVING c >= 5"
                ],
            },
        ]
        event_filter = EventFilter(rulesets)

        # The correlation's channel is claimed, and left unbounded: its SQL
        # decides which eventIDs matter, not the filter.
        assert event_filter.should_process_event("Security", 4625)
        assert event_filter.should_process_event("Security", 1234)
        # Unrelated channels keep the selectivity the filter exists for
        assert event_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 1
        )
        assert not event_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 99
        )
        assert not event_filter.should_process_event("Application", 1)

    def test_correlation_rule_without_a_readable_channel_disables_filtering(self):
        """An unreadable correlation rule must switch filtering off, not guess.

        pySigma emits correlation SQL with no Channel predicate whenever the
        logsource carried no pipeline. Nothing then says which channel the rule
        consumes, and the only safe answer is to stop dropping events.
        """
        rulesets = [
            {
                "title": "Sysmon",
                "channel": ["Microsoft-Windows-Sysmon/Operational"],
                "eventid": [1],
                "rule": [
                    "SELECT * FROM logs WHERE "
                    "Channel='Microsoft-Windows-Sysmon/Operational' AND EventID=1"
                ],
            },
            {
                "title": "Correlation",
                "correlation": True,
                "rule": [
                    "SELECT u, COUNT(*) AS c FROM (SELECT * FROM logs WHERE "
                    "EventID=4625) AS subquery GROUP BY u HAVING c >= 5"
                ],
            },
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.is_enabled is False
        assert event_filter.should_process_event("Security", 4625)
        assert event_filter.should_process_event("Anything", 999)

    def test_unparseable_eventids_make_channel_any(self):
        """An empty bound must never mean "nothing" -- it means "any"."""
        rulesets = [{"title": "A", "channel": ["Channel-A"], "eventid": ["not_a_number"]}]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event("Channel-A", 999)

    def test_no_false_negatives_vs_per_rule_ground_truth(self):
        """The filter must never drop an event some rule would have matched."""
        rulesets = [
            {"title": "A", "channel": ["Channel-A"], "eventid": [1, 2]},
            {"title": "B", "channel": ["Channel-B", "channel-a"], "eventid": [3]},
            {"title": "C", "channel": ["Channel-C"], "eventid": []},
        ]
        event_filter = EventFilter(rulesets)

        def accepted_by_some_rule(channel, eventid):
            for rule in rulesets:
                channels = [c for c in rule["channel"] if c]
                eventids = rule["eventid"]
                if channels and (
                    channel is None
                    or not any(channel.lower() == c.lower() for c in channels)
                ):
                    continue
                if eventids and eventid is not None and eventid not in eventids:
                    continue
                return True
            return False

        probes = ["Channel-A", "CHANNEL-A", "channel-b", "Channel-C", "Absent", None]
        for channel in probes:
            for eventid in [1, 2, 3, 999, None]:
                if accepted_by_some_rule(channel, eventid):
                    assert event_filter.should_process_event(channel, eventid), (
                        f"false negative for {channel!r} / {eventid!r}"
                    )

    @pytest.mark.integration
    def test_shipped_merged_ruleset_bounds_sysmon(self):
        """The shipped Windows ruleset must bound eventIDs on all but two channels."""
        from pathlib import Path

        import orjson

        ruleset_path = Path(__file__).parent.parent / "rules" / "rules_windows_merged.json"
        if not ruleset_path.exists():
            pytest.skip("shipped ruleset not available")

        rules = orjson.loads(ruleset_path.read_bytes())
        non_correlation = [r for r in rules if not r.get("correlation")]
        event_filter = EventFilter(non_correlation)
        stats = event_filter.get_stats()

        assert stats["mode"] == "per-channel"
        assert stats["any_eventid_channels"] == ["Security", "Windows PowerShell"]
        assert stats["bounded_channels_count"] == stats["channels_count"] - 2
        # Sysmon 5 (ProcessTerminate) is claimed by no rule
        assert not event_filter.should_process_event(
            "Microsoft-Windows-Sysmon/Operational", 5
        )
        # Security is unbounded, so its high-volume IDs still pass
        assert event_filter.should_process_event("Security", 4672)


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
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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
        for _event in processor.stream_json_events(str(test_file)):
            processed_count += 1

        # Should have processed 2 events and filtered 2
        assert processed_count == 2
        assert processor.events_filtered_count == 2

    def test_streaming_processor_no_filter(self, tmp_path):
        """Test that StreamingEventProcessor processes all events without filter."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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
        for _event in processor.stream_json_events(str(test_file)):
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
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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

        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file)))
        assert processed_count == 1

    def test_extract_from_flat_structure(self, sysmon_filter, tmp_path):
        """Test extraction from flat pre-flattened structure."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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

        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file)))
        assert processed_count == 1

    def test_extract_from_system_top_level(self, sysmon_filter, tmp_path):
        """Test extraction from System at top level structure."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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

        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file)))
        assert processed_count == 1

    def test_extract_eventid_with_text_attribute(self, sysmon_filter, tmp_path):
        """Test extraction when EventID is a dict with #text attribute."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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

        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file)))
        assert processed_count == 1

    def test_extract_lowercase_fields(self, sysmon_filter, tmp_path):
        """Test extraction from lowercase field names."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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

        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file)))
        assert processed_count == 1


class TestTimestampAutoDetection:
    """Tests for timestamp field auto-detection."""

    def test_auto_detect_system_time(self, tmp_path):
        """Test auto-detection of SystemTime field."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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

        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file)))
        assert processed_count == 1
        # With no explicit field, the config's timestamp_detection.default_field
        # seeds the processor's time field
        assert processor.time_field == "SystemTime"

    def test_auto_detect_timestamp_field(self, tmp_path):
        """Test auto-detection of @timestamp field (ECS format)."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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

        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file)))
        assert processed_count == 1
        # After flattening, @timestamp becomes "timestamp" (@ removed)
        # The detection should find a valid timestamp field
        assert processor._detected_time_field in ["@timestamp", "timestamp"]

    def test_auto_detect_utc_time_field(self, tmp_path):
        """Test auto-detection of UtcTime field (Sysmon format)."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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

        processed_count = sum(1 for _ in processor.stream_json_events(str(test_file)))
        assert processed_count == 1
        assert processor._detected_time_field == "UtcTime"

    def test_time_filter_excludes_events(self, tmp_path):
        """Test that time filtering excludes events outside the range."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

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

        processed_events = list(processor.stream_json_events(str(test_file)))
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


class TestEventFilterConfigKeys:
    """Regression tests: event_filter.enabled / filter_all_sources must be honored."""

    def _filter(self):
        rulesets = [{
            "title": "Sysmon Rule",
            "channel": ["Microsoft-Windows-Sysmon/Operational"],
            "eventid": [1],
        }]
        return EventFilter(rulesets)

    def _write_config(self, tmp_path, event_filter_cfg):
        import json as std_json
        cfg = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": False, "transforms": {},
            "event_filter": event_filter_cfg,
        }
        cfg_file = tmp_path / "config.json"
        cfg_file.write_text(std_json.dumps(cfg))
        return str(cfg_file)

    def test_event_filter_enabled_false_disables_filtering(self, tmp_path):
        """event_filter.enabled: false must disable filtering entirely."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

        config_file = self._write_config(tmp_path, {
            "enabled": False,
            "channel_fields": ["Channel"],
            "eventid_fields": ["EventID"],
        })
        test_file = tmp_path / "events.json"
        # This event would be filtered OUT if filtering were active
        test_file.write_text('{"Channel": "Unknown/Channel", "EventID": 9999}\n')

        args = Namespace(json_input=True, json_array_input=False)
        processor = StreamingEventProcessor(
            config_file=config_file,
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=self._filter(),
        )
        assert processor._filtering_enabled is False
        count = sum(1 for _ in processor.stream_json_events(str(test_file)))
        assert count == 1

    def test_filter_all_sources_false_skips_non_windows_input(self, tmp_path):
        """With filter_all_sources false, auditd input bypasses filtering."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

        config_file = self._write_config(tmp_path, {
            "enabled": True,
            "filter_all_sources": False,
            "channel_fields": ["Channel"],
            "eventid_fields": ["EventID"],
        })
        args = Namespace(json_input=False, json_array_input=False, auditd_input=True)
        processor = StreamingEventProcessor(
            config_file=config_file,
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=self._filter(),
        )
        assert processor._filtering_enabled is True
        assert processor._should_process_event({"Channel": "Unknown", "EventID": 9999}) is True

    def test_filter_all_sources_true_filters_non_windows_input(self, tmp_path):
        """With filter_all_sources true, auditd input is filtered too."""
        from argparse import Namespace

        from zircolite.config import ProcessingConfig
        from zircolite.streaming import StreamingEventProcessor

        config_file = self._write_config(tmp_path, {
            "enabled": True,
            "filter_all_sources": True,
            "channel_fields": ["Channel"],
            "eventid_fields": ["EventID"],
        })
        args = Namespace(json_input=False, json_array_input=False, auditd_input=True)
        processor = StreamingEventProcessor(
            config_file=config_file,
            args_config=args,
            processing_config=ProcessingConfig(),
            event_filter=self._filter(),
        )
        assert processor._should_process_event({"Channel": "Unknown", "EventID": 9999}) is False


class TestBoundsComeFromRuleSql:
    """The eventID metadata is a bag of values, so bounds come from the SQL.

    ``pysigma-backend-sqlite`` harvests ``eventid`` from every detection group
    including negated ``filter`` blocks, and ignores the rule's condition. Read
    as an allow-list it inverts the rule: the filter then admits exactly the
    eventIDs the rule excludes and drops the ones it wants.
    """

    def test_eventid_only_in_a_negated_filter_does_not_bound_the_channel(self):
        rulesets = [
            {
                "title": "Excludes 4624",
                "channel": ["Security"],
                "eventid": [4624],  # harvested from the `filter:` block
                "rule": [
                    "SELECT * FROM logs WHERE Channel='Security' "
                    "AND CommandLine LIKE '%x%' AND NOT (EventID=4624)"
                ],
            }
        ]
        event_filter = EventFilter(rulesets)

        # Every eventID on the channel must survive: the rule wants all but one
        assert event_filter.should_process_event("Security", 4688)
        assert event_filter.should_process_event("Security", 4720)
        assert event_filter.should_process_event("Security", 4624)

    def test_or_branch_without_an_eventid_does_not_bound_the_channel(self):
        """One free branch frees the disjunction, so the branch stays reachable."""
        rulesets = [
            {
                "title": "EventID or CommandLine",
                "channel": ["Security"],
                "eventid": [4688],
                "rule": [
                    "SELECT * FROM logs WHERE Channel='Security' "
                    "AND (EventID=4688 OR CommandLine LIKE '%mimikatz%')"
                ],
            }
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event("Security", 4104)
        assert event_filter.should_process_event("Security", 4688)

    def test_a_positive_eventid_still_bounds_the_channel(self):
        """The optimisation must survive the fix, or ingestion slows for nothing."""
        rulesets = [
            {
                "title": "Process creation",
                "channel": ["Security"],
                "eventid": [4688],
                "rule": [
                    "SELECT * FROM logs WHERE Channel='Security' AND EventID=4688"
                ],
            }
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event("Security", 4688)
        assert not event_filter.should_process_event("Security", 4104)
        assert not event_filter.should_process_event("Application", 4688)

    def test_eventid_in_an_in_list_bounds_the_channel(self):
        rulesets = [
            {
                "title": "Several ids",
                "channel": ["Security"],
                "rule": [
                    "SELECT * FROM logs WHERE Channel='Security' "
                    "AND EventID IN (4624,4625,4634)"
                ],
            }
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event("Security", 4625)
        assert not event_filter.should_process_event("Security", 4688)

    def test_eventid_written_inside_a_string_literal_is_not_a_constraint(self):
        """A CommandLine pattern mentioning an eventID must not bound anything.

        Shipped rules really do this: a rule hunting ``wevtutil`` command lines
        contains the text ``.eventid -eq 462`` inside a LIKE pattern.
        """
        rulesets = [
            {
                "title": "Log query recon",
                "channel": ["Security"],
                "rule": [
                    "SELECT * FROM logs WHERE Channel='Security' AND EventID=4688 "
                    "AND CommandLine LIKE '%.eventid -eq 462%'"
                ],
            }
        ]
        event_filter = EventFilter(rulesets)

        # Bounded by the real constraint (4688) and not by the text 462
        assert event_filter.should_process_event("Security", 4688)
        assert not event_filter.should_process_event("Security", 462)


class TestEventFilterChannelMetadataIsNotAChannel:
    """The `channel` metadata is not always a channel name.

    pysigma-backend-sqlite harvests the raw SigmaString of every Channel
    detection item, so a wildcard match contributes a pattern and a negated
    match contributes the channel the rule *excludes*. Neither names a channel
    the rule wants, but both are non-empty -- so the rule still counted as
    channel-bounded and the fail-open path never fired.
    """

    def test_wildcard_channel_pattern_does_not_bound_the_filter(self):
        """`Channel|contains: PowerShell` becomes '*PowerShell*', which matches nothing."""
        rulesets = [
            {
                "title": "PowerShell script block",
                "channel": ["*powershell*"],
                "rule": [
                    "SELECT * FROM logs WHERE Channel LIKE '%PowerShell%' "
                    "AND EventID = 4104"
                ],
            },
            {
                "title": "Logon",
                "channel": ["Security"],
                "rule": [
                    "SELECT * FROM logs WHERE Channel = 'Security' AND EventID = 4624"
                ],
            },
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event(
            "Microsoft-Windows-PowerShell/Operational", 4104
        ), "the events the wildcard rule needs must survive the early filter"

    def test_channel_named_only_under_a_negation_does_not_bound_the_filter(self):
        """A rule excluding a channel matches every *other* channel."""
        rulesets = [
            {
                "title": "Script block outside Windows PowerShell",
                "channel": ["Windows PowerShell"],
                "rule": [
                    "SELECT * FROM logs WHERE EventID = 4104 "
                    "AND (NOT Channel = 'Windows PowerShell')"
                ],
            },
            {
                "title": "Logon",
                "channel": ["Security"],
                "rule": [
                    "SELECT * FROM logs WHERE Channel = 'Security' AND EventID = 4624"
                ],
            },
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event(
            "Microsoft-Windows-PowerShell/Operational", 4104
        ), "the filter must not admit only the channel the rule excludes"

    def test_metadata_still_used_when_the_rule_carries_no_sql(self):
        """Rules without SQL cannot run; their metadata may still widen a channel."""
        rulesets = [
            {"title": "Metadata only", "channel": ["Security"], "eventid": [4624]}
        ]
        event_filter = EventFilter(rulesets)

        assert event_filter.should_process_event("Security", 4624)
