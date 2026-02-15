"""
Tests for the console module (quiet mode, output helpers, stats).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from zircolite.console import (
    set_quiet_mode,
    is_quiet,
    print_banner,
    print_section,
    print_no_detections,
    print_step,
    print_substep,
    print_info,
    print_warning,
    print_error,
    print_error_panel,
    print_success,
    print_file,
    print_count,
    print_detection,
    DetectionStats,
    ProcessingStats,
    ZircoliteConsole,
    RichProgressTracker,
    make_detection_counter,
    _format_file_node,
    build_file_tree,
    format_level,
    make_severity_badge,
    build_attack_summary,
    build_detection_table,
    make_file_link,
    LEVEL_PRIORITY,
    console,
)


# =============================================================================
# Quiet mode
# =============================================================================

class TestQuietMode:
    """Tests for set_quiet_mode and is_quiet."""

    def test_default_not_quiet(self):
        set_quiet_mode(False)
        assert is_quiet() is False

    def test_set_quiet_true(self):
        set_quiet_mode(True)
        try:
            assert is_quiet() is True
        finally:
            set_quiet_mode(False)

    def test_set_quiet_false(self):
        set_quiet_mode(True)
        set_quiet_mode(False)
        assert is_quiet() is False


# =============================================================================
# Banner and section (with capture)
# =============================================================================

class TestBannerAndSection:
    """Tests for print_banner and print_section."""

    def test_print_banner_visible_when_not_quiet(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_banner("3.2.0")
        out = capture.get()
        assert "Standalone Sigma" in out or "Sigma" in out
        assert "3.2.0" in out

    def test_print_banner_suppressed_when_quiet(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_banner("3.2.0")
            assert capture.get() == ""
        finally:
            set_quiet_mode(False)

    def test_print_section_with_title(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_section("Test Section")
        assert "Test Section" in capture.get()

    def test_print_section_suppressed_when_quiet(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_section("Hidden")
            assert capture.get() == ""
        finally:
            set_quiet_mode(False)


# =============================================================================
# No detections / step / error panel
# =============================================================================

class TestNoDetectionsAndSteps:
    """Tests for print_no_detections, print_step, print_substep, print_info."""

    def test_print_no_detections_visible_when_not_quiet(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_no_detections()
        out = capture.get()
        assert "No detections" in out or "detections" in out.lower()

    def test_print_step_visible_when_not_quiet(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_step("Loading rules")
        assert "Loading rules" in capture.get()

    def test_print_substep_visible_when_not_quiet(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_substep("Parsing file")
        assert "Parsing file" in capture.get()

    def test_print_info_visible_when_not_quiet(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_info("Info message")
        assert "Info message" in capture.get()


# =============================================================================
# Always-visible messages
# =============================================================================

class TestAlwaysVisibleMessages:
    """Tests for print_warning, print_error, print_error_panel."""

    def test_print_warning_always_shown(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_warning("Warning text")
            assert "Warning text" in capture.get()
        finally:
            set_quiet_mode(False)

    def test_print_error_always_shown(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_error("Error text")
            assert "Error text" in capture.get()
        finally:
            set_quiet_mode(False)

    def test_print_error_panel_always_shown(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_error_panel("Missing File", "File not found", "Check the path.")
            out = capture.get()
            assert "Missing File" in out or "Error" in out
            assert "File not found" in out
            assert "Check the path" in out
        finally:
            set_quiet_mode(False)


# =============================================================================
# DetectionStats
# =============================================================================

class TestDetectionStats:
    """Tests for DetectionStats dataclass."""

    def test_add_detection_critical(self):
        stats = DetectionStats()
        stats.add_detection("critical", 2)
        assert stats.critical == 2
        assert stats.total_events == 2
        assert stats.total_rules_matched == 1

    def test_add_detection_high_medium_low(self):
        stats = DetectionStats()
        stats.add_detection("high", 5)
        stats.add_detection("medium", 3)
        stats.add_detection("low", 1)
        assert stats.high == 5
        assert stats.medium == 3
        assert stats.low == 1
        assert stats.total_events == 9

    def test_total_by_severity(self):
        stats = DetectionStats()
        stats.add_detection("high", 1)
        totals = stats.total_by_severity
        assert totals["high"] == 1
        assert totals["critical"] == 0


# =============================================================================
# ProcessingStats
# =============================================================================

class TestProcessingStats:
    """Tests for ProcessingStats dataclass."""

    def test_elapsed_seconds(self):
        stats = ProcessingStats()
        assert stats.elapsed_seconds >= 0

    def test_events_per_second_zero_elapsed(self):
        stats = ProcessingStats()
        stats.events_total = 100
        stats.start_time = 1000.0
        stats.end_time = 1000.0  # zero elapsed -> rate is 0
        rate = stats.events_per_second
        assert isinstance(rate, (int, float))
        assert rate == 0


# =============================================================================
# ZircoliteConsole
# =============================================================================

class TestZircoliteConsole:
    """Tests for ZircoliteConsole class."""

    def test_init_default(self):
        zc = ZircoliteConsole()
        assert zc.quiet is False
        assert zc.stats is not None

    def test_init_quiet(self):
        zc = ZircoliteConsole(quiet=True)
        assert zc.quiet is True

    def test_print_banner_quiet(self):
        zc = ZircoliteConsole(quiet=True)
        with zc.console.capture() as capture:
            zc.print_banner("1.0.0")
        assert capture.get() == ""

    def test_print_banner_not_quiet(self):
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.print_banner("1.0.0")
        out = capture.get()
        assert "1.0.0" in out

    def test_info_quiet(self):
        zc = ZircoliteConsole(quiet=True)
        with zc.console.capture() as capture:
            zc.info("hello")
        assert capture.get() == ""

    def test_info_not_quiet(self):
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.info("hello")
        assert "hello" in capture.get()

    def test_warning_always_shown(self):
        zc = ZircoliteConsole(quiet=True)
        with zc.console.capture() as capture:
            zc.warning("warn")
        assert "warn" in capture.get()

    def test_error_always_shown(self):
        zc = ZircoliteConsole(quiet=True)
        with zc.console.capture() as capture:
            zc.error("err")
        assert "err" in capture.get()


# =============================================================================
# Section separator: no title (line 136)
# =============================================================================

class TestPrintSectionNoTitle:
    """Cover the else branch of print_section when no title is given."""

    def test_print_section_no_title(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_section()
        out = capture.get().strip()
        assert len(out) > 0
        assert "─" in out  # Rich Rule() draws a horizontal line


# =============================================================================
# print_success / print_file / print_count / print_detection
# =============================================================================

class TestPrintHelpers:
    """Cover print_success, print_file, print_count, print_detection."""

    def test_print_success_visible(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_success("All good")
        assert "All good" in capture.get()

    def test_print_success_suppressed_when_quiet(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_success("hidden")
            assert capture.get() == ""
        finally:
            set_quiet_mode(False)

    def test_print_file_visible(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_file("Output", "/tmp/result.json")
        out = capture.get()
        assert "Output" in out
        assert "/tmp/result.json" in out

    def test_print_file_suppressed_when_quiet(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_file("Output", "/tmp/result.json")
            assert capture.get() == ""
        finally:
            set_quiet_mode(False)

    def test_print_count_visible(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_count("Events", 42)
        out = capture.get()
        assert "Events" in out
        assert "42" in out

    def test_print_count_suppressed_when_quiet(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_count("Events", 42)
            assert capture.get() == ""
        finally:
            set_quiet_mode(False)

    def test_print_detection_visible_with_all_levels(self):
        set_quiet_mode(False)
        for level in ("critical", "high", "medium", "low", "informational"):
            with console.capture() as capture:
                print_detection(f"Rule {level}", level, 10)
            out = capture.get()
            assert f"Rule {level}" in out
            assert "10" in out

    def test_print_detection_unknown_level(self):
        """Unknown levels fall back to default style."""
        set_quiet_mode(False)
        with console.capture() as capture:
            print_detection("Unknown Rule", "custom_level", 5)
        assert "Unknown Rule" in capture.get()

    def test_print_detection_suppressed_when_quiet(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_detection("Rule", "high", 1)
            assert capture.get() == ""
        finally:
            set_quiet_mode(False)


# =============================================================================
# DetectionStats – informational level (line 277-278)
# =============================================================================

class TestDetectionStatsInformational:
    """Cover the informational level branch."""

    def test_add_detection_informational(self):
        stats = DetectionStats()
        stats.add_detection("informational", 7)
        assert stats.informational == 7
        assert stats.total_events == 7
        assert stats.total_rules_matched == 1

    def test_add_detection_unknown_level(self):
        """Unknown levels don't increment any severity bucket but still track total."""
        stats = DetectionStats()
        stats.add_detection("unknown", 3)
        assert stats.total_events == 3
        assert stats.total_rules_matched == 1
        assert stats.critical == 0


# =============================================================================
# ZircoliteConsole – success, workload, progress, detections, dashboard
# =============================================================================

class TestZircoliteConsoleExtended:
    """Extended tests for ZircoliteConsole methods."""

    def test_success_visible(self):
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.success("Done!")
        assert "Done!" in capture.get()

    def test_success_suppressed_when_quiet(self):
        zc = ZircoliteConsole(quiet=True)
        with zc.console.capture() as capture:
            zc.success("Hidden")
        assert capture.get() == ""

    def test_print_workload_analysis_unified(self):
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.print_workload_analysis(
                file_count=5,
                total_size="100 MB",
                avg_size="20 MB",
                available_ram="8 GB",
                cpu_count=4,
                db_mode="unified",
                db_reason="Many small files",
                parallel_enabled=False,
                parallel_workers=1,
                parallel_reason="Not needed"
            )
        out = capture.get()
        assert "5" in out
        assert "UNIFIED" in out

    def test_print_workload_analysis_perfile_parallel(self):
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.print_workload_analysis(
                file_count=10,
                total_size="500 MB",
                avg_size="50 MB",
                available_ram="16 GB",
                cpu_count=8,
                db_mode="per-file",
                db_reason="Multiple large files",
                parallel_enabled=True,
                parallel_workers=4,
                parallel_reason=""
            )
        out = capture.get()
        assert "ENABLED" in out
        assert "4" in out

    def test_print_workload_analysis_perfile_no_parallel(self):
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.print_workload_analysis(
                file_count=2,
                total_size="50 MB",
                avg_size="25 MB",
                available_ram="4 GB",
                cpu_count=2,
                db_mode="per-file",
                db_reason="Test",
                parallel_enabled=False,
                parallel_workers=1,
                parallel_reason="Low RAM"
            )
        out = capture.get()
        assert "disabled" in out.lower()

    def test_create_file_progress(self):
        zc = ZircoliteConsole(quiet=False)
        progress = zc.create_file_progress(total_files=10)
        assert progress is not None

    def test_create_rule_progress(self):
        zc = ZircoliteConsole(quiet=False)
        progress = zc.create_rule_progress(total_rules=100)
        assert progress is not None

    def test_live_status(self):
        zc = ZircoliteConsole(quiet=False)
        with zc.live_status("Working...") as status:
            assert status is not None

    def test_print_detection_stores_and_shows(self):
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.print_detection("Evil Rule", "critical", 5)
        out = capture.get()
        assert "Evil Rule" in out
        assert "5" in out
        assert len(zc._detections) == 1
        assert zc.stats.detection_stats.critical == 5

    def test_print_detection_quiet_stores_but_no_output(self):
        zc = ZircoliteConsole(quiet=True)
        with zc.console.capture() as capture:
            zc.print_detection("Evil Rule", "critical", 5)
        assert capture.get() == ""
        # Should still store internally
        assert len(zc._detections) == 1

    def test_print_detection_summary_table_with_detections(self):
        zc = ZircoliteConsole(quiet=False)
        zc.print_detection("Critical Rule", "critical", 10, show_immediately=False)
        zc.print_detection("Low Rule", "low", 2, show_immediately=False)
        with zc.console.capture() as capture:
            zc.print_detection_summary_table()
        out = capture.get()
        assert "Critical Rule" in out
        assert "Low Rule" in out
        assert "Detection Results" in out

    def test_print_detection_summary_table_empty(self):
        """When no detections, calls print_no_detections (which uses the global console)."""
        zc = ZircoliteConsole(quiet=False)
        # print_no_detections uses the module-level console, not zc.console,
        # so we capture the global console instead.
        set_quiet_mode(False)
        with console.capture() as capture:
            zc.print_detection_summary_table()
        out = capture.get()
        assert "No detections" in out.lower() or "detections" in out.lower()

    def test_print_summary_dashboard_basic(self):
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.print_summary_dashboard(
                processing_time=5.5,
                files_processed=2,
                total_events=500,
                peak_memory_mb=256.0,
                avg_memory_mb=128.0,
            )
        out = capture.get()
        assert "Summary" in out
        assert "500" in out
        assert "2" in out

    def test_print_summary_dashboard_long_time(self):
        """Cover the >=60s time formatting branch."""
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.print_summary_dashboard(
                processing_time=125.0,
                files_processed=10,
                total_events=10000,
                peak_memory_mb=512.0,
                avg_memory_mb=300.0,
                workers_used=4
            )
        out = capture.get()
        assert "2m" in out  # 125s -> 2m 5s
        assert "Summary" in out

    def test_print_summary_dashboard_large_memory(self):
        """Cover the >=1024 MB (GB) formatting branch."""
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.print_summary_dashboard(
                processing_time=10.0,
                files_processed=5,
                total_events=5000,
                peak_memory_mb=2048.0,
                avg_memory_mb=1024.0,
            )
        out = capture.get()
        assert "GB" in out

    def test_print_summary_dashboard_with_all_severity_detections(self):
        """Cover all severity branches in summary dashboard."""
        zc = ZircoliteConsole(quiet=False)
        zc.print_detection("C", "critical", 1, show_immediately=False)
        zc.print_detection("H", "high", 2, show_immediately=False)
        zc.print_detection("M", "medium", 3, show_immediately=False)
        zc.print_detection("L", "low", 4, show_immediately=False)
        zc.print_detection("I", "informational", 5, show_immediately=False)
        with zc.console.capture() as capture:
            zc.print_summary_dashboard(
                processing_time=1.0,
                files_processed=1,
                total_events=100,
                peak_memory_mb=50.0,
                avg_memory_mb=30.0,
            )
        out = capture.get()
        assert "CRIT" in out
        assert "HIGH" in out
        assert "MED" in out
        assert "LOW" in out
        assert "INFO" in out

    def test_print_summary_dashboard_no_detections(self):
        """Cover the 'None' detections branch."""
        zc = ZircoliteConsole(quiet=False)
        with zc.console.capture() as capture:
            zc.print_summary_dashboard(
                processing_time=1.0,
                files_processed=1,
                total_events=0,
                peak_memory_mb=0.0,
                avg_memory_mb=0.0,
            )
        out = capture.get()
        assert "None" in out

    def test_clear_detections(self):
        zc = ZircoliteConsole(quiet=False)
        zc.print_detection("Rule", "high", 5, show_immediately=False)
        assert len(zc._detections) == 1
        zc.clear_detections()
        assert len(zc._detections) == 0
        assert zc.stats.detection_stats.total_events == 0


# =============================================================================
# RichProgressTracker
# =============================================================================

class TestRichProgressTracker:
    """Tests for RichProgressTracker class."""

    def test_init_defaults(self):
        tracker = RichProgressTracker()
        assert tracker.quiet is False
        assert tracker._detection_count["critical"] == 0

    def test_init_quiet(self):
        tracker = RichProgressTracker(quiet=True)
        assert tracker.quiet is True

    def test_create_multi_progress(self):
        tracker = RichProgressTracker()
        progress = tracker.create_multi_progress()
        assert progress is not None
        assert tracker._progress is progress

    def test_live_progress_quiet_yields_none(self):
        tracker = RichProgressTracker(quiet=True)
        with tracker.live_progress(total=10) as update:
            assert update is None

    def test_live_progress_active(self):
        tracker = RichProgressTracker(quiet=False)
        with tracker.live_progress(total=5) as update:
            assert callable(update)
            update(advance=1, events=100)

    def test_live_rule_execution_quiet(self):
        tracker = RichProgressTracker(quiet=True)
        with tracker.live_rule_execution(total_rules=10) as (progress, update):
            assert progress is None
            # update should be a no-op lambda
            update(advance=1, detection={"level": "high", "count": 1})

    def test_live_rule_execution_active(self):
        tracker = RichProgressTracker(quiet=False)
        with tracker.live_rule_execution(total_rules=3) as (progress, update):
            assert progress is not None
            update(advance=1, detection={"level": "critical", "count": 5})
            update(advance=1, detection={"level": "high", "count": 3})
            update(advance=1)
        # After exiting, counts are reset
        assert tracker._detection_count["critical"] == 0


# =============================================================================
# make_detection_counter
# =============================================================================

class TestMakeDetectionCounter:
    """Tests for make_detection_counter function."""

    def test_all_severities(self):
        counts = {"critical": 2, "high": 5, "medium": 3, "low": 1, "informational": 10}
        text = make_detection_counter(counts)
        rendered = text.plain
        assert "2 CRIT" in rendered
        assert "5 HIGH" in rendered
        assert "3 MED" in rendered
        assert "1 LOW" in rendered
        assert "10 INFO" in rendered

    def test_empty_counts(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        text = make_detection_counter(counts)
        assert "No detections yet" in text.plain

    def test_partial_counts(self):
        counts = {"critical": 0, "high": 3, "medium": 0, "low": 0, "informational": 0}
        text = make_detection_counter(counts)
        assert "3 HIGH" in text.plain
        assert "CRIT" not in text.plain


# =============================================================================
# _format_file_node / build_file_tree
# =============================================================================

class TestFileTree:
    """Tests for _format_file_node and build_file_tree."""

    def test_format_file_node_zero_detections(self):
        fs = {"name": "test.evtx", "events": 100, "detections": 0}
        result = _format_file_node(fs)
        assert "test.evtx" in result
        assert "100" in result
        assert "0 detections" in result

    def test_format_file_node_few_detections(self):
        fs = {"name": "test.evtx", "events": 100, "detections": 3}
        result = _format_file_node(fs)
        assert "3 detections" in result

    def test_format_file_node_many_detections(self):
        fs = {"name": "test.evtx", "events": 100, "detections": 10}
        result = _format_file_node(fs)
        assert "10 detections" in result

    def test_format_file_node_single_detection(self):
        fs = {"name": "test.evtx", "events": 50, "detections": 1}
        result = _format_file_node(fs)
        assert "1 detection" in result
        assert "detections" not in result

    def test_format_file_node_with_filtered(self):
        fs = {"name": "test.evtx", "events": 100, "detections": 0, "filtered": 50}
        result = _format_file_node(fs)
        assert "50" in result
        assert "filtered" in result

    def test_build_file_tree_flat(self):
        file_stats = [
            {"name": "a.evtx", "events": 100, "detections": 0},
            {"name": "b.evtx", "events": 200, "detections": 5},
        ]
        tree = build_file_tree("Results", file_stats)
        assert tree.label  # Has a root label

    def test_build_file_tree_nested_dirs(self):
        """Cover the nested directory grouping branch (line 870-872)."""
        file_stats = [
            {"name": "dir1/a.evtx", "events": 100, "detections": 0},
            {"name": "dir2/b.evtx", "events": 200, "detections": 5},
        ]
        tree = build_file_tree("Results", file_stats)
        assert tree.label  # Has a root label


# =============================================================================
# format_level / make_severity_badge
# =============================================================================

class TestSeverityFormatters:
    """Tests for format_level and make_severity_badge."""

    def test_format_level_known(self):
        for level in ("critical", "high", "medium", "low", "informational"):
            result = format_level(level)
            assert level in result
            assert "[" in result  # Has Rich markup

    def test_format_level_unknown(self):
        result = format_level("custom")
        assert result == "custom"  # No markup wrapping

    def test_make_severity_badge_all_levels(self):
        for level in ("critical", "high", "medium", "low", "informational"):
            badge = make_severity_badge(level)
            assert badge.plain.strip()  # Not empty

    def test_make_severity_badge_unknown(self):
        badge = make_severity_badge("custom")
        assert "CUSTOM" in badge.plain


# =============================================================================
# build_attack_summary
# =============================================================================

class TestBuildAttackSummary:
    """Tests for build_attack_summary function."""

    def test_with_attack_tags(self):
        results = [
            {"tags": ["attack.execution", "attack.t1059.001"], "count": 10},
            {"tags": ["attack.persistence", "attack.t1055"], "count": 5},
            {"tags": ["attack.execution", "attack.t1059"], "count": 3},
        ]
        panel = build_attack_summary(results)
        assert panel is not None

    def test_no_attack_tags(self):
        results = [
            {"tags": ["custom.tag"], "count": 10},
        ]
        panel = build_attack_summary(results)
        assert panel is None

    def test_empty_results(self):
        panel = build_attack_summary([])
        assert panel is None

    def test_no_tags_key(self):
        results = [{"count": 10}]
        panel = build_attack_summary(results)
        assert panel is None

    def test_empty_tags(self):
        results = [{"tags": [], "count": 5}]
        panel = build_attack_summary(results)
        assert panel is None

    def test_techniques_only_no_tactics(self):
        """Techniques without matching tactics won't produce output."""
        results = [{"tags": ["attack.t1059"], "count": 5}]
        panel = build_attack_summary(results)
        assert panel is None

    def test_single_hit(self):
        """Cover singular 'hit' label."""
        results = [{"tags": ["attack.execution", "attack.t1059"], "count": 1}]
        panel = build_attack_summary(results)
        assert panel is not None


# =============================================================================
# build_detection_table
# =============================================================================

class TestBuildDetectionTable:
    """Tests for build_detection_table function."""

    def test_basic_table(self):
        results = [
            {"rule_level": "high", "title": "Test Rule", "count": 5,
             "tags": ["attack.execution", "attack.t1059.001"]},
        ]
        table = build_detection_table(results)
        assert table is not None

    def test_table_with_title(self):
        results = [
            {"rule_level": "medium", "title": "Rule A", "count": 3, "tags": []},
        ]
        table = build_detection_table(results, title="file.evtx")
        assert table is not None

    def test_table_truncation_many_attack_ids(self):
        """Cover the >3 ATT&CK IDs truncation branch (line 1074)."""
        results = [
            {"rule_level": "critical", "title": "Multi-Attack Rule", "count": 20,
             "tags": ["attack.t1059.001", "attack.t1055", "attack.t1003",
                      "attack.t1078", "attack.t1021"]},
        ]
        table = build_detection_table(results)
        assert table is not None

    def test_table_empty_results(self):
        table = build_detection_table([])
        assert table is not None

    def test_table_missing_fields(self):
        """Results with missing optional fields."""
        results = [{}]
        table = build_detection_table(results)
        assert table is not None


# =============================================================================
# make_file_link
# =============================================================================

class TestMakeFileLink:
    """Tests for make_file_link function."""

    def test_valid_path(self, tmp_path):
        test_file = tmp_path / "output.json"
        test_file.write_text("{}")
        result = make_file_link(str(test_file))
        assert "link=" in result
        assert "output.json" in result

    def test_exception_fallback(self):
        """Cover the exception handling branch (lines 1104-1105)."""
        # An empty path should still produce markup without crashing
        result = make_file_link("")
        assert isinstance(result, str)
