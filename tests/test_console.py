"""
Tests for the console module (quiet mode, output helpers, stats).
"""

import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from rich.console import Console

from zircolite.console import (
    DetectionStats,
    _format_file_node,
    build_attack_summary,
    build_detection_table,
    build_file_tree,
    console,
    is_quiet,
    make_detection_counter,
    make_file_link,
    make_severity_badge,
    print_banner,
    print_error_panel,
    print_no_detections,
    print_profiling_report,
    print_rule_test_results,
    print_section,
    set_quiet_mode,
)


@pytest.fixture(autouse=True)
def reset_quiet_mode_after_test():
    """Reset quiet mode after each test to avoid cross-test leakage."""
    yield
    set_quiet_mode(False)


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
            print_banner("3.7.6")
        out = capture.get()
        assert "Standalone Sigma" in out or "Sigma" in out
        assert "3.7.6" in out

    def test_print_banner_suppressed_when_quiet(self):
        set_quiet_mode(True)
        try:
            with console.capture() as capture:
                print_banner("3.7.6")
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

class TestNoDetections:
    """Tests for print_no_detections."""

    def test_print_no_detections_visible_when_not_quiet(self):
        set_quiet_mode(False)
        with console.capture() as capture:
            print_no_detections()
        out = capture.get()
        assert "No detections" in out or "detections" in out.lower()


# =============================================================================
# Always-visible messages
# =============================================================================

class TestAlwaysVisibleMessages:
    """Tests for print_error_panel."""

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
        """Files in sub-directories are grouped under their directory."""
        file_stats = [
            {"name": "dir1/a.evtx", "events": 100, "detections": 0},
            {"name": "dir2/b.evtx", "events": 200, "detections": 5},
        ]
        tree = build_file_tree("Results", file_stats)
        assert tree.label  # Has a root label


# =============================================================================
# make_severity_badge
# =============================================================================

class TestSeverityFormatters:
    """Tests for make_severity_badge."""

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
    """build_detection_table renders the row content it is handed.

    These render through a captured console rather than asserting the object
    is not None: the function cannot return None, so that assertion passed
    whatever the table actually contained.
    """

    @staticmethod
    def _render(table, width=200):
        capture_console = Console(width=width, no_color=True, force_terminal=False)
        with capture_console.capture() as capture:
            capture_console.print(table)
        return capture.get()

    def test_row_shows_title_count_and_severity(self):
        results = [
            {"rule_level": "high", "title": "Test Rule", "count": 5,
             "tags": ["attack.execution", "attack.t1059.001"]},
        ]
        out = self._render(build_detection_table(results))

        assert "Test Rule" in out
        assert "5" in out
        assert "HIGH" in out.upper()
        assert "T1059.001" in out

    def test_title_is_rendered_when_given(self):
        results = [
            {"rule_level": "medium", "title": "Rule A", "count": 3, "tags": []},
        ]
        out = self._render(build_detection_table(results, title="file.evtx"))

        assert "file.evtx" in out
        assert "Rule A" in out

    def test_attack_ids_beyond_three_are_summarised(self):
        results = [
            {"rule_level": "critical", "title": "Multi-Attack Rule", "count": 20,
             "tags": ["attack.t1059.001", "attack.t1055", "attack.t1003",
                      "attack.t1078", "attack.t1021"]},
        ]
        table = build_detection_table(results)

        # Read the cell, not the rendering: the ATT&CK column is fixed-width
        # and Rich ellipsises the marker away at any console size.
        attack_cell = next(iter(table.columns[3].cells))
        assert attack_cell == "T1059.001, T1055, T1003 +2"

    def test_three_or_fewer_attack_ids_are_listed_in_full(self):
        results = [
            {"rule_level": "low", "title": "Few", "count": 1,
             "tags": ["attack.t1059.001", "attack.t1055"]},
        ]
        table = build_detection_table(results)

        assert next(iter(table.columns[3].cells)) == "T1059.001, T1055"

    def test_empty_results_render_without_rows(self):
        out = self._render(build_detection_table([]))

        assert "Rule" in out or out.strip() != ""

    def test_missing_fields_do_not_break_rendering(self):
        out = self._render(build_detection_table([{}]))

        assert out.strip() != ""


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
        """A path that cannot be turned into a URI falls back to plain text."""
        # An empty path should still produce markup without crashing
        result = make_file_link("")
        assert isinstance(result, str)


# =============================================================================
# print_rule_test_results
# =============================================================================


class TestPrintRuleTestResults:
    """Tests for print_rule_test_results."""

    def test_all_pass(self):
        results = [
            {"title": "Rule A", "id": "r1", "tp_pass": True, "tn_pass": True},
            {"title": "Rule B", "id": "r2", "tp_pass": True, "tn_pass": True},
        ]
        with console.capture() as capture:
            print_rule_test_results(results)
        out = capture.get()
        assert "Rule A" in out
        assert "Rule B" in out
        assert "Passed: 2" in out or "Passed:" in out

    def test_partial_failure(self):
        results = [
            {"title": "Pass", "id": "r1", "tp_pass": True, "tn_pass": True},
            {"title": "Fail", "id": "r2", "tp_pass": False, "tn_pass": True, "error": "TP=0"},
        ]
        with console.capture() as capture:
            print_rule_test_results(results)
        out = capture.get()
        assert "Pass" in out
        assert "Fail" in out
        assert "Failed:" in out or "Failed" in out

    def test_no_test_case(self):
        results = [
            {"title": "NoCase", "id": "r1", "tp_pass": None, "tn_pass": None, "error": "no test case"},
        ]
        with console.capture() as capture:
            print_rule_test_results(results)
        out = capture.get()
        assert "NoCase" in out
        assert "no test case" in out

    def test_empty_results(self):
        with console.capture() as capture:
            print_rule_test_results([])
        out = capture.get()
        assert "No test results" in out or "no test results" in out.lower()


# =============================================================================
# print_profiling_report
# =============================================================================


class TestPrintProfilingReport:
    """Tests for print_profiling_report."""

    def test_basic_report(self):
        report = [
            {"title": "Rule A", "elapsed_ms": 50.0},
            {"title": "Rule B", "elapsed_ms": 120.0},
        ]
        with console.capture() as capture:
            print_profiling_report(report)
        out = capture.get()
        assert "Rule A" in out
        assert "Rule B" in out
        assert "50" in out or "120" in out
        assert "Total" in out or "total" in out.lower()

    def test_top_n_limit(self):
        report = [{"title": f"SlowRule{i}", "elapsed_ms": 10.0 * i} for i in range(30)]
        with console.capture() as capture:
            print_profiling_report(report, top_n=5)
        out = capture.get()
        assert "SlowRule0" in out
        assert "SlowRule4" in out
        assert "SlowRule5" not in out

    def test_empty_report(self):
        with console.capture() as capture:
            print_profiling_report([])
        out = capture.get()
        assert "No profiling" in out or "no profiling" in out.lower()


class TestConsoleLoggerHandling:
    """Regression tests for console/logger fixes."""

    def test_make_file_link_fallback_on_uri_error(self):
        """When as_uri() fails, make_file_link falls back to plain markup."""
        from unittest.mock import patch

        from zircolite.console import make_file_link
        with patch("pathlib.Path.as_uri", side_effect=ValueError("relative")):
            result = make_file_link("some/relative.json")
        assert result == "[cyan]some/relative.json[/]"

    def test_get_rich_logger_file_handler_utf8(self, tmp_path):
        """The file handler must use UTF-8 (locale encoding breaks on ✓ glyphs)."""
        from zircolite.console import get_rich_logger
        log_file = tmp_path / "test.log"
        logger = get_rich_logger(name="test_utf8_logger", log_file=str(log_file))
        file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) == 1
        assert file_handlers[0].encoding == "utf-8"
        # Writing non-ASCII must not produce logging errors
        logger.info("[green]\\[✓][/] Done")
        for h in logger.handlers:
            h.close()
        logger.handlers.clear()

    def test_get_rich_logger_reinit_closes_old_handler(self, tmp_path):
        """Re-initializing must close the previous file handler."""
        from zircolite.console import get_rich_logger
        logger = get_rich_logger(name="test_reinit_logger", log_file=str(tmp_path / "a.log"))
        old_file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
        logger = get_rich_logger(name="test_reinit_logger", log_file=str(tmp_path / "b.log"))
        for h in old_file_handlers:
            assert h.stream is None or h.stream.closed
        for h in logger.handlers:
            h.close()
        logger.handlers.clear()


class TestAttackTacticExtraction:
    """attack.extract_attack_tactics normalises the tag spellings SIGMA uses."""

    def test_hyphen_and_underscore_spellings_agree(self):
        from zircolite.attack import extract_attack_tactics

        hyphen = extract_attack_tactics(["attack.credential-access"])
        underscore = extract_attack_tactics(["attack.credential_access"])

        assert hyphen == underscore
        assert hyphen != []

    def test_techniques_are_not_reported_as_tactics(self):
        from zircolite.attack import extract_attack_tactics

        assert extract_attack_tactics(["attack.t1059.001"]) == []

    def test_duplicates_collapse_and_order_is_kept(self):
        from zircolite.attack import extract_attack_tactics

        tactics = extract_attack_tactics(
            ["attack.execution", "attack.persistence", "attack.execution"]
        )

        assert len(tactics) == len(set(tactics))
        assert tactics[0] != tactics[-1]

    def test_non_attack_tags_are_ignored(self):
        from zircolite.attack import extract_attack_tactics

        assert extract_attack_tactics(["cve.2024.1234", "car.2013-05-002"]) == []

    def test_v19_successors_of_defense_evasion_resolve(self):
        """ATT&CK v19 split Defense Evasion into Stealth and Defense Impairment."""
        from zircolite.attack import extract_attack_tactics

        assert extract_attack_tactics(["attack.stealth"]) == ["stealth"]
        assert extract_attack_tactics(["attack.defense-impairment"]) == ["defense-impairment"]

    def test_retired_defense_evasion_maps_to_the_tactic_that_kept_its_id(self):
        """Stealth inherited TA0005, so the retired spelling has to land there."""
        from zircolite.attack import extract_attack_tactics

        assert extract_attack_tactics(["attack.defense-evasion"]) == ["stealth"]
        assert extract_attack_tactics(["attack.defense_evasion"]) == ["stealth"]

    def test_every_tactic_tag_in_the_shipped_rulesets_resolves(self):
        """A tactic the alias table does not know is dropped silently.

        That is how the v19 rename went unnoticed: rules tagged attack.stealth
        produced no tactic at all, so Navigator entries merged under a null
        tactic and the Mini-GUI's lanes for them stayed empty.
        """
        import json

        from zircolite.attack import extract_attack_tactics

        rules_dir = Path(__file__).parent.parent / "rules"
        rulesets = sorted(rules_dir.glob("*.json"))
        if not rulesets:
            pytest.skip("no rulesets in rules/ to check against")

        # Technique (attack.tXXXX), software (attack.sXXXX), group (attack.gXXXX)
        # and data-source (attack.dsXXXX) tags are not tactics and never resolve.
        non_tactic = re.compile(r"^attack\.(t|s|g|ds)\d", re.IGNORECASE)
        unresolved = set()
        for ruleset in rulesets:
            for rule in json.loads(ruleset.read_text()):
                for tag in rule.get("tags", []):
                    tag = str(tag)
                    if not tag.lower().startswith("attack.") or non_tactic.match(tag):
                        continue
                    if not extract_attack_tactics([tag]):
                        unresolved.add(tag)

        assert not unresolved, f"tactic tags no alias covers: {sorted(unresolved)}"
