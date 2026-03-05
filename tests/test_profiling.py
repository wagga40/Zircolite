"""Tests for rule performance profiling (Feature 3)."""

import pytest

from zircolite.config import ProcessingConfig
from zircolite.core import ZircoliteCore


class TestProfilingConfig:
    def test_default_profile_rules_is_false(self):
        cfg = ProcessingConfig()
        assert cfg.profile_rules is False

    def test_profile_rules_can_be_set(self):
        cfg = ProcessingConfig(profile_rules=True)
        assert cfg.profile_rules is True


class TestProfilingCore:
    """Test that ZircoliteCore populates _profiling_data when enabled."""

    @pytest.fixture
    def profiling_core(self, field_mappings_file):
        cfg = ProcessingConfig(profile_rules=True, no_output=True)
        core = ZircoliteCore(field_mappings_file, cfg)
        core.create_db('"EventID" TEXT, "CommandLine" TEXT')
        core.insert_data_to_db([
            {"EventID": "4688", "CommandLine": "powershell.exe -c whoami"},
            {"EventID": "4688", "CommandLine": "cmd.exe /c dir"},
        ])
        core.ruleset = [
            {
                "title": "Test Rule A",
                "id": "a",
                "level": "high",
                "tags": [],
                "description": "",
                "filename": "",
                "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%' ESCAPE '\\'"],
            },
            {
                "title": "Test Rule B",
                "id": "b",
                "level": "medium",
                "tags": [],
                "description": "",
                "filename": "",
                "rule": ["SELECT * FROM logs WHERE EventID = '4688'"],
            },
        ]
        yield core
        core.close()

    def test_profiling_data_populated(self, profiling_core, tmp_path):
        profiling_core.execute_ruleset(
            str(tmp_path / "detected_events_test.json"), write_mode='w', last_ruleset=True
        )
        assert len(profiling_core._profiling_data) == 2
        assert "Test Rule A" in profiling_core._profiling_data
        assert "Test Rule B" in profiling_core._profiling_data

    def test_profiling_values_are_positive(self, profiling_core, tmp_path):
        profiling_core.execute_ruleset(
            str(tmp_path / "detected_events_test.json"), write_mode='w', last_ruleset=True
        )
        for ms in profiling_core._profiling_data.values():
            assert ms >= 0.0

    def test_get_profiling_report_sorted_descending(self, profiling_core, tmp_path):
        profiling_core.execute_ruleset(
            str(tmp_path / "detected_events_test.json"), write_mode='w', last_ruleset=True
        )
        report = profiling_core.get_profiling_report()
        assert isinstance(report, list)
        assert len(report) == 2
        # Should be sorted descending by elapsed_ms
        if len(report) > 1:
            assert report[0]["elapsed_ms"] >= report[1]["elapsed_ms"]

    def test_get_profiling_report_fields(self, profiling_core, tmp_path):
        profiling_core.execute_ruleset(
            str(tmp_path / "detected_events_test.json"), write_mode='w', last_ruleset=True
        )
        report = profiling_core.get_profiling_report()
        for entry in report:
            assert "title" in entry
            assert "elapsed_ms" in entry

    def test_profiling_skipped_when_disabled(self, field_mappings_file, tmp_path):
        cfg = ProcessingConfig(profile_rules=False, no_output=True)
        core = ZircoliteCore(field_mappings_file, cfg)
        core.create_db('"EventID" TEXT')
        core.insert_data_to_db([{"EventID": "4688"}])
        core.ruleset = [
            {
                "title": "Rule",
                "id": "x",
                "level": "low",
                "tags": [],
                "description": "",
                "filename": "",
                "rule": ["SELECT * FROM logs WHERE EventID = '4688'"],
            }
        ]
        core.execute_ruleset(
            str(tmp_path / "detected_events_test.json"), write_mode='w', last_ruleset=True
        )
        assert core._profiling_data == {}
        core.close()

    def test_profiling_accumulates_across_calls(self, field_mappings_file, tmp_path):
        """Profiling adds elapsed time per call; second_ms >= first_ms (timing is additive)."""
        cfg = ProcessingConfig(profile_rules=True, no_output=True)
        core = ZircoliteCore(field_mappings_file, cfg)
        core.create_db('"EventID" TEXT')
        core.insert_data_to_db([{"EventID": "1"}])
        rule = {
            "title": "Accumulating Rule",
            "id": "acc",
            "level": "low",
            "tags": [],
            "description": "",
            "filename": "",
            "rule": ["SELECT * FROM logs WHERE EventID = '1'"],
        }
        core.ruleset = [rule]
        outfile = str(tmp_path / "detected_events_test.json")
        core.execute_ruleset(outfile, write_mode='w', last_ruleset=False)
        first_ms = core._profiling_data.get("Accumulating Rule", 0.0)
        core.execute_ruleset(outfile, write_mode='a', last_ruleset=True)
        second_ms = core._profiling_data.get("Accumulating Rule", 0.0)
        assert second_ms >= first_ms
        core.close()

    def test_merge_profiling_data(self, field_mappings_file, tmp_path):
        cfg = ProcessingConfig(profile_rules=True, no_output=True)
        acc = ZircoliteCore(field_mappings_file, cfg)
        acc.create_db('"EventID" TEXT')
        acc.insert_data_to_db([{"EventID": "1"}])
        acc.ruleset = [
            {
                "title": "Rule A",
                "id": "a",
                "level": "low",
                "tags": [],
                "description": "",
                "filename": "",
                "rule": ["SELECT * FROM logs WHERE EventID = '1'"],
            },
        ]
        outfile = str(tmp_path / "detected_events_test.json")
        acc.execute_ruleset(outfile, write_mode='w', last_ruleset=True)
        other = ZircoliteCore(field_mappings_file, cfg)
        other.create_db('"EventID" TEXT')
        other.insert_data_to_db([{"EventID": "2"}])
        other.ruleset = [
            {"title": "Rule A", "id": "a", "level": "low", "tags": [], "description": "", "filename": "", "rule": ["SELECT * FROM logs WHERE EventID = '2'"]},
            {"title": "Rule B", "id": "b", "level": "low", "tags": [], "description": "", "filename": "", "rule": ["SELECT * FROM logs"]},
        ]
        other.execute_ruleset(outfile, write_mode='w', last_ruleset=True)
        acc.merge_profiling_data(other)
        report = acc.get_profiling_report()
        titles = {r["title"] for r in report}
        assert "Rule A" in titles
        assert "Rule B" in titles
        assert len(report) == 2
        acc.close()
        other.close()
