"""Tests for the Sigma rule testing mode (Feature 2)."""

import json
import pytest

from zircolite.config import ProcessingConfig
from zircolite.core import ZircoliteCore


@pytest.fixture
def rule_test_core(field_mappings_file, test_logger):
    """A ZircoliteCore pre-loaded with two test rules."""
    cfg = ProcessingConfig(no_output=True)
    core = ZircoliteCore(field_mappings_file, cfg, logger=test_logger)
    core.ruleset = [
        {
            "title": "Detect PowerShell",
            "id": "ps-001",
            "level": "high",
            "tags": ["attack.t1059.001"],
            "description": "Detects PowerShell execution",
            "filename": "ps.yml",
            "rule": [
                "SELECT * FROM logs WHERE CommandLine LIKE '%powershell%' ESCAPE '\\'"
            ],
        },
        {
            "title": "Detect CMD",
            "id": "cmd-001",
            "level": "medium",
            "tags": ["attack.t1059.003"],
            "description": "Detects CMD execution",
            "filename": "cmd.yml",
            "rule": [
                "SELECT * FROM logs WHERE CommandLine LIKE '%cmd.exe%' ESCAPE '\\'"
            ],
        },
    ]
    yield core
    core.close()


class TestRunRuleTests:
    def test_tp_match_passes(self, rule_test_core, tmp_path):
        test_data = [
            {
                "title": "Detect PowerShell",
                "id": "ps-001",
                "true_positive": [
                    {"CommandLine": "powershell.exe -c Get-Process", "EventID": "4688"}
                ],
                "true_negative": [],
            }
        ]
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps(test_data))

        results = rule_test_core.run_rule_tests(str(test_file))
        ps_result = next(r for r in results if r["id"] == "ps-001")
        assert ps_result["tp_pass"] is True
        assert ps_result["tp_count"] > 0

    def test_tn_no_match_passes(self, rule_test_core, tmp_path):
        test_data = [
            {
                "title": "Detect PowerShell",
                "id": "ps-001",
                "true_positive": [],
                "true_negative": [
                    {"CommandLine": "notepad.exe document.txt", "EventID": "4688"}
                ],
            }
        ]
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps(test_data))

        results = rule_test_core.run_rule_tests(str(test_file))
        ps_result = next(r for r in results if r["id"] == "ps-001")
        assert ps_result["tn_pass"] is True
        assert ps_result["tn_count"] == 0

    def test_false_negative_fails(self, rule_test_core, tmp_path):
        """A TP event that doesn't trigger the rule should fail."""
        test_data = [
            {
                "title": "Detect PowerShell",
                "id": "ps-001",
                "true_positive": [
                    # This should NOT trigger the PowerShell rule
                    {"CommandLine": "notepad.exe", "EventID": "4688"}
                ],
                "true_negative": [],
            }
        ]
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps(test_data))

        results = rule_test_core.run_rule_tests(str(test_file))
        ps_result = next(r for r in results if r["id"] == "ps-001")
        assert ps_result["tp_pass"] is False
        assert ps_result["tp_count"] == 0

    def test_false_positive_fails(self, rule_test_core, tmp_path):
        """A TN event that triggers the rule should fail."""
        test_data = [
            {
                "title": "Detect PowerShell",
                "id": "ps-001",
                "true_positive": [],
                "true_negative": [
                    # This WILL trigger the PowerShell rule — that's a false positive
                    {"CommandLine": "powershell.exe -c Get-Process", "EventID": "4688"}
                ],
            }
        ]
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps(test_data))

        results = rule_test_core.run_rule_tests(str(test_file))
        ps_result = next(r for r in results if r["id"] == "ps-001")
        assert ps_result["tn_pass"] is False
        assert ps_result["tn_count"] > 0

    def test_no_test_case_marked_as_none(self, rule_test_core, tmp_path):
        """Rules with no test case should have tp_pass=None, tn_pass=None."""
        test_data = []  # No test cases at all
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps(test_data))

        results = rule_test_core.run_rule_tests(str(test_file))
        assert len(results) == len(rule_test_core.ruleset)
        for r in results:
            assert r["tp_pass"] is None
            assert r["tn_pass"] is None
            assert r["error"] == "no test case"

    def test_match_by_id(self, rule_test_core, tmp_path):
        """Test cases can be matched by rule id (not just title)."""
        test_data = [
            {
                "id": "cmd-001",  # no title provided
                "true_positive": [
                    {"CommandLine": "cmd.exe /c dir", "EventID": "4688"}
                ],
                "true_negative": [],
            }
        ]
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps(test_data))

        results = rule_test_core.run_rule_tests(str(test_file))
        cmd_result = next(r for r in results if r["id"] == "cmd-001")
        assert cmd_result["tp_pass"] is True

    def test_missing_test_file_returns_empty(self, rule_test_core):
        results = rule_test_core.run_rule_tests("/nonexistent/path/tests.json")
        assert results == []

    def test_both_tp_and_tn_pass(self, rule_test_core, tmp_path):
        test_data = [
            {
                "title": "Detect CMD",
                "id": "cmd-001",
                "true_positive": [
                    {"CommandLine": "cmd.exe /c whoami", "EventID": "4688"}
                ],
                "true_negative": [
                    {"CommandLine": "notepad.exe", "EventID": "4688"}
                ],
            }
        ]
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps(test_data))

        results = rule_test_core.run_rule_tests(str(test_file))
        cmd_result = next(r for r in results if r["id"] == "cmd-001")
        assert cmd_result["tp_pass"] is True
        assert cmd_result["tn_pass"] is True


class TestRunRuleTestsEdgeCases:
    """Malformed or invalid test file handling."""

    def test_json_not_a_list_returns_empty(self, rule_test_core, tmp_path):
        test_file = tmp_path / "tests.json"
        test_file.write_text('{"title": "X"}')
        results = rule_test_core.run_rule_tests(str(test_file))
        assert results == []

    def test_malformed_json_returns_empty(self, rule_test_core, tmp_path):
        test_file = tmp_path / "tests.json"
        test_file.write_text("not valid json{{{")
        results = rule_test_core.run_rule_tests(str(test_file))
        assert results == []
