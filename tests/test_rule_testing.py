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

    def test_missing_test_file_is_fatal(self, rule_test_core):
        """A test file that cannot be read must not read as 'all tests passed'."""
        with pytest.raises(ValueError, match="Cannot load rule test file"):
            rule_test_core.run_rule_tests("/nonexistent/path/tests.json")

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

    def test_json_not_a_list_is_fatal(self, rule_test_core, tmp_path):
        test_file = tmp_path / "tests.json"
        test_file.write_text('{"title": "X"}')
        with pytest.raises(ValueError, match="must be a JSON array"):
            rule_test_core.run_rule_tests(str(test_file))

    def test_malformed_json_is_fatal(self, rule_test_core, tmp_path):
        """A trailing comma in the test file must fail CI, not pass it."""
        test_file = tmp_path / "tests.json"
        test_file.write_text("not valid json{{{")
        with pytest.raises(ValueError, match="Cannot load rule test file"):
            rule_test_core.run_rule_tests(str(test_file))


class TestUnrunnableRuleIsNotAPass:
    """A rule that cannot execute at all must not report as passing.

    run_rule_tests built throwaway cores, closed them in a finally, and never
    read their rules_in_error -- so an uncompilable regex or broken SQL came
    back tp_pass=True, tn_pass=True, error=''. And with no true_positive events
    to check, tp_pass defaulted to True: an untested half read as a pass.
    """

    def _core(self, field_mappings_file, test_logger, rule):
        cfg = ProcessingConfig(no_output=True)
        core = ZircoliteCore(field_mappings_file, cfg, logger=test_logger)
        core.ruleset = [rule]
        return core

    def _run(self, core, tmp_path, case):
        test_file = tmp_path / "cases.json"
        test_file.write_text(json.dumps([case]))
        try:
            return core.run_rule_tests(str(test_file))[0]
        finally:
            core.close()

    def test_uncompilable_regex_is_reported_as_a_failure(
        self, tmp_path, field_mappings_file, test_logger
    ):
        # \p{L} is PCRE, which Python's re rejects
        core = self._core(field_mappings_file, test_logger, {
            "title": "Broken regex rule", "id": "br-1", "level": "high", "tags": [],
            "rule": [r"SELECT * FROM logs WHERE CommandLine REGEXP '\p{L}+evil'"],
        })
        result = self._run(core, tmp_path, {
            "title": "Broken regex rule",
            "true_positive": [{"CommandLine": "evil.exe"}],
            "true_negative": [{"CommandLine": "notepad.exe"}],
        })

        assert result["tp_pass"] is False
        assert result["error"], "the reason must be reported, not left blank"

    def test_broken_sql_is_reported_as_a_failure(
        self, tmp_path, field_mappings_file, test_logger
    ):
        core = self._core(field_mappings_file, test_logger, {
            "title": "Syntax error rule", "id": "se-1", "level": "high", "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE"],
        })
        result = self._run(core, tmp_path, {
            "title": "Syntax error rule",
            "true_positive": [],
            "true_negative": [{"CommandLine": "notepad.exe"}],
        })

        assert result["tn_pass"] is False
        assert result["error"]

    def test_an_untested_half_is_not_a_pass(
        self, tmp_path, field_mappings_file, test_logger
    ):
        """No true_positive events means untested, which is not the same as passing."""
        core = self._core(field_mappings_file, test_logger, {
            "title": "Fine rule", "id": "ok-1", "level": "high", "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%evil%'"],
        })
        result = self._run(core, tmp_path, {
            "title": "Fine rule",
            "true_positive": [],
            "true_negative": [{"CommandLine": "notepad.exe"}],
        })

        assert result["tp_pass"] is None, "untested must not read as passed"
        assert result["tn_pass"] is True
