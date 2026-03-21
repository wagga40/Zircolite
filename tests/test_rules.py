"""
Tests for the RulesetHandler and RulesUpdater classes in zircolite/rules.py.
"""

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite.rules import RulesetHandler, RulesUpdater
from zircolite.config import RulesetConfig


class TestIsValidSigmaRule:
    """Tests for the is_valid_sigma_rule method."""

    def test_valid_sigma_rule(self, tmp_path, test_logger):
        """Test that a valid Sigma rule with all required fields is accepted."""
        valid_rule = tmp_path / "valid_rule.yml"
        valid_rule.write_text("""
title: Test Rule
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
    condition: selection
level: high
""")
        
        # Create handler with empty ruleset to test the method
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        assert handler.is_valid_sigma_rule(valid_rule) is True

    def test_invalid_sigma_rule_missing_title(self, tmp_path, test_logger):
        """Test that a Sigma rule missing title is rejected."""
        invalid_rule = tmp_path / "missing_title.yml"
        invalid_rule.write_text("""
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
""")
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        assert handler.is_valid_sigma_rule(invalid_rule) is False

    def test_invalid_sigma_rule_missing_logsource(self, tmp_path, test_logger):
        """Test that a Sigma rule missing logsource is rejected."""
        invalid_rule = tmp_path / "missing_logsource.yml"
        invalid_rule.write_text("""
title: Test Rule
detection:
    selection:
        EventID: 1
    condition: selection
""")
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        assert handler.is_valid_sigma_rule(invalid_rule) is False

    def test_invalid_sigma_rule_missing_detection(self, tmp_path, test_logger):
        """Test that a Sigma rule missing detection is rejected."""
        invalid_rule = tmp_path / "missing_detection.yml"
        invalid_rule.write_text("""
title: Test Rule
logsource:
    product: windows
""")
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        assert handler.is_valid_sigma_rule(invalid_rule) is False

    def test_invalid_sigma_rule_not_dict(self, tmp_path, test_logger):
        """Test that a YAML file that doesn't contain a dict is rejected."""
        invalid_rule = tmp_path / "not_dict.yml"
        invalid_rule.write_text("""
- item1
- item2
- item3
""")
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        assert handler.is_valid_sigma_rule(invalid_rule) is False

    def test_invalid_sigma_rule_malformed_yaml(self, tmp_path, test_logger):
        """Test that a malformed YAML file is rejected."""
        invalid_rule = tmp_path / "malformed.yml"
        invalid_rule.write_text("""
title: Test Rule
logsource: [invalid
detection: }malformed
""")
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        assert handler.is_valid_sigma_rule(invalid_rule) is False

    def test_invalid_sigma_rule_empty_file(self, tmp_path, test_logger):
        """Test that an empty YAML file is rejected."""
        invalid_rule = tmp_path / "empty.yml"
        invalid_rule.write_text("")
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        assert handler.is_valid_sigma_rule(invalid_rule) is False

    def test_invalid_sigma_rule_nonexistent_file(self, tmp_path, test_logger):
        """Test that a nonexistent file is rejected."""
        nonexistent = tmp_path / "nonexistent.yml"
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        assert handler.is_valid_sigma_rule(nonexistent) is False

    def test_is_valid_sigma_rule_exception_returns_false(self, tmp_path, test_logger):
        """is_valid_sigma_rule returns False on any Exception (e.g. read error)."""
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        with patch("builtins.open", side_effect=OSError("read error")):
            assert handler.is_valid_sigma_rule(tmp_path / "any.yml") is False

    def test_valid_correlation_rule_document(self, tmp_path, test_logger):
        """YAML containing only a Sigma correlation rule is accepted."""
        corr = tmp_path / "corr.yml"
        corr.write_text("""
title: Correlation Only
id: 11111111-1111-1111-1111-111111111111
correlation:
  type: event_count
  rules:
    - other_rule
  condition:
    gte: 10
level: high
""")
        with patch.object(RulesetHandler, "ruleset_parsing", return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger,
            )
        assert handler.is_valid_sigma_rule(corr) is True

    def test_valid_multi_document_standard_and_correlation(self, tmp_path, test_logger):
        """Multi-document YAML with base rule and correlation is accepted."""
        multi = tmp_path / "multi.yml"
        multi.write_text("""
---
title: Base Rule
name: base_ref
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
  condition: selection
level: high
---
title: Correlation
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
correlation:
  type: event_count
  rules:
    - base_ref
  condition:
    gte: 2
level: high
""")
        with patch.object(RulesetHandler, "ruleset_parsing", return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger,
            )
        assert handler.is_valid_sigma_rule(multi) is True

    def test_is_yaml_accepts_multi_document_stream(self, tmp_path, test_logger):
        """is_yaml must accept multi-document YAML (safe_load fails on those)."""
        multi = tmp_path / "multi.yml"
        multi.write_text("""
---
a: 1
---
b: 2
""")
        with patch.object(RulesetHandler, "ruleset_parsing", return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger,
            )
        assert handler.is_yaml(multi) is True


class TestDuplicateRemovalBySqlQuery:
    """Tests for duplicate rule removal based on SQL query."""

    def test_removes_duplicates_with_same_sql_query(self, test_logger):
        """Test that rules with identical SQL queries are deduplicated."""
        # Mock ruleset with duplicate SQL queries but different titles
        mock_rules = [
            {
                "title": "Rule A",
                "id": "rule-a",
                "level": "high",
                "rule": ["SELECT * FROM logs WHERE EventID = 1"]
            },
            {
                "title": "Rule B",
                "id": "rule-b",
                "level": "medium",
                "rule": ["SELECT * FROM logs WHERE EventID = 1"]  # Same query
            },
            {
                "title": "Rule C",
                "id": "rule-c",
                "level": "low",
                "rule": ["SELECT * FROM logs WHERE EventID = 2"]  # Different query
            }
        ]
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[mock_rules]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        # Should have 2 rules after deduplication (Rule A and Rule C)
        assert len(handler.rulesets) == 2
        # Verify both unique queries are present
        queries = [tuple(r['rule']) for r in handler.rulesets]
        assert ("SELECT * FROM logs WHERE EventID = 1",) in queries
        assert ("SELECT * FROM logs WHERE EventID = 2",) in queries

    def test_keeps_first_rule_when_duplicates_found(self, test_logger):
        """Test that the first rule is kept when duplicates are found."""
        mock_rules = [
            {
                "title": "First Rule",
                "id": "first",
                "level": "high",
                "rule": ["SELECT * FROM logs WHERE EventID = 1"]
            },
            {
                "title": "Second Rule",
                "id": "second",
                "level": "medium",
                "rule": ["SELECT * FROM logs WHERE EventID = 1"]
            }
        ]
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[mock_rules]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        # Should keep the first rule (higher level wins after sorting)
        assert len(handler.rulesets) == 1
        assert handler.rulesets[0]['title'] == "First Rule"

    def test_handles_multiple_sql_queries_per_rule(self, test_logger):
        """Test deduplication with rules containing multiple SQL queries."""
        mock_rules = [
            {
                "title": "Rule A",
                "id": "rule-a",
                "level": "high",
                "rule": ["SELECT * FROM logs WHERE EventID = 1", "SELECT * FROM logs WHERE EventID = 2"]
            },
            {
                "title": "Rule B",
                "id": "rule-b",
                "level": "medium",
                "rule": ["SELECT * FROM logs WHERE EventID = 1", "SELECT * FROM logs WHERE EventID = 2"]  # Same
            },
            {
                "title": "Rule C",
                "id": "rule-c",
                "level": "low",
                "rule": ["SELECT * FROM logs WHERE EventID = 1"]  # Different (only one query)
            }
        ]
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[mock_rules]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        # Should have 2 rules (A and C)
        assert len(handler.rulesets) == 2

    def test_handles_rules_without_rule_field(self, test_logger):
        """Test that rules without 'rule' field are skipped."""
        mock_rules = [
            {
                "title": "Rule A",
                "id": "rule-a",
                "level": "high",
                "rule": ["SELECT * FROM logs WHERE EventID = 1"]
            },
            {
                "title": "Malformed Rule",
                "id": "malformed",
                "level": "medium"
                # Missing 'rule' field
            }
        ]
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[mock_rules]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        # Should only have 1 rule (the valid one)
        assert len(handler.rulesets) == 1
        assert handler.rulesets[0]['title'] == "Rule A"

    def test_no_duplicates_when_all_unique(self, test_logger):
        """Test that no rules are removed when all have unique queries."""
        mock_rules = [
            {
                "title": "Rule A",
                "id": "rule-a",
                "level": "high",
                "rule": ["SELECT * FROM logs WHERE EventID = 1"]
            },
            {
                "title": "Rule B",
                "id": "rule-b",
                "level": "medium",
                "rule": ["SELECT * FROM logs WHERE EventID = 2"]
            },
            {
                "title": "Rule C",
                "id": "rule-c",
                "level": "low",
                "rule": ["SELECT * FROM logs WHERE EventID = 3"]
            }
        ]
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[mock_rules]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        # All 3 rules should be present
        assert len(handler.rulesets) == 3

    def test_event_filter_excludes_correlation_rules(self, test_logger):
        """Correlation rules must not disable EventFilter when base rules have channel/eventid."""
        mock_rules = [
            {
                "title": "Base",
                "rule": ["SELECT 1"],
                "level": "high",
                "channel": ["Security"],
                "eventid": [4625],
            },
            {
                "title": "Correlation",
                "rule": ["SELECT 2"],
                "level": "high",
                "correlation": True,
            },
        ]
        with patch.object(RulesetHandler, "ruleset_parsing", return_value=[mock_rules]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger,
            )
        assert handler.event_filter is not None
        assert handler.event_filter.is_enabled is True


class TestRulesetSortingByLevel:
    """Tests for ruleset sorting by severity level."""

    def test_sorts_by_level_critical_first(self, test_logger):
        """Test that rules are sorted with critical level first."""
        mock_rules = [
            {"title": "Low Rule", "level": "low", "rule": ["SELECT 1"]},
            {"title": "Critical Rule", "level": "critical", "rule": ["SELECT 2"]},
            {"title": "High Rule", "level": "high", "rule": ["SELECT 3"]},
            {"title": "Medium Rule", "level": "medium", "rule": ["SELECT 4"]},
            {"title": "Info Rule", "level": "informational", "rule": ["SELECT 5"]},
        ]
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[mock_rules]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        levels = [r['level'] for r in handler.rulesets]
        assert levels == ["critical", "high", "medium", "low", "informational"]

    def test_handles_missing_level(self, test_logger):
        """Test that rules without level are sorted last."""
        mock_rules = [
            {"title": "No Level Rule", "rule": ["SELECT 1"]},
            {"title": "Critical Rule", "level": "critical", "rule": ["SELECT 2"]},
        ]
        
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[mock_rules]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        
        # Critical should be first, no-level last
        assert handler.rulesets[0]['level'] == "critical"
        assert handler.rulesets[1].get('level') is None


class TestRulesetJsonParsing:
    """Tests for JSON ruleset parsing."""

    def test_loads_valid_json_ruleset(self, tmp_path, test_logger):
        """Test loading a valid JSON ruleset file."""
        ruleset_file = tmp_path / "test_ruleset.json"
        ruleset_data = [
            {
                "title": "Test Rule",
                "id": "test-001",
                "level": "high",
                "rule": ["SELECT * FROM logs WHERE EventID = 1"]
            }
        ]
        ruleset_file.write_text(json.dumps(ruleset_data))
        
        handler = RulesetHandler(
            ruleset_config=RulesetConfig(ruleset=[str(ruleset_file)]),
            logger=test_logger
        )
        
        assert len(handler.rulesets) == 1
        assert handler.rulesets[0]['title'] == "Test Rule"

    def test_handles_empty_ruleset_file(self, tmp_path, test_logger):
        """Test handling of empty ruleset file."""
        ruleset_file = tmp_path / "empty_ruleset.json"
        ruleset_file.write_text("[]")
        
        handler = RulesetHandler(
            ruleset_config=RulesetConfig(ruleset=[str(ruleset_file)]),
            logger=test_logger
        )
        
        assert len(handler.rulesets) == 0


@pytest.mark.requires_sigma
class TestSigmaRulesToRulesetBranches:
    """Tests for sigma_rules_to_ruleset code paths (directory, skipped invalid, saveRuleset)."""

    def test_sigma_rules_to_ruleset_directory_and_skipped_invalid(self, tmp_path, test_logger):
        """sigma_rules_to_ruleset with a directory and mixed valid/invalid YAML hits dir branch and skipped count."""
        sigma_dir = tmp_path / "sigma_rules"
        sigma_dir.mkdir()
        (sigma_dir / "valid.yml").write_text("""
title: Valid Rule
id: 5fce3e2a-5b3d-4c8e-9a1b-2c3d4e5f6a7b
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
    condition: selection
level: high
""")
        (sigma_dir / "invalid_no_detection.yml").write_text("""
title: No detection
logsource:
    product: windows
""")
        with patch.object(test_logger, "debug") as mock_debug:
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(
                    ruleset=[str(sigma_dir)],
                    pipeline=[["sysmon"]],
                ),
                logger=test_logger,
            )
        assert len(handler.rulesets) >= 1
        # Should have logged skipped invalid if invalid_no_detection was skipped
        debug_calls = " ".join(str(c) for c in mock_debug.call_args_list)
        assert "invalid" in debug_calls.lower() or "Skipped" in debug_calls or len(handler.rulesets) == 1

    def test_sigma_rules_to_ruleset_save_ruleset_writes_file(self, tmp_path, test_logger):
        """When save_ruleset is True, sigma_rules_to_ruleset writes a JSON file."""
        sigma_dir = tmp_path / "sigma"
        sigma_dir.mkdir()
        (sigma_dir / "one.yml").write_text("""
title: One
id: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
logsource: { product: windows, service: sysmon }
detection:
    selection: { EventID: 1 }
    condition: selection
level: high
""")
        import os
        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            with patch.object(test_logger, "info"):
                handler = RulesetHandler(
                    ruleset_config=RulesetConfig(
                        ruleset=[str(sigma_dir)],
                        pipeline=[["sysmon"]],
                        save_ruleset=True,
                    ),
                    logger=test_logger,
                )
            assert len(handler.rulesets) >= 1
            saved = list(tmp_path.glob("ruleset-*.json"))
            assert len(saved) >= 1
            content = saved[0].read_text()
            assert "One" in content or "rule" in content.lower()
        finally:
            os.chdir(old_cwd)

    def test_sigma_rules_to_ruleset_conversion_errors_in_summary(self, tmp_path, test_logger):
        """When some rules fail to convert, summary includes 'X failed' (covers conversion_errors branch)."""
        sigma_dir = tmp_path / "sigma"
        sigma_dir.mkdir()
        for i in range(2):
            (sigma_dir / f"r{i}.yml").write_text(f"""
title: Rule {i}
id: a1b2c3d4-e5f6-4a5b-8c9d-00000000000{i}
logsource: {{ product: windows, service: sysmon }}
detection:
    selection: {{ EventID: {i + 1} }}
    condition: selection
level: high
""")
        with patch.object(test_logger, "info") as mock_info:
            with patch.object(RulesetHandler, "convert_sigma_rules", side_effect=[{"rule": ["SELECT 1"], "level": "high"}, None]):
                handler = RulesetHandler(
                    ruleset_config=RulesetConfig(
                        ruleset=[str(sigma_dir)],
                        pipeline=[["sysmon"]],
                    ),
                    logger=test_logger,
                )
        assert len(handler.rulesets) == 1
        info_calls = " ".join(str(c) for c in mock_info.call_args_list)
        assert "failed" in info_calls


@pytest.mark.requires_sigma
class TestSigmaCorrelationConversion:
    """End-to-end conversion of multi-document Sigma rules with correlation."""

    def test_multi_doc_correlation_produces_zircolite_rule(self, tmp_path, test_logger):
        """Base + correlation in one YAML file converts to one correlation rule with SQL."""
        rules_yml = tmp_path / "rules.yml"
        rules_yml.write_text("""
---
title: Process Create
name: proc_create
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
  condition: selection
level: high
---
title: Many process creates
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
correlation:
  type: event_count
  rules:
    - proc_create
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 3
level: high
""")
        handler = RulesetHandler(
            ruleset_config=RulesetConfig(
                ruleset=[str(rules_yml)],
                pipeline=[["sysmon"]],
            ),
            logger=test_logger,
        )
        assert len(handler.rulesets) == 1
        corr = handler.rulesets[0]
        assert corr.get("correlation") is True
        assert "event_count" in corr["rule"][0] or "GROUP BY" in corr["rule"][0]
        assert "EventID" in corr["rule"][0]

    def test_correlation_event_count_sql_runs_on_sqlite(self, tmp_path, test_logger):
        """Generated event_count SQL executes against a minimal logs table."""
        rules_yml = tmp_path / "rules.yml"
        rules_yml.write_text("""
---
title: Process Create
name: proc_create
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
  condition: selection
level: high
---
title: Many process creates
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
correlation:
  type: event_count
  rules:
    - proc_create
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 3
level: high
""")
        handler = RulesetHandler(
            ruleset_config=RulesetConfig(
                ruleset=[str(rules_yml)],
                pipeline=[["sysmon"]],
            ),
            logger=test_logger,
        )
        sql = handler.rulesets[0]["rule"][0]
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute("CREATE TABLE logs (EventID INTEGER, Image TEXT)")
            for _ in range(3):
                conn.execute(
                    "INSERT INTO logs (EventID, Image) VALUES (?, ?)",
                    (1, "C:\\\\Windows\\\\System32\\\\cmd.exe"),
                )
            rows = conn.execute(sql).fetchall()
            assert len(rows) == 1
            assert rows[0][0] == "C:\\\\Windows\\\\System32\\\\cmd.exe"
            assert rows[0][1] == 3  # event_count
        finally:
            conn.close()

    def test_temporal_correlation_uses_configured_time_field(self, tmp_path, test_logger):
        """Temporal correlation SQL references the time_field from RulesetConfig, not 'timestamp'."""
        rules_yml = tmp_path / "temporal.yml"
        rules_yml.write_text("""
---
title: Process Create
name: proc_create
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
  condition: selection
level: high
---
title: Other Rule
name: other_rule
id: cccccccc-cccc-cccc-cccc-cccccccccccc
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 5
  condition: selection
level: high
---
title: Temporal test
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
correlation:
  type: temporal
  rules:
    - proc_create
    - other_rule
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 2
level: high
""")
        handler = RulesetHandler(
            ruleset_config=RulesetConfig(
                ruleset=[str(rules_yml)],
                pipeline=[["sysmon"]],
                time_field="UtcTime",
            ),
            logger=test_logger,
        )
        assert len(handler.rulesets) >= 1
        corr = [r for r in handler.rulesets if r.get("correlation")]
        assert len(corr) == 1
        sql = corr[0]["rule"][0]
        assert "UtcTime" in sql
        assert "timestamp" not in sql.lower().split("utctime")[0]

    def test_event_count_correlation_uses_custom_time_field(self, tmp_path, test_logger):
        """event_count correlation with non-default time_field propagates to backend."""
        rules_yml = tmp_path / "rules.yml"
        rules_yml.write_text("""
---
title: Process Create
name: proc_create
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
  condition: selection
level: high
---
title: Many process creates
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
correlation:
  type: event_count
  rules:
    - proc_create
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 3
level: high
""")
        handler = RulesetHandler(
            ruleset_config=RulesetConfig(
                ruleset=[str(rules_yml)],
                pipeline=[["sysmon"]],
                time_field="SystemTime",
            ),
            logger=test_logger,
        )
        assert len(handler.rulesets) == 1
        assert handler.rulesets[0].get("correlation") is True

    def test_default_time_field_is_system_time(self, test_logger):
        """RulesetConfig defaults time_field to SystemTime."""
        cfg = RulesetConfig()
        assert cfg.time_field == "SystemTime"


@pytest.mark.requires_sigma
class TestPipelineOrderPreserved:
    """Tests that user-specified pipeline order is preserved when converting Sigma rules."""

    def test_resolve_called_with_pipeline_names_in_user_order(self, tmp_path, test_logger):
        """Resolve must be called with pipeline names in the same order as -p sysmon -p windows-logsources."""
        wmi_rule = tmp_path / "wmi_event_subscription.yml"
        wmi_rule.write_text("""
title: WMI Event Subscription
id: test-wmi-001
status: test
logsource:
    product: windows
    category: wmi_event
detection:
    selection:
        EventID: [19, 20, 21]
    condition: selection
level: medium
""")
        resolve_calls = []

        def capture_resolve(self_resolver, pipeline_specs, target=None):
            resolve_calls.append(list(pipeline_specs))
            from sigma.processing.pipeline import ProcessingPipeline
            return ProcessingPipeline(name="combined", priority=0, items=[])

        with patch(
            "zircolite.rules.ProcessingPipelineResolver.resolve",
            capture_resolve,
        ):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(
                    ruleset=[str(wmi_rule)],
                    pipeline=[["sysmon"], ["windows-logsources"]],
                ),
                logger=test_logger,
            )

        assert len(resolve_calls) == 1, "resolve() should be called exactly once"
        names_passed = resolve_calls[0]
        assert isinstance(names_passed, list), "resolve() should be called with a list, not a dict"
        assert len(names_passed) == 2, "two pipelines should be passed"
        # User order is sysmon first, windows-logsources second
        assert names_passed[0] == handler.pipelines[0].name
        assert names_passed[1] == handler.pipelines[1].name

    def test_pipeline_priorities_restored_after_conversion(self, tmp_path, test_logger):
        """Pipeline priority values must be restored after sigma_rules_to_ruleset (no permanent mutation)."""
        wmi_rule = tmp_path / "wmi_event_subscription.yml"
        wmi_rule.write_text("""
title: WMI Event Subscription
id: test-wmi-002
status: test
logsource:
    product: windows
    category: wmi_event
detection:
    selection:
        EventID: 19
    condition: selection
level: medium
""")
        with patch(
            "zircolite.rules.ProcessingPipelineResolver.resolve",
            lambda self_resolver, pipeline_specs, target=None: __import__(
                "sigma.processing.pipeline", fromlist=["ProcessingPipeline"]
            ).ProcessingPipeline(name="combined", priority=0, items=[]),
        ):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(
                    ruleset=[str(wmi_rule)],
                    pipeline=[["sysmon"], ["windows-logsources"]],
                ),
                logger=test_logger,
            )

        # Record the actual priorities that exist after construction (the restored values).
        # Each pipeline object has a .priority attribute set by pySigma during loading;
        # all we assert is that no two pipelines have been mutated to the same temporary value
        # and that priorities remain distinct from 0 (the sentinel used during conversion).
        for p in handler.pipelines:
            assert p.priority != 0, (
                f"Pipeline '{p.name}' priority was not restored after conversion "
                f"(still has the temporary sentinel value 0)"
            )


class TestRulesUpdater:
    """Tests for RulesUpdater (download, unzip, checkIfNewerAndMove, clean, run)."""

    def test_download_mocked(self, test_logger, tmp_path):
        """Download writes file when requests.get is mocked."""
        mock_resp = MagicMock()
        mock_resp.headers.get.return_value = "100"
        mock_resp.iter_content.return_value = [b"x" * 50, b"y" * 50]

        with patch("zircolite.rules.requests.get", return_value=mock_resp):
            updater = RulesUpdater(logger=test_logger)
            updater.tempFile = str(tmp_path / "tmp-rules-abc.zip")
            updater.tmpDir = str(tmp_path / "tmp-rules-dir")
            updater.download()
            assert Path(updater.tempFile).exists()
            assert Path(updater.tempFile).stat().st_size == 100
            updater.clean()
            assert not Path(updater.tempFile).exists()

    def test_unzip_mocked(self, test_logger, tmp_path):
        """Unzip calls shutil.unpack_archive with temp file and dir."""
        zip_path = tmp_path / "rules.zip"
        zip_path.write_bytes(b"fake zip")
        dir_path = tmp_path / "out"
        dir_path.mkdir()

        updater = RulesUpdater(logger=test_logger)
        updater.tempFile = str(zip_path)
        updater.tmpDir = str(dir_path)
        with patch("zircolite.rules.shutil.unpack_archive") as mock_unpack:
            updater.unzip()
            mock_unpack.assert_called_once_with(str(zip_path), str(dir_path), "zip")

    def test_clean_removes_file_and_dir(self, test_logger, tmp_path):
        """Clean removes temp file and temp dir."""
        f = tmp_path / "tmp-rules-abc1.zip"
        d = tmp_path / "tmp-rules-xyz2"
        f.write_text("x")
        d.mkdir()

        updater = RulesUpdater(logger=test_logger)
        updater.tempFile = str(f)
        updater.tmpDir = str(d)
        updater.clean()

        assert not f.exists()
        assert not d.exists()

    def test_run_calls_clean_on_exception(self, test_logger):
        """Run calls clean in finally when download raises."""
        with patch.object(RulesUpdater, "download", side_effect=RuntimeError("network error")):
            with patch.object(RulesUpdater, "clean") as mock_clean:
                updater = RulesUpdater(logger=test_logger)
                updater.run()
                mock_clean.assert_called_once()

    def test_checkIfNewerAndMove_new_files(self, test_logger, tmp_path):
        """checkIfNewerAndMove moves new JSON rulesets to rules/ directory."""
        # Set up temp dir with a JSON ruleset
        tmp_dir = tmp_path / "tmp-rules-dir"
        tmp_dir.mkdir()
        ruleset = tmp_dir / "test_rules.json"
        ruleset.write_text('[{"title": "New Rule"}]')

        # Create the rules dir (empty)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        import os
        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            updater = RulesUpdater(logger=test_logger)
            updater.tmpDir = str(tmp_dir)
            updater.checkIfNewerAndMove()

            assert (rules_dir / "test_rules.json").exists()
            assert "test_rules.json" in str(updater.updated_rulesets[0])
        finally:
            os.chdir(old_cwd)

    def test_checkIfNewerAndMove_same_hash_skipped(self, test_logger, tmp_path):
        """checkIfNewerAndMove skips files with identical hashes."""
        content = '[{"title": "Same Rule"}]'

        # Set up temp dir with a JSON ruleset
        tmp_dir = tmp_path / "tmp-rules-dir"
        tmp_dir.mkdir()
        (tmp_dir / "test_rules.json").write_text(content)

        # Create the rules dir with identical file
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test_rules.json").write_text(content)

        import os
        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            updater = RulesUpdater(logger=test_logger)
            updater.tmpDir = str(tmp_dir)
            updater.checkIfNewerAndMove()

            assert len(updater.updated_rulesets) == 0
        finally:
            os.chdir(old_cwd)

    def test_checkIfNewerAndMove_creates_rules_dir(self, test_logger, tmp_path):
        """checkIfNewerAndMove creates rules/ directory if it doesn't exist."""
        tmp_dir = tmp_path / "tmp-rules-dir"
        tmp_dir.mkdir()
        (tmp_dir / "new.json").write_text("[]")

        import os
        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            updater = RulesUpdater(logger=test_logger)
            updater.tmpDir = str(tmp_dir)
            updater.checkIfNewerAndMove()

            assert (tmp_path / "rules").exists()
        finally:
            os.chdir(old_cwd)

    def test_run_exception_in_unzip(self, test_logger):
        """run() logs error and calls clean when unzip raises."""
        with patch.object(RulesUpdater, "download"):
            with patch.object(RulesUpdater, "unzip", side_effect=RuntimeError("bad zip")):
                with patch.object(RulesUpdater, "clean") as mock_clean:
                    updater = RulesUpdater(logger=test_logger)
                    updater.run()
                    mock_clean.assert_called_once()

    def test_run_logs_error_on_exception(self, test_logger):
        """run() logs the exception message when download raises."""
        with patch.object(RulesUpdater, "download", side_effect=RuntimeError("network error")):
            with patch.object(RulesUpdater, "clean"):
                updater = RulesUpdater(logger=test_logger)
                with patch.object(test_logger, "error") as mock_error:
                    updater.run()
                    mock_error.assert_called_once()
                    assert "network error" in str(mock_error.call_args)

    @pytest.mark.parametrize("exc_class,msg", [
        (requests.exceptions.ConnectionError, "network failed"),
        (requests.exceptions.Timeout, ""),
        (requests.exceptions.HTTPError, "502 Bad Gateway"),
    ])
    def test_run_download_exception_calls_clean(self, test_logger, exc_class, msg):
        """run() calls clean when download raises a requests exception."""
        with patch.object(RulesUpdater, "download", side_effect=exc_class(msg)):
            with patch.object(RulesUpdater, "clean") as mock_clean:
                updater = RulesUpdater(logger=test_logger)
                updater.run()
                mock_clean.assert_called_once()


class TestRulesetHandlerInitBranches:
    """Tests for RulesetHandler __init__ branches that are often uncovered."""

    def test_invalid_pipeline_name_logs_error(self, tmp_path, test_logger):
        """When a pipeline name is not found, logger.error is called."""
        valid_json = tmp_path / "rules.json"
        valid_json.write_text('[{"title": "R", "level": "high", "rule": ["SELECT 1"]}]')
        with patch.object(test_logger, "error") as mock_error:
            RulesetHandler(
                ruleset_config=RulesetConfig(
                    ruleset=[str(valid_json)],
                    pipeline=[["nonexistent-pipeline-xyz123"]],
                ),
                logger=test_logger,
            )
            mock_error.assert_called()
            call_str = " ".join(str(c) for c in mock_error.call_args_list)
            assert "nonexistent-pipeline-xyz123" in call_str or "not found" in call_str.lower()

    def test_no_rules_to_execute_logs_error(self, test_logger):
        """When ruleset_parsing returns only empty lists, 'No rules to execute' is logged."""
        with patch.object(RulesetHandler, "ruleset_parsing", return_value=[[]]):
            with patch.object(test_logger, "error") as mock_error:
                RulesetHandler(
                    ruleset_config=RulesetConfig(ruleset=["dummy"]),
                    logger=test_logger,
                )
                mock_error.assert_called()
                call_str = " ".join(str(c) for c in mock_error.call_args_list)
                assert "No rules to execute" in call_str

    def test_list_pipelines_only_logs_info(self, test_logger):
        """When list_pipelines_only=True, pipelines are listed and ruleset_parsing is not used for conversion."""
        with patch.object(RulesetHandler, "ruleset_parsing", return_value=[]):
            with patch.object(test_logger, "info") as mock_info:
                RulesetHandler(
                    ruleset_config=RulesetConfig(ruleset=[]),
                    logger=test_logger,
                    list_pipelines_only=True,
                )
                mock_info.assert_called()
                call_str = " ".join(str(c) for c in mock_info.call_args_list)
                assert "Installed pipelines" in call_str or "pipelines" in call_str.lower()


def _make_bare_handler(logger, **overrides):
    """Create a RulesetHandler without running __init__'s conversion logic."""
    with patch.object(RulesetHandler, '__init__', lambda self, **kw: None):
        handler = RulesetHandler()
    handler.logger = logger
    handler.rulesetPathList = overrides.get('rulesetPathList', [])
    handler.saveRuleset = overrides.get('saveRuleset', False)
    handler.pipelines = overrides.get('pipelines', [])
    handler.event_filter = overrides.get('event_filter', None)
    for key, val in overrides.items():
        if key not in ('rulesetPathList', 'saveRuleset', 'pipelines', 'event_filter'):
            setattr(handler, key, val)
    return handler


class TestRulesetHandlerEdgeCases:
    """Tests for RulesetHandler edge cases and error paths."""

    def test_is_yaml_returns_false_for_invalid_yaml(self, tmp_path, test_logger):
        """is_yaml returns False for files with invalid YAML content."""
        bad_yaml = tmp_path / "bad.yml"
        bad_yaml.write_text("key: [invalid\n  broken: }yaml")

        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        assert handler.is_yaml(bad_yaml) is False

    def test_is_yaml_returns_false_on_yaml_error(self, tmp_path, test_logger):
        """is_yaml returns False when yaml.safe_load raises YAMLError (covers except branch)."""
        invalid_yaml = tmp_path / "invalid.yml"
        invalid_yaml.write_text('key: "unclosed quote and no closing quote')
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        assert handler.is_yaml(invalid_yaml) is False

    def test_is_json_returns_false_for_invalid_json(self, tmp_path, test_logger):
        """is_json returns False for files with invalid JSON content."""
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{not valid json!!!")

        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        assert handler.is_json(bad_json) is False

    def test_rand_ruleset_name_format(self, test_logger):
        """rand_ruleset_name produces well-formed filename."""
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        name = handler.rand_ruleset_name("path/to/sigma rules!!")
        assert name.startswith("ruleset-")
        assert name.endswith(".json")
        assert "!!" not in name
        # Should contain a random string portion
        assert len(name) > len("ruleset-.json") + 2

    def test_rand_ruleset_name_special_chars(self, test_logger):
        """rand_ruleset_name cleans special characters and collapses hyphens."""
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        name = handler.rand_ruleset_name("a///b///c")
        assert "---" not in name  # Consecutive hyphens should be collapsed

    def test_convert_sigma_rules_exception_returns_none_and_logs(self, test_logger):
        """convert_sigma_rules returns None and logs when backend.convert_rule raises."""
        with patch.object(RulesetHandler, 'ruleset_parsing', return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger
            )
        mock_backend = MagicMock()
        mock_backend.convert_rule.side_effect = ValueError("unsupported condition")
        mock_rule = MagicMock()
        with patch.object(test_logger, "debug") as mock_debug:
            result = handler.convert_sigma_rules(mock_backend, mock_rule)
        assert result is None
        mock_debug.assert_called_once()

    def test_convert_correlation_rule_exception_returns_none_and_logs(self, test_logger):
        """convert_correlation_rule returns None and logs when backend raises."""
        with patch.object(RulesetHandler, "ruleset_parsing", return_value=[]):
            handler = RulesetHandler(
                ruleset_config=RulesetConfig(ruleset=[]),
                logger=test_logger,
            )
        mock_backend = MagicMock()
        mock_backend.convert_correlation_rule.side_effect = ValueError("bad correlation")
        mock_rule = MagicMock()
        mock_rule.title = "Bad Corr"
        with patch.object(test_logger, "debug") as mock_debug:
            result = handler.convert_correlation_rule(mock_backend, mock_rule)
        assert result is None
        mock_debug.assert_called_once()
        assert "Cannot convert rule" in str(mock_debug.call_args) or "convert" in str(mock_debug.call_args).lower()

    def test_ruleset_parsing_nonexistent_path(self, test_logger):
        """ruleset_parsing warns and skips non-existent paths."""
        handler_obj = _make_bare_handler(
            test_logger, rulesetPathList=["/nonexistent/rules.json"],
        )
        result = handler_obj.ruleset_parsing()
        assert result == []

    def test_ruleset_parsing_invalid_json_file(self, tmp_path, test_logger):
        """ruleset_parsing handles JSON files that fail to load."""
        bad_json = tmp_path / "broken.json"
        bad_json.write_bytes(b'\x00\x01\x02\x03')

        handler_obj = _make_bare_handler(
            test_logger, rulesetPathList=[str(bad_json)],
        )
        result = handler_obj.ruleset_parsing()
        # Should not crash, just log error and continue
        assert isinstance(result, list)

    def test_ruleset_parsing_json_load_exception_logs_error(self, tmp_path, test_logger):
        """ruleset_parsing logs error when json.loads fails (covers except branch)."""
        json_file = tmp_path / "bad.json"
        json_file.write_text("not valid json {{{")
        handler_obj = _make_bare_handler(
            test_logger,
            rulesetPathList=[str(json_file)],
            is_json=lambda p: p.suffix == ".json",
        )
        with patch.object(test_logger, "error") as mock_error:
            result = handler_obj.ruleset_parsing()
        assert result == []
        mock_error.assert_called_once()
        assert "Cannot load" in str(mock_error.call_args)

    def test_ruleset_parsing_yaml_conversion_exception_logs_error(self, tmp_path, test_logger):
        """ruleset_parsing logs error when Sigma conversion raises (YAML path)."""
        yaml_file = tmp_path / "rule.yml"
        yaml_file.write_text("""
title: Test
logsource: { product: windows }
detection:
    selection: { EventID: 1 }
    condition: selection
""")
        handler_obj = _make_bare_handler(
            test_logger,
            rulesetPathList=[str(yaml_file)],
            pipelines=[MagicMock()],
            is_json=lambda p: False,
            is_yaml=lambda p: p.suffix in (".yml", ".yaml"),
        )
        with patch.object(RulesetHandler, "sigma_rules_to_ruleset", side_effect=RuntimeError("convert failed")):
            with patch.object(test_logger, "error") as mock_error:
                result = handler_obj.ruleset_parsing()
        assert isinstance(result, list)
        mock_error.assert_called()
        assert "Cannot convert" in str(mock_error.call_args) or "convert failed" in str(mock_error.call_args)

    def test_ruleset_parsing_dir_conversion_exception_logs_error(self, tmp_path, test_logger):
        """ruleset_parsing logs error when directory Sigma conversion raises."""
        sigma_dir = tmp_path / "sigma"
        sigma_dir.mkdir()
        (sigma_dir / "a.yml").write_text("title: T\nlogsource: {}\ndetection: {}")
        handler_obj = _make_bare_handler(
            test_logger,
            rulesetPathList=[str(sigma_dir)],
            pipelines=[MagicMock()],
            is_json=lambda p: False,
            is_yaml=lambda p: p.suffix in (".yml", ".yaml"),
        )
        with patch.object(RulesetHandler, "sigma_rules_to_ruleset", side_effect=RuntimeError("dir convert failed")):
            with patch.object(test_logger, "error") as mock_error:
                result = handler_obj.ruleset_parsing()
        assert isinstance(result, list)
        mock_error.assert_called()
        assert "Cannot convert" in str(mock_error.call_args) or "dir convert failed" in str(mock_error.call_args)
