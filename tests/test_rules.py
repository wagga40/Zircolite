"""
Tests for the RulesetHandler class in zircolite/rules.py.
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite.rules import RulesetHandler
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
