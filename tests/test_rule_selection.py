"""Rule selection: -R, --min-level, --rule-status, --include-tag and --exclude-tag."""

import logging
from typing import ClassVar

import pytest

from zircolite.rule_selection import (
    RuleSelection,
    has_tag,
    level_rank,
    rule_status,
    select_rules,
    tag_problem,
)


def rule(title="R", level="high", status="test", tags=("attack.execution", "attack.t1059.001")):
    return {"title": title, "level": level, "status": status, "tags": list(tags), "rule": [f"SELECT '{title}'"]}


def titles(rules):
    return [r["title"] for r in rules]


class TestTags:
    @pytest.mark.parametrize("pattern,expected", [
        ("attack.t1059.001", True),
        ("attack.t1059", True),
        ("attack", True),
        ("attack.t105", False),
        ("attack.t1059.00", False),
        ("ATTACK.T1059", True),
        ("execution", False),
    ])
    def test_a_pattern_matches_whole_segments(self, pattern, expected):
        selection = RuleSelection.build(include_tags=[pattern])

        assert has_tag(rule(), selection.include_tags) is expected

    def test_tags_written_upper_case_match(self):
        assert has_tag(rule(tags=["attack.T1059.001"]), ["attack.t1059"])

    def test_a_tag_given_as_a_string_is_one_tag(self):
        assert has_tag({"tags": "cve.2021-44228"}, ["cve.2021-44228"])
        assert not has_tag({"tags": "cve.2021-44228"}, ["c"])

    def test_a_rule_without_tags_matches_nothing(self):
        assert not has_tag({"title": "untagged"}, ["attack"])

    @pytest.mark.parametrize("tag", ["", "  ", "a,b", ".attack", "attack.", None, 3])
    def test_a_tag_that_cannot_select_anything_is_a_problem(self, tag):
        assert tag_problem(tag)

    def test_a_whole_tag_is_fine(self):
        assert tag_problem("detection.threat-hunting") is None


class TestStatusAndLevel:
    @pytest.mark.parametrize("status,expected", [
        ("stable", "stable"), ("Test", "test"), ("", "experimental"), (None, "experimental"),
        ("unknown", "experimental"), ("deprecated", "deprecated"),
    ])
    def test_the_status_a_rule_counts_as(self, status, expected):
        assert rule_status({"status": status}) == expected

    def test_a_rule_without_a_level_ranks_as_informational(self):
        assert level_rank({}) == level_rank({"level": "informational"}) == 0
        assert level_rank({"level": "CRITICAL"}) == 4


class TestSelectRules:
    RULES: ClassVar[list] = [
        rule("Stable exec", status="stable"),
        rule("Test hunting", status="test", tags=["attack.execution", "detection.threat-hunting"]),
        rule("Experimental exec", status="experimental"),
        rule("No status", status=""),
        rule("Low", level="low", status="stable"),
        rule("Untagged", status="stable", tags=[]),
    ]

    def select(self, **settings):
        return titles(select_rules(self.RULES, RuleSelection.build(**settings), logging.getLogger("t")))

    def test_no_setting_keeps_every_rule(self):
        assert self.select() == titles(self.RULES)

    def test_status(self):
        assert self.select(statuses=["stable", "test"]) == ["Stable exec", "Test hunting", "Low", "Untagged"]

    def test_a_rule_without_a_status_counts_as_experimental(self):
        assert self.select(statuses=["experimental"]) == ["Experimental exec", "No status"]

    def test_include_drops_untagged_rules(self):
        assert "Untagged" not in self.select(include_tags=["attack"])

    def test_exclusion_wins_over_inclusion(self):
        kept = self.select(include_tags=["attack.execution"], exclude_tags=["detection.threat-hunting"])

        assert "Test hunting" not in kept
        assert "Stable exec" in kept

    def test_settings_combine(self):
        kept = self.select(statuses=["stable", "test"], exclude_tags=["detection.threat-hunting"],
                           min_level="medium", rule_filters=["Untagged"])

        assert kept == ["Stable exec"]

    def test_each_setting_reports_what_it_left_out(self, caplog):
        with caplog.at_level(logging.INFO):
            self.select(statuses=["stable"], exclude_tags=["detection.threat-hunting"])

        assert "Rule selection: status stable · not tagged detection.threat-hunting" in caplog.text
        assert "3 rule(s) left out by --rule-status" in caplog.text

    def test_a_tag_no_rule_carries_is_reported(self, caplog):
        with caplog.at_level(logging.WARNING):
            kept = self.select(exclude_tags=["attack.t9999"])

        assert kept == titles(self.RULES)
        assert "--exclude-tag attack.t9999: no loaded rule carries this tag" in caplog.text


class TestSelection:
    def test_flags_name_only_the_settings_used(self):
        selection = RuleSelection.build(statuses=["stable"], min_level="high")

        assert selection.flags() == ["--min-level", "--rule-status"]
        assert RuleSelection.build().flags() == []

    def test_values_are_folded_and_deduplicated(self):
        selection = RuleSelection.build(statuses=["Stable", "stable"], include_tags=[" Attack.Execution "])

        assert selection.statuses == ("stable",)
        assert selection.include_tags == ("attack.execution",)

    def test_rule_filters_keep_their_case(self):
        assert RuleSelection.build(rule_filters=["Noisy"]).rule_filters == ("Noisy",)
