"""Which of the loaded rules a run keeps: -R, --min-level, --rule-status and tags.

Selection runs once, as the rules load and before duplicates are merged, so a
rule left out neither widens the event filter nor hides another rule that
shares its SQL. Every setting is a test on one rule, so their order does not
change the result. Process workers import this module through core, so it
stays free of pySigma.
"""

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .config import RULE_LEVELS

STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
# What a rule without a known status counts as: the least vetted status a
# shipped ruleset carries, so a status filter never keeps it by accident.
UNKNOWN_STATUS = "experimental"


def level_rank(rule: dict[str, Any]) -> int:
    """The rule's position in RULE_LEVELS; a rule without a known level is informational."""
    level = str(rule.get("level") or "").lower()
    return RULE_LEVELS.index(level) if level in RULE_LEVELS else 0


def title_filtered(rule: dict[str, Any], rule_filters: Iterable[str]) -> bool:
    """Whether -R names this rule: its title contains one of the texts (case sensitive)."""
    title = rule.get("title", "")
    return any(rule_filter in title for rule_filter in rule_filters)


def rule_status(rule: dict[str, Any]) -> str:
    status = str(rule.get("status") or "").lower()
    return status if status in STATUSES else UNKNOWN_STATUS


def _tags(rule: dict[str, Any]) -> list[str]:
    tags = rule.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return [str(tag).lower() for tag in tags]


def has_tag(rule: dict[str, Any], patterns: Iterable[str]) -> bool:
    """Whether a tag equals a pattern or sits below one at a dot.

    ``attack.t1059`` selects ``attack.t1059.001`` but not ``attack.t10590``.
    Patterns are expected lower case.
    """
    tags = _tags(rule)
    return any(tag == pattern or tag.startswith(pattern + ".") for pattern in patterns for tag in tags)


def tag_problem(tag: Any) -> str | None:
    """Why *tag* cannot select anything, or None."""
    if not isinstance(tag, str) or not tag.strip():
        return "a tag cannot be empty"
    if "," in tag:
        return f"{tag!r} holds a comma: give each tag as its own value"
    if tag.startswith(".") or tag.endswith("."):
        return f"{tag!r} starts or ends with a dot"
    return None


@dataclass(frozen=True)
class RuleSelection:
    """The selection settings of a run, normalised. Empty means no restriction."""

    rule_filters: tuple[str, ...] = ()
    statuses: tuple[str, ...] = ()
    include_tags: tuple[str, ...] = ()
    exclude_tags: tuple[str, ...] = ()
    min_level: str | None = None

    @classmethod
    def build(cls, rule_filters: Iterable[str] | None = None, statuses: Iterable[str] | None = None,
              include_tags: Iterable[str] | None = None, exclude_tags: Iterable[str] | None = None,
              min_level: str | None = None) -> "RuleSelection":
        def folded(values: Iterable[str] | None) -> tuple[str, ...]:
            return tuple(dict.fromkeys(str(value).strip().lower() for value in values or ()))

        return cls(tuple(rule_filters or ()), folded(statuses), folded(include_tags), folded(exclude_tags),
                   min_level)

    def flags(self) -> list[str]:
        """The options this selection uses, as typed on the command line."""
        used = [("--rulefilter", self.rule_filters), ("--min-level", self.min_level),
                ("--rule-status", self.statuses), ("--include-tag", self.include_tags),
                ("--exclude-tag", self.exclude_tags)]
        return [flag for flag, value in used if value]

    def describe(self) -> str:
        """One line for the log: the status and tag settings, the ones with no message of their own."""
        parts = []
        if self.statuses:
            parts.append(f"status {', '.join(self.statuses)}")
        if self.include_tags:
            parts.append(f"tagged {', '.join(self.include_tags)}")
        if self.exclude_tags:
            parts.append(f"not tagged {', '.join(self.exclude_tags)}")
        return " · ".join(parts)


def select_rules(rules: list[dict[str, Any]], selection: RuleSelection,
                 logger: logging.Logger) -> list[dict[str, Any]]:
    """The rules *selection* keeps, logging how many each setting left out."""
    kept = rules

    def keep(wanted: Any, message: str) -> None:
        nonlocal kept
        before = len(kept)
        kept = [rule for rule in kept if wanted(rule)]
        if len(kept) < before:
            logger.info(f"[+] {before - len(kept)} rule(s) {message}")

    if description := selection.describe():
        logger.info(f"[+] Rule selection: {description}")
    for flag, patterns in (("--include-tag", selection.include_tags), ("--exclude-tag", selection.exclude_tags)):
        for pattern in patterns:
            if not any(has_tag(rule, (pattern,)) for rule in rules):
                logger.warning(f"[yellow]   [!] {flag} {pattern}: no loaded rule carries this tag[/]")

    if selection.rule_filters:
        keep(lambda rule: not title_filtered(rule, selection.rule_filters), "removed by --rulefilter")
    if selection.min_level is not None:
        floor = RULE_LEVELS.index(selection.min_level)
        keep(lambda rule: level_rank(rule) >= floor, f"below level {selection.min_level} left out")
    if selection.statuses:
        keep(lambda rule: rule_status(rule) in selection.statuses, "left out by --rule-status")
    if selection.include_tags:
        keep(lambda rule: has_tag(rule, selection.include_tags), "left out by --include-tag")
    if selection.exclude_tags:
        keep(lambda rule: not has_tag(rule, selection.exclude_tags), "left out by --exclude-tag")
    return kept
