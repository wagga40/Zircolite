"""Helpers for working with Sigma ATT&CK tags."""

import re

_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# Values are ATT&CK tactic shortnames, which is what a Navigator layer's
# "tactic" field expects. ATT&CK v19 retired Defense Evasion: Stealth kept
# TA0005 and Defense Impairment is the new TA0112, so a rule still carrying
# the retired tag maps to Stealth, the tactic that inherited the ID.
_TACTIC_ALIASES = {
    "reconnaissance": "reconnaissance",
    "resource-development": "resource-development",
    "resource_development": "resource-development",
    "initial-access": "initial-access",
    "initial_access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege-escalation",
    "privilege_escalation": "privilege-escalation",
    "stealth": "stealth",
    "defense-impairment": "defense-impairment",
    "defense_impairment": "defense-impairment",
    "defense-evasion": "stealth",
    "defense_evasion": "stealth",
    "credential-access": "credential-access",
    "credential_access": "credential-access",
    "discovery": "discovery",
    "lateral-movement": "lateral-movement",
    "lateral_movement": "lateral-movement",
    "collection": "collection",
    "command-and-control": "command-and-control",
    "command_and_control": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


def extract_attack_techniques(tags: list) -> list:
    """Extract ATT&CK technique IDs from Sigma tags."""
    seen: dict = {}
    for tag in (tags or []):
        match = _TECHNIQUE_RE.match(str(tag))
        if match:
            seen[match.group(1).upper()] = None
    return list(seen)


def extract_attack_tactics(tags: list) -> list:
    """Extract Navigator tactic IDs from Sigma tags."""
    seen: dict = {}
    for tag in (tags or []):
        if not str(tag).lower().startswith("attack."):
            continue
        suffix = str(tag)[7:].lower()
        tactic = _TACTIC_ALIASES.get(suffix)
        if tactic:
            seen[tactic] = None
    return list(seen)
