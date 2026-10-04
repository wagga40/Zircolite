"""The order the package viewer lays its tactic lanes and matrix columns out in."""

from zircolite.attack import _TACTIC_ALIASES, TACTIC_ORDER, extract_attack_tactics


def test_every_tactic_a_tag_can_name_has_a_place():
    assert set(_TACTIC_ALIASES.values()) == set(TACTIC_ORDER)


def test_each_tactic_appears_once():
    assert len(TACTIC_ORDER) == len(set(TACTIC_ORDER)) == 15


def test_retired_and_underscored_spellings_reach_a_lane():
    tactics = extract_attack_tactics(["attack.defense_evasion", "attack.privilege_escalation"])

    assert tactics == ["stealth", "privilege-escalation"]
    assert all(tactic in TACTIC_ORDER for tactic in tactics)


def test_defense_evasions_successors_take_its_place():
    position = TACTIC_ORDER.index("privilege-escalation")

    assert TACTIC_ORDER[position + 1:position + 4] == ("stealth", "defense-impairment", "credential-access")
