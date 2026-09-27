"""Channel bounds must not prune matches permitted by SQLite's collation."""

import pytest

from zircolite import ProcessingConfig, ZircoliteCore
from zircolite.sqlscan import scan_query


@pytest.mark.parametrize(
    "predicate, channels",
    [
        ("Channel='Security' AND Channel='SECURITY'", {"Security"}),
        ("Channel='SECURITY' AND Channel='Security'", {"SECURITY"}),
        (
            "Channel IN ('Security', 'System') "
            "AND Channel IN ('SECURITY', 'Application')",
            {"Security"},
        ),
        (
            "Channel='Security' COLLATE NOCASE "
            "AND Channel='SECURITY' COLLATE NOCASE",
            {"Security"},
        ),
        (
            "(Channel='Security' OR Channel='System') "
            "AND (Channel='SECURITY' OR Channel='SYSTEM')",
            {"Security", "System"},
        ),
        ("Channel='Security' AND Channel='System'", set()),
        ("Channel='Sécurity' AND Channel='SÉCURITY'", set()),
        ("Channel='Straße' AND Channel='STRASSE'", set()),
    ],
)
def test_channel_intersections_follow_ascii_nocase(predicate, channels):
    assert scan_query(f"SELECT * FROM logs WHERE {predicate}").channels == channels


@pytest.mark.parametrize("collation", ["BINARY", "RTRIM"])
def test_unsupported_collations_do_not_prove_channel_contradictions(collation):
    query = (
        f"SELECT * FROM logs WHERE Channel='Security' COLLATE {collation} "
        f"AND Channel='Security ' COLLATE {collation}"
    )
    assert scan_query(query).channels is None


@pytest.mark.parametrize(
    "predicate",
    [
        "Channel='Security' AND Channel='SECURITY'",
        "Channel IN ('Security', 'System') AND Channel IN ('SECURITY', 'Application')",
        "Channel='Security' COLLATE NOCASE AND Channel='SECURITY' COLLATE NOCASE",
    ],
)
def test_channel_case_intersections_keep_matching_rules(
    predicate, field_mappings_file, test_logger
):
    core = ZircoliteCore(
        field_mappings_file, ProcessingConfig(no_output=True), logger=test_logger
    )
    try:
        core.create_db("Channel TEXT COLLATE NOCASE, EventID INTEGER")
        core.insert_data_to_db([{"Channel": "Security", "EventID": 4688}])
        query = f"SELECT * FROM logs WHERE {predicate}"
        # The same matching SQL must also survive the ruleset's census pruning.
        assert len(core.execute_select_query(query)) == 1
        core.load_ruleset_from_var([{"title": "channel case", "rule": [query]}], None)
        core.execute_ruleset(
            "unused.json", keep_results=True, disable_progress=True, show_table=False
        )
        assert [(result["title"], result["count"]) for result in core.full_results] == [
            ("channel case", 1)
        ]
        assert core.metrics.data["pruned_rules"] == 0
    finally:
        core.close()
