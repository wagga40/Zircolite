"""The experimental store must reproduce public evidence or reject the workload."""
import sqlite3
from contextlib import closing

import pytest

from tools import compact_storage_benchmark as bench
from zircolite.config import ProcessingConfig
from zircolite.core import ZircoliteCore
from zircolite.spellings import record_spellings


def rule(sql, fields):
    return {"title": "event", "result_type": "event", "source_table": "logs",
            "required_fields": fields, "rule": [sql]}


@pytest.mark.parametrize("sql", [
    "SELECT COUNT(*) FROM logs WHERE Channel='A'",
    "SELECT * FROM logs WHERE Channel='A' LIMIT 1",
    "SELECT * FROM logs WHERE Channel='A' UNION SELECT * FROM logs WHERE EventID=1",
    "SELECT * FROM logs WHERE Channel='A' OR EXISTS (SELECT EventID FROM logs)",
    "SELECT * FROM logs WHERE EventID=(1+2)",
    "SELECT * FROM logs WHERE hex(EventID)=Other",
    "SELECT * FROM logs WHERE Other REGEXP Channel",
    "SELECT * FROM logs WHERE Channel='A' -- comment",
    "SELECT * FROM logs WHERE current_timestamp='a'",
    "SELECT * FROM logs WHERE _sigma_fulltext LIKE '%name%'",
    "SELECT * FROM logs WHERE EventID=1; SELECT * FROM logs",
])
def test_unsupported_rules_reject_the_complete_workload(sql):
    good = rule("SELECT * FROM logs WHERE EventID=1", ["EventID"])
    with pytest.raises(bench.Ineligible):
        bench.statements([good, rule(sql, ["Channel", "EventID", "Other", "current_timestamp", "_sigma_fulltext"])])


@pytest.mark.parametrize("metadata", [{"correlation": True}, {"correlation_plan": {}},
                                      {"source_table": "saved"}, {"required_fields": []}])
def test_missing_proof_and_correlation_metadata_reject_workload(metadata):
    with pytest.raises(bench.Ineligible):
        bench.statements([rule("SELECT * FROM logs WHERE EventID=1", ["EventID"]) | metadata])


def source_rows(source):
    source.execute('CREATE TABLE logs(row_id INTEGER PRIMARY KEY, Channel TEXT COLLATE NOCASE, '
                   'EventID INTEGER, "Cmd Field" TEXT COLLATE NOCASE, Extra, timefield TEXT)')
    source.executemany("INSERT INTO logs VALUES(?,?,?,?,?,?)", [
        (1, "ABC", 1, "Needle", b"\xff\0", "t"),
        (2, "ABC", 1, None, 2**62, "t"),
        (4, "ABC", 2, "Needle", float("inf"), "t"),
        (7, "ABC", "unknown", "Needle", -1.25, None),
        (9, None, 2, None, float("-inf"), "t"),
    ])
    record_spellings(source.cursor(), 1, [(0, ("cMd Field",))])


def test_matches_and_package_replay_restore_full_affinity_spelling_and_sparse_ids(tmp_path):
    plans = bench.statements([
        rule("SELECT * FROM logs WHERE Channel='abc' AND EventID=1 AND NOT (`Cmd Field` LIKE '%missing%')",
             ["Channel", "EventID", "Cmd Field"]),
        rule("SELECT * FROM logs WHERE Channel='abc' AND EventID=1 AND `Cmd Field` REGEXP 'Need'",
             ["Channel", "EventID", "Cmd Field"]),
        rule("SELECT * FROM logs WHERE EventID=2 AND missing IS NULL", ["EventID", "missing"]),
    ])
    config = ProcessingConfig(time_field="TimeField")
    with (closing(sqlite3.connect(":memory:")) as source,
          closing(ZircoliteCore(bench.CONFIG, config)) as compact,
          closing(ZircoliteCore(bench.CONFIG, config)) as reference):
        source_rows(source)
        source.commit()
        source.backup(reference.db_connection)
        evidence = bench.Evidence(compact.db_connection, tmp_path, 16 * bench.MIB)
        bench.project(source, compact, plans, evidence, part=3)
        canonical = [event for _, event in bench.all_events(source, "TimeField")]
        assert canonical == list(evidence.events(3))
        assert canonical[0]["cMd Field"] == "Needle" and canonical[0]["TimeField"] == "t"
        assert isinstance(canonical[0]["Extra"], bytes) and type(canonical[1]["Extra"]) is int
        for plan in plans:
            reference._widen_logs_table(plan.query, sorted(plan.fields))
            assert [evidence.get(3, row_id) for (row_id,) in compact.db_connection.execute(plan.ids_query)] == list(
                reference._iter_select_query(plan.query))
        assert compact.db_connection.execute('SELECT "Cmd Field", Extra FROM logs WHERE row_id=4').fetchone() == (None, None)
        assert compact.db_connection.execute('SELECT "Cmd Field" FROM logs WHERE row_id=7').fetchone() == ("Needle",)
        for part, identity in [(3, 3), (2, 1), (3, 80)]:
            with pytest.raises(KeyError):
                evidence.get(part, identity)


def test_evidence_write_failure_rolls_back_only_its_projected_block(tmp_path, monkeypatch):
    monkeypatch.setattr(bench, "BLOCK_ROWS", 2)
    plans = bench.statements([rule("SELECT * FROM logs WHERE EventID=1", ["EventID"])])
    with closing(sqlite3.connect(":memory:")) as source, closing(ZircoliteCore(bench.CONFIG)) as core:
        source_rows(source)
        db = core.db_connection
        evidence = bench.Evidence(db, tmp_path, 16 * bench.MIB)
        db.execute("CREATE TRIGGER evidence.fail BEFORE INSERT ON blocks WHEN new.first_id > 2 BEGIN "
                   "SELECT RAISE(ABORT, 'failed evidence insert'); END")
        with pytest.raises(sqlite3.IntegrityError, match="failed evidence insert"):
            bench.project(source, core, plans, evidence)
        assert [row[0] for row in db.execute("SELECT row_id FROM logs")] == [1, 2]
        assert [event["row_id"] for event in evidence.events(0)] == [1, 2]
        assert evidence.get(0, 2)["row_id"] == 2


def test_refuses_insufficient_disk_and_oversized_event(tmp_path, monkeypatch):
    with closing(sqlite3.connect(":memory:")) as source, closing(ZircoliteCore(bench.CONFIG)) as core:
        with pytest.raises(ValueError, match="budget"):
            bench.cap_disk(source, "main", tmp_path / "data", 0)
        source_rows(source)
        evidence = bench.Evidence(core.db_connection, tmp_path, 16 * bench.MIB)
        monkeypatch.setattr(bench, "BLOCK_BYTES", 16)
        plans = bench.statements([rule("SELECT * FROM logs WHERE EventID=1", ["EventID"])])
        with pytest.raises(bench.Ineligible, match="exceeds"):
            bench.project(source, core, plans, evidence)
        assert list(evidence.events(0)) == []


def test_sqlite_checks_declared_read_set_and_rejects_extra_read():
    from dataclasses import replace

    sql = "SELECT * FROM logs WHERE Channel='abc' AND NOT COALESCE((Image=ParentImage), 0)"
    plan, = bench.statements([rule(sql, ["Channel", "Image", "ParentImage"])])
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, Channel TEXT, Image TEXT, ParentImage TEXT)")
        bench.verify_reads(connection, plan)
        with pytest.raises(bench.Ineligible, match="read set"):
            bench.verify_reads(connection, replace(plan, fields=frozenset({"channel", "image"})))


def test_unbounded_or_and_unknown_channel_types_preserve_predicate_fields(tmp_path):
    plans = bench.statements([
        rule("SELECT * FROM logs WHERE Channel='abc' OR Extra=7", ["Channel", "Extra"]),
        rule("SELECT * FROM logs WHERE EventID=1 AND NOT COALESCE((Image=ParentImage), 0)",
             ["EventID", "Image", "ParentImage"]),
    ])
    with closing(sqlite3.connect(":memory:")) as source, closing(ZircoliteCore(bench.CONFIG)) as core:
        source.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, Channel, EventID, Image, ParentImage, Extra)")
        source.executemany("INSERT INTO logs VALUES(?,?,?,?,?,?)", [
            (1, "abc", 1, "A", "A", 0), (2, "other", 2, None, None, 7),
            (4, b"unknown", 1, "A", None, 7), (5, "a" * 512, "1", "A", "B", 7),
        ])
        evidence = bench.Evidence(core.db_connection, tmp_path, 16 * bench.MIB)
        bench.project(source, core, plans, evidence)
        for plan in plans:
            assert list(core.db_connection.execute(plan.ids_query)) == list(source.execute(plan.ids_query))


@pytest.mark.parametrize(("detector", "matches"), [("sql", 2), ("auto", 1)])
def test_benchmark_entry_point_verifies_a_real_evtx_match(tmp_path, detector, matches):
    import subprocess
    import sys

    import orjson

    ruleset = tmp_path / "rules.json"
    overlapping = rule("SELECT * FROM logs WHERE EventID=1", ["EventID"])
    overlapping.update(id="overlap", rule=overlapping["rule"] * 2)
    absent = rule("SELECT * FROM logs WHERE EventID=9", ["EventID"]) | {"id": "absent"}
    ruleset.write_bytes(orjson.dumps([overlapping, absent]))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    result = subprocess.run([
        sys.executable, bench.__file__, "--events", str(bench.ROOT / "tests/fixtures/sample_bitsadmin.evtx"),
        "--ruleset", str(ruleset), "--scratch-dir", str(scratch),
        *(["--detector", "sql"] if detector == "sql" else []),
    ], capture_output=True, check=True, timeout=30)
    report = orjson.loads(result.stdout)
    assert report["detector"] == detector
    assert report["stage"]["events"] == 1
    reference, compact = (report["runs"][0][mode] for mode in ("reference", "compact"))
    assert compact["matches"] == reference["matches"] == matches
    signature = "by_rule_digest" if detector == "auto" else "by_statement_digest"
    assert compact[signature] == reference[signature]
    assert compact["diagnostics"] == reference["diagnostics"]
    if detector == "auto":
        assert compact["matched_rules"] == 1
        assert compact["diagnostics"]["pruned_rules"] == 1
        assert compact["prefilter"][0]["requested"] == "auto"
    assert compact["all_events"] == reference["all_events"]
    assert compact["evidence_bytes"] > 0 and compact["worker_peak_rss_bytes"] > 0
    assert list(scratch.iterdir()) == []


def test_parts_can_reuse_the_same_committed_row_id(tmp_path):
    plans = bench.statements([rule("SELECT * FROM logs WHERE EventID=1", ["EventID"])])
    for part, value in [(0, "first"), (1, "second")]:
        with closing(sqlite3.connect(":memory:")) as source, closing(ZircoliteCore(bench.CONFIG)) as compact:
            source.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, EventID INTEGER, Payload TEXT)")
            source.execute("INSERT INTO logs VALUES(1, 1, ?)", (value,))
            evidence = bench.Evidence(compact.db_connection, tmp_path, 16 * bench.MIB)
            bench.project(source, compact, plans, evidence, part=part)
    with closing(sqlite3.connect(":memory:")) as reader:
        evidence = bench.Evidence(reader, tmp_path, 16 * bench.MIB)
        assert evidence.get(0, 1)["Payload"] == "first"
        assert evidence.get(1, 1)["Payload"] == "second"
        assert list(evidence.events(1)) == [evidence.get(1, 1)]


def test_decimal_text_bounds_leave_final_affinity_to_sqlite(tmp_path):
    plans = bench.statements([rule("SELECT * FROM logs WHERE EventID IN ('01', 1) AND User='u'", ["EventID", "User"])])
    with closing(sqlite3.connect(":memory:")) as source, closing(ZircoliteCore(bench.CONFIG)) as compact:
        source.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, EventID TEXT COLLATE NOCASE, User TEXT)")
        source.executemany("INSERT INTO logs VALUES(?,?,'u')", [(1, "01"), (2, "1"), (3, "2"), (4, "1e0")])
        evidence = bench.Evidence(compact.db_connection, tmp_path, 16 * bench.MIB)
        bench.project(source, compact, plans, evidence)
        assert list(compact.db_connection.execute(plans[0].ids_query)) == list(source.execute(plans[0].ids_query)) == [(1,), (2,)]
        assert list(compact.db_connection.execute("SELECT User FROM logs ORDER BY row_id")) == [("u",), ("u",), (None,), ("u",)]
