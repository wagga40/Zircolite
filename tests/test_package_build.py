"""Stage two of a package: spooled parts become Parquet tables and a manifest."""

import duckdb
import pytest

from tests.package_fixtures import make_logs, parquet_rows
from zircolite import package
from zircolite.package import (
    PACKAGE_FORMAT,
    PackageBuilder,
    RunInfo,
    check_duckdb,
    merge_columns,
    sql_identifier,
    sql_string,
)
from zircolite.package_spool import PackageError, PackageSpool, rule_index

RULES = [
    {"id": "r-0", "title": "Encoded PowerShell", "level": "high", "description": "d",
     "tags": ["attack.execution", "attack.t1059.001"], "falsepositives": "Admins", "filename": "a.yml"},
    {"id": "r-1", "title": "Brute force", "level": "medium", "tags": ["attack.credential-access"],
     "correlation_plan": {"version": 2}},
]
RUN = RunInfo(zircolite_version="9.9.9", mode="per-file", executor="sequential", timestamp_format="iso",
              after="1970-01-01T00:00:00", before="9999-12-12T23:59:59", limit=-1, rules_loaded=2)


@pytest.fixture
def spool(tmp_path):
    return PackageSpool(directory=str(tmp_path / "spool"), time_field="SystemTime", rule_keys=rule_index(RULES))


@pytest.fixture(autouse=True)
def spool_dir(spool):
    import pathlib
    pathlib.Path(spool.directory).mkdir()


def part(spool, number, rows, results=(), **options):
    writer = spool.open_part(number, [f"file{number}.evtx"])
    writer.export_events(make_logs(rows, **options))
    for result in results:
        writer.sink(result)
    return writer.finish()


def build(spool, parts, failed=()):
    return PackageBuilder(spool).build_data(parts=parts, rulesets=RULES, run=RUN, failed_sources=list(failed))


def table(data, name, tmp_path, sql="SELECT * FROM t"):
    return parquet_rows(data.tables[name].read_bytes(), tmp_path, sql)


class TestDuckdb:
    def test_this_build_has_what_packages_need(self):
        check_duckdb()

    def test_a_missing_extension_is_refused(self, monkeypatch):
        monkeypatch.setattr(package, "REQUIRED_EXTENSIONS", ("json", "no_such_extension"))

        with pytest.raises(PackageError, match="no_such_extension"):
            check_duckdb()

    @pytest.mark.parametrize("text", ["plain", "it's", "back\\slash", 'dou"ble', "semi;colon -- x", "Ä ä 😀"])
    def test_literals_and_identifiers_round_trip(self, text):
        connection = duckdb.connect()
        assert connection.execute(f"SELECT {sql_string(text)} AS {sql_identifier(text)}").fetchone()[0] == text
        assert connection.execute(f"SELECT {sql_string(text)} AS {sql_identifier(text)}").description[0][0] == text


class TestEvents:
    def test_events_round_trip_with_their_identity_and_time(self, spool, tmp_path):
        parts = [
            part(spool, 0, [{"SystemTime": "2021-06-03T06:36:55Z", "Computer": "a"}]),
            part(spool, 7, [{"SystemTime": "2021-06-03T06:36:56Z", "Computer": "b"}, {"Computer": "c"}]),
        ]

        data = build(spool, parts)

        columns, rows = table(data, "events", tmp_path, "SELECT _zl_uid, _zl_part, _zl_time, Computer FROM t ORDER BY _zl_uid")
        assert [row[0] for row in rows] == [1, (7 << 32) + 1, (7 << 32) + 2]
        assert [row[3] for row in rows] == ["a", "b", "c"]
        assert str(rows[0][2]) == "2021-06-03 06:36:55" and rows[2][2] is None
        assert data.manifest["totals"]["events"] == 3

    def test_column_types_follow_what_the_values_were(self, spool, tmp_path):
        parts = [part(spool, 0, [{"Num": 6, "Mixed": 6, "Real": 1.5, "Big": 9007199254740993},
                                 {"Num": 7, "Mixed": "six", "Real": 2.5, "Big": 1}],
                      types={"Num": "", "Mixed": "", "Real": "", "Big": ""})]

        data = build(spool, parts)

        _, described = table(data, "events", tmp_path, "SELECT column_name, column_type FROM (DESCRIBE t)")
        types = dict(described)
        assert (types["Num"], types["Mixed"], types["Real"], types["Big"]) == ("BIGINT", "VARCHAR", "DOUBLE", "BIGINT")
        _, rows = table(data, "events", tmp_path, "SELECT Mixed, Big FROM t ORDER BY _zl_uid")
        assert rows == [("6", 9007199254740993), ("six", 1)]

    def test_canonical_name_is_the_lowest_parts_spelling_and_parts_keep_theirs(self, spool, tmp_path):
        parts = [part(spool, 1, [{"ProcessID": "2"}]), part(spool, 0, [{"ProcessId": "1"}])]

        data = build(spool, parts)

        columns, rows = table(data, "events", tmp_path, "SELECT * EXCLUDE (_zl_uid, _zl_part, _zl_time, _zl_spelling) FROM t ORDER BY _zl_uid")
        assert columns == ["ProcessId"] and rows == [("1",), ("2",)]
        spellings = {p["part"]: p["spellings"] for p in data.manifest["parts"]}
        assert spellings == {0: {}, 1: {"processid": "ProcessID"}}

    def test_the_time_column_takes_the_time_field_name(self, spool, tmp_path):
        data = build(spool, [part(spool, 0, [{"systemtime": "2021-06-03T06:36:55Z"}])])

        assert [c["name"] for c in data.manifest["columns"]] == ["SystemTime"]
        assert data.manifest["parts"][0]["spellings"] == {}

    def test_hostile_column_names_survive(self, spool, tmp_path):
        names = ["it's", 'dou"ble', "back\\slash", "semi;colon", "with space", "Ä", "ä"]
        data = build(spool, [part(spool, 0, [dict.fromkeys(names, "v")])])

        columns, _ = table(data, "events", tmp_path)
        assert columns[4:] == names

    def test_empty_run_builds_empty_tables(self, spool, tmp_path):
        data = build(spool, [])

        for name in package.DATA_TABLES:
            assert table(data, name, tmp_path, "SELECT count(*) FROM t")[1] == [(0,)]
        assert table(data, "events", tmp_path)[0] == ["_zl_uid", "_zl_part", "_zl_time", "_zl_spelling"]
        assert data.manifest["totals"] == {"events": 0, "parts": 0, "rules_matched": 0, "hits": 0, "alerts": 0}

    def test_too_many_events_for_a_browser_is_refused(self, spool, monkeypatch):
        monkeypatch.setattr(package, "EVENTS_PARQUET_LIMIT", 10)

        with pytest.raises(PackageError, match="--after"):
            build(spool, [part(spool, 0, [{"A": "x"}])])


class TestDetections:
    def test_rules_hits_and_alerts(self, spool, tmp_path):
        alert = {"alert_id": "a1", "group_keys": {"Host": "h"}, "occurrence_time": 1622700000,
                 "window_start": 1622699000, "window_end": 1622700000, "metric_name": "event_count",
                 "metric_value": 2, "event_count": 2, "event_ids": ["0:1", "0:2"], "child_alert_ids": [],
                 "evidence": [{"event_id": "0:1", "source_table": "logs", "event": {}},
                              {"event_id": "0:2", "source_table": "logs", "event": {}}]}
        parts = [
            part(spool, 0, [{"A": "1"}, {"A": "2"}], results=[
                {"id": "r-0", "title": "Encoded PowerShell", "count": 2, "matches": [{"row_id": 1}, {"row_id": 1}]},
                {"id": "r-1", "title": "Brute force", "result_type": "correlation", "count": 1,
                 "alert_count": 1, "event_count": 2, "matches": [alert]},
            ]),
            part(spool, 1, [{"A": "3"}], results=[
                {"id": "r-0", "title": "Encoded PowerShell", "count": 1, "matches": [{"row_id": 1}, {"X": 1}]},
            ]),
        ]

        data = build(spool, parts)

        _, rules = table(data, "rules", tmp_path, "SELECT rule_idx, level_rank, falsepositives, tactics, techniques, result_type, count, linked, unlinked FROM t ORDER BY rule_idx")
        assert rules == [
            (0, 3, ["Admins"], ["execution"], ["T1059.001"], "match", 3, 3, 1),
            (1, 2, [], ["credential-access"], [], "correlation", 1, 0, 0),
        ]
        _, hits = table(data, "hits", tmp_path, "SELECT * FROM t")
        assert hits == [(0, 1), (0, (1 << 32) + 1), (1, 1), (1, 2)]
        _, alerts = table(data, "alerts", tmp_path, "SELECT alert_idx, rule_idx, alert_id, group_keys, event_count FROM t")
        assert alerts == [(0, 1, "a1", '{"Host":"h"}', 2)]
        _, links = table(data, "alert_events", tmp_path, "SELECT * FROM t")
        assert links == [(0, 1, 1), (0, 2, 2)]
        assert data.manifest["totals"] == {"events": 3, "parts": 2, "rules_matched": 2, "hits": 4, "alerts": 1}


class TestManifest:
    def test_families_columns_and_warnings(self, spool):
        parts = [
            part(spool, 0, [{"Channel": "Security", "EventID": "4624", "TargetUserName": "bob",
                             "SystemTime": "bad"}],
                 results=[{"id": "r-0", "title": "Encoded PowerShell", "count": 1, "matches": [{"N": 1}]}]),
            part(spool, 1, [{"Channel": "Security", "EventID": "4624", "IpAddress": "1.2.3.4"}]),
        ]

        manifest = build(spool, parts, failed=["broken.evtx"]).manifest

        assert manifest["format"] == PACKAGE_FORMAT and manifest["zircolite"] == "9.9.9"
        assert manifest["families"] == [{"channel": "Security", "eventid": "4624",
                                         "columns": ["Channel", "EventID", "IpAddress", "SystemTime", "TargetUserName"]}]
        assert manifest["failed_sources"] == ["broken.evtx"]
        assert manifest["tactics"][6:8] == ["stealth", "defense-impairment"]
        warnings = " ".join(manifest["warnings"])
        assert "1 event(s) have a SystemTime value that is not a time" in warnings
        assert "1 input(s) have no SystemTime field" in warnings
        assert "1 match(es) from custom SQL rules" in warnings
        assert "1 input(s) failed to process" in warnings

    def test_merge_columns_ors_masks_and_sums_counts(self, spool):
        parts = [part(spool, 0, [{"N": 1}], types={"N": ""}), part(spool, 1, [{"n": "x"}, {"n": "y"}])]

        (column,) = merge_columns(parts, "SystemTime")

        assert (column.name, column.mask, column.count, column.sql_type) == ("N", 5, 3, "VARCHAR")
