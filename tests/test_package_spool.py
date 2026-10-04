"""Stage one of a package: a working database's events copied to the spool."""

import pickle
from datetime import datetime, timezone

import orjson
import pytest

from tests.package_fixtures import make_logs, read_spool
from zircolite import package_spool
from zircolite.package_spool import (
    PackageError,
    PackageSpool,
    PartRecord,
    rule_index,
    rule_key,
    time_microseconds,
)
from zircolite.results import RowSpool
from zircolite.spellings import record_spellings


def us(text: str) -> int:
    moment = datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
    return int(moment.timestamp()) * 1_000_000 + moment.microsecond


@pytest.fixture
def spool(tmp_path):
    return PackageSpool(directory=str(tmp_path), time_field="SystemTime")


def export(spool, rows, part=0, **options):
    writer = spool.open_part(part, ["input.evtx"])
    writer.export_events(make_logs(rows, **options))
    return writer.record


class TestEvents:
    def test_every_row_is_spooled_with_its_identity(self, spool):
        record = export(spool, [{"Computer": "a", "EventID": "1"}, {"Computer": "b"}, {"EventID": "3"}], part=5)

        rows = read_spool(record.event_files)
        assert [row["_zl_rid"] for row in rows] == [1, 2, 3]
        assert {row["_zl_part"] for row in rows} == {5}
        assert rows[0]["computer"] == "a" and rows[0]["eventid"] == "1"
        assert "computer" not in rows[2]
        assert record.events == 3

    def test_census_types_and_counts_each_column(self, spool):
        record = export(spool, [{"Num": 6, "Real": 1.5}, {"Num": "six", "Real": 2.5}],
                        types={"Num": "", "Real": ""})

        by_key = {column["key"]: column for column in record.columns}
        assert by_key["num"]["mask"] == 1 | 4
        assert by_key["real"]["mask"] == 2
        assert by_key["num"]["count"] == 2

    def test_a_column_that_is_always_null_is_left_out(self, spool):
        record = export(spool, [{"Computer": "a"}], columns=["Computer", "Empty"])

        assert [column["key"] for column in record.columns] == ["computer"]

    def test_blob_values_are_written_as_hex(self, spool):
        record = export(spool, [{"Raw": b"\x01\xff"}], types={"Raw": ""})

        assert read_spool(record.event_files)[0]["raw"] == "01ff"
        assert record.columns[0]["mask"] == 8

    def test_spool_files_are_cut_every_n_rows(self, spool, monkeypatch):
        monkeypatch.setattr(package_spool, "ROWS_PER_SPOOL_FILE", 2)

        record = export(spool, [{"N": str(i)} for i in range(5)])

        assert len(record.event_files) == 3
        assert [row["n"] for row in read_spool(record.event_files)] == ["0", "1", "2", "3", "4"]

    def test_family_columns_follow_channel_and_eventid(self, spool):
        record = export(spool, [
            {"Channel": "Security", "EventID": "4624", "TargetUserName": "bob"},
            {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": "1", "Image": "x.exe"},
        ])

        families = {(f["channel"], f["eventid"]): f["keys"] for f in record.families}
        assert families[("Security", "4624")] == ["channel", "eventid", "targetusername"]
        assert families[("Microsoft-Windows-Sysmon/Operational", "1")] == ["channel", "eventid", "image"]

    def test_row_spellings_travel_with_their_row(self, spool):
        connection = make_logs([{"ProcessId": "1"}, {"ProcessId": "2"}])
        record_spellings(connection.cursor(), 2, [(0, ("ProcessID",))])
        writer = spool.open_part(0, ["x"])

        writer.export_events(connection)

        rows = read_spool(writer.record.event_files)
        assert "_zl_spelling" not in rows[0]
        assert orjson.loads(rows[1]["_zl_spelling"]) == ["ProcessID"]


class TestTime:
    def test_time_is_read_as_the_time_filter_reads_it(self, spool):
        record = export(spool, [
            {"SystemTime": "2021-06-03T06:36:55.9282437Z"},
            {"SystemTime": "not a time"},
            {"Computer": "no time"},
        ])

        rows = read_spool(record.event_files)
        assert rows[0]["_zl_time"] == us("2021-06-03T06:36:55.928243")
        assert rows[1]["_zl_time"] is None and rows[2]["_zl_time"] is None
        assert record.time == {"column": "SystemTime", "min": rows[0]["_zl_time"],
                               "max": rows[0]["_zl_time"], "unparsed": 1, "missing": 1}

    def test_time_field_matches_case_insensitively(self, tmp_path):
        spool = PackageSpool(directory=str(tmp_path), time_field="systemtime")
        record = export(spool, [{"SystemTime": "2021-06-03T06:36:55Z"}])

        assert record.time["column"] == "SystemTime"

    @pytest.mark.parametrize(("value", "fmt", "expected"), [
        ("1622700000123", "unix_ms", 1622700000123000),
        (1622700000, "unix", 1622700000000000),
        ("1622700000.5", "unix", 1622700000500000),
        (1622700000123456, "unix_us", 1622700000123456),
        ("soon", "unix", None),
        (float("inf"), "unix", None),
        (True, "unix", None),
        ("1622700000", "iso", 1622700000000000),
    ])
    def test_explicit_timestamp_formats(self, value, fmt, expected):
        assert time_microseconds(value, fmt) == expected

    def test_an_unknown_format_is_refused(self):
        with pytest.raises(PackageError):
            time_microseconds("1", "fortnights")


class TestRefusals:
    def test_a_field_using_the_reserved_prefix_is_refused(self, spool):
        with pytest.raises(PackageError, match="_ZL_time"):
            export(spool, [{"_ZL_time": "x"}])

    def test_a_row_id_the_viewer_cannot_address_is_refused(self, spool):
        connection = make_logs([{"A": "x"}])
        connection.execute("INSERT INTO logs (row_id, A) VALUES (?, 'y')", (1 << 32,))

        with pytest.raises(PackageError, match="row_id"):
            spool.open_part(0, ["x"]).export_events(connection)

    def test_a_part_number_out_of_range_is_refused(self, spool):
        with pytest.raises(PackageError):
            spool.open_part(1 << 21, ["x"])

    def test_undecodable_text_names_the_row(self, spool):
        connection = make_logs([{"A": "fine"}])
        connection.execute("INSERT INTO logs (A) VALUES (CAST(X'80' AS TEXT))")

        with pytest.raises(PackageError, match="row 2"):
            spool.open_part(0, ["x"]).export_events(connection)

    def test_the_failing_row_is_found_inside_a_larger_batch(self, spool):
        connection = make_logs([{"A": str(i)} for i in range(10)])
        connection.execute("INSERT INTO logs (A) VALUES (CAST(X'80' AS TEXT))")
        connection.execute("INSERT INTO logs (A) VALUES ('after')")

        with pytest.raises(PackageError, match="row 11"):
            spool.open_part(0, ["x"]).export_events(connection)

    def test_a_broken_spelling_table_is_a_package_error(self, spool):
        connection = make_logs([{"A": "x"}])
        connection.execute("CREATE TABLE logs_spelling (row_id INTEGER, spelling INTEGER)")
        connection.execute("CREATE TABLE field_spellings (wrong TEXT)")
        writer = spool.open_part(0, ["x"])

        with pytest.raises(PackageError):
            writer.export_events(connection)

        assert writer.record.event_files == []

    def test_a_write_failure_is_a_package_error_and_keeps_the_file_list(self, spool, monkeypatch):
        added = package_spool._SpoolFiles.add

        def failing(self, line):
            added(self, line)
            raise OSError("disk full")

        monkeypatch.setattr(package_spool._SpoolFiles, "add", failing)
        writer = spool.open_part(0, ["x"])

        with pytest.raises(PackageError, match="disk full"):
            writer.export_events(make_logs([{"A": "x"}]))

        assert len(writer.record.event_files) == 1


RULES = [{"id": "r-1", "title": "One"}, {"title": "Two"}, {"id": "r-1", "title": "Duplicate id"}]


@pytest.fixture
def hit_spool(tmp_path):
    return PackageSpool(directory=str(tmp_path), time_field="SystemTime", rule_keys=rule_index(RULES))


def hits_of(record):
    with open(record.hits_file, encoding="utf-8") as handle:
        return [tuple(int(v) for v in line.split(",")) for line in handle]


def alerts_of(record):
    with open(record.alerts_file, "rb") as handle:
        return [orjson.loads(line) for line in handle]


class TestRuleIndex:
    def test_first_rule_wins_a_shared_key_and_title_stands_in_for_id(self):
        assert rule_index(RULES) == {"r-1": 0, "Two": 1}

    def test_a_result_and_its_rule_share_a_key(self):
        assert rule_key({"id": "", "title": "Two"}) == rule_key(RULES[1]) == "Two"
        assert rule_key({}) == "Unnamed Rule"


class TestHits:
    def test_hits_are_recorded_per_rule(self, hit_spool):
        writer = hit_spool.open_part(3, ["x"])
        writer.sink({"id": "r-1", "title": "One", "count": 2, "matches": [{"row_id": 4}, {"row_id": 9}]})

        record = writer.finish()

        assert hits_of(record) == [(0, 3, 4), (0, 3, 9)]
        assert record.rules[0] == {"count": 2, "linked": 2, "unlinked": 0, "alert_count": 0, "event_count": 0}

    def test_spooled_matches_are_read(self, hit_spool):
        matches = RowSpool()
        matches.append({"row_id": 7, "Computer": "a"})
        writer = hit_spool.open_part(0, ["x"])
        writer.sink({"title": "Two", "count": 1, "matches": matches})
        matches.close()

        assert hits_of(writer.finish()) == [(1, 0, 7)]

    def test_a_match_without_a_row_id_is_unlinked(self, hit_spool):
        writer = hit_spool.open_part(0, ["x"])
        writer.sink({"title": "Two", "count": 1, "matches": [{"COUNT(*)": 12}]})

        record = writer.finish()

        assert record.hits_file is None
        assert record.rules[1]["unlinked"] == 1

    def test_csv_sanitised_rows_still_link(self, hit_spool):
        writer = hit_spool.open_part(0, ["x"])
        writer.sink({"title": "Two", "count": "1", "matches": [{"row_id": "7"}]})
        writer.sink({"id": "r-1", "title": "One", "result_type": "correlation", "count": 1, "alert_count": 1,
                     "event_count": 1, "matches": [{
                         "alert_id": "a1", "event_ids": '["0:4"]',
                         "evidence": '[{"event_id": "0:4", "source_table": "logs", "event": {}}]',
                         "group_keys": '{"Host": "h"}', "occurrence_time": "1622700000.5"}]})

        record = writer.finish()

        assert sorted(hits_of(record)) == [(0, 0, 4), (1, 0, 7)]
        assert alerts_of(record)[0]["occurrence_us"] == 1622700000500000

    def test_rules_unknown_to_the_run_fail_at_finish(self, hit_spool):
        writer = hit_spool.open_part(0, ["x"])
        writer.sink({"title": "Never loaded", "count": 1, "matches": [{"row_id": 1}]})

        with pytest.raises(PackageError, match="Never loaded"):
            writer.finish()


class TestCorrelations:
    def alert(self, table="logs"):
        return {"alert_id": "a1", "group_keys": {"Host": "h"}, "occurrence_time": 1622700000,
                "window_start": 1622699000, "window_end": 1622700000, "metric_name": "event_count",
                "metric_value": 2, "event_count": 2, "event_ids": ["0:4", "0:9"], "child_alert_ids": [],
                "evidence": [{"event_id": "0:4", "source_table": table, "event": {}},
                             {"event_id": "0:9", "source_table": table, "event": {}}]}

    def test_an_alert_links_its_evidence(self, hit_spool):
        writer = hit_spool.open_part(2, ["x"])
        writer.sink({"id": "r-1", "title": "One", "result_type": "correlation", "count": 1,
                     "alert_count": 1, "event_count": 2, "matches": [self.alert()]})

        record = writer.finish()

        assert hits_of(record) == [(0, 2, 4), (0, 2, 9)]
        alert = alerts_of(record)[0]
        assert alert["rids"] == [4, 9]
        assert orjson.loads(alert["group_keys"]) == {"Host": "h"}
        assert alert["occurrence_us"] == 1622700000000000
        assert record.rules[0]["alert_count"] == 1 and record.rules[0]["event_count"] == 2

    def test_evidence_from_another_table_fails(self, hit_spool):
        writer = hit_spool.open_part(0, ["x"])
        writer.sink({"id": "r-1", "title": "One", "result_type": "correlation", "count": 1,
                     "matches": [self.alert(table="other")]})

        with pytest.raises(PackageError, match="logs"):
            writer.finish()


class _FailingHandle:
    def __init__(self):
        self.closed = False

    def write(self, data):
        return len(data)

    def close(self):
        self.closed = True
        raise OSError("No space left on device")


class TestCloseFailures:
    def test_a_failing_close_is_a_package_error_and_closes_the_other_file(self, hit_spool):
        writer = hit_spool.open_part(0, ["x"])
        writer.sink({"title": "Two", "count": 1, "matches": [{"row_id": 1}]})
        real_hits = writer._hits
        failing = _FailingHandle()
        writer._hits = failing
        writer._alerts = other = open(writer.spool.directory + "/other", "wb")

        with pytest.raises(PackageError, match="No space left") as raised:
            writer.finish()

        assert isinstance(raised.value.__cause__, OSError)
        assert failing.closed and other.closed
        assert writer._hits is None and writer._alerts is None
        real_hits.close()

    def test_discard_removes_every_file_when_a_close_fails(self, hit_spool, tmp_path):
        writer = hit_spool.open_part(0, ["x"])
        writer.export_events(make_logs([{"A": "1"}]))
        writer.sink({"title": "Two", "count": 1, "matches": [{"row_id": 1}]})
        real_hits = writer._hits
        writer._hits = _FailingHandle()

        writer.discard()
        real_hits.close()

        assert list(tmp_path.iterdir()) == []


class TestLifecycle:
    def test_discard_removes_every_file(self, hit_spool, tmp_path):
        writer = hit_spool.open_part(0, ["x"])
        writer.export_events(make_logs([{"A": "1"}]))
        writer.sink({"title": "Two", "count": 1, "matches": [{"row_id": 1}]})

        writer.discard()

        assert list(tmp_path.iterdir()) == []

    def test_spool_and_record_survive_pickling(self, hit_spool):
        record = PartRecord(part=1, sources=["x", "y"], unreadable=["y"], rules={0: {"count": 1}})

        assert pickle.loads(pickle.dumps(hit_spool)) == hit_spool  # noqa: S301 -- round-trips our own objects
        assert pickle.loads(pickle.dumps(record)) == record  # noqa: S301 -- round-trips our own objects
