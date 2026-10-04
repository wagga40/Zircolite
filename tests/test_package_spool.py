"""Stage one of a package: a working database's events copied to the spool."""

from datetime import datetime, timezone

import orjson
import pytest

from tests.package_fixtures import make_logs, read_spool
from zircolite import package_spool
from zircolite.package_spool import PackageError, PackageSpool, time_microseconds
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
