"""Stage two of a package: spooled parts become Parquet tables and a manifest."""

import hashlib
import json
import zipfile

import duckdb
import pytest

from tests.package_fixtures import make_logs, parquet_rows, read_package
from zircolite import package
from zircolite.package import (
    CHUNK_BYTES,
    PACKAGE_FORMAT,
    PackageBuilder,
    RunInfo,
    Viewer,
    check_duckdb,
    find_viewer,
    merge_columns,
    sql_identifier,
    sql_string,
    write_package,
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


def part(spool, number, rows, results=(), *, sources=None, unreadable=(), **options):
    writer = spool.open_part(number, sources or [f"file{number}.evtx"], unreadable=unreadable)
    writer.export_events(make_logs(rows, **options))
    for result in results:
        writer.sink(result)
    return writer.finish()


def build(spool, parts, failed=(), rulesets=RULES, expected_events=None):
    if expected_events is None:
        expected_events = sum(record.events for record in parts)
    return PackageBuilder(spool).build_data(parts=parts, rulesets=rulesets, run=RUN, failed_sources=list(failed),
                                            expected_events=expected_events)


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

    def test_a_part_number_spooled_twice_is_refused(self, spool):
        parts = [part(spool, 0, [{"A": "1"}]), part(spool, 1, [{"A": "2"}]), part(spool, 1, [{"A": "3"}])]

        with pytest.raises(PackageError, match="part 1"):
            build(spool, parts)

    def test_a_package_that_misses_ingested_events_is_refused(self, spool):
        parts = [part(spool, 0, [{"A": "1"}, {"A": "2"}])]

        with pytest.raises(PackageError, match="2 events where the run ingested 3"):
            build(spool, parts, expected_events=3)

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


    def test_variants_sharing_an_id_keep_their_own_title_and_hits(self, spool, tmp_path):
        # rules_windows_merged.json ships most rules twice under one id, as "- Sysmon" and "- Generic".
        rulesets = [
            {"id": "b-1", "title": "BOINC - Sysmon", "level": "medium", "filename": "boinc.yml"},
            {"id": "b-1", "title": "BOINC - Generic", "level": "medium", "filename": "boinc.yml"},
            {"id": "c-1", "title": "Other", "level": "low"},
        ]
        variants = PackageSpool(directory=spool.directory, time_field="SystemTime", rule_keys=rule_index(rulesets))
        generic = {"id": "b-1", "title": "BOINC - Generic", "count": 1, "matches": [{"row_id": 2}]}
        parts = [part(variants, 0, [{"A": "1"}, {"A": "2"}], results=[generic])]

        data = build(variants, parts, rulesets=rulesets)

        _, rules = table(data, "rules", tmp_path, "SELECT rule_idx, key, title, count FROM t")
        assert rules == [(1, "b-1", "BOINC - Generic", 1)]
        _, hits = table(data, "hits", tmp_path, "SELECT * FROM t")
        assert hits == [(1, 2)]
        assert data.manifest["totals"]["rules_matched"] == 1

    def test_rules_matched_counts_each_key_once(self, spool, tmp_path):
        rulesets = [{"id": "b-1", "title": "BOINC - Sysmon"}, {"id": "b-1", "title": "BOINC - Generic"},
                    {"id": "c-1", "title": "Other"}]
        variants = PackageSpool(directory=spool.directory, time_field="SystemTime", rule_keys=rule_index(rulesets))
        results = [{"id": "b-1", "title": "BOINC - Sysmon", "count": 1, "matches": [{"row_id": 1}]},
                   {"id": "b-1", "title": "BOINC - Generic", "count": 1, "matches": [{"row_id": 1}]},
                   {"id": "c-1", "title": "Other", "count": 1, "matches": [{"row_id": 1}]}]

        data = build(variants, [part(variants, 0, [{"A": "1"}], results=results)], rulesets=rulesets)

        _, rules = table(data, "rules", tmp_path, "SELECT rule_idx, key, title FROM t ORDER BY rule_idx")
        assert rules == [(0, "b-1", "BOINC - Sysmon"), (1, "b-1", "BOINC - Generic"), (2, "c-1", "Other")]
        assert data.manifest["totals"]["rules_matched"] == 2
        assert data.manifest["totals"]["hits"] == 3


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

    def test_events_without_a_time_are_warned_about_once(self, spool):
        parts = [
            part(spool, 0, [{"SystemTime": "2021-06-03T06:36:55Z"}, {"A": "x"}, {"A": "y"}]),
            part(spool, 1, [{"A": "z"}]),
        ]

        warnings = build(spool, parts).manifest["warnings"]

        assert "2 event(s) have no SystemTime value; they are kept but have no place on the timeline" in warnings
        assert "1 input(s) have no SystemTime field, so their events have no time: file1.evtx" in warnings
        assert len(warnings) == 2

    def test_inputs_read_in_part_mark_their_part_partial(self, spool):
        parts = [
            part(spool, 0, [{"A": "1"}]),
            part(spool, 1, [{"A": "2"}], sources=["b.json", "c.json", "d.json", "e.json"],
                 unreadable=["b.json", "c.json", "d.json", "e.json"]),
        ]

        manifest = build(spool, parts).manifest

        assert [(p["status"], p["unreadable"]) for p in manifest["parts"]] == [
            ("complete", []), ("partial", ["b.json", "c.json", "d.json", "e.json"])]
        assert manifest["failed_sources"] == []
        assert ("4 input(s) could be read only in part or not at all: b.json, c.json, d.json ..."
                in manifest["warnings"])

    def test_merge_columns_ors_masks_and_sums_counts(self, spool):
        parts = [part(spool, 0, [{"N": 1}], types={"N": ""}), part(spool, 1, [{"n": "x"}, {"n": "y"}])]

        (column,) = merge_columns(parts, "SystemTime")

        assert (column.name, column.mask, column.count, column.sql_type) == ("N", 5, 3, "VARCHAR")


def fake_viewer(tmp_path, *, data_format=1, drop=None):
    directory = tmp_path / "gui" / "viewer"
    directory.mkdir(parents=True)
    copy, wrap = ["index.html", "app.js"], ["engine.wasm.gz"]
    for name in copy + wrap:
        if name != drop:
            (directory / name).write_bytes(name.encode() * 3)
    (directory / "viewer.json").write_text(json.dumps(
        {"data_format": data_format, "version": "0.0.1", "copy": copy, "wrap": wrap}), encoding="utf-8")
    return directory


class TestFindViewer:
    def test_the_shipped_viewer_is_complete(self):
        viewer = find_viewer()

        assert "index.html" in viewer.copy
        assert viewer.wrap == ("duckdb-eh.wasm.gz", "duckdb-browser-eh.worker.js", "parquet.duckdb_extension.wasm")

    def test_a_missing_file_is_refused(self, tmp_path, monkeypatch):
        directory = fake_viewer(tmp_path, drop="app.js")
        monkeypatch.setattr(package, "bundled_asset", lambda *parts: directory / parts[-1])

        with pytest.raises(PackageError, match=r"app\.js"):
            find_viewer()

    def test_another_package_format_is_refused(self, tmp_path, monkeypatch):
        directory = fake_viewer(tmp_path, data_format=99)
        monkeypatch.setattr(package, "bundled_asset", lambda *parts: directory / parts[-1])

        with pytest.raises(PackageError, match="format 99"):
            find_viewer()


class TestZip:
    def data(self, spool):
        return build(spool, [part(spool, 0, [{"Computer": "a"}, {"Computer": "b"}])])

    def viewer(self, tmp_path):
        directory = fake_viewer(tmp_path)
        return Viewer(directory, "0.0.1", ("index.html", "app.js"), ("engine.wasm.gz",))

    def test_every_file_reassembles_and_matches_its_digest(self, spool, tmp_path, monkeypatch):
        monkeypatch.setattr(package, "CHUNK_BYTES", 6)
        destination = tmp_path / "out"
        destination.mkdir()

        target = write_package(self.viewer(tmp_path), self.data(spool), destination, tmp_path)

        manifest, files = read_package(target)
        assert [entry["name"] for entry in manifest["files"]] == [
            "engine.wasm.gz", *(f"{t}.parquet" for t in package.DATA_TABLES), "text.parquet"]
        assert [entry["kind"] for entry in manifest["files"]][-1] == "index"
        for entry in manifest["files"]:
            assert hashlib.sha256(files[entry["name"]]).hexdigest() == entry["sha256"]
            assert len(files[entry["name"]]) == entry["bytes"]
        assert len(manifest["files"][0]["chunks"]) == 7  # 42 bytes in 6-byte chunks
        with zipfile.ZipFile(target) as archive:
            names = set(archive.namelist())
        assert {"index.html", "app.js", "README.txt", "data/manifest.js"} <= names
        assert manifest["totals"]["events"] == 2
        assert manifest["viewer"] == "0.0.1"

    def test_chunk_size_keeps_base64_unpadded_until_the_end(self):
        assert CHUNK_BYTES % 3 == 0

    def test_an_existing_package_is_never_overwritten(self, spool, tmp_path, monkeypatch):
        destination = tmp_path / "out"
        destination.mkdir()
        (destination / "zircolite-package-AAAA.zip").write_bytes(b"keep")
        suffixes = iter(["AAAA", "BBBB"])
        monkeypatch.setattr(package, "random_suffix", lambda length=4: next(suffixes))

        target = write_package(self.viewer(tmp_path), self.data(spool), destination, tmp_path)

        assert target.name == "zircolite-package-BBBB.zip"
        assert (destination / "zircolite-package-AAAA.zip").read_bytes() == b"keep"

    def test_a_failed_write_leaves_no_package(self, spool, tmp_path, monkeypatch):
        destination = tmp_path / "out"
        destination.mkdir()

        def broken(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(package, "_wrap", broken)
        with pytest.raises(OSError):
            write_package(self.viewer(tmp_path), self.data(spool), destination, tmp_path)

        assert list(destination.iterdir()) == []

    def test_build_writes_a_package_with_the_shipped_viewer(self, spool, tmp_path):
        destination = tmp_path / "out"
        destination.mkdir()
        builder = PackageBuilder(spool)

        target = builder.build(viewer=find_viewer(), parts=[part(spool, 0, [{"A": "1"}])], rulesets=RULES,
                               run=RUN, failed_sources=[], expected_events=1, destination=destination)

        manifest, files = read_package(target)
        assert {"duckdb-eh.wasm.gz", "parquet.duckdb_extension.wasm", "events.parquet"} <= set(files)
        assert manifest["totals"]["events"] == 1
        assert manifest["viewer"] == find_viewer().version != ""


class TestTextIndex:
    def test_holds_each_events_values_lowercased_in_event_order(self, spool, tmp_path):
        parts = [part(spool, 0, [{"Computer": "DC01", "CommandLine": "PowerShell -Enc AAA"}, {"Computer": "ws02"}]),
                 part(spool, 3, [{"EventID": 4624}])]

        data = build(spool, parts)

        _, rows = table(data, "text", tmp_path, "SELECT _zl_uid, _zl_text FROM t")
        assert [row[0] for row in rows] == [1, 2, (3 << 32) + 1]
        # chr(31) keeps a phrase from matching across two fields, as the viewer's scan does.
        assert sorted(rows[0][1].split("\x1f")) == ["dc01", "powershell -enc aaa"]
        assert rows[1][1] == "ws02"
        assert rows[2][1] == "4624"

    def test_is_left_out_with_a_warning_when_too_large(self, spool, tmp_path, monkeypatch):
        monkeypatch.setattr(package, "TEXT_PARQUET_LIMIT", 1)

        data = build(spool, [part(spool, 0, [{"Computer": "a"}])])

        assert "text" not in data.tables
        assert not (tmp_path / "spool" / "build" / "text.parquet").exists()
        assert any(warning.startswith("Full-text search reads every field of every event")
                   and "scans the events instead" in warning for warning in data.manifest["warnings"])
        directory = fake_viewer(tmp_path)
        viewer = Viewer(directory, "0.0.1", ("index.html", "app.js"), ("engine.wasm.gz",))
        destination = tmp_path / "out"
        destination.mkdir()
        target = write_package(viewer, data, destination, tmp_path)
        manifest, _ = read_package(target)
        assert "text.parquet" not in [entry["name"] for entry in manifest["files"]]
        with zipfile.ZipFile(target) as archive:
            assert not [name for name in archive.namelist() if name.startswith("data/text.parquet")]

    def test_an_oversized_events_file_fails_before_any_index_work(self, spool, monkeypatch):
        monkeypatch.setattr(package, "EVENTS_PARQUET_LIMIT", 10)

        def unexpected(*args, **kwargs):
            raise AssertionError("the index was written")

        monkeypatch.setattr(package, "write_text", unexpected)

        with pytest.raises(PackageError, match="the events take"):
            build(spool, [part(spool, 0, [{"Computer": "a"}])])
