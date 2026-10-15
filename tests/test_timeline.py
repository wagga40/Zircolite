"""Tests for the timeline: rows, their order, duplicates and the files written."""

import csv
import json
import os
import stat
from pathlib import Path

import pytest

from zircolite import timeline
from zircolite.package_spool import rule_index
from zircolite.timeline import (
    TimelineConfigError,
    TimelineError,
    TimelineSpool,
    _SortedRuns,
    build_timeline,
    load_presentation,
    merge_runs,
    parse_presentation,
    timeline_format,
)

SHIPPED = Path(__file__).parent.parent / "config" / "timeline.yaml"

WHOAMI = {"title": "Whoami", "id": "r-1", "level": "high", "filename": "whoami.yml",
          "tags": ["attack.discovery", "attack.t1033"], "rule": ["SELECT 1"]}
NET = {"title": "Net use", "id": "r-2", "level": "medium", "filename": "net.yml",
       "tags": [], "rule": ["SELECT 2"]}


def make_spool(tmp_path, profile="standard", presentation=None, rules=(WHOAMI, NET), fmt="jsonl", **overrides):
    presentation = presentation or load_presentation(SHIPPED)
    directory = tmp_path / "spool"
    directory.mkdir(exist_ok=True)
    return TimelineSpool(directory=str(directory), columns=presentation.profiles[profile],
                         presentation=presentation, fmt=fmt, time_field="SystemTime",
                         rule_keys=rule_index(list(rules)), **overrides)


def result(rule, *matches, **extra):
    return {"title": rule["title"], "id": rule["id"], "rule_level": rule["level"], "tags": rule["tags"],
            "sigmafile": rule["filename"], "count": len(matches), "matches": list(matches), **extra}


def event(record=1, time="2024-01-01T00:00:00.0000000Z", source="a.evtx", **fields):
    return {"row_id": record, "SystemTime": time, "Computer": "host", "Channel": "Security",
            "EventID": 4688, "EventRecordID": record, "OriginalLogfile": source, **fields}


def write(tmp_path, spool, *results, name=None, parts=1, **options):
    """Sink the results into ``parts`` parts, the way several databases would."""
    name = name or f"timeline.{spool.fmt}"
    records = []
    for index in range(parts):
        part = spool.open_part()
        for item in results[index::parts]:
            part.sink(item)
        records.append(part.finish())
    destination = tmp_path / name
    return build_timeline(spool, records, str(destination), **options), destination


def jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def csv_rows(path):
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def presentation_with(**changes):
    document = {
        "columns": {"Computer": ["Computer"], "Channel": ["Channel"], "EventID": ["EventID"],
                    "RecordID": ["EventRecordID"]},
        "profiles": {"p": ["Timestamp", "Details"]},
        "details": {"skip": ["OriginalLogfile"]},
    }
    document.update(changes)
    return document


class TestConfiguration:
    def test_the_shipped_configuration_validates(self):
        presentation = load_presentation(SHIPPED)

        assert {"minimal", "standard", "full"} <= set(presentation.profiles)

    @pytest.mark.parametrize("document,named", [
        ({"columns": {}, "profiles": {}}, "details is missing"),
        (presentation_with(extra=1), "extra is not a timeline setting"),
        (presentation_with(profiles={"p": ["Timestamp", "Nope"]}), "profiles.p[1] is neither a column"),
        (presentation_with(profiles={"p": ["Details", "%details%"]}), "profiles.p[1] repeats the column"),
        (presentation_with(profiles={}), "profiles must name at least one profile"),
        (presentation_with(columns={"Computer": ["Computer"], "Channel": ["Channel"],
                                    "EventID": ["EventID"]}), "columns.RecordID is missing"),
        (presentation_with(details={"skip": "Keywords"}), "details.skip must be a non-empty list"),
        (presentation_with(details={"layouts": []}), "details.layouts is not a timeline setting"),
    ])
    def test_a_wrong_key_is_named(self, document, named):
        with pytest.raises(TimelineConfigError, match=named.replace("[", r"\[").replace("]", r"\]")):
            parse_presentation(document, "t.yaml")

    def test_an_unreadable_file_is_a_configuration_error(self, tmp_path):
        broken = tmp_path / "t.yaml"
        broken.write_text("columns: [unclosed\n")

        with pytest.raises(TimelineConfigError, match=r"t\.yaml"):
            load_presentation(broken)

    @pytest.mark.parametrize("destination,expected", [
        ("t.csv", "csv"), ("t.JSONL", "jsonl"), ("t.ndjson", "jsonl"), ("-", "jsonl"),
        ("t.json", None), ("t", None),
    ])
    def test_the_format_follows_the_extension(self, destination, expected):
        assert timeline_format(destination) == expected


class TestRows:
    def test_an_event_row_carries_the_rule_and_the_event(self, tmp_path):
        spool = make_spool(tmp_path)

        _, path = write(tmp_path, spool, result(WHOAMI, event(7, CommandLine="whoami")))

        [row] = jsonl(path)
        assert row == {
            "Timestamp": "2024-01-01T00:00:00.000000+00:00", "Computer": "host", "Channel": "Security",
            "EventID": 4688, "RecordID": 7, "Level": "high", "RuleTitle": "Whoami",
            "Details": "CommandLine: whoami", "ExtraFields": None, "RuleID": "r-1",
            "Tactics": ["discovery"], "Techniques": ["T1033"], "SourceFile": "a.evtx",
        }

    def test_details_lists_the_activity_in_field_name_order(self, tmp_path):
        """Name order: a unified database and a per-file one list an event's columns differently."""
        spool = make_spool(tmp_path, "minimal")

        _, path = write(tmp_path, spool, result(WHOAMI, event(Image="C:\\w.exe", CommandLine="whoami",
                                                             Keywords="0x80", User="bob")))

        assert jsonl(path)[0]["Details"] == "CommandLine: whoami ¦ Image: C:\\w.exe ¦ User: bob"

    def test_field_names_compare_ignoring_case(self, tmp_path):
        spool = make_spool(tmp_path, "minimal")
        row = event()
        row["computer"] = row.pop("Computer")

        _, path = write(tmp_path, spool, result(WHOAMI, row))

        [written] = jsonl(path)
        assert written["Computer"] == "host"
        assert written["Details"] is None

    def test_a_missing_value_is_null_in_jsonl_and_a_dash_in_csv(self, tmp_path):
        row = event()
        del row["Computer"]

        _, path_jsonl = write(tmp_path, make_spool(tmp_path, "minimal"), result(WHOAMI, row))
        _, path_csv = write(tmp_path, make_spool(tmp_path, "minimal", fmt="csv"), result(WHOAMI, row))

        assert jsonl(path_jsonl)[0]["Computer"] is None
        assert csv_rows(path_csv)[0]["Computer"] == "-"

    def test_the_full_profile_keeps_every_field_but_the_row_id(self, tmp_path):
        row = event(3, Image="w.exe")

        _, path_jsonl = write(tmp_path, make_spool(tmp_path, "full"), result(WHOAMI, row))
        _, path_csv = write(tmp_path, make_spool(tmp_path, "full", fmt="csv"), result(WHOAMI, row))

        fields = jsonl(path_jsonl)[0]["AllFields"]
        assert list(fields) == sorted(fields, key=str.lower)
        assert "row_id" not in fields
        assert fields["EventRecordID"] == 3
        assert csv_rows(path_csv)[0]["AllFields"].startswith("Channel: Security ¦ Computer: host ¦ ")

    def test_a_field_column_leaves_details(self, tmp_path):
        presentation = parse_presentation(presentation_with(profiles={"p": ["Timestamp", "%commandline%", "Details"]}), "t")
        spool = make_spool(tmp_path, "p", presentation, fmt="csv")

        _, path = write(tmp_path, spool, result(WHOAMI, event(CommandLine="whoami", Image="w.exe")))

        [row] = csv_rows(path)
        assert row["commandline"] == "whoami"
        assert "CommandLine" not in row["Details"]

    @pytest.mark.parametrize("raw", ["2017-06-09T19:21:26.968669Z", "2017-06-09T19:21:26.9686691Z",
                                     "1969-12-31T23:59:59.000001Z", "0001-01-01T00:00:00.000000Z",
                                     "2017-06-09 19:21:26.968669Z", "2017-06-09T19:21:26+02:00"])
    def test_a_windows_time_is_cut_to_the_formatted_instant(self, raw):
        from zircolite.package_spool import time_microseconds
        from zircolite.timeline import _timestamp_text, format_instant

        instant = time_microseconds(raw, "iso")

        assert _timestamp_text(raw, instant) == format_instant(instant)

    def test_unix_times_follow_the_timestamp_format(self, tmp_path):
        spool = make_spool(tmp_path, "minimal", timestamp_format="unix_ms")

        _, path = write(tmp_path, spool, result(WHOAMI, event(time=1704067200500)))

        assert jsonl(path)[0]["Timestamp"] == "2024-01-01T00:00:00.500000+00:00"

    def test_an_unparseable_time_is_written_raw_and_listed_last(self, tmp_path):
        spool = make_spool(tmp_path, "minimal")

        stats, path = write(tmp_path, spool, result(WHOAMI, event(1, time="not a time"), event(2)))

        assert [row["Timestamp"] for row in jsonl(path)] == ["2024-01-01T00:00:00.000000+00:00", "not a time"]
        assert stats.unparsed == 1

    def test_a_correlation_alert_is_one_row_at_its_occurrence(self, tmp_path):
        spool = make_spool(tmp_path)
        alert = {"result_type": "correlation", "alert_id": "a1", "group_keys": {"Computer": "host"},
                 "occurrence_time": 1704067260.0, "window_start": 1704067200.0, "window_end": 1704067260.0,
                 "metric_name": "event_count", "metric_value": 2, "event_count": 2, "event_ids": [1, 2],
                 "evidence": [{"event": event()}], "SystemTime": "2024-01-01T00:01:00.000Z"}

        _, path = write(tmp_path, spool, result(WHOAMI, alert, result_type="correlation"))

        [row] = jsonl(path)
        assert row["Timestamp"] == "2024-01-01T00:01:00.000000+00:00"
        assert row["Computer"] == "host"
        assert row["Details"] == "Events: 2 ¦ Computer: host ¦ event_count: 2"
        assert row["ExtraFields"] == "alert_id: a1 ¦ window_end: 1704067260.0 ¦ window_start: 1704067200.0"
        assert row["SourceFile"] is None


class TestOrder:
    def test_rows_follow_the_time_then_the_ruleset(self, tmp_path):
        spool = make_spool(tmp_path, "minimal")
        late = "2024-01-02T00:00:00Z"

        _, path = write(tmp_path, spool, result(NET, event(1)), result(WHOAMI, event(2, time=late), event(1)))

        assert [(row["Timestamp"][:10], row["RuleTitle"]) for row in jsonl(path)] == [
            ("2024-01-01", "Whoami"), ("2024-01-01", "Net use"), ("2024-01-02", "Whoami")]

    def test_times_before_1970_come_first(self, tmp_path):
        spool = make_spool(tmp_path, "minimal")

        _, path = write(tmp_path, spool, result(WHOAMI, event(1), event(2, time="1969-12-31T23:59:59Z")))

        assert [row["Timestamp"][:4] for row in jsonl(path)] == ["1969", "2024"]

    def test_the_bytes_do_not_depend_on_how_the_rows_were_split(self, tmp_path):
        rows = [event(n, time=f"2024-01-01T00:00:{n % 7:02d}Z", source=f"{n % 3}.evtx") for n in range(30)]
        outputs = []
        for parts in (1, 3):
            run = tmp_path / str(parts)
            run.mkdir()
            spool = make_spool(run, fmt="csv")
            _, path = write(run, spool, *(result(WHOAMI, row) for row in rows), parts=parts)
            outputs.append(path.read_bytes())

        assert outputs[0] == outputs[1]


class TestDuplicates:
    def test_a_record_from_a_second_copy_of_a_log_is_dropped(self, tmp_path):
        spool = make_spool(tmp_path, "minimal")

        stats, path = write(tmp_path, spool, result(WHOAMI, event(7, source="Security.evtx")),
                            result(WHOAMI, event(7, source="Security-copy.evtx")), parts=2)

        assert len(jsonl(path)) == 1
        assert stats.duplicates == 1

    def test_two_rules_matching_one_event_give_two_rows(self, tmp_path):
        spool = make_spool(tmp_path, "minimal")

        stats, path = write(tmp_path, spool, result(WHOAMI, event(7)), result(NET, event(7)))

        assert [row["RuleTitle"] for row in jsonl(path)] == ["Whoami", "Net use"]
        assert stats.duplicates == 0

    def test_identical_events_in_one_log_stay_distinct(self, tmp_path):
        """Without a record ID an identical line is the only identity, and one log can repeat it."""
        spool = make_spool(tmp_path, "minimal")
        line = {"row_id": 1, "SystemTime": "2024-01-01T00:00:00Z", "msg": "failed login", "OriginalLogfile": "app.json"}

        stats, path = write(tmp_path, spool, result(WHOAMI, line, {**line, "row_id": 2}))

        assert len(jsonl(path)) == 2
        assert stats.duplicates == 0

    def test_a_copy_of_a_log_without_record_ids_is_dropped(self, tmp_path):
        spool = make_spool(tmp_path, "full")
        line = {"SystemTime": "2024-01-01T00:00:00Z", "msg": "failed login"}
        once = {**line, "row_id": 1, "OriginalLogfile": "app.json"}
        twice = [{**line, "row_id": n, "OriginalLogfile": "app-full.json"} for n in (2, 3)]

        stats, path = write(tmp_path, spool, result(WHOAMI, once, *twice))

        # The copy holding the event most often is the one kept
        assert [row["SourceFile"] for row in jsonl(path)] == ["app-full.json", "app-full.json"]
        assert stats.duplicates == 1

    def test_keep_duplicates_keeps_them(self, tmp_path):
        spool = make_spool(tmp_path, "minimal")

        stats, path = write(tmp_path, spool, result(WHOAMI, event(7, source="a.evtx"), event(7, source="b.evtx")),
                            keep_duplicates=True)

        assert len(jsonl(path)) == 2
        assert stats.duplicates == 0


class TestSorting:
    def test_runs_merge_back_to_one_order(self, tmp_path):
        lines = [f"{n * 7919 % 1009:016x}\t{n}\n".encode() for n in range(500)]
        runs = _SortedRuns(str(tmp_path), budget=200)
        for line in lines:
            runs.add(line)
        runs.flush()
        assert len(runs.paths) > 3

        # Three at a time: the merge has to go through longer runs first
        assert list(merge_runs(runs.paths, str(tmp_path), fan_in=3)) == sorted(lines)
        assert not list(tmp_path.iterdir())


class TestFiles:
    def test_csv_cells_cannot_become_formulas(self, tmp_path):
        presentation = parse_presentation(presentation_with(profiles={"p": ["%CommandLine%", "Details"]}), "t")
        spool = make_spool(tmp_path, "p", presentation, fmt="csv")

        _, path = write(tmp_path, spool, result(WHOAMI, event(CommandLine="=cmd|' /C calc'!A0")))

        assert csv_rows(path)[0]["CommandLine"] == "'=cmd|' /C calc'!A0"

    def test_quotes_and_commas_survive_a_csv_reader(self, tmp_path):
        presentation = parse_presentation(presentation_with(profiles={"p": ["%CommandLine%", "%Path%", "Details"]}), "t")
        spool = make_spool(tmp_path, "p", presentation, fmt="csv")
        command = 'cmd /c "echo a, b" , "c"'

        _, path = write(tmp_path, spool, result(WHOAMI, event(CommandLine=command, Path='C:\\x"y', User="a,b")))

        [row] = csv_rows(path)
        assert (row["CommandLine"], row["Path"]) == (command, 'C:\\x"y')
        assert row["Details"].endswith(" ¦ User: a,b")

    def test_lists_are_joined_in_csv(self, tmp_path):
        spool = make_spool(tmp_path, rules=(WHOAMI,), fmt="csv")
        tagged = {**WHOAMI, "tags": ["attack.discovery", "attack.execution"]}

        _, path = write(tmp_path, spool, result(tagged, event()))

        assert csv_rows(path)[0]["Tactics"] == "discovery ¦ execution"

    def test_a_failed_write_keeps_the_earlier_timeline(self, tmp_path, monkeypatch):
        spool = make_spool(tmp_path)
        earlier = tmp_path / "timeline.jsonl"
        earlier.write_text("earlier\n")
        monkeypatch.setattr(timeline, "_write", lambda *args: (_ for _ in ()).throw(OSError("disk full")))

        with pytest.raises(OSError, match="disk full"):
            write(tmp_path, spool, result(WHOAMI, event()))

        assert earlier.read_text() == "earlier\n"
        assert not list(tmp_path.glob(".timeline.jsonl.*"))

    def test_the_file_gets_the_usual_permissions(self, tmp_path):
        previous = os.umask(0o022)
        try:
            _, path = write(tmp_path, make_spool(tmp_path), result(WHOAMI, event()))
        finally:
            os.umask(previous)

        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o644

    @pytest.mark.parametrize("name", ["t.json", "t.csv"])
    def test_a_destination_unlike_the_parts_is_refused(self, tmp_path, name):
        """The parts hold rows already written as JSON lines; they cannot become CSV."""
        with pytest.raises(TimelineError, match="extension"):
            write(tmp_path, make_spool(tmp_path), result(WHOAMI, event()), name=name)

    def test_the_runs_are_removed_once_merged(self, tmp_path):
        spool = make_spool(tmp_path)

        write(tmp_path, spool, result(WHOAMI, event()), parts=2)

        assert not list(Path(spool.directory).iterdir())


class TestParts:
    def test_a_failing_part_reports_and_removes_its_file(self, tmp_path):
        spool = make_spool(tmp_path, "full")
        part = spool.open_part()

        part.sink(result(WHOAMI, event(Unwritable=object())))
        part.sink(result(WHOAMI, event()))

        with pytest.raises(TimelineError):
            part.finish()
        assert not list(Path(spool.directory).iterdir())

    def test_a_discarded_part_leaves_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("zircolite.timeline.PART_BUDGET", 1)
        spool = make_spool(tmp_path)
        part = spool.open_part()
        part.sink(result(WHOAMI, event(1), event(2)))
        assert list(Path(spool.directory).iterdir())

        part.discard()

        assert not list(Path(spool.directory).iterdir())
