"""Sigma correlation plans (SQLite backend 2) run through ZircoliteCore.

A correlation match is an alert summary -- a group, a window, a metric and the
events behind it -- and every part of the run has to report it as one: the
result, the CSV header, the console, the limit, the event filter and the
diagnostics that are the only trace of a timestamp column the plan cannot read.
"""

import csv
import json
import logging
import sqlite3
from typing import ClassVar

import pytest
import yaml

from zircolite import ProcessingConfig, ZircoliteCore
from zircolite.cli import collapse_results_by_rule
from zircolite.config import RulesetConfig
from zircolite.console import DetectionStats, build_detection_table, console
from zircolite.correlations import alert_rows, describe_diagnostics, occurrence_iso, plan_problem
from zircolite.results import RowSpool
from zircolite.rules import EventFilter, RulesetHandler, ruleset_format_problem
from zircolite.sqlscan import scan_query

needs_json_sqlite = pytest.mark.skipif(
    sqlite3.sqlite_version_info < (3, 38), reason="correlation plans need SQLite 3.38 with JSON functions"
)

COLUMNS = (
    "SystemTime TEXT COLLATE NOCASE, Computer TEXT COLLATE NOCASE, EventID INTEGER COLLATE NOCASE, "
    "User TEXT COLLATE NOCASE, OriginalLogfile TEXT COLLATE NOCASE"
)


def base(name="proc", event_id=1):
    return {
        "title": name,
        "name": name,
        "logsource": {"product": "windows", "category": "test"},
        "detection": {"s": {"EventID": event_id}, "condition": "s"},
        "level": "informational",
    }


def correlation(kind="event_count", rules=("proc",), condition=None, name="burst", **extra):
    body = {"type": kind, "rules": list(rules), "group-by": ["Computer"], "timespan": "5m", **extra}
    if condition is not None:
        body["condition"] = condition
    elif not kind.startswith("temporal"):
        body["condition"] = {"gte": 2}
    return {"title": name, "name": name, "correlation": body, "level": "high"}


def convert(tmp_path, documents, **config):
    path = tmp_path / "rules.yml"
    path.write_text(yaml.safe_dump_all(documents))
    return RulesetHandler(RulesetConfig(ruleset=[str(path)], **config)).rulesets


def event(seconds, **fields):
    minutes, seconds = divmod(seconds, 60)
    return {
        "SystemTime": f"2026-01-01T00:{minutes:02d}:{seconds:02d}.000Z",
        "Computer": "host",
        "EventID": 1,
        "User": "u",
        "OriginalLogfile": "a.evtx",
        **fields,
    }


@pytest.fixture
def make_core(field_mappings_file, test_logger):
    cores = []

    def make(events, **processing):
        processing.setdefault("no_output", True)
        core = ZircoliteCore(field_mappings_file, ProcessingConfig(**processing), logger=test_logger)
        cores.append(core)
        core.create_db(COLUMNS)
        core.insert_data_to_db(events)
        return core

    yield make
    for core in cores:
        core.close()


def temp_tables(core):
    return core.db_connection.execute("SELECT name FROM sqlite_temp_master WHERE type='table'").fetchall()


@pytest.mark.requires_sigma
@needs_json_sqlite
class TestCorrelationPlansRun:
    def test_event_count_reports_an_alert_with_its_evidence(self, tmp_path, make_core):
        rules = convert(tmp_path, [base(), correlation()])
        assert [rule["title"] for rule in rules] == ["burst"]
        assert rules[0]["correlation_plan"]["event_id_field"] == "row_id"
        core = make_core([event(0), event(60), event(1000), event(10, Computer="other")])

        result = core.execute_rule(rules[0])

        assert result["result_type"] == "correlation"
        assert result["count"] == result["alert_count"] == 1
        assert result["event_count"] == 2
        alert = result["matches"][0]
        assert alert["result_type"] == "correlation"
        assert alert["group_keys"] == {"Computer": "host"}
        assert alert["metric_value"] == 2
        assert alert["SystemTime"] == "2026-01-01T00:01:00.000Z"
        assert [e["event"]["SystemTime"] for e in alert["evidence"]] == [
            "2026-01-01T00:00:00.000Z", "2026-01-01T00:01:00.000Z"]
        assert {e["event"]["OriginalLogfile"] for e in alert["evidence"]} == {"a.evtx"}
        assert not temp_tables(core)
        assert not core.rules_in_error

    def test_value_count_counts_distinct_values(self, tmp_path, make_core):
        rules = convert(tmp_path, [base(), correlation("value_count", condition={"gte": 2, "field": "User"})])
        core = make_core([event(0, User="a"), event(1, User="A"), event(2, User="b")])

        result = core.execute_rule(rules[0])

        # Values compare case-insensitively, like the rest of Sigma
        assert [alert["metric_value"] for alert in result["matches"]] == [2]

    def test_ordered_stages_need_increasing_timestamps(self, tmp_path, make_core):
        docs = [base("a", 1), base("b", 2), correlation("temporal_ordered", ("a", "b"))]
        rules = convert(tmp_path, docs)

        out_of_order = make_core([event(0, EventID=2), event(10, EventID=1)])
        in_order = make_core([event(0, EventID=1), event(10, EventID=2)])

        assert out_of_order.execute_rule(rules[0]) == {}
        assert in_order.execute_rule(rules[0])["count"] == 1

    def test_absence_fires_only_once_its_window_has_passed(self, tmp_path, make_core):
        docs = [base("a", 1), base("b", 2), correlation("temporal", ("a", "b"), "a and not b")]
        rules = convert(tmp_path, docs)
        # Any later event, matched or not, is what proves the window closed
        expired = make_core([event(0), event(400, EventID=99)])
        still_open = make_core([event(0), event(100, EventID=99)])

        assert expired.execute_rule(rules[0])["count"] == 1
        assert still_open.execute_rule(rules[0]) == {}
        assert still_open.metrics.data["correlation_diagnostics"] == {"burst": {"incomplete_window": 1}}

    def test_invalid_timestamps_are_reported_even_without_alerts(self, tmp_path, make_core, caplog):
        rules = convert(tmp_path, [base(), correlation()])
        core = make_core([event(0, SystemTime="not a time"), event(1)])
        core.load_ruleset_from_var(rules, None)

        with caplog.at_level(logging.WARNING):
            core.execute_ruleset("unused.json", disable_progress=True, show_table=False)

        assert core.full_results == []
        assert core.metrics.data["correlation_diagnostics"] == {"burst": {"invalid_timestamp": 1}}
        assert "without a valid timestamp" in caplog.text
        assert "--timestamp-format" in caplog.text

    @pytest.mark.parametrize("limit,expected", [(1, None), (2, 2)])
    def test_limit_counts_alerts(self, tmp_path, make_core, limit, expected):
        rules = convert(tmp_path, [base(), correlation()])
        # Backward windows at each qualifying time: an alert at 1s and one at 2s
        core = make_core([event(0), event(1), event(2)], limit=limit)

        result = core.execute_rule(rules[0])

        assert (result or {}).get("count") == expected

    def test_csv_mode_writes_nested_values_as_json(self, tmp_path, make_core):
        rules = convert(tmp_path, [base(), correlation()])
        core = make_core([event(0), event(1)], csv_mode=True)

        alert = core.execute_rule(rules[0])["matches"][0]

        assert alert["group_keys"] == '{"Computer":"host"}'
        assert alert["event_ids"].startswith("[")

    def test_alerts_stream_through_a_row_spool(self, tmp_path, make_core):
        rules = convert(tmp_path, [base(), correlation()])
        core = make_core([event(0), event(1)])

        result = core._execute_rule(rules[0], stream_rows=True)
        try:
            assert isinstance(result["matches"], RowSpool)
            assert [alert["group_keys"] for alert in result["matches"]] == [{"Computer": "host"}]
        finally:
            result["matches"].close()

    def test_unified_csv_header_carries_the_alert_columns(self, tmp_path, make_core):
        rules = convert(tmp_path, [base(), correlation()])
        core = make_core([event(0), event(1)], csv_mode=True, no_output=False)
        core.load_ruleset_from_var(rules, None)
        out = tmp_path / "detections.csv"

        core.execute_ruleset(str(out), last_ruleset=True, disable_progress=True, show_table=False)

        with open(out, encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle, delimiter=";"))
        assert rows[0]["rule_title"] == "burst"
        assert rows[0]["group_keys"] == '{"Computer":"host"}'
        assert rows[0]["metric_value"] == "2"
        assert rows[0]["evidence"].startswith("[")

    def test_an_interrupted_plan_stops_cleanly(self, tmp_path, make_core, monkeypatch):
        """Ctrl+C lands mid-plan: the rule is neither reported nor recorded as broken."""
        rules = convert(tmp_path, [base(), correlation()])
        core = make_core([event(i % 3000) for i in range(3000)])
        calls = iter([False])
        monkeypatch.setattr("zircolite.core.is_shutdown_requested", lambda: next(calls, True))

        assert core.execute_rule(rules[0]) == {}
        assert not core.rules_in_error
        assert not temp_tables(core)

    def test_a_plan_this_sqlite_cannot_run_is_a_rule_error(self, tmp_path, make_core, monkeypatch):
        rules = convert(tmp_path, [base(), correlation()])
        core = make_core([event(0), event(1)])
        monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 37, 2))

        assert core.execute_rule(rules[0]) == {}
        assert "SQLite >= 3.38.0" in core.rules_in_error["burst"]

    def test_the_plan_widens_logs_with_the_fields_it_needs(self, tmp_path, make_core):
        rules = convert(tmp_path, [base(), correlation("value_count", condition={"gte": 1, "field": "Missing"})])
        core = make_core([event(0), event(1)])

        assert core.execute_rule(rules[0]) == {}
        assert "missing" in core._logs_columns()
        assert not core.rules_in_error


@pytest.mark.requires_sigma
class TestEventRulesWidenFromRequiredFields:
    def test_a_field_read_inside_a_function_is_widened(self, tmp_path, field_mappings_file, test_logger):
        """The second field of |fieldref|contains sits inside a function call,
        where the SQL scan cannot see it; the converter's list names it."""
        rule = {
            "title": "fieldref",
            "logsource": {"product": "aws"},
            "detection": {
                "s": {"eventName": "CreateAccessKey"},
                "f": {"userIdentity.arn|fieldref|contains": "responseElements.accessKey.userName"},
                "condition": "s and not f",
            },
        }
        [entry] = convert(tmp_path, [rule])
        assert "responseElements.accessKey.userName" in entry["required_fields"]
        assert "responseElements.accessKey.userName" not in scan_query(entry["rule"][0]).columns
        core = ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True), logger=test_logger)
        try:
            core.create_db("eventName TEXT COLLATE NOCASE, `userIdentity.arn` TEXT COLLATE NOCASE")
            core.insert_data_to_db({"eventName": "CreateAccessKey", "userIdentity.arn": "arn:test"})

            assert core.execute_rule(entry)["count"] == 1
            assert not core.rules_in_error
        finally:
            core.close()


PLAN_RULE = {
    "title": "burst",
    "schema_version": 2,
    "result_type": "correlation",
    "correlation": True,
    "rule": ["WITH x AS (SELECT 1) SELECT * FROM x"],
    "correlation_plan": {"version": 2},
}


class TestRulesetFormat:
    def test_a_newer_schema_is_refused(self):
        problem = ruleset_format_problem([{"title": "t", "schema_version": 3, "rule": ["SELECT 1"]}])

        assert "update Zircolite" in problem

    @pytest.mark.parametrize("version", ["2", 0, True, None])
    def test_an_invalid_schema_version_is_refused(self, version):
        assert "invalid schema_version" in ruleset_format_problem([{"title": "t", "schema_version": version}])

    def test_a_correlation_without_its_plan_is_refused(self):
        rule = {key: value for key, value in PLAN_RULE.items() if key != "correlation_plan"}

        assert "no correlation_plan" in ruleset_format_problem([rule])

    def test_version_one_and_two_rulesets_load(self):
        assert ruleset_format_problem([{"title": "t", "rule": ["SELECT * FROM logs"]}, PLAN_RULE]) is None

    def test_a_refused_file_loads_no_rules(self, tmp_path, test_logger, caplog):
        path = tmp_path / "rules.json"
        path.write_text('[{"title": "t", "schema_version": 9, "rule": ["SELECT * FROM logs"]}]')

        with caplog.at_level(logging.ERROR):
            handler = RulesetHandler(RulesetConfig(ruleset=[str(path)]), logger=test_logger)

        assert handler.rulesets == []

    def test_plans_this_sqlite_cannot_run_are_reported_at_load(self, tmp_path, monkeypatch):
        path = tmp_path / "rules.json"
        plan = {"version": 2, "prepare": [], "query": "", "diagnostics": "", "required_fields": {},
                "source_tables": {}, "event_id_field": "row_id", "sqlite_min_version": "3.38.0"}
        path.write_text(json.dumps([{**PLAN_RULE, "correlation_plan": plan}]))
        monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 37, 2))
        logger = logging.getLogger("zircolite-correlation-load")
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        logger.addHandler(handler)
        try:
            loaded = RulesetHandler(RulesetConfig(ruleset=[str(path)]), logger=logger)
        finally:
            logger.removeHandler(handler)

        assert len(loaded.rulesets) == 1
        assert any("1 correlation rule(s) cannot run" in record.getMessage() for record in records)


class TestEventFilterAndPlans:
    def test_a_plan_turns_the_event_filter_off(self):
        ordinary = {"title": "t", "rule": ["SELECT * FROM logs WHERE Channel='Security' AND EventID=4624"]}

        assert EventFilter([ordinary]).is_enabled
        event_filter = EventFilter([ordinary, PLAN_RULE])
        assert not event_filter.is_enabled
        assert event_filter.should_process_event("Other", 999)


class TestPlanHelpers:
    @pytest.mark.parametrize("plan,message", [
        ([], "not an object"),
        ({"version": 1}, "version 1 is not supported"),
        ({"version": 2}, "lacks prepare"),
    ])
    def test_plan_problem_names_the_reason(self, plan, message):
        assert message in plan_problem(plan)

    def test_an_unreadable_sqlite_version_is_a_problem(self):
        plan = {"version": 2, "prepare": [], "query": "", "diagnostics": "", "required_fields": {},
                "source_tables": {}, "event_id_field": "row_id", "sqlite_min_version": "three"}

        assert "unreadable SQLite version" in plan_problem(plan)

    def test_occurrence_time_is_iso_utc_with_milliseconds(self):
        assert occurrence_iso(1704067205.5) == "2024-01-01T00:00:05.500Z"
        assert occurrence_iso(1e20) is None

    def test_alert_rows_add_the_time_field(self):
        [alert] = alert_rows([{"alert_id": "a", "occurrence_time": 0}], "UtcTime")

        assert alert == {"result_type": "correlation", "alert_id": "a", "occurrence_time": 0,
                         "UtcTime": "1970-01-01T00:00:00.000Z"}

    def test_diagnostics_read_as_sentences(self):
        text = describe_diagnostics({"missing_group_key": 2, "invalid_timestamp": 1, "incomplete_window": 0})

        assert text == "1 event(s) without a valid timestamp, 2 event(s) missing a group-by field"


class TestCorrelationReporting:
    SUMMARY: ClassVar[dict] = {"title": "burst", "rule_level": "high", "count": 3, "tags": [],
               "result_type": "correlation", "event_count": 7}

    def test_the_detection_table_says_alerts(self):
        with console.capture() as capture:
            console.print(build_detection_table([self.SUMMARY, {**self.SUMMARY, "title": "plain", "result_type": None}]))

        text = capture.get()
        assert "Matches" in text
        assert "3 alerts" in text

    def test_stats_keep_alerts_apart_from_events(self):
        stats = DetectionStats()
        stats.add_detection("high", 3, alerts=True)
        stats.add_detection("high", 5)

        assert (stats.total_alerts, stats.total_events, stats.high) == (3, 5, 8)

    def test_collapsing_per_file_results_sums_alerts_and_events(self):
        collapsed = collapse_results_by_rule([
            {"id": "x", "count": 2, "alert_count": 2, "event_count": 4},
            {"id": "x", "count": 1, "alert_count": 1, "event_count": 3},
        ])

        assert collapsed == [{"id": "x", "count": 3, "alert_count": 3, "event_count": 7}]


@pytest.mark.requires_sigma
class TestOneCollectionAcrossPaths:
    """Every YAML path of a run is one Sigma collection, so references cross files."""

    @staticmethod
    def handler(paths, **config):
        return RulesetHandler(RulesetConfig(ruleset=[str(p) for p in paths], **config))

    @staticmethod
    def write(path, *documents):
        path.write_text(yaml.safe_dump_all(documents))
        return path

    def test_a_correlation_resolves_a_rule_from_another_file(self, tmp_path):
        a = self.write(tmp_path / "base.yml", base())
        b = self.write(tmp_path / "corr.yml", correlation())

        rules = self.handler([b, a]).rulesets

        assert [rule["title"] for rule in rules] == ["burst"]
        assert rules[0]["correlation_plan"]["version"] == 2

    def test_a_file_that_fails_to_load_leaves_the_others(self, tmp_path, caplog):
        folder = tmp_path / "rules"
        folder.mkdir()
        self.write(folder / "good.yml", {**base("good"), "level": "high"})
        self.write(folder / "bad.yml", {**base("bad"), "id": "not-a-uuid"})

        with caplog.at_level(logging.ERROR):
            rules = self.handler([folder]).rulesets

        assert [rule["title"] for rule in rules] == ["good"]
        assert "bad.yml" in caplog.text

    def test_a_missing_reference_drops_only_its_correlations(self, tmp_path, caplog):
        path = self.write(
            tmp_path / "rules.yml",
            {**base("standalone"), "level": "high"},
            correlation(rules=("nowhere",), name="orphan"),
            correlation("temporal_ordered", ("orphan", "standalone"), name="parent"),
        )

        with caplog.at_level(logging.ERROR):
            rules = self.handler([path]).rulesets

        assert [rule["title"] for rule in rules] == ["standalone"]
        assert "'orphan'" in caplog.text and "'nowhere'" in caplog.text
        assert "'parent'" in caplog.text

    @needs_json_sqlite
    def test_a_chain_across_three_files_runs(self, tmp_path, make_core):
        a = self.write(tmp_path / "a.yml", base("proc", 1), base("logon", 2))
        b = self.write(tmp_path / "b.yml", correlation(name="burst"))
        c = self.write(tmp_path / "c.yml", correlation("temporal_ordered", ("burst", "logon"), name="then_logon"))

        rules = self.handler([c, b, a]).rulesets
        core = make_core([event(0), event(1), event(2, EventID=2)])
        result = core.execute_rule(rules[0])

        assert [rule["title"] for rule in rules] == ["then_logon"]
        assert result["count"] == 1
        assert len(result["matches"][0]["child_alert_ids"]) == 1
        assert result["event_count"] == 3

    def test_each_path_is_saved_on_its_own(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        a = self.write(tmp_path / "a.yml", {**base("first"), "level": "high"}, base("proc"))
        b = self.write(tmp_path / "b.yml", correlation())

        rules = self.handler([a, b], save_ruleset=True).rulesets

        saved = sorted(
            [rule["title"] for rule in json.loads(path.read_text())]
            for path in tmp_path.glob("ruleset-*.json")
        )
        assert {rule["title"] for rule in rules} == {"first", "burst"}
        # The correlation is saved with the path that defines it, its plan self-contained
        assert saved == [["burst"], ["first"]]

    def test_a_sigma_filter_applies_to_rules_of_every_path(self, tmp_path):
        a = self.write(tmp_path / "a.yml", {**base("proc"), "id": "7e3c9e4f-2f5e-4a1b-9b0e-1c2d3e4f5a6b", "level": "high"})
        b = self.write(tmp_path / "b.yml", {
            "title": "Not admin",
            "logsource": {"product": "windows", "category": "test"},
            "filter": {"rules": ["7e3c9e4f-2f5e-4a1b-9b0e-1c2d3e4f5a6b"],
                       "selection": {"User": "admin"}, "condition": "not selection"},
        })

        [rule] = self.handler([a, b]).rulesets

        assert "User" in rule["rule"][0]
