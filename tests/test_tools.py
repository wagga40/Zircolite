"""Tests for the scripts in tools/.

These scripts reach into the package -- ``StreamingEventProcessor._flatten_event``,
``ZircoliteCore.run_streaming``, ``load_ruleset_from_var``, ``execute_rule``,
``_widen_logs_table`` -- but nothing else in the suite drives them, so a rename in
the engine used to leave them broken until somebody ran one by hand. The
end-to-end cases here exist to fail at that moment.

The filenames are hyphenated, so they are loaded by path rather than imported.
"""

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from zircolite import ProcessingConfig, ZircoliteCore

WORKSPACE_ROOT = Path(__file__).parent.parent
TOOLS = WORKSPACE_ROOT / "tools"
FIXTURES = WORKSPACE_ROOT / "tests" / "fixtures"
CONFIG = WORKSPACE_ROOT / "config" / "config.yaml"


def load_tool(name: str):
    """Import a hyphenated script from tools/ under a module name of its own."""
    path = TOOLS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def regression():
    return load_tool("sigma-regression")


@pytest.fixture(scope="module")
def benchmark():
    return load_tool("flatten-benchmark")


@pytest.fixture(scope="module")
def db_benchmark():
    return load_tool("db-benchmark")


# A rule split across pipelines: one Sigma id, two titles, as a merged Zircolite
# ruleset ships it. Only the Sysmon variant fires on the bitsadmin fixture.
BITSADMIN_ID = "0e6a9e6a-1111-4d4a-9a4a-1c1a1b1c1d1e"
BITSADMIN_TITLE = "File Download Via Bitsadmin"
BITSADMIN_RULESET = [
    {
        "title": f"{BITSADMIN_TITLE} - Generic",
        "id": BITSADMIN_ID,
        "level": "medium",
        "tags": [],
        "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%never-in-this-sample%' ESCAPE '\\'"],
    },
    {
        "title": f"{BITSADMIN_TITLE} - Sysmon",
        "id": BITSADMIN_ID,
        "level": "medium",
        "tags": [],
        "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%bitsadmin%' ESCAPE '\\'"],
    },
]


def write_case(tmp_path, *, match_count=1, name="Positive Detection Test", rule_id=BITSADMIN_ID):
    """Build a one-case regression_data tree around the tracked EVTX fixture."""
    case_dir = tmp_path / "regression_data" / "bitsadmin"
    case_dir.mkdir(parents=True)
    info = {
        "id": "11111111-2222-3333-4444-555555555555",
        "rule_metadata": [{"id": rule_id, "title": BITSADMIN_TITLE}],
        "regression_tests_info": [{
            "name": name,
            "type": "evtx",
            "match_count": match_count,
            "path": str(FIXTURES / "sample_bitsadmin.evtx"),
        }],
    }
    (case_dir / "info.yml").write_text(json.dumps(info), encoding="utf-8")
    return case_dir.parent


def write_ruleset(tmp_path, ruleset=None):
    path = tmp_path / "ruleset.json"
    path.write_text(json.dumps(ruleset if ruleset is not None else BITSADMIN_RULESET))
    return path


class TestExpectation:
    """match_count says the rule fired, not how many records it fired on."""

    def entry(self, regression, match_count):
        return regression.RegressionTestEntry(
            name="Positive Detection Test", type="evtx", path="x.evtx", match_count=match_count
        )

    def test_positive_passes_on_more_matches_than_declared(self, regression):
        # The regression samples routinely hold several matching records while
        # declaring match_count: 1. Demanding equality failed real detections.
        assert regression.expectation_met(self.entry(regression, 1), 3)

    def test_positive_passes_on_exactly_the_declared_count(self, regression):
        assert regression.expectation_met(self.entry(regression, 1), 1)

    def test_positive_fails_when_nothing_matched(self, regression):
        assert not regression.expectation_met(self.entry(regression, 1), 0)

    def test_negative_passes_only_on_silence(self, regression):
        entry = self.entry(regression, 0)
        assert regression.expectation_met(entry, 0)
        assert not regression.expectation_met(entry, 1)

    def test_labels(self, regression):
        assert regression.expectation_label(self.entry(regression, 1)) == "≥1"
        assert regression.expectation_label(self.entry(regression, 0)) == "0"


class TestInfoYmlParsing:
    """An absent match_count is inferred from the test name."""

    def parse(self, regression, tmp_path, name):
        case = tmp_path / "case"
        case.mkdir()
        (case / "info.yml").write_text(json.dumps({
            "rule_metadata": [{"id": "an-id", "title": "A Title"}],
            "regression_tests_info": [{"name": name, "type": "evtx", "path": "a.evtx"}],
        }))
        parsed = regression.parse_test_case(case)
        assert parsed is not None
        return parsed.tests[0]

    def test_positive_name_infers_one(self, regression, tmp_path):
        assert self.parse(regression, tmp_path, "Positive Detection Test").match_count == 1

    def test_negative_name_infers_zero(self, regression, tmp_path):
        assert self.parse(regression, tmp_path, "Negative Detection Test").match_count == 0

    def test_unknown_name_expects_a_detection(self, regression, tmp_path):
        # Defaulting to 0 would let a rule that never fires pass silently.
        assert self.parse(regression, tmp_path, "Some Other Test").match_count == 1


class TestRulesIndex:
    """Merged rulesets suffix the title per pipeline but keep the Sigma id."""

    def test_id_resolves_every_variant(self, regression):
        index = regression.RulesIndex(BITSADMIN_RULESET)
        found = index.find([regression.RuleRef(id=BITSADMIN_ID, title=BITSADMIN_TITLE)])
        assert [r["title"] for r in found] == [
            f"{BITSADMIN_TITLE} - Generic",
            f"{BITSADMIN_TITLE} - Sysmon",
        ]

    def test_title_is_the_fallback_when_the_ruleset_has_no_ids(self, regression):
        ruleset = [{"title": BITSADMIN_TITLE, "rule": ["SELECT * FROM logs"]}]
        index = regression.RulesIndex(ruleset)
        found = index.find([regression.RuleRef(id="not-in-the-ruleset", title=BITSADMIN_TITLE)])
        assert len(found) == 1

    def test_unknown_ref_resolves_to_nothing(self, regression):
        index = regression.RulesIndex(BITSADMIN_RULESET)
        assert index.find([regression.RuleRef(id="nope", title="Nope")]) == []

    def test_duplicate_refs_are_not_run_twice(self, regression):
        index = regression.RulesIndex(BITSADMIN_RULESET)
        ref = regression.RuleRef(id=BITSADMIN_ID, title=BITSADMIN_TITLE)
        assert len(index.find([ref, ref])) == 2


class TestColumnsUsedInSql:
    """The report filters events down to the fields the rule actually reads."""

    def test_reads_quoted_and_unquoted_names(self, regression):
        columns = regression._columns_used_in_sql([
            "SELECT * FROM logs WHERE Channel='X' AND EventID=13",
            "SELECT * FROM logs WHERE \"event.code\" = 1",
        ])
        assert columns == {"Channel", "EventID", "event.code"}

    def test_string_literals_are_not_columns(self, regression):
        assert regression._columns_used_in_sql(
            ["SELECT * FROM logs WHERE CommandLine LIKE '%user=bob%'"]
        ) == {"CommandLine"}


@pytest.mark.integration
class TestSigmaRegressionEndToEnd:
    """Drives the real script over the tracked EVTX fixture."""

    def run(self, regression, tmp_path, argv_extra=()):
        data = write_case(tmp_path)
        ruleset = write_ruleset(tmp_path)
        report = tmp_path / "report"
        argv = [
            "sigma-regression.py",
            "--regression-data", str(data),
            "-r", str(ruleset),
            "--zircolite-config", str(CONFIG),
            "--report", str(report),
            *argv_extra,
        ]
        with patch.object(sys, "argv", argv):
            code = regression.main()
        return code, json.loads((tmp_path / "report.json").read_text())

    def test_matched_rule_passes(self, regression, tmp_path):
        code, report = self.run(regression, tmp_path)
        assert code == 0
        assert (report["passed"], report["failed"], report["skipped"]) == (1, 0, 0)

    def test_report_markdown_is_written(self, regression, tmp_path):
        self.run(regression, tmp_path)
        assert (tmp_path / "report.md").exists()

    def test_unmatched_rule_is_skipped_and_fail_on_skip_reports_it(self, regression, tmp_path):
        data = write_case(tmp_path, rule_id="no-such-id")
        ruleset = write_ruleset(tmp_path, [{
            "title": "Something Else", "id": "other-id", "level": "low", "tags": [],
            "rule": ["SELECT * FROM logs"],
        }])
        argv = [
            "sigma-regression.py",
            "--regression-data", str(data),
            "-r", str(ruleset),
            "--zircolite-config", str(CONFIG),
            "--fail-on-skip",
        ]
        with patch.object(sys, "argv", argv):
            assert regression.main() == 1

    def test_rule_that_never_fires_fails(self, regression, tmp_path):
        data = write_case(tmp_path)
        ruleset = write_ruleset(tmp_path, [{
            "title": BITSADMIN_TITLE, "id": BITSADMIN_ID, "level": "low", "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%not-here%' ESCAPE '\\'"],
        }])
        report = tmp_path / "report"
        argv = [
            "sigma-regression.py",
            "--regression-data", str(data),
            "-r", str(ruleset),
            "--zircolite-config", str(CONFIG),
            "--report", str(report),
        ]
        with patch.object(sys, "argv", argv):
            assert regression.main() == 1
        # The report is written UTF-8 with ensure_ascii=False, so "≥" arrives as
        # multi-byte; decoding it with the platform default mangles it silently.
        report_json = (tmp_path / "report.json").read_text(encoding="utf-8")
        failed = json.loads(report_json)["failed_tests"]
        assert failed[0]["expected"] == "≥1"
        assert failed[0]["got"] == 0
        assert failed[0]["events"], "the report must carry the events that did not match"

    def test_every_variant_of_a_matched_id_runs(self, regression, tmp_path):
        # The Generic variant cannot fire on this sample; the Sysmon one can.
        # Testing only rules[0] would report a failure here.
        code, report = self.run(regression, tmp_path)
        assert code == 0 and report["failed"] == 0


@pytest.mark.integration
class TestFlattenBenchmark:
    """Pins the private flattening entry point the benchmark measures."""

    def test_runs_over_the_evtx_fixture(self, benchmark, capsys):
        argv = [
            "flatten-benchmark.py",
            "--evtx", str(FIXTURES / "sample_bitsadmin.evtx"),
            "--config", str(CONFIG),
            "--passes", "1",
        ]
        with patch.object(sys, "argv", argv):
            assert benchmark.main() == 0
        assert "events/s" in capsys.readouterr().out

    def test_missing_input_is_an_error_not_a_zero_measurement(self, benchmark, tmp_path):
        argv = [
            "flatten-benchmark.py",
            "--evtx", str(tmp_path / "nothing-here.evtx"),
            "--config", str(CONFIG),
        ]
        with patch.object(sys, "argv", argv):
            assert benchmark.main() == 1

    def test_collect_raw_events_searches_a_directory(self, benchmark):
        events = benchmark.collect_raw_events(FIXTURES, 10)
        assert events, "the EVTX fixture should be found by the recursive search"
        assert "Event" in events[0]

    def test_collect_raw_events_returns_nothing_for_a_missing_path(self, benchmark, tmp_path):
        assert benchmark.collect_raw_events(tmp_path / "absent.evtx", 10) == []


# One real MULTI-INDEX OR plan, captured from SQLite rather than invented: the
# index names live on the nested rows, not on the row naming the strategy.
MULTI_INDEX_OR_PLAN = [
    "MULTI-INDEX OR",
    "INDEX 1",
    "SEARCH logs USING INDEX idx_eventid (EventID=?)",
    "INDEX 2",
    "SEARCH logs USING INDEX idx_channel (Channel=?)",
]


@pytest.mark.integration
class TestDbBenchmark:
    """Pins the ingest, widening and plan-reading surfaces the harness drives."""

    def _core(self, field_mappings_file, test_logger):
        core = ZircoliteCore(
            config=field_mappings_file,
            processing_config=ProcessingConfig(disable_progress=True, no_output=True),
            logger=test_logger,
        )
        core.create_db('"Channel" TEXT COLLATE NOCASE, "CommandLine" TEXT COLLATE NOCASE')
        core.db_connection.execute(
            "INSERT INTO logs (Channel, CommandLine) VALUES (?, ?)",
            ("Security", "c:/evil.exe"),
        )
        core.db_connection.commit()
        return core

    def test_runs_over_the_evtx_fixture(self, db_benchmark, capsys):
        argv = [
            "db-benchmark.py",
            "--evtx", str(FIXTURES / "sample_bitsadmin.evtx"),
            "--ruleset", str(FIXTURES / "sample_ruleset.json"),
            "--config", str(CONFIG),
        ]
        with patch.object(sys, "argv", argv):
            assert db_benchmark.main() == 0
        out = capsys.readouterr().out
        assert "events/s" in out
        assert "selective:" in out

    def test_a_missing_corpus_is_an_error_not_a_zero_measurement(self, db_benchmark, tmp_path):
        argv = [
            "db-benchmark.py",
            "--evtx", str(tmp_path / "nothing-here.evtx"),
            "--ruleset", str(FIXTURES / "sample_ruleset.json"),
            "--config", str(CONFIG),
        ]
        with patch.object(sys, "argv", argv):
            assert db_benchmark.main() == 1

    def test_an_unreadable_ruleset_is_an_error(self, db_benchmark, tmp_path):
        not_a_ruleset = tmp_path / "notes.txt"
        not_a_ruleset.write_text("this is not a ruleset")
        argv = [
            "db-benchmark.py",
            "--evtx", str(FIXTURES / "sample_bitsadmin.evtx"),
            "--ruleset", str(not_a_ruleset),
            "--config", str(CONFIG),
        ]
        with patch.object(sys, "argv", argv):
            assert db_benchmark.main() == 1

    def test_a_rule_naming_an_absent_field_is_planned_not_written_off(
        self, db_benchmark, field_mappings_file, test_logger
    ):
        """Widening has to run before EXPLAIN, or 43% of rules never get a plan."""
        core = self._core(field_mappings_file, test_logger)
        try:
            ruleset = [{"rule": ["SELECT * FROM logs WHERE OriginalFileName = 'x'"]}]
            prepared, unpreparable = db_benchmark.prepare_queries(core, ruleset)

            assert len(prepared) == 1
            assert not unpreparable
            assert "OriginalFileName" in core._get_table_columns()
        finally:
            core.close()

    def test_a_regexp_rule_can_be_planned(self, db_benchmark, field_mappings_file, test_logger):
        """SQLite resolves function names when it prepares, so EXPLAIN needs the UDF.

        A bare ``sqlite3.connect`` raises ``no such function: REGEXP`` here, which
        would silently write off every regex rule as unplannable.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            details = db_benchmark.plan_for(
                core, "SELECT * FROM logs WHERE CommandLine REGEXP 'evil'"
            )

            assert details
        finally:
            core.close()

    def test_a_scan_is_not_a_selective_plan(self, db_benchmark):
        search_b = ["SEARCH logs USING INDEX idx_b (x=?)"]

        assert db_benchmark.plan_verdict(["SCAN logs"], {"idx_a"}, {"idx_a"}) == "scan"
        assert db_benchmark.plan_verdict(search_b, {"idx_a", "idx_b"}, {"idx_a"}) == "broad"
        assert db_benchmark.plan_verdict(search_b, {"idx_a", "idx_b"}, {"idx_b"}) == "selective"
        assert db_benchmark.plan_verdict(["SCAN logs"], set(), set()) == "unindexable"

    def test_a_multi_index_or_plan_counts_its_indexes(self, db_benchmark):
        assert db_benchmark.indexes_used(MULTI_INDEX_OR_PLAN) == {"idx_eventid", "idx_channel"}

    def test_a_transient_index_is_not_counted_as_one(self, db_benchmark):
        """An automatic index means no stored index served the query."""
        details = ["SEARCH logs USING AUTOMATIC COVERING INDEX (CommandLine=?)"]

        assert db_benchmark.indexes_used(details) == set()
        assert db_benchmark.plan_label(details) == "AUTOMATIC INDEX"

    def test_narrowest_picks_the_index_with_the_fewest_rows_per_key(self, db_benchmark):
        stats = {"idx_eventid": 12.0, "idx_channel": 75000.0}

        assert db_benchmark.narrowest({"idx_eventid", "idx_channel"}, stats) == {"idx_eventid"}
        assert db_benchmark.narrowest(set(), stats) == set()

    def test_collect_evtx_files_searches_a_directory(self, db_benchmark):
        files = db_benchmark.collect_evtx_files(FIXTURES, 0)

        assert files, "the EVTX fixture should be found by the recursive search"
        assert all(f.suffix == ".evtx" for f in files)

    def test_index_sets_reports_every_candidate(self, db_benchmark, capsys):
        argv = [
            "db-benchmark.py",
            "--evtx", str(FIXTURES / "sample_bitsadmin.evtx"),
            "--ruleset", str(FIXTURES / "sample_ruleset.json"),
            "--config", str(CONFIG),
            "--index-sets",
        ]
        with patch.object(sys, "argv", argv):
            assert db_benchmark.main() == 0
        out = capsys.readouterr().out
        for label, _ in db_benchmark._INDEX_SETS:
            assert label in out
        assert "detections identical across every set" in out

    def test_a_set_naming_an_absent_column_is_skipped_not_faked(
        self, db_benchmark, field_mappings_file, test_logger
    ):
        """SQLite would index the quoted name as a constant instead of refusing.

        The corpus here has a Channel but no eventid, so the composite cannot be
        built; reporting it as built would credit an index that indexes nothing.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            built, _ = db_benchmark.build_index_set(
                core,
                [("idx_channel", ("channel",)), ("idx_channel_eventid", ("channel", "eventid"))],
            )

            assert built == ["idx_channel"]
        finally:
            core.close()

    def test_index_columns_are_matched_case_insensitively(
        self, db_benchmark, field_mappings_file, test_logger
    ):
        """The corpus spells it ``Channel``; the set asks for ``channel``."""
        core = self._core(field_mappings_file, test_logger)
        try:
            built, _ = db_benchmark.build_index_set(core, [("idx_channel", ("channel",))])

            assert built == ["idx_channel"]
            indexes = {
                row[0]
                for row in core.db_connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
            assert "idx_channel" in indexes
        finally:
            core.close()

    def test_each_set_starts_from_a_clean_slate(
        self, db_benchmark, field_mappings_file, test_logger
    ):
        """Otherwise every set after the first is timed with its predecessors."""
        core = self._core(field_mappings_file, test_logger)
        try:
            db_benchmark.build_index_set(core, [("idx_channel", ("channel",))])
            built, _ = db_benchmark.build_index_set(
                core, [("idx_CommandLine", ("commandline",))]
            )

            assert built == ["idx_CommandLine"]
            indexes = {
                row[0]
                for row in core.db_connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
            assert "idx_channel" not in indexes
        finally:
            core.close()
