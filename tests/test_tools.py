"""Tests for the scripts in tools/.

These scripts reach into the package -- ``StreamingEventProcessor._flatten_event``,
``ZircoliteCore.run_streaming``, ``load_ruleset_from_var`` -- but nothing else in
the suite drives them, so a rename in the engine used to leave them broken until
somebody ran one by hand. The end-to-end cases here exist to fail at that moment.

Both filenames are hyphenated, so they are loaded by path rather than imported.
"""

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

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
        failed = json.loads((tmp_path / "report.json").read_text())["failed_tests"]
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
