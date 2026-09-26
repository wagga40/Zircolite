"""Tests for the scripts in tools/.

These scripts reach into the package -- ``StreamingEventProcessor._flatten_event``,
``ZircoliteCore.run_streaming``, ``load_ruleset_from_var``, ``execute_rule``,
``_widen_logs_table`` -- but nothing else in the suite drives them, so a rename in
the engine used to leave them broken until somebody ran one by hand. The
end-to-end cases here exist to fail at that moment.

The release scripts need a real PyInstaller build or a Windows ARM64 host, so the
suite does not run them end-to-end. Their decisions -- what goes in the archive,
which licences are demanded, which requirements Windows on ARM64 skips -- are
pinned here against fake checkouts instead.

The filenames are hyphenated, so they are loaded by path rather than imported.
"""

import importlib.metadata
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import zipfile
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


def test_benchmark_default_report_stays_outside_worktree(tmp_path, monkeypatch):
    import tempfile

    benchmark = load_tool("throughput-benchmark")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["throughput-benchmark.py", "--event-count", "12", "--files", "1",
                                     "--passes", "1", "--modes", "sequential", "--variants", "current"])
    assert benchmark.main() == 0
    reports = list(tmp_path.glob("zircolite-benchmark-*.json"))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text())["results"]["sequential"][0]["matches"] == 1
    assert list(tmp_path.iterdir()) == reports


@pytest.fixture(scope="module")
def tool_benchmark():
    return load_tool("tool-benchmark")


def write_fake_tool(path, body):
    """A stand-in for a Hayabusa or Chainsaw binary: a script run by this interpreter."""
    path.write_text(f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


FAKE_HAYABUSA = """
if sys.argv[1] == "help":
    print("Hayabusa v4.1.0 - Suzumushi Release")
    raise SystemExit(0)
print("\\x1b[0mTotal detection rules: 4,658\\x1b[0m")
print("Detection rules enabled after channel filter: 2,293")
lines = ['{ "RuleTitle":"Proc Exec","RuleID":"a" }', '{ "RuleTitle":"Net Conn","RuleID":"b" }',
         '{ "RuleTitle":"Proc Exec","RuleID":"a" }']
Path(sys.argv[sys.argv.index("-o") + 1]).write_text("\\n".join(lines) + "\\n")
"""

FAKE_CHAINSAW = """
if sys.argv[1] == "--version":
    print("chainsaw 2.16.0")
    raise SystemExit(0)
print("[!] Loaded 3,524 detection rules (388 not loaded)")
Path(sys.argv[sys.argv.index("-o") + 1]).write_text('{"id":"x","name":"Rule X"}\\n')
"""


class TestToolBenchmarkCounting:
    def test_zircolite_counts_merged_variants_as_one_rule(self, tool_benchmark, tmp_path):
        output = tmp_path / "out.json"
        output.write_text(json.dumps([
            {"id": "r1", "title": "Rule - Sysmon", "matches": [{"row_id": 1}, {"row_id": 2}]},
            {"id": "r1", "title": "Rule - Generic", "matches": [{"row_id": 3}]},
            {"id": "r2", "title": "Other", "matches": [{"row_id": 4}]},
        ]))
        assert tool_benchmark.count_zircolite(output) == (4, 2)

    def test_jsonl_skips_blank_lines_and_falls_back_to_the_title(self, tool_benchmark, tmp_path):
        output = tmp_path / "out.jsonl"
        output.write_text('{"id": "a", "name": "A"}\n\n{"name": "B"}\n{"id": "a", "name": "A"}\n')
        assert tool_benchmark.count_jsonl(output, "id", "name") == (3, 2)

    def test_rule_counts_ignore_colour_and_thousands_separators(self, tool_benchmark):
        text = "\x1b[0mTotal detection rules: 4,658\x1b[0m\nDetection rules enabled after channel filter: 2,293\n"
        assert tool_benchmark.rules_loaded("hayabusa", text) == {"loaded": 4658, "after channel filter": 2293}
        assert tool_benchmark.rules_loaded("chainsaw", "[!] Loaded 3,524 detection rules") == {"loaded": 3524}
        assert tool_benchmark.rules_loaded("zircolite", "INFO [+] 4319 rules loaded") == {"loaded": 4319}


class TestToolBenchmarkCommands:
    def test_hayabusa_reads_a_file_with_f_and_a_directory_with_d(self, tool_benchmark, tmp_path):
        binary = tmp_path / "hayabusa" / "hayabusa"
        single = tmp_path / "one.evtx"
        single.write_bytes(b"")
        for events, flag in ((single, "-f"), (tmp_path, "-d")):
            args = tool_benchmark.parse_arguments(["--events", str(events), "--hayabusa", str(binary)])
            command, cwd, output = tool_benchmark.hayabusa_command(args, tmp_path)
            assert command[1:4] == ["dfir-timeline", flag, str(events.resolve())]
            assert "-w" in command and command[command.index("-t") + 1] == "jsonl"
            assert cwd == binary.parent.resolve()
            assert command[command.index("-o") + 1] == str(output)

    def test_chainsaw_repeats_sigma_and_adds_its_own_rules_only_when_given(self, tool_benchmark, tmp_path):
        base = ["--events", str(tmp_path), "--chainsaw", str(tmp_path / "chainsaw"),
                "--chainsaw-mapping", str(tmp_path / "map.yml"),
                "--chainsaw-sigma", str(tmp_path / "a"), "--chainsaw-sigma", str(tmp_path / "b")]
        command, _, _ = tool_benchmark.chainsaw_command(tool_benchmark.parse_arguments(base), tmp_path)
        assert [command[i + 1] for i, part in enumerate(command) if part == "-s"] == [
            str((tmp_path / "a").resolve()), str((tmp_path / "b").resolve())]
        assert "-r" not in command
        with_rules = tool_benchmark.parse_arguments([*base, "--chainsaw-rules", str(tmp_path / "rules")])
        command, _, _ = tool_benchmark.chainsaw_command(with_rules, tmp_path)
        assert command[command.index("-r") + 1] == str((tmp_path / "rules").resolve())

    @pytest.mark.parametrize("argv", [
        ["--chainsaw", "chainsaw", "--chainsaw-sigma", "sigma"],
        ["--chainsaw", "chainsaw", "--chainsaw-mapping", "map.yml"],
        ["--runs", "0"],
        ["--warmup", "-1"],
    ])
    def test_incomplete_arguments_are_refused(self, tool_benchmark, tmp_path, argv):
        with pytest.raises(SystemExit) as refused:
            tool_benchmark.parse_arguments(["--events", str(tmp_path), *argv])
        assert refused.value.code == 2


@pytest.mark.skipif(sys.platform == "win32", reason="the fake tools are shebang scripts")
class TestToolBenchmarkEndToEnd:
    @pytest.fixture
    def setup(self, tool_benchmark, tmp_path, monkeypatch):
        import tempfile

        scratch = tmp_path / "tmp"
        scratch.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(scratch))
        ruleset = tmp_path / "rules.json"
        ruleset.write_text(json.dumps([{
            "id": "bits", "title": "Bitsadmin", "level": "high",
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%bitsadmin%'"],
        }]))
        (tmp_path / "hayabusa").mkdir()
        (tmp_path / "chainsaw").mkdir()
        hayabusa = write_fake_tool(tmp_path / "hayabusa" / "hayabusa", FAKE_HAYABUSA)
        chainsaw = write_fake_tool(tmp_path / "chainsaw" / "chainsaw", FAKE_CHAINSAW)
        argv = ["--events", str(FIXTURES / "sample_bitsadmin.evtx"), "--zircolite-ruleset", str(ruleset),
                "--hayabusa", str(hayabusa), "--chainsaw", str(chainsaw),
                "--chainsaw-mapping", str(tmp_path / "map.yml"), "--chainsaw-sigma", str(tmp_path / "sigma"),
                "--runs", "2", "--warmup", "1"]
        return scratch, argv, chainsaw

    def test_report_covers_every_tool_and_stays_outside_worktree(self, tool_benchmark, setup, capsys):
        scratch, argv, _ = setup
        assert tool_benchmark.main(argv) == 0
        reports = list(scratch.glob("tool-benchmark-*.json"))
        assert len(reports) == 1 and list(scratch.iterdir()) == reports
        tools = json.loads(reports[0].read_text())["tools"]
        assert list(tools) == ["zircolite", "hayabusa", "chainsaw"]
        assert [len(tool["runs"]) for tool in tools.values()] == [2, 2, 2]
        assert (tools["zircolite"]["detections"], tools["zircolite"]["rules_matched"]) == (1, 1)
        assert tools["zircolite"]["rules_loaded"] == {"loaded": 1}
        assert (tools["hayabusa"]["version"], tools["hayabusa"]["detections"], tools["hayabusa"]["rules_matched"]) == (
            "4.1.0", 3, 2)
        assert tools["hayabusa"]["rules_loaded"] == {"loaded": 4658, "after channel filter": 2293}
        assert (tools["chainsaw"]["version"], tools["chainsaw"]["rules_loaded"]) == ("2.16.0", {"loaded": 3524})
        assert "| chainsaw | 2.16.0 | 3,524 |" in capsys.readouterr().out

    def test_a_failing_tool_stops_the_benchmark(self, tool_benchmark, setup):
        _, argv, chainsaw = setup
        write_fake_tool(chainsaw, FAKE_CHAINSAW.replace('print("[!] Loaded', 'raise SystemExit(3)\nprint("'))
        with pytest.raises(RuntimeError, match="chainsaw exited 3"):
            tool_benchmark.main(argv)


@pytest.fixture(scope="module")
def regression():
    return load_tool("sigma-regression")


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


def write_case(tmp_path, *, match_count=1, name="Positive Detection Test", rule_id=BITSADMIN_ID,
               title=BITSADMIN_TITLE, path=None):
    """Build a one-case regression_data tree around the tracked EVTX fixture."""
    case_dir = tmp_path / "regression_data" / "bitsadmin"
    case_dir.mkdir(parents=True)
    info = {
        "id": "11111111-2222-3333-4444-555555555555",
        "rule_metadata": [{"id": rule_id, "title": title}],
        "regression_tests_info": [{
            "name": name,
            "type": "evtx",
            "match_count": match_count,
            "path": path if path is not None else str(FIXTURES / "sample_bitsadmin.evtx"),
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
class TestSigmaRegressionUntrustedText:
    """Titles, ids and paths from info.yml must print literally.

    Put into Rich markup as-is, "[/]" raised MarkupError out of main() before
    the report was written, "[link=...]" planted hyperlinks, and style tags
    forged pass lines.
    """

    NEVER_FIRES = ({
        "title": BITSADMIN_TITLE, "id": BITSADMIN_ID, "level": "low", "tags": [],
        "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%not-here%' ESCAPE '\\'"],
    },)

    def run(self, regression, tmp_path, ruleset, **case):
        from io import StringIO

        from rich.console import Console

        data = write_case(tmp_path, **case)
        report = tmp_path / "report"
        buf = StringIO()
        recording = Console(file=buf, force_terminal=True, width=300,
                            theme=regression.REGRESSION_THEME, highlight=False)
        argv = [
            "sigma-regression.py",
            "--regression-data", str(data),
            "-r", str(write_ruleset(tmp_path, ruleset)),
            "--zircolite-config", str(CONFIG),
            "--report", str(report),
        ]
        with patch.object(sys, "argv", argv), patch.object(regression, "console", recording):
            code = regression.main()
        return code, buf.getvalue(), tmp_path / "report.json"

    @staticmethod
    def plain(out):
        return re.sub(r"\x1b\][^\x1b]*\x1b\\|\x1b\[[0-9;?]*[A-Za-z]", "", out)

    def test_failed_rule_title_with_markup(self, regression, tmp_path):
        title = f"{BITSADMIN_TITLE}[/][/] [green]PASS all good[/] [link=https://attacker.example]x[/link]"
        code, out, report = self.run(regression, tmp_path, self.NEVER_FIRES, title=title)
        assert code == 1
        assert report.exists(), "the report must still be written"
        assert self.plain(out).count(title) == 2, "failure line and summary row"
        assert "https://attacker.example" not in re.findall(r"\x1b\]8;[^;]*;([^\x1b]*)", out)

    def test_title_control_characters_do_not_reach_the_terminal(self, regression, tmp_path):
        title = f"{BITSADMIN_TITLE}\x1b[2J\x1b[H"
        code, out, _ = self.run(regression, tmp_path, self.NEVER_FIRES, title=title)
        assert code == 1
        assert "\x1b[2J" not in out
        assert f"{BITSADMIN_TITLE}[2J[H" in self.plain(out)

    def test_missing_data_file_path_with_markup(self, regression, tmp_path):
        path = "x[/][/] [link=https://attacker.example]click[/link]"
        code, out, report = self.run(regression, tmp_path, BITSADMIN_RULESET, path=path)
        assert code == 0
        assert report.exists()
        assert path in self.plain(out)
        assert "https://attacker.example" not in re.findall(r"\x1b\]8;[^;]*;([^\x1b]*)", out)

    def test_failed_rule_lines_escape_every_field(self, regression, tmp_path):
        from rich.text import Text
        lines = regression.format_failed_rule_lines(
            tmp_path, tmp_path / "x.evtx", "t[/]", "i[/]", "err [/] [bold]x",
        )
        assert [Text.from_markup(line).plain.strip() for line in lines[1:]] == [
            "t[/] (id: i[/])", "err [/] [bold]x",
        ]


# ---------------------------------------------------------------------------
# tools/package-release.py
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def release():
    return load_tool("package-release")


FAKE_VERSION = "1.2.3"
PYTHON_LICENCE_TEXT = "PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2 (test copy)"


def make_checkout(root, executable="Zircolite"):
    """Just what the packager reads from a checkout, around a fake onedir build."""
    (root / "zircolite").mkdir(parents=True)
    (root / "zircolite" / "__init__.py").write_text(
        f'"""Docstring."""\n\n__version__ = "{FAKE_VERSION}"\n', encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "Zircolite"\nversion = "{FAKE_VERSION}"\ndependencies = [\n'
        '    "rich>=14",\n]\n\n[tool.other]\nversion = "9.9.9"\n', encoding="utf-8")
    for directory, name in [("config", "config.yaml"), ("rules", "rules_linux.json"),
                            ("templates", "exportForSplunk.tmpl"), ("gui", "zircogui.zip"),
                            ("docs", "Usage.md"), ("pics", "Zircolite.png")]:
        (root / directory).mkdir()
        (root / directory / name).write_text(directory, encoding="utf-8")
    (root / "config" / "__pycache__").mkdir()
    (root / "config" / "__pycache__" / "stale.cpython-314.pyc").write_bytes(b"")
    (root / "README.md").write_text("readme", encoding="utf-8")
    (root / "LICENSE").write_text("LGPL", encoding="utf-8")
    onedir = root / "dist" / "Zircolite"
    (onedir / "_internal").mkdir(parents=True)
    (onedir / "_internal" / "base_library.zip").write_bytes(b"PK")
    binary = onedir / executable
    binary.write_text(f"#!/bin/sh\necho banner v{FAKE_VERSION}\necho 'Zircolite - v{FAKE_VERSION}'\n",
                      encoding="utf-8")
    binary.chmod(0o755)
    return root


@pytest.fixture
def checkout(tmp_path, release, monkeypatch):
    """A fake checkout, with the interpreter licence pinned so no test depends on the host Python."""
    licence = tmp_path / "PYTHON-LICENSE.txt"
    licence.write_text(PYTHON_LICENCE_TEXT, encoding="utf-8")
    monkeypatch.setattr(release, "python_licence", lambda: licence)
    return make_checkout(tmp_path / "checkout")


def package(release, root, target, monkeypatch, capsys):
    monkeypatch.setenv("ZIRCOLITE_TARGET", target)
    code = release.main(["--root", str(root)])
    captured = capsys.readouterr()
    return code, captured.out.strip(), captured.err


def unix_mode(bundle: zipfile.ZipFile, name: str) -> int:
    info = bundle.getinfo(name)
    assert info.create_system == 3, f"{name} is not recorded as made on Unix"
    return info.external_attr >> 16


class TestPackageArchive:
    @pytest.mark.parametrize("target", ["linux-x64", "linux-arm64", "macos-arm64"])
    def test_posix_targets_get_a_zip(self, release, checkout, target, monkeypatch, capsys):
        code, printed, _ = package(release, checkout, target, monkeypatch, capsys)
        assert code == 0
        archive = checkout / "dist" / f"Zircolite-{FAKE_VERSION}-{target}.zip"
        assert Path(printed) == archive
        with zipfile.ZipFile(archive) as bundle:
            assert bundle.testzip() is None

    def test_archive_layout(self, release, checkout, monkeypatch, capsys):
        code, printed, _ = package(release, checkout, "linux-x64", monkeypatch, capsys)
        assert code == 0
        top = f"Zircolite-{FAKE_VERSION}-linux-x64"
        with zipfile.ZipFile(printed) as bundle:
            names = {name.rstrip("/") for name in bundle.namelist()}
        assert all(name == top or name.startswith(f"{top}/") for name in names)
        for expected in ["Zircolite", "_internal/base_library.zip", "config/config.yaml",
                         "rules/rules_linux.json", "templates/exportForSplunk.tmpl",
                         "gui/zircogui.zip", "docs/Usage.md", "pics/Zircolite.png",
                         "README.md", "LICENSE", "THIRD_PARTY_LICENSES"]:
            assert f"{top}/{expected}" in names, expected
        assert not [name for name in names if "__pycache__" in name]

    def test_executable_bit_survives(self, release, checkout, monkeypatch, capsys):
        # Checked in the archive itself: upload-artifact zips loose files, which drops the bit.
        _, printed, _ = package(release, checkout, "macos-arm64", monkeypatch, capsys)
        top = f"Zircolite-{FAKE_VERSION}-macos-arm64"
        with zipfile.ZipFile(printed) as bundle:
            assert unix_mode(bundle, f"{top}/Zircolite") & 0o111 == 0o111
            assert unix_mode(bundle, f"{top}/README.md") & 0o111 == 0

    def test_executable_bit_is_restored_when_the_build_lost_it(self, release, checkout,
                                                              monkeypatch, capsys):
        binary = checkout / "dist" / "Zircolite" / "Zircolite"
        binary.chmod(stat.S_IRUSR | stat.S_IWUSR)
        _, printed, _ = package(release, checkout, "linux-arm64", monkeypatch, capsys)
        with zipfile.ZipFile(printed) as bundle:
            mode = unix_mode(bundle, f"Zircolite-{FAKE_VERSION}-linux-arm64/Zircolite")
        assert mode & 0o111 == 0o111

    @pytest.mark.skipif(os.name == "nt" or not shutil.which("unzip"),
                        reason="needs unzip and symlinks, as a Linux or macOS user has")
    def test_unzip_restores_the_executable_and_symlinks(self, release, checkout, tmp_path,
                                                         monkeypatch, capsys):
        # What a user gets, rather than what the archive records.
        (checkout / "dist" / "Zircolite" / "_internal" / "Python").symlink_to("base_library.zip")
        _, printed, _ = package(release, checkout, "macos-arm64", monkeypatch, capsys)
        extracted = tmp_path / "extracted"
        unzip = shutil.which("unzip")
        assert unzip
        subprocess.run([unzip, "-q", printed, "-d", str(extracted)], check=True)
        top = extracted / f"Zircolite-{FAKE_VERSION}-macos-arm64"
        assert os.access(top / "Zircolite", os.X_OK)
        link = top / "_internal" / "Python"
        assert link.is_symlink() and os.readlink(link) == "base_library.zip"

    @pytest.mark.parametrize("target", ["windows-x64", "windows-arm64"])
    def test_windows_targets_get_a_zip(self, release, tmp_path, target, monkeypatch, capsys):
        licence = tmp_path / "PYTHON-LICENSE.txt"
        licence.write_text(PYTHON_LICENCE_TEXT, encoding="utf-8")
        monkeypatch.setattr(release, "python_licence", lambda: licence)
        root = make_checkout(tmp_path / "checkout", executable="Zircolite.exe")
        code, printed, _ = package(release, root, target, monkeypatch, capsys)
        assert code == 0
        archive = root / "dist" / f"Zircolite-{FAKE_VERSION}-{target}.zip"
        assert Path(printed) == archive
        top = f"Zircolite-{FAKE_VERSION}-{target}"
        with zipfile.ZipFile(archive) as bundle:
            assert bundle.testzip() is None
            names = set(bundle.namelist())
        for expected in ["Zircolite.exe", "_internal/base_library.zip", "rules/rules_linux.json",
                         "LICENSE", "THIRD_PARTY_LICENSES"]:
            assert f"{top}/{expected}" in names, expected

    def test_source_date_epoch_caps_timestamps(self, release, checkout, monkeypatch, capsys):
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "946684800")
        _, printed, _ = package(release, checkout, "linux-x64", monkeypatch, capsys)
        with zipfile.ZipFile(printed) as bundle:
            assert {info.date_time for info in bundle.infolist()} == {(2000, 1, 1, 0, 0, 0)}

    def test_repackaging_replaces_the_previous_run(self, release, checkout, monkeypatch, capsys):
        package(release, checkout, "linux-x64", monkeypatch, capsys)
        stale = checkout / "dist" / f"Zircolite-{FAKE_VERSION}-linux-x64" / "stale.txt"
        stale.write_text("left over", encoding="utf-8")
        code, printed, _ = package(release, checkout, "linux-x64", monkeypatch, capsys)
        assert code == 0
        assert not stale.exists()
        with zipfile.ZipFile(printed) as bundle:
            assert not [name for name in bundle.namelist() if name.endswith("stale.txt")]


class TestPackageRefusals:
    def test_missing_build(self, release, checkout, monkeypatch, capsys):
        shutil.rmtree(checkout / "dist" / "Zircolite")
        code, printed, err = package(release, checkout, "linux-x64", monkeypatch, capsys)
        assert code == 1 and printed == ""
        assert "pyinstaller --noconfirm Zircolite.spec" in err

    def test_missing_executable(self, release, checkout, monkeypatch, capsys):
        # The fake build has a POSIX executable; a Windows target wants Zircolite.exe.
        code, _, err = package(release, checkout, "windows-x64", monkeypatch, capsys)
        assert code == 1
        assert "Zircolite.exe does not exist" in err

    def test_onefile_build_is_refused(self, release, checkout, monkeypatch, capsys):
        shutil.rmtree(checkout / "dist" / "Zircolite" / "_internal")
        code, _, err = package(release, checkout, "linux-x64", monkeypatch, capsys)
        assert code == 1
        assert "not a onedir build" in err

    @pytest.mark.skipif(os.name == "nt", reason="creating a symlink needs a privilege on Windows")
    @pytest.mark.parametrize("link", ["docs/Alias.md", "config/nested/config.yaml", "README.md"])
    def test_symlink_in_the_copied_sources_fails_a_posix_target(self, release, checkout, link,
                                                                monkeypatch, capsys):
        # Only the Windows zip cannot carry it, but the linux-x64 canary must catch it.
        path = checkout / link
        path.parent.mkdir(exist_ok=True)
        path.unlink(missing_ok=True)
        path.symlink_to(checkout / "LICENSE")
        code, printed, err = package(release, checkout, "linux-x64", monkeypatch, capsys)
        assert code == 1 and printed == ""
        assert "symlink" in err and link in err
        assert not list((checkout / "dist").glob("Zircolite-*"))

    @pytest.mark.skipif(os.name == "nt", reason="creating a symlink needs a privilege on Windows")
    def test_symlinks_inside_the_build_are_kept(self, release, checkout, monkeypatch, capsys):
        # A macOS build links into Python.framework; the archive must keep that.
        internal = checkout / "dist" / "Zircolite" / "_internal"
        (internal / "Python").symlink_to("base_library.zip")
        code, printed, _ = package(release, checkout, "macos-arm64", monkeypatch, capsys)
        assert code == 0
        name = f"Zircolite-{FAKE_VERSION}-macos-arm64/_internal/Python"
        with zipfile.ZipFile(printed) as bundle:
            assert stat.S_ISLNK(unix_mode(bundle, name))
            assert bundle.read(name) == b"base_library.zip"

    @pytest.mark.skipif(os.name == "nt", reason="creating a symlink needs a privilege on Windows")
    def test_a_symlink_in_a_windows_build_is_refused(self, release, tmp_path, monkeypatch, capsys):
        licence = tmp_path / "PYTHON-LICENSE.txt"
        licence.write_text(PYTHON_LICENCE_TEXT, encoding="utf-8")
        monkeypatch.setattr(release, "python_licence", lambda: licence)
        root = make_checkout(tmp_path / "checkout", executable="Zircolite.exe")
        (root / "dist" / "Zircolite" / "_internal" / "alias").symlink_to("base_library.zip")
        code, printed, err = package(release, root, "windows-x64", monkeypatch, capsys)
        assert code == 1 and printed == ""
        assert "symlink" in err and "Windows" in err

    @pytest.mark.parametrize("value", [None, "", "linux-x86", "macos-x64"])
    def test_target_must_be_known(self, release, checkout, value, monkeypatch, capsys):
        if value is None:
            monkeypatch.delenv("ZIRCOLITE_TARGET", raising=False)
        else:
            monkeypatch.setenv("ZIRCOLITE_TARGET", value)
        assert release.main(["--root", str(checkout)]) == 1
        err = capsys.readouterr().err
        assert "windows-arm64" in err
        assert not list((checkout / "dist").glob("Zircolite-*"))


class TestThirdPartyLicences:
    @pytest.fixture
    def notices(self, release, checkout, monkeypatch, capsys):
        code, _, _ = package(release, checkout, "linux-x64", monkeypatch, capsys)
        assert code == 0
        staged = checkout / "dist" / f"Zircolite-{FAKE_VERSION}-linux-x64" / "THIRD_PARTY_LICENSES"
        return staged.read_text(encoding="utf-8")

    def titles(self, release, notices):
        # A header is separator, title, optional "License:" line, separator.
        lines = notices.splitlines()
        return [lines[i + 1] for i in range(len(lines) - 2)
                if lines[i] == release.SEPARATOR and lines[i + 1]
                and (lines[i + 2] == release.SEPARATOR or lines[i + 2].startswith("License: "))]

    def test_every_runtime_dependency_has_a_section(self, release, notices):
        titles = {title.split(" ")[0].lower() for title in self.titles(release, notices)}
        for name in ["rich", "pysigma", "orjson", "lxml", "py7zr", "requests", "pyroaring"]:
            assert name in titles, name
        # The project itself is under LICENSE, not in the third-party file.
        assert "zircolite" not in titles

    def test_evtx_falls_back_to_the_vendored_text(self, notices):
        # The evtx wheel ships no licence file at all.
        assert re.search(r"^evtx \S+$", notices, re.MULTILINE)
        assert "--- tools/licenses/evtx.txt ---" in notices
        assert "Omer Ben-Amram" in notices

    def test_interpreter_bootloader_and_rules(self, release, notices):
        assert PYTHON_LICENCE_TEXT in notices
        assert re.search(r"^pyinstaller \S+$", notices, re.MULTILINE)
        assert "bootloader" in notices.lower()
        assert "Detection Rule License (DRL) 1.1" in notices
        titles = self.titles(release, notices)
        assert titles[0].startswith("Python ")
        assert titles[-1] == "Detection rules (rules/)"

    def vendored_without(self, release, tmp_path, monkeypatch, missing):
        vendored = tmp_path / "vendored"
        shutil.copytree(release.VENDORED_LICENCES, vendored)
        (vendored / missing).unlink()
        monkeypatch.setattr(release, "VENDORED_LICENCES", vendored)

    def test_a_distribution_without_licence_fails(self, release, checkout, tmp_path,
                                                  monkeypatch, capsys):
        self.vendored_without(release, tmp_path, monkeypatch, "evtx.txt")
        code, printed, err = package(release, checkout, "linux-x64", monkeypatch, capsys)
        assert code == 1 and printed == ""
        assert "no licence text for: evtx" in err
        # Nothing half-built is left for a later step to pick up.
        assert not list((checkout / "dist").glob("Zircolite-*"))

    def test_the_rules_licence_is_required(self, release, checkout, tmp_path, monkeypatch, capsys):
        self.vendored_without(release, tmp_path, monkeypatch, "DRL-1.1.txt")
        code, _, err = package(release, checkout, "linux-x64", monkeypatch, capsys)
        assert code == 1
        assert "DRL-1.1.txt" in err

    @pytest.mark.parametrize("target", ["linux-x64", "linux-arm64", "macos-arm64"])
    def test_posix_targets_carry_the_runtime_libraries(self, release, checkout, target):
        notices = release.third_party_licences(FAKE_VERSION, target)
        assert self.titles(release, notices)[1] == "Libraries linked into the Python runtime"
        marker = "--- tools/licenses/python-runtime-libraries.txt ---"
        assert marker in notices
        runtime = notices.split(marker, 1)[1].split(release.SEPARATOR, 1)[0]
        # Apache-2.0 section 4(a) requires the whole text, not a pointer to it.
        openssl = runtime.split("\nOpenSSL 3\nLicense: Apache-2.0\n", 1)[1].split("\nlibffi\n", 1)[0]
        assert "Apache License\n                           Version 2.0, January 2004" in openssl
        assert "END OF TERMS AND CONDITIONS" in openssl
        for library in ["libffi", "mpdecimal", "liblzma", "libbzip2", "Zstandard", "Expat",
                        "zlib", "SQLite", "libedit", "ncurses", "libuuid"]:
            assert re.search(rf"^.*{library}.*\nLicense: ", runtime, re.MULTILINE), library

    @pytest.mark.parametrize("target", ["windows-x64", "windows-arm64"])
    def test_windows_leaves_the_runtime_libraries_to_the_python_licence(self, release, checkout,
                                                                        target):
        notices = release.third_party_licences(FAKE_VERSION, target)
        assert "Libraries linked into the Python runtime" not in self.titles(release, notices)
        assert "python-runtime-libraries.txt" not in notices

    def test_the_runtime_libraries_notice_is_required(self, release, checkout, tmp_path,
                                                      monkeypatch, capsys):
        self.vendored_without(release, tmp_path, monkeypatch, "python-runtime-libraries.txt")
        code, _, err = package(release, checkout, "macos-arm64", monkeypatch, capsys)
        assert code == 1
        assert "python-runtime-libraries.txt is missing" in err

    def test_python_licence_is_found_beside_the_stdlib(self, release, tmp_path, monkeypatch):
        stdlib = tmp_path / "lib" / "python3.14"
        stdlib.mkdir(parents=True)
        (stdlib / "LICENSE.txt").write_text("PSF", encoding="utf-8")
        monkeypatch.setattr(release.sysconfig, "get_path", lambda name: str(stdlib))
        assert release.python_licence() == stdlib / "LICENSE.txt"

    def test_python_licence_is_found_in_a_windows_layout(self, release, tmp_path, monkeypatch):
        (tmp_path / "Lib").mkdir()
        (tmp_path / "LICENSE.txt").write_text("PSF", encoding="utf-8")
        monkeypatch.setattr(release.sysconfig, "get_path", lambda name: str(tmp_path / "Lib"))
        monkeypatch.setattr(release.sys, "base_prefix", str(tmp_path))
        assert release.python_licence() == tmp_path / "LICENSE.txt"

    def test_missing_python_licence_fails(self, release, tmp_path, monkeypatch):
        monkeypatch.setattr(release.sysconfig, "get_path", lambda name: str(tmp_path / "lib"))
        monkeypatch.setattr(release.sys, "base_prefix", str(tmp_path))
        with pytest.raises(release.PackagingError, match="Python licence"):
            release.python_licence()

    def test_only_windows_arm64_may_lack_jq(self, release):
        assert dict(release.ALLOWED_ABSENT) == {"windows-arm64": frozenset({"jq"})}


class FakeDistribution:
    def __init__(self, name, requires=()):
        self.metadata = {"Name": name}
        self.requires = list(requires)


def fake_lookup(*distributions):
    table = {dist.metadata["Name"].lower(): dist for dist in distributions}

    def lookup(name):
        try:
            return table[name.lower()]
        except KeyError:
            raise importlib.metadata.PackageNotFoundError(name) from None
    return lookup


class TestRuntimeClosure:
    def names(self, closure):
        return [dist.metadata["Name"] for dist in closure]

    def test_walks_transitive_requirements_without_the_root(self, release):
        lookup = fake_lookup(FakeDistribution("root", ["a>=1", "b (>=2)"]),
                             FakeDistribution("a", ["c"]), FakeDistribution("b"),
                             FakeDistribution("c", ["a"]))
        assert self.names(release.runtime_closure("root", lookup=lookup)) == ["a", "b", "c"]

    def test_extras_nobody_asked_for_are_skipped(self, release):
        lookup = fake_lookup(FakeDistribution("root", ["a", 'pytest; extra == "test"']),
                             FakeDistribution("a", ['sphinx ; extra == "docs"']))
        assert self.names(release.runtime_closure("root", lookup=lookup)) == ["a"]

    def test_requested_extras_are_followed(self, release):
        lookup = fake_lookup(FakeDistribution("root", ["a[Fast_Path]"]),
                             FakeDistribution("a", ['speedups; extra == "fast-path"']),
                             FakeDistribution("speedups"))
        assert self.names(release.runtime_closure("root", lookup=lookup)) == ["a", "speedups"]

    def test_markers_false_here_are_skipped(self, release):
        lookup = fake_lookup(FakeDistribution("root", [
            'pypy-only; platform_python_implementation == "PyPy"',
            'old-python; python_version < "3.0"',
            "present",
        ]), FakeDistribution("present"))
        assert self.names(release.runtime_closure("root", lookup=lookup)) == ["present"]

    def test_absent_requirement_fails_and_names_who_wanted_it(self, release):
        lookup = fake_lookup(FakeDistribution("root", ["a"]), FakeDistribution("a", ["gone"]))
        with pytest.raises(release.PackagingError, match=r"gone \(required by a\)"):
            release.runtime_closure("root", lookup=lookup)

    def test_allow_list_covers_only_what_it_names(self, release):
        lookup = fake_lookup(FakeDistribution("root", ["a", "jq"]), FakeDistribution("a"))
        assert self.names(release.runtime_closure("root", frozenset({"jq"}), lookup)) == ["a"]
        lookup = fake_lookup(FakeDistribution("root", ["b", "jq"]))
        with pytest.raises(release.PackagingError, match="b"):
            release.runtime_closure("root", frozenset({"jq"}), lookup)

    def test_uninstalled_project_says_how_to_fix_it(self, release):
        with pytest.raises(release.PackagingError, match="pdm install"):
            release.runtime_closure("root", lookup=fake_lookup())


class TestShippedLicences:
    """Licence files come from the distribution's own metadata directory only."""

    @pytest.fixture
    def distribution(self, tmp_path):
        info = tmp_path / "demo-1.0.dist-info"
        (info / "licenses").mkdir(parents=True)
        (info / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: demo\nVersion: 1.0\nLicense-Expression: MIT\n"
            "License-File: LICENSE\n", encoding="utf-8")
        (info / "licenses" / "LICENSE").write_text("MIT text\r\n", encoding="utf-8")
        (info / "COPYING.rst").write_text("copying text", encoding="utf-8")
        (info / "WHEEL").write_text("Wheel-Version: 1.0\n", encoding="utf-8")
        vendored = tmp_path / "demo" / "_vendor" / "other-2.0.dist-info"
        vendored.mkdir(parents=True)
        (vendored / "LICENSE").write_text("vendored text", encoding="utf-8")
        (info / "RECORD").write_text("\n".join([
            "demo-1.0.dist-info/METADATA,,", "demo-1.0.dist-info/licenses/LICENSE,,",
            "demo-1.0.dist-info/COPYING.rst,,", "demo-1.0.dist-info/WHEEL,,",
            "demo-1.0.dist-info/RECORD,,", "demo/_vendor/other-2.0.dist-info/LICENSE,,",
        ]) + "\n", encoding="utf-8")
        return importlib.metadata.PathDistribution(info)

    def test_declared_and_licence_named_files(self, release, distribution):
        assert release.shipped_licences(distribution) == [
            ("COPYING.rst", "copying text"),
            ("licenses/LICENSE", "MIT text"),
        ]

    def test_declared_licence_prefers_the_expression(self, release, distribution):
        assert release.declared_licence(distribution) == "MIT"


LINUX_310 = {
    "implementation_name": "cpython", "implementation_version": "3.10.14", "os_name": "posix",
    "platform_machine": "x86_64", "platform_python_implementation": "CPython",
    "platform_release": "6.8.0", "platform_system": "Linux", "platform_version": "#1 SMP",
    "python_full_version": "3.10.14", "python_version": "3.10", "sys_platform": "linux",
    "extra": "",
}


class TestMarkers:
    """Markers are evaluated for the environment given, whatever the host is."""

    @pytest.mark.parametrize(("marker", "expected"), [
        ('sys_platform == "linux" and python_version < "3.11"', True),
        ('os_name == "nt" or platform_machine == "ARM64"', False),
        ('python_full_version < "3.10.14.post1"', True),
        ('python_version == "3.10.*"', True),
        ('extra == "test"', False),
    ])
    def test_evaluates_against_the_given_environment(self, release, marker, expected):
        assert release.evaluate_marker(marker, LINUX_310) is expected

    def test_extras_compare_normalised(self, release):
        assert release.evaluate_marker('extra == "Test_Extra"', {**LINUX_310, "extra": "test-extra"})

    @pytest.mark.parametrize("marker", [
        'python_version <',
        'python_version < "3.14" and',
        '(python_version < "3.14"',
        'no_such_variable == "x"',
        'python_version = "3.14"',
        'python_version ~= "3"',
    ])
    def test_malformed_markers_fail_loudly(self, release, marker):
        with pytest.raises(release.PackagingError, match="cannot evaluate marker"):
            release.evaluate_marker(marker, LINUX_310)

    def test_requirement_parsing(self, release):
        assert release.parse_requirement("coverage[toml, Fast_Path]>=5.2; extra == 'test'") == (
            "coverage", frozenset({"toml", "fast-path"}), "extra == 'test'")
        assert release.parse_requirement("diskcache (>=5.6.3,<6.0.0)") == (
            "diskcache", frozenset(), None)


class TestVersionsAndTag:
    def test_versions_are_read_without_importing(self, release, checkout):
        assert release.package_version(checkout) == FAKE_VERSION
        # Only the [project] table counts; [tool.other] also has a version key.
        assert release.pyproject_version(checkout) == FAKE_VERSION

    def test_real_checkout_versions_agree(self, release):
        from zircolite import __version__

        assert release.package_version(WORKSPACE_ROOT) == __version__
        assert release.pyproject_version(WORKSPACE_ROOT) == __version__

    def test_version_is_found_after_the_banner(self, release):
        output = ("\x1b[1m███ banner ███\x1b[0m\n   v9.9.9\n\n"
                  "\x1b[32mZircolite - v3.9.0\x1b[0m\n")
        assert release.version_from_output(output) == "3.9.0"
        with pytest.raises(release.PackagingError):
            release.version_from_output("banner only v3.9.0\n")

    def check(self, release, root, tag, monkeypatch, capsys, binary=FAKE_VERSION):
        monkeypatch.setattr(release, "binary_version", lambda executable: binary)
        monkeypatch.delenv("ZIRCOLITE_TARGET", raising=False)
        code = release.main(["--root", str(root), "--check-tag", tag])
        return code, capsys.readouterr().err

    def test_matching_tag_passes(self, release, checkout, monkeypatch, capsys):
        assert self.check(release, checkout, f"v{FAKE_VERSION}", monkeypatch, capsys)[0] == 0

    @pytest.mark.parametrize("tag", [FAKE_VERSION, "v1.2.4", "v1.2.3.0", "refs/tags/v1.2.3"])
    def test_other_tags_fail_and_name_every_source(self, release, checkout, tag,
                                                    monkeypatch, capsys):
        code, err = self.check(release, checkout, tag, monkeypatch, capsys)
        assert code == 1
        assert "__version__" in err and "pyproject.toml" in err and "--version" in err

    def test_pyproject_drift_is_named(self, release, checkout, monkeypatch, capsys):
        pyproject = checkout / "pyproject.toml"
        pyproject.write_text(pyproject.read_text(encoding="utf-8").replace(
            f'version = "{FAKE_VERSION}"', 'version = "1.2.2"', 1), encoding="utf-8")
        code, err = self.check(release, checkout, f"v{FAKE_VERSION}", monkeypatch, capsys)
        assert code == 1
        assert "pyproject.toml [project] version: 1.2.2" in err
        assert "__version__" not in err

    def test_stale_binary_is_named(self, release, checkout, monkeypatch, capsys):
        code, err = self.check(release, checkout, f"v{FAKE_VERSION}", monkeypatch, capsys,
                               binary="1.2.2")
        assert code == 1
        assert "--version: 1.2.2" in err
        assert "pyproject.toml" not in err

    @pytest.mark.skipif(os.name == "nt", reason="the fake binary is a shell script")
    def test_binary_version_runs_the_build(self, release, checkout):
        binary = checkout / "dist" / "Zircolite" / "Zircolite"
        assert release.binary_version(binary) == FAKE_VERSION
        binary.write_text("#!/bin/sh\necho 'Zircolite - v1.2.3'\nexit 3\n", encoding="utf-8")
        with pytest.raises(release.PackagingError, match="exited 3"):
            release.binary_version(binary)

    def test_missing_binary_fails(self, release, tmp_path):
        with pytest.raises(release.PackagingError, match="does not exist"):
            release.binary_version(tmp_path / "Zircolite")


# ---------------------------------------------------------------------------
# tools/install-win-arm64.py
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def win_arm64():
    return load_tool("install-win-arm64")


EXPORT = """\
# This file is @generated by PDM.
# Please do not edit it manually.

colorama==0.4.6; sys_platform == "win32" \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
evtx==0.12.1; python_version == "3.14" or python_version == "3.10" \\
    --hash=sha256:cccc \\
    --hash=sha256:dddd
evtx-tools==1.0 \\
    --hash=sha256:eeee
jq==1.12.0; python_version == "3.14" \\
    --hash=sha256:ffff
jqlang==2.0
pysigma==1.5.0 \\
    --hash=sha256:9999
"""


class TestWinArm64Requirements:
    def test_drops_evtx_and_jq_with_their_hashes(self, win_arm64):
        text, removed = win_arm64.drop_requirements(EXPORT)
        assert removed == {"evtx", "jq"}
        assert "evtx==" not in text and "jq==" not in text
        for gone in ("cccc", "dddd", "ffff"):
            assert gone not in text
        # Neighbours keep every line, so hash-checking mode still accepts the file.
        for kept in ("colorama==0.4.6", "aaaa", "bbbb", "evtx-tools==1.0", "eeee",
                     "jqlang==2.0", "pysigma==1.5.0", "9999", "# This file is @generated"):
            assert kept in text

    def test_every_kept_continuation_is_closed(self, win_arm64):
        text, _ = win_arm64.drop_requirements(EXPORT)
        records = win_arm64.requirement_records(text)
        assert all(not record[-1].rstrip().endswith("\\") for record in records)

    def test_names_are_normalised(self, win_arm64):
        text, removed = win_arm64.drop_requirements("EVTX==0.12.1\nJQ==1.0 \\\n    --hash=x\n")
        assert removed == {"evtx", "jq"}
        assert text == ""

    def test_crlf_export(self, win_arm64):
        text, removed = win_arm64.drop_requirements(EXPORT.replace("\n", "\r\n"))
        assert removed == {"evtx", "jq"}
        assert "cccc" not in text and "9999" in text

    def test_recipe(self, win_arm64, tmp_path, monkeypatch):
        commands = []

        def fake_run(command):
            commands.append(command)
            if command[:2] == ["pdm", "export"]:
                (tmp_path / "dist" / "reqs.txt").write_text(EXPORT, encoding="utf-8")

        wheels = tmp_path / "wheels"
        wheels.mkdir()
        wheel = wheels / "evtx-0.12.1-cp310-abi3-win_arm64.whl"
        wheel.write_bytes(b"")
        monkeypatch.setattr(win_arm64, "ROOT", tmp_path)
        monkeypatch.setattr(win_arm64, "run", fake_run)
        assert win_arm64.main(["--wheels", str(wheels)]) == 0

        uv_install = ["uv", "pip", "install", "--no-config", "--no-deps", "--python", ".venv"]
        assert commands == [
            ["pdm", "export", "-G", "dev", "-o", "dist/reqs.txt"],
            ["uv", "venv", "--clear", ".venv", "--python", sys.executable],
            [*uv_install, "-r", "dist/reqs.txt"],
            [*uv_install, str(wheel.resolve())],
            [*uv_install, "-e", "."],
            ["pdm", "use", "-f", ".venv"],
        ]
        filtered = (tmp_path / "dist" / "reqs.txt").read_text(encoding="utf-8")
        assert "evtx==" not in filtered and "jq==" not in filtered and "pysigma==" in filtered

    def test_export_without_jq_stops_the_recipe(self, win_arm64, tmp_path, monkeypatch, capsys):
        commands = []

        def fake_run(command):
            commands.append(command)
            if command[:2] == ["pdm", "export"]:
                (tmp_path / "dist" / "reqs.txt").write_text("evtx==0.12.1\n", encoding="utf-8")

        wheels = tmp_path / "wheels"
        wheels.mkdir()
        (wheels / "evtx-0.12.1-cp310-abi3-win_arm64.whl").write_bytes(b"")
        monkeypatch.setattr(win_arm64, "ROOT", tmp_path)
        monkeypatch.setattr(win_arm64, "run", fake_run)
        assert win_arm64.main(["--wheels", str(wheels)]) == 1
        assert "no requirement for: jq" in capsys.readouterr().err
        assert len(commands) == 1

    @pytest.mark.parametrize("wheels", [[], ["evtx-0.12.1-a.whl", "evtx-0.12.1-b.whl"]])
    def test_exactly_one_evtx_wheel(self, win_arm64, tmp_path, wheels):
        for name in wheels:
            (tmp_path / name).write_bytes(b"")
        with pytest.raises(win_arm64.InstallError, match="exactly one evtx"):
            win_arm64.evtx_wheel(tmp_path)
