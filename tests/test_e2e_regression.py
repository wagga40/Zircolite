"""End-to-end regression tests over the tracked sample logs.

The rest of the suite mostly builds events as Python dicts, which is how
several silent ingestion bugs survived: a reader can stop parsing a format
entirely and every dict-based test still passes. These drive the real CLI over
the real fixtures instead, and assert on what came out.

Three things are pinned here:

* every supported input format still ingests and still detects;
* per-file, --unified-db and parallel produce the *same* detections, so a
  change cannot quietly depend on which mode auto-mode chose;
* the detections for a fixture match a committed expectation, so a change that
  alters which events match has to say so in the diff.

With ``ZIRCOLITE_BINARY`` set, every run goes through that executable instead
of the in-process CLI, so a built binary has to pass the same checks.
"""

import csv
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import pytest

WORKSPACE_ROOT = Path(__file__).parent.parent
FIXTURES = WORKSPACE_ROOT / "tests" / "fixtures"
GOLDEN = Path(__file__).parent / "golden"

sys.path.insert(0, str(WORKSPACE_ROOT))

from zircolite import cli as zircolite_script  # noqa: E402

# Matches anything, so the assertion is "the reader produced events", not "these
# particular rules happen to fire on this sample".
MATCH_ALL_RULESET = json.dumps([{
    "title": "Any event",
    "id": "e2e-00000000-0000-0000-0000-000000000001",
    "level": "informational",
    "tags": [],
    "rule": ["SELECT * FROM logs"],
}])

# fixture -> the flags that select its format. EVTX has no flag: it is the
# default. Kept in step with INPUT_FORMATS by test_every_format_is_covered.
FORMAT_FIXTURES = [
    ("evtx", "sample_bitsadmin.evtx", []),
    ("json", "sample_events.json", ["-j"]),
    ("json", "winlogbeat_sysmon_sample.json", ["-j"]),
    ("csv", "sample_events.csv", ["--csv-input"]),
    ("xml", "xml_events_sample.xml", ["-x"]),
    ("auditd", "audit_sample.log", ["-AU"]),
    ("auditd", "audit_enriched_sample.log", ["-AU"]),
    ("sysmon_linux", "sysmon_linux_sample.log", ["-S"]),
    ("evtxtract", "evtxtract_sample.log", ["--evtxtract-input"]),
    ("sqlite", "sample_bitsadmin.db", ["-D"]),
]


def run_zircolite(tmp_path, source, flags, ruleset=MATCH_ALL_RULESET, extra=(), outname="detected.json",
                  read=lambda path: json.loads(path.read_text())):
    """Run the CLI over *source* and return the parsed detections."""
    ruleset_file = tmp_path / "ruleset.json"
    ruleset_file.write_text(ruleset)
    outfile = tmp_path / outname

    argv = [
        "zircolite.py",
        "-e", str(source),
        "-r", str(ruleset_file),
        "-o", str(outfile),
        "-l", str(tmp_path / "zircolite.log"),
        *flags,
        *extra,
    ]
    binary = os.environ.get("ZIRCOLITE_BINARY")
    if binary:
        # Run from tmp_path so config/ and the transforms come from the bundle,
        # not from the checkout the tests happen to run in. A relative path
        # names the binary from where pytest started, so it is resolved first.
        binary = str(Path(binary).resolve())
        result = subprocess.run(
            [binary, *argv[1:]], cwd=tmp_path, capture_output=True,
            encoding="utf-8", errors="replace", timeout=240,
        )
        assert result.returncode == 0, (
            f"{binary} exited {result.returncode}\n"
            f"--- stdout\n{result.stdout}\n--- stderr\n{result.stderr}"
        )
    else:
        with patch("sys.argv", argv):
            zircolite_script.main()

    assert outfile.exists(), f"no output written for {source}"
    return read(outfile)


def detection_summary(detections):
    """(title, total match count) per rule, order-independent.

    Totalled per rule rather than per entry: per-file mode emits one entry per
    file and --unified-db emits one for the whole corpus, which is the point of
    the flag. What must not differ is which rules fired, on how many events.
    """
    totals: dict[str, int] = {}
    for detection in detections:
        totals[detection["title"]] = (
            totals.get(detection["title"], 0) + len(detection["matches"])
        )
    return sorted(totals.items())


class TestFormatParity:
    """Every supported format still reads its sample and still detects."""

    @pytest.mark.parametrize(
        "fmt,filename,flags", FORMAT_FIXTURES, ids=[
            f"{fmt}-{name}" for fmt, name, _ in FORMAT_FIXTURES
        ]
    )
    def test_format_ingests_and_detects(self, fmt, filename, flags, tmp_path):
        source = FIXTURES / filename
        assert source.exists(), f"missing fixture {source}"

        detections = run_zircolite(tmp_path, source, flags)

        total = sum(len(d["matches"]) for d in detections)
        assert total > 0, (
            f"{fmt} read {filename} without producing a single event -- the "
            "reader is broken, or the fixture no longer parses"
        )

    def test_every_format_is_covered(self):
        """A new input format must arrive with a fixture, not just a flag."""
        from zircolite.formats import INPUT_FORMATS

        covered = {fmt for fmt, _, _ in FORMAT_FIXTURES}
        declared = {spec.name for spec in INPUT_FORMATS}
        missing = declared - covered - {"json_array"}
        assert missing == set(), (
            f"formats with no end-to-end fixture: {sorted(missing)}"
        )

    def test_json_array_reads_the_same_events(self, tmp_path):
        """json_array shares its fixture with json, rewritten as one array."""
        lines = (FIXTURES / "sample_events.json").read_text().splitlines()
        source = tmp_path / "events_array.json"
        source.write_text(json.dumps([json.loads(line) for line in lines if line.strip()]))

        detections = run_zircolite(tmp_path, source, ["--json-array-input"])
        assert sum(len(d["matches"]) for d in detections) > 0


class TestProcessingModeEquivalence:
    """The same input must detect the same things in every processing mode.

    Options applied on one path and dropped on another are invisible otherwise:
    the run succeeds, the summary looks healthy, and the detections are simply
    different from what another mode would have produced.
    """

    MODES: ClassVar[dict] = {
        "per-file": ["--no-parallel", "--no-auto-mode"],
        "unified": ["--unified-db", "--no-auto-mode"],
        "parallel": ["--no-auto-mode"],
    }

    def _run_every_mode(self, tmp_path, corpus, ruleset=MATCH_ALL_RULESET, extra=(), modes=None):
        results = {}
        for name, flags in (modes or self.MODES).items():
            run_dir = tmp_path / name
            run_dir.mkdir()
            results[name] = detection_summary(
                run_zircolite(run_dir, corpus, ["-j", *flags], ruleset=ruleset, extra=extra)
            )
        return results

    @staticmethod
    def _assert_agree(results):
        baseline = results["per-file"]
        for name, summary in results.items():
            assert summary == baseline, (
                f"per-file and {name} disagree on the same input:\n"
                f"  per-file: {baseline}\n  {name+':':9} {summary}"
            )

    def test_identical_files_agree(self, tmp_path):
        source = (FIXTURES / "sample_events.json").read_text()
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for index in range(4):
            (corpus / f"events{index}.json").write_text(source)

        self._assert_agree(self._run_every_mode(tmp_path, corpus))

    # One field typed differently per file, one spelled with different case, one
    # present in a single file. Four identical copies of a fixture cannot show
    # any of this: every file yields the same schema, so schema state carried
    # between files stays invisible.
    HETEROGENEOUS: ClassVar[dict] = {
        "a.json": {"Foo": 1, "Widget": "alpha"},
        "b.json": {"Foo": "ABC", "widget": "mimikatz.exe"},
        "c.json": {"Foo": "xyz", "Extra": "only here"},
    }

    SCHEMA_RULESET = json.dumps([
        {"title": "Foo matched case-insensitively", "id": "eq-1", "level": "high",
         "tags": [], "rule": ["SELECT * FROM logs WHERE Foo = 'abc'"]},
        {"title": "Widget whatever its spelling", "id": "eq-2", "level": "high",
         "tags": [], "rule": ["SELECT * FROM logs WHERE Widget LIKE '%mimikatz%'"]},
        {"title": "Field only one file carries", "id": "eq-3", "level": "low",
         "tags": [], "rule": ["SELECT * FROM logs WHERE Extra IS NOT NULL"]},
    ])

    def _heterogeneous_corpus(self, tmp_path, order=None):
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        names = order or list(self.HETEROGENEOUS)
        for name in names:
            event = {
                "Event": {
                    "System": {"Channel": "Security", "EventID": 1},
                    "EventData": self.HETEROGENEOUS[name],
                }
            }
            (corpus / name).write_text(json.dumps(event))
        return corpus

    def test_files_with_different_schemas_agree(self, tmp_path):
        """A column typed or spelled by one file must not decide for the others."""
        corpus = self._heterogeneous_corpus(tmp_path)
        self._assert_agree(
            self._run_every_mode(tmp_path, corpus, ruleset=self.SCHEMA_RULESET)
        )

    def test_every_rule_still_fires_across_a_mixed_corpus(self, tmp_path):
        """Agreement is worthless if every mode agrees on finding nothing."""
        corpus = self._heterogeneous_corpus(tmp_path)
        results = self._run_every_mode(
            tmp_path, corpus, ruleset=self.SCHEMA_RULESET
        )
        assert [title for title, _ in results["per-file"]] == [
            "Field only one file carries",
            "Foo matched case-insensitively",
            "Widget whatever its spelling",
        ]

    # Two titles share one query, so duplicate removal keeps only the first;
    # -R names that one. Workers in processes rebuild their rules from the
    # payload, so they are checked alongside the threads.
    RULEFILTER_RULESET = json.dumps([
        {"title": "Widget - Sysmon", "id": "rf-1", "level": "high",
         "tags": [], "rule": ["SELECT * FROM logs WHERE Widget LIKE '%mimikatz%'"]},
        {"title": "Widget seen", "id": "rf-2", "level": "medium",
         "tags": [], "rule": ["SELECT * FROM logs WHERE Widget LIKE '%mimikatz%'"]},
        {"title": "Foo matched case-insensitively", "id": "rf-3", "level": "high",
         "tags": [], "rule": ["SELECT * FROM logs WHERE Foo = 'abc'"]},
    ])

    def test_rulefilter_selects_the_same_rules_in_every_mode(self, tmp_path):
        corpus = self._heterogeneous_corpus(tmp_path)
        modes = {**self.MODES, "process": ["--no-auto-mode", "--executor", "process"]}
        results = self._run_every_mode(
            tmp_path, corpus, ruleset=self.RULEFILTER_RULESET, extra=["-R", "Sysmon"], modes=modes,
        )
        self._assert_agree(results)
        assert [title for title, _ in results["per-file"]] == [
            "Foo matched case-insensitively",
            "Widget seen",
        ]

    def test_csv_rewrites_values_alike_in_every_mode(self, tmp_path):
        """Each mode writes CSV through its own path; every one must defuse the same values."""
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for index in range(3):
            event = {"Event": {"System": {"Channel": "Security", "EventID": 1},
                               "EventData": {"CommandLine": f"=cmd{index}\nwhoami", "Delta": -3 - index}}}
            (corpus / f"events{index}.json").write_text(json.dumps(event))
        ruleset = json.dumps([{"title": "Delta below zero", "id": "csv-1", "level": "high",
                               "tags": [], "rule": ["SELECT * FROM logs WHERE Delta < 0"]}])
        modes = {**self.MODES, "process": ["--no-auto-mode", "--executor", "process"]}

        def read(path):
            with path.open(encoding="utf-8", newline="") as handle:
                # rule_count is per database: 1 per file in per-file runs, 3 in a unified one.
                return sorted(tuple(sorted((k, v) for k, v in row.items() if k != "rule_count"))
                              for row in csv.DictReader(handle, delimiter=";"))

        outputs = {}
        for name, flags in modes.items():
            run_dir = tmp_path / name
            run_dir.mkdir()
            outputs[name] = run_zircolite(run_dir, corpus, ["-j", "--csv", *flags], ruleset=ruleset,
                                          outname="detected.csv", read=read)

        assert all(rows == outputs["per-file"] for rows in outputs.values()), outputs
        values = sorted((dict(row)["CommandLine"], dict(row)["Delta"]) for row in outputs["per-file"])
        assert values == [("'=cmd0 whoami", "'-3"), ("'=cmd1 whoami", "'-4"), ("'=cmd2 whoami", "'-5")]

    def test_glob_order_does_not_change_the_answer(self, tmp_path):
        """Whichever file is read first must not decide what the rest can match."""
        names = list(self.HETEROGENEOUS)
        summaries = {}
        for label, order in (("forward", names), ("reverse", list(reversed(names)))):
            run_root = tmp_path / label
            run_root.mkdir()
            corpus = self._heterogeneous_corpus(run_root, order=order)
            summaries[label] = self._run_every_mode(
                run_root, corpus, ruleset=self.SCHEMA_RULESET
            )["per-file"]

        assert summaries["forward"] == summaries["reverse"], (
            f"reading the same files in the other order changed the result:\n"
            f"  forward: {summaries['forward']}\n  reverse: {summaries['reverse']}"
        )


class TestTimelineParity:
    """The timeline is written through each layout's own path, and must come out byte for byte the same."""

    MODES: ClassVar[dict] = {
        "per-file": ["--no-parallel", "--no-auto-mode"],
        "unified": ["--unified-db", "--no-auto-mode"],
        "thread": ["--no-auto-mode", "--executor", "thread"],
        "process": ["--no-auto-mode", "--executor", "process"],
    }

    RULESET = json.dumps([
        {"title": "Any event", "id": "tl-1", "level": "low", "tags": ["attack.execution"],
         "rule": ["SELECT * FROM logs"]},
        {"title": "Whoami", "id": "tl-2", "level": "high", "tags": ["attack.discovery", "attack.t1033"],
         "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%whoami%'"]},
    ])

    @staticmethod
    def _event(record, second, command, *, with_record=True):
        system = {"Channel": "Security", "EventID": 4688, "Computer": "WS01",
                  "TimeCreated": {"#attributes": {"SystemTime": f"2024-05-01T10:00:{second:02d}.1234567Z"}}}
        if with_record:
            system["EventRecordID"] = record
        return {"Event": {"System": system, "EventData": {"CommandLine": command, "Protocol": 6}}}

    def _corpus(self, tmp_path):
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        security = [self._event(n, 10 - n, "whoami /all" if n == 2 else f"cmd {n}") for n in (1, 2, 3)]
        lines = "\n".join(json.dumps(event) for event in security)
        (corpus / "security.json").write_text(lines)
        # A second copy of the same log: its records are dropped as duplicates
        (corpus / "security-copy.json").write_text(lines)
        # No record ID: two identical lines of one log are two events
        repeated = json.dumps(self._event(0, 30, "net use", with_record=False))
        (corpus / "app.json").write_text(f"{repeated}\n{repeated}")
        return corpus

    def _timeline(self, run_dir, source, flags, name, extra=()):
        run_dir.mkdir()
        path = run_dir / name
        run_zircolite(run_dir, source, [*flags] if "-D" in flags else ["-j", *flags], ruleset=self.RULESET,
                      extra=["--timeline", str(path), *extra], read=lambda _: None)
        return path

    def _every_layout(self, tmp_path, name, extra=()):
        corpus = self._corpus(tmp_path)
        timelines = {mode: self._timeline(tmp_path / mode, corpus, flags, name, extra)
                     for mode, flags in self.MODES.items()}
        database = tmp_path / "saved.db"
        self._timeline(tmp_path / "save", corpus, ["--unified-db", "--no-auto-mode", "-d", str(database)], name, extra)
        timelines["-D"] = self._timeline(tmp_path / "db-input", database, ["-D"], name, extra)
        return timelines

    def test_the_csv_timeline_is_identical_in_every_layout(self, tmp_path):
        timelines = self._every_layout(tmp_path, "timeline.csv")

        contents = {mode: path.read_bytes() for mode, path in timelines.items()}
        assert all(content == contents["per-file"] for content in contents.values()), contents
        with timelines["per-file"].open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        # 8 matches of "Any event" and 2 of "Whoami", less the copy's 4 rows. At one
        # instant the rules come in loaded order, which puts the most severe first.
        assert [(row["Timestamp"], row["RuleTitle"], row["RecordID"]) for row in rows] == [
            ("2024-05-01T10:00:07.123456+00:00", "Any event", "3"),
            ("2024-05-01T10:00:08.123456+00:00", "Whoami", "2"),
            ("2024-05-01T10:00:08.123456+00:00", "Any event", "2"),
            ("2024-05-01T10:00:09.123456+00:00", "Any event", "1"),
            ("2024-05-01T10:00:30.123456+00:00", "Any event", "-"),
            ("2024-05-01T10:00:30.123456+00:00", "Any event", "-"),
        ]
        # The shipped 4688 layout picks the command line; the value map explains the protocol
        assert (rows[1]["Details"], rows[1]["ExtraFields"]) == ("CommandLine: whoami /all", "Protocol: 6 (TCP)")
        assert rows[1]["Tactics"] == "discovery"

    def test_the_full_timeline_agrees_in_every_layout(self, tmp_path):
        """Raw values, so compared as text: a value's type follows its column in a database (docs/Internals.md)."""
        timelines = self._every_layout(tmp_path, "timeline.jsonl", extra=["--timeline-profile", "full"])

        def as_text(path):
            return [json.loads(line, parse_int=str, parse_float=str) for line in path.read_text().splitlines()]

        rows = {mode: as_text(path) for mode, path in timelines.items()}
        assert all(content == rows["per-file"] for content in rows.values())
        assert len(rows["per-file"]) == 6
        assert "row_id" not in rows["per-file"][0]["AllFields"]

    def test_keep_duplicates_keeps_the_copy(self, tmp_path):
        corpus = self._corpus(tmp_path)

        path = self._timeline(tmp_path / "run", corpus, self.MODES["per-file"], "t.jsonl", ["--keep-duplicates"])

        assert len(path.read_text().splitlines()) == 10

    def test_stdout_carries_the_timeline_and_nothing_else(self, tmp_path):
        corpus = self._corpus(tmp_path)
        ruleset = tmp_path / "ruleset.json"
        ruleset.write_text(self.RULESET)
        argv = ["-e", str(corpus), "-j", "-r", str(ruleset), "-o", str(tmp_path / "detected.json"),
                "-l", str(tmp_path / "z.log"), "--timeline", "-"]
        binary = os.environ.get("ZIRCOLITE_BINARY")
        command = [str(Path(binary).resolve())] if binary else [sys.executable, str(WORKSPACE_ROOT / "zircolite.py")]

        result = subprocess.run([*command, *argv], cwd=tmp_path, capture_output=True,
                                encoding="utf-8", timeout=240)

        assert result.returncode == 0, result.stderr
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(rows) == 6
        assert "Summary" in result.stderr


class TestGoldenDetections:
    """The detections for a real sample are pinned to a committed expectation.

    Regenerate deliberately, and read the diff:
        pdm run python tests/regenerate_golden.py
    """

    # The .db fixture is the .evtx one already ingested, so the two cases also
    # pin that reading a saved database detects what reading the EVTX did. To
    # rebuild it:
    #     zircolite.py -e tests/fixtures/sample_bitsadmin.evtx -d out.db
    # and move the resulting out_sample_bitsadmin.evtx.db over the fixture.
    #
    # CI builds the compiled flattening kernel, so the default run uses it. The
    # Python kernel is what a checkout without a compiler runs, and it must reach
    # the same golden detections.
    CASES: ClassVar[list] = [
        ("bitsadmin_sysmon", "sample_bitsadmin.evtx", [], "rules_windows_sysmon.json"),
        ("bitsadmin_sysmon", "sample_bitsadmin.evtx", ["--flatten-backend", "python"],
         "rules_windows_sysmon.json"),
        ("bitsadmin_sqlite", "sample_bitsadmin.db", ["-D"], "rules_windows_sysmon.json"),
    ]

    @pytest.mark.parametrize(
        "name,filename,flags,ruleset", CASES, ids=["-".join([c[0], *c[2]]) for c in CASES]
    )
    def test_detections_match_the_golden_file(
        self, name, filename, flags, ruleset, tmp_path
    ):
        expected_path = GOLDEN / f"{name}.json"
        assert expected_path.exists(), (
            f"missing golden file {expected_path}; run tests/regenerate_golden.py"
        )

        detections = run_zircolite(
            tmp_path,
            FIXTURES / filename,
            flags,
            ruleset=(WORKSPACE_ROOT / "rules" / ruleset).read_text(),
        )

        assert detection_summary(detections) == [
            tuple(entry) for entry in json.loads(expected_path.read_text())
        ]


class TestAuditdEnrichedDetections:
    """The bundled Linux rules must fire on auditd's default ENRICHED format.

    The fixture's SYSCALL records carry both syscall=133 and, after 0x1D,
    SYSCALL=mknod. Those differ only in case, which SQLite does not see, so the
    raw number used to take the column and every SYSCALL='...' rule matched
    nothing. The webshell record also pins the other half: its rule tests
    euid=33, so the enriched EUID="www-data" must not take that column.
    """

    EXPECTED: ClassVar[list] = [
        "Special File Creation via Mknod Syscall",
        "Webshell Remote Command Execution",
    ]

    def test_syscall_rules_fire(self, tmp_path):
        source = FIXTURES / "audit_enriched_sample.log"
        assert source.exists(), f"missing fixture {source}"

        detections = run_zircolite(
            tmp_path, source, ["-AU"],
            ruleset=(WORKSPACE_ROOT / "rules" / "rules_linux.json").read_text(),
        )

        fired = {title for title, _ in detection_summary(detections)}
        missing = [title for title in self.EXPECTED if title not in fired]
        assert missing == [], f"rules silent on ENRICHED auditd: {missing}"

        # Neither side of a collision is dropped, under the documented names
        mknod = next(
            d for d in detections if d["title"] == self.EXPECTED[0]
        )["matches"][0]
        assert (mknod["SYSCALL"], mknod["syscallRaw"]) == ("mknod", "133")
        assert (mknod["ARCH"], mknod["archRaw"]) == ("x86_64", "c000003e")
        assert (mknod["auid"], mknod["AUIDEnriched"]) == ("1000", "alice")

