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
"""

import importlib.util
import json
import sys
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import pytest

WORKSPACE_ROOT = Path(__file__).parent.parent
FIXTURES = WORKSPACE_ROOT / "tests" / "fixtures"
GOLDEN = Path(__file__).parent / "golden"

sys.path.insert(0, str(WORKSPACE_ROOT))


def load_zircolite_script():
    spec = importlib.util.spec_from_file_location(
        "zircolite_script", WORKSPACE_ROOT / "zircolite.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


zircolite_script = load_zircolite_script()

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
    ("sysmon_linux", "sysmon_linux_sample.log", ["-S"]),
    ("evtxtract", "evtxtract_sample.log", ["--evtxtract-input"]),
    ("sqlite", "sample_bitsadmin.db", ["-D"]),
]


def run_zircolite(tmp_path, source, flags, ruleset=MATCH_ALL_RULESET, extra=()):
    """Run the CLI over *source* and return the parsed detections."""
    ruleset_file = tmp_path / "ruleset.json"
    ruleset_file.write_text(ruleset)
    outfile = tmp_path / "detected.json"

    argv = [
        "zircolite.py",
        "-e", str(source),
        "-r", str(ruleset_file),
        "-o", str(outfile),
        "-l", str(tmp_path / "zircolite.log"),
        *flags,
        *extra,
    ]
    with patch("sys.argv", argv):
        zircolite_script.main()

    assert outfile.exists(), f"no output written for {source}"
    return json.loads(outfile.read_text())


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

    def _corpus(self, tmp_path):
        source = (FIXTURES / "sample_events.json").read_text()
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for index in range(4):
            (corpus / f"events{index}.json").write_text(source)
        return corpus

    def test_perfile_unified_and_parallel_agree(self, tmp_path):
        corpus = self._corpus(tmp_path)

        modes = {
            "per-file": ["--no-parallel", "--no-auto-mode"],
            "unified": ["--unified-db", "--no-auto-mode"],
            "parallel": ["--no-auto-mode"],
        }
        results = {}
        for name, flags in modes.items():
            run_dir = tmp_path / name
            run_dir.mkdir()
            detections = run_zircolite(run_dir, corpus, ["-j", *flags])
            results[name] = detection_summary(detections)

        assert results["per-file"] == results["unified"], (
            f"per-file and --unified-db disagree:\n"
            f"  per-file: {results['per-file']}\n  unified:  {results['unified']}"
        )
        assert results["per-file"] == results["parallel"], (
            f"per-file and parallel disagree:\n"
            f"  per-file: {results['per-file']}\n  parallel: {results['parallel']}"
        )


class TestGoldenDetections:
    """The detections for a real sample are pinned to a committed expectation.

    Regenerate deliberately, and read the diff:
        pdm run python tests/regenerate_golden.py
    """

    # The .db fixture is the .evtx one already ingested, so the two cases also
    # pin that reading a saved database detects what reading the EVTX did.
    CASES: ClassVar[list] = [
        ("bitsadmin_sysmon", "sample_bitsadmin.evtx", [], "rules_windows_sysmon.json"),
        ("bitsadmin_sqlite", "sample_bitsadmin.db", ["-D"], "rules_windows_sysmon.json"),
    ]

    @pytest.mark.parametrize(
        "name,filename,flags,ruleset", CASES, ids=[c[0] for c in CASES]
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
