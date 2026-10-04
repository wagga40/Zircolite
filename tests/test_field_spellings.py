"""An event keeps its own field spelling in output, whatever database stored it.

SQLite column names are case-insensitive, so ``ProcessId`` and ``ProcessID``
share one column, named after whichever spelling reached that database first.
Output must not depend on which files share a database: every event is printed
with its own spelling, except the run's time field, which outputs read by name.
"""

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.package_fixtures import parquet_rows, read_package
from zircolite import ProcessingConfig, ZircoliteCore
from zircolite import core as core_module

ROOT = Path(__file__).resolve().parent.parent
CONFIG = str(ROOT / "config/config.yaml")
WHOAMI = [{"id": "r", "title": "whoami", "level": "high",
           "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%whoami%'"]}]

LAYOUTS = {
    "unified": ["--unified-db"],
    "sequential": ["--no-parallel"],
    "thread": ["--executor", "thread", "--parallel-workers", "2"],
    "process": ["--executor", "process", "--parallel-workers", "2"],
}


def write_inputs(directory, files):
    directory.mkdir()
    for name, events in files.items():
        (directory / name).write_text("".join(json.dumps(event) + "\n" for event in events))
    return directory


def run(tmp_path, inputs, *flags, rules=None, rules_name="rules.json"):
    rules_path = tmp_path / rules_name
    if rules_path.suffix == ".json":
        rules_path.write_text(json.dumps(rules or WHOAMI))
    else:
        rules_path.write_text(yaml.safe_dump_all(rules))
    output = tmp_path / "out.json"
    output.unlink(missing_ok=True)
    command = [sys.executable, str(ROOT / "zircolite.py"), "-e", str(inputs), "-r", str(rules_path),
               "-c", CONFIG, "--quiet", "--no-auto-mode", "-o", str(output),
               "--logfile", str(tmp_path / "run.log"), *flags]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(output.read_text())


def process_ids(events):
    """``(CommandLine, spelling, value)`` for each event's ProcessId field."""
    found = set()
    for event in events:
        keys = [key for key in event if key.lower() == "processid"]
        assert len(keys) == 1, event
        found.add((event["CommandLine"], keys[0], event[keys[0]]))
    return found


def matched_events(results):
    return [match for result in results for match in result["matches"]]


SPELLINGS = {
    "a.json": [{"CommandLine": "whoami a", "ProcessId": "0x1"}],
    "b.json": [{"CommandLine": "whoami b", "ProcessID": "0x2"}],
    "c.json": [{"CommandLine": "whoami c1", "ProcessId": "0x3"},
               {"CommandLine": "whoami c2", "ProcessID": "0x4"}],
}
EXPECTED = {("whoami a", "ProcessId", "0x1"), ("whoami b", "ProcessID", "0x2"),
            ("whoami c1", "ProcessId", "0x3"), ("whoami c2", "ProcessID", "0x4")}


@pytest.mark.parametrize("layout", LAYOUTS)
def test_each_event_keeps_its_spelling_in_every_layout(tmp_path, layout):
    inputs = write_inputs(tmp_path / "inputs", SPELLINGS)
    results = run(tmp_path, inputs, "--json-input", *LAYOUTS[layout])
    assert process_ids(matched_events(results)) == EXPECTED


@pytest.mark.parametrize("layout", LAYOUTS)
def test_csv_has_a_column_for_every_spelling(tmp_path, layout):
    # The unified header comes from the table, which knows one spelling only;
    # a row under another spelling would lose its value to an empty cell.
    inputs = write_inputs(tmp_path / "inputs", SPELLINGS)
    output = tmp_path / "out.csv"
    command = [sys.executable, str(ROOT / "zircolite.py"), "-e", str(inputs), "-r", str(tmp_path / "rules.json"),
               "-c", CONFIG, "--quiet", "--no-auto-mode", "--json-input", "--csv", "-o", str(output),
               "--logfile", str(tmp_path / "run.log"), *LAYOUTS[layout]]
    (tmp_path / "rules.json").write_text(json.dumps(WHOAMI))
    completed = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    with output.open(newline="", encoding="utf-8") as handle:
        rows = [{key: value for key, value in row.items() if value} for row in csv.DictReader(handle, delimiter=";")]
    assert process_ids(rows) == EXPECTED


def test_an_event_with_both_spellings_keeps_the_one_whose_value_was_stored(tmp_path):
    # Both spellings land in one column, so one value is kept: the first that
    # is not null, as before. Its spelling has to come with it.
    inputs = write_inputs(tmp_path / "inputs", {"d.json": [
        {"CommandLine": "whoami d1", "ProcessId": "0x3"},
        {"CommandLine": "whoami d2", "ProcessID": "0x5", "ProcessId": "0x6"},
        {"CommandLine": "whoami d3", "ProcessId": "0x7", "ProcessID": "0x8"},
    ]})
    results = run(tmp_path, inputs, "--json-input", "--no-parallel")
    assert process_ids(matched_events(results)) == {
        ("whoami d1", "ProcessId", "0x3"), ("whoami d2", "ProcessID", "0x5"), ("whoami d3", "ProcessId", "0x7")}


def test_one_files_record_never_renames_the_next_files_rows(tmp_path):
    # Per-file runs reuse the database and number each file's rows from one, so
    # a record left behind would rename the next file's rows, in either order.
    inputs = write_inputs(tmp_path / "inputs", {
        "e.json": [{"CommandLine": "whoami e1", "ProcessId": "0x1"},
                   {"CommandLine": "whoami e2", "ProcessID": "0x2"},
                   {"CommandLine": "whoami e3", "ProcessId": "0x3"}],
        "f.json": [{"CommandLine": "whoami f1", "ProcessId": "0x4"},
                   {"CommandLine": "whoami f2", "ProcessId": "0x5"},
                   {"CommandLine": "whoami f3", "ProcessID": "0x6"}],
    })
    results = run(tmp_path, inputs, "--json-input", "--no-parallel")
    assert process_ids(matched_events(results)) == {
        ("whoami e1", "ProcessId", "0x1"), ("whoami e2", "ProcessID", "0x2"), ("whoami e3", "ProcessId", "0x3"),
        ("whoami f1", "ProcessId", "0x4"), ("whoami f2", "ProcessId", "0x5"), ("whoami f3", "ProcessID", "0x6")}


def test_a_saved_database_keeps_the_spellings(tmp_path):
    inputs = write_inputs(tmp_path / "inputs", SPELLINGS)
    saved = tmp_path / "saved.db"
    run(tmp_path, inputs, "--json-input", "--unified-db", "--dbfile", str(saved))
    results = run(tmp_path, saved, "--db-input")
    assert process_ids(matched_events(results)) == EXPECTED


@pytest.mark.requires_sigma
def test_correlation_evidence_keeps_each_events_spelling(tmp_path):
    base = {"title": "proc", "name": "proc", "logsource": {"product": "windows", "category": "test"},
            "detection": {"s": {"EventID": 1}, "condition": "s"}, "level": "informational"}
    burst = {"title": "burst", "name": "burst", "level": "high",
             "correlation": {"type": "event_count", "rules": ["proc"], "group-by": ["Computer"],
                             "timespan": "5m", "condition": {"gte": 2}}}
    common = {"Computer": "host", "EventID": 1}
    inputs = write_inputs(tmp_path / "inputs", {
        "a.json": [{**common, "SystemTime": "2026-01-01T00:00:00.000Z", "CommandLine": "whoami a",
                    "ProcessId": "0x1"}],
        "b.json": [{**common, "SystemTime": "2026-01-01T00:01:00.000Z", "CommandLine": "whoami b",
                    "ProcessID": "0x2"}],
    })
    results = run(tmp_path, inputs, "--json-input", "--unified-db", rules=[base, burst], rules_name="rules.yml")
    [alert] = matched_events(results)
    assert process_ids(item["event"] for item in alert["evidence"]) == {
        ("whoami a", "ProcessId", "0x1"), ("whoami b", "ProcessID", "0x2")}


@pytest.mark.parametrize("layout", LAYOUTS)
def test_the_time_field_keeps_the_runs_name(tmp_path, layout):
    # Timesketch and the package viewer read the time by the name --timefield gives it.
    inputs = write_inputs(tmp_path / "inputs", {
        "a.json": [{"CommandLine": "whoami a", "timestamp": "2026-01-01T00:00:00Z"}],
        "b.json": [{"CommandLine": "whoami b", "Timestamp": "2026-01-01T00:01:00Z"}],
    })
    timeline = tmp_path / "timesketch.jsonl"
    results = run(tmp_path, inputs, "--json-input", "--timefield", "timestamp",
                  "-t", str(ROOT / "templates/exportForTimesketch.tmpl"), "-T", str(timeline), *LAYOUTS[layout])
    times = {"2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z"}
    assert {event.get("timestamp") for event in matched_events(results)} == times
    lines = [json.loads(line) for line in timeline.read_text().splitlines() if line.strip()]
    assert {line["datetime"] for line in lines} == times


def viewer_names(manifest, row):
    """The names the package viewer shows a row's fields under: row, then part, then column."""
    row_names = {name.lower(): name for name in json.loads(row["_zl_spelling"] or "[]")}
    part_names = next(part["spellings"] for part in manifest["parts"] if part["part"] == row["_zl_part"])
    return {row_names.get(column["key"]) or part_names.get(column["key"]) or column["name"]
            for column in manifest["columns"] if row[column["name"]] is not None}


def test_the_package_names_every_field_as_the_detections_do(tmp_path):
    inputs = write_inputs(tmp_path / "inputs", {
        "a.json": [{"CommandLine": "whoami a", "ProcessId": "0x1", "SystemTime": "2026-01-01T00:00:00Z"}],
        "b.json": [{"CommandLine": "whoami b", "ProcessID": "0x2", "systemtime": "2026-01-01T00:01:00Z"},
                   {"CommandLine": "whoami c", "ProcessId": "0x3", "systemtime": "2026-01-01T00:02:00Z"}],
    })
    packages = tmp_path / "packages"
    packages.mkdir()

    results = run(tmp_path, inputs, "--json-input", "--unified-db", "--timefield", "SystemTime",
                  "--package", "--package-dir", str(packages))

    (target,) = packages.glob("zircolite-package-*.zip")
    manifest, files = read_package(target)
    columns, rows = parquet_rows(files["events.parquet"], tmp_path, "SELECT * FROM t ORDER BY _zl_uid")
    rows = [dict(zip(columns, row, strict=True)) for row in rows]
    assert [(row["CommandLine"], row["_zl_spelling"]) for row in rows] == [
        ("whoami a", None), ("whoami b", '["ProcessID"]'), ("whoami c", None)]
    printed = {event["CommandLine"]: set(event) - {"row_id"} for event in matched_events(results)}
    assert {row["CommandLine"]: viewer_names(manifest, row) for row in rows} == printed
    assert all("SystemTime" in names for names in printed.values())


def ingest(tmp_path, field_mappings_file, test_logger, events, **processing):
    source = tmp_path / "events.json"
    source.write_text("".join(json.dumps(event) + "\n" for event in events))
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True, disable_progress=True, **processing),
                         logger=test_logger)
    core.run_streaming([str(source)], input_type="json")
    return core


def test_rows_in_later_batches_keep_their_spelling(tmp_path, field_mappings_file, test_logger):
    # Batches of two: the record must count row IDs from where each batch starts.
    events = [{"CommandLine": f"whoami {i}", **{spelling: hex(i)}}
              for i, spelling in enumerate(["ProcessId", "ProcessId", "ProcessID", "ProcessId", "ProcessID"])]
    core = ingest(tmp_path, field_mappings_file, test_logger, events, batch_size=2)
    try:
        rows = core.execute_select_query("SELECT * FROM logs")
    finally:
        core.close()
    assert process_ids(rows) == {(event["CommandLine"], *next(iter(
        (key, value) for key, value in event.items() if key != "CommandLine"))) for event in events}


def test_events_with_one_spelling_leave_no_record(tmp_path, field_mappings_file, test_logger):
    core = ingest(tmp_path, field_mappings_file, test_logger,
                  [{"CommandLine": "whoami a", "ProcessId": "0x1"}, {"CommandLine": "whoami b", "ProcessId": "0x2"}])
    try:
        tables = {name for (name,) in core.db_connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        core.close()
    assert not tables & {"field_spellings", "logs_spelling"}


def test_a_partial_record_never_breaks_a_rule(tmp_path, field_mappings_file, test_logger):
    core = ingest(tmp_path, field_mappings_file, test_logger, SPELLINGS["c.json"])
    try:
        core.db_connection.execute("DROP TABLE logs_spelling")
        rows = core.execute_select_query("SELECT * FROM logs WHERE CommandLine LIKE '%whoami%'")
        assert not core.rules_in_error
    finally:
        core.close()
    assert len(rows) == 2


def test_a_failed_reset_keeps_rows_and_record_together(tmp_path, field_mappings_file, test_logger, monkeypatch):
    core = ingest(tmp_path, field_mappings_file, test_logger, SPELLINGS["c.json"])

    def fail(connection):
        raise core_module.sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(core_module, "drop_spellings", fail)
    try:
        core.reset_logs_table()
        tables = {name for (name,) in core.db_connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        core.close()
    # A record that outlived its rows would rename the next file's.
    assert ("logs" in tables) == ("logs_spelling" in tables)
