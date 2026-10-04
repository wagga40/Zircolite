"""Every processing mode spools the same events and hits for the package."""

import argparse
import json
import time
from pathlib import Path

import pytest

from tests.package_fixtures import read_spool
from zircolite.package_spool import PackageSpool, rule_index
from zircolite.processing import (
    ProcessingContext,
    process_db_input,
    process_parallel_streaming,
    process_perfile_streaming,
    process_unified_streaming,
)
from zircolite.utils import MemoryTracker

RULES = [
    {"title": "Encoded", "id": "r-0", "level": "high", "tags": [],
     "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%-enc%'"]},
    {"title": "Any logon", "id": "r-1", "level": "low", "tags": [],
     "rule": ["SELECT * FROM logs WHERE EventID = '4624'"]},
]
FILES = {
    "a.json": [{"EventID": 1, "CommandLine": "powershell -enc AAA", "ProcessId": 10, "SystemTime": "2021-06-03T06:00:00Z"},
               {"EventID": 4624, "TargetUserName": "bob", "SystemTime": "2021-06-03T06:00:01Z"}],
    "b.json": [{"EventID": 1, "CommandLine": "cmd /c dir", "ProcessID": 11, "SystemTime": "2021-06-03T06:00:02Z"}],
    "c.json": [{"EventID": 4624, "TargetUserName": "alice", "SystemTime": "2021-06-03T06:00:03Z"}],
}
CONFIG = {"exclusions": [], "useless": [], "alias": {}, "split": {}, "transforms_enabled": False, "transforms": {},
          "mappings": {"EventID": "EventID", "CommandLine": "CommandLine", "ProcessId": "ProcessId",
                       "ProcessID": "ProcessID", "TargetUserName": "TargetUserName", "SystemTime": "SystemTime"}}


def write_corpus(tmp_path, folder, texts):
    root = tmp_path / folder
    root.mkdir()
    for name, text in texts.items():
        (root / name).write_text(text, encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(json.dumps(CONFIG), encoding="utf-8")
    return sorted(root.iterdir()), config


@pytest.fixture
def corpus(tmp_path):
    return write_corpus(tmp_path, "logs", {
        name: "\n".join(json.dumps(event) for event in events) for name, events in FILES.items()})


@pytest.fixture
def damaged(tmp_path):
    """One clean input, one with a malformed line among good ones, one with nothing readable."""
    return write_corpus(tmp_path, "damaged", {
        "a.json": json.dumps(FILES["a.json"][0]),
        "b.json": json.dumps(FILES["b.json"][0]) + "\n{not json\n" + json.dumps(FILES["c.json"][0]),
        "c.json": "garbage\nmore garbage",
    })


def context(tmp_path, config, test_logger, *, dbfile=None):
    spool_dir = tmp_path / f"spool-{time.perf_counter_ns()}"
    spool_dir.mkdir()
    return ProcessingContext(
        config=str(config), logger=test_logger, no_output=True,
        events_after=time.strptime("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
        events_before=time.strptime("9999-12-12T23:59:59", "%Y-%m-%dT%H:%M:%S"),
        limit=-1, csv_mode=False, time_field="SystemTime", db_location=":memory:", delimiter=";",
        rulesets=RULES, rule_filters=None, outfile=str(tmp_path / "out.json"), ready_for_templating=False,
        package=True, dbfile=dbfile, keepflat=False, memory_tracker=MemoryTracker(logger=test_logger),
        retain_results=False,
        package_spool=PackageSpool(directory=str(spool_dir), time_field="SystemTime", rule_keys=rule_index(RULES)),
    )


@pytest.fixture
def args(default_args_config):
    """The conftest namespace the existing mode tests use, with overrides."""
    def make(**overrides):
        values = {**vars(default_args_config), "json_input": True, "executor": "thread", "parallel_workers": 2}
        values.update(overrides)
        return argparse.Namespace(**values)
    return make


def content(ctx):
    """Mode-independent view of what was spooled: events by file, hits by event."""
    assert ctx.package_errors == []
    events, hits = set(), set()
    by_part = {}
    for record in ctx.package_parts:
        for row in read_spool(record.event_files):
            fields = {k: v for k, v in row.items() if not k.startswith("_zl_") and k != "originallogfile"}
            key = (Path(row["originallogfile"]).name, json.dumps(fields, sort_keys=True))
            events.add(key)
            by_part[(record.part, row["_zl_rid"])] = key
        if record.hits_file:
            for line in Path(record.hits_file).read_text().splitlines():
                rule_idx, part, rid = map(int, line.split(","))
                hits.add((rule_idx, by_part[(part, rid)]))
    return events, hits


@pytest.fixture
def expected(corpus, tmp_path, test_logger, args):
    files, config = corpus
    ctx = context(tmp_path, config, test_logger)
    process_perfile_streaming(ctx, files, "json", None, args())
    return content(ctx)


def test_per_file_spools_every_event_and_hit(expected):
    events, hits = expected
    assert len(events) == 4
    assert {rule for rule, _ in hits} == {0, 1} and len(hits) == 3


def test_unified_matches_per_file(corpus, tmp_path, test_logger, expected, args):
    files, config = corpus
    ctx = context(tmp_path, config, test_logger)
    process_unified_streaming(ctx, files, "json", None, args())
    assert [record.part for record in ctx.package_parts] == [0]
    assert content(ctx) == expected


@pytest.mark.parametrize("executor", ["thread", "process"])
def test_parallel_matches_per_file(corpus, tmp_path, test_logger, expected, args, executor):
    files, config = corpus
    ctx = context(tmp_path, config, test_logger)
    process_parallel_streaming(ctx, files, "json", None, args(executor=executor), recommended_workers=2)
    assert sorted(record.part for record in ctx.package_parts) == [0, 1, 2]
    assert content(ctx) == expected


def test_database_input_matches_per_file(corpus, tmp_path, test_logger, expected, args):
    files, config = corpus
    saved = context(tmp_path, config, test_logger, dbfile=str(tmp_path / "dbs" / "saved.db"))
    saved.package_spool = None
    process_perfile_streaming(saved, files, "json", None, args())
    databases = sorted((tmp_path / "dbs").glob("*.db"))
    ctx = context(tmp_path, config, test_logger)
    process_db_input(ctx, args(db_input=True), file_list=databases)
    assert content(ctx) == expected


def run_mode(mode, ctx, files, args):
    if mode == "unified":
        process_unified_streaming(ctx, files, "json", None, args())
    elif mode == "per-file":
        process_perfile_streaming(ctx, files, "json", None, args())
    else:
        process_parallel_streaming(ctx, files, "json", None, args(executor=mode), recommended_workers=2)


@pytest.mark.parametrize("mode", ["per-file", "unified", "thread", "process"])
def test_inputs_read_in_part_or_not_at_all_are_recorded_on_their_part(damaged, tmp_path, test_logger, args, mode):
    files, config = damaged
    ctx = context(tmp_path, config, test_logger)

    run_mode(mode, ctx, files, args)

    assert ctx.package_errors == []
    a, b, c = (str(path) for path in files)
    unreadable = {record.part: record.unreadable for record in ctx.package_parts}
    if mode == "unified":
        assert unreadable == {0: [b, c]}
    else:
        assert unreadable == {0: [], 1: [b], 2: [c]}
    assert sum(record.events for record in ctx.package_parts) == ctx.total_events == 3


def test_an_export_failure_is_recorded_and_the_rules_still_run(corpus, tmp_path, test_logger, monkeypatch, args):
    from zircolite.package_spool import PackageError, PartWriter

    def broken(self, connection):
        raise PackageError("disk full")

    monkeypatch.setattr(PartWriter, "export_events", broken)
    files, config = corpus
    ctx = context(tmp_path, config, test_logger)
    _, results = process_perfile_streaming(ctx, files, "json", None, args())

    assert ctx.package_errors and "disk full" in ctx.package_errors[0]
    assert ctx.package_parts == []
    assert {result["title"] for result in results} == {"Encoded", "Any logon"}
