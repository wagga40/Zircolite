"""Correctness and resource-boundary regressions from the throughput review."""

import csv
import gzip
import io
import json
import logging
import subprocess
import sys
import tempfile
import time
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

from zircolite import EventFilter, ProcessingConfig, StreamingEventProcessor, ZircoliteCore
from zircolite.console import set_quiet_mode
from zircolite.jsonstream import iter_json_array
from zircolite.processing import (
    ProcessingContext,
    process_parallel_streaming,
    process_perfile_streaming,
)
from zircolite.results import RowSpool, result_summary, write_result_json
from zircolite.streaming import StrictParseError
from zircolite.utils import MemoryTracker, estimate_input_size, load_field_mappings


@pytest.fixture
def processor(field_mappings_file):
    return StreamingEventProcessor(field_mappings_file, Namespace(json_input=True))


def test_hints_never_override_precedence(processor):
    event_filter = EventFilter([{"rule": ["SELECT * FROM logs WHERE Channel='Security' AND EventID=4624"]}])
    processor.event_filter = event_filter
    processor._filtering_enabled = True
    processor._extract_event_filter_fields({"Channel": "Other", "EventID": 1})
    event = {"Channel": "Other", "EventID": 1,
             "Event": {"System": {"Channel": "Security", "EventID": 4624}}}
    # The fields disagree, so neither precedence nor the hint picks one: the
    # filter cannot tell which value the flattener puts in the column
    assert processor._extract_event_filter_fields(event) == (None, None)
    assert processor._should_process_event(event)
    agreeing = {"Channel": "Security", "EventID": 4624,
                "Event": {"System": {"Channel": "Security", "EventID": 4624}}}
    assert processor._extract_event_filter_fields(agreeing) == ("Security", 4624)


def test_filter_leaves_non_object_json_lines_alone(processor):
    processor.event_filter = EventFilter([{"rule": ["SELECT * FROM logs WHERE Channel='Security'"]}])
    processor._filtering_enabled = True
    # Longer than the configured channel paths, so the walk would index into it
    line = list(range(20))
    assert processor._extract_event_filter_fields(line) == (None, None)
    assert processor._should_process_event(line)


@pytest.mark.parametrize("query,channel,eventid", [
    ("SELECT * FROM logs WHERE EventID=1+1", "System", 2),
    ("SELECT * FROM logs WHERE Channel='Sec'||'urity'", "Security", 2),
    ("SELECT * FROM logs WHERE Channel='Security' UNION SELECT * FROM logs WHERE Channel='System'", "System", 2),
    ("SELECT * FROM logs WHERE (EventID=1) IS FALSE", "System", 2),
    ("SELECT * FROM logs WHERE EventID IN (1+1,3)", "System", 2),
    ("SELECT * FROM logs WHERE NOT EXISTS (SELECT 1 FROM logs WHERE EventID=1)", "System", 2),
])
def test_prefilter_keeps_actual_sql_matches(field_mappings_file, query, channel, eventid):
    core = ZircoliteCore(field_mappings_file)
    try:
        core.create_db("Channel TEXT, EventID INTEGER")
        core.insert_data_to_db({"Channel": channel, "EventID": eventid})
        assert core.execute_select_query(query)
        assert EventFilter([{"rule": [query]}]).should_process_event(channel, eventid)
    finally:
        core.close()


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("bad", [{"data": "{"}, RuntimeError("bad record"), {}])
def test_evtx_errors_are_accounted_for(processor, strict, bad):
    processor.strict_evtx = strict
    with patch("zircolite.streaming.PyEvtxParser") as parser:
        parser.return_value.records_json.return_value = iter([
            {"data": '{"EventID":1}'}, bad, {"data": '{"EventID":2}'},
        ])
        if strict:
            with pytest.raises(StrictParseError):
                list(processor.stream_evtx_events("sample.evtx"))
        else:
            assert len(list(processor.stream_evtx_events("sample.evtx"))) == 2
    assert processor.ingest_degraded


@pytest.mark.parametrize("content", [
    b'[{"EventID":1},{"broken":', b'[{"EventID":1} {"EventID":2}]',
    b'[{"EventID":1}]TRAILING', b'[{"EventID":1},]', b'[{"EventID":1}',
])
def test_array_damage_retains_prefix_and_marks_source(processor, tmp_path, content):
    path = tmp_path / "events.json.gz"
    with gzip.open(path, "wb") as source:
        source.write(content)
    events = list(processor.stream_json_array_chunked(str(path)))
    assert events and events[0]["EventID"] == 1
    assert processor.ingest_degraded


def test_stdlib_array_parser_chunk_boundaries(monkeypatch):
    monkeypatch.setattr("zircolite.jsonstream.ijson", None)
    monkeypatch.setattr("zircolite.jsonstream._CHUNK", 3)
    value = [{"text": "a😃\\\"", "uint": 2**64-1, "float": 1.25}, 1234, None, {}]
    assert list(iter_json_array(io.BytesIO(json.dumps(value).encode()))) == [value[0], {}]


def test_ijson_numeric_parity_when_installed():
    pytest.importorskip("ijson")
    assert list(iter_json_array(io.BytesIO(b'[{"n":18446744073709551615,"f":1.25}]'))) == [
        {"n": 2**64-1, "f": 1.25}]


def test_failed_batch_is_atomic(field_mappings_file, processor):
    core = ZircoliteCore(field_mappings_file)
    try:
        processor.create_initial_table(core.db_connection)
        processor._flatten_event({"Value": "ok"}, "sample")
        with pytest.raises(OverflowError):
            processor._insert_batch(core.db_connection, core.db_connection.cursor(),
                                    [{"Value": "ok"}, {"Value": 2**100}])
        assert core.execute_select_query("SELECT count(*) AS n FROM logs") == [{"n": 0}]
    finally:
        core.close()


def test_alias_values_are_normalized_and_typed(field_mappings_file):
    config = load_field_mappings(field_mappings_file)
    config["transforms_enabled"] = True
    config["transforms"] = {"Value": [
        {"code": "def transform(param):\n    return 18446744073709551615",
         "alias": True, "alias_name": "Big", "source_condition": ["json_input"]},
        {"code": "def transform(param):\n    return True",
         "alias": True, "alias_name": "Flag", "source_condition": ["json_input"]},
    ]}
    processor = StreamingEventProcessor(field_mappings_file, Namespace(json_input=True), _raw_config=config)
    row = processor._flatten_event({"Value": 1}, "sample")
    assert row["Big"] == str(2**64-1)
    assert row["Flag"] == "true"
    assert processor.field_types["Big"] == "TEXT COLLATE NOCASE"


def test_missing_quoted_identifier_is_null(field_mappings_file):
    core = ZircoliteCore(field_mappings_file)
    try:
        core.create_db("EventID INTEGER")
        core.insert_data_to_db({"EventID": 1})
        assert len(core.execute_select_query('SELECT * FROM logs WHERE "Missing" IS NULL')) == 1
        assert not core.rules_in_error
    finally:
        core.close()


def test_inactive_transforms_do_not_compile():
    processor = StreamingEventProcessor("config/config.yaml", Namespace(json_input=True))
    assert not processor.compiled_code_cache


def test_streamed_results_and_limit(field_mappings_file, tmp_path):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(limit=3, disable_progress=True))
    seen = []
    try:
        core.create_db("n INTEGER")
        core.insert_data_to_db([{"n": i} for i in range(1000)])
        core.load_ruleset_from_var([
            {"title": "large", "rule": ["SELECT * FROM logs"]},
            {"title": "combined", "rule": ["SELECT * FROM logs WHERE n<2", "SELECT * FROM logs WHERE n<2"]},
            {"title": "small", "rule": ["SELECT * FROM logs WHERE n<3"]},
        ], rule_filters=None)
        def collect(result):
            assert isinstance(result["matches"], RowSpool)
            seen.append(result_summary(result))
        output = tmp_path / "out.json"
        core.execute_ruleset(str(output), stream_results=True, result_sink=collect, last_ruleset=True)
        saved = json.loads(output.read_bytes())
        assert [r["title"] for r in saved] == ["small"]
        assert len(saved[0]["matches"]) == 3
        assert "matches" not in seen[0]
        assert not core.full_results
    finally:
        core.close()


def test_partial_query_results_are_discarded(field_mappings_file, tmp_path):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(disable_progress=True))
    try:
        core.create_db("n INTEGER")
        core.insert_data_to_db([{"n": i} for i in range(1000)])
        def fail(n):
            if n == 800:
                raise ValueError("UDF failed after several chunks")
            return n
        core.db_connection.create_function("fail", 1, fail)
        core.load_ruleset_from_var([{"title": "bad", "rule": [
            "SELECT * FROM logs WHERE n=0", "SELECT fail(n) FROM logs"]}], rule_filters=None)
        output = tmp_path / "out.json"
        core.execute_ruleset(str(output), stream_results=True, last_ruleset=True)
        assert json.loads(output.read_bytes())[0]["count"] == 1
        assert "bad" in core.rules_in_error
    finally:
        core.close()


@pytest.mark.parametrize("executor", ["sequential", "thread", "process", "process-auto"])
@pytest.mark.parametrize("csv_mode", [False, True])
@pytest.mark.parametrize("retain", [False, True])
def test_executor_output_parity(field_mappings_file, tmp_path, executor, csv_mode, retain):
    set_quiet_mode(True)
    inputs = []
    for i in range(3):
        source = tmp_path / f"input{i}.jsonl"
        source.write_text(json.dumps({"EventID": 1, f"Field{i}": f"value{i}"}) + "\n")
        inputs.append(source)
    logger = logging.getLogger("review_test")
    ctx = ProcessingContext(
        config=field_mappings_file, logger=logger, no_output=False,
        events_after=time.strptime("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
        events_before=time.strptime("9999-12-12T23:59:59", "%Y-%m-%dT%H:%M:%S"),
        limit=-1, csv_mode=csv_mode, time_field="SystemTime", hashes=False,
        db_location=":memory:", delimiter=";", rulesets=[{"title": "match", "id": "test", "rule": ["SELECT * FROM logs WHERE EventID=1"]}],
        rule_filters=None, outfile=str(tmp_path / "out"), ready_for_templating=False,
        package=False, dbfile=None, keepflat=False, memory_tracker=MemoryTracker(), retain_results=retain,
    )
    auto = executor == "process-auto"
    args = Namespace(json_input=True, executor="process" if auto else executor, parallel_workers=None if auto else 2)
    try:
        if executor == "sequential":
            core, results = process_perfile_streaming(ctx, inputs, "json", None, args)
        else:
            with patch("zircolite.parallel.os.cpu_count", return_value=4), \
                 patch("zircolite.parallel.MemoryAwareParallelProcessor.get_available_memory_mb", return_value=4096):
                core, results = process_parallel_streaming(ctx, inputs, "json", None, args, recommended_workers=1)
            if auto:
                assert ctx.workers_used == 3
        if core is not None:
            core.close()
        assert ctx.total_events == 3
        assert sum(r["count"] for r in results) == 3
        assert all(("matches" in r) == retain for r in results)
        if csv_mode:
            with open(ctx.outfile, newline="") as source:
                rows = list(csv.DictReader(source, delimiter=";"))
            assert len(rows) == 3
            assert all(f"Field{i}" in rows[0] for i in range(3))
            for i in range(3):
                assert any(row[f"Field{i}"] == f"value{i}" for row in rows)
        else:
            saved = json.loads(Path(ctx.outfile).read_bytes())
            assert sum(len(r["matches"]) for r in saved) == 3
    finally:
        set_quiet_mode(False)


def test_expanded_size_used_for_zip(tmp_path):
    import zipfile
    path = tmp_path / "events.zip"
    data = b"x" * 100000
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("events.json", data)
    assert estimate_input_size(path) == len(data)


def test_zip_member_is_not_read_eagerly(tmp_path):
    import zipfile

    from zircolite.utils import open_maybe_compressed
    path = tmp_path / "events.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("events.json", b"x" * 100000)
    with patch.object(zipfile.ZipFile, "read", side_effect=AssertionError("full member read")):
        with open_maybe_compressed(path) as source:
            assert source.read(10) == b"x" * 10
            assert not isinstance(source, io.BytesIO)
        assert source.closed


def test_incomplete_evtx_source_is_kept(field_mappings_file, tmp_path):
    from zircolite.cli import cleanup
    source = tmp_path / "events.evtx"
    source.write_bytes(b"fixture placeholder")
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(disable_progress=True))
    try:
        with patch("zircolite.streaming.PyEvtxParser") as parser:
            parser.return_value.records_json.return_value = iter([
                {"data": '{"EventID":1}'}, {"data": '{"broken":'},
            ])
            assert core.run_streaming([source], disable_progress=True) == 1
        cleanup(Namespace(remove_events=True), logging.getLogger("review_test"),
                [source], failed=core.failed_files)
        assert source.exists()
    finally:
        core.close()


def _worker_failure(_):
    raise RuntimeError("worker failed before returning a result")


def test_process_exceptions_report_failed_sources(tmp_path):
    from zircolite.parallel import MemoryAwareParallelProcessor, ParallelConfig
    source = tmp_path / "events.jsonl"
    source.write_text("{}\n")
    processor = MemoryAwareParallelProcessor(ParallelConfig(max_workers=1, executor="process"))
    results, stats = processor.process_files_parallel([source], _worker_failure, disable_progress=True)
    assert not results
    assert stats.failed_files == [(str(source), "worker failed before returning a result")]


def test_limit_stops_retrieving_rows(field_mappings_file):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(limit=2))
    calls = []
    try:
        core.create_db("n INTEGER")
        core.insert_data_to_db([{"n": i} for i in range(1000)])
        def visit(n):
            calls.append(n)
            return n
        core.db_connection.create_function("visit", 1, visit)
        assert not core.execute_rule({"rule": ["SELECT visit(n) FROM logs"]})
        assert len(calls) <= 4  # limit + overflow row + SQLite cursor lookahead
    finally:
        core.close()


def test_throughput_harness_checks_output(tmp_path):
    report = tmp_path / "report.json"
    root = Path(__file__).resolve().parent.parent
    completed = subprocess.run([
        sys.executable, str(root / "tools/throughput-benchmark.py"),
        "--event-count", "12", "--files", "2", "--passes", "1",
        "--modes", "sequential", "thread", "--report", str(report),
    ], cwd=root, capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    saved = json.loads(report.read_text())
    assert len({run["fingerprint"] for runs in saved["results"].values() for run in runs}) == 1


@pytest.mark.parametrize("payload", [b'[{}\x0b]', b'[\xc2\xa0{}]'])
def test_array_parser_rejects_non_json_whitespace(payload):
    with patch("zircolite.jsonstream.ijson", None), pytest.raises(ValueError):
        list(iter_json_array(io.BytesIO(payload)))


def test_progress_failure_closes_detection_spool(field_mappings_file):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))
    spool = RowSpool()
    try:
        core.create_db("n INTEGER")
        core.insert_data_to_db({"n": 1})
        core.load_ruleset_from_var([{"title": "match", "rule": ["SELECT * FROM logs"]}], rule_filters=None)
        def progress(done, total):
            if done:
                raise RuntimeError("callback failed")
        with patch.object(RowSpool, "__new__", return_value=spool), pytest.raises(RuntimeError, match="callback failed"):
            # Reusing this already initialized object would otherwise orphan
            # its original handle when __init__ runs a second time.
            spool.close()
            core.execute_ruleset("unused", stream_results=True, progress_callback=progress)
        assert spool.file.closed
    finally:
        spool.close()
        core.close()


@pytest.mark.parametrize("available_mb, expected_max", [(128, 1), (100000, 4)])
def test_process_workers_budget_interpreter_memory_and_cpus(tmp_path, available_mb, expected_max):
    from zircolite.parallel import MemoryAwareParallelProcessor, ParallelConfig
    source = tmp_path / "tiny.jsonl"
    source.write_text("{}\n")
    processor = MemoryAwareParallelProcessor(ParallelConfig(executor="process"))
    with patch.object(processor, "get_available_memory_mb", return_value=available_mb), \
         patch("zircolite.parallel.os.cpu_count", return_value=4):
        assert 1 <= processor.calculate_optimal_workers([source] * 20) <= expected_max


def test_spooled_json_serialization_across_chunks():
    spool = RowSpool()
    expected = [{"n": n, "text": 'unicode 😃 and "quotes"\n'} for n in range(5000)]
    try:
        for row in expected:
            spool.append(row)
        chunks = []
        write_result_json(chunks.append, {"title": "test", "matches": spool})
        assert json.loads(b"".join(chunks))["matches"] == expected
        # Serialization leaves the callback's repeatable iterator usable.
        assert list(spool) == expected
    finally:
        spool.close()


def test_spool_creates_its_file_only_once_a_row_arrives(field_mappings_file):
    # Most rules match nothing; a temporary file per rule per database cost
    # 0.1 ms each, 0.44 s for one pass of the merged Windows ruleset.
    spool = RowSpool()
    try:
        assert spool.file is None
        checkpoint = spool.checkpoint()
        assert list(spool) == []
        assert b"".join(spool.json_chunks()) == b""
        spool.append({"n": 1})
        spool.rollback(checkpoint)
        assert len(spool) == 0 and list(spool) == []
        spool.append({"n": 2})
        assert list(spool) == [{"n": 2}]
    finally:
        spool.close()

    created = []
    real = tempfile.TemporaryFile

    def counting(*args, **kwargs):
        created.append(1)
        return real(*args, **kwargs)

    core = ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))
    try:
        core.create_db("n INTEGER")
        core.insert_data_to_db({"n": 1})
        rules = [{"title": f"quiet {i}", "rule": [f"SELECT * FROM logs WHERE n = {i + 2}"]} for i in range(20)]
        rules.append({"title": "match", "rule": ["SELECT * FROM logs WHERE n = 1"]})
        core.load_ruleset_from_var(rules, rule_filters=None)
        with patch("zircolite.results.tempfile.TemporaryFile", counting):
            core.execute_ruleset("unused", stream_results=True, disable_progress=True, show_table=False)
    finally:
        core.close()
    assert len(created) == 1
