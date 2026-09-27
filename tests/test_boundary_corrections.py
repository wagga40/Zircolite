"""Regressions for source retention, unique matches and numeric/CSV boundaries."""

import csv
import gzip
import json
import os
import sqlite3
import subprocess
import sys
from argparse import Namespace
from contextlib import closing
from pathlib import Path

import pytest

from zircolite import LogTypeDetector, ProcessingConfig, ZircoliteCore
from zircolite.processing import (
    process_db_input,
    process_parallel_streaming,
    process_perfile_streaming,
    process_unified_streaming,
)
from zircolite.sqlscan import normalize_numeric_literals

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("mode", ["perfile", "unified", "thread", "process", "database"])
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink"])
def test_cli_rejects_output_aliasing_an_input(tmp_path, field_mappings_file, mode, alias):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    source = inputs / ("a.db" if mode == "database" else "a.jsonl")
    if mode == "database":
        with closing(sqlite3.connect(source)) as db:
            db.execute("CREATE TABLE logs(Value TEXT)")
            db.execute("INSERT INTO logs VALUES ('a')")
            db.commit()
    else:
        source.write_text('{"Value":"a"}\n')
        (inputs / "b.jsonl").write_text('{"Value":"b"}\n')
    original = source.read_bytes()
    output = source
    if alias != "direct":
        output = tmp_path / "alias.json"
        if alias == "symlink":
            output.symlink_to(source)
        else:
            os.link(source, output)
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"title": "all", "rule": ["SELECT * FROM logs"]}]))
    options = ["--db-input"] if mode == "database" else ["--jsononly", "--no-auto-mode"]
    if mode == "unified":
        options.append("--unified-db")
    elif mode == "perfile":
        options.append("--no-parallel")
    elif mode in ("thread", "process"):
        options += ["--parallel-workers", "2", "--executor", mode]
    result = subprocess.run([
        sys.executable, str(ROOT / "zircolite.py"), "-e", str(inputs),
        "-r", str(rules), "-c", field_mappings_file, "-o", str(output),
        "-l", str(tmp_path / "run.log"), "--quiet", "--remove-events", *options,
    ], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert result.returncode == 2, result.stdout + result.stderr
    assert source.read_bytes() == original
    assert "output" in (result.stdout + result.stderr).lower()


@pytest.mark.parametrize("mode", ["perfile", "unified", "parallel", "database"])
def test_library_rejects_output_aliasing_an_input(tmp_path, make_processing_context, mode):
    source = tmp_path / "events.jsonl"
    if mode == "database":
        with closing(sqlite3.connect(source)) as db:
            db.execute("CREATE TABLE logs(Value TEXT)")
            db.execute("INSERT INTO logs VALUES ('a')")
            db.commit()
    else:
        source.write_text('{"Value":"a"}\n')
    original = source.read_bytes()
    ctx = make_processing_context(no_output=False, outfile=str(source))
    args = Namespace(json_input=True)
    with pytest.raises(ValueError, match="output"):
        if mode == "database":
            process_db_input(ctx, args, file_list=[source])
        else:
            process = {"perfile": process_perfile_streaming, "unified": process_unified_streaming,
                       "parallel": process_parallel_streaming}[mode]
            process(ctx, [source], "json", None, args)
    assert source.read_bytes() == original


@pytest.mark.parametrize("no_output", [False, True])
def test_separate_output_or_disabled_output_preserves_input(tmp_path, make_processing_context, no_output):
    source = tmp_path / "events.jsonl"
    source.write_text('{"Value":"a"}\n')
    original = source.read_bytes()
    output = source if no_output else tmp_path / "results.json"
    if not no_output:
        output.write_text("old report")
    ctx = make_processing_context(no_output=no_output, outfile=str(output), rulesets=[
        {"title": "all", "rule": ["SELECT * FROM logs"]},
    ])
    core, results = process_unified_streaming(ctx, [source], "json", None, Namespace(json_input=True))
    core.close()
    assert results[0]["count"] == 1
    assert source.read_bytes() == original
    if not no_output:
        assert json.loads(output.read_text())[0]["matches"][0]["Value"] == "a"


@pytest.mark.parametrize("stream_rows", [False, True])
@pytest.mark.parametrize("limit", [-1, 2])
def test_overlapping_queries_count_unique_events(field_mappings_file, stream_rows, limit):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True, limit=limit))) as core:
        core.create_db("Value INTEGER")
        # Equal payloads still represent two distinct events.
        core.insert_data_to_db([{"Value": 1}, {"Value": 1}])
        result = core._execute_rule({"title": "overlap", "rule": [
            "SELECT * FROM logs WHERE row_id=1", "SELECT * FROM logs WHERE Value=1",
        ]}, stream_rows=stream_rows)
        try:
            assert result.get("count") == 2
            assert [row["row_id"] for row in result["matches"]] == [1, 2]
        finally:
            if stream_rows and result:
                result["matches"].close()


def test_duplicates_do_not_hide_a_later_unique_match(field_mappings_file):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True, limit=2))) as core:
        core.create_db("Value INTEGER")
        core.insert_data_to_db([{"Value": 1}, {"Value": 2}])
        result = core.execute_rule({"title": "overlap", "rule": [
            "SELECT * FROM logs WHERE row_id=1",
            "SELECT * FROM logs UNION ALL SELECT * FROM logs ORDER BY row_id",
        ]})
        assert result.get("count") == 2


def test_one_overlapping_event_survives_limit_one(field_mappings_file):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True, limit=1))) as core:
        core.create_db("Value INTEGER")
        core.insert_data_to_db({"Value": 1})
        rule = {"rule": ["SELECT * FROM logs", "SELECT * FROM logs WHERE Value=1"]}
        assert core.execute_rule(rule)["count"] == 1
        core.insert_data_to_db({"Value": 1})
        assert core.execute_rule(rule) == {}


def test_projection_results_without_event_identity_are_preserved(field_mappings_file):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        core.create_db("Value INTEGER")
        result = core.execute_rule({"rule": [
            "SELECT COUNT(*) AS n FROM logs", "SELECT COUNT(Value) AS n FROM logs",
        ]})
        assert result["matches"] == [{"n": 0}, {"n": 0}]


def test_overlapping_negative_row_ids_are_deduplicated(field_mappings_file):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        core.create_db("Value INTEGER")
        core.insert_data_to_db([{"row_id": -1, "Value": 1}, {"row_id": 1, "Value": 1}])
        result = core.execute_rule({"rule": ["SELECT * FROM logs", "SELECT * FROM logs WHERE Value=1"]})
        assert [row["row_id"] for row in result["matches"]] == [-1, 1]


@pytest.mark.parametrize("stream_rows", [False, True])
def test_failed_query_rolls_back_seen_event_ids(field_mappings_file, stream_rows):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        core.create_db("Value INTEGER")
        core.insert_data_to_db([{"Value": i} for i in range(300)])
        result = core._execute_rule({"title": "failure", "rule": [
            "SELECT * FROM logs WHERE Value < 290 OR json_extract('broken', '$.x')=1",
            "SELECT * FROM logs",
        ]}, stream_rows=stream_rows)
        try:
            assert result["count"] == 300
            assert len({row["row_id"] for row in result["matches"]}) == 300
            assert "failure" in core.rules_in_error
        finally:
            if stream_rows:
                result["matches"].close()


@pytest.mark.parametrize("backend", ["python", "auto"])
@pytest.mark.parametrize("batch_size", [1, 5000])
@pytest.mark.parametrize("first", [1, 1.5])
@pytest.mark.parametrize("kind", ["plain", "alias", "transform", "split", "case_variant"])
def test_oversized_integer_strings_remain_exact(tmp_path, backend, batch_size, first, kind):
    mapping = {}
    if kind == "alias":
        mapping = {"alias": {"Value": "Copy"}}
    elif kind == "transform":
        mapping = {"transforms_enabled": True, "transforms": {"Source": [{
            "alias": True, "alias_name": "Value", "source_condition": ["json_input"],
            "code": "def transform(param):\n    return param",
        }]}}
    elif kind == "split":
        mapping = {"split": {"Payload": {"separator": ",", "equal": "="}}}
    config = tmp_path / "mapping.json"
    config.write_text(json.dumps(mapping))
    values = [first, "18446744073709551615", "-9223372036854775809", "1"]
    events = [{"Value": value} for value in values]
    if kind == "transform":
        events = [{"Source": value} for value in values]
    elif kind == "split":
        events[1:] = [{"Payload": f"Value={value}"} for value in values[1:]]
    elif kind == "case_variant":
        events[1] = {"value": values[1]}
    source = tmp_path / "events.jsonl"
    source.write_text("".join(json.dumps(event) + "\n" for event in events))
    with closing(ZircoliteCore(str(config), ProcessingConfig(
        no_output=True, flatten_backend=backend, batch_size=batch_size,
    ))) as core:
        assert core.run_streaming([source], "json", Namespace(json_input=True), disable_progress=True) == 4
        assert [row["Value"] for row in core.execute_select_query("SELECT Value FROM logs ORDER BY row_id")] == [
            first, "18446744073709551615", "-9223372036854775809", 1,
        ]
        if kind == "alias":
            assert [row["Copy"] for row in core.execute_select_query("SELECT Copy FROM logs ORDER BY row_id")] == [
                first, "18446744073709551615", "-9223372036854775809", 1,
            ]


@pytest.mark.parametrize("condition,expected", [
    ("Value < 0", [1, 2]),
    ("Value < '0'", [1, 2]),
    ("0 > Value", [1, 2]),
    ("Value = 18446744073709551615", [6]),
    ("18446744073709551615 = Value", [6]),
    ("Value = '18446744073709551614'", [5]),
    ("Value = - 9223372036854775809", [1]),
    ("Value >= -9223372036854775809 AND Value <= -1", [1, 2]),
    ("Value IN (18446744073709551615, '1', NULL)", [4, 6]),
    ("Value NOT IN (18446744073709551615, '1', NULL)", []),
    ("Value BETWEEN '-9223372036854775809' AND '-1'", [1, 2]),
    ("Value IS 18446744073709551615", [6]),
    ("Value IS NOT 18446744073709551615", [1, 2, 3, 4, 5, 7, 8]),
    ("Value IS NULL", [8]),
    ("Value = 'ALPHA'", [7]),
    ("Value COLLATE BINARY = 'ALPHA'", []),
    ("Value IN ('ALPHA' COLLATE BINARY)", []),
    ("Value IN ('ALPHA' COLLATE BINARY, 'x')", [7]),
    ("Value NOT IN ('ALPHA' COLLATE BINARY, 'x')", [1, 2, 3, 4, 5, 6]),
    ("Value IN (('ALPHA' COLLATE BINARY), NULL, 18446744073709551615)", [6, 7]),
    ("Value COLLATE BINARY IN ('ALPHA' COLLATE NOCASE, 'x')", []),
    ("(logs.Value) = 18446744073709551615", [6]),
])
def test_promoted_numeric_predicates_are_exact(field_mappings_file, condition, expected):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        core.create_db("Value BLOB_NUMERIC COLLATE NOCASE")
        core.insert_data_to_db([{"Value": value} for value in [
            "-9223372036854775809", -1, 0, 1,
            "18446744073709551614", "18446744073709551615", "Alpha", None,
        ]])
        rows = core.execute_select_query(f"SELECT row_id FROM logs WHERE {condition}")
        assert [row["row_id"] for row in rows] == expected


def test_numeric_rewrite_is_stable_across_query_repair():
    # A missing column retries the normalized SQL; its fallback must not grow
    # another UDF wrapper on every repair or repeated library execution.
    columns = frozenset({"value"})
    normalized = normalize_numeric_literals("SELECT * FROM logs WHERE Value < 0", columns)
    assert normalize_numeric_literals(normalized, columns) == normalized


@pytest.mark.parametrize("backend", ["python", "auto"])
def test_negative_large_integer_range_survives_database_roundtrip(tmp_path, field_mappings_file, backend):
    source = tmp_path / "events.json"
    source.write_text('[{"Value":1},{"Value":-9223372036854775809}]')
    saved = tmp_path / "saved.db"
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True, flatten_backend=backend))) as core:
        assert core.run_streaming([source], "json_array", Namespace(json_array_input=True), disable_progress=True) == 2
        query = "SELECT Value FROM logs WHERE Value < 0"
        assert core.execute_select_query(query) == [{"Value": "-9223372036854775809"}]
        core.save_db_to_disk(str(saved))
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as reloaded:
        reloaded.load_db_in_memory(str(saved))
        assert reloaded.execute_select_query(query) == [{"Value": "-9223372036854775809"}]


@pytest.mark.parametrize("size", [131072, 131073, 1048576])
@pytest.mark.parametrize("compressed", [False, True])
def test_large_csv_fields_keep_following_records(tmp_path, field_mappings_file, size, compressed):
    source = tmp_path / ("events.csv.gz" if compressed else "events.csv")
    opener = gzip.open if compressed else open
    value = "x" * (size - 5) + "\ntail"
    with opener(source, "wt", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows([["Value"], [value], ["needle"]])
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        assert core.run_streaming([source], "csv", Namespace(csv_input=True), disable_progress=True) == 2
        assert core.execute_select_query("SELECT Value FROM logs ORDER BY row_id") == [
            {"Value": value}, {"Value": "needle"},
        ]
        assert not core.failed_files


def test_csv_detection_accepts_a_large_first_record():
    # Use the classifier directly so its complete sample includes the large field.
    detected = LogTypeDetector()._check_csv(
        ["Value,Other,Third", "x" * 131073 + ",data,more"], ".log",
    )
    assert detected is not None
    assert detected.input_type == "csv"
