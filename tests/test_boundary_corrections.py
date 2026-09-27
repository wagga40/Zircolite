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
        "-l", str(tmp_path / "run.log"), "--quiet", *options,
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
