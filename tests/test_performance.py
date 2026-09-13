"""Acceleration parity, observable activation, and bounded performance reports."""

import json
import sqlite3
import subprocess
import sys
import threading
from collections import Counter
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import psutil
import pytest

from zircolite.parallel import select_executor
from zircolite.performance import FileMetrics, aggregate_stages
from zircolite.prefilter import LiteralPrefilter
from zircolite.utils import MemoryTracker

ROOT = Path(__file__).resolve().parents[1]


def test_nested_stage_timings_are_exclusive_even_on_error(monkeypatch):
    ticks = iter([0.0, 1.0, 3.0, 5.0])
    monkeypatch.setattr("zircolite.performance.perf_counter", lambda: next(ticks))
    metrics = FileMetrics()
    with pytest.raises(ValueError), metrics.stage("ingestion"), metrics.stage("indexes"):
        raise ValueError("interrupted")
    assert metrics.data["seconds"]["ingestion"] == 3
    assert metrics.data["seconds"]["indexes"] == 2
    # Parallel work totals can exceed the elapsed wall time, without a percent.
    assert sum(aggregate_stages([metrics.data, metrics.data]).values()) == 10


def test_sparse_null_fields_do_not_exhaust_literal_budget():
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, text TEXT)")
        conn.executemany("INSERT INTO logs(text) VALUES (?)", ((None,) for _ in range(64000)))
        conn.execute("INSERT INTO logs(text) VALUES ('needle00')")
        rules = [{"rule": [f"SELECT * FROM logs WHERE text LIKE '%needle{i:02d}%'"]} for i in range(32)]
        with closing(LiteralPrefilter(conn, rules, automatic=True, max_postings=10)) as prefilter:
            assert prefilter.reason is None
            assert len(prefilter.plans) == 32
            for rule in rules:
                query = rule["rule"][0]
                assert conn.execute(prefilter.rewrite(query)).fetchall() == conn.execute(query).fetchall()
            assert prefilter.stats()["applied_queries"] == 32
            assert prefilter.stats()["postings"] == 1
        assert not conn.execute("SELECT name FROM sqlite_temp_master").fetchall()


def test_budget_overflow_keeps_other_columns_and_boolean_semantics():
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, broad TEXT, rare TEXT)")
        conn.executemany("INSERT INTO logs(broad,rare) VALUES (?,?)",
                         (("common", "needle" if i == 499 else None) for i in range(500)))
        atoms = ["broad LIKE '%common%'", "rare LIKE '%needle%'"]
        queries = ["SELECT * FROM logs WHERE " + expression for expression in (
            atoms[0], atoms[1], f"{atoms[0]} AND {atoms[1]}", f"{atoms[0]} OR {atoms[1]}",
            f"NOT ({atoms[0]}) OR {atoms[1]}", f"NOT ({atoms[0]}) AND {atoms[1]}",
        )]
        with closing(LiteralPrefilter(conn, [{"rule": queries}], max_postings=20)) as prefilter:
            assert prefilter.skipped_columns == {"broad": "literal posting budget exceeded"}
            assert prefilter.reason is None
            assert prefilter.stats()["postings"] == 1
            for query in queries:
                assert Counter(conn.execute(prefilter.rewrite(query))) == Counter(conn.execute(query)), query
            assert prefilter.accelerated > 0


def test_nontext_candidates_are_shared_without_losing_sqlite_matches():
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, value)")
        conn.executemany("INSERT INTO logs(value) VALUES (?)", [(12345,), (b"12345",)] + [(None,)] * 50)
        queries = [f"SELECT * FROM logs WHERE value LIKE '%{n}%'" for n in (123, 234, 345)]
        with closing(LiteralPrefilter(conn, [{"rule": queries}], max_postings=2)) as prefilter:
            assert prefilter.reason is None
            assert prefilter.stats()["postings"] == 2
            for query in queries:
                assert list(conn.execute(prefilter.rewrite(query))) == list(conn.execute(query))


def test_memory_average_uses_all_samples_with_bounded_storage(monkeypatch):
    tracker = MemoryTracker()
    samples = iter([1000.0] + [1.0] * 999)
    monkeypatch.setattr(tracker, "get_memory_usage", lambda: next(samples))
    for _ in range(1000):
        tracker.sample()
    assert len(tracker.memory_samples) == 128
    assert tracker.get_stats() == (1000.0, 1.999)


def test_sampler_observes_peak_between_phase_boundaries(monkeypatch):
    tracker = MemoryTracker()
    seen = threading.Event()
    calls = 0

    def memory():
        nonlocal calls
        calls += 1
        if calls == 2:
            seen.set()
            return 500.0
        return 10.0

    monkeypatch.setattr(tracker, "get_memory_usage", memory)
    tracker.start()
    try:
        assert seen.wait(3)
    finally:
        tracker.stop()
    assert tracker.get_stats()[0] == 500
    assert tracker._sampling_thread is None


def test_memory_reports_incomplete_tree_and_includes_known_workers(monkeypatch):
    tracker = MemoryTracker()
    tracker.process = Mock()
    tracker.process.memory_info.return_value.rss = 10 * 1024**2
    tracker.process.children.side_effect = psutil.AccessDenied()
    monkeypatch.setattr("zircolite.utils.multiprocessing.active_children", lambda: [SimpleNamespace(pid=123)])
    worker = Mock()
    worker.memory_info.return_value.rss = 100 * 1024**2
    monkeypatch.setattr("zircolite.utils.psutil.Process", lambda pid: worker)
    assert tracker.get_memory_usage() == 110
    assert not tracker.complete_scope


@pytest.mark.parametrize("requested,average,count,ram,cpus,auto,maximum,expected", [
    ("auto", 50, 2, 4096, 2, True, None, "process"),
    ("auto", 49, 2, 4096, 2, True, None, "thread"),
    ("auto", 100, 1, 4096, 8, True, None, "thread"),
    ("auto", 100, 4, 512, 8, True, None, "thread"),
    ("auto", 100, 4, 4096, 1, True, None, "thread"),
    ("auto", 100, 4, 4096, 8, False, None, "thread"),
    ("auto", 100, 4, 4096, 8, True, 1, "thread"),
    ("thread", 100, 4, 4096, 8, True, None, "thread"),
    ("process", 1, 2, 512, 1, False, None, "process"),
])
def test_executor_selection(requested, average, count, ram, cpus, auto, maximum, expected):
    selected, reason = select_executor(requested, [average * 1024**2] * count, ram, cpus,
                                       auto_mode=auto, max_workers=maximum)
    assert selected == expected
    assert reason


@pytest.fixture
def corpus(tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for name in ("first", "second"):
        rows = [{"CommandLine": "needle00" if i % 100 == 0 else None} for i in range(1100)]
        (inputs / f"{name}.jsonl").write_text("\n".join(json.dumps(row) for row in rows))
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"title": f"Rule {i}", "id": str(i), "level": "high",
                                 "rule": [f"SELECT * FROM logs WHERE CommandLine LIKE '%needle{i:02d}%'"]}
                                for i in range(32)]))
    return inputs, rules


def run_cli(corpus, tmp_path, *flags):
    inputs, rules = corpus
    return subprocess.run([sys.executable, str(ROOT / "zircolite.py"), "-e", str(inputs),
                           "-r", str(rules), *([] if "-D" in flags else ["--json-input"]), "--quiet", "--flatten-backend", "python",
                           "-o", str(tmp_path / "matches.json"), "--logfile", str(tmp_path / "run.log"),
                           *flags], cwd=ROOT, capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize("mode", ["sequential", "thread", "process"])
def test_cli_reports_actual_activation_and_per_file_metrics(corpus, tmp_path, mode):
    report = tmp_path / "metrics.json"
    flags = ["--no-parallel"] if mode == "sequential" else ["--executor", mode, "--parallel-workers", "2"]
    result = run_cli(corpus, tmp_path, "--performance-json", str(report), *flags)
    assert result.returncode == 0, result.stderr + result.stdout
    data = json.loads(report.read_text())
    assert data["schema_version"] == 1 and data["status"] == "complete"
    assert data["settings"]["executor_selected"] == mode
    assert data["events"] == 2200
    assert len(data["files"]) == 2
    for record in data["files"]:
        assert record["flattening"]["selected"] == "python"
        assert record["events"] == 1100
        assert record["prefilter"][0]["applied_queries"] == 32
        assert record["prefilter"][0]["postings"] == 11
        assert record["seconds"]["ingestion"] > 0
    assert sum(r["count"] for r in json.loads((tmp_path / "matches.json").read_text())) == 22
    assert "Literal filter" in result.stdout and "Stage times" in result.stdout
    assert data["memory"]["sampled_peak_rss_mib"] > 0


def test_explicit_report_is_written_with_nolog_and_cli_overrides_yaml(corpus, tmp_path):
    report = tmp_path / "metrics.json"
    unused = tmp_path / "unused.json"
    config = tmp_path / "run.yaml"
    config.write_text(f"output:\n  performance_json: {unused}\nparallel:\n  executor: thread\n")
    result = run_cli(corpus, tmp_path, "--nolog", "--yaml-config", str(config), "--performance-json", str(report))
    assert result.returncode == 0, result.stderr + result.stdout
    assert report.exists() and not unused.exists()
    assert not (tmp_path / "matches.json").exists()


def test_report_cannot_overwrite_detection_output(corpus, tmp_path):
    output = tmp_path / "matches.json"
    output.write_text("preserve this")
    result = run_cli(corpus, tmp_path, "--performance-json", str(output))
    assert result.returncode != 0
    assert output.read_text() == "preserve this"


def test_partial_ingestion_is_recorded(corpus, tmp_path):
    inputs, _ = corpus
    with (inputs / "first.jsonl").open("a") as source:
        source.write('\n{"broken":\n')
    report = tmp_path / "metrics.json"
    result = run_cli(corpus, tmp_path, "--no-parallel", "--performance-json", str(report))
    assert result.returncode == 0, result.stderr + result.stdout
    data = json.loads(report.read_text())
    assert data["status"] == "partial"
    by_source = {Path(record["sources"][0]).name: record for record in data["files"]}
    assert by_source["first.jsonl"]["status"] == "partial"
    assert by_source["second.jsonl"]["status"] == "complete"


def test_database_input_reports_flattening_unused(corpus, tmp_path):
    db = tmp_path / "events.db"
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, CommandLine TEXT)")
        conn.execute("INSERT INTO logs(CommandLine) VALUES ('needle00')")
        conn.commit()
    report = tmp_path / "metrics.json"
    result = run_cli((db, corpus[1]), tmp_path, "-D", "--performance-json", str(report))
    assert result.returncode == 0, result.stderr + result.stdout
    data = json.loads(report.read_text())
    assert data["events"] == 1
    assert data["files"][0]["flattening"]["selected"] == "unused"


def test_small_databases_do_not_prepare_literal_plans(monkeypatch):
    from zircolite.prefilter import clear_prepared_rules, prepare_rules

    clear_prepared_rules()
    queries = tuple(f"SELECT * FROM logs WHERE text LIKE '%literal{i}%'" for i in range(32))
    prepared = prepare_rules(queries, with_literals=False)
    monkeypatch.setattr("zircolite.prefilter._parse_literal_plan", Mock(side_effect=AssertionError("unnecessary planning")))
    with closing(sqlite3.connect(":memory:")) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, text TEXT)")
        conn.execute("INSERT INTO logs(text) VALUES ('literal0')")
        with closing(LiteralPrefilter(conn, [{"rule": queries}], automatic=True, prepared=prepared)) as prefilter:
            assert prefilter.reason == "too few events for automatic filtering"


def test_preparation_preserves_skipping_malformed_rule_values():
    from zircolite import ProcessingConfig, ZircoliteCore

    query = "SELECT * FROM logs WHERE text LIKE '%needle%'"
    rules = [{"rule": None}, {"rule": query}, {"title": "valid", "rule": [query]}]
    core = ZircoliteCore(str(ROOT / "config/config.yaml"), ProcessingConfig(no_output=True))
    try:
        core.create_db("text TEXT")
        core.insert_data_to_db({"text": "needle"})
        core.load_ruleset_from_var(rules, None)
        assert core.execute_rule(rules[0]) == {}
        assert core.execute_rule(rules[1]) == {}
        assert core.execute_rule(rules[2])["count"] == 1
        with closing(LiteralPrefilter(core.db_connection, rules)) as prefilter:
            assert prefilter.reason is None
            assert len(prefilter.plans) == 1
    finally:
        core.close()


def test_pattern_budget_drops_only_the_oversized_column():
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, large TEXT, small TEXT)")
        conn.executemany("INSERT INTO logs(large,small) VALUES (?,?)", [("abcdefghijk", "yes")] + [(None, None)] * 10)
        queries = ["SELECT * FROM logs WHERE large LIKE '%abcdefghijk%' AND small LIKE '%yes%'",
                   "SELECT * FROM logs WHERE large LIKE '%abcdefghijk%' OR small LIKE '%yes%'"]
        with closing(LiteralPrefilter(conn, [{"rule": queries}], max_pattern_chars=5)) as prefilter:
            assert prefilter.skipped_columns == {"large": "literal pattern budget exceeded"}
            assert len(prefilter.plans) == 1
            for query in queries:
                assert list(conn.execute(prefilter.rewrite(query))) == list(conn.execute(query))


# MemoryError() and KeyError() have an empty message, so a failure recorded by
# its text alone would read as a clean run.
@pytest.mark.parametrize("error", [RuntimeError("injected failure"), MemoryError()])
def test_failed_run_still_writes_report_and_stops_sampler(corpus, tmp_path, monkeypatch, error):
    from zircolite import cli

    report = tmp_path / "metrics.json"
    monkeypatch.setattr(sys, "argv", ["zircolite.py", "-e", str(corpus[0]), "-r", str(corpus[1]),
                                    "--nolog", "--quiet", "--performance-json", str(report)])
    monkeypatch.setattr(cli, "_run_processing", Mock(side_effect=error))
    try:
        with pytest.raises(type(error)):
            cli.main()
    finally:
        cli.set_quiet_mode(False)
    assert json.loads(report.read_text())["status"] == "failed"
    assert not any(thread.name == "zircolite-rss" for thread in threading.enumerate())


def test_interrupt_writes_report_and_stops_sampler(corpus, tmp_path, monkeypatch):
    from zircolite import cli
    from zircolite.shutdown import reset_shutdown_state

    report = tmp_path / "interrupted.json"
    monkeypatch.setattr(sys, "argv", ["zircolite.py", "-e", str(corpus[0]), "-r", str(corpus[1]),
                                    "--nolog", "--quiet", "--performance-json", str(report)])
    monkeypatch.setattr(cli, "_run_processing", Mock(side_effect=KeyboardInterrupt()))
    try:
        with pytest.raises(SystemExit) as interrupted:
            cli.main()
        assert interrupted.value.code == 130
    finally:
        reset_shutdown_state()
        cli.set_quiet_mode(False)
    assert json.loads(report.read_text())["status"] == "interrupted"
    assert not any(thread.name == "zircolite-rss" for thread in threading.enumerate())
