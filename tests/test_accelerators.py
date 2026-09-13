"""Compare accelerator paths against SQLite and the Python ingestion contract."""

import argparse
import ast
import gzip
import importlib
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
from collections import Counter
from contextlib import closing
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from zircolite import ProcessingConfig, ZircoliteCore
from zircolite.config_loader import ConfigLoader
from zircolite.prefilter import LiteralPrefilter, _plan_for, _posting_budget
from zircolite.sqlscan import quote_sql_identifiers
from zircolite.streaming import StreamingEventProcessor, select_flatten_kernel
from zircolite.utils import open_maybe_compressed, safe_load, safe_load_all

ROOT = Path(__file__).resolve().parent.parent
CONFIG = str(ROOT / "config/config.yaml")


def native(name):
    try:
        return importlib.import_module(name)
    except ImportError:
        if os.environ.get("ZIRCOLITE_REQUIRE_NATIVE") == "1":
            pytest.fail(f"Required accelerator was not built/installed: {name}")
        pytest.skip(f"Native dependency unavailable: {name}")


def test_runtime_dependencies_match_and_exclude_developer_tools():
    project = (ROOT / "pyproject.toml").read_text()
    declared = ast.literal_eval(re.search(r"(?ms)^dependencies = (\[.*?^\])", project)[1])
    requirements = [line.strip() for line in (ROOT / "requirements.txt").read_text().splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    assert sorted(declared) == sorted(requirements)
    assert len(declared) == len(set(declared))
    names = {re.split(r"[<>=!~;\[]", name, maxsplit=1)[0].lower() for name in declared}
    assert {"ijson", "pyahocorasick", "pyroaring"} <= names
    assert not names & {"apsw", "isal", "cython", "setuptools", "memray", "pytest", "ruff", "mypy", "pyinstaller"}


def test_auto_flattening_uses_native_when_available():
    compiled = native("zircolite._flatten_native")
    assert select_flatten_kernel("auto") is compiled
    assert select_flatten_kernel("python").__name__ == "zircolite.flatten_kernel"


def test_auto_flattening_falls_back_without_extension(monkeypatch):
    original = importlib.import_module
    def missing(name):
        if name == "zircolite._flatten_native":
            raise ImportError("extension unavailable")
        return original(name)
    monkeypatch.setattr("zircolite.streaming.importlib.import_module", missing)
    processor = StreamingEventProcessor(CONFIG, argparse.Namespace(), ProcessingConfig())
    assert processor._flatten_impl.__module__ == "zircolite.flatten_kernel"
    assert processor._flatten_event({"CommandLine": "whoami"}, "events.json")["CommandLine"] == "whoami"
    with pytest.raises(RuntimeError, match="build-accelerators"):
        select_flatten_kernel("cython")


def test_native_kernel_records_the_source_it_was_built_from():
    import hashlib

    compiled = native("zircolite._flatten_native")
    source = ROOT / "zircolite" / "flatten_kernel.py"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == compiled.SOURCE_SHA256


def test_a_stale_native_kernel_is_never_used(monkeypatch):
    import types

    stale = types.ModuleType("zircolite._flatten_native")
    stale.SOURCE_SHA256 = "0" * 64
    original = importlib.import_module
    monkeypatch.setattr("zircolite.streaming.importlib.import_module",
                        lambda name: stale if name == "zircolite._flatten_native" else original(name))

    assert select_flatten_kernel("auto").__name__ == "zircolite.flatten_kernel"
    processor = StreamingEventProcessor(CONFIG, argparse.Namespace(), ProcessingConfig())
    assert processor.flattening_info["selected"] == "python"
    assert "build-accelerators" in processor.flattening_info["reason"]
    assert "older" in processor.flattening_info["reason"]
    with pytest.raises(RuntimeError, match="build-accelerators"):
        select_flatten_kernel("cython")


def test_c_yaml_preserves_safe_tags_aliases_and_documents():
    source = "base: &base {flag: true, n: 12}\ncopy: {<<: *base, n: 19}\n---\n- null\n- 2026-09-13\n"
    assert list(safe_load_all(source)) == list(yaml.safe_load_all(source))
    for load in (safe_load, yaml.safe_load):
        with pytest.raises(yaml.YAMLError):
            load("!!python/object/apply:builtins.eval ['1+1']")


def test_gzip_members_text_and_corruption(tmp_path):
    path = tmp_path / "events.json.gz"
    data = 'αβ\r\n{"ok":true}\n'.encode()
    encoded = gzip.compress(data[:5]) + gzip.compress(data[5:])
    path.write_bytes(encoded)
    with open_maybe_compressed(path) as source:
        assert source.read(3) + source.read() == data
    with open_maybe_compressed(path, "rt") as source:
        assert source.read() == data.decode().replace("\r\n", "\n")
    for damaged in (encoded[:-4], encoded[:-8] + bytes([encoded[-8] ^ 1]) + encoded[-7:]):
        path.write_bytes(damaged)
        with pytest.raises((OSError, EOFError, ValueError)):
            with open_maybe_compressed(path) as source:
                source.read()


def test_disk_storage_exports_rolls_back_and_cleans_up(tmp_path):
    proc = ProcessingConfig(working_db="disk", working_db_dir=str(tmp_path),
                            sqlite_cache_mib=2, no_output=True)
    core = ZircoliteCore(CONFIG, proc)
    working = Path(core._working_directory.name)
    saved = tmp_path / "saved.sqlite"
    try:
        conn = core.db_connection
        assert conn.execute("PRAGMA cache_size").fetchone()[0] == -2048
        assert conn.execute("PRAGMA mmap_size").fetchone()[0] == 0
        assert conn.execute("PRAGMA temp_store").fetchone()[0] == 1
        core.create_db('value TEXT COLLATE NOCASE')
        assert core.insert_data_to_db({"value": "Alpha"})
        assert not core.insert_data_to_db([{"value": "first"}, {"value": object()}])
        assert core.execute_select_query("SELECT value FROM logs") == [{"value": "Alpha"}]
        assert core.execute_select_query("SELECT * FROM logs WHERE value='ALPHA'")
        assert core.execute_select_query("SELECT value FROM logs WHERE 0") == []
        core.save_db_to_disk(str(saved))
    finally:
        core.close()
        core.close()
    assert not working.exists()
    with closing(sqlite3.connect(saved)) as exported:
        assert exported.execute("SELECT value FROM logs").fetchall() == [("Alpha",)]
    with closing(ZircoliteCore(CONFIG, proc)) as reloaded:
        reloaded.load_db_in_memory(str(saved))
        assert reloaded.execute_select_query("SELECT value FROM logs") == [{"value": "Alpha"}]
    assert list(tmp_path.iterdir()) == [saved]


def test_disk_cleanup_when_connection_setup_fails(tmp_path, monkeypatch):
    def fail(self, db):
        raise RuntimeError("connection failed")
    monkeypatch.setattr(ZircoliteCore, "create_connection", fail)
    with pytest.raises(RuntimeError, match="connection failed"):
        ZircoliteCore(CONFIG, ProcessingConfig(working_db="disk", working_db_dir=str(tmp_path)))
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("hashes", [False, True])
def test_cython_ingestion_matches_python_with_transforms(tmp_path, hashes):
    native("zircolite._flatten_native")
    events = [
        {"Event": {"System": {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"},
                   "EventData": {"Image": "C:\\Windows\\cmd.exe", "CommandLine": "cmd /c whoami",
                                 "Hashes": "MD5=aa,SHA256=bb", "Flag": True, "Large": 2**70,
                                 "List": [1, "two"], "Empty": None}}},
        {"EventID": 3, "eventid": None, "User": "DOMAIN\\user", "Message": "héllo", "Flag": False},
    ]
    args = argparse.Namespace(all_transforms=True, transform_categories=None)
    results = []
    for backend in ("python", "cython"):
        processor = StreamingEventProcessor(CONFIG, args, ProcessingConfig(flatten_backend=backend, hashes=hashes))
        rows = [processor._flatten_event(deepcopy(event), "events.json") for event in events]
        with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
            processor.create_initial_table(conn)
            processor._insert_batch(conn, conn.cursor(), rows)
            stored = conn.execute("SELECT * FROM logs").fetchall()
            schema = conn.execute("PRAGMA table_info(logs)").fetchall()
        results.append((rows, processor.field_types, schema, stored))
    assert results[0] == results[1]


class ReferenceAutomaton:
    """Independent primitives for testing candidate logic without native wheels."""
    def __init__(self):
        self.words = {}
    def add_word(self, word, value):
        self.words[word] = value
    def make_automaton(self):
        pass
    def iter(self, text):
        return ((0, value) for word, value in self.words.items() if word in text)


@pytest.mark.parametrize("rows,queries,active", [(999, 32, False), (1000, 31, False), (1000, 32, True)])
def test_automatic_prefilter_boundaries(rows, queries, active):
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, text TEXT)")
        conn.executemany("INSERT INTO logs(text) VALUES (?)", [("needle0",)] + [("quiet",)] * (rows - 1))
        rules = [{"rule": [f"SELECT * FROM logs WHERE text LIKE '%needle{i}%'"]} for i in range(queries)]
        with closing(LiteralPrefilter(conn, rules, automatic=True)) as prefilter:
            assert bool(prefilter.plans) == active
            for rule in rules:
                query = rule["rule"][0]
                assert conn.execute(prefilter.rewrite(query)).fetchall() == conn.execute(query).fetchall()
        assert not conn.execute("SELECT name FROM sqlite_temp_master").fetchall()


def test_automatic_prefilter_counts_eligible_unique_queries(event_database):
    event_database.executemany("INSERT INTO logs(text) VALUES (?)", [("quiet",)] * 1000)
    query = "SELECT * FROM logs WHERE text LIKE '%alpha%'"
    for rules in ([{"rule": [query] * 32}],
                  [{"rule": [query] + [f"SELECT count(*) FROM logs WHERE n={i}" for i in range(31)]}]):
        with closing(LiteralPrefilter(event_database, rules, automatic=True)) as prefilter:
            assert prefilter.reason == "too few eligible queries for automatic filtering"
            assert not prefilter.plans and not prefilter.postings
            assert prefilter.rewrite(query) == query


@pytest.fixture
def event_database():
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, text TEXT, n INTEGER, other TEXT)")
        values = [None, "", "alpha", "ALPHA", "alpha_beta", "alpha%beta", "alpha\\beta",
                  "alpha'beta", "école", "ÉCOLE", "Kelvin", "kelvin", "nul\x00alpha", 12345, b"alpha"]
        conn.executemany("INSERT INTO logs(text,n,other) VALUES(?,?,?)",
                         ((value, i % 3, values[-i - 1]) for i, value in enumerate(values)))
        yield conn


@pytest.mark.parametrize("implementation", ["reference", "native"])
def test_literal_prefilter_matches_sqlite_boolean_wildcard_semantics(event_database, implementation):
    kwargs = {"automaton_factory": ReferenceAutomaton, "bitmap_factory": set}
    if implementation == "native":
        native("ahocorasick")
        native("pyroaring")
        kwargs = {}
    atoms = ["text LIKE '%alpha%'", "text LIKE '%ALPHA%'", "text LIKE '%alpha\\_%' ESCAPE '\\'",
             "text LIKE '%alpha\\%%' ESCAPE '\\'", "text LIKE '%alpha''beta%'",
             "text LIKE '%éco%'", "text LIKE '%ÉCO%'", "text LIKE '%kel%'",
             "text IS NULL", "n=1", "n LIKE '%234%'", "other LIKE '%alpha%'",
             "NOT (text LIKE '%alpha%')", "text LIKE 'a%'", "text LIKE '%missing%'",
             "text LIKE '%alpha*_%' ESCAPE '*'", "text LIKE '%alpha%bet%'",
             "text LIKE '%alpha%_%' ESCAPE '%'", "text LIKE '%alpha\\\\%' ESCAPE '\\'",
             "text LIKE '%é%'", "text LIKE '%É%'", "text LIKE '%k%'"]
    rng = random.Random(90210)  # noqa: S311 -- reproducible test inputs
    queries = ["SELECT * FROM logs WHERE " + atom for atom in atoms]
    for _ in range(250):
        a, b, c = rng.choices(atoms, k=3)
        queries.append(f"SELECT * FROM logs WHERE ({a} {rng.choice(['AND', 'OR'])} {b}) {rng.choice(['AND', 'OR'])} ({c})")
    rules = [{"rule": queries}]
    with closing(LiteralPrefilter(event_database, rules, **kwargs)) as prefilter:
        assert prefilter.reason is None
        for query in queries:
            actual = event_database.execute(prefilter.rewrite(query)).fetchall()
            expected = event_database.execute(query).fetchall()
            assert Counter(actual) == Counter(expected), query
        assert prefilter.accelerated > 0
    assert not event_database.execute("SELECT name FROM sqlite_temp_master").fetchall()


def test_short_literals_are_indexed_only_when_they_hold_non_ascii_characters():
    # A single emoji or accented letter is selective in logs; a one-letter ASCII
    # run is not, and SQLite LIKE folds case for ASCII only.
    assert _plan_for("SELECT * FROM logs WHERE text LIKE '%🦆%'") is not None
    assert _plan_for("SELECT * FROM logs WHERE text LIKE '%é%'") is not None
    assert _plan_for("SELECT * FROM logs WHERE text LIKE '%é_ab%'") is not None
    assert _plan_for("SELECT * FROM logs WHERE text LIKE '%ab%'") is None


def test_candidates_reach_sqlite_without_temporary_tables(event_database):
    factories = {"automaton_factory": ReferenceAutomaton, "bitmap_factory": set}
    query = "SELECT * FROM logs WHERE text LIKE '%beta%'"
    with closing(LiteralPrefilter(event_database, [{"rule": [query]}], **factories)) as prefilter:
        rewritten = prefilter.rewrite(query)
        assert "json_each" in rewritten
        assert Counter(event_database.execute(rewritten).fetchall()) == Counter(event_database.execute(query).fetchall())
        assert not event_database.execute("SELECT name FROM sqlite_temp_master").fetchall()


def test_an_empty_candidate_set_skips_the_scan_but_not_the_errors():
    factories = {"automaton_factory": ReferenceAutomaton, "bitmap_factory": set}
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, text TEXT)")
        conn.executemany("INSERT INTO logs(text) VALUES (?)", [("quiet",)] * 10)
        absent = "SELECT * FROM logs WHERE text LIKE '%missing%'"
        broken = "SELECT * FROM logs WHERE text LIKE '%missing%' AND nowhere = 1"
        with closing(LiteralPrefilter(conn, [{"rule": [absent, broken]}], **factories)) as prefilter:
            rewritten = prefilter.rewrite(absent)
            assert "json_each" not in rewritten and rewritten != absent
            assert conn.execute(rewritten).fetchall() == []
            assert prefilter.accelerated == 1
            # Never planned, so it still reaches SQLite and the repair path.
            assert prefilter.rewrite(broken) == broken


def test_without_json_each_the_filter_stays_off(event_database):
    class NoJson:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, *args):
            if "json_each" in sql:
                raise sqlite3.OperationalError("no such table: json_each")
            return self.conn.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(self.conn, name)

    factories = {"automaton_factory": ReferenceAutomaton, "bitmap_factory": set}
    query = "SELECT * FROM logs WHERE text LIKE '%alpha%'"
    with closing(LiteralPrefilter(NoJson(event_database), [{"rule": [query]}], **factories)) as prefilter:
        assert prefilter.rewrite(query) == query
        assert "json_each" in prefilter.reason


def test_broad_bypass_is_judged_against_the_rule_partition():
    factories = {"automaton_factory": ReferenceAutomaton, "bitmap_factory": set}
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
        conn.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, EventID INTEGER, text TEXT)")
        conn.executemany("INSERT INTO logs(EventID, text) VALUES (?,?)",
                         [(1, "needle")] * 100 + [(2, "quiet")] * 900)
        query = "SELECT * FROM logs WHERE EventID=1 AND text LIKE '%needle%'"
        census = {(None, 1): 100, (None, 2): 900}
        with closing(LiteralPrefilter(conn, [{"rule": [query]}], census=census, **factories)) as prefilter:
            assert prefilter.rewrite(query) == query
            assert prefilter.broad_bypasses == 1
        with closing(LiteralPrefilter(conn, [{"rule": [query]}], **factories)) as prefilter:
            assert prefilter.rewrite(query) != query


def test_posting_budget_scales_with_the_table():
    assert _posting_budget(0) == 2_000_000
    assert _posting_budget(1_000_000) == 16_000_000


def test_depth_repaired_rules_are_accelerated(tmp_path):
    native("ahocorasick")
    native("pyroaring")
    terms = " OR ".join(f"text LIKE '%needle{i:04d}%'" for i in range(1500))
    query = f"SELECT * FROM logs WHERE {terms}"
    outcomes = []
    for mode in ("off", "literal"):
        with closing(ZircoliteCore(CONFIG, ProcessingConfig(rule_prefilter=mode, no_output=True))) as core:
            core.create_db("text TEXT")
            core.insert_data_to_db([{"text": "a needle0042 here"}, *[{"text": "quiet"} for _ in range(30)]])
            core.load_ruleset_from_var([{"id": "deep", "title": "deep", "level": "high", "rule": [query]}], None)
            core.execute_ruleset(str(tmp_path / "unused.json"), keep_results=True, disable_progress=True)
            outcomes.append(([r["count"] for r in core.full_results], dict(core.rules_in_error)))
            if mode == "literal":
                assert core.metrics.data["prefilter"][0]["applied_queries"] == 1
    assert outcomes[0] == outcomes[1] == ([1], {})


@pytest.mark.parametrize("query", [
    "SELECT count(*) FROM logs WHERE text LIKE '%alpha%'",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' ORDER BY n",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' UNION SELECT * FROM logs",
    "SELECT * FROM logs WHERE CASE WHEN n=1 THEN text LIKE '%alpha%' ELSE 1 END",
    "SELECT * FROM logs WHERE NOT (text LIKE '%alpha%')",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' OR n=1",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' AND missing_function(n)",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' AND text REGEXP n",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' AND n BETWEEN 0 AND 3",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' -- comment",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' AND text LIKE 'x' ESCAPE 'xx'",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' AND text LIKE other",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' AND text LIKE 'x' ESCAPE 12",
    'SELECT * FROM logs WHERE text LIKE \'%alpha%\' AND "AND"(n)',
    "SELECT * FROM logs WHERE CURRENT_TIMESTAMP LIKE '%202%'",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' AND current_date LIKE '%202%'",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' AND text -> '$.k' = 1",
    "SELECT * FROM logs WHERE text LIKE '%alpha%' AND text ->> '$.k' = 1",
])
def test_unsupported_sql_has_no_prefilter_plan(query):
    assert _plan_for(quote_sql_identifiers(query)) is None


def test_a_keyword_is_never_mistaken_for_a_same_named_column():
    # SQLite reads CURRENT_TIMESTAMP as the keyword even when a column has that
    # name, so indexing the column would bound the wrong expression.
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as conn:
        conn.execute('CREATE TABLE logs(row_id INTEGER PRIMARY KEY, "current_timestamp" TEXT)')
        year = conn.execute("SELECT strftime('%Y', 'now')").fetchone()[0]
        conn.executemany('INSERT INTO logs("current_timestamp") VALUES (?)',
                         [(f"{year}-01-01",)] + [("none",)] * 9)
        query = f"SELECT * FROM logs WHERE CURRENT_TIMESTAMP LIKE '%{year}%'"
        factories = {"automaton_factory": ReferenceAutomaton, "bitmap_factory": set}
        with closing(LiteralPrefilter(conn, [{"rule": [query]}], **factories)) as prefilter:
            assert Counter(conn.execute(prefilter.rewrite(query)).fetchall()) == Counter(conn.execute(query).fetchall())


def test_budget_and_custom_like_fall_back(event_database):
    query = "SELECT * FROM logs WHERE text LIKE '%alpha%'"
    factories = {"automaton_factory": ReferenceAutomaton, "bitmap_factory": set}
    with closing(LiteralPrefilter(event_database, [{"rule": [query]}], max_postings=0, **factories)) as prefilter:
        assert prefilter.reason == "literal posting budget exceeded"
        assert prefilter.rewrite(query) == query
        assert not prefilter.postings
    event_database.create_function("like", 2, lambda pattern, value: 1)
    with closing(LiteralPrefilter(event_database, [{"rule": [query]}], **factories)) as prefilter:
        assert prefilter.reason == "LIKE has been overridden"
        assert prefilter.rewrite(query) == query


def test_literal_ids_above_32_bits_and_quoted_columns(event_database):
    native("ahocorasick")
    native("pyroaring")
    event_database.execute("INSERT INTO logs(row_id,text) VALUES (?,?)", (2**40, "unique needle"))
    query = 'SELECT * FROM "logs" WHERE "text" LIKE \'%needle%\';'
    from zircolite.sqlscan import quote_sql_identifiers

    with closing(LiteralPrefilter(event_database, [{"rule": [query]}])) as prefilter:
        rewritten = prefilter.rewrite(quote_sql_identifiers(query))
        assert rewritten != query
        assert event_database.execute(rewritten).fetchall() == event_database.execute(query).fetchall()


def test_prefilter_preserves_runtime_pattern_errors(event_database):
    if not hasattr(event_database, "setlimit"):
        pytest.skip("sqlite3 runtime limits require Python 3.11+")
    event_database.setlimit(sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 4)
    query = "SELECT * FROM logs WHERE text LIKE '%alpha%'"
    with closing(LiteralPrefilter(event_database, [{"rule": [query]}],
                                 automaton_factory=ReferenceAutomaton, bitmap_factory=set)) as prefilter:
        assert prefilter.rewrite(query) == query
        with pytest.raises(sqlite3.OperationalError, match="too complex"):
            event_database.execute(prefilter.rewrite(query)).fetchall()


@pytest.mark.parametrize("limit", [-1, 1])
def test_core_prefilter_output_limits_errors_and_cleanup(tmp_path, limit):
    native("ahocorasick")
    native("pyroaring")
    outcomes = []
    queries = [
        "SELECT * FROM logs WHERE text LIKE '%needle%'",
        "SELECT * FROM logs WHERE text LIKE '%quiet%'",
        "SELECT * FROM logs WHERE text LIKE '%needle%' OR missing='x'",
        "SELECT * FROM logs WHERE text LIKE '%needle%' AND text LIKE 'x' ESCAPE 12",
        "SELECT count(*) AS count FROM logs WHERE text LIKE '%needle%'",
        "SELECT * FROM logs WHERE text LIKE '%needle%' AND text REGEXP '['",
    ]
    for mode in ("off", "auto", "literal"):
        proc = ProcessingConfig(rule_prefilter=mode, limit=limit, no_output=True)
        with closing(ZircoliteCore(CONFIG, proc)) as core:
            core.create_db("text TEXT")
            core.insert_data_to_db([{"text": "needle"}, *[{"text": "quiet"} for _ in range(30)]])
            core.ruleset = [{"id": str(i), "title": str(i), "level": "high", "rule": [query]}
                            for i, query in enumerate(queries)]
            core.ruleset.append({"id": "dup", "title": "dup", "level": "high", "rule": [queries[0], queries[0]]})
            core.execute_ruleset(str(tmp_path / "unused.json"), disable_progress=True)
            outcomes.append((core.full_results, set(core.rules_in_error)))
            assert core._prefilter is None
            assert not core.db_connection.execute("SELECT name FROM sqlite_temp_master").fetchall()
    assert outcomes[0] == outcomes[1] == outcomes[2]


def test_a_rewrite_that_sqlite_rejects_falls_back_to_the_original_query(tmp_path):
    native("ahocorasick")
    native("pyroaring")

    def query(terms):
        # AND is never re-associated by the depth repair, so a chain this deep
        # can only run exactly as written.
        return "SELECT * FROM logs WHERE text LIKE '%needle%'" + "".join(f" AND n != {i}" for i in range(terms))

    outcomes = []
    for mode in ("off", "literal"):
        with closing(ZircoliteCore(CONFIG, ProcessingConfig(rule_prefilter=mode, no_output=True))) as core:
            core.create_db("text TEXT, n INTEGER")
            core.insert_data_to_db([{"text": "needle", "n": -1}, *[{"text": "quiet", "n": -1} for _ in range(30)]])
            low, high = 1, 4000
            while low < high:
                middle = (low + high + 1) // 2
                try:
                    core.db_connection.execute("EXPLAIN " + query(middle)).fetchall()
                    low = middle
                except sqlite3.OperationalError:
                    high = middle - 1
            core.ruleset = [{"id": "deep", "title": "deep", "level": "high", "rule": [query(low)]}]
            core.execute_ruleset(str(tmp_path / "unused.json"), keep_results=True, disable_progress=True)
            outcomes.append(([r["count"] for r in core.full_results], dict(core.rules_in_error)))
            if mode == "literal":
                assert core.metrics.data["prefilter"][0]["applied_queries"] == 1
    assert outcomes[0] == outcomes[1] == ([1], {})


@pytest.mark.parametrize("mode", ["sequential", "thread", "process", "unified"])
def test_cli_disk_storage_equivalence_and_cleanup(tmp_path, mode):
    inputs, working = tmp_path / "inputs", tmp_path / "working"
    inputs.mkdir()
    working.mkdir()
    for i in range(2):
        (inputs / f"events{i}.json").write_text('{"EventID":1,"CommandLine":"whoami"}\n')
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"id": "r", "title": "test", "level": "high", "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%whoami%'"]}]))
    outputs = []
    for storage in ("memory", "disk"):
        output = tmp_path / "out.json"
        command = [sys.executable, str(ROOT / "zircolite.py"), "-e", str(inputs), "-r", str(rules),
                   "-c", CONFIG, "--quiet", "--json-input", "--no-auto-mode", "-o", str(output),
                   "--logfile", str(tmp_path / "run.log"), "--working-db", storage,
                   "--working-db-dir", str(working), "--sqlite-cache-mib", "2"]
        command += ["--unified-db"] if mode == "unified" else ["--no-parallel"] if mode == "sequential" else ["--executor", mode, "--parallel-workers", "2"]
        run = subprocess.run(command, capture_output=True, text=True, timeout=60)
        assert run.returncode == 0, run.stdout + run.stderr
        results = json.loads(output.read_text())
        outputs.append(Counter(json.dumps(row, sort_keys=True) for result in results for row in result["matches"]))
        assert not list(working.iterdir())
    assert outputs[0] == outputs[1]


def test_yaml_performance_settings_reach_resolution(tmp_path):
    from zircolite.run_config import resolve

    source = tmp_path / "run.yaml"
    source.write_text("processing:\n  working_db: disk\n  sqlite_cache_mib: 8\n  rule_prefilter: 'off'\n")
    loader = ConfigLoader()
    raw = loader.load_yaml(str(source))
    config = loader.parse_config(raw)
    assert not loader.validate_config(config)
    args = argparse.Namespace(working_db="memory")
    resolve(args, raw)
    assert args.working_db == "memory"
    assert args.sqlite_cache_mib == 8
    assert args.flatten_backend == "auto"
    assert args.rule_prefilter == "off"


def test_frozen_native_binary(tmp_path):
    binary = os.environ.get("ZIRCOLITE_NATIVE_BINARY")
    if not binary:
        pytest.skip("Set ZIRCOLITE_NATIVE_BINARY to test a PyInstaller build")
    binary = str(Path(binary).resolve())
    events, output, rules = tmp_path / "events.json.gz", tmp_path / "output.json", tmp_path / "rules.json"
    events.write_bytes(gzip.compress(b'{"CommandLine":"whoami"}\n' + b'{"CommandLine":"quiet"}\n' * 999))
    queries = ["SELECT * FROM logs WHERE CommandLine LIKE '%whoami%'"]
    queries += [f"SELECT * FROM logs WHERE CommandLine LIKE '%missing{i}%'" for i in range(31)]
    rules.write_text(json.dumps([{"title": "native smoke", "id": "native", "level": "high", "rule": queries}]))
    result = subprocess.run([
        binary, "-e", str(events), "-r", str(rules), "-o", str(output), "--quiet",
        "--no-parallel", "--no-auto-mode", "--json-input", "--working-db", "disk",
        "--flatten-backend", "cython",
    ], cwd=tmp_path, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert sum(len(rule["matches"]) for rule in json.loads(output.read_text())) == 1


def test_throughput_variant_reports_compare_native_results(tmp_path, monkeypatch):
    from tests.test_tools import load_tool

    for module in ("ahocorasick", "pyroaring", "zircolite._flatten_native"):
        native(module)
    benchmark = load_tool("throughput-benchmark")
    report = tmp_path / "report.json"
    variants = ["reference", "current", "disk"]
    monkeypatch.setattr(sys, "argv", ["throughput-benchmark.py", "--scenario", "array-gzip",
                                     "--event-count", "200", "--files", "2", "--passes", "1",
                                     "--modes", "sequential", "--report", str(report), "--variants", *variants])
    assert benchmark.main() == 0
    data = json.loads(report.read_text())
    runs = [run for entries in data["results"].values() for run in entries]
    assert len(runs) == len(variants)
    assert {run["matches"] for run in runs} == {2}
    assert len({run["fingerprint"] for run in runs}) == 1
    assert data["source_sha256"] and data["ruleset_sha256"]
