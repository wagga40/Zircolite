"""The on-disk rule analysis must answer exactly what recomputing would."""

import os
from pathlib import Path

import orjson
import pytest

from zircolite import analysis_cache, prefilter, sqlscan

RULESET = Path(__file__).resolve().parent.parent / "rules" / "rules_windows_merged.json"


def forget():
    sqlscan.clear_scan_cache()
    prefilter.clear_prepared_rules()


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("ZIRCOLITE_NO_CACHE", raising=False)
    monkeypatch.setenv("ZIRCOLITE_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv(analysis_cache.ENV_DIRECTORY, raising=False)
    analysis_cache.enable()
    yield tmp_path
    forget()


def snapshot(queries):
    texts = {query: sqlscan.normalize_rule_sql(query) for query in queries}
    plans = {text: prefilter._plan_for(text) for text in texts.values()}
    scans = {sql: sqlscan.scan_query(sql) for sql in (*queries, *texts.values(),
                                                      *(plan.sql for plan in plans.values() if plan))}
    return texts, plans, scans


def test_a_reloaded_ruleset_analysis_equals_a_fresh_one(cache_dir):
    rules = orjson.loads(RULESET.read_bytes())
    queries = prefilter.rule_queries(rules)
    forget()
    assert analysis_cache.warm(rules) is False
    assert len(list(cache_dir.glob("analysis-*.json"))) == 1
    fresh = snapshot(queries)
    forget()
    assert analysis_cache.warm(rules) is True
    assert snapshot(queries) == fresh
    # Nothing was recomputed: every answer came from the file.
    assert len(sqlscan._SCANS) == len(fresh[2])


@pytest.mark.parametrize("damage", [
    b"", b"{", b'{"format": 99}', b'{"format": 4, "count": 0}', b'{"format": 4, "count": 1}',
    b'{"format": 4, "count": 1}\n[null, [null, ["1"], [], [], false], null, null]\nnull',
    b'{"format": 4, "count": 1}\n[null, [null, null, [], [], "no"], null, null]\nnull',
    b'{"format": 4, "count": 1}\n[null, null]\nnull',
])
def test_a_damaged_file_is_ignored_and_rewritten(cache_dir, damage):
    rules = [{"title": "t", "rule": ["SELECT * FROM logs WHERE Image LIKE '%\\\\cmd.exe' AND EventID=1"]}]
    forget()
    analysis_cache.warm(rules)
    path = next(cache_dir.glob("analysis-*.json"))
    expected = snapshot(prefilter.rule_queries(rules))
    path.write_bytes(damage)
    forget()
    assert analysis_cache.warm(rules) is False
    assert snapshot(prefilter.rule_queries(rules)) == expected
    forget()
    assert analysis_cache.warm(rules) is True


def test_the_key_follows_the_queries_and_the_cache_can_be_turned_off(cache_dir, monkeypatch):
    one = analysis_cache.cache_key(("SELECT * FROM logs WHERE a='x'",))
    assert one != analysis_cache.cache_key(("SELECT * FROM logs WHERE a='y'",))
    assert one == analysis_cache.cache_key(("SELECT * FROM logs WHERE a='x'",))
    monkeypatch.setenv("ZIRCOLITE_NO_CACHE", "1")
    assert analysis_cache.enable() is None
    assert analysis_cache.ENV_DIRECTORY not in os.environ
    assert analysis_cache.warm([{"rule": ["SELECT * FROM logs WHERE a='x'"]}]) is False
    assert not list(cache_dir.glob("analysis-*.json"))


def test_a_library_caller_never_touches_the_disk(tmp_path, monkeypatch):
    monkeypatch.delenv(analysis_cache.ENV_DIRECTORY, raising=False)
    monkeypatch.setenv("ZIRCOLITE_CACHE_DIR", str(tmp_path))
    assert analysis_cache.warm([{"rule": ["SELECT * FROM logs WHERE a='x'"]}]) is False
    assert not list(tmp_path.iterdir())


def test_a_damaged_plan_is_recomputed_when_first_asked_for(cache_dir):
    rules = [{"title": "t", "rule": ["SELECT * FROM logs WHERE Image LIKE '%\\\\cmd.exe' AND EventID=1"]}]
    forget()
    analysis_cache.warm(rules)
    text = sqlscan.normalize_rule_sql(rules[0]["rule"][0])
    expected = prefilter._plan_for(text)
    path = next(cache_dir.glob("analysis-*.json"))
    header, meta, _plan = path.read_bytes().split(b"\n")
    path.write_bytes(b"\n".join([header, meta, b'[null, 99999, ["literal", ["image", "cmd"]], 0]']))
    forget()
    assert analysis_cache.warm(rules) is True
    assert text in prefilter._PENDING_PLANS
    assert prefilter._plan_for(text) == expected
    assert text not in prefilter._PENDING_PLANS
