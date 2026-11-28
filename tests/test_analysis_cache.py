"""The on-disk rule analysis must answer exactly what recomputing would."""

import hashlib
import os
from collections import Counter
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


def write_checksummed_payload(path, payload):
    """Exercise the format checks independently of the byte-integrity check."""
    header = orjson.loads(path.read_bytes().split(b"\n", 1)[0])
    header["sha256"] = hashlib.sha256(payload).hexdigest()
    path.write_bytes(orjson.dumps(header) + b"\n" + payload)


def test_cold_analysis_shares_tokens_and_preserves_independent_readers(cache_dir, monkeypatch):
    queries = (
        "SELECT * FROM logs WHERE EventID=1 AND Image LIKE '%editor.exe'",
        """  SELECT * FROM logs WHERE NOT "Image" LIKE '%editor.exe' AND EventID=2;  """,
        "SELECT * FROM logs /* keep comments */ WHERE Channel='a''b'",
        "SELECT * FROM logs WHERE Image='unterminated",
    )
    forget()
    expected = snapshot(queries)
    forget()
    calls = Counter()
    tokenize = sqlscan.iter_tokens

    def counted(sql):
        calls[sql] += 1
        return tokenize(sql)

    monkeypatch.setattr(sqlscan, "iter_tokens", counted)
    monkeypatch.setattr(prefilter, "iter_tokens", counted)
    analysis_cache.warm([{"rule": list(queries)}])
    assert snapshot(queries) == expected
    assert calls[queries[0]] == 1
    assert max(calls.values()) == 1
    analysis_cache.enable(cache_dir / "empty")
    calls.clear()
    analysis_cache.warm([{"rule": list(queries)}])
    assert not calls, "a disk miss can still find the entire analysis in memory"


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


def test_overlap_reuses_only_matching_statements_and_saves_the_new_selection(cache_dir, monkeypatch):
    first = "  SELECT * FROM logs WHERE Image LIKE '%editor.exe'; "
    second = "SELECT * FROM logs WHERE EventID=2"
    new = "SELECT * FROM logs WHERE EventID=3"
    expected = snapshot((first, second, new))
    forget()
    analysis_cache.warm([{"rule": [first, second]}])
    forget()
    analysed = []
    analyse = analysis_cache._analyse

    def counted(queries):
        analysed.extend(queries)
        return analyse(queries)

    monkeypatch.setattr(analysis_cache, "_analyse", counted)
    assert analysis_cache.warm([{"rule": [new, second, first, first]}]) is False
    assert analysed == [new]
    assert snapshot((first, second, new)) == expected
    forget()
    analysed.clear()
    assert analysis_cache.warm([{"rule": [first]}]) is True
    assert len(list(cache_dir.glob("analysis-*.json"))) == 3
    forget()
    assert analysis_cache.warm([{"rule": [first]}]) is True
    assert not analysed
    assert prefilter._plan_for(first).sql == first.strip().rstrip(";")


@pytest.mark.parametrize("damage", ["index", "entry", "analyzer"])
def test_overlap_recomputes_incompatible_or_damaged_entries(cache_dir, monkeypatch, damage):
    a, b = (f"SELECT * FROM logs WHERE EventID={i}" for i in (1, 2))
    analysis_cache.warm([{"rule": [a, b]}])
    path = next(cache_dir.glob("analysis-*.json"))
    lines = path.read_bytes().split(b"\n")
    if damage == "index":
        header = orjson.loads(lines[0])
        header["queries"].reverse()
        lines[0] = orjson.dumps(header)
    elif damage == "entry":
        lines[1] = b"{}"
    else:
        monkeypatch.setattr(analysis_cache, "_code_fingerprint", lambda: b"another build")
    path.write_bytes(b"\n".join(lines))
    forget()
    assert analysis_cache.warm([{"rule": [a]}]) is False
    assert sqlscan.scan_query(a).eventids == {1}


@pytest.mark.parametrize("subset", [False, True])
def test_changed_bounds_in_valid_json_cannot_seed_a_cache_hit(cache_dir, subset):
    queries = [f"SELECT * FROM logs WHERE EventID={i}" for i in (1, 2)]
    analysis_cache.warm([{"rule": queries}])
    path = next(cache_dir.glob("analysis-*.json"))
    lines = path.read_bytes().split(b"\n")
    meta = orjson.loads(lines[1])
    meta[1][1] = [9]
    lines[1] = orjson.dumps(meta)
    path.write_bytes(b"\n".join(lines))
    forget()
    assert analysis_cache.warm([{"rule": queries[:1] if subset else queries}]) is False
    assert sqlscan.scan_query(queries[0]).eventids == {1}


@pytest.mark.parametrize("damage", [
    b"", b"{", b'{"format": 99}', b'{"format": 4, "count": 0}', b'{"format": 4, "count": 1}',
    b'\n[null, [null, ["1"], [], [], false], null, null]\nnull',
    b'\n[null, [null, null, [], [], "no"], null, null]\nnull',
    b'\n[null, null]\nnull',
])
def test_a_damaged_file_is_ignored_and_rewritten(cache_dir, damage):
    rules = [{"title": "t", "rule": ["SELECT * FROM logs WHERE Image LIKE '%\\\\cmd.exe' AND EventID=1"]}]
    forget()
    analysis_cache.warm(rules)
    path = next(cache_dir.glob("analysis-*.json"))
    expected = snapshot(prefilter.rule_queries(rules))
    if damage.startswith(b"\n"):
        write_checksummed_payload(path, damage[1:])
    else:
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
    _, meta, _plan = path.read_bytes().split(b"\n")
    write_checksummed_payload(path, meta + b'\n[null, 99999, ["literal", ["image", "cmd"]], 0]')
    forget()
    assert analysis_cache.warm(rules) is True
    assert text in prefilter._PENDING_PLANS
    assert prefilter._plan_for(text) == expected
    assert text not in prefilter._PENDING_PLANS


def write_ruleset(path, statements):
    path.write_bytes(orjson.dumps([{"title": f"r{i}", "rule": [sql]} for i, sql in enumerate(statements)]))
    return path


def test_a_seeded_file_serves_every_selection_of_its_rulesets(cache_dir, tmp_path_factory, monkeypatch):
    a = "SELECT * FROM logs WHERE Image LIKE '%editor.exe'"
    b = "SELECT * FROM logs WHERE EventID=2"
    c = "  SELECT * FROM logs WHERE Channel='x'; "
    expected = snapshot((a, b, c))
    forget()
    rules = tmp_path_factory.mktemp("rules")
    one = write_ruleset(rules / "rules_one.json", [a, b])
    two = write_ruleset(rules / "rules_two.json", [c, b])
    seeded = analysis_cache.seed([two, one])
    assert seeded.parent == cache_dir
    assert analysis_cache.seed([one, two]) == seeded
    forget()

    def refuse(queries):
        raise AssertionError(f"analysed {queries}")

    monkeypatch.setattr(analysis_cache, "_analyse", refuse)
    # Whole rulesets, a filtered rule and a mix of both: none is the seeded selection.
    for selection in ([{"rule": [a]}, {"rule": [b]}], [{"rule": [c]}], [{"rule": [b]}, {"rule": [c]}]):
        assert analysis_cache.warm(selection) is True
        assert snapshot((a, b, c)) == expected
        forget()


@pytest.mark.parametrize("problem", ["no statements", "not a ruleset", "unwritable", "cache off"])
def test_seeding_raises_instead_of_shipping_no_file(cache_dir, tmp_path_factory, monkeypatch, problem):
    rules = tmp_path_factory.mktemp("rules")
    ruleset = write_ruleset(rules / "rules_one.json", ["SELECT * FROM logs WHERE EventID=1"])
    directory = None
    if problem == "no statements":
        ruleset = write_ruleset(ruleset, [])
    elif problem == "not a ruleset":
        ruleset.write_bytes(b'{"rule": []}')
    elif problem == "unwritable":
        directory = rules / "taken"
        directory.write_bytes(b"")
    else:
        monkeypatch.setenv("ZIRCOLITE_NO_CACHE", "1")
    with pytest.raises((ValueError, OSError)):
        analysis_cache.seed([ruleset], directory)
    assert not list(cache_dir.glob("analysis-*.json"))
