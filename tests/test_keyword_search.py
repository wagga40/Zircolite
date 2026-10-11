"""Execution contracts for keyword search over original event values."""
import io
import json
import sqlite3

import pytest

from zircolite import ProcessingConfig, ZircoliteCore
from zircolite.fulltext import source_values
from zircolite.rules import RulesetHandler, ruleset_format_problem
from zircolite.streaming import StreamingEventProcessor

REQUIREMENT = [{"table": "logs", "field": "_sigma_fulltext", "representation": "source-values-v1"}]


def _rule(sql, *, keyword=True):
    rule = {"title": "keyword", "schema_version": 3 if keyword else 2, "rule": [sql]}
    if keyword:
        rule["fulltext"] = REQUIREMENT
    return rule


@pytest.mark.parametrize("backend", ["python", "cython"])
def test_original_values_capture_and_export(field_mappings_file, default_args_config, test_logger, tmp_path, backend):
    path = tmp_path / "events.json"
    path.write_text(json.dumps({"z": [True, None, 42], "a": {"hidden": "Needle"}}) + "\n")
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(fulltext_capture=True, flatten_backend=backend), logger=test_logger)
    try:
        flattened = io.BytesIO()
        core.run_streaming([path], input_type="json", args_config=default_args_config, keepflat_file=flattened)
        assert core.metrics.data["flattening"]["selected"] == backend
        assert "_sigma_fulltext" not in flattened.getvalue().decode()
        row = core.db_connection.execute('SELECT _sigma_fulltext FROM logs').fetchone()
        assert row == ("Needle\ntrue\n42",)
        assert core.db_connection.execute('SELECT * FROM _zircolite_fulltext').fetchall() == [("logs", "_sigma_fulltext", "source-values-v1")]
        result = core.execute_rule(_rule("SELECT * FROM logs WHERE _sigma_fulltext LIKE '%Needle%'"))
        assert result["count"] == 1
        assert "_sigma_fulltext" not in result["matches"][0]
        core.save_db_to_disk(str(tmp_path / "saved.db"))
    finally:
        core.close()


def test_old_database_keeps_independent_rules(field_mappings_file, test_logger):
    core = ZircoliteCore(field_mappings_file, logger=test_logger)
    try:
        core.create_db('"Message" TEXT')
        assert core.insert_data_to_db({"Message": "Needle"})
        assert core.execute_rule(_rule("SELECT * FROM logs WHERE _sigma_fulltext LIKE '%Needle%'")) == {}
        assert "re-ingest" in core.rules_in_error["keyword"].lower()
        assert core.execute_rule(_rule("SELECT * FROM logs WHERE Message='Needle'", keyword=False))["count"] == 1
    finally:
        core.close()


@pytest.mark.parametrize("prefilter", ["off", "literal"])
def test_missing_text_is_never_made_up(field_mappings_file, test_logger, tmp_path, prefilter):
    """Neither repair adds the text as a NULL column, which would match nothing quietly."""
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(rule_prefilter=prefilter, no_output=True),
                         logger=test_logger)
    try:
        core.create_db('"Message" TEXT')
        assert core.insert_data_to_db([{"Message": "Needle"}] * 3)
        keyword = _rule("SELECT * FROM logs WHERE _sigma_fulltext LIKE '%Needle%' AND Other IS NULL")
        keyword["required_fields"] = ["_sigma_fulltext", "Other"]
        legacy = _rule("SELECT * FROM logs WHERE _sigma_fulltext LIKE '%Needle%'", keyword=False)
        legacy["title"] = "legacy"
        plain = _rule("SELECT * FROM logs WHERE Message='Needle' AND Absent IS NULL", keyword=False)
        plain.update(title="plain", required_fields=["Message", "Absent"])
        core.ruleset = [keyword, legacy, plain]
        core.execute_ruleset(str(tmp_path / "unused.json"), keep_results=True, disable_progress=True,
                             show_table=False)
        columns = {row[1] for row in core.db_connection.execute("PRAGMA table_info(logs)")}
        assert "_sigma_fulltext" not in columns
        # The keyword rule was refused before any of its other fields were added.
        assert "Other" not in columns and "Absent" in columns
        assert [(r["title"], r["count"]) for r in core.full_results] == [("plain", 3)]
        assert {"keyword", "legacy"} <= set(core.rules_in_error)
    finally:
        core.close()


def test_an_event_naming_the_reserved_field_is_kept(field_mappings_file, default_args_config, test_logger):
    """Refusing it would let whoever controls a field name hide the event from every rule."""
    processor = StreamingEventProcessor(field_mappings_file, default_args_config, ProcessingConfig(fulltext_capture=True, flatten_backend="python"), logger=test_logger)
    flat = processor._flatten_event({"_SIGMA_FULLTEXT": "planted", "Image": "evil.exe"}, "source.json")
    assert flat is not None and "evil.exe" in flat.values()
    assert [key for key in flat if key.lower() == "_sigma_fulltext"] == ["_sigma_fulltext"]
    assert flat["_sigma_fulltext"] == "evil.exe\nplanted"


def test_source_values_order_and_depth():
    assert source_values({"b": [1, {"z": "z", "a": True}], "a": "x", "c": None, "d": 2.5}) == "x\n1\ntrue\nz\n2.5"
    event = current = {}
    for _ in range(5000):
        current["n"] = {}
        current = current["n"]
    current["leaf"] = "deep"
    assert source_values(event) == "deep"


def test_schema_three_and_branch_union(test_logger):
    assert ruleset_format_problem([_rule("SELECT 1")]) is None
    merged = RulesetHandler._merge_converted_queries([
        _rule("SELECT 1", keyword=False), _rule("SELECT 2")
    ])
    assert merged["schema_version"] == 3
    assert merged["fulltext"] == REQUIREMENT


def test_converted_sigma_keyword_runs_after_streaming(field_mappings_file, default_args_config, test_logger, tmp_path):
    from zircolite.config import RulesetConfig

    rules = tmp_path / "keyword.yml"
    rules.write_text("""title: Source keyword
id: 77777777-7777-4777-8777-777777777777
logsource:
  category: test
detection:
  keywords:
    - Needle
  condition: keywords
level: high
""")
    handler = RulesetHandler(RulesetConfig(ruleset=[str(rules)]), logger=test_logger)
    assert len(handler.rulesets) == 1
    rule = handler.rulesets[0]
    assert rule["fulltext"] == REQUIREMENT
    events = tmp_path / "events.json"
    events.write_text(json.dumps({"nested": {"source": "Needle"}}) + "\n")
    core = ZircoliteCore(field_mappings_file, logger=test_logger)
    try:
        core.load_ruleset_from_var(handler.rulesets, None)
        core.run_streaming([events], input_type="json", args_config=default_args_config)
        result = core.execute_rule(rule)
        assert result["count"] == 1
        assert "_sigma_fulltext" not in result["matches"][0]
    finally:
        core.close()


def test_saved_database_and_missing_coverage(field_mappings_file, test_logger, tmp_path):
    saved = tmp_path / "events.db"
    source = ZircoliteCore(field_mappings_file, ProcessingConfig(fulltext_capture=True), logger=test_logger)
    try:
        source.create_db('"Message" TEXT')
        assert source.insert_data_to_db({"Message": "Needle"})
        source.save_db_to_disk(str(saved))
    finally:
        source.close()
    loaded = ZircoliteCore(field_mappings_file, logger=test_logger)
    try:
        loaded.load_db_in_memory(str(saved))
        assert loaded.execute_rule(_rule("SELECT * FROM logs WHERE _sigma_fulltext LIKE '%Needle%'"))["count"] == 1
        with sqlite3.connect(saved) as disk:
            disk.execute("UPDATE logs SET _sigma_fulltext=NULL")
        loaded.load_db_in_memory(str(saved))
        assert loaded.execute_rule(_rule("SELECT * FROM logs WHERE _sigma_fulltext LIKE '%Needle%'")) == {}
        assert "re-ingest" in loaded.rules_in_error["keyword"].lower()
    finally:
        loaded.close()


def test_keyword_correlation_and_v2_evidence_are_private(field_mappings_file, test_logger, tmp_path):
    from zircolite.config import RulesetConfig

    rules = tmp_path / "correlation.yml"
    rules.write_text("""---
title: Keyword base
name: keyword_base
id: 11111111-1111-4111-8111-111111111111
logsource:
  product: windows
  service: sysmon
detection:
  keywords:
    - Needle
  condition: keywords
level: high
---
title: Keyword burst
id: 22222222-2222-4222-8222-222222222222
correlation:
  type: event_count
  rules:
    - keyword_base
  group-by:
    - Image
  timespan: 5m
  condition:
    gte: 2
level: high
""")
    handler = RulesetHandler(RulesetConfig(ruleset=[str(rules)], pipeline=[["sysmon"]]), logger=test_logger)
    rule = handler.rulesets[0]
    assert rule["schema_version"] == rule["correlation_plan"]["version"] == 3
    assert rule["fulltext"] == rule["correlation_plan"]["fulltext"] == REQUIREMENT
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(fulltext_capture=True), logger=test_logger)
    try:
        core.create_db('"SystemTime" TEXT, "Channel" TEXT, "EventID" INTEGER, "Image" TEXT, "Message" TEXT')
        assert core.insert_data_to_db([
            {"SystemTime": f"2026-01-01T00:00:0{i}Z", "Channel": "Microsoft-Windows-Sysmon/Operational",
             "EventID": 1, "Image": "cmd.exe", "Message": "Needle"}
            for i in range(2)
        ])
        traced = []
        core.db_connection.set_trace_callback(traced.append)

        def coverage_count():
            return sum(statement.lower().startswith("select 1 from logs where")
                       and "typeof(" in statement.lower() and "_sigma_fulltext" in statement.lower()
                       for statement in traced)

        alert = core.execute_rule(rule)["matches"][0]
        assert coverage_count() == 1
        traced.clear()
        assert core.execute_rule(rule)["count"] == 1
        assert coverage_count() == 0
        assert core.insert_data_to_db({
            "SystemTime": "2026-01-01T00:00:02Z", "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 1, "Image": "cmd.exe", "Message": "Needle",
        })
        traced.clear()
        assert core.execute_rule(rule)["count"] >= 1
        assert coverage_count() == 1
        core.db_connection.set_trace_callback(None)
        assert "_sigma_fulltext" not in alert["evidence"][0]["event"]
        old_plan = dict(rule["correlation_plan"], version=2)
        old_plan.pop("fulltext")
        old_rule = dict(rule, schema_version=2, correlation_plan=old_plan)
        old_rule.pop("fulltext")
        alert = core.execute_rule(old_rule)["matches"][0]
        assert "_sigma_fulltext" not in alert["evidence"][0]["event"]
    finally:
        core.close()


def test_processing_factories_enable_capture_before_rules_load(make_processing_context):
    from zircolite.processing import create_worker_core, create_zircolite_core

    ctx = make_processing_context(rulesets=[{"title": "correlation", "correlation_plan": {"fulltext": REQUIREMENT}}])
    for factory in (lambda: create_zircolite_core(ctx), lambda: create_worker_core(ctx, 0)):
        core = factory()
        try:
            assert core.fulltext_capture
            assert core.ruleset == []
        finally:
            core.close()


def test_empty_direct_schema_with_capture(field_mappings_file, test_logger):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(fulltext_capture=True), logger=test_logger)
    try:
        core.create_db("")
        assert core.db_connection.execute('PRAGMA table_info(logs)').fetchall()[-1][1:3] == ("_sigma_fulltext", "TEXT")
    finally:
        core.close()


def test_mapped_reserved_field_rejected(default_args_config, test_logger, tmp_path, minimal_field_mappings):
    config = dict(minimal_field_mappings)
    config["mappings"] = {"Event.Message": "_SIGMA_FULLTEXT"}
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="reserved"):
        StreamingEventProcessor(str(path), default_args_config,
                                ProcessingConfig(fulltext_capture=True), logger=test_logger)


def test_unrelated_provenance_table_rejected(field_mappings_file, default_args_config, test_logger):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(fulltext_capture=True), logger=test_logger)
    try:
        core.db_connection.execute('CREATE TABLE _zircolite_fulltext (other TEXT)')
        processor = StreamingEventProcessor(field_mappings_file, default_args_config,
                                            ProcessingConfig(fulltext_capture=True), logger=test_logger)
        with pytest.raises(ValueError, match="unrelated"):
            processor.create_initial_table(core.db_connection)
    finally:
        core.close()


def test_schema_three_requires_matching_plan_requirements():
    malformed = _rule("SELECT 1")
    malformed["fulltext"] = []
    assert "lacks fulltext" in ruleset_format_problem([malformed])
    malformed["fulltext"] = REQUIREMENT
    malformed["correlation"] = True
    malformed["correlation_plan"] = {"version": 3, "fulltext": []}
    assert "inconsistent" in ruleset_format_problem([malformed])


def test_preflight_cache_invalidated_by_insert(field_mappings_file, test_logger):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(fulltext_capture=True), logger=test_logger)
    rule = _rule("SELECT * FROM logs WHERE _sigma_fulltext LIKE '%Needle%'")
    try:
        core.create_db('"Message" TEXT')
        assert core.insert_data_to_db({"Message": "Needle"})
        assert core.execute_rule(rule)["count"] == 1
        core.fulltext_capture = False
        assert core.insert_data_to_db({"Message": "other"})
        assert core.execute_rule(rule) == {}
        assert "incomplete" in core.rules_in_error["keyword"].lower()
    finally:
        core.close()


@pytest.mark.parametrize("mode", ["unified", "perfile", "thread", "process"])
def test_processing_modes_capture_before_ingestion(mode, make_processing_context,
                                                  default_args_config, tmp_path):
    from argparse import Namespace

    from zircolite.processing import (
        process_parallel_streaming,
        process_perfile_streaming,
        process_unified_streaming,
    )

    files = [tmp_path / f"event{i}.json" for i in range(2)]
    for path in files:
        path.write_text(json.dumps({"nested": {"source": "Needle"}}) + "\n")
    ctx = make_processing_context(rulesets=[_rule("SELECT * FROM logs WHERE _sigma_fulltext LIKE '%Needle%'")])
    args = Namespace(**vars(default_args_config))
    args.executor = mode if mode in ("thread", "process") else "thread"
    args.parallel_workers = 2
    args.parallel_adaptive = False
    if mode == "unified":
        core, results = process_unified_streaming(ctx, files, "json", None, args)
        core.close()
    elif mode == "perfile":
        _, results = process_perfile_streaming(ctx, files, "json", None, args)
    else:
        _, results = process_parallel_streaming(ctx, files, "json", None, args)
    assert sum(result["count"] for result in results) == 2
    assert all("_sigma_fulltext" not in match for result in results for match in result["matches"])


def test_reset_preserves_unrelated_reserved_table(field_mappings_file, test_logger):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(fulltext_capture=True), logger=test_logger)
    try:
        core.db_connection.execute('CREATE TABLE _zircolite_fulltext (other TEXT)')
        with pytest.raises(ValueError, match="unrelated"):
            core.reset_logs_table()
        assert core.db_connection.execute(
            "SELECT name FROM sqlite_master WHERE name='_zircolite_fulltext'"
        ).fetchone()
    finally:
        core.close()


def test_longer_column_name_is_not_reserved(field_mappings_file, test_logger):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(fulltext_capture=True), logger=test_logger)
    try:
        core.create_db('"_sigma_fulltext_suffix" TEXT')
        columns = [row[1] for row in core.db_connection.execute('PRAGMA table_info(logs)')]
        assert "_sigma_fulltext_suffix" in columns
        assert "_sigma_fulltext" in columns
    finally:
        core.close()


@pytest.mark.parametrize("path", ["streaming", "direct"])
def test_capture_cannot_stamp_preexisting_rows(path, field_mappings_file,
                                                 default_args_config, test_logger):
    core = ZircoliteCore(field_mappings_file, logger=test_logger)
    try:
        core.create_db('"Message" TEXT, "_sigma_fulltext" TEXT')
        assert core.insert_data_to_db({"Message": "old", "_sigma_fulltext": "Needle"})
        if path == "streaming":
            processor = StreamingEventProcessor(
                field_mappings_file, default_args_config,
                ProcessingConfig(fulltext_capture=True), logger=test_logger,
            )
            with pytest.raises(ValueError, match="re-ingest"):
                processor.create_initial_table(core.db_connection)
        else:
            core.fulltext_capture = True
            with pytest.raises(ValueError, match="re-ingest"):
                core.insert_data_to_db({"Message": "new"})
        assert core.db_connection.execute(
            "SELECT name FROM sqlite_master WHERE name='_zircolite_fulltext'"
        ).fetchone() is None
        assert core.db_connection.execute("SELECT count(*) FROM logs").fetchone() == (1,)
    finally:
        core.close()


def test_loaded_nullable_provenance_is_not_trusted(field_mappings_file, default_args_config, test_logger, tmp_path):
    saved = tmp_path / "foreign.db"
    source = ZircoliteCore(field_mappings_file, logger=test_logger)
    try:
        source.create_db('"Message" TEXT, "_sigma_fulltext" TEXT')
        assert source.insert_data_to_db({"Message": "old", "_sigma_fulltext": "Needle"})
        source.db_connection.execute(
            "CREATE TABLE _zircolite_fulltext ("
            "source_table TEXT PRIMARY KEY, field TEXT, representation TEXT)"
        )
        source.db_connection.execute(
            "INSERT INTO _zircolite_fulltext VALUES ('logs', '_sigma_fulltext', 'source-values-v1')"
        )
        processor = StreamingEventProcessor(
            field_mappings_file, default_args_config,
            ProcessingConfig(fulltext_capture=True), logger=test_logger,
        )
        with pytest.raises(ValueError, match="unrelated"):
            processor.create_initial_table(source.db_connection)
        source.save_db_to_disk(str(saved))
    finally:
        source.close()
    loaded = ZircoliteCore(field_mappings_file, logger=test_logger)
    try:
        loaded.load_db_in_memory(str(saved))
        assert loaded.execute_rule(_rule("SELECT * FROM logs WHERE _sigma_fulltext LIKE '%Needle%'")) == {}
        assert "provenance" in loaded.rules_in_error["keyword"].lower() or "re-ingest" in loaded.rules_in_error["keyword"].lower()
    finally:
        loaded.close()


def test_captured_insert_before_table_creation_returns_false(field_mappings_file, test_logger):
    core = ZircoliteCore(field_mappings_file, ProcessingConfig(fulltext_capture=True), logger=test_logger)
    try:
        assert core.insert_data_to_db({"Message": "x"}) is False
        assert core.db_connection.execute(
            "SELECT name FROM sqlite_master WHERE name='_zircolite_fulltext'"
        ).fetchone() is None
    finally:
        core.close()


def test_native_capture_matches_the_reference():
    import random

    from zircolite import flatten_kernel
    from zircolite.streaming import _load_native_kernel

    native, reason = _load_native_kernel()
    if native is None:
        pytest.skip(f"native kernel unavailable: {reason}")
    rng = random.Random(3)  # noqa: S311 -- reproducible test inputs

    def node(depth):
        kind = rng.random()
        if depth > 3 or kind < 0.5:
            return rng.choice(["x", "Needle", "", True, False, None, 7, -2.5, 10**30, "é\nk"])
        if kind < 0.75:
            return [node(depth + 1) for _ in range(rng.randint(0, 3))]
        return {rng.choice(["a", "B", "_SIGMA_FULLTEXT", "z", "é"]) + str(i): node(depth + 1) for i in range(rng.randint(0, 4))}

    for _ in range(500):
        event = node(0)
        assert native.source_values(event) == flatten_kernel.source_values(event)
