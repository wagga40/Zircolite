"""Functional review regressions across ingestion, pruning and database export."""

import io
import json
import sqlite3
from argparse import Namespace
from contextlib import closing

import pytest

from zircolite import ProcessingConfig, StreamingEventProcessor, ZircoliteCore
from zircolite.config import ExtractorConfig
from zircolite.extractor import EvtxExtractor
from zircolite.processing import perfile_db_paths
from zircolite.streaming import _EntityReferenceRewriter


@pytest.mark.parametrize("first", [1, 1.5])
@pytest.mark.parametrize("batch_size", [1, 5000])
@pytest.mark.parametrize("backend", ["python", "auto"])
@pytest.mark.parametrize("kind", ["plain", "alias", "transform", "case_variant"])
def test_mixed_numeric_column_preserves_oversized_integers(
    tmp_path, first, batch_size, backend, kind
):
    config = {}
    if kind == "alias":
        config = {"alias": {"Value": "Copy"}}
    elif kind == "transform":
        config = {"transforms_enabled": True, "transforms": {"Source": [{
            "alias": True, "alias_name": "Value", "source_condition": ["json_input"],
            "code": "def transform(param):\n    return int(param) if '.' not in param else float(param)",
        }]}}
    mapping = tmp_path / "config.json"
    mapping.write_text(json.dumps(config))
    # JSON readers support native integers up to uint64; negative integers
    # below int64 arrive as text (or are produced by a transform).
    values = [first, 18446744073709551615, "-9223372036854775809", 9007199254740993]
    events = [{"Value": value} for value in values]
    if kind == "transform":
        events = [{"Source": str(value)} for value in values]
    elif kind == "case_variant":
        events[1] = {"value": values[1]}
    source = tmp_path / "events.jsonl"
    source.write_text("".join(json.dumps(event) + "\n" for event in events))
    processor = StreamingEventProcessor(
        str(mapping), Namespace(json_input=True),
        ProcessingConfig(batch_size=batch_size, flatten_backend=backend),
    )
    with closing(sqlite3.connect(":memory:")) as db:
        processor.create_initial_table(db)
        assert processor.process_file_streaming(db, str(source), "json") == 4
        assert db.execute("SELECT Value FROM logs ORDER BY row_id").fetchall() == [
            (first,), ("18446744073709551615",), ("-9223372036854775809",), (9007199254740993,),
        ]
        assert db.execute("SELECT row_id FROM logs WHERE Value='18446744073709551615'").fetchall() == [(2,)]
        assert db.execute("SELECT row_id FROM logs WHERE Value=9007199254740993").fetchall() == [(4,)]
        assert not processor.ingest_degraded
        if kind == "alias":
            assert db.execute("SELECT Copy FROM logs ORDER BY row_id").fetchall() == [
                (first,), ("18446744073709551615",), ("-9223372036854775809",), (9007199254740993,),
            ]


@pytest.mark.parametrize("reader", ["xml", "evtxtract"])
@pytest.mark.parametrize("annotation", ["<!-- export -->", "<?export source?>"])
def test_annotations_between_events_preserve_remaining_records(
    tmp_path, field_mappings_file, reader, annotation
):
    source = tmp_path / "events.xml"
    source.write_text(
        '<Event><System><EventID>1</EventID></System></Event>' + annotation
        + '<Event><System><EventID>2</EventID></System></Event>'
    )
    processor = StreamingEventProcessor(field_mappings_file, Namespace(xml_input=True))
    extractor = EvtxExtractor(ExtractorConfig(encoding="utf-8"))
    events = list(getattr(processor, f"stream_{reader}_events")(str(source), extractor))
    assert [event["EventID"] for event in events] == [1, 2]
    assert not processor.ingest_degraded


@pytest.mark.parametrize("reader", ["xml", "evtxtract"])
def test_cdata_keeps_literal_entities_while_normal_text_decodes(
    tmp_path, field_mappings_file, reader
):
    source = tmp_path / "events.xml"
    source.write_text(
        '<Event><EventData><Data Name="CommandLine">'
        '<![CDATA[echo &amp; &gt;]]> &amp; &gt;'
        '</Data></EventData></Event>'
    )
    processor = StreamingEventProcessor(field_mappings_file, Namespace(xml_input=True))
    events = list(getattr(processor, f"stream_{reader}_events")(
        str(source), EvtxExtractor(ExtractorConfig(encoding="utf-8"))
    ))
    assert events[0]["CommandLine"] == "echo &amp; &gt; & >"
    assert not processor.ingest_degraded


@pytest.mark.parametrize("codec", ["latin-1", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("chunk_size", [1, 2, 7, 17, 65536])
def test_entity_rewriting_respects_markup_across_chunks(codec, chunk_size):
    text = (
        '<Event><!-- <![CDATA[ &amp; --><?export &gt;?>'
        '<Data><![CDATA[a &amp; <!-- &gt;]]> &amp; &gt;</Data></Event>'
    )
    expected = (
        '<Event><!-- <![CDATA[ &amp; --><?export &gt;?>'
        '<Data><![CDATA[a &amp; <!-- &gt;]]> &#38; &#62;</Data></Event>'
    )
    rewriter = _EntityReferenceRewriter(codec)
    source = io.BytesIO(text.encode(codec))
    output = b""
    while chunk := source.read(chunk_size):
        output += rewriter.feed(chunk)
    output += rewriter.flush()
    assert output == expected.encode(codec)


@pytest.mark.parametrize("query", [
    "SELECT COUNT(*) AS n FROM logs WHERE EventID=1 HAVING COUNT(*)=0",
    "SELECT COUNT(*) AS n FROM (SELECT * FROM logs WHERE EventID=1) AS filtered",
])
def test_zero_count_rules_run_when_no_event_matches(field_mappings_file, query):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        core.create_db("EventID INTEGER")
        core.insert_data_to_db({"EventID": 2})
        core.load_ruleset_from_var([{"title": "absence", "rule": [query]}], None)
        core.execute_ruleset("unused", keep_results=True, show_table=False, disable_progress=True)
        assert len(core.full_results) == 1
        assert core.full_results[0]["matches"] == [{"n": 0}]


@pytest.mark.parametrize("collation", ["RTRIM", '"RTRIM"', "/* source collation */ RTRIM"])
def test_saved_database_matches_use_its_collation(tmp_path, field_mappings_file, collation):
    source = tmp_path / "events.db"
    with closing(sqlite3.connect(source)) as db:
        db.execute(f"CREATE TABLE logs(Channel TEXT COLLATE {collation}, EventID INTEGER)")
        db.execute("INSERT INTO logs VALUES ('Security ', 1)")
        db.commit()
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        core.load_db_in_memory(str(source))
        core.load_ruleset_from_var([{"title": "rtrim", "rule": [
            "SELECT * FROM logs WHERE Channel='Security' AND EventID=1",
        ]}], None)
        core.execute_ruleset("unused", keep_results=True, show_table=False, disable_progress=True)
        assert len(core.full_results) == 1
        assert core.full_results[0]["count"] == 1


def test_database_export_names_cannot_collide_with_generated_suffixes(tmp_path):
    paths = perfile_db_paths(str(tmp_path / "out.db"), [
        tmp_path / "a/4_log.json", tmp_path / "b/5_log.json",
        tmp_path / "c/log.json", tmp_path / "d/log.json",
    ])
    assert len(set(paths)) == 4
    for path in paths:
        # Exercise the same non-overwriting contract as save_db_to_disk.
        with path.open("x") as output:
            output.write("database")


@pytest.mark.parametrize("working_db", [":memory:", "events.sqlite"])
def test_numeric_promotion_preserves_schema_and_sequence(tmp_path, working_db):
    mapping = tmp_path / "mapping.json"
    mapping.write_text(json.dumps({"mappings": {"Value": 'value"(,)'}}))
    processor = StreamingEventProcessor(str(mapping), Namespace(json_input=True))
    location = working_db if working_db == ":memory:" else str(tmp_path / working_db)
    with closing(sqlite3.connect(location)) as db, closing(db.cursor()) as cursor:
        processor.create_initial_table(db)
        processor._insert_batch(db, cursor, [processor._flatten_event({"Value": 1.5}, "a")])
        db.execute('ALTER TABLE logs ADD COLUMN Other TEXT COLLATE NOCASE DEFAULT \'Mixed\'')
        db.execute('CREATE INDEX value_index ON logs("value""(,)")')
        db.execute('CREATE TABLE audit(event_id INTEGER)')
        db.execute('CREATE VIEW seen_logs AS SELECT row_id FROM logs')
        db.execute('CREATE TRIGGER audit_lookup AFTER INSERT ON audit BEGIN SELECT row_id FROM logs; END')
        db.execute('CREATE TRIGGER audit_insert AFTER INSERT ON logs BEGIN INSERT INTO audit VALUES (new.row_id); END')
        db.execute('INSERT INTO logs(row_id) VALUES (20)')
        db.execute('DELETE FROM logs WHERE row_id=20')
        db.commit()
        processor._insert_batch(db, cursor, [processor._flatten_event({"Value": 18446744073709551615}, "b")])
        assert db.execute('SELECT row_id, "value""(,)" FROM logs ORDER BY row_id').fetchall() == [
            (1, 1.5), (21, "18446744073709551615"),
        ]
        assert db.execute("SELECT count(*) FROM logs WHERE Other='MIXED'").fetchone() == (2,)
        assert db.execute("SELECT event_id FROM audit ORDER BY event_id").fetchall() == [(20,), (21,)]
        assert db.execute("SELECT name FROM sqlite_master WHERE name='value_index'").fetchone() == ("value_index",)
        assert db.execute('SELECT * FROM seen_logs ORDER BY row_id').fetchall() == [(1,), (21,)]


@pytest.mark.parametrize("condition", [
    "Value='1'", "Value IN ('1', '4')", "Value BETWEEN '0' AND '2'",
    "Value >= '1' AND Value < '2'", "'1'=Value", "Value IS '1'",
])
def test_numeric_rules_keep_matching_after_promotion(tmp_path, field_mappings_file, condition):
    source = tmp_path / "events.jsonl"
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        for values in ([1], [18446744073709551615, "1"], ["1e0"]):
            source.write_text("".join(json.dumps({"Value": value}) + "\n" for value in values))
            assert core.run_streaming([source], "json", Namespace(json_input=True), disable_progress=True) == len(values)
        query = "SELECT row_id FROM logs WHERE " + condition
        assert core.execute_select_query(query) == [{"row_id": 1}, {"row_id": 3}, {"row_id": 4}]
        assert core.execute_select_query("SELECT Value FROM logs WHERE Value='18446744073709551615'") == [
            {"Value": "18446744073709551615"},
        ]
        saved = tmp_path / "saved.db"
        core.save_db_to_disk(str(saved))
        with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as reloaded:
            reloaded.load_db_in_memory(str(saved))
            assert reloaded.execute_select_query(query) == [{"row_id": 1}, {"row_id": 3}, {"row_id": 4}]


@pytest.mark.parametrize("condition", [
    "Value IN ('1', -2, '3')", "Value IN (1e0, '3')", "Value IN (0x01, '3')",
    "Value BETWEEN -1 AND '2'", "(Value)='1'", "Value COLLATE NOCASE='1'",
    "'1'=Value+0", "0+Value='1'", "Value+0='1'", "abs(Value)='1'",
    "'1'=logs.Value", "Value BETWEEN - 1e0 AND '2'", "Value = '0'||'1'",
])
def test_promoted_comparisons_respect_operand_boundaries(field_mappings_file, condition):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        core.create_db("Value BLOB_NUMERIC")
        for value in [1, 3, "18446744073709551615"]:
            core.insert_data_to_db({"Value": value})
        with closing(sqlite3.connect(":memory:")) as reference:
            reference.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY, Value NUMERIC)")
            reference.executemany("INSERT INTO logs(Value) VALUES (?)", [(1,), (3,), ("18446744073709551615",)])
            query = "SELECT row_id FROM logs WHERE " + condition
            expected = [{"row_id": row[0]} for row in reference.execute(query)]
        # Complex arithmetic/concatenation keeps SQLite's no-affinity behavior.
        # Concatenation on the other operand needs explicit numeric typing in
        # custom SQL; normalization must never edit one fragment of it.
        if condition == "Value = '0'||'1'":
            expected = []
        assert core.execute_select_query(query) == expected


def test_schema_probe_failure_uses_query_error_handling(field_mappings_file):
    with closing(ZircoliteCore(field_mappings_file, ProcessingConfig(no_output=True))) as core:
        core.db_connection.close()
        assert core.execute_select_query("SELECT * FROM logs WHERE Value=1", "unavailable") == []
        assert "unavailable" in core.rules_in_error
