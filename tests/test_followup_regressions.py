"""Functional review regressions across ingestion, pruning and database export."""

import io
import sqlite3
from argparse import Namespace
from contextlib import closing

import pytest

from zircolite import ProcessingConfig, StreamingEventProcessor, ZircoliteCore
from zircolite.config import ExtractorConfig
from zircolite.extractor import EvtxExtractor
from zircolite.processing import perfile_db_paths
from zircolite.streaming import _EntityReferenceRewriter


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
