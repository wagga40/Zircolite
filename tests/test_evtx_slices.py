"""Big EVTX files split into slices, each read as a working database of its own."""

import json
import pickle
import sqlite3
import struct
import time
from collections import Counter
from dataclasses import replace
from functools import partial
from pathlib import Path

import pytest
from evtx import PyEvtxParser

from zircolite import processing
from zircolite.config import ProcessingConfig
from zircolite.evtx_slices import (
    CHUNK_SIZE,
    HEADER_SIZE,
    MAX_CHUNK_RECORDS,
    EvtxSlice,
    SliceReader,
    plan_slices,
    slice_header,
)
from zircolite.processing import ProcessingContext, process_parallel_streaming
from zircolite.results import RowSpool, merge_result_spools, write_result_json
from zircolite.streaming import StreamingEventProcessor
from zircolite.utils import MemoryTracker

FIXTURE = Path(__file__).parent / "fixtures" / "sample_bitsadmin.evtx"


def _evtx(path, ranges):
    """The fixture's one chunk repeated, each chunk header claiming ``ranges[i]``.

    ``None`` keeps the record range the fixture has; ``"insane"`` writes one no
    chunk can hold. Only planning reads these numbers: the parser reads the
    records themselves.
    """
    data = FIXTURE.read_bytes()
    chunk = data[HEADER_SIZE:HEADER_SIZE + CHUNK_SIZE]
    body = bytearray()
    for numbers in ranges:
        piece = bytearray(chunk)
        if numbers == "insane":
            struct.pack_into("<QQ", piece, 8, 10, 10 + MAX_CHUNK_RECORDS + 5)
        elif numbers is not None:
            struct.pack_into("<QQ", piece, 8, *numbers)
        body += piece
    path.write_bytes(slice_header(data[:HEADER_SIZE], len(ranges)) + bytes(body))
    return path


class TestPlan:
    def test_small_foreign_and_missing_files_are_read_whole(self, tmp_path):
        text = tmp_path / "events.evtx"
        text.write_text("not an event log")
        assert plan_slices(FIXTURE) == []
        assert plan_slices(text) == []
        assert plan_slices(tmp_path / "missing.evtx") == []
        assert plan_slices(_evtx(tmp_path / "three.evtx", [(1, 2), (3, 4), (5, 6)]), records=4) == []

    def test_slices_follow_the_order_the_parser_reads(self, tmp_path):
        """A circular log keeps its oldest records mid-file; the parser starts there and wraps."""
        path = _evtx(tmp_path / "wrapped.evtx", [(7, 8), (9, 10), (1, 2), (3, 4), (5, 6)])
        slices = plan_slices(path, records=4)
        assert [s.chunks for s in slices] == [(2, 3), (4, 0), (1,)]
        assert [(s.row_id_base, s.records) for s in slices] == [(0, 4), (4, 4), (8, 2)]
        assert {(s.index, s.count) for s in slices} == {(0, 3), (1, 3), (2, 3)}

    def test_an_untrusted_chunk_header_is_given_room_for_a_full_chunk(self, tmp_path):
        """Its records still count toward the row IDs, never toward the slice size."""
        path = _evtx(tmp_path / "odd.evtx", [(1, 2), (3, 4), "insane", (5, 6), (7, 8)])
        slices = plan_slices(path, records=4)
        assert [s.chunks for s in slices] == [(0, 1), (2, 3, 4)]
        assert [(s.row_id_base, s.records) for s in slices] == [(0, 4), (4, MAX_CHUNK_RECORDS + 4)]

    def test_a_gap_before_the_last_chunk_keeps_the_file_whole(self, tmp_path):
        """The parser skips an empty slot and stops at a garbled one; a plan copies neither."""
        path = _evtx(tmp_path / "gap.evtx", [(1, 2), (3, 4), (5, 6), (7, 8), (9, 10)])
        data = bytearray(path.read_bytes())
        empty = bytes(data)
        start = HEADER_SIZE + 3 * CHUNK_SIZE
        path.write_bytes(empty[:start] + bytes(CHUNK_SIZE) + empty[start + CHUNK_SIZE:])
        assert plan_slices(path, records=2) == []
        data[start:start + 8] = b"garbage!"
        path.write_bytes(bytes(data))
        assert plan_slices(path, records=2) == []

    def test_preallocated_space_and_a_cut_chunk_are_not_planned(self, tmp_path):
        path = _evtx(tmp_path / "tail.evtx", [(1, 2), (3, 4), (5, 6)])
        data = path.read_bytes()
        path.write_bytes(data + bytes(2 * CHUNK_SIZE))
        assert [s.chunks for s in plan_slices(path, records=2)] == [(0,), (1,), (2,)]
        path.write_bytes(data + data[HEADER_SIZE:HEADER_SIZE + 4000])
        assert [s.chunks for s in plan_slices(path, records=2)] == [(0,), (1,), (2,)]

    def test_a_slice_pickles_and_names_its_place(self, tmp_path):
        evtx_slice = EvtxSlice(str(tmp_path / "a.evtx"), 1, 3, (4, 5), 10, 20)
        # Process workers receive their work pickled; this round-trips our own object.
        assert pickle.loads(pickle.dumps(evtx_slice)) == evtx_slice  # noqa: S301
        assert Path(evtx_slice) == tmp_path / "a.evtx"
        assert str(evtx_slice) == f"{tmp_path / 'a.evtx'} [2/3]"
        assert evtx_slice.name == "a.evtx [2/3]"
        assert evtx_slice.input_size == HEADER_SIZE + 2 * CHUNK_SIZE


class TestReader:
    def test_the_slices_together_give_every_record_once(self, tmp_path):
        path = _evtx(tmp_path / "seven.evtx", [None] * 7)
        whole = [record["data"] for record in PyEvtxParser(str(path)).records_json()]
        sliced = []
        slices = plan_slices(path, records=2)
        assert len(slices) == 4
        for evtx_slice in slices:
            with SliceReader(evtx_slice) as reader:
                sliced += [record["data"] for record in PyEvtxParser(reader).records_json()]
        assert len(whole) == 7
        assert sliced == whole

    def test_a_slice_reads_as_its_header_then_its_chunks(self, tmp_path):
        path = _evtx(tmp_path / "three.evtx", [(1, 1), (2, 2), (3, 3)])
        data = path.read_bytes()
        evtx_slice = EvtxSlice(str(path), 0, 1, (2, 0), 2, 0)
        expected = (slice_header(data[:HEADER_SIZE], 2)
                    + data[HEADER_SIZE + 2 * CHUNK_SIZE:HEADER_SIZE + 3 * CHUNK_SIZE]
                    + data[HEADER_SIZE:HEADER_SIZE + CHUNK_SIZE])
        with SliceReader(evtx_slice) as reader:
            assert reader.read() == expected
            reader.seek(HEADER_SIZE + CHUNK_SIZE - 3)
            assert reader.read(6) == expected[HEADER_SIZE + CHUNK_SIZE - 3:HEADER_SIZE + CHUNK_SIZE + 3]
            assert reader.tell() == HEADER_SIZE + CHUNK_SIZE + 3
            assert reader.seek(-4, 2) == len(expected) - 4
            assert reader.read(10) == expected[-4:]


def _spool(path, results):
    """A worker's result spool and its index, as process_single_file_worker writes them."""
    index = []
    with open(path, "wb") as out:
        out.write(b"[")
        for number, (position, title, rows) in enumerate(results):
            if number:
                out.write(b",\n")
            matches = RowSpool()
            for row in rows:
                matches.append(row)
            result = {"title": title, "id": title, "count": len(rows), "matches": matches}
            start = out.tell()
            head, body = write_result_json(out.write, result)
            index.append((position, {k: v for k, v in result.items() if k != "matches"}, start + head, body))
            matches.close()
        out.write(b"]")
    return str(path), index


class TestMerge:
    def test_each_rule_takes_every_slice_matches_in_order(self, tmp_path):
        first = _spool(tmp_path / "a.json", [(2, "two", [{"row_id": 1}, {"row_id": 2}]), (5, "five", [{"row_id": 2}])])
        second = _spool(tmp_path / "b.json", [(1, "one", [{"row_id": 9}]), (2, "two", [{"row_id": 7}])])
        destination = tmp_path / "merged.json"
        summaries = merge_result_spools([first, second], destination)
        merged = json.loads(destination.read_bytes())
        assert [(r["title"], r["count"], [m["row_id"] for m in r["matches"]]) for r in merged] == [
            ("one", 1, [9]), ("two", 3, [1, 2, 7]), ("five", 1, [2]),
        ]
        assert summaries == [{k: v for k, v in r.items() if k != "matches"} for r in merged]

    def test_without_spools_only_the_summaries_merge(self):
        index = [(3, {"title": "t", "count": 2}, 0, 0)]
        assert merge_result_spools([(None, index), (None, index)], None) == [{"title": "t", "count": 4}]


class TestShortFile:
    def test_a_short_read_stops_where_the_file_ends(self, tmp_path):
        """Bytes past a short read must never be filled from the next chunk."""
        path = _evtx(tmp_path / "two.evtx", [(1, 1), (2, 2)])
        data = path.read_bytes()
        path.write_bytes(data[:HEADER_SIZE + CHUNK_SIZE + 4000])
        with SliceReader(EvtxSlice(str(path), 0, 1, (1, 0), 2, 0)) as reader:
            read = reader.read(HEADER_SIZE + 2 * CHUNK_SIZE)
            assert len(read) == HEADER_SIZE + 4000
            assert reader.tell() == HEADER_SIZE + 4000
            assert read[HEADER_SIZE:] == data[HEADER_SIZE + CHUNK_SIZE:HEADER_SIZE + CHUNK_SIZE + 4000]


class TestRowIds:
    def test_a_slice_numbers_its_rows_after_the_slices_before_it(self, field_mappings_file, test_logger,
                                                                   default_args_config, tmp_path):
        path = _evtx(tmp_path / "four.evtx", [None] * 4)
        slices = plan_slices(path, records=2)
        processor = StreamingEventProcessor(config_file=field_mappings_file, args_config=default_args_config,
                                            processing_config=ProcessingConfig(disable_progress=True),
                                            logger=test_logger)
        conn = sqlite3.connect(":memory:", isolation_level=None)
        processor.create_initial_table(conn)
        assert processor.process_file_streaming(conn, slices[1], input_type="evtx") == 2
        assert [row[0] for row in conn.execute("SELECT row_id FROM logs ORDER BY row_id")] == [3, 4]
        assert {row[0] for row in conn.execute("SELECT OriginalLogfile FROM logs")} == {"four.evtx"}
        conn.close()

    def test_a_slice_holding_more_than_its_bound_is_flagged(self, field_mappings_file, test_logger,
                                                             default_args_config, tmp_path):
        """Reading on would number rows the next slice numbers too."""
        path = _evtx(tmp_path / "two.evtx", [None, None])
        processor = StreamingEventProcessor(config_file=field_mappings_file, args_config=default_args_config,
                                            processing_config=ProcessingConfig(disable_progress=True),
                                            logger=test_logger)
        conn = sqlite3.connect(":memory:", isolation_level=None)
        processor.create_initial_table(conn)
        evtx_slice = EvtxSlice(str(path), 0, 2, (0, 1), 1, 0)
        assert processor.process_file_streaming(conn, evtx_slice, input_type="evtx") == 1
        assert processor.ingest_degraded
        assert [row[0] for row in conn.execute("SELECT row_id FROM logs")] == [1]
        conn.close()


RULES = [
    {"title": "Every event", "id": "all", "level": "low", "tags": [], "filename": "all.yml",
     "description": "", "rule": ["SELECT * FROM logs"]},
    {"title": "Bitsadmin", "id": "bits", "level": "high", "tags": [], "filename": "bits.yml",
     "description": "", "rule": ["SELECT * FROM logs WHERE OriginalLogfile LIKE '%.evtx'"]},
]


def _run(tmp_path, field_mappings_file, test_logger, default_args_config, files, executor, name):
    outfile = tmp_path / f"{name}.json"
    ctx = ProcessingContext(
        config=field_mappings_file, logger=test_logger, no_output=False,
        events_after=time.strptime("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
        events_before=time.strptime("9999-12-12T23:59:59", "%Y-%m-%dT%H:%M:%S"),
        limit=-1, csv_mode=False, time_field="SystemTime", db_location=":memory:", delimiter=";",
        rulesets=RULES, outfile=str(outfile), ready_for_templating=False, package=False,
        dbfile=None, keepflat=False, memory_tracker=MemoryTracker(logger=test_logger),
        retain_results=False,
    )
    default_args_config.parallel_workers = 2
    default_args_config.executor = executor
    process_parallel_streaming(ctx, files, "evtx", None, default_args_config, recommended_workers=2)
    return json.loads(outfile.read_text())


@pytest.mark.parametrize("executor", ["thread", "process"])
def test_a_sliced_file_reports_as_one(tmp_path, monkeypatch, field_mappings_file, test_logger,
                                      default_args_config, executor):
    """One entry per rule per file, the counts of an unsliced run, and row IDs unique per file."""
    big = _evtx(tmp_path / "big.evtx", [None] * 7)
    small = tmp_path / "small.evtx"
    small.write_bytes(FIXTURE.read_bytes())
    files = [big, small]

    monkeypatch.setattr(processing, "plan_slices", lambda path: [])
    whole = _run(tmp_path, field_mappings_file, test_logger, default_args_config, files, executor, "whole")
    monkeypatch.setattr(processing, "plan_slices", partial(plan_slices, records=2))
    sliced = _run(tmp_path, field_mappings_file, test_logger, default_args_config, files, executor, "sliced")

    def entries(results):
        return Counter((r["title"], r["matches"][0]["OriginalLogfile"], r["count"]) for r in results)

    assert entries(sliced) == entries(whole) == Counter({
        ("Every event", "big.evtx", 7): 1, ("Bitsadmin", "big.evtx", 7): 1,
        ("Every event", "small.evtx", 1): 1, ("Bitsadmin", "small.evtx", 1): 1,
    })
    for result in sliced:
        row_ids = [match["row_id"] for match in result["matches"]]
        assert len(row_ids) == len(set(row_ids)) == result["count"]
        assert row_ids == sorted(row_ids)
        assert all({k: v for k, v in match.items() if k != "row_id"}
                   == {k: v for k, v in result["matches"][0].items() if k != "row_id"}
                   for match in result["matches"])


def test_slicing_stays_off_where_a_database_boundary_shows(field_mappings_file, test_logger):
    ctx = ProcessingContext(
        config=field_mappings_file, logger=test_logger, no_output=True,
        events_after=time.strptime("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
        events_before=time.strptime("9999-12-12T23:59:59", "%Y-%m-%dT%H:%M:%S"),
        limit=-1, csv_mode=False, time_field="SystemTime", db_location=":memory:", delimiter=";",
        rulesets=[], outfile="unused.json", ready_for_templating=False, package=False, dbfile=None,
        keepflat=False, memory_tracker=MemoryTracker(logger=test_logger), retain_results=False,
    )
    assert processing._slicing_allowed(ctx, "evtx")
    assert not processing._slicing_allowed(ctx, "json")
    for change in ({"limit": 10}, {"csv_mode": True}, {"dbfile": "x.db"}, {"keepflat": True},
                   {"retain_results": True}):
        assert not processing._slicing_allowed(replace(ctx, **change), "evtx"), change
    # A rule over several rows at once would see each slice apart.
    plain = {"title": "plain", "rule": ["SELECT * FROM logs WHERE EventID=1 AND x LIKE '%group by%'"]}
    assert processing._slicing_allowed(replace(ctx, rulesets=[plain]), "evtx")
    for rule in (
        {"title": "aggregate", "rule": ["SELECT User, count(*) AS n FROM logs GROUP BY User HAVING n > 5"]},
        {"title": "grouped rows", "rule": ["SELECT * FROM logs WHERE EventID=4625 GROUP BY User HAVING count(*) > 9"]},
        {"title": "subquery", "rule": ["SELECT * FROM logs WHERE row_id = (SELECT min(row_id) FROM logs)"]},
        {"title": "limit", "rule": ["SELECT * FROM logs WHERE EventID=1 LIMIT 5"]},
        {"title": "legacy", "correlation": {"type": "event_count"}, "rule": ["SELECT * FROM logs"]},
        {"title": "plan", "correlation_plan": {}, "rule": ["SELECT * FROM logs"]},
    ):
        assert not processing._slicing_allowed(replace(ctx, rulesets=[plain, rule]), "evtx"), rule["title"]
