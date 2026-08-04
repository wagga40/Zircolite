"""
Tests for zircolite/processing.py.

Covers:
- ProcessingContext dataclass (including cached time strings)
- LEVEL_PRIORITY constant
- Factory helpers (create_zircolite_core, create_worker_core, create_extractor)
- sort_key_severity helper
- _write_csv_results (buffered CSV output, shared by per-file and parallel)
- Module-level imports / public API surface
- CSV output keeping fields that only later files carry
"""

import argparse
import csv
import json
import os
import sqlite3
import sys
import threading
import time
from argparse import Namespace
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest

import zircolite.cli
from zircolite.console import LEVEL_PRIORITY
from zircolite.processing import (
    ProcessingContext,
    _IncrementalResultWriter,
    _keepflat_context,
    _ThreadSafeWriter,
    _unpack_streaming_result,
    _write_csv_results,
    create_extractor,
    create_worker_core,
    create_zircolite_core,
    process_perfile_streaming,
    process_single_file_worker,
    sort_key_severity,
)
from zircolite.utils import MemoryTracker

# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def memory_tracker():
    """Create a MemoryTracker for testing."""
    logger = MagicMock()
    return MemoryTracker(logger=logger)


@pytest.fixture
def dummy_ctx(tmp_path, memory_tracker):
    """Build a minimal ProcessingContext for unit tests."""
    logger = MagicMock()
    # Write a minimal field mappings file
    config_file = tmp_path / "fieldMappings.json"
    config_file.write_text(json.dumps({
        "exclusions": ["xmlns"],
        "useless": [None, ""],
        "mappings": {},
        "alias": {},
        "split": {},
        "transforms_enabled": False,
        "transforms": {},
    }))

    return ProcessingContext(
        config=str(config_file),
        logger=logger,
        no_output=True,
        events_after=time.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
        events_before=time.strptime("2025-12-31T23:59:59", "%Y-%m-%dT%H:%M:%S"),
        limit=-1,
        csv_mode=False,
        time_field="SystemTime",
        hashes=False,
        db_location=":memory:",
        delimiter=";",
        rulesets=[],
        rule_filters=None,
        outfile=str(tmp_path / "detected_events.json"),
        ready_for_templating=False,
        package=False,
        dbfile=None,
        keepflat=False,
        memory_tracker=memory_tracker,
    )


@pytest.fixture
def dummy_args():
    """Simulated CLI args namespace."""
    return Namespace(
        logs_encoding=None,
        parallel_workers=None,
        parallel_memory_limit=85.0,
    )


# =============================================================================
# LEVEL_PRIORITY
# =============================================================================

class TestLevelPriority:
    """Tests for the centralised LEVEL_PRIORITY constant."""

    def test_has_all_five_levels(self):
        expected = {"critical", "high", "medium", "low", "informational"}
        assert set(LEVEL_PRIORITY.keys()) == expected

    def test_ordering(self):
        assert LEVEL_PRIORITY["critical"] < LEVEL_PRIORITY["high"]
        assert LEVEL_PRIORITY["high"] < LEVEL_PRIORITY["medium"]
        assert LEVEL_PRIORITY["medium"] < LEVEL_PRIORITY["low"]
        assert LEVEL_PRIORITY["low"] < LEVEL_PRIORITY["informational"]

    def test_importable_from_package(self):
        from zircolite import LEVEL_PRIORITY as pkg_lp
        assert pkg_lp is LEVEL_PRIORITY


# =============================================================================
# ProcessingContext
# =============================================================================

class TestProcessingContext:
    """Tests for ProcessingContext dataclass."""

    def test_time_strings_computed(self, dummy_ctx):
        assert dummy_ctx.time_after_str == "2024-01-01T00:00:00"
        assert dummy_ctx.time_before_str == "2025-12-31T23:59:59"

    def test_time_strings_match_struct_time(self, dummy_ctx):
        re_parsed = time.strptime(dummy_ctx.time_after_str, "%Y-%m-%dT%H:%M:%S")
        assert re_parsed == dummy_ctx.events_after

    def test_default_mutable_fields(self, dummy_ctx):
        assert dummy_ctx.total_events == 0
        assert dummy_ctx.total_filtered_events == 0
        assert dummy_ctx.workers_used == 1


# =============================================================================
# Factory helpers
# =============================================================================

class TestCreateZircoliteCore:
    """Tests for create_zircolite_core."""

    def test_returns_core_instance(self, dummy_ctx):
        from zircolite.core import ZircoliteCore
        core = create_zircolite_core(dummy_ctx)
        assert isinstance(core, ZircoliteCore)
        core.close()

    def test_respects_db_location_override(self, dummy_ctx):
        core = create_zircolite_core(dummy_ctx, db_location=":memory:")
        assert core.db_connection is not None
        core.close()

    def test_passes_time_fields(self, dummy_ctx):
        core = create_zircolite_core(dummy_ctx)
        assert core.time_after == "2024-01-01T00:00:00"
        assert core.time_before == "2025-12-31T23:59:59"
        core.close()


class TestCreateWorkerCore:
    """Tests for create_worker_core."""

    def test_creates_silent_logger(self, dummy_ctx):
        import logging
        core = create_worker_core(dummy_ctx, worker_id=0)
        # Silent loggers have level above CRITICAL
        assert core.logger.level > logging.CRITICAL
        core.close()

    def test_worker_cores_are_independent(self, dummy_ctx):
        core0 = create_worker_core(dummy_ctx, worker_id=0)
        core1 = create_worker_core(dummy_ctx, worker_id=1)
        assert core0.db_connection is not core1.db_connection
        core0.close()
        core1.close()


class TestCreateExtractor:
    """Tests for create_extractor."""

    def test_returns_none_for_evtx(self, dummy_args):
        logger = MagicMock()
        assert create_extractor(dummy_args, logger, "evtx") is None

    def test_returns_none_for_json(self, dummy_args):
        logger = MagicMock()
        assert create_extractor(dummy_args, logger, "json") is None

    def test_returns_extractor_for_xml(self, dummy_args):
        from zircolite.extractor import EvtxExtractor
        logger = MagicMock()
        ext = create_extractor(dummy_args, logger, "xml")
        assert isinstance(ext, EvtxExtractor)


# =============================================================================
# Helpers
# =============================================================================

class TestHelpers:
    """Tests for module-level helper functions."""

    def test_unpack_streaming_result_tuple(self):
        assert _unpack_streaming_result((42, 5, 3)) == (42, 5, 3)

    def test_unpack_streaming_result_short_tuple(self):
        """A 2-tuple from an older caller pads the time-filter count to zero."""
        assert _unpack_streaming_result((42, 5)) == (42, 5, 0)

    def test_unpack_streaming_result_int(self):
        assert _unpack_streaming_result(42) == (42, 0, 0)

    def test_sort_key_severity_ordering(self):
        critical = {"rule_level": "critical", "count": 1}
        high = {"rule_level": "high", "count": 100}
        assert sort_key_severity(critical) < sort_key_severity(high)

    def test_sort_key_severity_count_descending(self):
        a = {"rule_level": "high", "count": 50}
        b = {"rule_level": "high", "count": 10}
        assert sort_key_severity(a) < sort_key_severity(b)

    def test_sort_key_unknown_level_goes_last(self):
        unknown = {"rule_level": "custom", "count": 100}
        info = {"rule_level": "informational", "count": 1}
        assert sort_key_severity(info) < sort_key_severity(unknown)


# =============================================================================
# _write_csv_results
# =============================================================================

class TestWriteCsvResults:
    """Tests for _write_csv_results, the buffered CSV output path.

    Shared by per-file and parallel mode: both need every column known before
    the header is written. JSON does not come through here -- it streams out
    per file via _IncrementalResultWriter, which has its own tests below.
    """

    def test_csv_output_is_valid(self, dummy_ctx, tmp_path):
        dummy_ctx.no_output = False
        dummy_ctx.csv_mode = True
        dummy_ctx.outfile = str(tmp_path / "results.csv")

        sample_results = [
            {
                "title": "Rule A",
                "description": "desc",
                "rule_level": "high",
                "count": 1,
                "matches": [{"field1": "val1", "field2": "val2"}],
            },
        ]
        _write_csv_results(dummy_ctx, sample_results)

        content = Path(dummy_ctx.outfile).read_text(encoding="utf-8")
        assert "rule_title" in content
        assert "val1" in content

    def test_csv_header_unions_every_rule_s_columns(self, dummy_ctx, tmp_path):
        """A later rule's wider rows must not lose columns to the first one."""
        dummy_ctx.no_output = False
        dummy_ctx.csv_mode = True
        dummy_ctx.outfile = str(tmp_path / "results.csv")

        _write_csv_results(dummy_ctx, [
            {"title": "Narrow", "rule_level": "high", "count": 1,
             "matches": [{"CommandLine": "a"}]},
            {"title": "Wide", "rule_level": "low", "count": 1,
             "matches": [{"CommandLine": "b", "User": "alice"}]},
        ])

        content = Path(dummy_ctx.outfile).read_text(encoding="utf-8")
        assert "User" in content.splitlines()[0]
        assert "alice" in content

    def test_no_output_flag_skips_write(self, dummy_ctx, tmp_path):
        dummy_ctx.no_output = True
        dummy_ctx.csv_mode = True
        dummy_ctx.outfile = str(tmp_path / "should_not_exist.csv")
        _write_csv_results(dummy_ctx, [{"title": "Rule A"}])
        assert not Path(dummy_ctx.outfile).exists()


# =============================================================================
# process_perfile_streaming
# =============================================================================

class TestProcessPerfileStreaming:
    """Tests for process_perfile_streaming behavior."""

    def test_perfile_no_template_returns_accumulated_results(
        self, default_args_config,
        sample_ruleset, tmp_path, make_processing_context,
    ):
        """Per-file streaming always returns accumulated results for summary/ATT&CK dashboard."""
        ctx = make_processing_context(
            rulesets=sample_ruleset,
            outfile=str(tmp_path / "out.json"),
        )
        events = [{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}]
        jf = tmp_path / "ev.json"
        jf.write_text(json.dumps(events[0]) + "\n")

        _, results = process_perfile_streaming(
            ctx, [jf], "json", None, default_args_config,
        )
        # Results are always accumulated (for summary dashboard), so we get detections when rules match
        assert isinstance(results, list)
        assert len(results) >= 1
        assert results[0].get("title") == "Suspicious PowerShell Command"

    def test_perfile_streaming_two_files_aggregates_results(
        self, default_args_config,
        sample_ruleset, tmp_path, make_processing_context,
    ):
        """Per-file streaming with two files reuses connection and aggregates results."""
        ctx = make_processing_context(
            rulesets=sample_ruleset,
            outfile=str(tmp_path / "out.json"),
        )
        event = {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}
        jf1 = tmp_path / "f1.json"
        jf2 = tmp_path / "f2.json"
        jf1.write_text(json.dumps(event) + "\n")
        jf2.write_text(json.dumps(event) + "\n")

        _, results = process_perfile_streaming(
            ctx, [jf1, jf2], "json", None, default_args_config,
        )
        assert isinstance(results, list)
        assert len(results) >= 1
        total_matches = sum(r.get("count", 0) for r in results)
        assert total_matches >= 2


# =============================================================================
# Public API surface
# =============================================================================

class TestPublicAPI:
    """Ensure expected names are importable from the package."""

    def test_processing_context_from_package(self):
        from zircolite import ProcessingContext as PC
        assert PC is ProcessingContext

    def test_process_functions_from_package(self):
        from zircolite import (
            process_db_input,
            process_parallel_streaming,
            process_perfile_streaming,
            process_unified_streaming,
        )
        # Just check they're callable
        for fn in [
            process_unified_streaming,
            process_perfile_streaming,
            process_db_input,
            process_parallel_streaming,
        ]:
            assert callable(fn)


# =============================================================================
# Incremental Result Writing
# =============================================================================


class TestIncrementalResultWriter:
    """Tests for _IncrementalResultWriter in processing.py."""

    def _make_ctx(self, tmp_path, csv_mode=False):
        outfile = str(
            tmp_path / "output.csv" if csv_mode else tmp_path / "output.json"
        )

        class FakeCtx:
            pass

        ctx = FakeCtx()
        ctx.no_output = False
        ctx.csv_mode = csv_mode
        ctx.outfile = outfile
        ctx.delimiter = ";"
        return ctx

    def test_json_incremental_write(self, tmp_path):
        ctx = self._make_ctx(tmp_path)

        with _IncrementalResultWriter(ctx) as writer:
            writer.write_file_results({
                "results": [
                    {"title": "Rule A", "rule_level": "high", "count": 1,
                     "matches": [{"CommandLine": "test"}]},
                ]
            })
            writer.write_file_results({
                "results": [
                    {"title": "Rule B", "rule_level": "low", "count": 2,
                     "matches": [{"Image": "cmd.exe"}]},
                ]
            })

        with open(ctx.outfile) as f:
            data = json.loads(f.read())

        assert len(data) == 2
        assert data[0]["title"] == "Rule A"
        assert data[1]["title"] == "Rule B"

    def test_no_output_mode(self, tmp_path):
        ctx = self._make_ctx(tmp_path)
        ctx.no_output = True

        with _IncrementalResultWriter(ctx) as writer:
            writer.write_file_results({
                "results": [{"title": "X", "matches": []}]
            })

        assert not os.path.exists(ctx.outfile)

    def test_empty_results(self, tmp_path):
        ctx = self._make_ctx(tmp_path)

        with _IncrementalResultWriter(ctx) as writer:
            writer.write_file_results({"results": []})

        with open(ctx.outfile) as f:
            data = json.loads(f.read())
        assert data == []


# =============================================================================
# Keepflat context manager & multi-file support
# =============================================================================

# =============================================================================
# process_single_file_worker
# =============================================================================


class TestProcessSingleFileWorker:
    """Functional tests for process_single_file_worker."""

    def test_returns_result_tuple_with_results_key(
        self, default_args_config, sample_ruleset, tmp_path, make_processing_context,
    ):
        ctx = make_processing_context(
            rulesets=sample_ruleset,
            outfile=str(tmp_path / "out.json"),
        )
        jf = tmp_path / "ev.json"
        jf.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}\n'
        )
        thread_local = threading.local()
        counter_lock = threading.Lock()
        worker_counter = [0]
        total_filtered_count = [0, 0]

        event_count, file_data = process_single_file_worker(
            jf,
            ctx,
            "json",
            None,
            default_args_config,
            counter_lock=counter_lock,
            worker_counter=worker_counter,
            total_filtered_count=total_filtered_count,
            thread_local=thread_local,
        )
        assert event_count == 1
        assert "results" in file_data
        assert file_data["name"] == "ev.json"
        assert len(file_data["results"]) >= 1
        assert file_data["events"] == 1

    def test_broken_rule_is_reported_out_of_the_worker(
        self, default_args_config, tmp_path, make_processing_context,
    ):
        """Workers log to a silent logger, so a broken rule must ride out in the result.

        Otherwise a rule that cannot run on any file produces no user-visible
        output at all in parallel mode.
        """
        ctx = make_processing_context(
            rulesets=[
                {
                    "title": "Broken Rule",
                    "id": "broken-1",
                    "level": "high",
                    "rule": ["SELECT * FROM logs WHERE CommandLine REGEXP ']'["],
                }
            ],
            outfile=str(tmp_path / "out.json"),
        )
        jf = tmp_path / "ev.json"
        jf.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}\n'
        )

        _, file_data = process_single_file_worker(
            jf,
            ctx,
            "json",
            None,
            default_args_config,
            counter_lock=threading.Lock(),
            worker_counter=[0],
            total_filtered_count=[0, 0],
            thread_local=threading.local(),
        )

        assert "Broken Rule" in file_data["rules_in_error"]

    def test_worker_reports_no_broken_rules_for_valid_ruleset(
        self, default_args_config, sample_ruleset, tmp_path, make_processing_context,
    ):
        ctx = make_processing_context(
            rulesets=sample_ruleset,
            outfile=str(tmp_path / "out.json"),
        )
        jf = tmp_path / "ev.json"
        jf.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe"}}}\n'
        )

        _, file_data = process_single_file_worker(
            jf,
            ctx,
            "json",
            None,
            default_args_config,
            counter_lock=threading.Lock(),
            worker_counter=[0],
            total_filtered_count=[0, 0],
            thread_local=threading.local(),
        )

        assert file_data["rules_in_error"] == {}

    def test_returns_empty_matches_when_no_rule_matches(
        self, default_args_config, sample_ruleset, tmp_path, make_processing_context,
    ):
        ctx = make_processing_context(
            rulesets=sample_ruleset,
            outfile=str(tmp_path / "out.json"),
        )
        jf = tmp_path / "ev.json"
        jf.write_text(
            '{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "notepad.exe"}}}\n'
        )
        thread_local = threading.local()
        counter_lock = threading.Lock()
        worker_counter = [0]
        total_filtered_count = [0, 0]

        event_count, file_data = process_single_file_worker(
            jf,
            ctx,
            "json",
            None,
            default_args_config,
            counter_lock=counter_lock,
            worker_counter=worker_counter,
            total_filtered_count=total_filtered_count,
            thread_local=thread_local,
        )
        assert event_count == 1
        assert file_data["results"] == []
        assert file_data["events"] == 1


# =============================================================================
# _ThreadSafeWriter concurrency
# =============================================================================


class TestThreadSafeWriterConcurrency:
    """Concurrent writes must not interleave lines."""

    def test_concurrent_writes_no_interleaving(self, tmp_path):
        out = tmp_path / "out.jsonl"
        with open(out, "wb") as fh:
            writer = _ThreadSafeWriter(fh)
            num_threads = 4
            lines_per_thread = 50

            def write_lines(prefix):
                for i in range(lines_per_thread):
                    writer.write(f"{prefix}_{i}\n".encode())

            threads = [
                threading.Thread(target=write_lines, args=(f"T{t}",))
                for t in range(num_threads)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        lines = out.read_text().strip().splitlines()
        assert len(lines) == num_threads * lines_per_thread
        for line in lines:
            parts = line.split("_")
            assert len(parts) == 2
            assert parts[0] in [f"T{t}" for t in range(num_threads)]
            assert parts[1].isdigit()


# =============================================================================
# Keepflat context
# =============================================================================


class TestKeepflatContext:
    """Tests for _keepflat_context and _ThreadSafeWriter."""

    def _make_ctx(self, tmp_path, keepflat=True):
        logger = MagicMock()

        class FakeCtx:
            pass

        ctx = FakeCtx()
        ctx.keepflat = keepflat
        ctx.logger = logger
        return ctx

    def test_yields_none_when_disabled(self, tmp_path):
        ctx = self._make_ctx(tmp_path, keepflat=False)
        with _keepflat_context(ctx) as kf:
            assert kf is None

    def test_yields_file_handle_when_enabled(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ctx = self._make_ctx(tmp_path, keepflat=True)
        with _keepflat_context(ctx) as kf:
            assert kf is not None
            kf.write(b'hello\n')
        flat_files = list(tmp_path.glob("flattened_events_*.json"))
        assert len(flat_files) == 1
        assert flat_files[0].read_bytes() == b'hello\n'

    def test_thread_safe_wrapper(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ctx = self._make_ctx(tmp_path, keepflat=True)
        with _keepflat_context(ctx, thread_safe=True) as kf:
            assert isinstance(kf, _ThreadSafeWriter)
            kf.write(b'line1\n')
            kf.write(b'line2\n')
        flat_files = list(tmp_path.glob("flattened_events_*.json"))
        assert len(flat_files) == 1
        assert flat_files[0].read_bytes() == b'line1\nline2\n'

    def test_file_closed_after_context(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ctx = self._make_ctx(tmp_path, keepflat=True)
        handle = None
        with _keepflat_context(ctx) as kf:
            handle = kf
        assert handle.closed


class TestKeepflatPerfile:
    """Test that per-file streaming produces a single consolidated keepflat file."""

    def test_perfile_single_keepflat_file(
        self, default_args_config,
        sample_ruleset, tmp_path, make_processing_context,
    ):
        ctx = make_processing_context(
            rulesets=sample_ruleset,
            outfile=str(tmp_path / "out.json"),
            keepflat=True,
        )

        ev1 = tmp_path / "ev1.json"
        ev1.write_text('{"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "a"}}}\n')
        ev2 = tmp_path / "ev2.json"
        ev2.write_text('{"Event": {"System": {"EventID": 2}, "EventData": {"CommandLine": "b"}}}\n')

        # chdir so keepflat file is created in tmp_path
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            process_perfile_streaming(
                ctx, [ev1, ev2], "json", None, default_args_config,
            )
        finally:
            os.chdir(original_cwd)

        flat_files = list(tmp_path.glob("flattened_events_*.json"))
        assert len(flat_files) == 1, (
            f"Expected 1 consolidated keepflat file, got {len(flat_files)}"
        )

        lines = flat_files[0].read_text().strip().splitlines()
        assert len(lines) == 2, (
            f"Expected 2 events in keepflat file, got {len(lines)}"
        )


class TestProcessDbInputSkippedFiles:
    """Regression tests: skipped DB files must not corrupt JSON output."""

    def _ctx(self, tmp_path, memory_tracker):
        logger = MagicMock()
        config_file = tmp_path / "fieldMappings.json"
        config_file.write_text(json.dumps({
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": False, "transforms": {},
        }))
        return ProcessingContext(
            config=str(config_file),
            logger=logger,
            no_output=False,
            events_after=time.strptime("2024-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
            events_before=time.strptime("2025-12-31T23:59:59", "%Y-%m-%dT%H:%M:%S"),
            limit=-1,
            csv_mode=False,
            time_field="SystemTime",
            hashes=False,
            db_location=":memory:",
            delimiter=";",
            rulesets=[{
                "title": "PS Rule", "id": "ps-1", "description": "d",
                "level": "high", "tags": [],
                "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%' ESCAPE '\\'"],
            }],
            rule_filters=None,
            outfile=str(tmp_path / "detected_events.json"),
            ready_for_templating=False,
            package=False,
            dbfile=None,
            keepflat=False,
            memory_tracker=memory_tracker,
        )

    def _make_valid_db(self, path: Path):
        conn = sqlite3.connect(str(path))
        conn.execute("CREATE TABLE logs (row_id INTEGER PRIMARY KEY, CommandLine TEXT)")
        conn.execute("INSERT INTO logs (CommandLine) VALUES ('powershell.exe test')")
        conn.commit()
        conn.close()

    def _make_empty_db(self, path: Path):
        conn = sqlite3.connect(str(path))
        conn.execute("CREATE TABLE other (x TEXT)")
        conn.commit()
        conn.close()

    def test_skipped_first_db_still_produces_valid_json(self, tmp_path, memory_tracker):
        from zircolite.processing import process_db_input
        bad = tmp_path / "bad.db"
        good = tmp_path / "good.db"
        self._make_empty_db(bad)
        self._make_valid_db(good)
        ctx = self._ctx(tmp_path, memory_tracker)
        args = Namespace(logs_encoding=None)

        process_db_input(ctx, args, file_list=[bad, good])

        with open(ctx.outfile) as f:
            results = json.load(f)
        assert len(results) == 1

    def test_skipped_last_db_still_closes_json_array(self, tmp_path, memory_tracker):
        from zircolite.processing import process_db_input
        good = tmp_path / "good.db"
        bad = tmp_path / "bad.db"
        self._make_valid_db(good)
        self._make_empty_db(bad)
        ctx = self._ctx(tmp_path, memory_tracker)
        args = Namespace(logs_encoding=None)

        process_db_input(ctx, args, file_list=[good, bad])

        with open(ctx.outfile) as f:
            content = f.read()
        assert content.rstrip().endswith("]")
        assert len(json.loads(content)) == 1

    def test_all_dbs_skipped_no_output_file_mess(self, tmp_path, memory_tracker):
        from zircolite.processing import process_db_input
        bad1 = tmp_path / "bad1.db"
        bad2 = tmp_path / "bad2.db"
        self._make_empty_db(bad1)
        self._make_empty_db(bad2)
        ctx = self._ctx(tmp_path, memory_tracker)
        args = Namespace(logs_encoding=None)

        # Nothing was analysed, so the run must fail rather than exit 0 with a
        # summary pointing at an output file that was never written
        with pytest.raises(SystemExit) as exc_info:
            process_db_input(ctx, args, file_list=[bad1, bad2])
        assert exc_info.value.code != 0
        assert not Path(ctx.outfile).exists()

    def test_missing_db_file_is_skipped_in_multi_file_mode(self, tmp_path, memory_tracker):
        from zircolite.processing import process_db_input
        missing = tmp_path / "missing.db"
        good = tmp_path / "good.db"
        self._make_valid_db(good)
        ctx = self._ctx(tmp_path, memory_tracker)
        args = Namespace(logs_encoding=None)

        process_db_input(ctx, args, file_list=[missing, good])

        with open(ctx.outfile) as f:
            results = json.load(f)
        assert len(results) == 1

    def test_single_missing_db_exits_with_friendly_error(self, tmp_path, memory_tracker):
        from zircolite.processing import process_db_input
        ctx = self._ctx(tmp_path, memory_tracker)
        args = Namespace(logs_encoding=None, evtx=str(tmp_path / "missing.db"))

        with pytest.raises(SystemExit) as exc:
            process_db_input(ctx, args)
        assert exc.value.code == 1

    def test_midloop_failure_still_closes_json_array(self, tmp_path, memory_tracker, monkeypatch):
        from zircolite.core import ZircoliteCore
        from zircolite.processing import process_db_input
        good1 = tmp_path / "good1.db"
        good2 = tmp_path / "good2.db"
        self._make_valid_db(good1)
        self._make_valid_db(good2)
        ctx = self._ctx(tmp_path, memory_tracker)
        args = Namespace(logs_encoding=None)

        original = ZircoliteCore.execute_ruleset
        calls = {"n": 0}

        def failing(core_self, *a, **kw):
            calls["n"] += 1
            if calls["n"] == 2:
                raise sqlite3.OperationalError("disk I/O error")
            return original(core_self, *a, **kw)

        monkeypatch.setattr(ZircoliteCore, "execute_ruleset", failing)

        with pytest.raises(sqlite3.OperationalError):
            process_db_input(ctx, args, file_list=[good1, good2])

        with open(ctx.outfile) as f:
            results = json.load(f)
        assert len(results) == 1


class TestParallelKeepflatEndToEnd:
    """Parallel keepflat output must be valid JSONL (no interleaved writes)."""

    def test_parallel_keepflat_all_lines_parse(self, tmp_path, memory_tracker, monkeypatch):
        import orjson

        from zircolite.processing import process_parallel_streaming

        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "fieldMappings.json"
        config_file.write_text(json.dumps({
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": False, "transforms": {},
        }))
        files = []
        for i in range(4):
            f = tmp_path / f"events_{i}.json"
            f.write_text("\n".join(
                json.dumps({"EventID": i * 10 + j, "Message": f"m{i}-{j}"})
                for j in range(50)
            ) + "\n")
            files.append(f)

        logger = MagicMock()
        ctx = ProcessingContext(
            config=str(config_file), logger=logger, no_output=True,
            events_after=time.strptime("2020-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
            events_before=time.strptime("2030-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
            limit=-1, csv_mode=False, time_field="SystemTime", hashes=False,
            db_location=":memory:", delimiter=";", rulesets=[], rule_filters=None,
            outfile=str(tmp_path / "out.json"), ready_for_templating=False,
            package=False, dbfile=None, keepflat=True, memory_tracker=memory_tracker,
        )
        args = Namespace(logs_encoding=None, parallel_workers=4, parallel_memory_limit=95.0)

        process_parallel_streaming(ctx, files, "json", None, args)

        keepflat_files = list(tmp_path.glob("flattened_events_*.json"))
        assert len(keepflat_files) == 1
        lines = keepflat_files[0].read_bytes().splitlines()
        assert len(lines) == 200
        for line in lines:
            orjson.loads(line)  # every line must be a complete JSON object


class TestWorkerCoreReuse:
    """Thread-local core reuse across files (DELETE FROM logs branch)."""

    def test_worker_reuses_core_and_clears_table(self, tmp_path, dummy_ctx, dummy_args):
        import threading as _threading

        from zircolite.processing import process_single_file_worker

        f1 = tmp_path / "a.json"
        f1.write_text(json.dumps({"EventID": 1}) + "\n")
        f2 = tmp_path / "b.json"
        f2.write_text(json.dumps({"EventID": 2}) + "\n" + json.dumps({"EventID": 3}) + "\n")

        thread_local = _threading.local()
        kwargs = dict(
            counter_lock=_threading.Lock(),
            worker_counter=[0],
            total_filtered_count=[0, 0],
            thread_local=thread_local,
        )
        count1, _ = process_single_file_worker(f1, dummy_ctx, "json", None, dummy_args, **kwargs)
        assert count1 == 1
        # Second file on the same worker: table cleared, only its events remain
        count2, _ = process_single_file_worker(f2, dummy_ctx, "json", None, dummy_args, **kwargs)
        assert count2 == 2
        cursor = thread_local.core.db_connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        assert cursor.fetchone()[0] == 2


class TestPerfileShutdownFinalization:
    """Interrupted per-file runs must still produce valid (closed) JSON."""

    def test_shutdown_break_closes_json_array(self, tmp_path, memory_tracker, monkeypatch):
        from zircolite.processing import process_perfile_streaming

        config_file = tmp_path / "fieldMappings.json"
        config_file.write_text(json.dumps({
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": False, "transforms": {},
        }))
        outfile = tmp_path / "detected.json"
        files = []
        for i in range(3):
            f = tmp_path / f"events_{i}.json"
            f.write_text(json.dumps({"EventID": i, "CommandLine": "powershell.exe x"}) + "\n")
            files.append(f)

        logger = MagicMock()
        ctx = ProcessingContext(
            config=str(config_file), logger=logger, no_output=False,
            events_after=time.strptime("2020-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
            events_before=time.strptime("2030-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
            limit=-1, csv_mode=False, time_field="SystemTime", hashes=False,
            db_location=":memory:", delimiter=";",
            rulesets=[{
                "title": "PS", "id": "1", "description": "", "level": "high", "tags": [],
                "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%' ESCAPE '\\'"],
            }],
            rule_filters=None,
            outfile=str(outfile), ready_for_templating=False,
            package=False, dbfile=None, keepflat=False, memory_tracker=memory_tracker,
        )
        args = Namespace(logs_encoding=None)

        # First loop iteration runs, the second check triggers the shutdown break
        checks = iter([False, True, True, True])
        monkeypatch.setattr(
            "zircolite.processing.is_shutdown_requested", lambda: next(checks, True)
        )

        process_perfile_streaming(ctx, files, "json", None, args)

        with open(outfile) as f:
            results = json.load(f)  # must be a valid, closed JSON array
        assert len(results) == 1


class TestDbInputDirectoryExpansion:
    """-D pointed at a directory used to fail while auto-detection coped."""

    def test_directory_expands_to_the_databases_inside(self, tmp_path, test_logger):
        from zircolite.processing import expand_db_path

        (tmp_path / "a.db").write_bytes(b"")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.sqlite").write_bytes(b"")
        (tmp_path / "notes.txt").write_text("ignore me")

        args = argparse.Namespace(fileext=None, no_recursion=False)
        found = expand_db_path(tmp_path, args, test_logger)

        assert [p.name for p in found] == ["a.db", "b.sqlite"]

    def test_fileext_narrows_the_search(self, tmp_path, test_logger):
        from zircolite.processing import expand_db_path

        (tmp_path / "a.db").write_bytes(b"")
        (tmp_path / "b.sqlite").write_bytes(b"")

        args = argparse.Namespace(fileext="db", no_recursion=False)
        found = expand_db_path(tmp_path, args, test_logger)

        assert [p.name for p in found] == ["a.db"]

    def test_file_pattern_narrows_the_search(self, tmp_path, test_logger):
        """-D pointed at a directory honours --file-pattern.

        The explicit -D route skips discover_files entirely, so the pattern was
        silently dropped -- while the auto-detected SQLite route honoured it,
        because discovery had already run.
        """
        from zircolite.processing import expand_db_path

        (tmp_path / "Security.db").write_bytes(b"")
        (tmp_path / "System.db").write_bytes(b"")

        args = argparse.Namespace(
            fileext=None, no_recursion=False, file_pattern="Sec*.db"
        )
        found = expand_db_path(tmp_path, args, test_logger)

        assert [p.name for p in found] == ["Security.db"]

    def test_a_plain_path_is_passed_through(self, tmp_path, test_logger):
        from zircolite.processing import expand_db_path

        db = tmp_path / "single.db"
        db.write_bytes(b"")

        args = argparse.Namespace(fileext=None, no_recursion=False)
        assert expand_db_path(db, args, test_logger) == [db]

    def test_empty_directory_is_fatal(self, tmp_path):
        """Finding no database is as fatal as being handed a missing one.

        Returning [] left the run exiting 0 while the summary still advertised
        an output file that was never written.
        """
        from unittest.mock import MagicMock

        from zircolite.processing import expand_db_path

        logger = MagicMock()
        args = argparse.Namespace(fileext=None, no_recursion=False)

        with pytest.raises(SystemExit) as exc_info:
            expand_db_path(tmp_path, args, logger)
        assert exc_info.value.code != 0


class TestCsvKeepsFieldsFromEveryFile:
    """A field only later files carry must survive into the CSV.

    The header is written before the rows it describes, but the field set is
    only complete once every input has been read. Taking it from the first
    detection and letting ``extrasaction='ignore'`` swallow the rest lost
    evidence without a word: the detection was still reported, the field was
    simply gone from it.
    """

    RULE: ClassVar[list[dict]] = [
        {
            "title": "encoded powershell",
            "id": "cccccccc-0000-0000-0000-000000000001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%-enc %'"],
        }
    ]

    def _corpus(self, tmp_path):
        """Two files, both detecting; only the second carries ParentImage.

        The narrow file is padded so it sorts first, which is what puts the
        incomplete schema in front of the complete one.
        """
        logs = tmp_path / "logs"
        logs.mkdir(parents=True)

        def event(extra, padding=""):
            return json.dumps(
                {
                    "Event": {
                        "System": {
                            "Channel": "Security",
                            "EventID": 4688,
                            "SystemTime": "2024-01-01T00:00:00Z",
                            "Padding": padding,
                        },
                        "EventData": {"CommandLine": "powershell -enc AAAA", **extra},
                    }
                }
            )

        (logs / "narrow.json").write_text(event({}, "x" * 500), encoding="utf-8")
        (logs / "wide.json").write_text(
            event({"ParentImage": "C:\\evil\\dropper.exe"}), encoding="utf-8"
        )
        ruleset = tmp_path / "rules.json"
        ruleset.write_text(json.dumps(self.RULE), encoding="utf-8")
        return logs, ruleset

    def _run(self, tmp_path, *mode_flags):
        logs, ruleset = self._corpus(tmp_path)
        out = tmp_path / "out.csv"
        argv = [
            "zircolite.py",
            "--evtx", str(logs),
            "-j",
            "--ruleset", str(ruleset),
            "--csv",
            "--no-auto-mode",
            "-o", str(out),
            "--quiet",
            *mode_flags,
        ]
        with patch.object(sys, "argv", argv):
            zircolite.cli.main()
        rows = list(csv.DictReader(out.read_text(encoding="utf-8").splitlines(), delimiter=";"))
        return rows

    @pytest.mark.parametrize(
        "mode_flags",
        [pytest.param(("--no-parallel",), id="per-file"),
         pytest.param((), id="parallel"),
         pytest.param(("--unified-db",), id="unified")],
    )
    def test_the_later_file_s_field_reaches_the_csv(self, tmp_path, mode_flags):
        rows = self._run(tmp_path, *mode_flags)

        assert len(rows) == 2
        assert "ParentImage" in rows[0]
        assert {r.get("ParentImage") for r in rows} == {"", "C:\\evil\\dropper.exe"}

    @pytest.mark.parametrize(
        "mode_flags",
        [pytest.param(("--no-parallel",), id="per-file"),
         pytest.param((), id="parallel"),
         pytest.param(("--unified-db",), id="unified")],
    )
    def test_the_database_row_id_is_not_a_detection_field(self, tmp_path, mode_flags):
        """``SELECT *`` returns it; it identifies a row in a discarded database.

        The streaming header always dropped it, so leaving it in the buffered
        one gave the same corpus a different column set per mode.
        """
        rows = self._run(tmp_path, *mode_flags)

        assert "row_id" not in rows[0]

    def test_every_mode_produces_the_same_columns(self, tmp_path):
        columns = [
            set(self._run(tmp_path / mode, *flags)[0])
            for mode, flags in (
                ("perfile", ("--no-parallel",)),
                ("parallel", ()),
                ("unified", ("--unified-db",)),
            )
        ]

        assert columns[0] == columns[1] == columns[2]
