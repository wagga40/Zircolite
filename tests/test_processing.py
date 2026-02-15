"""
Tests for zircolite/processing.py.

Covers:
- ProcessingContext dataclass (including cached time strings)
- LEVEL_PRIORITY constant
- Factory helpers (create_zircolite_core, create_worker_core, create_extractor)
- _sort_key_severity helper
- _write_parallel_results (binary JSON + CSV output)
- Module-level imports / public API surface
"""

import json
import os
import time
import threading
import pytest
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

from zircolite.console import LEVEL_PRIORITY
from zircolite.processing import (
    ProcessingContext,
    create_zircolite_core,
    create_worker_core,
    create_extractor,
    _sort_key_severity,
    _unpack_streaming_result,
    _write_parallel_results,
    process_single_file_worker,
    process_perfile_streaming,
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
        parallel_memory_limit=75.0,
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
        assert dummy_ctx.file_stats is None


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
        assert _unpack_streaming_result((42, 5)) == (42, 5)

    def test_unpack_streaming_result_int(self):
        assert _unpack_streaming_result(42) == (42, 0)

    def test_sort_key_severity_ordering(self):
        critical = {"rule_level": "critical", "count": 1}
        high = {"rule_level": "high", "count": 100}
        assert _sort_key_severity(critical) < _sort_key_severity(high)

    def test_sort_key_severity_count_descending(self):
        a = {"rule_level": "high", "count": 50}
        b = {"rule_level": "high", "count": 10}
        assert _sort_key_severity(a) < _sort_key_severity(b)

    def test_sort_key_unknown_level_goes_last(self):
        unknown = {"rule_level": "custom", "count": 100}
        info = {"rule_level": "informational", "count": 1}
        assert _sort_key_severity(info) < _sort_key_severity(unknown)


# =============================================================================
# _write_parallel_results
# =============================================================================

class TestWriteParallelResults:
    """Tests for _write_parallel_results (binary JSON + CSV)."""

    def test_json_output_is_valid(self, dummy_ctx, tmp_path):
        dummy_ctx.no_output = False
        dummy_ctx.outfile = str(tmp_path / "results.json")

        sample_results = [
            {"title": "Rule A", "rule_level": "high", "count": 3, "matches": []},
            {"title": "Rule B", "rule_level": "low", "count": 1, "matches": []},
        ]
        _write_parallel_results(dummy_ctx, sample_results)

        with open(dummy_ctx.outfile, "rb") as f:
            data = json.loads(f.read())
        assert len(data) == 2
        assert data[0]["title"] == "Rule A"

    def test_json_output_binary_mode(self, dummy_ctx, tmp_path):
        """Ensure output is written in binary mode (no BOM, valid UTF-8)."""
        dummy_ctx.no_output = False
        dummy_ctx.outfile = str(tmp_path / "results.json")

        _write_parallel_results(dummy_ctx, [{"title": "Test", "count": 1, "matches": []}])

        raw = Path(dummy_ctx.outfile).read_bytes()
        assert raw.startswith(b"[")
        assert raw.endswith(b"]")

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
        _write_parallel_results(dummy_ctx, sample_results)

        content = Path(dummy_ctx.outfile).read_text(encoding="utf-8")
        assert "rule_title" in content
        assert "val1" in content

    def test_no_output_flag_skips_write(self, dummy_ctx, tmp_path):
        dummy_ctx.no_output = True
        dummy_ctx.outfile = str(tmp_path / "should_not_exist.json")
        _write_parallel_results(dummy_ctx, [{"title": "Rule A"}])
        assert not Path(dummy_ctx.outfile).exists()

    def test_empty_results_writes_empty_array(self, dummy_ctx, tmp_path):
        dummy_ctx.no_output = False
        dummy_ctx.outfile = str(tmp_path / "empty.json")
        _write_parallel_results(dummy_ctx, [])
        raw = Path(dummy_ctx.outfile).read_bytes()
        assert raw == b"[]"


# =============================================================================
# process_perfile_streaming
# =============================================================================

class TestProcessPerfileStreaming:
    """Tests for process_perfile_streaming behavior."""

    def test_perfile_no_template_returns_accumulated_results(
        self, field_mappings_file, test_logger, default_args_config,
        sample_ruleset, tmp_path,
    ):
        """Per-file streaming always returns accumulated results for summary/ATT&CK dashboard."""
        ctx = ProcessingContext(
            config=field_mappings_file,
            logger=test_logger,
            no_output=True,
            events_after=time.strptime("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"),
            events_before=time.strptime("9999-12-12T23:59:59", "%Y-%m-%dT%H:%M:%S"),
            limit=-1,
            csv_mode=False,
            time_field="SystemTime",
            hashes=False,
            db_location=":memory:",
            delimiter=";",
            rulesets=sample_ruleset,
            rule_filters=None,
            outfile=str(tmp_path / "out.json"),
            ready_for_templating=False,
            package=False,
            dbfile=None,
            keepflat=False,
            memory_tracker=MemoryTracker(logger=test_logger),
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
            process_unified_streaming,
            process_perfile_streaming,
            process_db_input,
            process_parallel_streaming,
        )
        # Just check they're callable
        for fn in [
            process_unified_streaming,
            process_perfile_streaming,
            process_db_input,
            process_parallel_streaming,
        ]:
            assert callable(fn)
