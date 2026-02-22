"""
Tests for the parallel processing module.
"""

import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite.parallel import (
    ParallelConfig,
    ParallelStats,
    MemoryAwareParallelProcessor,
    calculate_optimal_workers,
    process_files_with_memory_awareness,
    estimate_parallel_viability,
)


# ============================================================================
# CONFIGURATION DATACLASSES
# ============================================================================


class TestParallelConfig:
    """Tests for ParallelConfig dataclass."""

    def test_default_values(self):
        config = ParallelConfig()

        assert config.max_workers is None
        assert config.min_workers == 1
        assert config.memory_limit_percent == 75.0
        assert config.memory_check_interval == 5
        assert config.adaptive_workers is True
        assert config.batch_size == 10
        assert config.sort_by_size is True
        assert config.adaptive_memory is True

    def test_custom_values(self):
        config = ParallelConfig(
            max_workers=4,
            min_workers=2,
            memory_limit_percent=80.0,
        )

        assert config.max_workers == 4
        assert config.min_workers == 2
        assert config.memory_limit_percent == 80.0

    def test_override_new_fields(self):
        config = ParallelConfig(sort_by_size=False, adaptive_memory=False)
        assert config.sort_by_size is False
        assert config.adaptive_memory is False


class TestParallelStats:
    """Tests for ParallelStats dataclass."""

    def test_default_values(self):
        stats = ParallelStats()

        assert stats.total_files == 0
        assert stats.processed_files == 0
        assert stats.failed_files == 0
        assert stats.total_events == 0
        assert stats.peak_memory_mb == 0.0
        assert stats.avg_memory_mb == 0.0
        assert stats.processing_time_seconds == 0.0
        assert stats.workers_used == 0
        assert stats.throttle_events == 0
        assert stats.submissions_paused == 0
        assert stats.memory_calibrated is False
        assert stats.calibrated_ratio == 0.0

    def test_custom_values(self):
        stats = ParallelStats(
            total_files=10,
            processed_files=8,
            failed_files=2,
            total_events=1000,
            submissions_paused=5,
            memory_calibrated=True,
            calibrated_ratio=4.2,
        )

        assert stats.total_files == 10
        assert stats.processed_files == 8
        assert stats.failed_files == 2
        assert stats.total_events == 1000
        assert stats.submissions_paused == 5
        assert stats.memory_calibrated is True
        assert stats.calibrated_ratio == 4.2


# ============================================================================
# PROCESSOR INIT
# ============================================================================


class TestMemoryAwareParallelProcessorInit:
    """Tests for MemoryAwareParallelProcessor initialization."""

    def test_init_defaults(self, test_logger):
        processor = MemoryAwareParallelProcessor(logger=test_logger)

        assert processor.config is not None
        assert processor.logger is test_logger
        assert isinstance(processor.stats, ParallelStats)

    def test_init_with_config(self, test_logger):
        config = ParallelConfig(max_workers=4)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        assert processor.config.max_workers == 4


# ============================================================================
# MEMORY HELPERS
# ============================================================================


class TestMemoryAwareParallelProcessorMemory:
    """Tests for memory-related methods."""

    def test_get_available_memory_mb(self, test_logger):
        processor = MemoryAwareParallelProcessor(logger=test_logger)

        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.available = 8 * 1024 * 1024 * 1024
            available = processor.get_available_memory_mb()
            assert available == 8 * 1024

    def test_get_current_memory_mb(self, test_logger):
        processor = MemoryAwareParallelProcessor(logger=test_logger)

        with patch.object(processor._process, 'memory_info') as mock_mem:
            mock_mem.return_value.rss = 512 * 1024 * 1024
            current = processor.get_current_memory_mb()
            assert current == 512.0

    def test_get_memory_percent(self, test_logger):
        processor = MemoryAwareParallelProcessor(logger=test_logger)

        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.percent = 65.5
            percent = processor.get_memory_percent()
            assert percent == 65.5

    def test_should_throttle_below_limit(self, test_logger):
        config = ParallelConfig(memory_limit_percent=75.0)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.percent = 50.0
            assert processor.should_throttle() is False

    def test_should_throttle_above_limit(self, test_logger):
        config = ParallelConfig(memory_limit_percent=75.0)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.percent = 80.0
            assert processor.should_throttle() is True


# ============================================================================
# WORKER CALCULATION
# ============================================================================


class TestMemoryAwareParallelProcessorWorkerCalc:
    """Tests for worker calculation."""

    def test_calculate_optimal_workers_with_max_set(self, test_logger, tmp_path):
        config = ParallelConfig(max_workers=4)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        files = []
        for i in range(10):
            f = tmp_path / f"test_{i}.evtx"
            f.write_bytes(b"x" * 1000)
            files.append(f)

        workers = processor.calculate_optimal_workers(files)
        assert workers == 4

    def test_calculate_optimal_workers_auto(self, test_logger, tmp_path):
        config = ParallelConfig(max_workers=None)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        files = []
        for i in range(5):
            f = tmp_path / f"test_{i}.evtx"
            f.write_bytes(b"x" * 1024 * 1024)
            files.append(f)

        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.available = 8 * 1024 * 1024 * 1024
            workers = processor.calculate_optimal_workers(files)
            assert workers >= 1
            assert workers <= len(files)

    def test_calculate_optimal_workers_respects_min(self, test_logger, tmp_path):
        config = ParallelConfig(max_workers=None, min_workers=2)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        f = tmp_path / "test.evtx"
        f.write_bytes(b"x" * 1000)
        files = [f]

        workers = processor.calculate_optimal_workers(files)
        assert workers == 1  # single file can't exceed file count

    def test_estimate_memory_per_file(self, test_logger, tmp_path):
        processor = MemoryAwareParallelProcessor(logger=test_logger)

        files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.evtx"
            f.write_bytes(b"x" * (1024 * 1024))
            files.append(f)

        estimate = processor.estimate_memory_per_file(files)
        assert estimate > 0
        assert estimate < 100


# ============================================================================
# CONSOLIDATED WORKER CALCULATION (module-level function)
# ============================================================================


class TestConsolidatedWorkerCalc:
    """Tests for the module-level calculate_optimal_workers function."""

    def test_returns_max_workers_when_set(self):
        result = calculate_optimal_workers(
            file_sizes=[1024] * 5,
            available_memory_mb=8192,
            cpu_count=4,
            max_workers=3,
        )
        assert result == 3

    def test_max_workers_clamped_to_file_count(self):
        result = calculate_optimal_workers(
            file_sizes=[1024] * 2,
            available_memory_mb=8192,
            cpu_count=4,
            max_workers=10,
        )
        assert result == 2

    def test_respects_min_workers(self):
        result = calculate_optimal_workers(
            file_sizes=[1024],
            available_memory_mb=8192,
            cpu_count=4,
            min_workers=2,
            max_workers=5,
        )
        assert result >= 2

    def test_empty_file_list(self):
        assert calculate_optimal_workers([], 8192, 4) == 1

    def test_auto_scales_with_resources(self):
        result = calculate_optimal_workers(
            file_sizes=[1024 * 1024] * 10,
            available_memory_mb=16384,
            cpu_count=8,
        )
        assert 1 <= result <= 32
        assert result <= 10

    def test_never_exceeds_max_cap(self):
        result = calculate_optimal_workers(
            file_sizes=[100] * 100,
            available_memory_mb=999999,
            cpu_count=64,
            max_cap=16,
        )
        assert result <= 16

    def test_utils_delegates_to_parallel(self, tmp_path):
        """utils.analyze_files_and_recommend_mode uses the consolidated function."""
        from zircolite.utils import analyze_files_and_recommend_mode

        files = []
        for i in range(3):
            p = tmp_path / f"f{i}.evtx"
            p.write_bytes(b"x" * (1024 * 1024))
            files.append(p)

        with patch("psutil.virtual_memory") as mock_vm:
            mock_vm.return_value.available = 16 * 1024**3
            mock_vm.return_value.total = 32 * 1024**3

            _, _, stats = analyze_files_and_recommend_mode(files)

        assert "parallel_workers" in stats
        assert stats["parallel_workers"] >= 1


# ============================================================================
# LPT SCHEDULING
# ============================================================================


class TestLPTScheduling:
    """Tests for Longest Processing Time file scheduling."""

    def test_sort_files_by_size_descending(self, tmp_path):
        small = tmp_path / "small.evtx"
        medium = tmp_path / "medium.evtx"
        large = tmp_path / "large.evtx"
        small.write_bytes(b"x" * 100)
        medium.write_bytes(b"x" * 500)
        large.write_bytes(b"x" * 1000)

        result = MemoryAwareParallelProcessor.sort_files_by_size(
            [small, medium, large]
        )

        assert result[0] == large
        assert result[1] == medium
        assert result[2] == small

    def test_sort_handles_missing_files(self, tmp_path):
        existing = tmp_path / "exists.evtx"
        existing.write_bytes(b"x" * 500)
        missing = tmp_path / "missing.evtx"

        result = MemoryAwareParallelProcessor.sort_files_by_size(
            [missing, existing]
        )

        assert result[0] == existing
        assert result[1] == missing

    def test_sort_empty_list(self):
        assert MemoryAwareParallelProcessor.sort_files_by_size([]) == []

    def test_parallel_uses_sort_when_enabled(self, test_logger, tmp_path):
        files = []
        sizes = [100, 1000, 500]
        for i, size in enumerate(sizes):
            f = tmp_path / f"file_{i}.json"
            f.write_bytes(b"x" * size)
            files.append(f)

        processing_order = []

        def track_order(f):
            processing_order.append(f.name)
            return (1, {"file": str(f)})

        config = ParallelConfig(max_workers=1, sort_by_size=True)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)
        processor.process_files_parallel(
            files, track_order, disable_progress=True
        )

        assert processing_order[0] == "file_1.json"  # 1000 bytes
        assert processing_order[1] == "file_2.json"  # 500 bytes
        assert processing_order[2] == "file_0.json"  # 100 bytes

    def test_parallel_no_sort_when_disabled(self, test_logger, tmp_path):
        files = []
        sizes = [100, 1000, 500]
        for i, size in enumerate(sizes):
            f = tmp_path / f"file_{i}.json"
            f.write_bytes(b"x" * size)
            files.append(f)

        processing_order = []

        def track_order(f):
            processing_order.append(f.name)
            return (1, {"file": str(f)})

        config = ParallelConfig(max_workers=1, sort_by_size=False)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)
        processor.process_files_parallel(
            files, track_order, disable_progress=True
        )

        assert processing_order == ["file_0.json", "file_1.json", "file_2.json"]


# ============================================================================
# ADAPTIVE MEMORY ESTIMATION
# ============================================================================


class TestAdaptiveMemory:
    """Tests for runtime memory calibration."""

    def test_calibrate_memory_updates_estimate(self, test_logger, tmp_path):
        f = tmp_path / "test.evtx"
        f.write_bytes(b"x" * (1024 * 1024))

        processor = MemoryAwareParallelProcessor(logger=test_logger)
        processor._first_file_memory_before = 100.0

        processor.calibrate_memory(f, 120.0)  # 20 MB delta

        assert processor._calibrated_memory_per_file_mb is not None
        assert processor.stats.memory_calibrated is True
        assert processor.stats.calibrated_ratio > 0

        calibrated = processor.estimate_memory_per_file([f])
        assert calibrated == processor._calibrated_memory_per_file_mb

    def test_calibrate_no_op_if_no_before_snapshot(self, test_logger, tmp_path):
        f = tmp_path / "test.evtx"
        f.write_bytes(b"x" * 1024)

        processor = MemoryAwareParallelProcessor(logger=test_logger)
        processor.calibrate_memory(f, 200.0)

        assert processor._calibrated_memory_per_file_mb is None
        assert processor.stats.memory_calibrated is False

    def test_calibrate_no_op_if_negative_delta(self, test_logger, tmp_path):
        f = tmp_path / "test.evtx"
        f.write_bytes(b"x" * 1024)

        processor = MemoryAwareParallelProcessor(logger=test_logger)
        processor._first_file_memory_before = 200.0
        processor.calibrate_memory(f, 100.0)  # delta < 0

        assert processor._calibrated_memory_per_file_mb is None

    def test_adaptive_memory_in_parallel_run(self, test_logger, tmp_path):
        files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.json"
            f.write_bytes(b"x" * (512 * 1024))
            files.append(f)

        config = ParallelConfig(
            max_workers=1, adaptive_memory=True, sort_by_size=False
        )
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        def simple(f):
            return (10, {"file": str(f)})

        _, stats = processor.process_files_parallel(
            files, simple, disable_progress=True
        )

        assert stats.processed_files == 3


# ============================================================================
# THROTTLING
# ============================================================================


class TestRealThrottling:
    """Tests for submission-pausing throttle behaviour."""

    def test_submissions_paused_under_pressure(self, test_logger, tmp_path):
        files = []
        for i in range(8):
            f = tmp_path / f"test_{i}.json"
            f.write_text("{}")
            files.append(f)

        config = ParallelConfig(
            max_workers=2,
            memory_limit_percent=10.0,
            memory_check_interval=1,
            sort_by_size=False,
        )
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        def simple_process(f):
            return (1, {"file": str(f)})

        with patch("psutil.virtual_memory") as mock_vm:
            mock_vm.return_value.percent = 95.0
            _, stats = processor.process_files_parallel(
                files, simple_process, disable_progress=True
            )

        assert stats.processed_files == 8
        assert stats.submissions_paused > 0

    def test_all_files_eventually_processed_despite_throttle(
        self, test_logger, tmp_path
    ):
        """Even under sustained throttling, all files complete via safety valve."""
        files = []
        for i in range(5):
            f = tmp_path / f"test_{i}.json"
            f.write_text("{}")
            files.append(f)

        config = ParallelConfig(
            max_workers=1,
            memory_limit_percent=5.0,
            memory_check_interval=1,
            sort_by_size=False,
        )
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        def simple(f):
            return (1, None)

        with patch("psutil.virtual_memory") as mock_vm:
            mock_vm.return_value.percent = 99.0
            _, stats = processor.process_files_parallel(
                files, simple, disable_progress=True
            )

        assert stats.processed_files + stats.failed_files == 5

    def test_throttle_events_counted_under_memory_pressure(self, test_logger, tmp_path):
        """Legacy throttle_events counter is also incremented."""
        files = []
        for i in range(6):
            f = tmp_path / f"test_{i}.json"
            f.write_text('{}')
            files.append(f)

        config = ParallelConfig(
            max_workers=2,
            memory_limit_percent=10.0,
            memory_check_interval=1,
        )
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        def simple_process(f):
            return (1, {"file": str(f)})

        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.percent = 95.0
            results, stats = processor.process_files_parallel(
                files, simple_process, disable_progress=True,
            )

        assert stats.processed_files == 6
        assert stats.throttle_events > 0


# ============================================================================
# CALLBACKS
# ============================================================================


class TestCallbacks:
    """Tests for on_result and event_count_callback."""

    def test_on_result_called_per_file(self, test_logger, tmp_path):
        files = []
        for i in range(4):
            f = tmp_path / f"test_{i}.json"
            f.write_text("{}")
            files.append(f)

        received = []

        def capture(result):
            received.append(result)

        config = ParallelConfig(max_workers=2, sort_by_size=False)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        processor.process_files_parallel(
            files,
            lambda f: (10, {"name": f.name}),
            disable_progress=True,
            on_result=capture,
        )

        assert len(received) == 4
        names = {r["name"] for r in received}
        for f in files:
            assert f.name in names

    def test_on_result_not_called_for_none(self, test_logger, tmp_path):
        f = tmp_path / "test.json"
        f.write_text("{}")

        received = []
        config = ParallelConfig(max_workers=1)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        processor.process_files_parallel(
            [f],
            lambda x: (5, None),
            disable_progress=True,
            on_result=lambda r: received.append(r),
        )

        assert received == []

    def test_event_count_callback(self, test_logger, tmp_path):
        files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.json"
            f.write_text("{}")
            files.append(f)

        counts = []

        config = ParallelConfig(max_workers=1, sort_by_size=False)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)

        processor.process_files_parallel(
            files,
            lambda f: (100, {"name": f.name}),
            disable_progress=True,
            event_count_callback=lambda c: counts.append(c),
        )

        assert len(counts) == 3
        assert counts == [100, 200, 300]


# ============================================================================
# FILE PROCESSING
# ============================================================================


class TestMemoryAwareParallelProcessorProcessFiles:
    """Tests for file processing."""

    def test_process_files_empty_list(self, test_logger):
        processor = MemoryAwareParallelProcessor(logger=test_logger)

        def dummy_func(f):
            return (0, None)

        results, stats = processor.process_files_parallel([], dummy_func)

        assert results == []
        assert stats.total_files == 0

    def test_process_files_simple(self, test_logger, tmp_path):
        processor = MemoryAwareParallelProcessor(logger=test_logger)

        files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.json"
            f.write_text('{"test": true}')
            files.append(f)

        def simple_process(f):
            return (1, {"file": str(f)})

        results, stats = processor.process_files_parallel(
            files,
            simple_process,
            disable_progress=True
        )

        assert stats.total_files == 3
        assert stats.processed_files == 3
        assert stats.failed_files == 0
        assert len(results) == 3

    def test_process_files_with_failures(self, test_logger, tmp_path):
        processor = MemoryAwareParallelProcessor(logger=test_logger)

        files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.json"
            f.write_text('{"test": true}')
            files.append(f)

        call_count = [0]

        def failing_process(f):
            call_count[0] += 1
            if call_count[0] == 2:
                raise Exception("Simulated failure")
            return (1, {"file": str(f)})

        results, stats = processor.process_files_parallel(
            files,
            failing_process,
            disable_progress=True
        )

        assert stats.total_files == 3
        assert stats.processed_files == 2
        assert stats.failed_files == 1


# ============================================================================
# VIABILITY & CONVENIENCE
# ============================================================================


class TestEstimateParallelViability:
    """Tests for estimate_parallel_viability function."""

    def test_single_file_not_recommended(self, test_logger, tmp_path):
        f = tmp_path / "test.evtx"
        f.write_bytes(b"x" * 1000)

        result = estimate_parallel_viability([f], test_logger)

        assert result["recommended"] is False
        assert "Single file" in result["reason"]

    def test_multiple_files_recommended(self, test_logger, tmp_path):
        files = []
        for i in range(5):
            f = tmp_path / f"test_{i}.evtx"
            f.write_bytes(b"x" * 1024 * 1024)
            files.append(f)

        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.available = 16 * 1024 * 1024 * 1024
            mock_vm.return_value.total = 32 * 1024 * 1024 * 1024

            result = estimate_parallel_viability(files, test_logger)

            assert "suggested_workers" in result
            assert result["suggested_workers"] >= 1

    def test_empty_list(self, test_logger):
        result = estimate_parallel_viability([], test_logger)
        assert result["recommended"] is False


class TestProcessFilesWithMemoryAwareness:
    """Tests for convenience function."""

    def test_convenience_function(self, test_logger, tmp_path):
        files = []
        for i in range(2):
            f = tmp_path / f"test_{i}.json"
            f.write_text('{"test": true}')
            files.append(f)

        def simple_process(f):
            return (1, str(f))

        results, stats = process_files_with_memory_awareness(
            files,
            simple_process,
            logger=test_logger,
            disable_progress=True
        )

        assert stats.processed_files == 2
        assert len(results) == 2


# ============================================================================
# EDGE CASES
# ============================================================================


class TestMemoryAwareParallelProcessorEdgeCases:
    """Edge case tests."""

    def test_handles_psutil_error(self, test_logger):
        processor = MemoryAwareParallelProcessor(logger=test_logger)

        with patch('psutil.virtual_memory', side_effect=Exception("Error")):
            available = processor.get_available_memory_mb()
            assert available == 4096

    def test_handles_process_error(self, test_logger):
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        processor._process = MagicMock()
        processor._process.memory_info.side_effect = Exception("Error")

        current = processor.get_current_memory_mb()
        assert current == 0
