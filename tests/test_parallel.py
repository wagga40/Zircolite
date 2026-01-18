"""
Tests for the parallel processing module.
"""

import os
import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite.parallel import (
    ParallelConfig,
    ParallelStats,
    MemoryAwareParallelProcessor,
    process_files_with_memory_awareness,
    estimate_parallel_viability,
)


class TestParallelConfig:
    """Tests for ParallelConfig dataclass."""
    
    def test_default_values(self):
        """Test ParallelConfig default values."""
        config = ParallelConfig()
        
        assert config.max_workers is None
        assert config.min_workers == 1
        assert config.memory_limit_percent == 75.0
        assert config.memory_check_interval == 5
        assert config.use_processes is False
        assert config.adaptive_workers is True
        assert config.batch_size == 10
    
    def test_custom_values(self):
        """Test ParallelConfig with custom values."""
        config = ParallelConfig(
            max_workers=4,
            min_workers=2,
            memory_limit_percent=80.0,
            use_processes=True
        )
        
        assert config.max_workers == 4
        assert config.min_workers == 2
        assert config.memory_limit_percent == 80.0
        assert config.use_processes is True


class TestParallelStats:
    """Tests for ParallelStats dataclass."""
    
    def test_default_values(self):
        """Test ParallelStats default values."""
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
    
    def test_custom_values(self):
        """Test ParallelStats with custom values."""
        stats = ParallelStats(
            total_files=10,
            processed_files=8,
            failed_files=2,
            total_events=1000
        )
        
        assert stats.total_files == 10
        assert stats.processed_files == 8
        assert stats.failed_files == 2
        assert stats.total_events == 1000


class TestMemoryAwareParallelProcessorInit:
    """Tests for MemoryAwareParallelProcessor initialization."""
    
    def test_init_defaults(self, test_logger):
        """Test initialization with defaults."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        
        assert processor.config is not None
        assert processor.logger is test_logger
        assert isinstance(processor.stats, ParallelStats)
    
    def test_init_with_config(self, test_logger):
        """Test initialization with custom config."""
        config = ParallelConfig(max_workers=4)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)
        
        assert processor.config.max_workers == 4


class TestMemoryAwareParallelProcessorMemory:
    """Tests for memory-related methods."""
    
    def test_get_available_memory_mb(self, test_logger):
        """Test getting available memory."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        
        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.available = 8 * 1024 * 1024 * 1024  # 8 GB
            
            available = processor.get_available_memory_mb()
            
            assert available == 8 * 1024  # 8192 MB
    
    def test_get_current_memory_mb(self, test_logger):
        """Test getting current process memory."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        
        with patch.object(processor._process, 'memory_info') as mock_mem:
            mock_mem.return_value.rss = 512 * 1024 * 1024  # 512 MB
            
            current = processor.get_current_memory_mb()
            
            assert current == 512.0
    
    def test_get_memory_percent(self, test_logger):
        """Test getting memory usage percentage."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        
        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.percent = 65.5
            
            percent = processor.get_memory_percent()
            
            assert percent == 65.5
    
    def test_should_throttle_below_limit(self, test_logger):
        """Test throttling when below memory limit."""
        config = ParallelConfig(memory_limit_percent=75.0)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)
        
        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.percent = 50.0
            
            assert processor.should_throttle() is False
    
    def test_should_throttle_above_limit(self, test_logger):
        """Test throttling when above memory limit."""
        config = ParallelConfig(memory_limit_percent=75.0)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)
        
        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.percent = 80.0
            
            assert processor.should_throttle() is True


class TestMemoryAwareParallelProcessorWorkerCalc:
    """Tests for worker calculation."""
    
    def test_calculate_optimal_workers_with_max_set(self, test_logger, tmp_path):
        """Test worker calculation when max_workers is set."""
        config = ParallelConfig(max_workers=4)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)
        
        # Create dummy files
        files = []
        for i in range(10):
            f = tmp_path / f"test_{i}.evtx"
            f.write_bytes(b"x" * 1000)
            files.append(f)
        
        workers = processor.calculate_optimal_workers(files)
        
        assert workers == 4
    
    def test_calculate_optimal_workers_auto(self, test_logger, tmp_path):
        """Test automatic worker calculation."""
        config = ParallelConfig(max_workers=None)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)
        
        # Create dummy files
        files = []
        for i in range(5):
            f = tmp_path / f"test_{i}.evtx"
            f.write_bytes(b"x" * 1024 * 1024)  # 1 MB each
            files.append(f)
        
        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.available = 8 * 1024 * 1024 * 1024  # 8 GB
            
            workers = processor.calculate_optimal_workers(files)
            
            # Should return at least 1 worker
            assert workers >= 1
            # Should not exceed file count
            assert workers <= len(files)
    
    def test_calculate_optimal_workers_respects_min(self, test_logger, tmp_path):
        """Test that minimum workers is respected."""
        config = ParallelConfig(max_workers=None, min_workers=2)
        processor = MemoryAwareParallelProcessor(config=config, logger=test_logger)
        
        # Create single file
        f = tmp_path / "test.evtx"
        f.write_bytes(b"x" * 1000)
        files = [f]
        
        workers = processor.calculate_optimal_workers(files)
        
        # Should not exceed file count even with min_workers
        assert workers == 1
    
    def test_estimate_memory_per_file(self, test_logger, tmp_path):
        """Test memory estimation per file."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        
        # Create files of known sizes
        files = []
        for i in range(3):
            f = tmp_path / f"test_{i}.evtx"
            f.write_bytes(b"x" * (1024 * 1024))  # 1 MB each
            files.append(f)
        
        estimate = processor.estimate_memory_per_file(files)
        
        # 1 MB file * 6x multiplier = ~6 MB
        assert estimate > 0
        assert estimate < 100  # Reasonable upper bound


class TestMemoryAwareParallelProcessorProcessFiles:
    """Tests for file processing."""
    
    def test_process_files_empty_list(self, test_logger):
        """Test processing empty file list."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        
        def dummy_func(f):
            return (0, None)
        
        results, stats = processor.process_files_parallel([], dummy_func)
        
        assert results == []
        assert stats.total_files == 0
    
    def test_process_files_simple(self, test_logger, tmp_path):
        """Test simple file processing."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        
        # Create test files
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
        """Test processing with some failures."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        
        # Create test files
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


class TestEstimateParallelViability:
    """Tests for estimate_parallel_viability function."""
    
    def test_single_file_not_recommended(self, test_logger, tmp_path):
        """Test that single file returns not recommended."""
        f = tmp_path / "test.evtx"
        f.write_bytes(b"x" * 1000)
        
        result = estimate_parallel_viability([f], test_logger)
        
        assert result["recommended"] is False
        assert "Single file" in result["reason"]
    
    def test_multiple_files_recommended(self, test_logger, tmp_path):
        """Test that multiple files may be recommended."""
        files = []
        for i in range(5):
            f = tmp_path / f"test_{i}.evtx"
            f.write_bytes(b"x" * 1024 * 1024)  # 1 MB each
            files.append(f)
        
        with patch('psutil.virtual_memory') as mock_vm:
            mock_vm.return_value.available = 16 * 1024 * 1024 * 1024  # 16 GB
            mock_vm.return_value.total = 32 * 1024 * 1024 * 1024  # 32 GB
            
            result = estimate_parallel_viability(files, test_logger)
            
            assert "suggested_workers" in result
            assert result["suggested_workers"] >= 1
    
    def test_empty_list(self, test_logger):
        """Test with empty file list."""
        result = estimate_parallel_viability([], test_logger)
        
        assert result["recommended"] is False


class TestProcessFilesWithMemoryAwareness:
    """Tests for convenience function."""
    
    def test_convenience_function(self, test_logger, tmp_path):
        """Test the convenience function wrapper."""
        # Create test files
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


class TestMemoryAwareParallelProcessorEdgeCases:
    """Edge case tests."""
    
    def test_handles_psutil_error(self, test_logger):
        """Test handling of psutil errors."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        
        with patch('psutil.virtual_memory', side_effect=Exception("Error")):
            # Should return fallback value
            available = processor.get_available_memory_mb()
            assert available == 4096  # Fallback value
    
    def test_handles_process_error(self, test_logger):
        """Test handling of process memory errors."""
        processor = MemoryAwareParallelProcessor(logger=test_logger)
        processor._process = MagicMock()
        processor._process.memory_info.side_effect = Exception("Error")
        
        current = processor.get_current_memory_mb()
        assert current == 0
