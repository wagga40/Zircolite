"""
Tests for the MemoryTracker class.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import MemoryTracker


class TestMemoryTrackerInit:
    """Tests for MemoryTracker initialization."""
    
    def test_init_defaults(self, test_logger):
        """Test MemoryTracker initialization with defaults."""
        tracker = MemoryTracker(logger=test_logger)
        
        assert tracker.memory_samples == []
        assert tracker.peak_memory == 0
    
    def test_init_with_psutil(self, test_logger, mock_psutil):
        """Test initialization when psutil is available."""
        tracker = MemoryTracker(logger=test_logger)
        
        assert tracker.process is not None


class TestMemoryTrackerGetMemoryUsage:
    """Tests for get_memory_usage method."""
    
    def test_get_memory_usage_with_psutil(self, test_logger):
        """Test getting memory usage with psutil mock."""
        mock_process = MagicMock()
        mock_process.memory_info.return_value.rss = 100 * 1024 * 1024  # 100 MB
        
        with patch('psutil.Process', return_value=mock_process):
            tracker = MemoryTracker(logger=test_logger)
            tracker.process = mock_process
            
            memory_mb = tracker.get_memory_usage()
            
            assert memory_mb == 100.0
    
    def test_get_memory_usage_returns_float(self, test_logger):
        """Test that get_memory_usage returns a float."""
        tracker = MemoryTracker(logger=test_logger)
        
        result = tracker.get_memory_usage()
        
        assert isinstance(result, (int, float))
        assert result >= 0
    
    def test_get_memory_usage_handles_error(self, test_logger):
        """Test that errors are handled gracefully."""
        tracker = MemoryTracker(logger=test_logger)
        tracker.process = None
        
        # Should return 0 on error
        result = tracker.get_memory_usage()
        
        assert result >= 0


class TestMemoryTrackerSample:
    """Tests for sample method."""
    
    def test_sample_adds_to_list(self, test_logger):
        """Test that sample adds to memory_samples list."""
        mock_process = MagicMock()
        mock_process.memory_info.return_value.rss = 50 * 1024 * 1024  # 50 MB
        
        tracker = MemoryTracker(logger=test_logger)
        tracker.process = mock_process
        
        tracker.sample()
        
        assert len(tracker.memory_samples) == 1
        assert tracker.memory_samples[0] == 50.0
    
    def test_sample_updates_peak(self, test_logger):
        """Test that sample updates peak_memory."""
        mock_process = MagicMock()
        tracker = MemoryTracker(logger=test_logger)
        tracker.process = mock_process
        
        # First sample: 50 MB
        mock_process.memory_info.return_value.rss = 50 * 1024 * 1024
        tracker.sample()
        
        # Second sample: 100 MB (new peak)
        mock_process.memory_info.return_value.rss = 100 * 1024 * 1024
        tracker.sample()
        
        # Third sample: 75 MB (not a new peak)
        mock_process.memory_info.return_value.rss = 75 * 1024 * 1024
        tracker.sample()
        
        assert tracker.peak_memory == 100.0
        assert len(tracker.memory_samples) == 3
    
    def test_multiple_samples(self, test_logger):
        """Test taking multiple samples."""
        mock_process = MagicMock()
        tracker = MemoryTracker(logger=test_logger)
        tracker.process = mock_process
        
        for i in range(10):
            mock_process.memory_info.return_value.rss = (i + 1) * 10 * 1024 * 1024
            tracker.sample()
        
        assert len(tracker.memory_samples) == 10
        assert tracker.peak_memory == 100.0  # 100 MB


class TestMemoryTrackerGetStats:
    """Tests for get_stats method."""
    
    def test_get_stats_empty(self, test_logger):
        """Test get_stats with no samples."""
        tracker = MemoryTracker(logger=test_logger)
        
        peak, average = tracker.get_stats()
        
        assert peak == 0
        assert average == 0
    
    def test_get_stats_with_samples(self, test_logger):
        """Test get_stats with samples."""
        tracker = MemoryTracker(logger=test_logger)
        tracker.memory_samples = [50.0, 100.0, 75.0]
        tracker.peak_memory = 100.0
        
        peak, average = tracker.get_stats()
        
        assert peak == 100.0
        assert average == 75.0  # (50 + 100 + 75) / 3
    
    def test_get_stats_single_sample(self, test_logger):
        """Test get_stats with single sample."""
        tracker = MemoryTracker(logger=test_logger)
        tracker.memory_samples = [42.0]
        tracker.peak_memory = 42.0
        
        peak, average = tracker.get_stats()
        
        assert peak == 42.0
        assert average == 42.0


class TestMemoryTrackerFormatMemory:
    """Tests for format_memory method."""
    
    def test_format_memory_mb(self, test_logger):
        """Test formatting memory in MB."""
        tracker = MemoryTracker(logger=test_logger)
        
        result = tracker.format_memory(100.0)
        
        assert "100.00 MB" == result
    
    def test_format_memory_gb(self, test_logger):
        """Test formatting memory in GB."""
        tracker = MemoryTracker(logger=test_logger)
        
        result = tracker.format_memory(2048.0)  # 2048 MB = 2 GB
        
        assert "2.00 GB" == result
    
    def test_format_memory_small(self, test_logger):
        """Test formatting small memory values."""
        tracker = MemoryTracker(logger=test_logger)
        
        result = tracker.format_memory(0.5)
        
        assert "0.50 MB" == result
    
    def test_format_memory_exactly_1024(self, test_logger):
        """Test formatting exactly 1024 MB (1 GB)."""
        tracker = MemoryTracker(logger=test_logger)
        
        result = tracker.format_memory(1024.0)
        
        assert "1.00 GB" == result
    
    def test_format_memory_large(self, test_logger):
        """Test formatting large memory values."""
        tracker = MemoryTracker(logger=test_logger)
        
        result = tracker.format_memory(8192.0)  # 8 GB
        
        assert "8.00 GB" == result
    
    def test_format_memory_precision(self, test_logger):
        """Test that formatting has 2 decimal places."""
        tracker = MemoryTracker(logger=test_logger)
        
        result = tracker.format_memory(123.456)
        
        assert "123.46 MB" == result


class TestMemoryTrackerIntegration:
    """Integration tests for MemoryTracker."""
    
    def test_full_tracking_workflow(self, test_logger):
        """Test complete tracking workflow."""
        mock_process = MagicMock()
        tracker = MemoryTracker(logger=test_logger)
        tracker.process = mock_process
        
        # Simulate memory usage over time
        memory_values = [50, 75, 100, 90, 80, 120, 100, 85]
        
        for mem_mb in memory_values:
            mock_process.memory_info.return_value.rss = mem_mb * 1024 * 1024
            tracker.sample()
        
        peak, average = tracker.get_stats()
        
        assert peak == 120.0
        assert average == sum(memory_values) / len(memory_values)
        
        peak_formatted = tracker.format_memory(peak)
        assert "120.00 MB" == peak_formatted


class TestMemoryTrackerEdgeCases:
    """Edge case tests for MemoryTracker."""
    
    def test_negative_memory_handled(self, test_logger):
        """Test that negative values are handled."""
        tracker = MemoryTracker(logger=test_logger)
        
        # format_memory should handle negative (though shouldn't happen)
        result = tracker.format_memory(-100.0)
        
        # Should still format without crashing
        assert "MB" in result or "GB" in result
    
    def test_zero_memory(self, test_logger):
        """Test zero memory value."""
        tracker = MemoryTracker(logger=test_logger)
        
        result = tracker.format_memory(0)
        
        assert "0.00 MB" == result
    
    def test_very_large_memory(self, test_logger):
        """Test very large memory value."""
        tracker = MemoryTracker(logger=test_logger)
        
        result = tracker.format_memory(102400.0)  # 100 GB
        
        assert "100.00 GB" == result
    
    def test_psutil_exception_handling(self, test_logger):
        """Test handling of psutil exceptions."""
        mock_process = MagicMock()
        mock_process.memory_info.side_effect = Exception("Process error")
        
        tracker = MemoryTracker(logger=test_logger)
        tracker.process = mock_process
        
        # Should not raise exception
        result = tracker.get_memory_usage()
        
        assert result >= 0
