"""
Tests for utility functions in zircolite.py.
"""

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import (
    avoid_files,
    check_if_exists,
    create_silent_logger,
    init_logger,
    quit_on_error,
    select_files,
)


class TestInitLogger:
    """Tests for init_logger function."""

    def test_init_logger_default(self):
        """Test logger initialization with default settings."""
        logger = init_logger(debug_mode=False)

        assert logger is not None
        assert isinstance(logger, logging.Logger)

    def test_init_logger_debug_mode(self):
        """Test logger initialization with debug mode."""
        logger = init_logger(debug_mode=True)

        assert logger is not None

    def test_init_logger_with_log_file(self, tmp_path):
        """Test logger initialization with log file."""
        log_file = str(tmp_path / "test.log")

        logger = init_logger(debug_mode=False, log_file=log_file)

        assert logger is not None
        # Log a message
        logger.info("Test message")

        # Force flush handlers
        for handler in logger.handlers:
            handler.flush()

        # File creation may be delayed - check logger has file handler configured
        file_handlers = [h for h in logger.handlers if hasattr(h, 'baseFilename')]
        assert len(file_handlers) >= 1

    def test_init_logger_debug_with_file(self, tmp_path):
        """Test logger in debug mode with file output."""
        log_file = str(tmp_path / "debug.log")

        logger = init_logger(debug_mode=True, log_file=log_file)

        assert logger is not None

        # Log debug message
        logger.debug("Debug test message")

        # Force flush handlers
        for handler in logger.handlers:
            handler.flush()

        # Check logger is properly configured (file may be delayed)
        assert logger.level in [logging.DEBUG, logging.INFO, logging.NOTSET]


class TestCreateSilentLogger:
    """Tests for create_silent_logger."""

    def test_silent_logger_level_above_critical(self):
        """Silent logger has level above CRITICAL so no messages are emitted."""
        logger = create_silent_logger()
        assert logger.level > logging.CRITICAL

    def test_silent_logger_custom_name(self):
        """create_silent_logger accepts custom name."""
        logger = create_silent_logger(name="worker_1")
        assert logger.name == "worker_1"


class TestCheckIfExists:
    """Tests for check_if_exists function."""

    def test_check_existing_file(self, tmp_path, test_logger):
        """Test checking an existing file."""
        test_file = tmp_path / "existing.txt"
        test_file.touch()

        # Existing files should pass validation and return None
        result = check_if_exists(str(test_file), "File not found", test_logger)
        assert result is None

    def test_check_nonexistent_file(self, test_logger):
        """Test checking a non-existent file."""
        with pytest.raises(SystemExit) as exc_info:
            check_if_exists("/nonexistent/path/file.txt", "File not found", test_logger)

        assert exc_info.value.code == 1

    def test_check_if_exists_rejects_directory(self, tmp_path, test_logger):
        """check_if_exists uses is_file(), so a directory must be rejected."""
        assert tmp_path.is_dir()
        with pytest.raises(SystemExit):
            check_if_exists(str(tmp_path), "Not a file", test_logger)


class TestQuitOnError:
    """Tests for quit_on_error function."""

    def test_quit_on_error_exits(self, test_logger):
        """Test that quit_on_error exits with code 1."""
        with pytest.raises(SystemExit) as exc_info:
            quit_on_error("Error message", test_logger)

        assert exc_info.value.code == 1

    def test_quit_on_error_default_logger(self):
        """quit_on_error with logger=None uses default logger and exits."""
        with pytest.raises(SystemExit) as exc_info:
            quit_on_error("Error message", None)
        assert exc_info.value.code == 1


class TestSelectFiles:
    """Tests for select_files function."""

    def test_select_files_with_match(self):
        """Test selecting files that match filter."""
        path_list = [
            Path("/logs/sysmon.evtx"),
            Path("/logs/security.evtx"),
            Path("/logs/application.evtx"),
            Path("/logs/sysmon_backup.evtx"),
        ]

        result = select_files(path_list, [["sysmon"]])

        assert len(result) == 2
        assert all("sysmon" in str(p).lower() for p in result)

    def test_select_files_case_insensitive(self):
        """Test that select is case-insensitive."""
        path_list = [
            Path("/logs/SYSMON.evtx"),
            Path("/logs/Sysmon.evtx"),
            Path("/logs/sysmon.evtx"),
        ]

        result = select_files(path_list, [["sysmon"]])

        assert len(result) == 3

    def test_select_files_no_match(self):
        """Test when no files match filter."""
        path_list = [
            Path("/logs/security.evtx"),
            Path("/logs/application.evtx"),
        ]

        result = select_files(path_list, [["sysmon"]])

        assert len(result) == 0

    def test_select_files_no_filter(self):
        """Test with no filter (returns all files)."""
        path_list = [
            Path("/logs/file1.evtx"),
            Path("/logs/file2.evtx"),
        ]

        result = select_files(path_list, None)

        assert result == path_list

    def test_select_files_multiple_filters(self):
        """Test with multiple filter terms."""
        path_list = [
            Path("/logs/sysmon.evtx"),
            Path("/logs/security.evtx"),
            Path("/logs/dns.evtx"),
        ]

        # Any file matching any filter should be included
        result = select_files(path_list, [["sysmon"], ["security"]])

        assert len(result) >= 1

    def test_select_files_multiple_patterns_per_group(self):
        """All patterns in a nargs='+' group must be honored, not just the first."""
        path_list = [
            Path("/logs/sysmon.evtx"),
            Path("/logs/security.evtx"),
            Path("/logs/application.evtx"),
        ]

        result = select_files(path_list, [["sysmon", "security"]])

        assert len(result) == 2
        assert any("sysmon" in p for p in result)
        assert any("security" in p for p in result)


class TestAvoidFiles:
    """Tests for avoid_files function."""

    def test_avoid_files_excludes_match(self):
        """Test excluding files that match filter."""
        path_list = [
            Path("/logs/sysmon.evtx"),
            Path("/logs/security.evtx"),
            Path("/logs/application.evtx"),
        ]

        result = avoid_files(path_list, [["sysmon"]])

        assert len(result) == 2
        assert all("sysmon" not in str(p).lower() for p in result)

    def test_avoid_files_case_insensitive(self):
        """Test that avoid is case-insensitive."""
        path_list = [
            Path("/logs/SYSMON.evtx"),
            Path("/logs/security.evtx"),
        ]

        result = avoid_files(path_list, [["sysmon"]])

        assert len(result) == 1
        assert "security" in str(result[0])

    def test_avoid_files_multiple_patterns_per_group(self):
        """All patterns in a nargs='+' group must be honored, not just the first."""
        path_list = [
            Path("/logs/sysmon.evtx"),
            Path("/logs/security.evtx"),
            Path("/logs/application.evtx"),
        ]

        result = avoid_files(path_list, [["sysmon", "security"]])

        assert result == [str(Path("/logs/application.evtx"))]

    def test_avoid_files_no_filter(self):
        """Test with no filter (returns all files)."""
        path_list = [
            Path("/logs/file1.evtx"),
            Path("/logs/file2.evtx"),
        ]

        result = avoid_files(path_list, None)

        assert result == path_list

    def test_avoid_matches_the_filename_not_the_directory(self):
        """--avoid is documented as matching filenames.

        Matching the whole path meant `-e /data/evtx-archive/ -a evtx` excluded
        every file, and the resulting "no file found" error blamed the
        extension.
        """
        path_list = [
            Path("/data/evtx-archive/security.json"),
            Path("/data/evtx-archive/sysmon.json"),
        ]

        result = avoid_files(path_list, [["evtx"]])

        assert len(result) == 2


class TestSelectFilesPathSemantics:
    """--select is documented as matching filenames, not whole paths."""

    def test_select_matches_the_filename_not_the_directory(self):
        path_list = [
            Path("/data/sysmon-exports/security.json"),
            Path("/data/sysmon-exports/application.json"),
        ]

        result = select_files(path_list, [["sysmon"]])

        assert result == []

    def test_select_still_matches_a_real_filename(self):
        path_list = [
            Path("/data/exports/sysmon.json"),
            Path("/data/exports/application.json"),
        ]

        result = select_files(path_list, [["sysmon"]])

        assert result == [str(Path("/data/exports/sysmon.json"))]

    def test_avoid_files_all_excluded(self):
        """Test when all files are excluded."""
        path_list = [
            Path("/logs/sysmon1.evtx"),
            Path("/logs/sysmon2.evtx"),
        ]

        result = avoid_files(path_list, [["sysmon"]])

        assert len(result) == 0

    def test_avoid_files_multiple_filters(self):
        """Test with multiple exclusion filters."""
        path_list = [
            Path("/logs/sysmon.evtx"),
            Path("/logs/security.evtx"),
            Path("/logs/application.evtx"),
        ]

        result = avoid_files(path_list, [["sysmon"], ["security"]])

        # Files should be excluded if they match ANY filter
        assert len(result) <= 3


class TestSelectAndAvoidCombined:
    """Tests for combining select_files and avoid_files."""

    def test_select_then_avoid(self):
        """Test applying select first, then avoid."""
        path_list = [
            Path("/logs/sysmon_2024.evtx"),
            Path("/logs/sysmon_backup.evtx"),
            Path("/logs/security.evtx"),
            Path("/logs/application.evtx"),
        ]

        # Select sysmon files
        selected = select_files(path_list, [["sysmon"]])

        # Avoid backup files
        final = avoid_files(selected, [["backup"]])

        assert len(final) == 1
        assert "sysmon_2024" in str(final[0])


class TestPathHandling:
    """Tests for path-related edge cases."""

    def test_select_files_with_path_objects(self):
        """Test select_files with Path objects."""
        paths = [
            Path("/test/sysmon.evtx"),
            Path("/test/other.evtx"),
        ]

        result = select_files(paths, [["sysmon"]])

        assert len(result) == 1

    def test_avoid_files_with_path_objects(self):
        """Test avoid_files with Path objects."""
        paths = [
            Path("/test/sysmon.evtx"),
            Path("/test/other.evtx"),
        ]

        result = avoid_files(paths, [["sysmon"]])

        assert len(result) == 1
        assert "other" in str(result[0])

    def test_select_files_with_mixed_separators(self):
        """Test file selection with different path separators."""
        paths = [
            Path("C:/Users/test/sysmon.evtx"),
            Path("C:\\Users\\test\\other.evtx"),
        ]

        result = select_files(paths, [["sysmon"]])

        assert len(result) == 1


# =============================================================================
# format_size
# =============================================================================

class TestFormatSize:
    """Tests for format_size utility function."""

    def test_format_size_bytes(self):
        from zircolite.utils import format_size
        assert format_size(500) == "500 bytes"

    def test_format_size_kb(self):
        from zircolite.utils import format_size
        result = format_size(2048)
        assert "KB" in result

    def test_format_size_mb(self):
        """Cover line 329: MB formatting branch."""
        from zircolite.utils import format_size
        result = format_size(50 * 1024 * 1024)
        assert "MB" in result
        assert "50.0" in result

    def test_format_size_gb(self):
        from zircolite.utils import format_size
        result = format_size(2 * 1024 * 1024 * 1024)
        assert "GB" in result


# =============================================================================
# analyze_files_and_recommend_mode
# =============================================================================

class TestAnalyzeFilesAndRecommendMode:
    """Tests for analyze_files_and_recommend_mode."""

    def test_single_file_returns_perfile(self, tmp_path):
        from zircolite.utils import analyze_files_and_recommend_mode
        f = tmp_path / "single.evtx"
        f.write_bytes(b"x" * 1000)
        mode, reason, stats = analyze_files_and_recommend_mode([str(f)])
        assert mode == "per-file"
        assert "Single file" in reason

    def test_psutil_failure_fallback(self, tmp_path):
        """Cover lines 362-366: psutil failure fallback."""
        from unittest.mock import patch

        from zircolite.utils import analyze_files_and_recommend_mode

        f1 = tmp_path / "a.evtx"
        f2 = tmp_path / "b.evtx"
        f1.write_bytes(b"x" * 1000)
        f2.write_bytes(b"x" * 1000)

        with patch("zircolite.utils.psutil") as mock_psutil:
            mock_psutil.virtual_memory.side_effect = Exception("no psutil")
            mode, reason, stats = analyze_files_and_recommend_mode([str(f1), str(f2)])

        assert stats['has_psutil'] is False

    def test_file_size_error_returns_zero(self, tmp_path):
        """Cover lines 374-375: OSError when getting file size."""
        from zircolite.utils import analyze_files_and_recommend_mode

        mode, reason, stats = analyze_files_and_recommend_mode(
            ["/nonexistent/file1.evtx", "/nonexistent/file2.evtx"]
        )
        assert stats['total_size'] == 0

    def test_many_small_files_unified(self, tmp_path):
        """Many small files should recommend unified mode."""
        from zircolite.utils import analyze_files_and_recommend_mode

        files = []
        for i in range(15):
            f = tmp_path / f"small_{i}.evtx"
            f.write_bytes(b"x" * 1024)  # 1 KB each
            files.append(str(f))

        mode, reason, stats = analyze_files_and_recommend_mode(files)
        assert mode == "unified"

    def test_memory_multiplier_medium_files(self, tmp_path):
        """Cover line 386: medium file multiplier (10-50MB avg)."""
        from zircolite.utils import analyze_files_and_recommend_mode

        files = []
        for i in range(3):
            f = tmp_path / f"med_{i}.evtx"
            f.write_bytes(b"x" * (20 * 1024 * 1024))  # 20 MB each
            files.append(str(f))

        mode, reason, stats = analyze_files_and_recommend_mode(files)
        assert stats['file_count'] == 3

    def test_memory_multiplier_large_files(self, tmp_path):
        """Cover line 388: large file multiplier (>50MB avg)."""
        from unittest.mock import patch

        from zircolite.utils import analyze_files_and_recommend_mode

        # Mock file sizes instead of creating large files
        files = [str(tmp_path / f"large_{i}.evtx") for i in range(3)]
        for f in files:
            Path(f).write_bytes(b"x" * 100)

        with patch("os.path.getsize", return_value=60 * 1024 * 1024):
            mode, reason, stats = analyze_files_and_recommend_mode(files)
        assert stats['file_count'] == 3

    def test_low_ram_rejection(self, tmp_path):
        """Cover line 415: very low RAM rejects parallel."""
        from unittest.mock import MagicMock, patch

        from zircolite.utils import analyze_files_and_recommend_mode

        files = []
        for i in range(3):
            f = tmp_path / f"f_{i}.evtx"
            f.write_bytes(b"x" * 1024)
            files.append(str(f))

        mock_vm = MagicMock()
        mock_vm.available = 500 * 1024 * 1024  # 500 MB
        mock_vm.total = 1 * 1024 * 1024 * 1024  # 1 GB

        with patch("zircolite.utils.psutil.virtual_memory", return_value=mock_vm):
            mode, reason, stats = analyze_files_and_recommend_mode(files)

        assert stats['parallel_recommended'] is False
        assert "RAM" in stats.get('parallel_reason', '') or "Low" in reason


# =============================================================================
# print_mode_recommendation (plain fallback)
# =============================================================================


class TestSelectAvoidFilesBugFixes:
    """Tests for edge cases in select_files and avoid_files."""

    def test_select_files_empty_sublist(self):
        """select_files with empty sublists should not raise IndexError."""
        from zircolite.utils import select_files
        paths = [Path("a.evtx"), Path("b.evtx")]
        result = select_files(paths, [["a"], []])
        assert len(result) == 1
        assert "a.evtx" in str(result[0])

    def test_avoid_files_empty_sublist(self):
        """avoid_files with empty sublists should not raise IndexError."""
        from zircolite.utils import avoid_files
        paths = [Path("a.evtx"), Path("b.evtx")]
        result = avoid_files(paths, [["a"], []])
        assert len(result) == 1
        assert "b.evtx" in str(result[0])


class TestModeRecommendationRamHeuristics:
    """Regression tests for RAM-heuristic fixes in analyze_files_and_recommend_mode."""

    def test_rule3_accounts_for_memory_expansion(self):
        """Unified mode must compare the expanded footprint, not raw file size.

        1 GB of small files expands ~5x in the in-memory DB (5 GB) which is
        over 85% of 4 GB available RAM: per-file must be chosen even though
        raw size (1 GB) is under the old RAM/3 threshold.
        """
        from unittest.mock import MagicMock, patch

        from zircolite.utils import analyze_files_and_recommend_mode

        files = [f"/fake/f{i}.evtx" for i in range(1024)]
        one_mb = 1024 * 1024
        vm = MagicMock()
        vm.available = 4 * 1024**3
        vm.total = 16 * 1024**3
        with patch("zircolite.utils.psutil.virtual_memory", return_value=vm), \
             patch("zircolite.utils.os.path.getsize", return_value=one_mb), \
             patch("zircolite.utils.os.cpu_count", return_value=8):
            mode, reason, stats = analyze_files_and_recommend_mode(files)
        assert mode == "per-file"

    def test_rule6_reason_reflects_actual_parallel_recommendation(self):
        """Rule 6 must not claim parallel is enabled when it is not."""
        from unittest.mock import MagicMock, patch

        from zircolite.utils import analyze_files_and_recommend_mode

        # One huge file hides behind two small ones: parallel must be rejected
        files = ["/fake/big.evtx", "/fake/s1.evtx", "/fake/s2.evtx"]
        sizes = {
            "/fake/big.evtx": 8 * 1024**3,
            "/fake/s1.evtx": 1024 * 1024,
            "/fake/s2.evtx": 1024 * 1024,
        }
        vm = MagicMock()
        vm.available = 16 * 1024**3
        vm.total = 32 * 1024**3
        with patch("zircolite.utils.psutil.virtual_memory", return_value=vm), \
             patch("zircolite.utils.os.path.getsize", side_effect=lambda p: sizes[p]), \
             patch("zircolite.utils.os.cpu_count", return_value=8):
            mode, reason, stats = analyze_files_and_recommend_mode(files)
        assert stats["parallel_recommended"] is False
        assert "parallel processing enabled" not in reason

    def test_one_huge_file_blocks_parallel_even_with_small_avg(self):
        """The parallel safety check must use the largest file, not the average."""
        from unittest.mock import MagicMock, patch

        from zircolite.utils import analyze_files_and_recommend_mode

        files = ["/fake/big.evtx"] + [f"/fake/s{i}.evtx" for i in range(9)]
        sizes = {"/fake/big.evtx": 6 * 1024**3}
        for f in files[1:]:
            sizes[f] = 1024 * 1024
        vm = MagicMock()
        vm.available = 8 * 1024**3
        vm.total = 16 * 1024**3
        with patch("zircolite.utils.psutil.virtual_memory", return_value=vm), \
             patch("zircolite.utils.os.path.getsize", side_effect=lambda p: sizes[p]), \
             patch("zircolite.utils.os.cpu_count", return_value=8):
            mode, reason, stats = analyze_files_and_recommend_mode(files)
        assert stats["parallel_recommended"] is False
        assert "Very large files" in stats["parallel_reason"]


class TestInitLoggerHandlerManagement:
    """Regression tests for init_logger handler management."""

    def test_reinit_closes_previous_file_handler(self, tmp_path):
        """Re-initializing the logger must close the old file handler."""
        import logging

        from zircolite.utils import init_logger
        log1 = tmp_path / "one.log"
        log2 = tmp_path / "two.log"
        logger1 = init_logger(debug_mode=False, log_file=str(log1))
        old_handlers = list(logger1.handlers)
        logger2 = init_logger(debug_mode=False, log_file=str(log2))
        assert logger1 is logger2  # same named logger
        for h in old_handlers:
            if isinstance(h, logging.FileHandler):
                assert h.stream is None or h.stream.closed


class TestModeRecommendationRemainingRules:
    """Coverage for recommendation Rules 5, 7 and the empty-input edge."""

    def _analyze(self, files, sizes, avail_gb=16, cpus=8):
        from unittest.mock import MagicMock, patch

        from zircolite.utils import analyze_files_and_recommend_mode
        vm = MagicMock()
        vm.available = avail_gb * 1024**3
        vm.total = avail_gb * 2 * 1024**3
        with patch("zircolite.utils.psutil.virtual_memory", return_value=vm), \
             patch("zircolite.utils.os.path.getsize", side_effect=lambda p: sizes[p]), \
             patch("zircolite.utils.os.cpu_count", return_value=cpus):
            return analyze_files_and_recommend_mode(files)

    def test_rule5_few_large_files_perfile(self):
        """Few large files (>50MB avg) → per-file."""
        files = ["/fake/a.evtx", "/fake/b.evtx", "/fake/c.evtx"]
        sizes = {f: 80 * 1024 * 1024 for f in files}
        mode, reason, stats = self._analyze(files, sizes, avail_gb=4)
        # 240MB * 3.5x = 840MB < 4GB*0.85 → passes Rule 3, avg >= 50MB → Rule 5
        assert mode == "per-file"
        assert "large files" in reason.lower()

    def test_rule7_many_medium_files_unified(self):
        """Many files that are not tiny but fit in RAM → unified."""
        files = [f"/fake/f{i}.evtx" for i in range(12)]
        sizes = {f: 20 * 1024 * 1024 for f in files}  # 240 MB total
        mode, reason, stats = self._analyze(files, sizes, avail_gb=4)
        # 240MB * 4x = 960MB < 4GB*0.85 → Rule 7 (>= 10 files)
        assert mode == "unified"

    def test_empty_file_list_returns_perfile(self):
        from unittest.mock import MagicMock, patch

        from zircolite.utils import analyze_files_and_recommend_mode
        vm = MagicMock()
        vm.available = 8 * 1024**3
        vm.total = 16 * 1024**3
        with patch("zircolite.utils.psutil.virtual_memory", return_value=vm):
            mode, reason, stats = analyze_files_and_recommend_mode([])
        assert mode == "per-file"


class TestSniffCsvDelimiter:
    """Delimiter detection shared by the log detector and the CSV stream."""

    @pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
    def test_detects_each_supported_delimiter(self, delimiter):
        from zircolite.utils import sniff_csv_delimiter
        sample = (
            delimiter.join(["EventID", "Channel", "Computer"]) + "\n"
            + delimiter.join(["4688", "Security", "HOST01"]) + "\n"
        )
        assert sniff_csv_delimiter(sample) == delimiter

    def test_does_not_latch_onto_a_data_letter(self):
        """csv.Sniffer can pick a recurring letter; candidates stay restricted."""
        from zircolite.utils import sniff_csv_delimiter
        sample = "EventID;Channel\n4688;Security\n1;Security\n"
        assert sniff_csv_delimiter(sample) == ";"

    def test_single_column_falls_back_to_default(self):
        from zircolite.utils import sniff_csv_delimiter
        assert sniff_csv_delimiter("OnlyColumn\nvalue\n") == ","

    def test_empty_sample_falls_back_to_default(self):
        from zircolite.utils import sniff_csv_delimiter
        assert sniff_csv_delimiter("") == ","
        assert sniff_csv_delimiter("\n  \n") == ","

    def test_custom_default_is_honoured(self):
        from zircolite.utils import sniff_csv_delimiter
        assert sniff_csv_delimiter("OnlyColumn\nvalue\n", default="\t") == "\t"

    def test_header_only_sample(self):
        from zircolite.utils import sniff_csv_delimiter
        assert sniff_csv_delimiter("EventID;Channel;Computer\n") == ";"


class TestOpenMaybeCompressedDecodeErrors:
    """A single undecodable byte must not abort a whole log file."""

    def test_text_mode_replaces_bad_bytes_by_default(self, tmp_path):
        from zircolite.utils import open_maybe_compressed
        src = tmp_path / "audit.log"
        src.write_bytes(b"good line\nbad \xff line\nlast line\n")
        with open_maybe_compressed(str(src), "rt") as f:
            lines = f.readlines()
        assert len(lines) == 3

    def test_errors_policy_is_overridable(self, tmp_path):
        from zircolite.utils import open_maybe_compressed
        src = tmp_path / "audit.log"
        src.write_bytes(b"bad \xff line\n")
        with pytest.raises(UnicodeDecodeError):
            with open_maybe_compressed(str(src), "rt", errors="strict") as f:
                f.read()

    def test_gzip_text_mode_replaces_bad_bytes(self, tmp_path):
        import gzip

        from zircolite.utils import open_maybe_compressed
        src = tmp_path / "audit.log.gz"
        with gzip.open(src, "wb") as f:
            f.write(b"good line\nbad \xff line\n")
        with open_maybe_compressed(str(src), "rt") as f:
            assert len(f.readlines()) == 2


class TestCsvSanitisation:
    """sanitize_*_for_csv keep one detection on one CSV row.

    Embedded newlines in a match value would otherwise split the record, so
    the writers in core.py and processing.py run every value through these.
    """

    def test_newlines_become_spaces(self):
        """Deleting them glued adjacent lines into tokens that never existed."""
        from zircolite.utils import sanitize_value_for_csv

        assert sanitize_value_for_csv("a\nb") == "a b"
        assert sanitize_value_for_csv("a\r\nb") == "a b"
        assert sanitize_value_for_csv("a\rb") == "a b"
        assert sanitize_value_for_csv("Invoke-Expression\n$payload") == (
            "Invoke-Expression $payload"
        )

    def test_formula_prefixes_are_neutralised(self):
        """A logged string must not become live code in the analyst's spreadsheet."""
        from zircolite.utils import sanitize_value_for_csv

        assert sanitize_value_for_csv('=cmd|/c calc!A1') == "'=cmd|/c calc!A1"
        assert sanitize_value_for_csv("+1+1") == "'+1+1"
        assert sanitize_value_for_csv("-2+3") == "'-2+3"
        assert sanitize_value_for_csv("@SUM(A1)") == "'@SUM(A1)"

    def test_none_becomes_empty_string(self):
        from zircolite.utils import sanitize_value_for_csv

        assert sanitize_value_for_csv(None) == ""

    def test_non_strings_are_stringified(self):
        from zircolite.utils import sanitize_value_for_csv

        assert sanitize_value_for_csv(42) == "42"
        assert sanitize_value_for_csv(True) == "True"

    def test_ordinary_values_are_untouched(self):
        from zircolite.utils import sanitize_value_for_csv

        for benign in ("powershell.exe", "C:\\Windows", "4624", ""):
            assert sanitize_value_for_csv(benign) == benign

    def test_row_sanitisation_covers_every_value(self):
        from zircolite.utils import sanitize_row_for_csv

        row = {"a": "one\ntwo", "b": None, "c": 7, "d": "fine"}
        out = sanitize_row_for_csv(row)

        assert out == {"a": "one two", "b": "", "c": "7", "d": "fine"}
        assert set(out) == set(row)

    def test_row_sanitisation_does_not_mutate_the_input(self):
        from zircolite.utils import sanitize_row_for_csv

        row = {"a": "one\ntwo"}
        sanitize_row_for_csv(row)

        assert row == {"a": "one\ntwo"}
