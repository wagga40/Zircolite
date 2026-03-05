"""Tests for compressed / archived file input support (Feature 1)."""

import gzip
import bz2
import importlib.util
import json
import zipfile
import pytest

from zircolite.utils import (
    ARCHIVE_PASSWORD_ERROR_MESSAGE,
    COMPRESSED_SUFFIXES,
    open_maybe_compressed,
)


_HAS_PY7ZR = importlib.util.find_spec("py7zr") is not None


# =============================================================================
# Unit tests for open_maybe_compressed()
# =============================================================================

class TestOpenMaybeCompressed:
    """Unit tests for open_maybe_compressed()."""

    # ---- plain files ----

    def test_plain_file_binary(self, tmp_path):
        p = tmp_path / "plain.bin"
        p.write_bytes(b"hello world")
        with open_maybe_compressed(p) as f:
            assert f.read() == b"hello world"

    def test_plain_file_text(self, tmp_path):
        p = tmp_path / "plain.txt"
        p.write_text("hello\n", encoding="utf-8")
        with open_maybe_compressed(p, 'rt') as f:
            assert f.read() == "hello\n"

    # ---- gz ----

    def test_gz_binary(self, tmp_path):
        p = tmp_path / "data.json.gz"
        data = b'{"key": "value"}'
        with gzip.open(p, 'wb') as f:
            f.write(data)
        with open_maybe_compressed(p) as f:
            assert f.read() == data

    def test_gz_text(self, tmp_path):
        p = tmp_path / "data.log.gz"
        text = "line one\nline two\n"
        with gzip.open(p, 'wt', encoding="utf-8") as f:
            f.write(text)
        with open_maybe_compressed(p, 'rt') as f:
            assert f.read() == text

    # ---- bz2 ----

    def test_bz2_binary(self, tmp_path):
        p = tmp_path / "data.json.bz2"
        data = b'{"key": "value"}'
        with bz2.open(p, 'wb') as f:
            f.write(data)
        with open_maybe_compressed(p) as f:
            assert f.read() == data

    def test_bz2_text(self, tmp_path):
        p = tmp_path / "data.log.bz2"
        text = "auditd line one\n"
        with bz2.open(p, 'wt', encoding="utf-8") as f:
            f.write(text)
        with open_maybe_compressed(p, 'rt') as f:
            assert f.read() == text

    # ---- zip (no password) ----

    def test_zip_binary(self, tmp_path):
        p = tmp_path / "data.json.zip"
        data = b'{"key": "value"}'
        with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.json", data)
        with open_maybe_compressed(p) as f:
            assert f.read() == data

    def test_zip_text(self, tmp_path):
        p = tmp_path / "data.log.zip"
        text = "event line one\n"
        with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.log", text.encode("utf-8"))
        with open_maybe_compressed(p, 'rt') as f:
            assert f.read() == text

    def test_zip_with_password(self, tmp_path):
        p = tmp_path / "secure.json.zip"
        data = b'{"secret": true}'
        with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.setpassword(b"hunter2")
            zf.writestr(zipfile.ZipInfo("data.json"), data, zipfile.ZIP_DEFLATED)
        with open_maybe_compressed(p, password="hunter2") as f:
            assert f.read() == data

    def test_zip_with_password_bytes(self, tmp_path):
        p = tmp_path / "secure2.json.zip"
        data = b'{"secret": 42}'
        with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.setpassword(b"pass123")
            zf.writestr(zipfile.ZipInfo("data.json"), data, zipfile.ZIP_DEFLATED)
        with open_maybe_compressed(p, password=b"pass123") as f:
            assert f.read() == data

    def test_zip_multi_file_raises(self, tmp_path):
        """Archives with more than one member are rejected."""
        p = tmp_path / "multi.zip"
        with zipfile.ZipFile(p, 'w') as zf:
            zf.writestr("a.json", b'{}')
            zf.writestr("b.json", b'{}')
        with pytest.raises(ValueError, match="2 files"):
            open_maybe_compressed(p)

    def test_zip_empty_raises(self, tmp_path):
        p = tmp_path / "empty.zip"
        with zipfile.ZipFile(p, 'w'):
            pass
        with pytest.raises(ValueError, match="no files"):
            open_maybe_compressed(p)

    # ---- 7z (no password) ----

    @pytest.mark.requires_py7zr
    @pytest.mark.skipif(not _HAS_PY7ZR, reason="py7zr not installed")
    def test_7z_binary(self, tmp_path):
        import py7zr
        p = tmp_path / "data.json.7z"
        data = b'{"key": "value"}'
        with py7zr.SevenZipFile(p, 'w') as szf:
            szf.writestr(data, "data.json")
        with open_maybe_compressed(p) as f:
            assert f.read() == data

    @pytest.mark.requires_py7zr
    @pytest.mark.skipif(not _HAS_PY7ZR, reason="py7zr not installed")
    def test_7z_text(self, tmp_path):
        import py7zr
        p = tmp_path / "data.log.7z"
        text = "event line\n"
        with py7zr.SevenZipFile(p, 'w') as szf:
            szf.writestr(text.encode("utf-8"), "data.log")
        with open_maybe_compressed(p, 'rt') as f:
            assert f.read() == text

    @pytest.mark.requires_py7zr
    @pytest.mark.skipif(not _HAS_PY7ZR, reason="py7zr not installed")
    def test_7z_with_password(self, tmp_path):
        import py7zr
        p = tmp_path / "secure.json.7z"
        data = b'{"secret": true}'
        with py7zr.SevenZipFile(p, 'w', password="hunter2") as szf:
            szf.writestr(data, "data.json")
        with open_maybe_compressed(p, password="hunter2") as f:
            assert f.read() == data

    @pytest.mark.requires_py7zr
    @pytest.mark.skipif(not _HAS_PY7ZR, reason="py7zr not installed")
    def test_7z_wrong_password_raises_value_error(self, tmp_path):
        """Opening a password-protected .7z with wrong password raises ValueError with a clear message."""
        import py7zr
        p = tmp_path / "secure.json.7z"
        with py7zr.SevenZipFile(p, 'w', password="correct") as szf:
            szf.writestr(b'{"x": 1}', "data.json")
        with pytest.raises(ValueError, match=ARCHIVE_PASSWORD_ERROR_MESSAGE):
            open_maybe_compressed(p, password="wrong")

    def test_7z_missing_package_raises_importerror(self, tmp_path, monkeypatch):
        """Opening a .7z without py7zr installed raises ImportError."""
        import sys
        # Setting the module entry to None is the only reliable way to block
        # re-import when the package is actually installed on the system.
        monkeypatch.setitem(sys.modules, "py7zr", None)
        p = tmp_path / "data.7z"
        p.write_bytes(b"\x37\x7a\xbc\xaf\x27\x1c")  # 7z magic bytes
        with pytest.raises(ImportError):
            open_maybe_compressed(p)


# =============================================================================
# Integration tests: stream JSON events from compressed/archived files
# =============================================================================

class TestStreamingWithCompressedJSON:
    """Integration tests: stream JSON events from compressed files."""

    def test_stream_jsonl_gz(self, tmp_path, field_mappings_file, test_logger):
        from zircolite.config import ProcessingConfig
        from zircolite.core import ZircoliteCore

        events = [
            {"EventID": "4688", "CommandLine": "powershell.exe"},
            {"EventID": "4624", "CommandLine": "cmd.exe"},
        ]
        gz_file = tmp_path / "events.json.gz"
        with gzip.open(gz_file, 'wt', encoding='utf-8') as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

        cfg = ProcessingConfig(no_output=True)
        core = ZircoliteCore(field_mappings_file, cfg, logger=test_logger)
        total = core.run_streaming([str(gz_file)], input_type='json')
        assert total == 2
        core.close()

    def test_stream_jsonl_bz2(self, tmp_path, field_mappings_file, test_logger):
        from zircolite.config import ProcessingConfig
        from zircolite.core import ZircoliteCore

        events = [{"EventID": "4688", "CommandLine": "notepad.exe"}]
        bz2_file = tmp_path / "events.json.bz2"
        with bz2.open(bz2_file, 'wt', encoding='utf-8') as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

        cfg = ProcessingConfig(no_output=True)
        core = ZircoliteCore(field_mappings_file, cfg, logger=test_logger)
        total = core.run_streaming([str(bz2_file)], input_type='json')
        assert total == 1
        core.close()

    def test_stream_jsonl_zip(self, tmp_path, field_mappings_file, test_logger):
        from zircolite.config import ProcessingConfig
        from zircolite.core import ZircoliteCore

        events = [
            {"EventID": "4688", "CommandLine": "whoami.exe"},
            {"EventID": "4624", "CommandLine": "net.exe"},
        ]
        payload = "".join(json.dumps(ev) + "\n" for ev in events).encode("utf-8")
        zip_file = tmp_path / "events.json.zip"
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("events.json", payload)

        cfg = ProcessingConfig(no_output=True)
        core = ZircoliteCore(field_mappings_file, cfg, logger=test_logger)
        total = core.run_streaming([str(zip_file)], input_type='json')
        assert total == 2
        core.close()

    def test_stream_jsonl_zip_with_password(self, tmp_path, field_mappings_file, test_logger):
        from zircolite.config import ProcessingConfig
        from zircolite.core import ZircoliteCore

        events = [{"EventID": "4688", "CommandLine": "mimikatz.exe"}]
        payload = "".join(json.dumps(ev) + "\n" for ev in events).encode("utf-8")
        zip_file = tmp_path / "secure.json.zip"
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.setpassword(b"secret")
            zf.writestr(zipfile.ZipInfo("events.json"), payload, zipfile.ZIP_DEFLATED)

        cfg = ProcessingConfig(no_output=True, archive_password="secret")
        core = ZircoliteCore(field_mappings_file, cfg, logger=test_logger)
        total = core.run_streaming([str(zip_file)], input_type='json')
        assert total == 1
        core.close()

    @pytest.mark.requires_py7zr
    @pytest.mark.skipif(not _HAS_PY7ZR, reason="py7zr not installed")
    def test_stream_jsonl_7z(self, tmp_path, field_mappings_file, test_logger):
        import py7zr
        from zircolite.config import ProcessingConfig
        from zircolite.core import ZircoliteCore

        events = [{"EventID": "4688", "CommandLine": "calc.exe"}]
        payload = "".join(json.dumps(ev) + "\n" for ev in events).encode("utf-8")
        szf_file = tmp_path / "events.json.7z"
        with py7zr.SevenZipFile(szf_file, 'w') as szf:
            szf.writestr(payload, "events.json")

        cfg = ProcessingConfig(no_output=True)
        core = ZircoliteCore(field_mappings_file, cfg, logger=test_logger)
        total = core.run_streaming([str(szf_file)], input_type='json')
        assert total == 1
        core.close()

    @pytest.mark.requires_py7zr
    @pytest.mark.skipif(not _HAS_PY7ZR, reason="py7zr not installed")
    def test_stream_jsonl_7z_with_password(self, tmp_path, field_mappings_file, test_logger):
        import py7zr
        from zircolite.config import ProcessingConfig
        from zircolite.core import ZircoliteCore

        events = [{"EventID": "4688", "CommandLine": "secret.exe"}]
        payload = "".join(json.dumps(ev) + "\n" for ev in events).encode("utf-8")
        szf_file = tmp_path / "secure.json.7z"
        with py7zr.SevenZipFile(szf_file, 'w', password="pwd7z") as szf:
            szf.writestr(payload, "events.json")

        cfg = ProcessingConfig(no_output=True, archive_password="pwd7z")
        core = ZircoliteCore(field_mappings_file, cfg, logger=test_logger)
        total = core.run_streaming([str(szf_file)], input_type='json')
        assert total == 1
        core.close()


# =============================================================================
# Constants and detection tests
# =============================================================================

class TestCompressedConstants:
    """Test compressed-handling constants."""

    def test_compressed_suffixes_defined(self):
        """COMPRESSED_SUFFIXES contains expected archive/compression extensions."""
        assert COMPRESSED_SUFFIXES == frozenset(('.gz', '.bz2', '.zip', '.7z'))


# =============================================================================
# Detection tests: LogTypeDetector identifies content inside archives
# =============================================================================

class TestDetectorWithCompressedFiles:
    """Test that LogTypeDetector correctly identifies compressed log files."""

    def test_detect_json_gz(self, tmp_path):
        from zircolite.detector import LogTypeDetector

        events = [{"EventID": "4688", "CommandLine": "powershell.exe"}]
        gz_file = tmp_path / "events.json.gz"
        with gzip.open(gz_file, 'wt', encoding='utf-8') as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

        result = LogTypeDetector().detect(gz_file)
        assert result.input_type == "json"

    def test_detect_log_bz2(self, tmp_path):
        from zircolite.detector import LogTypeDetector

        bz2_file = tmp_path / "audit.log.bz2"
        log_line = (
            "type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e "
            "syscall=59 success=yes exit=0 pid=5678 uid=0 comm=\"bash\" exe=\"/bin/bash\"\n"
        )
        with bz2.open(bz2_file, 'wt', encoding='utf-8') as f:
            f.write(log_line * 5)

        result = LogTypeDetector().detect(bz2_file)
        assert result.input_type == "auditd"

    def test_detect_json_zip(self, tmp_path):
        from zircolite.detector import LogTypeDetector

        events = [{"EventID": "4688", "CommandLine": "cmd.exe"}]
        payload = "".join(json.dumps(ev) + "\n" for ev in events).encode("utf-8")
        zip_file = tmp_path / "events.json.zip"
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("events.json", payload)

        result = LogTypeDetector().detect(zip_file)
        assert result.input_type == "json"
