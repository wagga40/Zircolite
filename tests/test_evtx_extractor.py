"""
Tests for the EvtxExtractor class.
"""

import importlib.util
import json
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import EvtxExtractor, ExtractorConfig


class TestEvtxExtractorInit:
    """Tests for EvtxExtractor initialization."""
    
    def test_init_creates_tmp_dir(self, test_logger):
        """Test that initialization creates a temporary directory."""
        extractor = EvtxExtractor(logger=test_logger)
        
        assert Path(extractor.tmpDir).exists()
        assert extractor.tmpDir.startswith("tmp-")
        
        extractor.cleanup()
    
    def test_init_with_provided_tmpdir(self, tmp_path, test_logger):
        """Test initialization with a custom temp directory."""
        custom_dir = str(tmp_path / "custom_tmp")
        
        config = ExtractorConfig(tmp_dir=custom_dir)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        assert extractor.tmpDir == custom_dir
        assert Path(custom_dir).exists()
        
        extractor.cleanup()
    
    def test_init_handles_existing_directory(self, tmp_path, test_logger):
        """Test handling when provided directory already exists."""
        existing_dir = tmp_path / "existing"
        existing_dir.mkdir()
        
        config = ExtractorConfig(tmp_dir=str(existing_dir))
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        # When directory exists, should use a different random directory name
        assert extractor.tmpDir != str(existing_dir)
        # The new tmpDir starts with 'tmp-'
        assert extractor.tmpDir.startswith("tmp-")
        
        # Create the directory for cleanup to work (the constructor errors but doesn't create it)
        if not Path(extractor.tmpDir).exists():
            Path(extractor.tmpDir).mkdir(exist_ok=True)
        
        extractor.cleanup()
    
    def test_init_sysmon_linux_mode(self, test_logger):
        """Test initialization for Sysmon for Linux logs."""
        config = ExtractorConfig(sysmon4linux=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        assert extractor.sysmon4linux is True
        assert extractor.encoding == "ISO-8859-1"
        
        extractor.cleanup()
    
    def test_init_auditd_mode(self, test_logger):
        """Test initialization for Auditd logs."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        assert extractor.auditdLogs is True
        assert extractor.encoding == "utf-8"
        
        extractor.cleanup()
    
    def test_init_xml_mode(self, test_logger):
        """Test initialization for XML logs."""
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        assert extractor.xmlLogs is True
        assert extractor.encoding == "utf-8"
        
        extractor.cleanup()
    
    def test_init_csv_mode(self, test_logger):
        """Test initialization for CSV input."""
        config = ExtractorConfig(csv_input=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        assert extractor.csvInput is True
        
        extractor.cleanup()
    
    def test_init_custom_encoding(self, test_logger):
        """Test initialization with custom encoding."""
        config = ExtractorConfig(sysmon4linux=True, encoding="utf-16")
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        assert extractor.encoding == "utf-16"
        
        extractor.cleanup()


class TestEvtxExtractorRandString:
    """Tests for random string generation."""
    
    def test_rand_string_length(self, test_logger):
        """Test that rand_string generates 8 character strings."""
        extractor = EvtxExtractor(logger=test_logger)
        
        random_str = extractor.rand_string()
        
        assert len(random_str) == 8
        extractor.cleanup()
    
    def test_rand_string_unique(self, test_logger):
        """Test that rand_string generates unique strings."""
        extractor = EvtxExtractor(logger=test_logger)
        
        strings = [extractor.rand_string() for _ in range(100)]
        unique_strings = set(strings)
        
        # All should be unique (with very high probability)
        assert len(unique_strings) == 100
        extractor.cleanup()
    
    def test_rand_string_alphanumeric(self, test_logger):
        """Test that rand_string uses only alphanumeric characters."""
        extractor = EvtxExtractor(logger=test_logger)
        
        random_str = extractor.rand_string()
        
        assert random_str.isalnum()
        extractor.cleanup()


class TestEvtxExtractorAuditdConversion:
    """Tests for Auditd log conversion."""
    
    def test_get_time(self, test_logger):
        """Test timestamp extraction from auditd log."""
        extractor = EvtxExtractor(logger=test_logger)
        
        audit_time = "msg=audit(1705318200.123:456):"
        result = extractor.get_time(audit_time)
        
        # Should be a valid timestamp string
        assert len(result) == 19  # YYYY-MM-DD HH:MM:SS format
        extractor.cleanup()
    
    def test_auditd_line_to_json_basic(self, test_logger):
        """Test basic Auditd line conversion."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        line = 'type=SYSCALL msg=audit(1705318200.123:456): arch=c000003e syscall=59 success=yes exit=0 pid=5678 uid=0 comm="bash" exe="/bin/bash"'
        
        result = extractor.auditd_line_to_json(line)
        
        assert result is not None
        assert 'type' in result
        assert result['type'] == 'SYSCALL'
        assert 'timestamp' in result
        assert 'pid' in result
        assert result['pid'] == '5678'
        
        extractor.cleanup()
    
    def test_auditd_line_to_json_adds_offline_host(self, test_logger):
        """Test that missing host is set to 'offline'."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        line = 'type=SYSCALL msg=audit(1705318200.123:456): pid=5678'
        
        result = extractor.auditd_line_to_json(line)
        
        assert result['host'] == 'offline'
        extractor.cleanup()
    
    def test_auditd_line_to_json_removes_special_chars(self, test_logger):
        """Test that special characters (GS) are handled."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        # Include GS character (0x1D) in line
        line = 'type=SYSCALL msg=audit(1705318200.123:456): comm="bash"\x1dcomm_enriched="Bourne Again Shell"'
        
        result = extractor.auditd_line_to_json(line)
        
        # Should process without error
        assert result is not None
        extractor.cleanup()


class TestEvtxExtractorCsvConversion:
    """Tests for CSV log conversion."""
    
    def test_csv_to_json(self, tmp_csv_file, test_logger):
        """Test CSV to JSON conversion."""
        config = ExtractorConfig(csv_input=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        output_file = str(Path(extractor.tmpDir) / "output.json")
        extractor.csv_to_json(tmp_csv_file, output_file)
        
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            lines = f.readlines()
        
        assert len(lines) >= 1
        
        # Verify JSON structure
        first_event = json.loads(lines[0])
        assert 'EventID' in first_event
        
        extractor.cleanup()


class TestEvtxExtractorXmlConversion:
    """Tests for XML log conversion."""
    
    @pytest.mark.skipif(
        'lxml' not in sys.modules,
        reason="lxml not installed"
    )
    def test_xml_to_dict(self, test_logger):
        """Test XML to dictionary conversion."""
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        try:
            from lxml import etree
        except ImportError:
            pytest.skip("lxml not available")
        
        xml_str = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID>1</EventID>
                <Channel>Test</Channel>
            </System>
            <EventData>
                <Data Name="CommandLine">test.exe</Data>
            </EventData>
        </Event>'''
        
        root = etree.fromstring(xml_str)
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
        
        result = extractor.xml_to_dict(root, ns)
        
        assert 'Event' in result
        assert 'System' in result['Event']
        
        extractor.cleanup()
    
    @pytest.mark.skipif(
        'lxml' not in sys.modules,
        reason="lxml not installed"
    )
    def test_xml_line_to_json(self, test_logger, sample_xml_event):
        """Test XML line to JSON conversion."""
        if importlib.util.find_spec("lxml") is None:
            pytest.skip("lxml not available")
        
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        result = extractor.xml_line_to_json(sample_xml_event)
        
        assert result is not None
        assert 'Event' in result
        
        extractor.cleanup()
    
    @pytest.mark.skipif(
        'lxml' not in sys.modules,
        reason="lxml not installed"
    )
    def test_xml_line_to_json_invalid(self, test_logger):
        """Test handling of invalid XML."""
        if importlib.util.find_spec("lxml") is None:
            pytest.skip("lxml not available")
        
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        result = extractor.xml_line_to_json("not xml at all")
        
        assert result is None
        extractor.cleanup()


class TestEvtxExtractorSysmonLinux:
    """Tests for Sysmon for Linux log conversion."""
    
    @pytest.mark.skipif(
        'lxml' not in sys.modules,
        reason="lxml not installed"
    )
    def test_sysmon_xml_line_to_json(self, test_logger):
        """Test Sysmon XML line to JSON conversion."""
        if importlib.util.find_spec("lxml") is None:
            pytest.skip("lxml not available")
        
        config = ExtractorConfig(sysmon4linux=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        sysmon_line = 'Jan 15 10:30:00 host sysmon: <Event><EventData><Data Name="Image">/usr/bin/bash</Data></EventData></Event>'
        
        result = extractor.sysmon_xml_line_to_json(sysmon_line)
        
        assert result is not None
        assert 'Event' in result
        
        extractor.cleanup()
    
    @pytest.mark.skipif(
        'lxml' not in sys.modules,
        reason="lxml not installed"
    )
    def test_sysmon_xml_line_no_event(self, test_logger):
        """Test handling of lines without Event tag."""
        if importlib.util.find_spec("lxml") is None:
            pytest.skip("lxml not available")
        
        config = ExtractorConfig(sysmon4linux=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        result = extractor.sysmon_xml_line_to_json("just a regular log line")
        
        assert result is None
        extractor.cleanup()


class TestEvtxExtractorLogsToJson:
    """Tests for logs_to_json method."""
    
    def test_logs_to_json_from_file(self, tmp_auditd_file, test_logger):
        """Test converting logs from file."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        output_file = str(Path(extractor.tmpDir) / "output.json")
        extractor.logs_to_json(
            extractor.auditd_line_to_json,
            tmp_auditd_file,
            output_file,
            is_file=True
        )
        
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            lines = f.readlines()
        
        assert len(lines) >= 1
        extractor.cleanup()
    
    def test_logs_to_json_from_string(self, test_logger):
        """Test converting logs from string data."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        data = """type=SYSCALL msg=audit(1705318200.123:456): pid=1
type=SYSCALL msg=audit(1705318201.456:457): pid=2"""
        
        output_file = str(Path(extractor.tmpDir) / "output.json")
        extractor.logs_to_json(
            extractor.auditd_line_to_json,
            data,
            output_file,
            is_file=False
        )
        
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            lines = f.readlines()
        
        assert len(lines) == 2
        extractor.cleanup()


class TestEvtxExtractorRun:
    """Tests for the run method."""
    
    def test_run_csv_input(self, tmp_csv_file, test_logger):
        """Test run method with CSV input."""
        config = ExtractorConfig(csv_input=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        extractor.run(tmp_csv_file)
        
        # Should have created JSON file
        json_files = list(Path(extractor.tmpDir).glob("*.json"))
        assert len(json_files) == 1
        
        extractor.cleanup()
    
    def test_run_auditd_input(self, tmp_auditd_file, test_logger):
        """Test run method with Auditd input."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        extractor.run(tmp_auditd_file)
        
        json_files = list(Path(extractor.tmpDir).glob("*.json"))
        assert len(json_files) == 1
        
        extractor.cleanup()
    
    @pytest.mark.skipif(
        'lxml' not in sys.modules,
        reason="lxml not installed"
    )
    def test_run_xml_input(self, tmp_xml_file, test_logger):
        """Test run method with XML input."""
        if importlib.util.find_spec("lxml") is None:
            pytest.skip("lxml not available")
        
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        extractor.run(tmp_xml_file)
        
        json_files = list(Path(extractor.tmpDir).glob("*.json"))
        assert len(json_files) == 1
        
        extractor.cleanup()


class TestEvtxExtractorCleanup:
    """Tests for cleanup functionality."""
    
    def test_cleanup_removes_tmpdir(self, test_logger):
        """Test that cleanup removes temporary directory."""
        extractor = EvtxExtractor(logger=test_logger)
        
        tmp_dir = extractor.tmpDir
        assert Path(tmp_dir).exists()
        
        extractor.cleanup()
        
        assert not Path(tmp_dir).exists()
    
    def test_cleanup_with_files(self, test_logger):
        """Test cleanup with files in temp directory."""
        extractor = EvtxExtractor(logger=test_logger)
        
        # Create some files
        (Path(extractor.tmpDir) / "test1.json").touch()
        (Path(extractor.tmpDir) / "test2.json").touch()
        
        tmp_dir = extractor.tmpDir
        extractor.cleanup()
        
        assert not Path(tmp_dir).exists()


class TestEvtxExtractorEvtxBinding:
    """Tests for EVTX Python binding functionality."""
    
    @pytest.mark.skipif(
        'evtx' not in sys.modules,
        reason="evtx (PyEvtxParser) not installed"
    )
    def test_run_using_bindings_with_real_evtx(self, test_logger):
        """Test EVTX processing with real EVTX file if available."""
        # Check if sample EVTX exists
        sample_evtx = Path("build/LINUX-ARM64-GLIBC/sample.evtx")
        if not sample_evtx.exists():
            pytest.skip("No sample EVTX file available")
        
        if importlib.util.find_spec("evtx") is None:
            pytest.skip("evtx not available")
        
        extractor = EvtxExtractor(logger=test_logger)
        
        extractor.run_using_bindings(str(sample_evtx))
        
        json_files = list(Path(extractor.tmpDir).glob("*.json"))
        assert len(json_files) == 1
        
        extractor.cleanup()
    
    def test_run_using_bindings_handles_errors(self, tmp_path, test_logger):
        """Test that run_using_bindings handles errors gracefully."""
        # Create an invalid EVTX file
        invalid_evtx = tmp_path / "invalid.evtx"
        invalid_evtx.write_text("not a valid EVTX file")
        
        extractor = EvtxExtractor(logger=test_logger)
        
        # Should not raise exception
        extractor.run_using_bindings(str(invalid_evtx))
        
        extractor.cleanup()


class TestEvtxExtractorEvtxtract:
    """Tests for EVTXtract log conversion."""
    
    @pytest.mark.skipif(
        'lxml' not in sys.modules,
        reason="lxml not installed"
    )
    def test_evtxtract_to_json(self, tmp_path, test_logger):
        """Test EVTXtract log conversion."""
        if importlib.util.find_spec("lxml") is None:
            pytest.skip("lxml not available")
        
        # Create sample EVTXtract output
        evtxtract_content = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <EventID>1</EventID>
    </System>
    <EventData>
        <Data Name="CommandLine">test.exe</Data>
    </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <EventID>2</EventID>
    </System>
</Event>'''
        
        evtxtract_file = tmp_path / "evtxtract.log"
        evtxtract_file.write_text(evtxtract_content)
        
        config = ExtractorConfig(evtxtract=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        output_file = str(Path(extractor.tmpDir) / "output.json")
        extractor.evtxtract_to_json(str(evtxtract_file), output_file)
        
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            lines = f.readlines()
        
        assert len(lines) == 2
        extractor.cleanup()
