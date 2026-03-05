"""
Tests for the EvtxExtractor class.
"""

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
        """Test that when provided directory already exists, it is used."""
        existing_dir = tmp_path / "existing"
        existing_dir.mkdir()
        
        config = ExtractorConfig(tmp_dir=str(existing_dir))
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        
        assert extractor.tmpDir == str(existing_dir)
        assert Path(existing_dir).exists()
        
        extractor.cleanup()

    def test_init_when_tmp_dir_path_is_file_uses_random_dir(self, tmp_path, test_logger):
        """When tmp_dir path exists and is not a directory, use a random tmp dir."""
        file_path = tmp_path / "a_file"
        file_path.write_text("not a dir")
        config = ExtractorConfig(tmp_dir=str(file_path))
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        assert extractor.tmpDir != str(file_path)
        assert "tmp-" in extractor.tmpDir
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


class TestRandomSuffix:
    """Tests for random_suffix (used by extractor and others)."""

    def test_random_suffix_length(self):
        """Test that random_suffix(8) generates 8 character strings."""
        from zircolite.utils import random_suffix
        random_str = random_suffix(8)
        assert len(random_str) == 8

    def test_random_suffix_unique(self):
        """Test that random_suffix generates unique strings."""
        from zircolite.utils import random_suffix
        strings = [random_suffix(8) for _ in range(100)]
        assert len(set(strings)) == 100

    def test_random_suffix_alphanumeric(self):
        """Test that random_suffix uses only alphanumeric characters."""
        from zircolite.utils import random_suffix
        random_str = random_suffix(8)
        assert random_str.isalnum()


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


@pytest.mark.requires_lxml
class TestEvtxExtractorXmlConversion:
    """Tests for XML log conversion."""

    def test_xml_to_dict(self, test_logger):
        """Test XML to dictionary conversion."""
        from lxml import etree

        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        xml_str = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID>1</EventID>
                <Channel>Test</Channel>
                <TimeCreated SystemTime="2024-06-15T10:30:00.000Z"/>
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
        assert 'TimeCreated' in result['Event']['System']
        assert result['Event']['System']['TimeCreated'] == {"#attributes": {"SystemTime": "2024-06-15T10:30:00.000Z"}}

        extractor.cleanup()

    def test_xml_to_dict_multiple_eventdata_fields(self, test_logger):
        """xml_to_dict merges multiple EventData Data elements into one dict."""
        from lxml import etree

        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        xml_str = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System><EventID>2</EventID></System>
            <EventData>
                <Data Name="CommandLine">cmd.exe</Data>
                <Data Name="Image">C:\\cmd.exe</Data>
                <Data Name="ParentCommandLine">explorer.exe</Data>
            </EventData>
        </Event>'''
        root = etree.fromstring(xml_str)
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

        result = extractor.xml_to_dict(root, ns)

        event_data = result['Event']['EventData']
        assert event_data['CommandLine'] == 'cmd.exe'
        assert event_data['Image'] == 'C:\\cmd.exe'
        assert event_data['ParentCommandLine'] == 'explorer.exe'
        assert len(event_data) == 3

        extractor.cleanup()

    def test_xml_line_to_json(self, test_logger, sample_xml_event):
        """Test XML line to JSON conversion."""
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        result = extractor.xml_line_to_json(sample_xml_event)

        assert result is not None
        assert 'Event' in result

        extractor.cleanup()

    def test_xml_line_to_json_invalid(self, test_logger):
        """Test handling of invalid XML."""
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        result = extractor.xml_line_to_json("not xml at all")

        assert result is None
        extractor.cleanup()

    def test_xml_line_to_json_malformed_triggers_exception_path(self, test_logger):
        """When XML contains <Event but is malformed, exception is caught and returns None."""
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        result = extractor.xml_line_to_json('<Event ><System><EventID>1</System></Event>')
        assert result is None
        extractor.cleanup()


@pytest.mark.requires_lxml
class TestEvtxExtractorSysmonLinux:
    """Tests for Sysmon for Linux log conversion."""

    def test_sysmon_xml_line_to_json(self, test_logger):
        """Test Sysmon XML line to JSON conversion."""
        config = ExtractorConfig(sysmon4linux=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        sysmon_line = 'Jan 15 10:30:00 host sysmon: <Event><EventData><Data Name="Image">/usr/bin/bash</Data></EventData></Event>'

        result = extractor.sysmon_xml_line_to_json(sysmon_line)

        assert result is not None
        assert 'Event' in result

        extractor.cleanup()

    def test_sysmon_xml_line_to_json_malformed_returns_none(self, test_logger):
        """When Sysmon XML line is malformed, exception is caught and returns None."""
        config = ExtractorConfig(sysmon4linux=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        result = extractor.sysmon_xml_line_to_json('Jan 15 10:30:00 host sysmon: <Event><System>unclosed')
        assert result is None
        extractor.cleanup()

    def test_sysmon_xml_line_no_event(self, test_logger):
        """Test handling of lines without Event tag."""
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
    
    @pytest.mark.requires_lxml
    def test_run_xml_input(self, tmp_xml_file, test_logger):
        """Test run method with XML input."""
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
    
    @pytest.mark.requires_evtx
    def test_run_using_bindings_with_real_evtx(self, test_logger):
        """Test EVTX processing with real EVTX file (Sigma regression sample)."""
        # Sample from SigmaHQ/sigma regression_data: proc_creation_win_bitsadmin_download
        sample_evtx = Path(__file__).parent / "fixtures" / "sample_bitsadmin.evtx"
        if not sample_evtx.exists():
            pytest.skip("No sample EVTX file available (tests/fixtures/sample_bitsadmin.evtx)")
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
        
        # Invalid input should not produce JSON output
        json_files = list(Path(extractor.tmpDir).glob("*.json"))
        assert len(json_files) == 0
        
        extractor.cleanup()


@pytest.mark.requires_lxml
class TestEvtxExtractorEvtxtract:
    """Tests for EVTXtract log conversion."""

    def test_evtxtract_to_json(self, tmp_path, test_logger):
        """Test EVTXtract log conversion."""
        
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


class TestExtractorBugFixes:
    """Tests verifying specific bug fixes in the extractor."""

    def test_auditd_attribute_with_equals_in_value(self, tmp_path):
        """Auditd attributes with '=' in the value should not be truncated."""
        extractor = EvtxExtractor(
            ExtractorConfig(tmp_dir=str(tmp_path / "tmp"), auditd_logs=True)
        )
        line = 'type=EXECVE msg=audit(1600000000.123:456): argc=1 a0=ls key=user=admin'
        event = extractor.auditd_line_to_json(line)
        assert event.get("key") == "user=admin"
        extractor.cleanup()

    def test_get_time_malformed_returns_empty(self, tmp_path):
        """get_time returns empty string on malformed auditd timestamp."""
        extractor = EvtxExtractor(
            ExtractorConfig(tmp_dir=str(tmp_path / "tmp"))
        )
        result = extractor.get_time("msg=audit():")
        assert result == ""
        extractor.cleanup()

    def test_cleanup_missing_dir_no_error(self, tmp_path):
        """cleanup() does not raise if tmpDir was already removed."""
        extractor = EvtxExtractor(
            ExtractorConfig(tmp_dir=str(tmp_path / "tmp"))
        )
        import shutil
        shutil.rmtree(extractor.tmpDir)
        extractor.cleanup()
