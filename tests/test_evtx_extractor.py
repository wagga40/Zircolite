"""
Tests for the EvtxExtractor class.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import EvtxExtractor, ExtractorConfig


class TestEvtxExtractorInit:
    """Tests for EvtxExtractor initialization."""





    def test_init_sysmon_linux_mode(self, test_logger):
        """Test initialization for Sysmon for Linux logs."""
        config = ExtractorConfig(sysmon4linux=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        assert extractor.encoding == "ISO-8859-1"


    def test_init_auditd_mode(self, test_logger):
        """Test initialization for Auditd logs."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        assert extractor.encoding == "utf-8"


    def test_init_xml_mode(self, test_logger):
        """Test initialization for XML logs."""
        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        assert extractor.encoding == "utf-8"



    def test_init_custom_encoding(self, test_logger):
        """Test initialization with custom encoding."""
        config = ExtractorConfig(sysmon4linux=True, encoding="utf-16")
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        assert extractor.encoding == "utf-16"



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


    def test_auditd_user_record_msg_payload_is_flattened(self, test_logger):
        """USER_* records carry key=value pairs inside msg='...'; they must stay queryable."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        line = (
            "type=USER_ACCT msg=audit(1571830893.700:361): pid=1735 uid=0 "
            "msg='op=PAM:accounting grantors=pam_permit acct=\"root\" "
            "exe=\"/usr/sbin/crond\" hostname=? addr=? terminal=cron res=success'"
        )

        result = extractor.auditd_line_to_json(line)

        assert result["op"] == "PAM:accounting"
        assert result["acct"] == "root"
        assert result["exe"] == "/usr/sbin/crond"
        assert result["res"] == "success"
        assert result["pid"] == "1735"


    def test_auditd_proctitle_with_equals_stays_intact(self, test_logger):
        """Quoted values that merely contain '=' (e.g. proctitle) must not be split."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        line = (
            "type=PROCTITLE msg=audit(1571830893.700:362): "
            "proctitle=\"java -Dfoo=bar -jar app.jar\""
        )

        result = extractor.auditd_line_to_json(line)

        assert result["proctitle"] == "java -Dfoo=bar -jar app.jar"


    def test_auditd_line_to_json_adds_offline_host(self, test_logger):
        """Test that missing host is set to 'offline'."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        line = 'type=SYSCALL msg=audit(1705318200.123:456): pid=5678'

        result = extractor.auditd_line_to_json(line)

        assert result['host'] == 'offline'

    def test_auditd_line_to_json_removes_special_chars(self, test_logger):
        """Test that special characters (GS) are handled."""
        config = ExtractorConfig(auditd_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        # Include GS character (0x1D) in line
        line = 'type=SYSCALL msg=audit(1705318200.123:456): comm="bash"\x1dcomm_enriched="Bourne Again Shell"'

        result = extractor.auditd_line_to_json(line)

        # Should process without error
        assert result is not None




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


    def test_xml_to_dict_keeps_text_of_an_element_with_attributes(self, test_logger):
        """Classic providers write <EventID Qualifiers="...">7045</EventID>.

        Regression: the attribute dict used to replace the text outright, so the
        event ended up with a Qualifiers field and no EventID at all, and every
        rule for a classic provider's event ID silently stopped matching.
        """
        from lxml import etree

        config = ExtractorConfig(xml_logs=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        xml_str = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID Qualifiers="16384">7045</EventID>
                <Channel>System</Channel>
            </System>
        </Event>'''

        root = etree.fromstring(xml_str)
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

        event_id = extractor.xml_to_dict(root, ns)['Event']['System']['EventID']
        assert event_id['#text'] == 7045
        assert event_id['#attributes'] == {"Qualifiers": "16384"}

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


    def test_sysmon_xml_line_to_json_malformed_returns_none(self, test_logger):
        """When Sysmon XML line is malformed, exception is caught and returns None."""
        config = ExtractorConfig(sysmon4linux=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)
        result = extractor.sysmon_xml_line_to_json('Jan 15 10:30:00 host sysmon: <Event><System>unclosed')
        assert result is None

    def test_sysmon_xml_line_no_event(self, test_logger):
        """Test handling of lines without Event tag."""
        config = ExtractorConfig(sysmon4linux=True)
        extractor = EvtxExtractor(extractor_config=config, logger=test_logger)

        result = extractor.sysmon_xml_line_to_json("just a regular log line")

        assert result is None










@pytest.mark.requires_lxml


class TestExtractorBugFixes:
    """Tests verifying specific bug fixes in the extractor."""

    def test_auditd_attribute_with_equals_in_value(self, tmp_path):
        """Auditd attributes with '=' in the value should not be truncated."""
        extractor = EvtxExtractor(
            ExtractorConfig(auditd_logs=True)
        )
        line = 'type=EXECVE msg=audit(1600000000.123:456): argc=1 a0=ls key=user=admin'
        event = extractor.auditd_line_to_json(line)
        assert event.get("key") == "user=admin"

    def test_get_time_malformed_returns_empty(self, tmp_path):
        """get_time returns empty string on malformed auditd timestamp."""
        extractor = EvtxExtractor(
            ExtractorConfig()
        )
        result = extractor.get_time("msg=audit():")
        assert result == ""




    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only TZ semantics")
    def test_get_time_is_utc_not_local(self, tmp_path, monkeypatch):
        """auditd epoch timestamps must render in UTC regardless of host TZ.

        Only reachable where ``time.tzset`` exists: Windows resolves the time
        zone at process start and offers no way to change it from the test.
        """
        import time as time_module
        monkeypatch.setenv("TZ", "America/New_York")
        time_module.tzset()
        try:
            extractor = EvtxExtractor(
                ExtractorConfig()
            )
            result = extractor.get_time("msg=audit(1705318200.123:456):")
            assert result == time_module.strftime(
                "%Y-%m-%d %H:%M:%S", time_module.gmtime(1705318200.123)
            )
        finally:
            monkeypatch.undo()
            time_module.tzset()

    def test_sysmon_xml_line_without_event_tag_returns_none(self, tmp_path):
        """A syslog line containing 'Event' but no '<Event>' must not crash."""
        extractor = EvtxExtractor(
            ExtractorConfig(sysmon4linux=True)
        )
        line = "Jan  1 00:00:00 host myapp: Event something happened"
        assert extractor.sysmon_xml_line_to_json(line) is None


class TestExtractorRobustness:
    """Regression tests for extractor robustness fixes."""

    def test_auditd_quoted_value_with_spaces_preserved(self, tmp_path):
        """Quoted auditd values containing spaces must not be truncated."""
        extractor = EvtxExtractor(
            ExtractorConfig(auditd_logs=True)
        )
        line = 'type=SYSCALL msg=audit(1600000000.123:456): comm="my proc" exe="/bin/my proc"'
        event = extractor.auditd_line_to_json(line)
        assert event.get("comm") == "my proc"
        assert event.get("exe") == "/bin/my proc"

    def test_auditd_quotes_inside_value_preserved(self, tmp_path):
        extractor = EvtxExtractor(
            ExtractorConfig(auditd_logs=True)
        )
        line = 'type=EXECVE msg=audit(1600000000.123:456): a0=sh a1=-c a2=echo "hi'
        event = extractor.auditd_line_to_json(line)
        # Unterminated quote: kept as-is (minus nothing), no crash
        assert event.get("a0") == "sh"


    def test_xml_to_dict_flattens_userdata(self, tmp_path):
        """UserData subtrees must be flattened, not dropped."""
        from lxml import etree
        extractor = EvtxExtractor(
            ExtractorConfig(xml_logs=True)
        )
        xml_str = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>1</EventID></System>"
            "<UserData><EventXML><Param1>value1</Param1></EventXML></UserData>"
            "</Event>"
        )
        root = etree.fromstring(xml_str)
        result = extractor.xml_to_dict(root, "{http://schemas.microsoft.com/win/2004/08/events/event}")
        assert result["Event"]["UserData"].get("Param1") == "value1"

    def test_xml_to_dict_eventdata_values_stay_strings(self, tmp_path):
        """EventData values must not be int-converted (EVTX/JSON parity)."""
        from lxml import etree
        extractor = EvtxExtractor(
            ExtractorConfig(xml_logs=True)
        )
        xml_str = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>5</EventID></System>"
            '<EventData><Data Name="ProcessId">010</Data></EventData>'
            "</Event>"
        )
        root = etree.fromstring(xml_str)
        result = extractor.xml_to_dict(root, "{http://schemas.microsoft.com/win/2004/08/events/event}")
        assert result["Event"]["EventData"]["ProcessId"] == "010"
        assert result["Event"]["System"]["EventID"] == 5  # System stays int

    def test_auditd_msg_audit_inside_a_value_is_not_a_timestamp(self):
        """The `msg=audit(` test must look at the key, not the whole pair.

        An EXECVE record can carry the literal text in an argument, e.g. a
        grep pattern. Matching on the pair dropped that argument and blanked
        the timestamp that had already been parsed.
        """
        extractor = EvtxExtractor(ExtractorConfig(auditd_logs=True))
        line = (
            'type=EXECVE msg=audit(1600000000.123:456): '
            'a0="grep" a1="msg=audit(" a2="/var/log/audit"'
        )
        event = extractor.auditd_line_to_json(line)

        assert event["a1"] == "msg=audit("
        assert event["a0"] == "grep"
        assert event["a2"] == "/var/log/audit"
        assert event["timestamp"] == "2020-09-13 12:26:40"

    def test_xml_unnamed_data_elements_are_all_kept(self):
        """`<Data>` without a Name attribute is common (e.g. SCM 7036).

        Keying them all on the missing attribute collapsed them into a single
        column named "None", so only the last value survived.
        """
        from lxml import etree
        extractor = EvtxExtractor(ExtractorConfig(xml_logs=True))
        xml_str = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>7036</EventID></System>"
            "<EventData><Data>Print Spooler</Data><Data>running</Data></EventData>"
            "</Event>"
        )
        root = etree.fromstring(xml_str)
        result = extractor.xml_to_dict(
            root, "{http://schemas.microsoft.com/win/2004/08/events/event}"
        )
        event_data = result["Event"]["EventData"]

        assert "None" not in event_data
        assert event_data["Data"] == ["Print Spooler", "running"]

    def test_xml_named_and_unnamed_data_coexist(self):
        from lxml import etree
        extractor = EvtxExtractor(ExtractorConfig(xml_logs=True))
        xml_str = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>1</EventID></System>"
            '<EventData><Data Name="Image">a.exe</Data><Data>extra</Data></EventData>'
            "</Event>"
        )
        root = etree.fromstring(xml_str)
        result = extractor.xml_to_dict(
            root, "{http://schemas.microsoft.com/win/2004/08/events/event}"
        )
        event_data = result["Event"]["EventData"]

        assert event_data["Image"] == "a.exe"
        assert event_data["Data"] == ["extra"]


