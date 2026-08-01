"""
Log line and XML conversion helpers for Zircolite.

This module contains the EvtxExtractor class, which turns individual raw log
lines or XML elements into event dictionaries. It is used by the streaming
processor for the formats that need conversion before flattening:
- Auditd log lines
- Sysmon for Linux log lines (syslog header + XML)
- XML events (EVTX exports, EVTXtract output)
"""

import contextlib
import logging
import re
import time
from typing import Any

from lxml import etree  # type: ignore[attr-defined]

from .config import ExtractorConfig

# auditd key=value pairs: values may be double/single-quoted (with spaces) or bare
_AUDITD_ATTR_RE = re.compile(r"([\w\[\].]+)=(\"[^\"]*\"|'[^']*'|\S*)")


class EvtxExtractor:
    """Convert raw log lines and XML events to event dictionaries."""

    def __init__(
        self,
        extractor_config: ExtractorConfig | None = None,
        *,
        logger: logging.Logger | None = None
    ):
        """
        Initialize EvtxExtractor.

        Args:
            extractor_config: Extractor configuration (uses defaults if None)
            logger: Logger instance (creates default if None)
        """
        cfg = extractor_config or ExtractorConfig()

        self.logger = logger or logging.getLogger(__name__)

        self.encoding = cfg.encoding

    def get_time(self, line: str) -> str:
        """Extract timestamp from auditd log line.

        auditd timestamps are epoch seconds (UTC); render them in UTC so results
        do not depend on the analysis machine's local timezone.
        """
        try:
            parts = line.replace("msg=audit(", "").replace("):", "").split(":")
            return time.strftime(
                "%Y-%m-%d %H:%M:%S", time.gmtime(float(parts[0]))
            )
        except (ValueError, IndexError, OSError):
            return ""

    def auditd_line_to_json(self, auditd_line: str) -> dict[str, Any]:
        """Convert auditd logs to JSON. Code from https://github.com/csark/audit2json."""
        event = {}
        # According to auditd specs https://github.com/linux-audit/audit-documentation/wiki/SPEC-Audit-Event-Enrichment
        # a GS ASCII character, 0x1D, will be inserted to separate original and translated fields
        # Best way to deal with it is to remove it.
        line = auditd_line.replace('\x1d', ' ')
        # Regex parsing preserves quoted values containing spaces and
        # embedded quotes
        for match in _AUDITD_ATTR_RE.finditer(line):
            key, value = match.group(1), match.group(2)
            # Test the key, not the whole pair: an EXECVE argument can contain
            # the literal text "msg=audit(" (a grep pattern, for instance) and
            # must not be mistaken for the record header.
            if key == "msg" and value.startswith("audit("):
                event['timestamp'] = self.get_time(match.group(0))
                continue
            # Strip only the surrounding quotes, not quotes inside the value
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            if key == "msg" and "=" in value:
                # USER_* records carry an enriched key=value payload in
                # msg='...'; flatten it so fields like acct/exe/res stay
                # queryable by rules
                for sub in _AUDITD_ATTR_RE.finditer(value):
                    sub_key, sub_value = sub.group(1), sub.group(2)
                    if (
                        len(sub_value) >= 2
                        and sub_value[0] == sub_value[-1]
                        and sub_value[0] in ('"', "'")
                    ):
                        sub_value = sub_value[1:-1]
                    if sub_key:
                        event[sub_key] = sub_value.rstrip()
                continue
            if key:
                event[key] = value.rstrip()
        if "host" not in event:
            event['host'] = 'offline'
        return event

    def sysmon_xml_line_to_json(self, xml_line: str) -> dict[str, Any] | None:
        """Remove syslog header and convert XML data to JSON. Code from ZikyHD (https://github.com/ZikyHD)."""
        if "<Event>" not in xml_line:
            return None
        try:  # isolate individual line parsing errors
            xml_line = "<Event>" + xml_line.split("<Event>", 1)[1]
            root = etree.fromstring(xml_line)
            return self.xml_to_dict(root)
        except Exception as ex:
            self.logger.debug(f"Unable to parse line \"{xml_line}\": {ex}")
            return None

    def xml_to_dict(
        self,
        event_root: Any,
        ns: str = "http://schemas.microsoft.com/win/2004/08/events/event",
    ) -> dict[str, Any]:
        """Convert XML event to dictionary structure."""
        def clean_tag(tag: str, ns: str) -> str:
            """Remove namespace from XML tag (namespace may be braced or not)."""
            braced = ns if ns.startswith("{") else "{" + ns + "}"
            if tag.startswith(braced):
                return tag[len(braced):]
            return tag

        child: dict[str, Any] = {"#attributes": {"xmlns": ns}}
        for appt in event_root:
            node_name = clean_tag(appt.tag, ns)
            node_value: dict[str, Any] = {}
            for elem in appt:
                cleaned_tag = clean_tag(elem.tag, ns)
                text: Any = "" if not elem.text else elem.text
                if elem.text and node_name == "System":
                    # Numeric conversion is limited to System fields: EventData
                    # values stay strings, consistent with the EVTX/JSON paths.
                    with contextlib.suppress(Exception):
                        text = int(elem.text)
                if cleaned_tag == "Data":
                    child_node = elem.get("Name")
                    if child_node is None:
                        # Unnamed <Data> is common (Service Control Manager
                        # 7036 and friends). Collect them into a list under
                        # "Data" so several in one event cannot overwrite each
                        # other, matching what the EVTX parser produces.
                        node_value.setdefault("Data", []).append(text)
                        continue
                elif cleaned_tag == "Qualifiers":
                    child_node = cleaned_tag
                    text = elem.text
                elif len(elem):
                    # Container element (e.g. UserData payloads): flatten one
                    # level of grandchildren
                    for sub in elem:
                        sub_tag = clean_tag(sub.tag, ns)
                        node_value[sub_tag] = "" if not sub.text else sub.text
                    continue
                else:
                    child_node = cleaned_tag
                    if elem.attrib:
                        # Classic providers write both, e.g.
                        # <EventID Qualifiers="16384">7045</EventID>. Keeping only
                        # the attributes would throw the EventID away.
                        node: dict[str, Any] = {"#attributes": dict(elem.attrib)}
                        if elem.text and elem.text.strip():
                            node["#text"] = text
                        text = node
                node_value[str(child_node)] = text
            child[str(node_name)] = node_value
        event = {"Event": child}
        return event
