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

# ENRICHED logs (auditd's default log_format) append interpreted fields after a
# 0x1D separator, each named as the upper-case spelling of the raw field it
# interprets: syscall=59 ... \x1dSYSCALL=execve EUID="www-data". SQLite folds
# column names, so the two spellings cannot both keep their name. For these
# fields the interpreted value takes the name: a syscall number only means
# something alongside the architecture, and Sigma rules name the call
# (SYSCALL: execve). The raw value moves to "<name>Raw" (no separator: column
# names lose every non-alphanumeric character when events are flattened).
_AUDITD_ENRICHED_WINS = frozenset({"arch", "syscall"})
# For every other collision (AUID, UID, EUID, OUID, SADDR, ...) the raw value
# keeps the name, because the interpretation is a lookup in the logging host's
# own tables and rules match the number (euid: 33). The interpreted value is
# kept as "<NAME>Enriched".


def _strip_quotes(value: str) -> str:
    """Remove one pair of matching surrounding quotes, and only those."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


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
        # a GS ASCII character, 0x1D, separates the original fields from the
        # translated ones. They are parsed separately: a translated field has
        # the upper-case name of the original it translates.
        line, _, enriched = auditd_line.partition('\x1d')
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
            value = _strip_quotes(value)
            if key == "msg" and "=" in value:
                # USER_* records carry an enriched key=value payload in
                # msg='...'; flatten it so fields like acct/exe/res stay
                # queryable by rules
                for sub in _AUDITD_ATTR_RE.finditer(value):
                    sub_key, sub_value = sub.group(1), _strip_quotes(sub.group(2))
                    if sub_key:
                        event[sub_key] = sub_value.rstrip()
                continue
            if key:
                event[key] = value.rstrip()
        if enriched:
            self._add_auditd_enriched_fields(event, enriched)
        if "host" not in event:
            event['host'] = 'offline'
        return event

    @staticmethod
    def _add_auditd_enriched_fields(event: dict[str, Any], enriched: str) -> None:
        """Merge the fields after 0x1D without two keys differing only in case."""
        existing = {key.lower(): key for key in event}
        for match in _AUDITD_ATTR_RE.finditer(enriched):
            key, value = match.group(1), _strip_quotes(match.group(2)).rstrip()
            # SADDR={ saddr_fam=inet laddr=... lport=... }: the brace opens a
            # group whose members parse as fields of their own
            if not key or value == "{":
                continue
            raw_key = existing.get(key.lower())
            if raw_key is None:
                event[key] = value
            elif key.lower() in _AUDITD_ENRICHED_WINS:
                event[f"{raw_key}Raw"] = event.pop(raw_key)
                event[key] = value
            else:
                event[f"{key}Enriched"] = value

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
        def clean_tag(tag: str) -> str:
            """Remove any namespace from an XML tag, not only the Event one.

            UserData payloads declare their own, e.g. <LogFileCleared
            xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">,
            and the EVTX parser drops it from field names too.
            """
            return tag.split("}", 1)[1] if tag.startswith("{") else tag

        child: dict[str, Any] = {"#attributes": {"xmlns": ns}}
        for appt in event_root:
            node_name = clean_tag(appt.tag)
            node_value: dict[str, Any] = {}
            for elem in appt:
                cleaned_tag = clean_tag(elem.tag)
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
                        sub_tag = clean_tag(sub.tag)
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
