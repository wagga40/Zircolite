#!python3
"""
Log extraction and conversion for Zircolite.

This module contains the EvtxExtractor class for:
- EVTX file extraction using Python bindings
- Auditd log conversion
- Sysmon for Linux log conversion
- XML log conversion
- CSV log conversion
- EVTXtract output conversion
"""

import csv
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

import orjson as json
# Rich console for styled output
from evtx import PyEvtxParser
from lxml import etree

from .config import ExtractorConfig
from .utils import random_suffix


class EvtxExtractor:
    """Extract and convert various log formats to JSON."""

    def __init__(
        self,
        extractor_config: Optional[ExtractorConfig] = None,
        *,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize EvtxExtractor.
        
        Args:
            extractor_config: Extractor configuration (uses defaults if None)
            logger: Logger instance (creates default if None)
        """
        cfg = extractor_config or ExtractorConfig()
        
        self.logger = logger or logging.getLogger(__name__)
        
        # Handle temporary directory: use provided path (create if needed) or a unique dir in cwd
        if cfg.tmp_dir:
            path = Path(cfg.tmp_dir)
            if path.exists() and not path.is_dir():
                self.logger.error(
                    f"[red]    [-] Path exists and is not a directory: {path}, using random tmp dir[/]"
                )
                self.tmpDir = f"tmp-{random_suffix(8)}"
                os.mkdir(self.tmpDir)
            else:
                self.tmpDir = str(path)
                if not path.exists():
                    os.mkdir(self.tmpDir)
        else:
            self.tmpDir = f"tmp-{random_suffix(8)}"
            os.mkdir(self.tmpDir)
        
        self.sysmon4linux = cfg.sysmon4linux
        self.xmlLogs = cfg.xml_logs
        self.auditdLogs = cfg.auditd_logs
        self.evtxtract = cfg.evtxtract
        self.csvInput = cfg.csv_input
        self.encoding = cfg.encoding
        self.strict_evtx = cfg.strict_evtx
        
    def run_using_bindings(self, file: Union[Path, str]) -> None:
        """Convert EVTX to JSON using evtx_dump bindings. Drop resulting JSON files in a tmp folder."""
        try:
            filepath = Path(file)
            filename = filepath.name
            parser = PyEvtxParser(str(filepath))
            with open(f"{self.tmpDir}/{str(filename)}-{random_suffix(8)}.json", "w", encoding="utf-8") as f:
                for record in parser.records_json():
                    if record is None:
                        continue
                    data = record.get("data")
                    if data is None:
                        continue
                    f.write(f"{json.dumps(json.loads(data)).decode('utf-8')}\n")
        except Exception as e:
            if self.strict_evtx:
                self.logger.error(f"[red]    [-] Cannot use PyEvtxParser : {e}[/]")
                raise
            self.logger.warning(
                f"[yellow]    [!] EVTX parsing error in {file}: {e} — "
                "recovered events before the error were kept (use [cyan]--strict[/] to abort on parse errors)[/]"
            )

    def get_time(self, line: str) -> str:
        """Extract timestamp from auditd log line."""
        try:
            parts = line.replace("msg=audit(", "").replace("):", "").split(":")
            return time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(float(parts[0]))
            )
        except (ValueError, IndexError, OSError):
            return ""

    def auditd_line_to_json(self, auditd_line: str) -> Dict[str, Any]:
        """Convert auditd logs to JSON. Code from https://github.com/csark/audit2json."""
        event = {}
        # According to auditd specs https://github.com/linux-audit/audit-documentation/wiki/SPEC-Audit-Event-Enrichment
        # a GS ASCII character, 0x1D, will be inserted to separate original and translated fields
        # Best way to deal with it is to remove it.
        attributes = auditd_line.replace('\x1d',' ').split(' ')
        for attribute in attributes:
            if 'msg=audit' in attribute:
                event['timestamp'] = self.get_time(attribute)
            else:
                try:
                    cleaned = (
                        attribute.replace("msg=", "")
                        .replace("'", "")
                        .replace('"', "")
                    )
                    key, _, value = cleaned.partition("=")
                    if key and _ == "=":
                        event[key] = value.rstrip()
                except Exception as e:
                    self.logger.debug(f"Skipping malformed auditd attribute '{attribute}': {e}")
        if "host" not in event:
            event['host'] = 'offline'
        return event

    def sysmon_xml_line_to_json(self, xml_line: str) -> Optional[Dict[str, Any]]:
        """Remove syslog header and convert XML data to JSON. Code from ZikyHD (https://github.com/ZikyHD)."""
        if 'Event' not in xml_line:
            return None
        xml_line = "<Event>" + xml_line.split("<Event>")[1]
        try:  # isolate individual line parsing errors
            root = etree.fromstring(xml_line)
            return self.xml_to_dict(root)
        except Exception as ex:
            self.logger.debug(f"Unable to parse line \"{xml_line}\": {ex}")
            return None

    def xml_line_to_json(self, xml_line: str) -> Optional[Dict[str, Any]]:
        """Remove "Events" header and convert XML data to JSON. Code from ZikyHD (https://github.com/ZikyHD)."""
        if '<Event ' not in xml_line:
            return None
        try:  # isolate individual line parsing errors
            root = etree.fromstring(xml_line)
            return self.xml_to_dict(root, u'{http://schemas.microsoft.com/win/2004/08/events/event}')
        except Exception as ex:
            self.logger.debug(f"Unable to parse line \"{xml_line}\": {ex}")
            return None

    def xml_to_dict(
        self,
        event_root: Any,
        ns: str = "http://schemas.microsoft.com/win/2004/08/events/event",
    ) -> Dict[str, Any]:
        """Convert XML event to dictionary structure."""
        def clean_tag(tag: str, ns: str) -> str:
            """Remove namespace from XML tag."""
            if ns in tag: 
                return tag[len(ns):]
            return tag

        child: Dict[str, Any] = {"#attributes": {"xmlns": ns}}
        for appt in event_root:
            node_name = clean_tag(appt.tag, ns)
            node_value: Dict[str, Any] = {}
            for elem in appt:
                cleaned_tag = clean_tag(elem.tag, ns)
                text: Any = "" if not elem.text else elem.text
                if elem.text:
                    try:
                        text = int(elem.text)
                    except Exception:
                        pass
                if cleaned_tag == "Data":
                    child_node = elem.get("Name")
                elif cleaned_tag == "Qualifiers":
                    child_node = cleaned_tag
                    text = elem.text
                else:
                    child_node = cleaned_tag
                    if elem.attrib:
                        text = {"#attributes": dict(elem.attrib)}
                node_value[str(child_node)] = text
            child[str(node_name)] = node_value
        event = {"Event": child}
        return event

    def logs_to_json(
        self,
        func: Callable[[str], Optional[Dict[str, Any]]],
        datasource: str,
        outfile: str,
        is_file: bool = True,
    ) -> None:
        """Convert supported log formats to JSON sequentially."""
        if is_file:
            with open(datasource, "r", encoding=self.encoding) as fp: 
                data = fp.readlines()
        else: 
            data = datasource.split("\n")
        
        # Process sequentially for better memory efficiency
        with open(outfile, "w", encoding="UTF-8") as fp:
            for line in data:
                element = func(line)
                if element is not None:
                    fp.write(json.dumps(element).decode("utf-8") + '\n')

    def csv_to_json(self, csv_path: Union[Path, str], json_path: Union[Path, str]) -> None:
        """Convert CSV logs to JSON."""
        with open(csv_path, encoding='utf-8') as csv_file: 
            csv_reader = csv.DictReader(csv_file) 
            with open(json_path, 'w', encoding='utf-8') as json_file: 
                for row in csv_reader: 
                    json_file.write(json.dumps(row).decode("utf-8") + '\n')

    def evtxtract_to_json(self, file: Union[Path, str], outfile: Union[Path, str]) -> None:
        """Convert EVTXtract logs to JSON using xml_to_dict and write to a file."""
        # Load file as a string to add enclosing document since XML doesn't support multiple documents
        with open(file, "r", encoding=self.encoding) as fp:
            data = fp.read()
        # Remove all non UTF-8 characters
        data = bytes(data.replace('\x00','').replace('\x0B',''), 'utf-8').decode('utf-8', 'ignore')
        data = f'<evtxtract>\n{data}\n</evtxtract>'
        # Load the XML file
        parser = etree.XMLParser(recover=True)  # Recover=True allows the parser to ignore bad characters
        root = etree.fromstring(data, parser=parser)
        with open(outfile, "w", encoding="UTF-8") as fp:
            for event in root:
                if "Event" in event.tag:
                    extracted_event = self.xml_to_dict(event, u'{http://schemas.microsoft.com/win/2004/08/events/event}')
                    fp.write(json.dumps(extracted_event).decode("utf-8") + '\n')

    def run(self, file: Union[Path, str]) -> None:
        """
        Convert Logs to JSON
        Drop resulting JSON files in a tmp folder.
        """
        self.logger.debug(f"EXTRACTING : {file}")
        filename = Path(file).name
        output_json_filename = f"{self.tmpDir}/{str(filename)}-{random_suffix(8)}.json"
        
        try:
            # Auditd or Sysmon4Linux logs
            if self.sysmon4linux or self.auditdLogs:
                func = self.sysmon_xml_line_to_json if self.sysmon4linux else self.auditd_line_to_json
                self.logs_to_json(func, str(file), output_json_filename)
            
            # XML logs
            elif self.xmlLogs:
                with open(str(file), 'r', encoding="utf-8") as xml_file:
                    data = xml_file.read().replace("\n","").replace("</Event>","</Event>\n").replace("<Event ","\n<Event ")
                self.logs_to_json(self.xml_line_to_json, data, output_json_filename, is_file=False)
            
            # EVTXtract
            elif self.evtxtract:
                self.evtxtract_to_json(str(file), output_json_filename)
            
            # CSV
            elif self.csvInput:
                self.csv_to_json(str(file), output_json_filename)
            
            # EVTX - Always use Python bindings
            else:
                self.run_using_bindings(file)
                    
        except Exception as e:
            self.logger.error(f"[red]    [-] {e}[/]")
            raise

    def cleanup(self) -> None:
        if os.path.isdir(self.tmpDir):
            shutil.rmtree(self.tmpDir)
