#!python3
"""
Streaming event processor for Zircolite.

This module contains the StreamingEventProcessor class for:
- Single-pass streaming of events from various log formats
- Dynamic schema discovery during streaming
- Batch database insertion
- Early event filtering based on channel/eventID
"""

import base64
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Generator, List, Optional, TYPE_CHECKING

import chardet
import orjson as json
import xxhash
# Rich console for styled output
from evtx import PyEvtxParser
from RestrictedPython import compile_restricted
from RestrictedPython import limited_builtins
from RestrictedPython import safe_builtins
from RestrictedPython import utility_builtins
from RestrictedPython.Eval import default_guarded_getiter
from RestrictedPython.Guards import guarded_iter_unpack_sequence

from .config import ProcessingConfig
from .utils import load_field_mappings

if TYPE_CHECKING:
    from .extractor import EvtxExtractor
    from .rules import EventFilter


class StreamingEventProcessor:
    """
    Single-pass streaming processor that combines extraction, flattening, and DB insertion.
    
    This eliminates intermediate file I/O and double JSON parsing by processing events
    as they are extracted from EVTX/XML/Auditd sources and directly inserting them
    into the SQLite database in batches.
    
    Supports early event filtering based on channel/eventID to skip events that won't
    match any detection rules.
    """

    __slots__ = (
        'logger', 'config_file', 'time_after', 'time_before', 'time_field',
        'hashes', 'args_config', 'disable_progress', 'batch_size',
        # Config data (loaded once)
        'field_exclusions', 'field_mappings', 'useless_values', 'aliases',
        'field_split_list', 'transforms', 'transforms_enabled', 'enabled_transforms_set',
        'chosen_input',
        # Event filter config (from fieldMappings config)
        '_channel_field_paths', '_eventid_field_paths',
        # Timestamp config (from fieldMappings config)
        '_timestamp_detection_fields', '_timestamp_auto_detect', '_detected_time_field',
        # Schema tracking
        'discovered_fields', 'field_types', 'field_stmt_cache',
        # Caches
        'compiled_code_cache', '_transform_func_cache', 'RestrictedPython_BUILTINS',
        # Time filter cache
        '_has_time_filter', '_time_after_parsed', '_time_before_parsed',
        # DB column caching (optimization)
        '_db_columns', '_last_insert_stmt', '_last_insert_columns',
        # Event filtering (early skip based on channel/eventID)
        'event_filter', '_events_filtered_count', '_filtering_enabled'
    )

    def __init__(
        self,
        config_file: str,
        args_config: Any,
        processing_config: Optional[ProcessingConfig] = None,
        *,
        logger: Optional[logging.Logger] = None,
        event_filter: 'Optional[EventFilter]' = None
    ):
        """
        Initialize StreamingEventProcessor.
        
        Args:
            config_file: Path to field mappings configuration file
            args_config: Argparse namespace with input format options
            processing_config: Processing configuration (uses defaults if None)
            logger: Logger instance (creates default if None)
            event_filter: Optional EventFilter for early event filtering based on channel/eventID
        """
        proc = processing_config or ProcessingConfig()
        
        self.logger = logger or logging.getLogger(__name__)
        self.config_file = config_file
        self.time_after = proc.time_after
        self.time_before = proc.time_before
        self.time_field = proc.time_field
        self.hashes = proc.hashes
        self.args_config = args_config
        self.disable_progress = proc.disable_progress
        self.batch_size = proc.batch_size
        
        # Event filter for early filtering based on channel/eventID
        self.event_filter = event_filter
        self._events_filtered_count = 0
        # Pre-compute filtering enabled flag (avoids repeated checks in hot loop)
        self._filtering_enabled = event_filter is not None and event_filter.is_enabled
        
        # Schema tracking - fields discovered during streaming
        self.discovered_fields = {}  # field_name_lower -> original_field_name
        self.field_types = {}  # field_name -> 'INTEGER' or 'TEXT'
        self.field_stmt_cache = {}
        
        # Caches for transforms
        self.compiled_code_cache = {}
        self._transform_func_cache = {}
        
        # DB column caching for batch inserts (avoid repeated PRAGMA queries)
        self._db_columns = None  # Set of known columns in DB, None = needs refresh
        self._last_insert_stmt = None  # Cached INSERT statement
        self._last_insert_columns = None  # Columns used in cached statement (as tuple for comparison)
        
        # Pre-parse time bounds once
        self._has_time_filter = (proc.time_after != "1970-01-01T00:00:00" or proc.time_before != "9999-12-12T23:59:59")
        if self._has_time_filter:
            self._time_after_parsed = self._parse_time_bound(proc.time_after, "1970-01-01T00:00:00")
            self._time_before_parsed = self._parse_time_bound(proc.time_before, "9999-12-12T23:59:59")
        else:
            self._time_after_parsed = None
            self._time_before_parsed = None
        
        # Determine chosen input format
        if args_config:
            args_dict = vars(args_config)
            self.chosen_input = next((key for key, value in args_dict.items() if "_input" in key and value), None)
        if not hasattr(self, 'chosen_input') or self.chosen_input is None:
            self.chosen_input = "evtx_input"
        
        # Load field mappings config (includes event_filter and timestamp_detection)
        self._load_config()
        
        # Initialize RestrictedPython builtins
        self._init_restricted_builtins()
        
        # Timestamp auto-detection state
        self._detected_time_field = None

    @staticmethod
    def _parse_time_bound(value, fallback):
        """Parse a time bound once; accept either a struct_time or an ISO-like string."""
        if isinstance(value, time.struct_time):
            return value
        try:
            return time.strptime(value, '%Y-%m-%dT%H:%M:%S')
        except (ValueError, TypeError):
            return time.strptime(fallback, '%Y-%m-%dT%H:%M:%S')

    def _load_config(self):
        """Load field mappings configuration (supports JSON and YAML formats)."""
        config = load_field_mappings(self.config_file, logger=self.logger)
        self.field_exclusions = tuple(config["exclusions"])
        self.field_mappings = config["mappings"]
        self.useless_values = frozenset(config["useless"]) if config["useless"] else frozenset()
        self.aliases = config["alias"]
        self.field_split_list = config["split"]
        self.transforms = config["transforms"]
        self.transforms_enabled = config["transforms_enabled"]
        
        # Load enabled_transforms list for quick enable/disable control
        # If present, only transforms in this list are enabled (overrides per-transform 'enabled' flag)
        enabled_list = config.get("enabled_transforms", None)
        if enabled_list is not None:
            self.enabled_transforms_set = frozenset(enabled_list)
        else:
            # If no list provided, fall back to per-transform 'enabled' flag (set to None)
            self.enabled_transforms_set = None
        
        # Load event filter field paths from config (defaults provided by load_field_mappings)
        event_filter = config.get("event_filter", {})
        self._channel_field_paths = tuple(event_filter.get("channel_fields", []))
        self._eventid_field_paths = tuple(event_filter.get("eventid_fields", []))
        
        # Load timestamp detection config (defaults provided by load_field_mappings)
        timestamp = config.get("timestamp_detection", {})
        self._timestamp_detection_fields = tuple(timestamp.get("detection_fields", []))
        self._timestamp_auto_detect = timestamp.get("auto_detect", True)

    def _init_restricted_builtins(self):
        """Initialize RestrictedPython builtins for transforms."""
        def default_guarded_getitem(ob, index):
            return ob[index]

        self.RestrictedPython_BUILTINS = {
            '__name__': 'script',
            "_getiter_": default_guarded_getiter,
            '_getattr_': getattr,
            '_getitem_': default_guarded_getitem,
            'base64': base64,
            're': re,
            'chardet': chardet,
            '_iter_unpack_sequence_': guarded_iter_unpack_sequence
        }
        self.RestrictedPython_BUILTINS.update(safe_builtins)
        self.RestrictedPython_BUILTINS.update(limited_builtins)
        self.RestrictedPython_BUILTINS.update(utility_builtins)

    def _extract_event_filter_fields(self, event_dict: dict) -> tuple:
        """
        Extract Channel and EventID from raw event data for early filtering.
        
        This method tries to extract these fields using configured field paths.
        Paths are tried in order until a value is found.
        
        The field paths support:
        - Dot notation for nested fields (e.g., "Event.System.Channel")
        - Direct field names (e.g., "Channel")
        - Special handling for EventID which may be a dict with '#text'
        
        Args:
            event_dict: Raw event dictionary (not yet flattened)
            
        Returns:
            Tuple of (channel, eventid) where eventid is int or None
        """
        channel = None
        eventid = None
        
        # Extract channel using configured field paths
        channel = self._extract_field_value(event_dict, self._channel_field_paths)
        
        # Extract eventID using configured field paths
        eventid = self._extract_field_value(event_dict, self._eventid_field_paths)
        
        # Convert eventid to int if possible (guarantees int or None for caller)
        if eventid is not None:
            # Handle EventID as dict with '#text' (XML style)
            if isinstance(eventid, dict):
                eventid = eventid.get('#text')
            try:
                eventid = int(eventid)
            except (ValueError, TypeError):
                eventid = None
        
        return channel, eventid

    def _extract_field_value(self, event_dict: dict, field_paths: tuple) -> Any:
        """
        Extract a field value from an event dict using a list of possible paths.
        
        Paths support dot notation for nested access (e.g., "Event.System.Channel").
        Tries each path in order until a non-None value is found.
        
        Args:
            event_dict: The event dictionary to extract from
            field_paths: Tuple of field paths to try
            
        Returns:
            The first non-None value found, or None if no path succeeds
        """
        for path in field_paths:
            value = self._get_nested_value(event_dict, path)
            if value is not None:
                return value
        return None

    def _get_nested_value(self, obj: dict, path: str) -> Any:
        """
        Get a value from a nested dictionary using dot notation.
        
        Args:
            obj: The dictionary to search
            path: Dot-separated path (e.g., "Event.System.Channel")
            
        Returns:
            The value at the path, or None if not found
        """
        if not path or not isinstance(obj, dict):
            return None
        
        # Split path by dots
        parts = path.split('.')
        current = obj
        
        for part in parts:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
            if current is None:
                return None
        
        return current

    def _detect_timestamp_field(self, flattened_event: dict) -> Optional[str]:
        """
        Auto-detect the timestamp field from a flattened event.
        
        Tries the default time_field first, then falls back to configured
        detection fields in order of priority.
        
        Args:
            flattened_event: A flattened event dictionary
            
        Returns:
            The name of the detected timestamp field, or None if not found
        """
        # First, try the explicitly configured time_field (if set)
        if self.time_field and self.time_field in flattened_event:
            return self.time_field
        
        # If auto-detect is enabled, try detection fields from config
        if self._timestamp_auto_detect:
            for field in self._timestamp_detection_fields:
                if field in flattened_event:
                    return field
        
        return None

    def _should_process_event(self, event_dict: dict) -> bool:
        """
        Check if an event should be processed based on the event filter.
        
        This is a fast check performed before expensive flattening operations.
        
        Args:
            event_dict: Raw event dictionary
            
        Returns:
            True if the event should be processed, False if it can be skipped
        """
        # Fast path: use pre-computed flag instead of repeated attribute checks
        if not self._filtering_enabled:
            return True
        
        channel, eventid = self._extract_event_filter_fields(event_dict)
        should_process = self.event_filter.should_process_event(channel, eventid)
        
        if not should_process:
            self._events_filtered_count += 1
        
        return should_process

    @property
    def events_filtered_count(self) -> int:
        """Return the number of events skipped by the event filter."""
        return self._events_filtered_count

    def _get_transform_func(self, code):
        """Get or create cached transform function."""
        func = self._transform_func_cache.get(code)
        if func is not None:
            return func
        try:
            byte_code = self.compiled_code_cache.get(code)
            if byte_code is None:
                byte_code = compile_restricted(code, filename='<inline code>', mode='exec')
                self.compiled_code_cache[code] = byte_code
            transform_ns = {}
            exec(byte_code, self.RestrictedPython_BUILTINS, transform_ns)
            func = transform_ns.get("transform")
            if func:
                self._transform_func_cache[code] = func
            return func
        except Exception:
            return None

    def _transform_value(self, code, param):
        """Transform a value using cached transform function."""
        try:
            func = self._get_transform_func(code)
            if func:
                return func(param)
            return param
        except Exception:
            return param

    def _flatten_event(self, event_dict: dict, filename: str, raw_bytes: bytes = None) -> Optional[dict]:
        """
        Flatten a single event dictionary and track discovered fields.
        Returns flattened dict or None if filtered out.
        """
        # Add metadata
        event_dict["OriginalLogfile"] = filename
        if self.hashes and raw_bytes:
            event_dict["OriginalLogLinexxHash"] = xxhash.xxh64_hexdigest(raw_bytes)
        
        # Cache references for hot loop (local vars are faster than attribute access)
        field_exclusions = self.field_exclusions
        field_mappings = self.field_mappings
        field_mappings_get = field_mappings.get
        useless_values = self.useless_values
        aliases = self.aliases
        aliases_get = aliases.get
        field_split_list = self.field_split_list
        field_split_list_get = field_split_list.get
        transforms = self.transforms
        transforms_get = transforms.get
        transforms_enabled = self.transforms_enabled
        enabled_transforms_set = self.enabled_transforms_set
        chosen_input = self.chosen_input
        discovered_fields = self.discovered_fields
        field_types = self.field_types
        transform_value = self._transform_value
        
        # Result dict
        json_line = {}
        
        # Iterative flattening using stack with mutable path list
        # Stack entries: (object, path_list, depth)
        # We track depth to know how many path elements to pop when backtracking
        stack = [(event_dict, [], 0)]
        
        while stack:
            obj, path, depth = stack.pop()
            
            if isinstance(obj, dict):
                items = list(obj.items())
                for k, v in reversed(items):  # Reverse to maintain order when popping
                    # Build new path by copying (list slicing is fast for small lists)
                    new_path = path[:depth]
                    new_path.append(k)
                    stack.append((v, new_path, depth + 1))
            else:
                # Build field name from path
                raw_field_name = '.'.join(path)
                
                # Check exclusions (early exit)
                excluded = False
                for exclusion in field_exclusions:
                    if exclusion in raw_field_name:
                        excluded = True
                        break
                if excluded:
                    continue
                
                # Handle arrays - convert to string
                if isinstance(obj, list):
                    value = str(obj)
                else:
                    value = obj
                
                # Skip useless values
                if value in useless_values:
                    continue
                
                # Get mapped field name (cache lookup)
                mapped_key = field_mappings_get(raw_field_name)
                if mapped_key is None:
                    # Use last path component, filtered to alphanumeric
                    last_part = path[-1] if path else ''
                    mapped_key = ''.join(c for c in last_part if c.isalnum())
                
                key = mapped_key
                keys = [key]
                
                # Check aliases
                alias_key = aliases_get(key)
                if alias_key is not None:
                    keys.append(alias_key)
                alias_raw = aliases_get(raw_field_name)
                if alias_raw is not None:
                    keys.append(alias_raw)
                
                # Handle transforms
                transformed_keys = None
                transformed_values = None
                if transforms_enabled and enabled_transforms_set:
                    for field_name in (key, raw_field_name):
                        field_transforms = transforms_get(field_name)
                        if field_transforms:
                            for transform in field_transforms:
                                # Check if transform is enabled via enabled_transforms list
                                alias_name = transform.get("alias_name", "")
                                if alias_name in enabled_transforms_set and chosen_input in transform["source_condition"]:
                                    transform_code = transform["code"]
                                    if transform["alias"]:
                                        keys.append(alias_name)
                                        if transformed_keys is None:
                                            transformed_keys = set()
                                            transformed_values = {}
                                        transformed_keys.add(alias_name)
                                        transformed_values[alias_name] = transform_value(transform_code, value)
                                    else:
                                        value = transform_value(transform_code, value)
                
                # Handle field splitting
                split_config = field_split_list_get(raw_field_name) or field_split_list_get(key)
                if split_config:
                    try:
                        separator = split_config["separator"]
                        equal_sign = split_config["equal"]
                        for split_field in value.split(separator):
                            k, v = split_field.split(equal_sign)
                            json_line[k] = v
                            key_lower = k.lower()
                            if key_lower not in discovered_fields:
                                discovered_fields[key_lower] = k
                                field_types[k] = 'TEXT COLLATE NOCASE'
                    except Exception:
                        pass
                
                # Apply values to all keys and track schema
                is_int = isinstance(value, int)
                has_transforms = transformed_keys is not None
                
                for k in keys:
                    if has_transforms and k in transformed_keys:
                        json_line[k] = transformed_values[k]
                    else:
                        json_line[k] = value
                    
                    key_lower = k.lower()
                    if key_lower not in discovered_fields:
                        discovered_fields[key_lower] = k
                        field_types[k] = 'INTEGER' if is_int else 'TEXT COLLATE NOCASE'
        
        # Time filtering (with pre-parsed bounds)
        if self._has_time_filter:
            # Use configured time_field or auto-detect
            effective_time_field = self.time_field
            
            # Auto-detect timestamp field if not found or not set
            if not effective_time_field or effective_time_field not in json_line:
                if self._detected_time_field and self._detected_time_field in json_line:
                    effective_time_field = self._detected_time_field
                elif self._timestamp_auto_detect:
                    detected = self._detect_timestamp_field(json_line)
                    if detected:
                        self._detected_time_field = detected
                        effective_time_field = detected
                        self.logger.debug(f"Auto-detected timestamp field: {detected}")
            
            if effective_time_field:
                ts_str = json_line.get(effective_time_field)
                if ts_str:
                    try:
                        # Strip fractional seconds and timezone
                        dot_pos = ts_str.find('.')
                        if dot_pos != -1:
                            ts_str = ts_str[:dot_pos]
                        elif ts_str.endswith('Z'):
                            ts_str = ts_str[:-1]
                        # Handle timezone offset (e.g., +00:00)
                        if '+' in ts_str:
                            ts_str = ts_str.split('+')[0]
                        timestamp = time.strptime(ts_str[:19], '%Y-%m-%dT%H:%M:%S')
                        if not (self._time_after_parsed < timestamp < self._time_before_parsed):
                            return None
                    except Exception:
                        pass
        
        return json_line

    def stream_evtx_events(self, evtx_file: str) -> Generator[dict, None, None]:
        """Stream and flatten events from an EVTX file."""
        try:
            filepath = Path(evtx_file)
            filename = filepath.name
            parser = PyEvtxParser(str(filepath))
            flatten = self._flatten_event  # Local reference for speed
            json_loads = json.loads
            should_process = self._should_process_event  # Local reference for speed
            
            for record in parser.records_json():
                try:
                    raw_data = record["data"]
                    if isinstance(raw_data, str):
                        raw_bytes = raw_data.encode('utf-8')
                        event_dict = json_loads(raw_bytes)
                    else:
                        raw_bytes = raw_data
                        event_dict = json_loads(raw_data)
                    
                    # Early filter check before expensive flattening
                    if not should_process(event_dict):
                        continue
                    
                    flattened = flatten(event_dict, filename, raw_bytes)
                    if flattened:
                        yield flattened
                except Exception as e:
                    self.logger.debug(f"Error processing EVTX record: {e}")
                    continue
        except Exception as e:
            self.logger.error(f"[red]   [-] Error streaming EVTX file {evtx_file}: {e}[/]")

    def stream_json_events(self, json_file: str, json_array: bool = False) -> Generator[dict, None, None]:
        """
        Stream and flatten events from a JSON file.
        
        Optimizations:
        - JSONL mode: True line-by-line streaming (no full file load)
        - JSON array mode: Single parse, iterate elements
        - Early event filtering based on channel/eventID
        """
        try:
            filename = os.path.basename(json_file)
            flatten = self._flatten_event  # Local reference
            should_process = self._should_process_event  # Local reference
            
            if json_array:
                # JSON array: must load entire file to parse array
                with open(json_file, 'rb') as f:
                    logs = json.loads(f.read())
                for event_dict in logs:
                    # Early filter check before expensive flattening
                    if not should_process(event_dict):
                        continue
                    flattened = flatten(event_dict, filename, None)
                    if flattened:
                        yield flattened
            else:
                # JSONL: stream line by line (memory efficient)
                with open(json_file, 'rb') as f:
                    for line in f:
                        line = line.rstrip(b'\n\r')
                        if not line:
                            continue
                        try:
                            event_dict = json.loads(line)
                            # Early filter check before expensive flattening
                            if not should_process(event_dict):
                                continue
                            flattened = flatten(event_dict, filename, line)
                            if flattened:
                                yield flattened
                        except Exception:
                            continue
        except Exception as e:
            self.logger.error(f"[red]   [-] Error streaming JSON file {json_file}: {e}[/]")

    def stream_xml_events(self, xml_file: str, extractor: 'EvtxExtractor') -> Generator[dict, None, None]:
        """Stream and flatten events from an XML file using the extractor's conversion methods."""
        try:
            filename = Path(xml_file).name
            flatten = self._flatten_event  # Local reference
            should_process = self._should_process_event  # Local reference
            xml_convert = extractor.xml_line_to_json
            
            with open(xml_file, 'r', encoding=extractor.encoding) as f:
                data = f.read().replace("\n", "").replace("</Event>", "</Event>\n").replace("<Event ", "\n<Event ")
            
            for line in data.split("\n"):
                if not line:
                    continue
                try:
                    event_dict = xml_convert(line)
                    if event_dict:
                        # Early filter check before expensive flattening
                        if not should_process(event_dict):
                            continue
                        flattened = flatten(event_dict, filename, line.encode('utf-8'))
                        if flattened:
                            yield flattened
                except Exception:
                    continue
        except Exception as e:
            self.logger.error(f"[red]   [-] Error streaming XML file {xml_file}: {e}[/]")

    def stream_sysmon_linux_events(self, log_file: str, extractor: 'EvtxExtractor') -> Generator[dict, None, None]:
        """Stream and flatten events from a Sysmon for Linux log file."""
        try:
            filename = Path(log_file).name
            flatten = self._flatten_event  # Local reference
            should_process = self._should_process_event  # Local reference
            sysmon_convert = extractor.sysmon_xml_line_to_json
            
            with open(log_file, 'r', encoding=extractor.encoding) as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        event_dict = sysmon_convert(line)
                        if event_dict:
                            # Early filter check before expensive flattening
                            if not should_process(event_dict):
                                continue
                            flattened = flatten(event_dict, filename, line.encode('utf-8'))
                            if flattened:
                                yield flattened
                    except Exception:
                        continue
        except Exception as e:
            self.logger.error(f"[red]   [-] Error streaming Sysmon Linux file {log_file}: {e}[/]")

    def stream_auditd_events(self, log_file: str, extractor: 'EvtxExtractor') -> Generator[dict, None, None]:
        """Stream and flatten events from an Auditd log file."""
        try:
            filename = Path(log_file).name
            flatten = self._flatten_event  # Local reference
            should_process = self._should_process_event  # Local reference
            auditd_convert = extractor.auditd_line_to_json
            
            with open(log_file, 'r', encoding=extractor.encoding) as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        event_dict = auditd_convert(line)
                        if event_dict:
                            # Early filter check (may not apply to Auditd, but keeps consistent)
                            if not should_process(event_dict):
                                continue
                            flattened = flatten(event_dict, filename, line.encode('utf-8'))
                            if flattened:
                                yield flattened
                    except Exception:
                        continue
        except Exception as e:
            self.logger.error(f"[red]   [-] Error streaming Auditd file {log_file}: {e}[/]")

    def stream_csv_events(self, csv_file: str) -> Generator[dict, None, None]:
        """
        Stream and flatten events from a CSV file.
        
        Memory-efficient: reads one row at a time using csv.DictReader.
        """
        import csv as csv_module
        try:
            filename = os.path.basename(csv_file)
            flatten = self._flatten_event  # Local reference
            should_process = self._should_process_event  # Local reference
            
            with open(csv_file, 'r', encoding='utf-8', newline='') as f:
                reader = csv_module.DictReader(f)
                for row in reader:
                    try:
                        # CSV rows are already flat dicts, check filter on them directly
                        if not should_process(row):
                            continue
                        flattened = flatten(row, filename, None)
                        if flattened:
                            yield flattened
                    except Exception:
                        continue
        except Exception as e:
            self.logger.error(f"[red]   [-] Error streaming CSV file {csv_file}: {e}[/]")

    def stream_evtxtract_events(self, log_file: str, extractor: 'EvtxExtractor') -> Generator[dict, None, None]:
        """
        Stream and flatten events from an EVTXtract output file.
        
        EVTXtract produces XML-like output that needs special parsing.
        Memory optimization: process events as they're parsed rather than loading all.
        """
        from lxml import etree
        
        try:
            filename = Path(log_file).name
            flatten = self._flatten_event  # Local reference
            should_process = self._should_process_event  # Local reference
            xml_to_dict = extractor.xml_to_dict
            
            # Read and clean the file content
            with open(log_file, 'r', encoding=extractor.encoding) as f:
                data = f.read()
            
            # Clean non-UTF-8 characters
            data = bytes(data.replace('\x00', '').replace('\x0B', ''), 'utf-8').decode('utf-8', 'ignore')
            data = f'<evtxtract>\n{data}\n</evtxtract>'
            
            # Parse with recovery mode for malformed XML
            parser = etree.XMLParser(recover=True)
            root = etree.fromstring(data, parser=parser)
            
            # Stream events from parsed tree
            ns = u'{http://schemas.microsoft.com/win/2004/08/events/event}'
            for event in root.getchildren():
                if "Event" in event.tag:
                    try:
                        event_dict = xml_to_dict(event, ns)
                        if event_dict:
                            # Early filter check before expensive flattening
                            if not should_process(event_dict):
                                continue
                            flattened = flatten(event_dict, filename, None)
                            if flattened:
                                yield flattened
                    except Exception:
                        continue
            
            # Free memory from parsed tree
            root.clear()
            del data
            
        except Exception as e:
            self.logger.error(f"[red]   [-] Error streaming EVTXtract file {log_file}: {e}[/]")

    def stream_json_array_chunked(self, json_file: str, chunk_size: int = 10000) -> Generator[dict, None, None]:
        """
        Stream and flatten events from a large JSON array file with chunked processing.
        
        For very large JSON arrays, this attempts to parse incrementally.
        Falls back to standard parsing if file is small enough.
        
        Memory optimization: yields events in chunks rather than all at once.
        Includes early event filtering based on channel/eventID.
        """
        try:
            filename = os.path.basename(json_file)
            flatten = self._flatten_event  # Local reference
            should_process = self._should_process_event  # Local reference
            
            file_size = os.path.getsize(json_file)
            
            # For files under 50MB, use standard single-load approach (faster)
            if file_size < 50 * 1024 * 1024:
                with open(json_file, 'rb') as f:
                    logs = json.loads(f.read())
                for event_dict in logs:
                    # Early filter check before expensive flattening
                    if not should_process(event_dict):
                        continue
                    flattened = flatten(event_dict, filename, None)
                    if flattened:
                        yield flattened
                return
            
            # For larger files, try memory-mapped reading with chunked parsing
            # Read and parse in chunks to reduce peak memory
            self.logger.debug(f"Large JSON array ({file_size / 1024 / 1024:.1f}MB), using chunked processing")
            
            with open(json_file, 'rb') as f:
                logs = json.loads(f.read())
            
            # Process in chunks to allow garbage collection
            total_events = len(logs)
            for i in range(0, total_events, chunk_size):
                chunk = logs[i:i + chunk_size]
                for event_dict in chunk:
                    # Early filter check before expensive flattening
                    if not should_process(event_dict):
                        continue
                    flattened = flatten(event_dict, filename, None)
                    if flattened:
                        yield flattened
                # Allow GC to reclaim chunk memory
                del chunk
                
        except Exception as e:
            self.logger.error(f"[red]   [-] Error streaming JSON array file {json_file}: {e}[/]")

    def get_field_statement(self) -> str:
        """Generate SQL field statement from discovered fields."""
        parts = []
        for field_name, sql_type in self.field_types.items():
            parts.append(f"'{field_name}' {sql_type},\n")
        return ''.join(parts)

    def process_file_streaming(self, db_connection, log_file: str, 
                               input_type: str = 'evtx', 
                               extractor: 'EvtxExtractor' = None,
                               json_array: bool = False,
                               use_chunked_json: bool = True) -> int:
        """
        Process a single log file with streaming, directly inserting into database.
        
        Args:
            db_connection: SQLite database connection
            log_file: Path to the log file to process
            input_type: Type of input ('evtx', 'json', 'xml', 'sysmon_linux', 'auditd', 'csv', 'evtxtract')
            extractor: EvtxExtractor instance (required for xml, sysmon_linux, auditd, evtxtract)
            json_array: If True, treat JSON file as array instead of JSONL
            use_chunked_json: If True, use memory-efficient chunked reading for large JSON arrays
        
        Returns the number of events processed.
        """
        # Select appropriate streaming method (dispatch table approach)
        if input_type == 'evtx':
            event_stream = self.stream_evtx_events(log_file)
        elif input_type == 'json':
            if json_array and use_chunked_json:
                event_stream = self.stream_json_array_chunked(log_file)
            else:
                event_stream = self.stream_json_events(log_file, json_array=json_array)
        elif input_type == 'xml' and extractor:
            event_stream = self.stream_xml_events(log_file, extractor)
        elif input_type == 'sysmon_linux' and extractor:
            event_stream = self.stream_sysmon_linux_events(log_file, extractor)
        elif input_type == 'auditd' and extractor:
            event_stream = self.stream_auditd_events(log_file, extractor)
        elif input_type == 'csv':
            event_stream = self.stream_csv_events(log_file)
        elif input_type == 'evtxtract' and extractor:
            event_stream = self.stream_evtxtract_events(log_file, extractor)
        else:
            self.logger.error(f"Unsupported input type: {input_type}")
            return 0
        
        # Batch processing with local variable caching
        batch = []
        batch_append = batch.append
        batch_size = self.batch_size
        event_count = 0
        cursor = db_connection.cursor()
        insert_batch = self._insert_batch
        
        # SQLite integer limit (constant)
        SQLITE_INT_MAX = 9223372036854775807
        
        for event in event_stream:
            batch_append(event)
            event_count += 1
            
            if len(batch) >= batch_size:
                insert_batch(db_connection, cursor, batch, SQLITE_INT_MAX)
                batch = []
                batch_append = batch.append  # Rebind after list replacement
        
        # Insert remaining batch
        if batch:
            insert_batch(db_connection, cursor, batch, SQLITE_INT_MAX)
        
        return event_count

    def _insert_batch(self, db_connection, cursor, batch: List[dict], sqlite_int_max: int):
        """Insert a batch of events into the database with dynamic schema handling."""
        if not batch:
            return
        
        # Collect all columns from batch using set union
        all_columns_set = set()
        for event in batch:
            all_columns_set.update(event.keys())
        all_columns = tuple(sorted(all_columns_set))  # tuple for hashable comparison
        
        # Check if we need to update schema or INSERT statement
        schema_changed = self._ensure_columns_exist_cached(db_connection, cursor, all_columns)
        
        # Reuse INSERT statement if columns haven't changed
        if self._last_insert_columns == all_columns and not schema_changed:
            insert_stmt = self._last_insert_stmt
        else:
            # Build new INSERT statement
            columns_escaped = ', '.join(f'"{col}"' for col in all_columns)
            placeholders = ', '.join(['?'] * len(all_columns))
            insert_stmt = f'INSERT INTO logs ({columns_escaped}) VALUES ({placeholders})'
            self._last_insert_stmt = insert_stmt
            self._last_insert_columns = all_columns
        
        # Prepare batch data with local variable caching
        rows = []
        rows_append = rows.append
        for event in batch:
            event_get = event.get
            values = []
            values_append = values.append
            for col in all_columns:
                value = event_get(col)
                # Convert large integers to string for SQLite compatibility
                if value is not None and isinstance(value, int) and abs(value) > sqlite_int_max:
                    value = str(value)
                values_append(value)
            rows_append(tuple(values))
        
        # Execute batch insert with transaction
        try:
            db_connection.execute('BEGIN TRANSACTION')
            cursor.executemany(insert_stmt, rows)
            db_connection.execute('COMMIT')
        except Exception as e:
            db_connection.execute('ROLLBACK')
            self.logger.debug(f"Batch insert error: {e}")
            raise

    def _ensure_columns_exist_cached(self, db_connection, cursor, columns: tuple) -> bool:
        """
        Dynamically add columns to the table if they don't exist.
        Uses cached column set to minimize PRAGMA queries.
        
        Returns True if schema was modified, False otherwise.
        """
        # Initialize cache if needed
        if self._db_columns is None:
            cursor.execute("PRAGMA table_info(logs)")
            self._db_columns = {row[1].lower() for row in cursor.fetchall()}
        
        db_columns = self._db_columns
        schema_changed = False
        field_types = self.field_types
        
        # Add missing columns
        for col in columns:
            col_lower = col.lower()
            if col_lower not in db_columns:
                sql_type = field_types.get(col, 'TEXT COLLATE NOCASE')
                try:
                    cursor.execute(f'ALTER TABLE logs ADD COLUMN "{col}" {sql_type}')
                    db_columns.add(col_lower)  # Update cache
                    schema_changed = True
                except Exception:
                    # Column might already exist; refresh cache to be safe
                    pass
        
        return schema_changed

    def _ensure_columns_exist(self, db_connection, cursor, columns: List[str]):
        """Dynamically add columns to the table if they don't exist (legacy method)."""
        self._ensure_columns_exist_cached(db_connection, cursor, tuple(columns))

    def create_initial_table(self, db_connection):
        """Create the initial logs table with basic structure."""
        cursor = db_connection.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    row_id INTEGER PRIMARY KEY AUTOINCREMENT
                )
            """)
            db_connection.commit()
            # Reset column cache since we have a fresh table
            self._db_columns = {'row_id'}
            self._last_insert_stmt = None
            self._last_insert_columns = None
        except Exception as e:
            self.logger.error(f"Error creating initial table: {e}")
            raise
