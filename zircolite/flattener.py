#!python3
"""
JSON flattening for Zircolite.

This module contains the JSONFlattener class for:
- Flattening nested JSON log events
- Field mapping and transformation
- Time-based filtering
- SQL schema generation
"""

import base64
import logging
import os
import re
import time
from typing import Any, Optional

import chardet
import orjson as json
import xxhash
from RestrictedPython import compile_restricted
from RestrictedPython import limited_builtins
from RestrictedPython import safe_builtins
from RestrictedPython import utility_builtins
from RestrictedPython.Eval import default_guarded_getiter
from RestrictedPython.Guards import guarded_iter_unpack_sequence
# Rich progress
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
from .console import console

from .config import ProcessingConfig
from .utils import load_field_mappings


class JSONFlattener:
    """Perform JSON flattening operations"""

    __slots__ = (
        'logger', 'key_dict', 'field_stmt_parts', 'values_stmt', 'time_after', 'time_before',
        'time_field', 'hashes', 'args_config', 'json_array', 'disable_progress',
        'compiled_code_cache', 'chosen_input', 'field_exclusions', 'field_mappings',
        'useless_values', 'aliases', 'field_split_list', 'transforms', 'transforms_enabled',
        'RestrictedPython_BUILTINS', '_time_after_parsed', '_time_before_parsed',
        '_has_time_filter', '_transform_func_cache', '_sql_type_cache'
    )

    @staticmethod
    def _parse_time_bound(value, fallback):
        """Parse a time bound once; accept either a struct_time or an ISO-like string."""
        if isinstance(value, time.struct_time):
            return value
        try:
            return time.strptime(value, '%Y-%m-%dT%H:%M:%S')
        except (ValueError, TypeError):
            return time.strptime(fallback, '%Y-%m-%dT%H:%M:%S')

    def __init__(
        self,
        config_file: str,
        args_config: Any,
        processing_config: Optional[ProcessingConfig] = None,
        *,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize JSONFlattener.
        
        Args:
            config_file: Path to field mappings configuration file
            args_config: Argparse namespace with input format options
            processing_config: Processing configuration (uses defaults if None)
            logger: Logger instance (creates default if None)
        """
        proc = processing_config or ProcessingConfig()
        
        self.logger = logger or logging.getLogger(__name__)
        self.key_dict = {}
        self.field_stmt_parts = []
        self.values_stmt = []
        self.time_after = proc.time_after
        self.time_before = proc.time_before
        self.time_field = proc.time_field
        self.hashes = proc.hashes
        self.args_config = args_config
        self.json_array = args_config.json_array_input
        self.disable_progress = proc.disable_progress
        self.compiled_code_cache = {}
        # Cache for compiled+executed transform functions (not just bytecode)
        self._transform_func_cache = {}
        # Pre-computed SQL type strings to avoid f-string overhead
        self._sql_type_cache = {}

        # Pre-parse time bounds once instead of per-event
        self._has_time_filter = (proc.time_after != "1970-01-01T00:00:00" or proc.time_before != "9999-12-12T23:59:59")
        if self._has_time_filter:
            self._time_after_parsed = self._parse_time_bound(proc.time_after, "1970-01-01T00:00:00")
            self._time_before_parsed = self._parse_time_bound(proc.time_before, "9999-12-12T23:59:59")
        else:
            self._time_after_parsed = None
            self._time_before_parsed = None

        # Convert the argparse.Namespace to a dictionary
        args_dict = vars(args_config)
        # Find the chosen input format
        self.chosen_input = next((key for key, value in args_dict.items() if "_input" in key and value), None)
        if self.chosen_input is None:
            self.chosen_input = "evtx_input"
        
        # Load field mappings config (supports JSON and YAML formats)
        field_mappings_dict = load_field_mappings(config_file, logger=self.logger)
        self.field_exclusions = tuple(field_mappings_dict["exclusions"])
        self.field_mappings = field_mappings_dict["mappings"]
        self.useless_values = frozenset(field_mappings_dict["useless"]) if field_mappings_dict["useless"] else frozenset()
        self.aliases = field_mappings_dict["alias"]
        self.field_split_list = field_mappings_dict["split"]
        self.transforms = field_mappings_dict["transforms"]
        self.transforms_enabled = field_mappings_dict["transforms_enabled"]

        # Define the authorized BUILTINS for Restricted Python
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
        except Exception as e:
            self.logger.debug(f"ERROR: Couldn't apply transform: {e}")
            return param

    def _get_sql_field_stmt(self, key, is_int):
        """Get cached SQL field statement."""
        cache_key = (key, is_int)
        stmt = self._sql_type_cache.get(cache_key)
        if stmt is None:
            sql_type = 'INTEGER' if is_int else 'TEXT COLLATE NOCASE'
            stmt = f"'{key}' {sql_type},\n"
            self._sql_type_cache[cache_key] = stmt
        return stmt

    def run(self, file):
        """Flatten JSON object with nested keys into a single level."""
        self.logger.debug(f"FLATTENING : {file}")
        
        # If file size is zero, return early
        try:
            if os.stat(file).st_size == 0:
                return {"dbFields": "", "dbValues": []}
        except OSError:
            return {"dbFields": "", "dbValues": []}

        # Pre-allocate output list (estimate based on typical log density)
        json_output = []
        json_output_append = json_output.append  # Cache method reference
        field_stmt_parts = []
        field_stmt_parts_append = field_stmt_parts.append
        
        # Cache everything as locals for maximum speed in hot loop
        key_dict = self.key_dict
        field_exclusions = self.field_exclusions
        field_mappings = self.field_mappings
        field_mappings_get = field_mappings.get
        useless_values = self.useless_values
        useless_values_contains = useless_values.__contains__
        aliases = self.aliases
        aliases_get = aliases.get
        field_split_list = self.field_split_list
        field_split_list_get = field_split_list.get
        transforms = self.transforms
        transforms_get = transforms.get
        transforms_enabled = self.transforms_enabled
        chosen_input = self.chosen_input
        hashes = self.hashes
        json_array = self.json_array
        time_field = self.time_field
        has_time_filter = self._has_time_filter
        time_after_parsed = self._time_after_parsed
        time_before_parsed = self._time_before_parsed
        transform_value = self._transform_value
        get_sql_field_stmt = self._get_sql_field_stmt
        
        # Cache type checks
        dict_type = dict
        list_type = list
        int_type = int
        isinstance_local = isinstance
        
        # Read file as bytes for faster orjson parsing
        with open(str(file), 'rb') as json_file:
            filename = os.path.basename(file)
            file_content = json_file.read()
            
            # Load logs based on format
            if json_array:
                try:
                    logs = json.loads(file_content)
                except Exception as e:
                    self.logger.debug(f'JSON ARRAY ERROR : {e}')
                    return {"dbFields": "", "dbValues": []}
            else:
                # Split by newlines for line-delimited JSON
                logs = file_content.split(b'\n')

            for line in logs:
                if not line:  # Skip empty lines
                    continue
                try:
                    if json_array:
                        dict_to_flatten = line
                    else:
                        dict_to_flatten = json.loads(line)
                    
                    dict_to_flatten["OriginalLogfile"] = filename
                    if hashes:
                        # Use bytes directly for xxhash (faster)
                        dict_to_flatten["OriginalLogLinexxHash"] = xxhash.xxh64_hexdigest(line)
                    
                    # Iterative flattening using a stack with tuples (immutable, faster)
                    json_line = {}
                    json_line_setitem = json_line.__setitem__
                    # Use tuple for path (immutable, faster concatenation pattern)
                    stack = [(dict_to_flatten, ())]
                    
                    while stack:
                        obj, path_parts = stack.pop()
                        
                        if isinstance_local(obj, dict_type):
                            # Add children to stack - use tuple concatenation
                            items = obj.items()
                            for k, v in items:
                                stack.append((v, path_parts + (k,)))
                        else:
                            # Build the full path name only when needed
                            raw_field_name = '.'.join(path_parts)
                            
                            # Check exclusions - early exit on match
                            excluded = False
                            for exclusion in field_exclusions:
                                if exclusion in raw_field_name:
                                    excluded = True
                                    break
                            if excluded:
                                continue
                            
                            # Handle arrays - join to string
                            if isinstance_local(obj, list_type):
                                value = ''.join(str(obj))
                            else:
                                value = obj
                            
                            # Skip useless values - use cached __contains__
                            if useless_values_contains(value):
                                continue
                            
                            # Get mapped field name or extract from last path component
                            mapped_key = field_mappings_get(raw_field_name)
                            if mapped_key is None:
                                last_part = path_parts[-1] if path_parts else ''
                                # Faster alphanumeric extraction using translate or filter
                                mapped_key = ''.join(c for c in last_part if c.isalnum())
                            
                            key = mapped_key
                            
                            # Build keys list - start with single element
                            keys = [key]
                            alias_key = aliases_get(key)
                            if alias_key is not None:
                                keys.append(alias_key)
                            alias_raw = aliases_get(raw_field_name)
                            if alias_raw is not None:
                                keys.append(alias_raw)
                            
                            # Handle transforms - only allocate if needed
                            transformed_keys = None
                            transformed_values = None
                            if transforms_enabled:
                                for field_name in (key, raw_field_name):
                                    field_transforms = transforms_get(field_name)
                                    if field_transforms:
                                        for transform in field_transforms:
                                            if transform["enabled"] and chosen_input in transform["source_condition"]:
                                                transform_code = transform["code"]
                                                if transform["alias"]:
                                                    alias_name = transform["alias_name"]
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
                                        key_lower = k.lower()
                                        json_line_setitem(k, v)
                                        if key_lower not in key_dict:
                                            key_dict[key_lower] = k
                                            field_stmt_parts_append(get_sql_field_stmt(k, False))
                                except Exception:
                                    pass  # Skip logging in hot path
                            
                            # Apply values to all keys
                            is_int = isinstance_local(value, int_type)
                            has_transforms = transformed_keys is not None
                            
                            for k in keys:
                                if has_transforms and k in transformed_keys:
                                    json_line_setitem(k, transformed_values[k])
                                else:
                                    json_line_setitem(k, value)
                                
                                key_lower = k.lower()
                                if key_lower not in key_dict:
                                    key_dict[key_lower] = k
                                    field_stmt_parts_append(get_sql_field_stmt(k, is_int))
                    
                    # Handle timestamp filtering
                    if has_time_filter and time_field and time_field in json_line:
                        try:
                            ts_str = json_line[time_field]
                            # Fast timestamp parsing
                            dot_pos = ts_str.find('.')
                            if dot_pos != -1:
                                ts_str = ts_str[:dot_pos]
                            elif ts_str[-1] == 'Z':
                                ts_str = ts_str[:-1]
                            timestamp = time.strptime(ts_str, '%Y-%m-%dT%H:%M:%S')
                            if time_after_parsed < timestamp < time_before_parsed:
                                json_output_append(json_line)
                        except Exception:
                            json_output_append(json_line)
                    else:
                        json_output_append(json_line)
                        
                except Exception:
                    pass  # Skip detailed logging in hot path for speed
        
        return {"dbFields": ''.join(field_stmt_parts), "dbValues": json_output}

    @property
    def field_stmt(self):
        """Return field statement as string (computed from parts for efficiency)."""
        return ''.join(self.field_stmt_parts)

    def run_all(self, evtx_json_list):
        """Process all JSON files in the list."""
        iterator = evtx_json_list  # Simplified - progress handled at higher level
        for evtx_json in iterator:
            if os.stat(evtx_json).st_size != 0:
                results = self.run(evtx_json)
                self.field_stmt_parts.append(results["dbFields"])
                self.values_stmt += results["dbValues"]
