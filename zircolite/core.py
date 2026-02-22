#!python3
"""
Core processing engine for Zircolite.

This module contains the ZircoliteCore class for:
- Database connection and management
- Event insertion and querying
- Rule execution and result handling
- Output generation (JSON/CSV)
"""

import csv
import logging
import os
import re
import sqlite3
from functools import lru_cache
from pathlib import Path
from sqlite3 import Error
from typing import TYPE_CHECKING, Optional

import orjson as json


# ---------------------------------------------------------------------------
# Optimisation: LRU-cached regex compilation for the SQLite ``regexp`` UDF.
# SIGMA rules reuse the same patterns across thousands of rows; caching the
# compiled objects avoids redundant ``re.compile`` calls per row.
# ---------------------------------------------------------------------------
@lru_cache(maxsize=512)
def _compile_regex(pattern: str) -> re.Pattern:
    """Return a compiled regex, cached for repeated use by the SQLite UDF."""
    return re.compile(pattern)

from .config import ProcessingConfig
from .streaming import StreamingEventProcessor
from .console import console, is_quiet, make_detection_counter, build_detection_table, LEVEL_PRIORITY

# Rich progress bar and live display
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    MofNCompleteColumn, TimeElapsedColumn
)
from rich.syntax import Syntax

if TYPE_CHECKING:
    from .extractor import EvtxExtractor
    from .rules import EventFilter


class ZircoliteCore:
    """Load data into database and apply detection rules."""

    # Use __slots__ for reduced memory footprint per instance
    __slots__ = (
        'logger', 'db_connection', 'full_results', 'ruleset', 'no_output',
        'time_after', 'time_before', 'config', 'limit', 'csv_mode', 
        'time_field', 'hashes', 'delimiter', 'first_json_output', 
        'disable_progress', '_escape_cache', '_level_format_map',
        '_cursor'  # Reusable cursor for better performance
    )

    def __init__(
        self,
        config: str,
        processing_config: Optional[ProcessingConfig] = None,
        *,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize ZircoliteCore.
        
        Args:
            config: Path to field mappings configuration file
            processing_config: Processing configuration (uses defaults if None)
            logger: Logger instance (creates default if None)
        """
        proc = processing_config or ProcessingConfig()
        
        self.logger = logger or logging.getLogger(__name__)
        self.db_connection = self.create_connection(proc.db_location)
        self.full_results: list = []
        self.ruleset: list = []
        self.no_output = proc.no_output
        self.time_after = proc.time_after
        self.time_before = proc.time_before
        self.config = config
        self.limit = proc.limit
        self.csv_mode = proc.csv_mode
        self.time_field = proc.time_field
        self.hashes = proc.hashes
        self.delimiter = proc.delimiter
        self.first_json_output = True  # To manage commas in JSON output
        self.disable_progress = proc.disable_progress
        # Cache for escaped identifiers to avoid repeated string operations
        self._escape_cache: dict = {}
        # Pre-computed level format map for O(1) lookup (Rich styles)
        self._level_format_map = {
            "informational": "rule.level.informational",
            "low": "rule.level.low",
            "medium": "rule.level.medium",
            "high": "rule.level.high",
            "critical": "rule.level.critical"
        }
        # Reusable cursor to avoid creating new cursors for each query
        self._cursor = None
    
    def close(self):
        """Close the database connection. Safe to call multiple times."""
        self._cursor = None
        if self.db_connection is not None:
            self.db_connection.close()
            self.db_connection = None

    def __del__(self):
        """Ensure connection is closed when the instance is garbage-collected."""
        if getattr(self, 'db_connection', None) is not None:
            try:
                self.db_connection.close()
            except Exception:
                pass
            self.db_connection = None
        self._cursor = None

    def _get_cursor(self):
        """Get a reusable cursor for better performance."""
        if self._cursor is None:
            self._cursor = self.db_connection.cursor()
        return self._cursor

    def create_connection(self, db):
        """Create a database connection to a SQLite database."""
        conn = None
        self.logger.debug(f"CONNECTING TO : {db}")
        try:
            # Connect to database
            conn = sqlite3.connect(db, isolation_level=None, check_same_thread=False)
            
            # Configure PRAGMA settings based on database type
            # Common PRAGMA settings for both in-memory and on-disk databases
            common_pragmas = [
                ('temp_store', 'MEMORY'),
                ('mmap_size', '268435456'),        # 256MB memory-mapped I/O
                ('page_size', '4096'),
                ('threads', '4'),
            ]
            
            if db == ':memory:':
                # In-memory database settings
                pragmas = [
                    ('journal_mode', 'OFF'),           # No journal needed for in-memory
                    ('synchronous', 'OFF'),
                    ('cache_size', '-128000'),         # 128MB cache
                    ('locking_mode', 'EXCLUSIVE'),     # Single-user mode
                ] + common_pragmas
            else:
                # On-disk database settings
                pragmas = [
                    ('journal_mode', 'WAL'),           # Write-Ahead Logging
                    ('synchronous', 'NORMAL'),         # Balance safety and speed
                    ('cache_size', '-64000'),          # 64MB cache
                    ('wal_autocheckpoint', '10000'),   # Less frequent checkpoints
                ] + common_pragmas
            
            # Apply all PRAGMA settings
            for pragma, value in pragmas:
                conn.execute(f'PRAGMA {pragma} = {value};')
            
            # Enable dictionary-style row access
            conn.row_factory = sqlite3.Row

            def udf_regex(x, y):
                """User-defined function for regex matching in SQLite.
                
                Uses LRU-cached compiled patterns to avoid redundant
                re.compile() calls when the same SIGMA rule pattern is
                evaluated against many rows.
                """
                if y is None: 
                    return 0
                try:
                    return 1 if _compile_regex(x).search(y) else 0
                except re.error:
                    return 0

            conn.create_function('regexp', 2, udf_regex)  # Allows to use regex in SQLite
            return conn
        except Error as e:
            self.logger.error(f"[red]   [-] {e}[/]")
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            return None
        except BaseException:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            raise

    def create_db(self, field_stmt):
        """Create the database table with the specified field statement."""
        cleaned_field_stmt = field_stmt.strip()
        if cleaned_field_stmt.endswith(','):
            cleaned_field_stmt = cleaned_field_stmt[:-1]
        if cleaned_field_stmt:
            create_table_stmt = f"CREATE TABLE logs ( row_id INTEGER PRIMARY KEY AUTOINCREMENT, {cleaned_field_stmt} );"
        else:
            create_table_stmt = "CREATE TABLE logs ( row_id INTEGER PRIMARY KEY AUTOINCREMENT );"
        self.logger.debug(f" CREATE : {create_table_stmt}")
        if not self.execute_query(create_table_stmt):
            self.logger.error("[red]   [-] Unable to create table[/]")
            import sys
            sys.exit(1)

    def create_index(self):
        """Create an index on the eventid column."""
        self.execute_query('CREATE INDEX "idx_eventid" ON "logs" ("eventid");')

    def execute_query(self, query):
        """Perform a SQL query with the provided connection."""
        if self.db_connection is not None:
            self.logger.debug(f"EXECUTING : {query}")
            try:
                self._get_cursor().execute(query)
                self.db_connection.commit()
                return True
            except Error as e:
                self.logger.debug(f"   [-] {e}")
                return False
        else:
            self.logger.error("[error]   [-] No connection to Db[/]")
            return False

    def execute_select_query(self, query):
        """Execute a SELECT SQL query and return the results as a list of dictionaries."""
        if self.db_connection is None:
            self.logger.error("[error]   [-] No connection to Db[/]")
            return []
        try:
            cursor = self._get_cursor()
            # Syntax-highlighted SQL in debug mode
            if self.logger.isEnabledFor(logging.DEBUG):
                console.print(Panel(
                    Syntax(query, "sql", theme="monokai", line_numbers=False, word_wrap=True),
                    title="[dim]SQL Query[/]",
                    border_style="dim",
                    padding=(0, 1),
                ))
            cursor.execute(query)
            # Fetch all rows - sqlite3.Row objects are already dict-like
            rows = cursor.fetchall()
            if not rows:
                return []
            # Convert to dicts using C-level dict(Row) (faster than
            # Python-level dict comprehension)
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            self.logger.debug(f"   [-] SQL query error: {e}")
            return []

    def load_db_in_memory(self, db):
        """In db-only mode, restore an on-disk database to avoid EVTX extraction and flattening."""
        db_file_connection = self.create_connection(db)
        if db_file_connection is None:
            raise RuntimeError(f"Could not connect to database: {db}")
        try:
            db_file_connection.backup(self.db_connection)
        finally:
            db_file_connection.close()

    def escape_identifier(self, identifier):
        """Escape SQL identifiers like table or column names with caching."""
        # Check cache first for frequently used identifiers
        escaped = self._escape_cache.get(identifier)
        if escaped is None:
            escaped = identifier.replace("\"", "\"\"")
            self._escape_cache[identifier] = escaped
        return escaped

    def insert_data_to_db(self, data):
        """Build a parameterized INSERT INTO query and insert data into the database.
        Supports both single dictionaries and lists of dictionaries (batch insertion).
        """
        if not data:
            return True

        # Convert single dictionary to list for uniform batch processing
        if isinstance(data, dict):
            batch = [data]
        elif isinstance(data, list):
            batch = data
        else:
            self.logger.debug("   [-] Data must be a dictionary or a list of dictionaries")
            return False

        # To optimize, we group by the exact set of columns.
        # In most cases, a batch has homogeneous keys.
        # If keys vary, we process them in sub-batches.
        
        try:
            self.db_connection.execute('BEGIN TRANSACTION')
            
            # Group rows by their column signatures
            batches_by_columns = {}
            for row in batch:
                cols = tuple(row.keys())
                if cols not in batches_by_columns:
                    batches_by_columns[cols] = []
                batches_by_columns[cols].append(row)
                
            for cols, rows in batches_by_columns.items():
                columns_escaped = ', '.join([self.escape_identifier(col) for col in cols])
                placeholders = ', '.join(['?'] * len(cols))
                insert_stmt = f'INSERT INTO logs ({columns_escaped}) VALUES ({placeholders})'
                
                values_list = []
                for row in rows:
                    values = []
                    for col in cols:
                        value = row[col]
                        if isinstance(value, int):
                            # Check if value exceeds SQLite INTEGER limits
                            if abs(value) > 9223372036854775807:
                                value = str(value)  # Convert to string
                        values.append(value)
                    values_list.append(tuple(values))
                
                self.db_connection.executemany(insert_stmt, values_list)
                
            self.db_connection.execute('COMMIT')
            return True
        except Exception as e:
            self.db_connection.execute('ROLLBACK')
            self.logger.debug(f"   [-] {e}")
            return False

    def save_db_to_disk(self, db_filename):
        """Save the working database to disk as a SQLite DB file."""
        self.logger.info("[+] Saving working data to disk as a SQLite DB")
        on_disk_db = sqlite3.connect(db_filename)
        self.db_connection.backup(on_disk_db)
        on_disk_db.close()

    def execute_rule(self, rule):
        """Execute a single Sigma rule against the database and return the results."""
        # Fast path: check for required key first
        sigma_queries = rule.get("rule")
        if sigma_queries is None:
            self.logger.debug("RULE FORMAT ERROR: 'rule' key missing")
            return {}

        # Pre-allocate list with estimated capacity
        filtered_rows = []
        filtered_rows_extend = filtered_rows.extend  # Cache method reference
        csv_mode = self.csv_mode  # Cache instance variable
        execute_select = self.execute_select_query  # Cache method reference

        # Process each SQL query in the rule
        for sql_query in sigma_queries:
            data = execute_select(sql_query)
            if data:
                if csv_mode:
                    # Clean values for CSV output
                    cleaned_rows = [
                        {
                            k: ("" if v is None else str(v)).replace("\n", "").replace("\r", "")
                            for k, v in row.items()
                        }
                        for row in data
                    ]
                else:
                    # Remove None values - already dicts from execute_select_query
                    cleaned_rows = [
                        {k: v for k, v in row.items() if v is not None}
                        for row in data
                    ]
                filtered_rows_extend(cleaned_rows)

        if not filtered_rows:
            return {}

        # Extract rule metadata only when we have results (avoid work for non-matching rules)
        rule_get = rule.get  # Cache method
        title = rule_get("title", "Unnamed Rule")
        description = rule_get("description", "")
        
        results = {
            "title": title,
            "id": rule_get("id", ""),
            "description": description.replace("\n", "").replace("\r", "") if csv_mode else description,
            "sigmafile": rule_get("filename", ""),
            "sigma": sigma_queries,
            "rule_level": rule_get("level", "unknown"),
            "tags": rule_get("tags", []),
            "count": len(filtered_rows),
            "matches": filtered_rows
        }
        self.logger.debug(f'DETECTED: {title} - Matches: {len(filtered_rows)} events')
        return results

    def load_ruleset_from_file(self, filename, rule_filters):
        """Load a ruleset from a JSON file."""
        try:
            with open(filename, encoding='utf-8') as f:
                self.ruleset = json.loads(f.read())
            self.apply_ruleset_filters(rule_filters)
        except Exception as e:
            self.logger.error(f"[red]   [-] Loading JSON ruleset failed, are you sure it is a valid JSON file ? : {e}[/]")

    def load_ruleset_from_var(self, ruleset, rule_filters):
        """Load a ruleset from a variable."""
        self.ruleset = ruleset
        self.apply_ruleset_filters(rule_filters)
    
    def apply_ruleset_filters(self, rule_filters=None):
        """Remove empty rules and filtered rules from the ruleset."""
        self.ruleset = list(filter(None, self.ruleset))
        if rule_filters is not None:
            self.ruleset = [rule for rule in self.ruleset if not any(rule_filter in rule["title"] for rule_filter in rule_filters)]

    def rule_level_print_formatter(self, level, org_style="cyan"):
        """Format rule level for colored output using Rich markup."""
        style = self._level_format_map.get(level.lower())
        if style is not None:
            return f'[{style}]{level}[/][{org_style}]'
        return f'{level}'

    def _write_result_to_output(self, rule_results, file_handle, csv_writer, needs_comma_prefix):
        """Write rule results to output file. Returns (csv_writer, needs_comma_prefix)."""
        if self.csv_mode:
            # Initialize CSV writer if not already done
            if csv_writer is None:
                fieldnames = ["rule_title", "rule_description", "rule_level", "rule_count"] + list(rule_results["matches"][0].keys())
                csv_writer = csv.DictWriter(file_handle, delimiter=self.delimiter, fieldnames=fieldnames)
                csv_writer.writeheader()
            # Write matches to CSV - pre-compute common values
            title = rule_results["title"]
            description = rule_results["description"]
            level = rule_results["rule_level"]
            count = rule_results["count"]
            for data in rule_results["matches"]:
                dict_csv = {
                    "rule_title": title,
                    "rule_description": description,
                    "rule_level": level,
                    "rule_count": count,
                    **data
                }
                csv_writer.writerow(dict_csv)
        else:
            # Write results as JSON using orjson
            try:
                # Handle commas between JSON objects
                if needs_comma_prefix and self.first_json_output:
                    file_handle.write(',\n')
                    self.first_json_output = False
                    needs_comma_prefix = False
                elif not self.first_json_output:
                    file_handle.write(',\n')
                else:
                    self.first_json_output = False
                # Serialize rule_results to JSON bytes with indentation
                json_bytes = json.dumps(rule_results, option=json.OPT_INDENT_2)
                file_handle.write(json_bytes.decode('utf-8'))
            except Exception as e:
                self.logger.error(f"[error]   [-] Error saving some results: {e}[/]")
        return csv_writer, needs_comma_prefix

    def execute_ruleset(self, out_file, write_mode='w',
                    keep_results=False, last_ruleset=False, source_label=None,
                    show_table=True):
        """Execute all rules in the ruleset and handle output."""
        csv_writer = None
        is_json_mode = not self.csv_mode

        # Prepare output file handle if needed
        file_handle = None
        needs_comma_prefix = False
        if not self.no_output:
            # For append mode in JSON, check if file exists and has content
            if is_json_mode and write_mode == 'a' and Path(out_file).exists():
                with open(out_file, 'r', encoding='utf-8') as f:
                    content = f.read().rstrip()
                    if content and not content.endswith('[') and not content.endswith(','):
                        # Remove closing bracket if present, we'll add it back at the end
                        if content.endswith(']'):
                            content = content[:-1].rstrip()
                            with open(out_file, 'w', encoding='utf-8') as f:
                                f.write(content)
                        needs_comma_prefix = True
            
            # Open file in text mode since we will write decoded strings
            file_handle = open(out_file, write_mode, encoding='utf-8', newline='')
            if is_json_mode and write_mode != 'a':
                file_handle.write('[')  # Start JSON array

        try:
            # Cache frequently accessed attributes and methods
            execute_rule = self.execute_rule
            limit = self.limit
            no_output = self.no_output
            full_results_append = self.full_results.append

            # Collect all results for sorting by level
            all_rule_results = []

            # Create Rich progress bar for rule execution
            if self.disable_progress:
                # Process without progress bar
                for rule in self.ruleset:
                    # Execute the rule
                    rule_results = execute_rule(rule)
                    if not rule_results:
                        continue  # No matches, skip to next rule

                    # Apply limit if set
                    if limit != -1 and rule_results["count"] > limit:
                        continue  # Exceeds limit, skip this result

                    # Collect results for later display (sorted by level)
                    all_rule_results.append({
                        "title": rule_results.get("title", "Unknown"),
                        "rule_level": rule_results.get("rule_level", "unknown"),
                        "count": rule_results.get("count", 0),
                        "tags": rule_results.get("tags", [])
                    })

                    # Store results if needed
                    if keep_results:
                        full_results_append(rule_results)

                    # Handle output to file
                    if not no_output:
                        csv_writer, needs_comma_prefix = self._write_result_to_output(
                            rule_results, file_handle, csv_writer, needs_comma_prefix
                        )
            else:
                # Process with Rich Live display: progress bar + live detection counter
                detection_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
                
                progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    MofNCompleteColumn(),
                    TextColumn("•"),
                    TimeElapsedColumn(),
                )
                
                task_id = progress.add_task("Executing rules", total=len(self.ruleset))
                
                with Live(console=console, refresh_per_second=10, transient=True) as live:
                    for rule in self.ruleset:
                        # Execute the rule
                        rule_results = execute_rule(rule)
                        progress.advance(task_id)
                        
                        if rule_results:
                            # Apply limit if set
                            if limit != -1 and rule_results["count"] > limit:
                                pass  # Exceeds limit, skip this result
                            else:
                                # Collect results for later display (sorted by level)
                                all_rule_results.append({
                                    "title": rule_results.get("title", "Unknown"),
                                    "rule_level": rule_results.get("rule_level", "unknown"),
                                    "count": rule_results.get("count", 0),
                                    "tags": rule_results.get("tags", [])
                                })

                                # Update live detection counts
                                det_level = rule_results.get("rule_level", "unknown").lower()
                                if det_level in detection_counts:
                                    detection_counts[det_level] += 1

                                # Store results if needed
                                if keep_results:
                                    full_results_append(rule_results)

                                # Handle output to file
                                if not no_output:
                                    csv_writer, needs_comma_prefix = self._write_result_to_output(
                                        rule_results, file_handle, csv_writer, needs_comma_prefix
                                    )
                        
                        # Update live display with progress + detection counter
                        live.update(Group(progress, make_detection_counter(detection_counts)))

            # Sort results by level priority, then by count (descending)
            def sort_key(result):
                level = result.get("rule_level", "unknown").lower()
                priority = LEVEL_PRIORITY.get(level, 5)  # Unknown levels at the end
                return (priority, -result.get("count", 0))  # Negative count for descending
            
            all_rule_results.sort(key=sort_key)
            
            # Display sorted results as a table (suppressed in quiet mode or when show_table=False)
            if show_table and not is_quiet() and all_rule_results:
                console.print()
                console.print(build_detection_table(all_rule_results, title=source_label))
                console.print()
        finally:
            # Close output file handle if needed (always run, including on exception)
            if file_handle is not None:
                if is_json_mode and last_ruleset:
                    file_handle.write(']')  # Close JSON array
                file_handle.close()

    def run_streaming(self, log_files: list, input_type: str = 'evtx', 
                      args_config=None, extractor: Optional['EvtxExtractor'] = None,
                      disable_progress: bool = False,
                      event_filter: 'Optional[EventFilter]' = None,
                      return_filtered_count: bool = False,
                      keepflat_file=None,
                      _raw_config: Optional[dict] = None) -> 'int | tuple[int, int]':
        """
        Process log files using streaming mode - single-pass extraction, flattening, and DB insertion.
        
        Features:
        - Eliminates intermediate JSON file I/O
        - Avoids double JSON parsing
        - Processes events in a streaming fashion
        - Uses dynamic schema discovery
        - Supports early event filtering based on channel/eventID
        - Optional keepflat: writes flattened events to a caller-managed file handle
        
        Args:
            log_files: List of log files to process
            input_type: Type of input ('evtx', 'json', 'json_array', 'xml', 'sysmon_linux', 'auditd')
            args_config: Argument configuration namespace
            extractor: EvtxExtractor instance (required for xml, sysmon_linux, auditd)
            disable_progress: Whether to disable progress bars
            event_filter: Optional EventFilter for early event filtering based on channel/eventID
            return_filtered_count: If True, return (total_events, filtered_count) tuple
            keepflat_file: Open binary file handle to write flattened JSONL events to (caller
                          is responsible for opening and closing the file)
            _raw_config: Pre-parsed field-mappings dict passed through to
                        StreamingEventProcessor to skip redundant config reads.
            
        Returns:
            Total number of events processed, or (total_events, filtered_count) if return_filtered_count=True
        """
        self.logger.info("[+] Processing events (streaming mode)")
        
        # Determine if JSON array mode
        json_array = False
        if args_config and hasattr(args_config, 'json_array_input'):
            json_array = args_config.json_array_input
        
        # Create streaming processor with ProcessingConfig
        proc_config = ProcessingConfig(
            time_after=self.time_after,
            time_before=self.time_before,
            time_field=self.time_field,
            hashes=self.hashes,
            disable_progress=disable_progress or self.disable_progress
        )
        processor = StreamingEventProcessor(
            config_file=self.config,
            args_config=args_config,
            processing_config=proc_config,
            logger=self.logger,
            event_filter=event_filter,
            _raw_config=_raw_config,
        )
        
        # Create initial table structure
        self.logger.info("[+] Creating dynamic model")
        processor.create_initial_table(self.db_connection)
        
        # Process each file
        total_events = 0

        def process_single_file(log_file, progress_cb=None):
            """Process a single log file and return event count."""
            nonlocal total_events
            try:
                file_size = os.path.getsize(log_file)
                if file_size == 0:
                    return 0
                
                # Map input type to streaming method parameter
                stream_input_type = input_type
                local_json_array = json_array
                if input_type == 'json_array':
                    stream_input_type = 'json'
                    local_json_array = True
                
                event_count = processor.process_file_streaming(
                    self.db_connection,
                    str(log_file),
                    input_type=stream_input_type,
                    extractor=extractor,
                    json_array=local_json_array,
                    keepflat_file=keepflat_file,
                    progress_callback=progress_cb,
                )
                return event_count
                    
            except Exception as e:
                self.logger.error(f"[error]   [-] Error processing {log_file}: {e}[/]")
                return 0
        
        show_progress = not is_quiet()
        if show_progress:
            if disable_progress:
                progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    TextColumn("\u2022"),
                    TextColumn("[magenta]{task.fields[events]:,}[/] events"),
                    TextColumn("\u2022"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                )
                with progress:
                    task_id = progress.add_task("Streaming", total=None, events=0)

                    def _streaming_cb_lite(event_count):
                        progress.update(task_id, events=total_events + event_count)

                    for log_file in log_files:
                        event_count = process_single_file(log_file, progress_cb=_streaming_cb_lite)
                        total_events += event_count
                        progress.update(task_id, events=total_events)
            else:
                progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    MofNCompleteColumn(),
                    TextColumn("\u2022"),
                    TextColumn("[magenta]{task.fields[events]:,}[/] events"),
                    TextColumn("\u2022"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                )
                with progress:
                    task_id = progress.add_task("Processing files", total=len(log_files), events=0)

                    def _streaming_progress_cb(event_count):
                        progress.update(task_id, events=total_events + event_count)

                    for log_file in log_files:
                        event_count = process_single_file(log_file, progress_cb=_streaming_progress_cb)
                        total_events += event_count
                        progress.update(task_id, advance=1, events=total_events)
        else:
            for log_file in log_files:
                total_events += process_single_file(log_file)
        # Create index after all data is inserted
        self.logger.info("[+] Creating indexes")
        self.create_index()
        
        # Log filtered events statistics
        filtered_count = processor.events_filtered_count
        if filtered_count > 0:
            self.logger.info(
                f"[+] Total events processed: [magenta]{total_events:,}[/] "
                f"([dim]{filtered_count:,} events filtered out[/])"
            )
        else:
            self.logger.info(f"[+] Total events processed: [magenta]{total_events:,}[/]")
        
        if return_filtered_count:
            return total_events, filtered_count
        return total_events
