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
import time as _time_module
from functools import lru_cache
from pathlib import Path
from sqlite3 import Error
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, Union

import orjson as json

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
)
from rich.syntax import Syntax

from .config import ProcessingConfig
from .console import (
    LEVEL_PRIORITY,
    build_detection_table,
    console,
    is_quiet,
    make_detection_counter,
)
from .streaming import StreamingEventProcessor
from .utils import sanitize_row_for_csv

# ---------------------------------------------------------------------------
# LRU-cached regex compilation for the SQLite ``regexp`` UDF.
# SIGMA rules reuse the same patterns across thousands of rows; caching the
# compiled objects avoids redundant ``re.compile`` calls per row.
# ---------------------------------------------------------------------------
@lru_cache(maxsize=512)
def _compile_regex(pattern: str) -> re.Pattern:
    """Return a compiled regex, cached for repeated use by the SQLite UDF."""
    return re.compile(pattern)


if TYPE_CHECKING:
    from .extractor import EvtxExtractor
    from .rules import EventFilter


class ZircoliteCore:
    """Load data into database and apply detection rules."""

    # Use __slots__ for reduced memory footprint per instance
    __slots__ = (
        "logger",
        "db_connection",
        "full_results",
        "ruleset",
        "no_output",
        "time_after",
        "time_before",
        "config",
        "limit",
        "csv_mode",
        "time_field",
        "hashes",
        "delimiter",
        "first_json_output",
        "disable_progress",
        "_escape_cache",
        "_cursor",
        "profile_rules",
        "_profiling_data",
        "archive_password",
        "add_index",
        "remove_index",
    )
    _cursor: Optional[sqlite3.Cursor]

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
        self.profile_rules = proc.profile_rules
        self._profiling_data: dict = {}
        self.archive_password = proc.archive_password
        self.add_index = list(proc.add_index) if proc.add_index else []
        self.remove_index = list(proc.remove_index) if proc.remove_index else []
        # Cache for escaped identifiers to avoid repeated string operations
        self._escape_cache: dict = {}
        # Reusable cursor to avoid creating new cursors for each query
        self._cursor = None
    
    def close(self) -> None:
        """Close the database connection. Safe to call multiple times."""
        self._cursor = None
        conn = self.db_connection
        if conn is not None:
            conn.close()
            self.db_connection = None

    def __del__(self) -> None:
        """Ensure connection is closed when the instance is garbage-collected."""
        conn = getattr(self, "db_connection", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self.db_connection = None
        self._cursor = None

    def _get_cursor(self) -> sqlite3.Cursor:
        """Get a reusable cursor for better performance."""
        if self._cursor is not None:
            return self._cursor
        if self.db_connection is None:
            raise RuntimeError("No database connection")
        self._cursor = self.db_connection.cursor()
        return self._cursor

    def create_connection(self, db: str) -> Optional[sqlite3.Connection]:
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
            
            # Raw tuples; we build dicts with None filtered in execute_select_query
            conn.row_factory = None

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
            self.logger.error(f"[red]    [-] {e}[/]")
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

    def create_db(self, field_stmt: str) -> None:
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
            raise RuntimeError("Unable to create database table")

    def _get_table_columns(self) -> List[str]:
        """Return the list of column names for the logs table."""
        cursor = self._get_cursor()
        cursor.execute('PRAGMA table_info("logs")')
        return [row[1] for row in cursor.fetchall()]

    def create_index(self) -> None:
        """Create standard and optional indexes; drop any requested by remove_index."""
        columns = self._get_table_columns()
        cursor = self._get_cursor()

        self.execute_query('CREATE INDEX "idx_eventid" ON "logs" ("eventid");')

        if "Channel" in columns:
            try:
                cursor.execute('CREATE INDEX "idx_channel" ON "logs" ("Channel");')
                self.db_connection.commit()
            except sqlite3.OperationalError:
                pass

        for col in self.add_index:
            if col not in columns:
                self.logger.debug("Column %s not present; skipping index", col)
                continue
            idx_name = "idx_" + col.replace(".", "_")
            q_idx = self.escape_identifier(idx_name)
            q_col = self.escape_identifier(col)
            try:
                cursor.execute(f'CREATE INDEX "{q_idx}" ON "logs" ("{q_col}");')
                self.db_connection.commit()
            except sqlite3.OperationalError as e:
                self.logger.debug("Could not create index on %s: %s", col, e)

        for idx_name in self.remove_index:
            q_idx = self.escape_identifier(idx_name)
            try:
                cursor.execute(f'DROP INDEX IF EXISTS "{q_idx}";')
                self.db_connection.commit()
            except sqlite3.OperationalError as e:
                self.logger.debug("Could not drop index %s: %s", idx_name, e)

    def execute_query(self, query: str) -> bool:
        """Perform a SQL query with the provided connection."""
        if self.db_connection is not None:
            self.logger.debug(f"EXECUTING : {query}")
            try:
                self._get_cursor().execute(query)
                self.db_connection.commit()
                return True
            except Error as e:
                self.logger.debug(f"    [-] {e}")
                return False
        else:
            self.logger.error("[error]    [-] No connection to Db[/]")
            return False

    def execute_select_query(self, query: str) -> List[Dict[str, Any]]:
        """Execute a SELECT SQL query and return the results as a list of dictionaries."""
        if self.db_connection is None:
            self.logger.error("[error]    [-] No connection to Db[/]")
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
            rows = cursor.fetchall()
            if not rows:
                return []
            col_names = [d[0] for d in cursor.description]
            return [
                {k: v for k, v in zip(col_names, row) if v is not None}
                for row in rows
            ]
        except sqlite3.Error as e:
            self.logger.debug(f"    [-] SQL query error: {e}")
            return []

    def load_db_in_memory(self, db: str) -> None:
        """In db-only mode, restore an on-disk database to avoid EVTX extraction and flattening."""
        try:
            db_file_connection = sqlite3.connect(db, check_same_thread=False)
            db_file_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Error as e:
            raise RuntimeError(f"Could not connect to database: {db} ({e})") from e
        if self.db_connection is None:
            raise RuntimeError("No main database connection")
        try:
            db_file_connection.backup(self.db_connection)
        finally:
            db_file_connection.close()

    def escape_identifier(self, identifier: str) -> str:
        """Escape SQL identifiers like table or column names with caching."""
        # Check cache first for frequently used identifiers
        escaped = self._escape_cache.get(identifier)
        if escaped is None:
            escaped = identifier.replace("\"", "\"\"")
            self._escape_cache[identifier] = escaped
        return escaped

    def insert_data_to_db(self, data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> bool:
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
            self.logger.debug("    [-] Data must be a dictionary or a list of dictionaries")
            return False

        # To optimize, we group by the exact set of columns.
        # In most cases, a batch has homogeneous keys.
        # If keys vary, we process them in sub-batches.

        conn = self.db_connection
        if conn is None:
            return False

        try:
            conn.execute('BEGIN TRANSACTION')

            # Group rows by their column signatures
            batches_by_columns: Dict[Tuple[str, ...], List[Dict[str, Any]]] = {}
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
                
                conn.executemany(insert_stmt, values_list)

            conn.execute('COMMIT')
            return True
        except Exception as e:
            conn.execute('ROLLBACK')
            self.logger.debug(f"    [-] {e}")
            return False

    def save_db_to_disk(self, db_filename: str) -> None:
        """Save the working database to disk as a SQLite DB file."""
        self.logger.info("[+] Saving working data to disk as a SQLite DB")
        if self.db_connection is None:
            raise RuntimeError("No database connection")
        if Path(db_filename).exists():
            raise FileExistsError(
                f"Database file '{db_filename}' already exists. "
                f"Remove it first or choose a different path."
            )
        on_disk_db = sqlite3.connect(db_filename)
        self.db_connection.backup(on_disk_db)
        on_disk_db.execute("PRAGMA journal_mode = DELETE")
        on_disk_db.close()

    def execute_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single Sigma rule against the database and return the results."""
        # Fast path: check for required key first
        sigma_queries = rule.get("rule")
        if sigma_queries is None:
            self.logger.debug("RULE FORMAT ERROR: 'rule' key missing")
            return {}

        # Pre-allocate list with estimated capacity
        filtered_rows: List[Dict[str, Any]] = []
        filtered_rows_extend = filtered_rows.extend  # Cache method reference
        csv_mode = self.csv_mode  # Cache instance variable
        execute_select = self.execute_select_query  # Cache method reference

        # Process each SQL query in the rule
        for sql_query in sigma_queries:
            data = execute_select(sql_query)
            if data:
                if csv_mode:
                    cleaned_rows = [sanitize_row_for_csv(row) for row in data]
                else:
                    cleaned_rows = data
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

    def load_ruleset_from_file(
        self, filename: str, rule_filters: Optional[List[str]]
    ) -> None:
        """Load a ruleset from a JSON file."""
        try:
            with open(filename, encoding='utf-8') as f:
                self.ruleset = json.loads(f.read())
            self.apply_ruleset_filters(rule_filters)
        except Exception as e:
            self.logger.error(f"[red]    [-] Loading JSON ruleset failed, are you sure it is a valid JSON file ? : {e}[/]")

    def load_ruleset_from_var(
        self, ruleset: List[Dict[str, Any]], rule_filters: Optional[List[str]]
    ) -> None:
        """Load a ruleset from a variable."""
        self.ruleset = ruleset
        self.apply_ruleset_filters(rule_filters)
    
    def apply_ruleset_filters(
        self, rule_filters: Optional[List[str]] = None
    ) -> None:
        """Remove empty rules and filtered rules from the ruleset."""
        self.ruleset = list(filter(None, self.ruleset))
        if rule_filters is not None:
            self.ruleset = [rule for rule in self.ruleset if not any(rule_filter in rule.get("title", "") for rule_filter in rule_filters)]

    def _write_result_to_output(
        self,
        rule_results: Dict[str, Any],
        file_handle: Any,
        csv_writer: Optional[Any],
        needs_comma_prefix: bool,
    ) -> Tuple[Optional[Any], bool]:
        """Write rule results to output file. Returns (csv_writer, needs_comma_prefix).

        In CSV mode, the writer is created once with fieldnames from the first match row
        (plus rule metadata columns). Later rules may return wider rows; keys not in that
        header are omitted, unlike JSON where each rule is serialized in full. See
        docs/Usage.md (section CSV detection output).
        """
        if self.csv_mode:
            # Initialize CSV writer if not already done
            if csv_writer is None:
                fieldnames = ["rule_title", "rule_description", "rule_level", "rule_count"] + list(rule_results["matches"][0].keys())
                csv_writer = csv.DictWriter(
                    file_handle,
                    delimiter=self.delimiter,
                    fieldnames=fieldnames,
                    extrasaction="ignore",
                )
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
                self.logger.error(f"[error]    [-] Error saving some results: {e}[/]")
        return csv_writer, needs_comma_prefix

    def execute_ruleset(
        self,
        out_file: str,
        write_mode: str = "w",
        keep_results: bool = False,
        last_ruleset: bool = False,
        source_label: Optional[str] = None,
        show_table: bool = True,
        disable_progress: Optional[bool] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """Execute all rules in the ruleset and handle output."""
        csv_writer = None
        is_json_mode = not self.csv_mode
        _disable = disable_progress if disable_progress is not None else self.disable_progress

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

            # Cache profiling flag locally for the inner loop
            _profile = self.profile_rules
            _profiling_data = self._profiling_data
            _perf_counter = _time_module.perf_counter
            total_rules = len(self.ruleset)

            if progress_callback is not None:
                progress_callback(0, total_rules)
                for i, rule in enumerate(self.ruleset):
                    if _profile:
                        _t0 = _perf_counter()
                    rule_results = execute_rule(rule)
                    if _profile:
                        _title = rule.get('title', 'unknown')
                        _profiling_data[_title] = _profiling_data.get(_title, 0.0) + (_perf_counter() - _t0) * 1000
                    progress_callback(i + 1, total_rules)
                    if not rule_results:
                        continue
                    if limit != -1 and rule_results["count"] > limit:
                        continue
                    all_rule_results.append({
                        "title": rule_results.get("title", "Unknown"),
                        "rule_level": rule_results.get("rule_level", "unknown"),
                        "count": rule_results.get("count", 0),
                        "tags": rule_results.get("tags", [])
                    })
                    if keep_results:
                        full_results_append(rule_results)
                    if not no_output:
                        csv_writer, needs_comma_prefix = self._write_result_to_output(
                            rule_results, file_handle, csv_writer, needs_comma_prefix
                        )
            elif _disable:
                for rule in self.ruleset:
                    if _profile:
                        _t0 = _perf_counter()
                    rule_results = execute_rule(rule)
                    if _profile:
                        _title = rule.get('title', 'unknown')
                        _profiling_data[_title] = _profiling_data.get(_title, 0.0) + (_perf_counter() - _t0) * 1000
                    if not rule_results:
                        continue
                    if limit != -1 and rule_results["count"] > limit:
                        continue
                    all_rule_results.append({
                        "title": rule_results.get("title", "Unknown"),
                        "rule_level": rule_results.get("rule_level", "unknown"),
                        "count": rule_results.get("count", 0),
                        "tags": rule_results.get("tags", [])
                    })
                    if keep_results:
                        full_results_append(rule_results)
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
                        if _profile:
                            _t0 = _perf_counter()
                        rule_results = execute_rule(rule)
                        if _profile:
                            _title = rule.get('title', 'unknown')
                            _profiling_data[_title] = _profiling_data.get(_title, 0.0) + (_perf_counter() - _t0) * 1000
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

    def run_rule_tests(self, test_file: str) -> list:
        """Validate rules against known-positive and known-negative events.

        The test file is a JSON array where each element contains:
        - ``title`` or ``id``: matched against the loaded ruleset
        - ``true_positive``: list of event dicts that MUST trigger the rule
        - ``true_negative``: list of event dicts that MUST NOT trigger the rule

        Returns a list of result dicts with keys:
        ``title``, ``id``, ``tp_pass``, ``tn_pass``, ``tp_count``, ``tn_count``, ``error``
        """
        try:
            with open(test_file, encoding='utf-8') as f:
                test_cases = json.loads(f.read())
        except Exception as e:
            self.logger.error(f"[red]    [-] Cannot load rule test file: {e}[/]")
            return []

        if not isinstance(test_cases, list):
            self.logger.error("[red]    [-] Rule test file must be a JSON array[/]")
            return []

        # Index test cases by title and id for fast lookup
        by_title = {tc.get('title', ''): tc for tc in test_cases if tc.get('title')}
        by_id = {tc.get('id', ''): tc for tc in test_cases if tc.get('id')}

        results = []
        for rule in self.ruleset:
            title = rule.get('title', '')
            rule_id = rule.get('id', '')
            tc = by_title.get(title) or by_id.get(rule_id)
            if tc is None:
                results.append({
                    'title': title, 'id': rule_id,
                    'tp_pass': None, 'tn_pass': None,
                    'tp_count': 0, 'tn_count': 0,
                    'error': 'no test case',
                })
                continue

            tp_events = tc.get('true_positive', [])
            tn_events = tc.get('true_negative', [])
            tp_pass = True
            tn_pass = True
            tp_count = 0
            tn_count = 0
            error = ''

            try:
                # Run true-positive check
                if tp_events:
                    all_keys: set = set()
                    for ev in tp_events:
                        all_keys.update(ev.keys())
                    tp_core = ZircoliteCore(
                        self.config,
                        processing_config=None,  # defaults
                        logger=self.logger,
                    )
                    tp_core.create_db(
                        ', '.join(f'"{k}" TEXT' for k in sorted(all_keys))
                    )
                    tp_core.insert_data_to_db(tp_events)
                    tp_res = tp_core.execute_rule(rule)
                    tp_count = tp_res.get('count', 0) if tp_res else 0
                    tp_pass = tp_count > 0
                    tp_core.close()

                # Run true-negative check
                if tn_events:
                    all_keys = set()
                    for ev in tn_events:
                        all_keys.update(ev.keys())
                    tn_core = ZircoliteCore(
                        self.config,
                        processing_config=None,
                        logger=self.logger,
                    )
                    tn_core.create_db(
                        ', '.join(f'"{k}" TEXT' for k in sorted(all_keys))
                    )
                    tn_core.insert_data_to_db(tn_events)
                    tn_res = tn_core.execute_rule(rule)
                    tn_count = tn_res.get('count', 0) if tn_res else 0
                    tn_pass = tn_count == 0
                    tn_core.close()

            except Exception as exc:
                error = str(exc)
                tp_pass = False
                tn_pass = False

            results.append({
                'title': title, 'id': rule_id,
                'tp_pass': tp_pass, 'tn_pass': tn_pass,
                'tp_count': tp_count, 'tn_count': tn_count,
                'error': error,
            })

        return results

    def get_profiling_report(self) -> list:
        """Return rule timing data sorted by elapsed time (descending).

        Each entry is a dict with keys: ``title``, ``elapsed_ms``.
        Only populated when ``profile_rules=True`` was set at construction.
        """
        return sorted(
            [{"title": t, "elapsed_ms": ms} for t, ms in self._profiling_data.items()],
            key=lambda r: r["elapsed_ms"],
            reverse=True,
        )

    def merge_profiling_data(self, other: "ZircoliteCore") -> None:
        """Merge another core's rule timing data into this core (additive by rule title)."""
        for title, ms in other._profiling_data.items():
            self._profiling_data[title] = self._profiling_data.get(title, 0.0) + ms

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
            disable_progress=disable_progress or self.disable_progress,
            archive_password=self.archive_password,
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
                self.logger.error(f"[error]    [-] Error processing {log_file}: {e}[/]")
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
