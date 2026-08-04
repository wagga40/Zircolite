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
from collections.abc import Callable
from contextlib import nullcontext, suppress
from functools import lru_cache
from pathlib import Path
from sqlite3 import Error
from typing import TYPE_CHECKING, Any, Optional

import orjson as json
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.syntax import Syntax

from .config import ProcessingConfig
from .console import (
    build_detection_table,
    console,
    is_quiet,
    make_detection_counter,
    sort_key_severity,
)
from .formats import json_array_requested
from .shutdown import is_shutdown_requested
from .sqlscan import rebalance_sql, scan_query
from .streaming import StreamingEventProcessor, StrictParseError
from .utils import sanitize_row_for_csv

# Translation table for stripping newline characters from CSV descriptions.
_NEWLINE_TRANSLATE = str.maketrans("", "", "\n\r")

# SQLite reports one missing column at a time, quoted or bare.
_MISSING_COLUMN_RE = re.compile(r"no such column", re.IGNORECASE)

# Raised while parsing when a rule's value list is deeper than
# SQLITE_MAX_EXPR_DEPTH; see zircolite/sqlscan.py for the repair.
_DEPTH_LIMIT_RE = re.compile(r"expression tree is too large", re.IGNORECASE)

# ---------------------------------------------------------------------------
# LRU-cached regex compilation for the SQLite ``regexp`` UDF.
# SIGMA rules reuse the same patterns across thousands of rows; caching the
# compiled objects avoids redundant ``re.compile`` calls per row.
# ---------------------------------------------------------------------------
@lru_cache(maxsize=512)
def _compile_regex(pattern: str) -> re.Pattern:
    """Return a compiled regex, cached for repeated use by the SQLite UDF."""
    return re.compile(pattern)


# Rebalancing a 350 KB rule takes ~100 ms, and per-file and parallel modes run
# the same ruleset once per input file. Only a handful of rules ever reach here.
@lru_cache(maxsize=32)
def _rebalance_cached(query: str) -> str:
    """Return the depth-repaired form of ``query``, memoised across files."""
    return rebalance_sql(query)


def _uncompilable_regex(query: str) -> str | None:
    """Why ``query``'s REGEXP patterns cannot compile, or None if they all can.

    SIGMA rules are written against PCRE, so a pattern can use a construct
    Python's ``re`` rejects -- ``\\p{L}``, a possessive quantifier, a mistyped
    ``(?<name>)``. Discovering that inside the UDF means discovering it once per
    row, with nowhere to report it; the rule then looks like a clean non-match.

    Uncached on purpose. ``scan_query`` already memoises the pattern list, and
    the overwhelming majority of rules carry no REGEXP at all, so what is left
    here is a loop over an empty tuple.
    """
    for pattern in scan_query(query).regex_patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            return f"invalid regex {pattern!r}: {exc}"
    return None


def _index_name_for(column: str) -> str:
    """Index name Zircolite gives a column, as accepted by --remove-index."""
    return "idx_" + column.replace(".", "_")


if TYPE_CHECKING:
    from .extractor import EvtxExtractor
    from .rules import EventFilter


class ZircoliteCore:
    """Load data into database and apply detection rules."""

    # Use __slots__ for reduced memory footprint per instance
    __slots__ = (
        "_auto_index_applied",
        "_csv_fieldnames",
        "_csv_header_written",
        "_cursor",
        "_escape_cache",
        "_logs_columns_lower",
        "_profiling_data",
        "add_index",
        "archive_password",
        "auto_index_top_n",
        "batch_size",
        "config",
        "csv_mode",
        "db_connection",
        "delimiter",
        "disable_progress",
        "failed_files",
        "first_json_output",
        "full_results",
        "hashes",
        "limit",
        "logger",
        "no_output",
        "profile_rules",
        "remove_index",
        "rules_in_error",
        "ruleset",
        "strict_evtx",
        "time_after",
        "time_before",
        "time_field",
    )
    _cursor: sqlite3.Cursor | None
    db_connection: sqlite3.Connection | None

    def __init__(
        self,
        config: str,
        processing_config: ProcessingConfig | None = None,
        *,
        logger: logging.Logger | None = None
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
        # Track the CSV header and its fieldnames across execute_ruleset calls:
        # append flows re-enter with a fresh local writer, and rows must stay
        # aligned with the header written on the first call
        self._csv_header_written = False
        self._csv_fieldnames: list[str] | None = None
        self.disable_progress = proc.disable_progress
        self.profile_rules = proc.profile_rules
        self._profiling_data: dict = {}
        self.archive_password = proc.archive_password
        self.batch_size = proc.batch_size
        self.add_index = list(proc.add_index) if proc.add_index else []
        self.remove_index = list(proc.remove_index) if proc.remove_index else []
        self.auto_index_top_n = max(0, int(proc.auto_index_top_n or 0))
        self._auto_index_applied = False
        self.strict_evtx = proc.strict_evtx
        # Rules whose SQL cannot run at all, by title: reported once, then counted
        # in the summary so a broken rule is never mistaken for a quiet one
        self.rules_in_error: dict[str, str] = {}
        # Inputs that raised during ingestion; --remove-events must not
        # delete a source whose events never made it into the results
        self.failed_files: set[str] = set()
        # Lowercased logs columns; rebuilt on demand, dropped on any schema change
        self._logs_columns_lower: set[str] | None = None
        # Cache for escaped identifiers to avoid repeated string operations
        self._escape_cache: dict = {}
        # Reusable cursor to avoid creating new cursors for each query
        self._cursor = None

    def close(self) -> None:
        """Close the database connection. Safe to call multiple times."""
        self._cursor = None
        self._logs_columns_lower = None
        conn = self.db_connection
        if conn is not None:
            conn.close()
            self.db_connection = None

    def __del__(self) -> None:
        """Ensure connection is closed when the instance is garbage-collected."""
        conn = getattr(self, "db_connection", None)
        if conn is not None:
            with suppress(Exception):
                conn.close()
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

    def create_connection(self, db: str) -> sqlite3.Connection:
        """Create a database connection to a SQLite database.

        Raises:
            RuntimeError: If the underlying sqlite3 driver reports an error
                while opening the connection or applying PRAGMAs.
        """
        conn = None
        self.logger.debug(f"CONNECTING TO : {db}")
        try:
            # Connect to database
            conn = sqlite3.connect(db, isolation_level=None, check_same_thread=False)

            # Configure PRAGMA settings based on database type
            # Common PRAGMA settings for both in-memory and on-disk databases.
            # SQLite's auxiliary worker threads (sorting, index scans) scale with cores,
            # but more than 8 rarely helps and adds context-switch overhead.
            sqlite_threads = min(8, os.cpu_count() or 4)
            common_pragmas = [
                ('temp_store', 'MEMORY'),
                ('mmap_size', '268435456'),        # 256MB memory-mapped I/O
                ('page_size', '4096'),
                ('threads', str(sqlite_threads)),
            ]

            if db == ':memory:':
                # In-memory database settings
                pragmas = [
                    ('journal_mode', 'OFF'),           # No journal needed for in-memory
                    ('synchronous', 'OFF'),
                    ('cache_size', '-128000'),         # 128MB cache
                    ('locking_mode', 'EXCLUSIVE'),     # Single-user mode
                    *common_pragmas,
                ]
            else:
                # On-disk database settings
                pragmas = [
                    ('journal_mode', 'WAL'),           # Write-Ahead Logging
                    ('synchronous', 'NORMAL'),         # Balance safety and speed
                    ('cache_size', '-64000'),          # 64MB cache
                    ('wal_autocheckpoint', '10000'),   # Less frequent checkpoints
                    *common_pragmas,
                ]

            # Apply all PRAGMA settings
            for pragma, value in pragmas:
                conn.execute(f'PRAGMA {pragma} = {value};')

            # Raw tuples; we build dicts with None filtered in execute_select_query
            conn.row_factory = None

            def udf_regex(x, y):
                """User-defined function for regex matching in SQLite.

                Uses LRU-cached compiled patterns to avoid redundant
                re.compile() calls when the same SIGMA rule pattern is
                evaluated against many rows. Patterns that cannot compile are
                caught before the query runs, by ``_uncompilable_regex``.
                """
                if y is None:
                    return 0
                # str(): a column whose first value was an int is typed
                # INTEGER, and re.search would raise TypeError on it --
                # which SQLite reports as a failure of the whole rule.
                return 1 if _compile_regex(x).search(str(y)) else 0

            conn.create_function('regexp', 2, udf_regex)  # Allows to use regex in SQLite
            return conn
        except BaseException as exc:
            # Half-opened connections must not leak, whatever went wrong --
            # including KeyboardInterrupt part-way through the PRAGMAs.
            if conn is not None:
                with suppress(Exception):
                    conn.close()
            if isinstance(exc, Error):
                self.logger.error(f"[red]    [-] {exc}[/]")
                raise RuntimeError(
                    f"Unable to open SQLite database '{db}': {exc}"
                ) from exc
            raise

    def create_db(self, field_stmt: str) -> None:
        """Create the database table with the specified field statement."""
        cleaned_field_stmt = field_stmt.strip()
        cleaned_field_stmt = cleaned_field_stmt.removesuffix(',')
        if cleaned_field_stmt:
            create_table_stmt = f"CREATE TABLE logs ( row_id INTEGER PRIMARY KEY AUTOINCREMENT, {cleaned_field_stmt} );"
        else:
            create_table_stmt = "CREATE TABLE logs ( row_id INTEGER PRIMARY KEY AUTOINCREMENT );"
        self.logger.debug(f" CREATE : {create_table_stmt}")
        if not self.execute_query(create_table_stmt):
            raise RuntimeError("Unable to create database table")

    def reset_logs_table(self) -> None:
        """Drop the logs table so the next file starts from an empty schema.

        ``DELETE FROM logs`` empties the rows but keeps the declaration, and a
        column is typed from the first value ever seen for that field. A field
        that one file carried as a number therefore stayed ``INTEGER`` -- and so
        kept ``BINARY`` collation rather than ``TEXT COLLATE NOCASE`` -- for
        every later file, and a rule comparing it case-insensitively silently
        stopped matching. That is correct for ``--unified-db``, which really is
        one table; per-file mode promises the files are processed separately.

        Dropping the table takes its indexes with it, and the next
        ``run_streaming`` recreates both.
        """
        self._cursor = None
        self._logs_columns_lower = None
        self._auto_index_applied = False
        conn = self.db_connection
        if conn is None:
            return
        try:
            conn.execute("DROP TABLE IF EXISTS logs")
            conn.commit()
        except sqlite3.Error as exc:
            self.logger.debug(f"Could not reset the logs table between files: {exc}")

    def _get_table_columns(self) -> list[str]:
        """Return the list of column names for the logs table."""
        cursor = self._get_cursor()
        cursor.execute('PRAGMA table_info("logs")')
        return [row[1] for row in cursor.fetchall()]

    def _auto_index_candidates(self, columns: list[str]) -> list[str]:
        """Pick the top-N columns referenced by the loaded ruleset.

        Columns already covered by built-in indices (``eventid``, ``Channel``)
        and those queued via ``add_index`` are excluded so the work isn't
        duplicated. Columns whose index name ``remove_index`` drops are
        excluded too, so auto-indexing cannot silently recreate an index the
        user asked for gone. Names are matched case-insensitively against the
        actual table columns.

        Columns are ranked by how many *rules* filter on them, not by how often
        they appear: one rule listing three thousand hashes says no more about
        which index earns its keep than a rule listing one.
        """
        if not self.auto_index_top_n or not self.ruleset:
            return []

        already_indexed_lower = {"eventid", "channel"}
        already_indexed_lower.update(c.lower() for c in self.add_index)
        dropped_lower = {name.lower() for name in self.remove_index}
        columns_by_lower = {c.lower(): c for c in columns}

        counts: dict[str, int] = {}
        for rule in self.ruleset:
            referenced: set[str] = set()
            for sql_query in rule.get("rule", []):
                if isinstance(sql_query, str):
                    referenced |= scan_query(sql_query).columns
            for candidate in referenced:
                if candidate.lower() in already_indexed_lower:
                    continue
                actual = columns_by_lower.get(candidate.lower())
                if actual is None:
                    continue
                if _index_name_for(actual).lower() in dropped_lower:
                    continue
                counts[actual] = counts.get(actual, 0) + 1

        if not counts:
            return []

        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return [col for col, _ in ranked[: self.auto_index_top_n]]

    def create_index(self) -> None:
        """Create standard and optional indexes; drop any requested by remove_index."""
        conn = self.db_connection
        if conn is None:
            self.logger.error("[error]    [-] No connection to Db[/]")
            return
        columns = self._get_table_columns()
        cursor = self._get_cursor()

        # Case-folded like every other column lookup: a dataset whose channel
        # arrives as `winlog.channel` produces a lowercase `channel` column,
        # and an exact-case test would leave it unindexed.
        #
        # Presence is checked here rather than left to SQLite, which accepts
        # `CREATE INDEX ... ON logs ("absent")` by reading the name as a string
        # literal and building an index over a constant -- no error, no use.
        by_lower = {c.lower(): c for c in columns}
        eventid_column = by_lower.get("eventid")
        channel_column = by_lower.get("channel")

        def build(name: str, *cols: str) -> None:
            keys = ", ".join(f'"{self.escape_identifier(c)}"' for c in cols)
            try:
                cursor.execute(f'CREATE INDEX "{name}" ON "logs" ({keys});')
                conn.commit()
            except sqlite3.OperationalError as e:
                self.logger.debug("Could not create index %s: %s", name, e)

        # Kept alongside the composite: a (Channel, …) index cannot serve a rule
        # that names only an eventID, and plenty do.
        if eventid_column is not None:
            build("idx_eventid", eventid_column)

        if channel_column is not None:
            if eventid_column is not None:
                # Composite rather than an index on Channel alone. The Sigma
                # shape is `Channel = … AND EventID = …`, and a channel-only
                # index leaves SQLite fetching and re-checking every row of the
                # channel. Its left prefix still serves the channel-only rules a
                # lone idx_channel did, so this replaces it rather than joining.
                build("idx_channel_eventid", channel_column, eventid_column)
            else:
                build("idx_channel", channel_column)

        self._create_column_indexes(self.add_index, columns)

        for idx_name in self.remove_index:
            q_idx = self.escape_identifier(idx_name)
            try:
                cursor.execute(f'DROP INDEX IF EXISTS "{q_idx}";')
                conn.commit()
            except sqlite3.OperationalError as e:
                self.logger.debug("Could not drop index %s: %s", idx_name, e)

    def apply_auto_index(self) -> None:
        """Create indexes for the top-N rule-referenced columns.

        Called from ``execute_ruleset`` (not ``create_index``) because the
        candidates are derived from the loaded ruleset, which is unavailable
        at the end of ingestion in every processing flow.
        """
        if self._auto_index_applied or not self.auto_index_top_n:
            return
        self._auto_index_applied = True
        if self.db_connection is None:
            return

        columns = self._get_table_columns()
        auto_index_cols = self._auto_index_candidates(columns)
        if not auto_index_cols:
            return

        self.logger.info(
            f"[+] Auto-indexing top [yellow]{len(auto_index_cols)}[/] columns "
            f"from ruleset: [cyan]{', '.join(auto_index_cols)}[/]"
        )
        self._create_column_indexes(auto_index_cols, columns)

    def _create_column_indexes(
        self, cols: list[str], columns: list[str]
    ) -> None:
        """Create one ``idx_<column>`` index per entry of *cols* that exists.

        Matched case-insensitively: the flattened column is whatever spelling
        the events used, so ``--add-index commandline`` against a dataset
        carrying ``CommandLine`` created nothing and said so only at DEBUG.
        """
        if self.db_connection is None:
            return
        by_lower = {c.lower(): c for c in columns}
        cursor = self._get_cursor()
        for requested in cols:
            col = by_lower.get(requested.lower())
            if col is None:
                self.logger.warning(
                    f"[yellow]   [!] Cannot index '{requested}': no such column "
                    "in the ingested events[/]"
                )
                continue
            q_idx = self.escape_identifier(_index_name_for(col))
            q_col = self.escape_identifier(col)
            try:
                cursor.execute(f'CREATE INDEX "{q_idx}" ON "logs" ("{q_col}");')
                self.db_connection.commit()
            except sqlite3.OperationalError as e:
                self.logger.debug("Could not create index on %s: %s", col, e)

    def execute_query(self, query: str) -> bool:
        """Perform a SQL query with the provided connection."""
        if self.db_connection is not None:
            self._logs_columns_lower = None  # the query may be DDL
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

    def _query_columns(self, query: str) -> frozenset[str]:
        """Column names a rule query compares against, minus SQL keywords.

        ``query`` may be the rebalanced form rather than the one in the ruleset.
        That only re-associates OR, so the columns are the same; it costs one
        extra memo entry and is not worth guarding against.
        """
        return scan_query(query).columns

    def _logs_columns(self) -> set[str]:
        """Lowercased column names of the logs table, cached between rules."""
        if self._logs_columns_lower is None:
            self._logs_columns_lower = {c.lower() for c in self._get_table_columns()}
        return self._logs_columns_lower

    def _widen_logs_table(self, query: str) -> bool:
        """Materialise the query's referenced-but-absent columns. True if widened.

        SQLite resolves column names when it prepares a statement, so a rule
        naming one field this dataset never produced fails as a whole -- losing
        the branches that reference fields it *does* have. Adding the absent ones
        as NULL makes the rule evaluate exactly as it would against an event that
        simply lacks those fields.

        Rules whose fields are *all* absent are widened too: ``|exists: false``
        becomes ``IS NULL``, which matches every row once the column is there.
        """
        columns = self._logs_columns()
        missing = [c for c in self._query_columns(query) if c.lower() not in columns]
        if not missing:
            return False
        cursor = self._get_cursor()
        for name in missing:
            escaped = self.escape_identifier(name)
            try:
                cursor.execute(
                    f'ALTER TABLE "logs" ADD COLUMN "{escaped}" TEXT COLLATE NOCASE'
                )
            except sqlite3.Error as exc:
                # Typically SQLITE_MAX_COLUMN; the rule stays unevaluated.
                self.logger.debug(f"Could not add column {name}: {exc}")
                self._logs_columns_lower = None
                return False
            columns.add(name.lower())
        return True

    def _note_broken_rule(
        self, rule_title: str | None, error: Exception | str
    ) -> None:
        """Record a rule whose SQL cannot run at all; reported once, in the summary."""
        title = rule_title or "unknown rule"
        if title in self.rules_in_error:
            return
        self.rules_in_error[title] = str(error)
        self.logger.debug(f"Rule '{title}' could not be evaluated: {error}")

    def execute_select_query(
        self, query: str, rule_title: str | None = None
    ) -> list[dict[str, Any]]:
        """Execute a SELECT SQL query and return the results as a list of dictionaries."""
        if self.db_connection is None:
            self.logger.error("[error]    [-] No connection to Db[/]")
            return []
        bad_regex = _uncompilable_regex(query)
        if bad_regex is not None:
            self._note_broken_rule(rule_title, bad_regex)
            return []
        # Syntax-highlighted SQL in debug mode
        if self.logger.isEnabledFor(logging.DEBUG):
            console.print(Panel(
                Syntax(query, "sql", theme="monokai", line_numbers=False, word_wrap=True),
                title="[dim]SQL Query[/]",
                border_style="dim",
                padding=(0, 1),
            ))
        # A query can need more than one repair, and the first failure hides the
        # rest: an over-deep rule is rejected while parsing, before SQLite ever
        # looks up its column names. Each repair is attempted at most once.
        attempted: set[str] = set()
        while True:
            try:
                cursor = self._get_cursor()
                cursor.execute(query)
                rows = cursor.fetchall()
                if not rows:
                    return []
                col_names = [d[0] for d in cursor.description]
                return [
                    {k: v for k, v in zip(col_names, row, strict=True) if v is not None}
                    for row in rows
                ]
            except sqlite3.Error as e:
                message = str(e)
                if _DEPTH_LIMIT_RE.search(message) and "rebalance" not in attempted:
                    attempted.add("rebalance")
                    rebalanced = _rebalance_cached(query)
                    if rebalanced != query:
                        query = rebalanced
                        continue
                    self._note_broken_rule(rule_title, e)
                    return []
                if _MISSING_COLUMN_RE.search(message) is None:
                    # Syntax errors, parser-depth limits, UDF failures: the rule
                    # can never match, and staying quiet about it hides a blind spot.
                    self._note_broken_rule(rule_title, e)
                    return []
                if "widen" in attempted:
                    # Widening ran and the column is still missing, so the name
                    # was never reported to it. That is a blind spot, not a
                    # dataset that simply lacks the field.
                    self._note_broken_rule(rule_title, e)
                    return []
                if not self._widen_logs_table(query):
                    self.logger.debug(f"    [-] Rule fields absent from dataset: {e}")
                    return []
                attempted.add("widen")

    def load_db_in_memory(self, db: str) -> None:
        """In db-only mode, restore an on-disk database to avoid EVTX extraction and flattening."""
        # sqlite3.connect() would silently create a 0-byte file for a missing path
        if not Path(db).is_file():
            raise RuntimeError(f"Database file does not exist: {db}")
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
        # backup() replaced the whole in-memory DB, indexes and schema included:
        # the next execute_ruleset must re-read both
        self._auto_index_applied = False
        self._logs_columns_lower = None

    def escape_identifier(self, identifier: str) -> str:
        """Escape SQL identifiers like table or column names with caching."""
        # Check cache first for frequently used identifiers
        escaped = self._escape_cache.get(identifier)
        if escaped is None:
            escaped = identifier.replace("\"", "\"\"")
            self._escape_cache[identifier] = escaped
        return escaped

    def insert_data_to_db(self, data: dict[str, Any] | list[dict[str, Any]]) -> bool:
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
            batches_by_columns: dict[tuple[str, ...], list[dict[str, Any]]] = {}
            for row in batch:
                cols = tuple(row.keys())
                if cols not in batches_by_columns:
                    batches_by_columns[cols] = []
                batches_by_columns[cols].append(row)

            for cols, rows in batches_by_columns.items():
                # Identifiers must be quoted: event keys can be SQL keywords
                # ('Group') or contain spaces
                columns_escaped = ', '.join([f'"{self.escape_identifier(col)}"' for col in cols])
                placeholders = ', '.join(['?'] * len(cols))
                # Column names go through escape_identifier; the values are
                # bound parameters and are never interpolated.
                insert_stmt = (
                    f'INSERT INTO logs ({columns_escaped}) VALUES ({placeholders})'  # noqa: S608
                )

                values_list = []
                for row in rows:
                    values = []
                    for col in cols:
                        value = row[col]
                        # Values past SQLite's INTEGER range must go in as text
                        if isinstance(value, int) and abs(value) > 9223372036854775807:
                            value = str(value)
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
        try:
            self.db_connection.backup(on_disk_db)
            on_disk_db.execute("PRAGMA journal_mode = DELETE")
        finally:
            on_disk_db.close()

    def execute_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        """Execute a single Sigma rule against the database and return the results."""
        # Fast path: check for required key first
        sigma_queries = rule.get("rule")
        if sigma_queries is None:
            self.logger.debug("RULE FORMAT ERROR: 'rule' key missing")
            return {}
        if not isinstance(sigma_queries, list):
            # A string would be iterated character by character below
            self.logger.debug("RULE FORMAT ERROR: 'rule' value must be a list of SQL queries")
            return {}

        # Pre-allocate list with estimated capacity
        filtered_rows: list[dict[str, Any]] = []
        filtered_rows_extend = filtered_rows.extend  # Cache method reference
        csv_mode = self.csv_mode  # Cache instance variable
        execute_select = self.execute_select_query  # Cache method reference
        rule_title = rule.get("title", "Unnamed Rule")

        # Process each SQL query in the rule
        for sql_query in sigma_queries:
            data = execute_select(sql_query, rule_title=rule_title)
            if data:
                cleaned_rows = [sanitize_row_for_csv(row) for row in data] if csv_mode else data
                filtered_rows_extend(cleaned_rows)

        if not filtered_rows:
            return {}

        # Extract rule metadata only when we have results (avoid work for non-matching rules)
        rule_get = rule.get  # Cache method
        description = rule_get("description", "")

        results = {
            "title": rule_title,
            "id": rule_get("id", ""),
            "description": description.translate(_NEWLINE_TRANSLATE) if csv_mode else description,
            "sigmafile": rule_get("filename", ""),
            "sigma": sigma_queries,
            "rule_level": rule_get("level", "unknown"),
            "tags": rule_get("tags", []),
            "count": len(filtered_rows),
            "matches": filtered_rows
        }
        self.logger.debug(f'DETECTED: {rule_title} - Matches: {len(filtered_rows)} events')
        return results

    def load_ruleset_from_var(
        self, ruleset: list[dict[str, Any]], rule_filters: list[str] | None
    ) -> None:
        """Load a ruleset from a variable."""
        self.ruleset = ruleset
        self.apply_ruleset_filters(rule_filters)

    def apply_ruleset_filters(
        self, rule_filters: list[str] | None = None
    ) -> None:
        """Remove empty rules and filtered rules from the ruleset."""
        self.ruleset = list(filter(None, self.ruleset))
        if rule_filters is not None:
            self.ruleset = [rule for rule in self.ruleset if not any(rule_filter in rule.get("title", "") for rule_filter in rule_filters)]

    def _write_result_to_output(
        self,
        rule_results: dict[str, Any],
        file_handle: Any,
        csv_writer: Any | None,
        needs_comma_prefix: bool,
    ) -> tuple[Any | None, bool]:
        """Write rule results to output file. Returns (csv_writer, needs_comma_prefix).

        In CSV mode the header comes from the events table schema plus the rule
        metadata columns, not from the first match row -- see _csv_event_columns
        for why. Rows carry only their non-NULL fields, so a header taken from
        whichever detection happened to be written first silently dropped the
        rest. See docs/Usage.md (section CSV detection output).
        """
        if self.csv_mode:
            # Initialize CSV writer if not already done
            if csv_writer is None:
                # Fieldnames persist across calls: in append mode (per-file /
                # multi-DB flows) each call re-enters with a fresh local writer,
                # and rows must stay aligned with the single header.
                if self._csv_fieldnames is None:
                    self._csv_fieldnames = ["rule_title", "rule_description", "rule_level", "rule_count", *self._csv_event_columns(rule_results)]
                csv_writer = csv.DictWriter(
                    file_handle,
                    delimiter=self.delimiter,
                    fieldnames=self._csv_fieldnames,
                    extrasaction="ignore",
                )
                if not self._csv_header_written:
                    csv_writer.writeheader()
                    self._csv_header_written = True
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
                # Serialize first: on failure the comma bookkeeping must stay untouched
                json_bytes = json.dumps(rule_results, option=json.OPT_INDENT_2)
            except Exception as e:
                self.logger.error(f"[error]    [-] Error serializing some results: {e}[/]")
                return csv_writer, needs_comma_prefix
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
                file_handle.write(json_bytes.decode('utf-8'))
            except Exception as e:
                self.logger.error(f"[error]    [-] Error saving some results: {e}[/]")
        return csv_writer, needs_comma_prefix

    def _csv_event_columns(self, rule_results: dict[str, Any]) -> list[str]:
        """Event columns for the CSV header.

        The table schema, not the first matching row: rows carry only their
        non-NULL fields, so a header taken from the first match silently dropped
        User, ParentImage, hashes and the rest from every later row -- and which
        columns survived depended on which detection happened to be written
        first. Falls back to the first row if the schema is unavailable.
        """
        try:
            columns = self._get_table_columns()
        except sqlite3.Error as exc:
            self.logger.debug(f"Could not read the logs schema for the CSV header: {exc}")
            columns = []
        columns = [c for c in columns if c != "row_id"]
        if columns:
            return columns
        return list(rule_results["matches"][0].keys())

    def execute_ruleset(
        self,
        out_file: str,
        write_mode: str = "w",
        keep_results: bool = False,
        last_ruleset: bool = False,
        source_label: str | None = None,
        show_table: bool = True,
        disable_progress: bool | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        """Execute all rules in the ruleset and handle output."""
        csv_writer = None
        is_json_mode = not self.csv_mode
        _disable = disable_progress if disable_progress is not None else self.disable_progress
        # Ingestion discovered the schema through its own connection
        self._logs_columns_lower = None

        # Apply auto-index now that the ruleset is loaded (create_index runs at
        # the end of ingestion, before the ruleset is available in every flow),
        # then analyse, so the indexes it just created are covered too. Rules
        # widen the table with an all-NULL column per absent field, and with no
        # statistics SQLite prices a row by its column count alone -- the wider
        # the table, the more queries leave their selective index. PRAGMA
        # optimize cannot stand in: it samples at an implicit analysis_limit, so
        # both indexes report the same capped figure once the corpus is large
        # enough, and it then treats the table as analysed. Once is enough;
        # ADD COLUMN leaves sqlite_stat1 intact.
        self.apply_auto_index()
        if self.db_connection is not None:
            try:
                self.db_connection.execute("ANALYZE logs")
            except sqlite3.Error as exc:
                self.logger.debug(f"ANALYZE failed (non-fatal): {exc}")

        # Prepare output file handle if needed
        file_handle = None
        needs_comma_prefix = False
        if not self.no_output:
            json_fresh_output = False
            if is_json_mode and write_mode == 'a':
                out_path = Path(out_file)
                file_size = out_path.stat().st_size if out_path.exists() else 0
                if file_size == 0:
                    # Nothing to append to: behave like a fresh write
                    json_fresh_output = True
                else:
                    # The closing bracket can only sit in the file tail, so
                    # reading it is enough to prepare the array for appending
                    with open(out_file, 'rb+') as f:
                        tail_start = max(0, file_size - 65536)
                        f.seek(tail_start)
                        tail = f.read(file_size - tail_start)
                        stripped = tail.rstrip()
                        if not stripped:
                            json_fresh_output = True
                        else:
                            if stripped.endswith(b']'):
                                # Remove the closing bracket; it is re-added when
                                # the last ruleset closes the array
                                f.seek(tail_start + len(stripped) - 1)
                                f.truncate()
                                stripped = stripped[:-1].rstrip()
                                if not stripped:
                                    json_fresh_output = True
                            if not json_fresh_output:
                                # Prefix a comma only when the file already holds
                                # a complete element
                                needs_comma_prefix = not stripped.endswith((b'[', b','))

            # Open file in text mode since we will write decoded strings
            # Results stream out rule by rule, so the handle has to outlive
            # this scope; the enclosing try/finally closes it.
            file_handle = open(  # noqa: SIM115
                out_file, write_mode, encoding='utf-8', newline=''
            )
            if is_json_mode and (write_mode != 'a' or json_fresh_output):
                file_handle.write('[')  # Start JSON array
            if self.csv_mode and write_mode != 'a':
                self._csv_header_written = False
                self._csv_fieldnames = None

        try:
            # Cache frequently accessed attributes and methods
            execute_rule = self.execute_rule
            limit = self.limit
            no_output = self.no_output
            full_results_append = self.full_results.append

            # Collect all results for sorting by level
            all_rule_results = []

            # Per-call timings: in per-file mode the caller merges this dict
            # after every file, so keeping the running total across files would
            # count each file's rules once more than the last
            self._profiling_data = {}

            # Cache profiling flag locally for the inner loop
            _profile = self.profile_rules
            _profiling_data = self._profiling_data
            _perf_counter = _time_module.perf_counter
            total_rules = len(self.ruleset)

            def run_rule(rule) -> dict | None:
                """Execute one rule, timing it and recording the summary row."""
                _t0 = _perf_counter() if _profile else 0.0
                rule_results = execute_rule(rule)
                if _profile:
                    _title = rule.get('title', 'unknown')
                    _profiling_data[_title] = _profiling_data.get(_title, 0.0) + (
                        _perf_counter() - _t0
                    ) * 1000
                if not rule_results:
                    return None
                if limit != -1 and rule_results["count"] > limit:
                    return None
                all_rule_results.append({
                    "title": rule_results.get("title", "Unknown"),
                    "rule_level": rule_results.get("rule_level", "unknown"),
                    "count": rule_results.get("count", 0),
                    "tags": rule_results.get("tags", [])
                })
                if keep_results:
                    full_results_append(rule_results)
                return rule_results

            # One loop, three ways of showing it: an external callback, no
            # display at all, or a Rich Live progress bar with a running
            # detection counter. Only the reporting differs, so only the
            # reporting is branched on.
            detection_counts = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0
            }
            progress = None
            task_id = None
            live_display: Any = nullcontext(None)

            if progress_callback is not None:
                progress_callback(0, total_rules)
            elif not _disable:
                progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    MofNCompleteColumn(),
                    TextColumn("\u2022"),
                    TimeElapsedColumn(),
                )
                task_id = progress.add_task("Executing rules", total=total_rules)
                live_display = Live(
                    console=console, refresh_per_second=10, transient=True
                )

            with live_display as live:
                for i, rule in enumerate(self.ruleset):
                    if is_shutdown_requested():
                        break
                    rule_results = run_rule(rule)

                    if progress_callback is not None:
                        progress_callback(i + 1, total_rules)
                    elif progress is not None and task_id is not None:
                        progress.advance(task_id)

                    if rule_results is not None:
                        if progress is not None:
                            det_level = rule_results.get("rule_level", "unknown").lower()
                            if det_level in detection_counts:
                                # Matching events, like the summary panel: the
                                # two badges look identical, so counting rules
                                # here made the same run show two numbers
                                detection_counts[det_level] += rule_results.get(
                                    "count", 0
                                )
                        if not no_output:
                            csv_writer, needs_comma_prefix = self._write_result_to_output(
                                rule_results, file_handle, csv_writer, needs_comma_prefix
                            )

                    if live is not None and progress is not None:
                        live.update(
                            Group(progress, make_detection_counter(detection_counts))
                        )

            # Sort results by level priority, then by count (descending)
            all_rule_results.sort(key=sort_key_severity)

            # Display sorted results as a table (suppressed in quiet mode or when show_table=False)
            if show_table and not is_quiet() and all_rule_results:
                console.print()
                console.print(build_detection_table(all_rule_results, title=source_label))
                console.print()

            if self.rules_in_error:
                names = list(self.rules_in_error)
                shown = ", ".join(names[:3]) + (" ..." if len(names) > 3 else "")
                self.logger.warning(
                    f"[yellow]   [!] {len(names)} rule(s) could not be evaluated and "
                    f"matched nothing: {shown} (use --debug for the SQL error)[/]"
                )
        finally:
            # Close output file handle if needed (always run, including on exception)
            if file_handle is not None:
                if is_json_mode and last_ruleset:
                    file_handle.write(']')  # Close JSON array
                file_handle.close()

    @staticmethod
    def _as_ingested(event: dict[str, Any]) -> dict[str, Any]:
        """Normalise a test event the way ingestion normalises a real one.

        Only booleans differ: ingestion writes them as ``'true'``/``'false'``
        (streaming.py), so a rule matching ``IsExecutable='true'`` fires in a
        real run. Handing sqlite3 a Python ``True`` instead stores ``'1'``, and
        --test-rules would report a false negative against a working rule.
        """
        return {
            key: ("true" if value else "false") if isinstance(value, bool) else value
            for key, value in event.items()
        }

    @staticmethod
    def _infer_field_statement(events: list[dict[str, Any]]) -> str:
        """Build a field statement with column types inferred from event values.

        The production pipeline stores ints in INTEGER columns; an all-TEXT test
        schema would make numeric predicates compare lexicographically and
        diverge from production behavior.

        Booleans are the exception: ingestion writes them as the strings
        ``'true'``/``'false'`` (streaming.py), so typing them INTEGER here would
        report a rule matching ``IsExecutable='true'`` as a failure while it
        fires perfectly well in a real run.
        """
        types: dict[str, str] = {}
        for ev in events:
            for key, value in ev.items():
                if key in types or value is None or isinstance(value, bool):
                    continue
                if isinstance(value, int):
                    types[key] = "INTEGER"
                elif isinstance(value, float):
                    types[key] = "REAL"
        keys = sorted({k for ev in events for k in ev})
        return ", ".join(
            '"{}" {}'.format(k.replace('"', '""'), types.get(k, "TEXT COLLATE NOCASE"))
            for k in keys
        )

    def run_rule_tests(self, test_file: str) -> list:
        """Validate rules against known-positive and known-negative events.

        The test file is a JSON array where each element contains:
        - ``title`` or ``id``: matched against the loaded ruleset
        - ``true_positive``: list of event dicts that MUST trigger the rule
        - ``true_negative``: list of event dicts that MUST NOT trigger the rule

        Returns a list of result dicts with keys:
        ``title``, ``id``, ``tp_pass``, ``tn_pass``, ``tp_count``, ``tn_count``, ``error``

        Raises:
            ValueError: the test file cannot be read or is not a JSON array.
                Returning "no results" instead would let a typo in a CI job
                report success, which is exactly what rule testing is for.
        """
        try:
            with open(test_file, encoding='utf-8') as f:
                test_cases = json.loads(f.read())
        except Exception as e:
            raise ValueError(f"Cannot load rule test file: {e}") from e

        if not isinstance(test_cases, list):
            raise ValueError("Rule test file must be a JSON array")

        invalid_entries = sum(1 for tc in test_cases if not isinstance(tc, dict))
        if invalid_entries:
            self.logger.warning(
                f"[yellow]    [!] Ignoring {invalid_entries} non-object "
                f"entries in the rule test file[/]"
            )
            test_cases = [tc for tc in test_cases if isinstance(tc, dict)]

        # Index test cases by title and id for fast lookup
        by_title = {tc.get('title', ''): tc for tc in test_cases if tc.get('title')}
        by_id = {tc.get('id', ''): tc for tc in test_cases if tc.get('id')}
        if len(by_title) != sum(1 for tc in test_cases if tc.get('title')):
            self.logger.warning(
                "[yellow]    [!] Duplicate rule titles in test file; "
                "only the last test case for each title is used[/]"
            )
        if len(by_id) != sum(1 for tc in test_cases if tc.get('id')):
            self.logger.warning(
                "[yellow]    [!] Duplicate rule ids in test file; "
                "only the last test case for each id is used[/]"
            )

        matched_case_ids: set = set()
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
            matched_case_ids.add(id(tc))

            tp_events = [self._as_ingested(e) for e in tc.get('true_positive', [])]
            tn_events = [self._as_ingested(e) for e in tc.get('true_negative', [])]
            # None means "not tested": with no events on that side there is
            # nothing to conclude, and defaulting to True reported an untested
            # half as a pass.
            tp_pass: bool | None = None
            tn_pass: bool | None = None
            tp_count = 0
            tn_count = 0
            error = ''

            try:
                # Run true-positive check
                if tp_events:
                    tp_core = ZircoliteCore(
                        self.config,
                        processing_config=None,  # defaults
                        logger=self.logger,
                    )
                    try:
                        tp_core.create_db(self._infer_field_statement(tp_events))
                        if not tp_core.insert_data_to_db(tp_events):
                            raise RuntimeError("could not insert true-positive test events")
                        tp_res = tp_core.execute_rule(rule)
                        tp_count = tp_res.get('count', 0) if tp_res else 0
                        tp_pass = tp_count > 0
                        # A rule that could not run returns no matches, which is
                        # indistinguishable from one that ran and matched
                        # nothing unless its recorded error is read back.
                        if tp_core.rules_in_error:
                            error = next(iter(tp_core.rules_in_error.values()))
                            tp_pass = False
                    finally:
                        tp_core.close()

                # Run true-negative check
                if tn_events:
                    tn_core = ZircoliteCore(
                        self.config,
                        processing_config=None,
                        logger=self.logger,
                    )
                    try:
                        tn_core.create_db(self._infer_field_statement(tn_events))
                        if not tn_core.insert_data_to_db(tn_events):
                            raise RuntimeError("could not insert true-negative test events")
                        tn_res = tn_core.execute_rule(rule)
                        tn_count = tn_res.get('count', 0) if tn_res else 0
                        tn_pass = tn_count == 0
                        # A broken rule matches nothing, so the true-negative
                        # side would otherwise always pass.
                        if tn_core.rules_in_error:
                            error = next(iter(tn_core.rules_in_error.values()))
                            tn_pass = False
                    finally:
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

        # Surface test cases that matched no rule in the loaded ruleset
        for tc in test_cases:
            if id(tc) not in matched_case_ids:
                results.append({
                    'title': tc.get('title', ''), 'id': tc.get('id', ''),
                    'tp_pass': None, 'tn_pass': None,
                    'tp_count': 0, 'tn_count': 0,
                    'error': 'no matching rule in ruleset',
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
                      event_filter: 'EventFilter | None' = None,
                      return_filtered_count: bool = False,
                      keepflat_file=None,
                      _raw_config: dict | None = None) -> 'int | tuple[int, int, int]':
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
            return_filtered_count: If True, return (total_events, filtered_count,
                          time_filtered_count) tuple
            keepflat_file: Open binary file handle to write flattened JSONL events to (caller
                          is responsible for opening and closing the file)
            _raw_config: Pre-parsed field-mappings dict passed through to
                        StreamingEventProcessor to skip redundant config reads.

        Returns:
            Total number of events processed, or (total_events, filtered_count,
            time_filtered_count) if return_filtered_count=True
        """
        self.logger.info("[+] Processing events (streaming mode)")

        json_array = json_array_requested(args_config) if args_config else False

        # Create streaming processor with ProcessingConfig
        proc_config = ProcessingConfig(
            time_after=self.time_after,
            time_before=self.time_before,
            time_field=self.time_field,
            hashes=self.hashes,
            disable_progress=disable_progress or self.disable_progress,
            archive_password=self.archive_password,
            strict_evtx=self.strict_evtx,
            batch_size=self.batch_size,
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
            try:
                file_size = os.path.getsize(log_file)
                if file_size == 0:
                    return 0

                event_count = processor.process_file_streaming(
                    self.db_connection,
                    str(log_file),
                    input_type=input_type,
                    extractor=extractor,
                    json_array=json_array,
                    keepflat_file=keepflat_file,
                    progress_callback=progress_cb,
                )
                if processor.ingest_degraded:
                    # Read only in part: --remove-events must not delete it
                    self.failed_files.add(str(log_file))
                return event_count

            except StrictParseError:
                # --strict asked us to stop on parse errors, so this one must
                # not be swallowed into a "0 events" result like the rest.
                raise
            except Exception as e:
                self.logger.error(f"[error]    [-] Error processing {log_file}: {e}[/]")
                self.failed_files.add(str(log_file))
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

        # Log filtered events statistics. Report whenever a filter was active,
        # not only when it dropped something: "ran and dropped nothing" and
        # "never ran" are different answers to "is the filter working?".
        filtered_count = processor.events_filtered_count
        time_filtered_count = processor.events_time_filtered_count
        dropped = []
        if event_filter is not None and event_filter.is_enabled:
            dropped.append(f"{filtered_count:,} filtered out by log source")
        if processor.has_time_filter:
            dropped.append(f"{time_filtered_count:,} outside the time range")
        if dropped:
            self.logger.info(
                f"[+] Total events processed: [magenta]{total_events:,}[/] "
                f"([dim]{', '.join(dropped)}[/])"
            )
        else:
            self.logger.info(f"[+] Total events processed: [magenta]{total_events:,}[/]")

        if return_filtered_count:
            return total_events, filtered_count, time_filtered_count
        return total_events
