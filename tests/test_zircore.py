"""
Tests for the ZircoliteCore class.
"""

import csv
import gc
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import ProcessingConfig, ZircoliteCore, sqlscan
from zircolite.core import _compile_regex
from zircolite.streaming import StreamingEventProcessor


class TestZircoliteCoreInit:
    """Tests for ZircoliteCore initialization."""

    def test_init_creates_in_memory_db(self, field_mappings_file, test_logger):
        """Test ZircoliteCore creates in-memory database by default."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        assert zircore.db_connection is not None
        zircore.close()

    def test_init_with_custom_db_location(self, field_mappings_file, tmp_path, test_logger):
        """Test ZircoliteCore with on-disk database."""
        db_file = str(tmp_path / "test.db")

        proc_config = ProcessingConfig(db_location=db_file)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        assert zircore.db_connection is not None
        zircore.close()

        # Verify file was created
        assert Path(db_file).exists()

    def test_init_with_time_filters(self, field_mappings_file, test_logger):
        """Test ZircoliteCore with time filtering."""
        proc_config = ProcessingConfig(
            time_after="2024-01-01T00:00:00",
            time_before="2024-12-31T23:59:59"
        )
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        assert zircore.time_after == "2024-01-01T00:00:00"
        assert zircore.time_before == "2024-12-31T23:59:59"
        zircore.close()

    def test_init_csv_mode(self, field_mappings_file, test_logger):
        """Test ZircoliteCore in CSV output mode."""
        proc_config = ProcessingConfig(csv_mode=True, delimiter=",")
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        assert zircore.csv_mode is True
        assert zircore.delimiter == ","
        zircore.close()

    def test_init_with_no_output(self, field_mappings_file, test_logger):
        """Test ZircoliteCore with output disabled."""
        proc_config = ProcessingConfig(no_output=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        assert zircore.no_output is True
        zircore.close()


class TestZircoliteCoreDatabase:
    """Tests for ZircoliteCore database operations."""

    def test_create_connection(self, field_mappings_file, test_logger):
        """Test database connection creation."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        # Test connection is valid
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()

        assert result[0] == 1
        zircore.close()

    def test_create_db(self, field_mappings_file, test_logger):
        """Test database table creation."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        field_stmt = "'EventID' TEXT COLLATE NOCASE,\n'CommandLine' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)

        # Verify table was created
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        result = cursor.fetchone()

        assert result is not None
        assert result[0] == 'logs'
        zircore.close()

    def test_execute_query(self, field_mappings_file, test_logger):
        """Test SQL query execution."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        # Create a simple table
        result = zircore.execute_query("CREATE TABLE test (id INTEGER, value TEXT)")
        assert result is True

        # Insert data
        result = zircore.execute_query("INSERT INTO test VALUES (1, 'test')")
        assert result is True

        zircore.close()

    def test_execute_query_with_error(self, field_mappings_file, test_logger):
        """Test SQL query execution with invalid query."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        # Invalid SQL should return False
        result = zircore.execute_query("INVALID SQL QUERY")
        assert result is False

        zircore.close()

    def test_execute_select_query(self, field_mappings_file, test_logger):
        """Test SELECT query execution."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        # Create and populate table
        zircore.execute_query("CREATE TABLE test (id INTEGER, value TEXT)")
        zircore.execute_query("INSERT INTO test VALUES (1, 'first')")
        zircore.execute_query("INSERT INTO test VALUES (2, 'second')")

        results = zircore.execute_select_query("SELECT * FROM test ORDER BY id")

        assert len(results) == 2
        assert results[0]['id'] == 1
        assert results[0]['value'] == 'first'

        zircore.close()

    def test_execute_select_query_empty_result(self, field_mappings_file, test_logger):
        """Test SELECT query with no results."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        zircore.execute_query("CREATE TABLE test (id INTEGER)")

        results = zircore.execute_select_query("SELECT * FROM test")

        assert results == []
        zircore.close()

    def test_execute_select_query_omits_none_values(self, field_mappings_file, test_logger):
        """execute_select_query returns dicts with None values omitted (key absent)."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )
        zircore.execute_query(
            "CREATE TABLE test (id INTEGER, a TEXT, b TEXT)"
        )
        zircore.db_connection.execute(
            "INSERT INTO test (id, a, b) VALUES (1, 'x', NULL)"
        )
        zircore.db_connection.commit()

        results = zircore.execute_select_query("SELECT * FROM test")
        assert len(results) == 1
        row = results[0]
        assert row.get("id") == 1
        assert row.get("a") == "x"
        assert "b" not in row

        zircore.close()

    def test_insert_data_to_db(self, field_mappings_file, test_logger):
        """Test inserting data into database."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        # Create table
        zircore.execute_query("CREATE TABLE logs (row_id INTEGER PRIMARY KEY, EventID TEXT, CommandLine TEXT)")

        # Insert data
        data = {"EventID": "1", "CommandLine": "test.exe"}
        result = zircore.insert_data_to_db(data)

        assert result is True

        # Verify data
        results = zircore.execute_select_query("SELECT * FROM logs")
        assert len(results) == 1

        zircore.close()

    def test_rule_still_matches_when_one_referenced_field_is_absent(
        self, field_mappings_file, test_logger
    ):
        """A field this dataset never produced must not disable the whole rule.

        SQLite resolves column names when it prepares the statement, so the
        entire query used to fail and the rule reported no match -- including the
        OR branch on a field that *is* present.
        """
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.execute_query(
            "CREATE TABLE logs (row_id INTEGER PRIMARY KEY, CommandLine TEXT)"
        )
        zircore.insert_data_to_db({"CommandLine": "mimikatz.exe"})

        results = zircore.execute_select_query(
            "SELECT * FROM logs WHERE CommandLine LIKE '%mimikatz%' "
            "OR OriginalFileName LIKE '%mimikatz%'"
        )
        assert len(results) == 1
        assert not zircore.rules_in_error

        zircore.close()

    def test_unparsable_rule_sql_is_reported_not_swallowed(
        self, field_mappings_file, test_logger
    ):
        """Broken SQL must be surfaced: silence looks exactly like 'no detections'."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.execute_query("CREATE TABLE logs (row_id INTEGER PRIMARY KEY, A TEXT)")

        results = zircore.execute_select_query(
            "SELECT * FROM logs WHERE A REGEXP ']'[", rule_title="Broken Rule"
        )
        assert results == []
        assert "Broken Rule" in zircore.rules_in_error

        zircore.close()

    def test_over_deep_rule_is_repaired_and_matches(
        self, field_mappings_file, test_logger
    ):
        """A rule with a huge value list must run, not be written off as broken.

        pySigma emits value lists as a left-deep OR chain, and SQLite refuses to
        parse one deeper than SQLITE_MAX_EXPR_DEPTH.
        """
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.execute_query(
            "CREATE TABLE logs (row_id INTEGER PRIMARY KEY, CommandLine TEXT)"
        )
        zircore.insert_data_to_db({"CommandLine": "payload-1500"})

        chain = " OR ".join(
            f"CommandLine LIKE '%payload-{i}%' ESCAPE '\\'" for i in range(2000)
        )
        results = zircore.execute_select_query(
            f"SELECT * FROM logs WHERE ({chain})", rule_title="Huge Rule"
        )

        assert len(results) == 1
        assert not zircore.rules_in_error

        zircore.close()

    def test_over_deep_rule_also_gets_its_columns_widened(
        self, field_mappings_file, test_logger
    ):
        """The depth error masks the missing-column error, so both repairs must chain.

        SQLite rejects an over-deep statement while parsing, before it ever
        resolves column names -- so widening only becomes reachable once the
        expression has been rebalanced.
        """
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.execute_query(
            "CREATE TABLE logs (row_id INTEGER PRIMARY KEY, CommandLine TEXT)"
        )
        zircore.insert_data_to_db({"CommandLine": "payload-1500"})

        chain = " OR ".join(
            f"CommandLine LIKE '%payload-{i}%' ESCAPE '\\'" for i in range(2000)
        )
        results = zircore.execute_select_query(
            f"SELECT * FROM logs WHERE ({chain}) OR OriginalFileName='absent.exe'",
            rule_title="Huge Rule With Absent Field",
        )

        assert len(results) == 1
        assert not zircore.rules_in_error

        zircore.close()

    def test_insert_data_to_db_multiple_rows(self, field_mappings_file, test_logger):
        """Test inserting multiple data rows individually."""
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        # Create table
        field_stmt = "'EventID' TEXT COLLATE NOCASE,\n'CommandLine' TEXT COLLATE NOCASE,\n'Computer' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)

        # Insert individual rows
        data = [
            {"EventID": "1", "CommandLine": "test1.exe", "Computer": "PC1"},
            {"EventID": "2", "CommandLine": "test2.exe", "Computer": "PC2"},
            {"EventID": "3", "CommandLine": "test3.exe", "Computer": "PC3"},
        ]

        for row in data:
            zircore.insert_data_to_db(row)

        # Verify data
        results = zircore.execute_select_query("SELECT * FROM logs")
        assert len(results) == 3

        zircore.close()

    def test_insert_handles_large_integers(self, field_mappings_file, test_logger):
        """Test handling of very large integer values."""
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        field_stmt = "'EventID' TEXT COLLATE NOCASE,\n'LargeValue' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)

        # Insert data with large integer (exceeds SQLite INTEGER limit)
        large_int = 99999999999999999999999
        zircore.insert_data_to_db({"EventID": "1", "LargeValue": large_int})

        results = zircore.execute_select_query("SELECT * FROM logs")
        assert len(results) == 1
        assert results[0]["LargeValue"] == str(large_int)

        zircore.close()

    def test_create_index(self, field_mappings_file, test_logger):
        """Test index creation on eventid column."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        field_stmt = "'eventid' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)

        zircore.create_index()

        # Verify index exists
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_eventid'")
        result = cursor.fetchone()

        assert result is not None
        zircore.close()

    def test_get_table_columns(self, field_mappings_file, test_logger):
        """Test _get_table_columns returns column names from logs table."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )
        field_stmt = "'eventid' TEXT, 'Channel' TEXT"
        zircore.create_db(field_stmt)
        cols = zircore._get_table_columns()
        assert "eventid" in cols
        assert "Channel" in cols
        zircore.close()

    def test_create_index_with_channel_column_creates_the_composite(self, field_mappings_file, test_logger):
        """A Channel column earns a (Channel, eventid) index, not a lone one.

        The Sigma shape is ``Channel = … AND EventID = …``; a channel-only index
        leaves SQLite re-checking every row of the channel.
        """
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )
        field_stmt = "'eventid' TEXT, 'Channel' TEXT"
        zircore.create_db(field_stmt)
        zircore.create_index()
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        names = {row[0] for row in cursor.fetchall()}
        assert "idx_channel_eventid" in names
        assert "idx_eventid" in names
        zircore.close()

    def test_a_channel_without_an_eventid_still_gets_indexed(self, field_mappings_file, test_logger):
        """The composite needs both columns; falling back is not optional.

        A dataset carrying Channel but no eventid would otherwise leave the one
        column rules do filter on unindexed.
        """
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )
        zircore.create_db("'Channel' TEXT")
        zircore.create_index()
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        names = {row[0] for row in cursor.fetchall()}
        assert "idx_channel" in names
        assert "idx_channel_eventid" not in names
        zircore.close()

    def test_an_absent_column_is_not_indexed_over_a_constant(self, field_mappings_file, test_logger):
        """SQLite would accept the statement and index nothing useful.

        A double-quoted name that matches no column is read as a string literal
        rather than rejected, so `CREATE INDEX ... ON logs ("eventid")` against a
        table without one succeeds and builds an index over the constant
        'eventid'. No error is raised and none of the queries can use it, so the
        only signal is the wasted index sitting in the schema.
        """
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )
        zircore.create_db("'Channel' TEXT")
        zircore.create_index()
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        names = {row[0] for row in cursor.fetchall()}
        assert "idx_eventid" not in names
        zircore.close()

    def test_create_index_add_index_creates_extra_indexes(self, field_mappings_file, test_logger):
        """create_index with add_index creates indexes on requested columns."""
        proc_config = ProcessingConfig(
            disable_progress=True,
            add_index=["Channel", "SystemTime"],
            remove_index=[],
        )
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        field_stmt = "'eventid' TEXT, 'Channel' TEXT, 'SystemTime' TEXT"
        zircore.create_db(field_stmt)
        zircore.create_index()
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        names = [row[0] for row in cursor.fetchall()]
        assert "idx_eventid" in names
        assert "idx_channel_eventid" in names  # auto-created when Channel column exists
        assert "idx_SystemTime" in names  # from add_index (idx_Channel may be skipped if same as idx_channel)
        zircore.close()

    def test_auto_index_picks_top_columns_from_ruleset(self, field_mappings_file, test_logger):
        """auto_index_top_n picks the top-N referenced columns and creates indices."""
        proc_config = ProcessingConfig(
            disable_progress=True,
            add_index=[],
            remove_index=[],
            auto_index_top_n=2,
        )
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        field_stmt = (
            "'eventid' TEXT, 'Channel' TEXT, 'Image' TEXT, "
            "'CommandLine' TEXT, 'TargetFilename' TEXT"
        )
        zircore.create_db(field_stmt)
        zircore.ruleset = [
            {
                "title": "rule a",
                "rule": [
                    "SELECT * FROM logs WHERE Image='x' AND CommandLine LIKE '%a%'",
                    "SELECT * FROM logs WHERE Image='y' AND TargetFilename='z'",
                ],
            },
            {
                "title": "rule b",
                "rule": ["SELECT * FROM logs WHERE Image='q' AND CommandLine='r'"],
            },
        ]
        zircore.create_index()
        # Auto-index candidates come from the loaded ruleset, so they are
        # applied via apply_auto_index() (called by execute_ruleset)
        zircore.apply_auto_index()
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        names = {row[0] for row in cursor.fetchall()}
        # Image appears 3x, CommandLine 2x, TargetFilename 1x — top 2 win.
        assert "idx_Image" in names
        assert "idx_CommandLine" in names
        assert "idx_TargetFilename" not in names
        # Built-in indices remain.
        assert "idx_eventid" in names
        assert "idx_channel_eventid" in names
        zircore.close()

    def test_auto_index_zero_creates_no_extra_indices(self, field_mappings_file, test_logger):
        """auto_index_top_n=0 leaves only built-in indices."""
        proc_config = ProcessingConfig(disable_progress=True, auto_index_top_n=0)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        zircore.create_db("'eventid' TEXT, 'Image' TEXT")
        zircore.ruleset = [
            {"title": "r", "rule": ["SELECT * FROM logs WHERE Image='x'"]}
        ]
        zircore.create_index()
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        names = {row[0] for row in cursor.fetchall()}
        assert "idx_Image" not in names
        assert "idx_eventid" in names
        zircore.close()

    def test_create_index_remove_index_drops_indexes(self, field_mappings_file, test_logger):
        """create_index with remove_index drops the given index names."""
        proc_config = ProcessingConfig(
            disable_progress=True,
            add_index=[],
            remove_index=["idx_channel"],
        )
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        field_stmt = "'eventid' TEXT, 'Channel' TEXT"
        zircore.create_db(field_stmt)
        zircore.create_index()
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_channel'")
        assert cursor.fetchone() is None
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_eventid'")
        assert cursor.fetchone() is not None
        zircore.close()

    def test_save_db_to_disk(self, field_mappings_file, tmp_path, test_logger):
        """Test saving in-memory database to disk."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        # Create and populate
        zircore.execute_query("CREATE TABLE test (id INTEGER, value TEXT)")
        zircore.execute_query("INSERT INTO test VALUES (1, 'test')")

        # Save to disk
        db_file = str(tmp_path / "saved.db")
        zircore.save_db_to_disk(db_file)

        # Verify file exists and contains data
        assert Path(db_file).exists()

        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM test")
        results = cursor.fetchall()
        conn.close()

        assert len(results) == 1
        zircore.close()

    def test_load_db_in_memory(self, field_mappings_file, tmp_path, test_logger):
        """Test loading database from disk to memory."""
        # Create on-disk database
        db_file = str(tmp_path / "source.db")
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test (id INTEGER, value TEXT)")
        cursor.execute("INSERT INTO test VALUES (1, 'loaded')")
        conn.commit()
        conn.close()

        # Load into ZircoliteCore
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        zircore.load_db_in_memory(db_file)

        # Verify data was loaded
        results = zircore.execute_select_query("SELECT * FROM test")
        assert len(results) == 1
        assert results[0]['value'] == 'loaded'

        zircore.close()

    def test_create_connection_raises_runtimeerror_on_sqlite_error(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """When sqlite3.connect raises Error, create_connection raises RuntimeError."""
        with patch('zircolite.core.sqlite3.connect', side_effect=sqlite3.Error("mock")):
            proc_config = ProcessingConfig(db_location=str(tmp_path / "fail.db"))
            with pytest.raises(RuntimeError, match="Unable to open SQLite database"):
                ZircoliteCore(
                    config=field_mappings_file,
                    processing_config=proc_config,
                    logger=test_logger,
                )

    def test_create_connection_reraises_base_exception(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """When sqlite3.connect raises BaseException, create_connection reraises."""
        with patch('zircolite.core.sqlite3.connect', side_effect=MemoryError("mock")):
            proc_config = ProcessingConfig(db_location=str(tmp_path / "fail.db"))
            with pytest.raises(MemoryError):
                ZircoliteCore(
                    config=field_mappings_file,
                    processing_config=proc_config,
                    logger=test_logger,
                )

    def test_create_db_raises_when_execute_query_fails(self, field_mappings_file, test_logger):
        """When execute_query returns False in create_db, RuntimeError is raised."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger,
        )
        with patch('zircolite.core.ZircoliteCore.execute_query', return_value=False):
            with pytest.raises(RuntimeError, match="Unable to create database table"):
                zircore.create_db("'EventID' TEXT")
        zircore.close()

    def test_execute_query_returns_false_when_no_connection(self, field_mappings_file, test_logger):
        """execute_query returns False when db_connection is None."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger,
        )
        zircore.close()
        zircore.db_connection = None
        result = zircore.execute_query("SELECT 1")
        assert result is False

    def test_execute_select_query_returns_empty_when_no_connection(
        self, field_mappings_file, test_logger
    ):
        """execute_select_query returns [] when db_connection is None."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger,
        )
        zircore.close()
        zircore.db_connection = None
        result = zircore.execute_select_query("SELECT 1")
        assert result == []

    def test_execute_select_query_returns_empty_on_sql_error(
        self, field_mappings_file, test_logger
    ):
        """execute_select_query returns [] and logs when query raises sqlite3.Error."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger,
        )
        zircore.execute_query("CREATE TABLE t (x INTEGER)")
        results = zircore.execute_select_query("SELECT * FROM nonexistent_table")
        assert results == []
        zircore.close()

    def test_insert_data_to_db_rollback_on_exception(self, field_mappings_file, test_logger):
        """When executemany raises, insert_data_to_db rolls back and returns False."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger,
        )
        zircore.create_db("'EventID' TEXT COLLATE NOCASE,\n'CommandLine' TEXT COLLATE NOCASE")
        zircore.db_connection.execute(
            "INSERT INTO logs (EventID, CommandLine) VALUES ('1', 'first')"
        )
        zircore.db_connection.commit()
        row_count_before = zircore.execute_select_query("SELECT COUNT(*) as c FROM logs")[0]["c"]
        result = zircore.insert_data_to_db(
            [{"EventID": "2", "CommandLine": "x", "ExtraCol": "y"}]
        )
        assert result is False
        row_count_after = zircore.execute_select_query("SELECT COUNT(*) as c FROM logs")[0]["c"]
        assert row_count_after == row_count_before
        zircore.close()


class TestZircoliteCoreRuleExecution:
    """Tests for rule execution functionality."""

    def test_execute_rule_with_matches(self, field_mappings_file, test_logger):
        """Test executing a rule that produces matches."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        # Setup database with test data
        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n'Computer' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute("INSERT INTO logs (CommandLine, Computer) VALUES ('powershell.exe whoami', 'PC1')")
        zircore.db_connection.execute("INSERT INTO logs (CommandLine, Computer) VALUES ('cmd.exe', 'PC2')")
        zircore.db_connection.commit()

        rule = {
            "title": "Test PowerShell Rule",
            "id": "test-001",
            "description": "Test rule",
            "level": "high",
            "tags": ["attack.execution"],
            "filename": "test.yml",
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }

        results = zircore.execute_rule(rule)

        assert results["title"] == "Test PowerShell Rule"
        assert results["count"] == 1
        assert len(results["matches"]) == 1

        zircore.close()

    def test_execute_rule_no_matches(self, field_mappings_file, test_logger):
        """Test executing a rule with no matches."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute("INSERT INTO logs (CommandLine) VALUES ('notepad.exe')")
        zircore.db_connection.commit()

        rule = {
            "title": "Test Rule",
            "id": "test-001",
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%malware%'"]
        }

        results = zircore.execute_rule(rule)

        assert results == {}
        zircore.close()

    def test_execute_rule_missing_rule_key(self, field_mappings_file, test_logger):
        """Test executing a malformed rule without 'rule' key."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        rule = {"title": "Malformed Rule"}

        results = zircore.execute_rule(rule)

        assert results == {}
        zircore.close()

    def test_execute_rule_with_defaults(self, field_mappings_file, test_logger):
        """Test rule execution fills in default values for missing fields."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute("INSERT INTO logs (CommandLine) VALUES ('test.exe')")
        zircore.db_connection.commit()

        # Minimal rule with only required 'rule' key
        rule = {"rule": ["SELECT * FROM logs"]}

        results = zircore.execute_rule(rule)

        assert results["title"] == "Unnamed Rule"
        assert results["rule_level"] == "unknown"
        assert results["tags"] == []

        zircore.close()

    def test_execute_rule_csv_mode(self, field_mappings_file, test_logger):
        """Test rule execution in CSV mode cleans values."""
        proc_config = ProcessingConfig(csv_mode=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n'Description' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute("INSERT INTO logs (CommandLine, Description) VALUES ('test.exe', 'Line1\nLine2')")
        zircore.db_connection.commit()

        rule = {
            "title": "Test Rule",
            "id": "test-001",
            "description": "Test\ndescription",
            "rule": ["SELECT * FROM logs"]
        }

        results = zircore.execute_rule(rule)

        # CSV mode should strip newlines from description
        assert "\n" not in results["description"]

        zircore.close()

    def test_execute_rule_removes_none_values(self, field_mappings_file, test_logger):
        """Test rule execution removes None values in normal mode."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n'Image' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute("INSERT INTO logs (CommandLine, Image) VALUES ('test.exe', NULL)")
        zircore.db_connection.commit()

        rule = {
            "title": "Test Rule",
            "id": "test-001",
            "rule": ["SELECT * FROM logs"]
        }

        results = zircore.execute_rule(rule)

        assert results, "Expected rule to produce matches"
        assert results.get("matches"), "Expected at least one match"
        first_match = results["matches"][0]
        assert all(v is not None for v in first_match.values())

        zircore.close()


class TestZircoliteCoreRuleset:
    """Tests for ruleset handling."""

    def test_load_ruleset_from_var(self, field_mappings_file, sample_ruleset, test_logger):
        """Test loading ruleset from variable."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)

        assert len(zircore.ruleset) == 3
        zircore.close()

    def test_apply_ruleset_filters(self, field_mappings_file, sample_ruleset, test_logger):
        """Test filtering rules by title."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=["PowerShell"])

        # PowerShell rule should be filtered out
        assert all("PowerShell" not in rule["title"] for rule in zircore.ruleset)
        assert len(zircore.ruleset) == 2

        zircore.close()

    def test_apply_ruleset_removes_empty_rules(self, field_mappings_file, test_logger):
        """Test that empty/null rules are removed."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        ruleset_with_nulls = [
            {"title": "Valid Rule", "rule": ["SELECT 1"]},
            None,
            {"title": "Another Valid", "rule": ["SELECT 2"]}
        ]

        zircore.load_ruleset_from_var(ruleset_with_nulls, rule_filters=None)

        assert len(zircore.ruleset) == 2
        zircore.close()


class TestZircoliteCoreRulesetExecution:
    """Tests for execute_ruleset functionality."""

    def test_execute_ruleset_json_output(self, field_mappings_file, sample_ruleset, tmp_path, test_logger):
        """Test executing ruleset with JSON output."""
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        # Setup database
        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n'TargetFileName' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute("INSERT INTO logs (CommandLine) VALUES ('powershell.exe whoami')")
        zircore.db_connection.commit()

        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)

        output_file = str(tmp_path / "output.json")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)

        # Verify output file
        assert Path(output_file).exists()

        with open(output_file) as f:
            content = f.read()
            results = json.loads(content)

        assert len(results) > 0
        zircore.close()

    def test_execute_ruleset_csv_output(self, field_mappings_file, sample_ruleset, tmp_path, test_logger):
        """Test executing ruleset with CSV output."""
        proc_config = ProcessingConfig(csv_mode=True, disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        # Setup database
        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute("INSERT INTO logs (CommandLine) VALUES ('powershell.exe test')")
        zircore.db_connection.commit()

        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)

        output_file = str(tmp_path / "output.csv")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)

        assert Path(output_file).exists()

        with open(output_file) as f:
            content = f.read()

        assert "rule_title" in content
        zircore.close()

    def test_execute_ruleset_csv_header_covers_every_event_column(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """The CSV header comes from the schema, so no later row loses fields.

        It used to be frozen from the first matching row, and rows carry only
        their non-NULL fields -- so whichever detection was written first
        decided which columns the whole report kept.
        """
        proc_config = ProcessingConfig(csv_mode=True, disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        field_stmt = (
            "'CommandLine' TEXT COLLATE NOCASE,\n"
            "'PrivilegeList' TEXT COLLATE NOCASE,\n"
        )
        zircore.create_db(field_stmt)
        zircore.db_connection.execute(
            "INSERT INTO logs (CommandLine, PrivilegeList) VALUES ('first_row', 'SeTcbPrivilege')"
        )
        zircore.db_connection.execute(
            "INSERT INTO logs (CommandLine, PrivilegeList) VALUES ('second_row', 'SeSecurityPrivilege')"
        )
        zircore.db_connection.commit()

        ruleset = [
            {
                "title": "Narrow projection",
                "id": "narrow-1",
                "description": "CommandLine only",
                "level": "high",
                "tags": [],
                "rule": [
                    "SELECT CommandLine FROM logs WHERE CommandLine = 'first_row'"
                ],
            },
            {
                "title": "Wide projection",
                "id": "wide-1",
                "description": "All columns",
                "level": "medium",
                "tags": [],
                "rule": ["SELECT * FROM logs WHERE CommandLine = 'second_row'"],
            },
        ]
        zircore.load_ruleset_from_var(ruleset, rule_filters=None)

        output_file = str(tmp_path / "extra_keys.csv")
        zircore.execute_ruleset(output_file, write_mode="w", last_ruleset=True)

        assert Path(output_file).exists()
        with open(output_file, encoding="utf-8") as f:
            header = f.readline()
            rows = f.read()
        # The narrow rule is written first, but the wide rule's evidence survives
        assert "PrivilegeList" in header
        assert "CommandLine" in header
        assert "SeSecurityPrivilege" in rows
        assert "row_id" not in header
        zircore.close()

    def test_execute_ruleset_progress_callback_invoked(
        self, field_mappings_file, sample_ruleset, tmp_path, test_logger
    ):
        """progress_callback is called with (current_index, total_rules) for each rule."""
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute(
            "INSERT INTO logs (CommandLine) VALUES ('powershell.exe whoami')"
        )
        zircore.db_connection.commit()
        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)
        total_rules = len(zircore.ruleset)
        progress_updates = []

        def capture(cur: int, tot: int) -> None:
            progress_updates.append((cur, tot))

        output_file = str(tmp_path / "output.json")
        zircore.execute_ruleset(
            output_file,
            write_mode="w",
            last_ruleset=True,
            progress_callback=capture,
        )
        expected = [(i, total_rules) for i in range(total_rules + 1)]
        assert progress_updates == expected
        zircore.close()

    def test_execute_ruleset_with_limit(self, field_mappings_file, tmp_path, test_logger):
        """Test that limit discards rules with too many matches."""
        proc_config = ProcessingConfig(limit=2, disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        # Setup database with many matching records
        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        for i in range(10):
            zircore.db_connection.execute(f"INSERT INTO logs (CommandLine) VALUES ('powershell.exe test{i}')")
        zircore.db_connection.commit()

        ruleset = [{
            "title": "Test Rule",
            "id": "test-001",
            "level": "high",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%'"]
        }]

        zircore.load_ruleset_from_var(ruleset, rule_filters=None)

        output_file = str(tmp_path / "output.json")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)

        with open(output_file) as f:
            content = f.read()

        # With limit=2, the rule should be discarded (10 matches > 2)
        results = json.loads(content)
        assert len(results) == 0

        zircore.close()

    def test_execute_ruleset_keeps_results(self, field_mappings_file, sample_ruleset, tmp_path, test_logger):
        """Test that keep_results stores results in full_results."""
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute("INSERT INTO logs (CommandLine) VALUES ('powershell.exe test')")
        zircore.db_connection.commit()

        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)

        output_file = str(tmp_path / "output.json")
        zircore.execute_ruleset(output_file, write_mode='w', keep_results=True, last_ruleset=True)

        assert len(zircore.full_results) > 0
        zircore.close()

    def test_execute_ruleset_no_output(self, field_mappings_file, sample_ruleset, tmp_path, test_logger):
        """Test executing ruleset with output disabled."""
        proc_config = ProcessingConfig(no_output=True, disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        field_stmt = "'CommandLine' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        zircore.db_connection.execute("INSERT INTO logs (CommandLine) VALUES ('powershell.exe')")
        zircore.db_connection.commit()

        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)

        output_file = str(tmp_path / "output.json")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)

        # No file should be created
        assert not Path(output_file).exists()
        zircore.close()


class TestZircoliteCoreRegexSupport:
    """Tests for regex support in SQL queries."""

    def test_compile_regex_returns_pattern(self):
        """_compile_regex should return a compiled re.Pattern."""
        pat = _compile_regex(r'hello.*world')
        assert isinstance(pat, re.Pattern)

    def test_compile_regex_caches(self):
        """Repeated calls with the same pattern return the same object."""
        pat1 = _compile_regex(r'^test\d+$')
        pat2 = _compile_regex(r'^test\d+$')
        assert pat1 is pat2

    def test_regex_function_registered(self, field_mappings_file, test_logger):
        """Test that regexp function is available in SQLite."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        zircore.execute_query("CREATE TABLE test (value TEXT)")
        zircore.execute_query("INSERT INTO test VALUES ('hello123world')")
        zircore.execute_query("INSERT INTO test VALUES ('test456')")

        # Test regex query
        results = zircore.execute_select_query("SELECT * FROM test WHERE value REGEXP 'hello.*world'")

        assert len(results) == 1
        assert results[0]['value'] == 'hello123world'

        zircore.close()

    def test_regex_function_no_match(self, field_mappings_file, test_logger):
        """Test regex function with no matches."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        zircore.execute_query("CREATE TABLE test (value TEXT)")
        zircore.execute_query("INSERT INTO test VALUES ('hello123world')")

        results = zircore.execute_select_query("SELECT * FROM test WHERE value REGEXP '^xyz'")

        assert len(results) == 0
        zircore.close()

    def test_regex_function_handles_null(self, field_mappings_file, test_logger):
        """Test regex function handles NULL values."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )

        zircore.execute_query("CREATE TABLE test (value TEXT)")
        zircore.execute_query("INSERT INTO test VALUES (NULL)")
        zircore.execute_query("INSERT INTO test VALUES ('valid')")

        # Should not crash on NULL values
        results = zircore.execute_select_query("SELECT * FROM test WHERE value REGEXP 'valid'")

        assert len(results) == 1
        zircore.close()

    def test_regex_against_non_text_column_does_not_break_the_rule(
        self, field_mappings_file, test_logger
    ):
        """A column typed INTEGER must not turn a REGEXP branch into a broken rule.

        Column types are inferred from the first value seen, so a field whose
        first event carried a number is INTEGER for the rest of the run.
        """
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.execute_query("CREATE TABLE test (v INTEGER)")
        zircore.execute_query("INSERT INTO test VALUES (4688)")

        results = zircore.execute_select_query(
            "SELECT * FROM test WHERE v REGEXP '46'", rule_title="Numeric Field Rule"
        )

        assert len(results) == 1
        assert not zircore.rules_in_error

        zircore.close()

    def test_regex_invalid_pattern_returns_no_match(self, field_mappings_file, test_logger):
        """Invalid regex pattern should not crash; query returns 0 matches."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )
        zircore.execute_query("CREATE TABLE test (v TEXT)")
        zircore.execute_query("INSERT INTO test VALUES ('test')")
        results = zircore.execute_select_query("SELECT * FROM test WHERE v REGEXP '[invalid'")
        assert len(results) == 0
        zircore.close()


@pytest.mark.slow
class TestZircoliteCoreStreamingMode:
    """Tests for ZircoliteCore streaming mode functionality."""

    def test_run_streaming_basic(self, field_mappings_file, tmp_path, test_logger, default_args_config):
        """Test basic run_streaming functionality."""
        # Create a test JSON file
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "test.exe"}}},
            {"Event": {"System": {"EventID": 2}, "EventData": {"CommandLine": "another.exe"}}},
        ]

        json_file = tmp_path / "test_events.json"
        with open(json_file, 'w') as f:
            f.writelines(json.dumps(event) + "\n" for event in events)

        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        total_events = zircore.run_streaming(
            [str(json_file)],
            input_type='json',
            args_config=default_args_config,
            disable_progress=True
        )

        assert total_events == 2
        zircore.close()

    def test_run_streaming_creates_table_and_index(self, field_mappings_file, tmp_path, test_logger, default_args_config):
        """Test that run_streaming creates table and index."""
        events = [{"Event": {"System": {"EventID": 1}}}]

        json_file = tmp_path / "test.json"
        with open(json_file, 'w') as f:
            f.write(json.dumps(events[0]) + "\n")

        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        zircore.run_streaming(
            [str(json_file)],
            input_type='json',
            args_config=default_args_config,
            disable_progress=True
        )

        # Check table exists
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        table_result = cursor.fetchone()
        assert table_result is not None

        # Check index exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_eventid'")
        index_result = cursor.fetchone()
        assert index_result is not None

        zircore.close()

    def test_run_streaming_with_rules(self, field_mappings_file, tmp_path, test_logger, default_args_config, sample_ruleset):
        """Test run_streaming followed by rule execution."""
        events = [
            {"Event": {"System": {"EventID": 1}, "EventData": {"CommandLine": "powershell.exe -c test"}}},
        ]

        json_file = tmp_path / "test.json"
        with open(json_file, 'w') as f:
            f.write(json.dumps(events[0]) + "\n")

        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        zircore.run_streaming(
            [str(json_file)],
            input_type='json',
            args_config=default_args_config,
            disable_progress=True
        )

        zircore.load_ruleset_from_var(sample_ruleset, rule_filters=None)

        output_file = str(tmp_path / "output.json")
        zircore.execute_ruleset(output_file, write_mode='w', last_ruleset=True)

        assert Path(output_file).exists()

        with open(output_file) as f:
            results = json.load(f)

        # PowerShell rule should match
        assert len(results) > 0

        zircore.close()

    def test_run_streaming_json_array(self, field_mappings_file, tmp_path, test_logger, default_args_config):
        """Test run_streaming with JSON array input."""
        events = [
            {"Event": {"System": {"EventID": 1}}},
            {"Event": {"System": {"EventID": 2}}},
            {"Event": {"System": {"EventID": 3}}},
        ]

        json_file = tmp_path / "test_array.json"
        with open(json_file, 'w') as f:
            f.write(json.dumps(events))

        # Configure for JSON array
        default_args_config.json_array_input = True

        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        total_events = zircore.run_streaming(
            [str(json_file)],
            input_type='json_array',
            args_config=default_args_config,
            disable_progress=True
        )

        assert total_events == 3
        zircore.close()

    def test_run_streaming_handles_empty_file(self, field_mappings_file, tmp_path, test_logger, default_args_config):
        """Test run_streaming gracefully handles empty files."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")

        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )

        total_events = zircore.run_streaming(
            [str(empty_file)],
            input_type='json',
            args_config=default_args_config,
            disable_progress=True
        )

        assert total_events == 0
        zircore.close()

    def test_run_streaming_logs_error_and_returns_zero_on_file_exception(
        self, field_mappings_file, tmp_path, test_logger, default_args_config
    ):
        """When process_file_streaming raises, run_streaming logs and returns 0 for that file."""
        not_a_file = str(tmp_path / "nonexistent.json")
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        total = zircore.run_streaming(
            [not_a_file],
            input_type='json',
            args_config=default_args_config,
            disable_progress=True,
        )
        assert total == 0
        zircore.close()

    def test_run_streaming_with_progress_bar_when_not_quiet(
        self, field_mappings_file, tmp_path, test_logger, default_args_config
    ):
        """run_streaming uses spinner progress when is_quiet() is False and disable_progress is True."""
        json_file = tmp_path / "ev.json"
        json_file.write_text(json.dumps({"Event": {"System": {"EventID": 1}}}) + "\n")
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        with patch('zircolite.core.is_quiet', return_value=False):
            total = zircore.run_streaming(
                [str(json_file)],
                input_type='json',
                args_config=default_args_config,
                disable_progress=True,
            )
        assert total == 1
        zircore.close()

    def test_run_streaming_with_bar_progress_when_not_quiet_and_multi_file(
        self, field_mappings_file, tmp_path, test_logger, default_args_config
    ):
        """run_streaming uses BarColumn progress when is_quiet() False and disable_progress False."""
        f1 = tmp_path / "a.json"
        f2 = tmp_path / "b.json"
        ev = json.dumps({"Event": {"System": {"EventID": 1}}}) + "\n"
        f1.write_text(ev)
        f2.write_text(ev)
        proc_config = ProcessingConfig(disable_progress=False)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        with patch('zircolite.core.is_quiet', return_value=False):
            total = zircore.run_streaming(
                [str(f1), str(f2)],
                input_type='json',
                args_config=default_args_config,
                disable_progress=False,
            )
        assert total == 2
        zircore.close()


class TestZircoliteCoreEscapeIdentifier:
    """Tests for the escape_identifier method and its caching."""

    def test_escape_plain_identifier(self, field_mappings_file, test_logger):
        """Plain identifiers are returned unchanged."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        assert zircore.escape_identifier("EventID") == "EventID"
        zircore.close()

    def test_escape_identifier_with_quotes(self, field_mappings_file, test_logger):
        """Double quotes inside identifiers are doubled."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        assert zircore.escape_identifier('col"name') == 'col""name'
        zircore.close()

    def test_escape_identifier_caching(self, field_mappings_file, test_logger):
        """Repeated calls return the same cached result."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        first = zircore.escape_identifier("CachedCol")
        second = zircore.escape_identifier("CachedCol")
        assert first == second
        assert "CachedCol" in zircore._escape_cache
        zircore.close()


class TestZircoliteCoreGetCursorAndClose:
    """Tests for _get_cursor reuse and close() safety."""

    def test_get_cursor_returns_same_object(self, field_mappings_file, test_logger):
        """_get_cursor should return the same cursor on repeated calls."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        c1 = zircore._get_cursor()
        c2 = zircore._get_cursor()
        assert c1 is c2
        zircore.close()

    def test_close_clears_cursor(self, field_mappings_file, test_logger):
        """After close(), the internal cursor should be None."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore._get_cursor()  # Ensure cursor is populated
        zircore.close()
        assert zircore._cursor is None

    def test_close_can_be_called_once(self, field_mappings_file, test_logger):
        """close() should work without error on a live connection."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.close()
        # Connection is closed; verify cursor was cleared
        assert zircore._cursor is None

    def test_del_closes_connection(self, field_mappings_file, test_logger):
        """__del__ runs and closes db_connection when instance is garbage-collected."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        assert zircore.db_connection is not None
        del zircore
        gc.collect()


class TestBugFixes:
    """Tests verifying specific bug fixes."""

    def test_apply_ruleset_filters_missing_title(self, field_mappings_file, test_logger):
        """Rules without a 'title' key should not cause KeyError when filtering."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        ruleset = [
            {"title": "Keep This", "rule": ["SELECT 1"]},
            {"rule": ["SELECT 2"]},
            {"title": "Filter Out", "rule": ["SELECT 3"]},
        ]
        zircore.load_ruleset_from_var(ruleset, rule_filters=["Filter Out"])
        assert len(zircore.ruleset) == 2
        titles = [r.get("title", "") for r in zircore.ruleset]
        assert "Keep This" in titles
        assert "Filter Out" not in titles
        zircore.close()

    def test_create_db_raises_runtime_error(self, field_mappings_file, test_logger):
        """create_db raises RuntimeError instead of calling sys.exit."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        with patch('zircolite.core.ZircoliteCore.execute_query', return_value=False):
            with pytest.raises(RuntimeError, match="Unable to create database table"):
                zircore.create_db("'x' TEXT")
        zircore.close()

    def test_run_rule_tests_heterogeneous_keys(self, field_mappings_file, tmp_path, test_logger):
        """run_rule_tests builds schema from all event keys, not just the first."""
        test_file = tmp_path / "tests.json"
        test_cases = [{
            "title": "Test Rule",
            "true_positive": [
                {"CommandLine": "cmd.exe"},
                {"CommandLine": "powershell.exe", "Image": "ps.exe"},
            ],
            "true_negative": [],
        }]
        test_file.write_text(json.dumps(test_cases))

        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.ruleset = [{
            "title": "Test Rule",
            "id": "t1",
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%cmd%'"],
        }]
        results = zircore.run_rule_tests(str(test_file))
        assert len(results) == 1
        assert results[0]["error"] == ""
        assert results[0]["tp_pass"] is True
        zircore.close()


class TestAppendModeOutput:
    """Regression tests for JSON/CSV append-mode output corruption."""

    def _make_core(self, field_mappings_file, test_logger, csv_mode=False):
        proc_config = ProcessingConfig(csv_mode=csv_mode, disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        zircore.create_db("'CommandLine' TEXT COLLATE NOCASE,\n")
        zircore.db_connection.execute(
            "INSERT INTO logs (CommandLine) VALUES ('powershell.exe test')"
        )
        zircore.db_connection.commit()
        zircore.load_ruleset_from_var(
            [{
                "title": "PS Rule",
                "id": "ps-1",
                "description": "d",
                "level": "high",
                "tags": [],
                "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%' ESCAPE '\\'"],
            }],
            rule_filters=None,
        )
        return zircore

    def test_append_to_nonexistent_file_produces_valid_json(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """Appending to a missing file must start a new JSON array."""
        zircore = self._make_core(field_mappings_file, test_logger)
        out = str(tmp_path / "out.json")
        zircore.execute_ruleset(out, write_mode="a", last_ruleset=True)
        with open(out) as f:
            results = json.load(f)
        assert len(results) == 1
        zircore.close()

    def test_csv_append_keeps_header_alignment_across_calls(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """Append calls must reuse the first call's fieldnames, not rebuild them."""
        proc_config = ProcessingConfig(csv_mode=True, disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        zircore.create_db(
            "'CommandLine' TEXT COLLATE NOCASE, 'User' TEXT COLLATE NOCASE,\n"
        )
        zircore.db_connection.execute(
            "INSERT INTO logs (CommandLine, User) VALUES ('powershell.exe', 'SECRETUSER')"
        )
        zircore.db_connection.commit()
        out = str(tmp_path / "out.csv")

        zircore.load_ruleset_from_var(
            [{
                "title": "CmdLine Rule", "id": "c1", "description": "d",
                "level": "high", "tags": [],
                "rule": ["SELECT CommandLine FROM logs WHERE CommandLine LIKE '%powershell%' ESCAPE '\\'"],
            }],
            rule_filters=None,
        )
        zircore.execute_ruleset(out, write_mode="w", last_ruleset=False)

        zircore.load_ruleset_from_var(
            [{
                "title": "User Rule", "id": "u1", "description": "d",
                "level": "high", "tags": [],
                "rule": ["SELECT User FROM logs WHERE User = 'SECRETUSER'"],
            }],
            rule_filters=None,
        )
        zircore.execute_ruleset(out, write_mode="a", last_ruleset=True)

        with open(out, newline="") as f:
            rows = list(csv.DictReader(f, delimiter=";"))
        assert len(rows) == 2
        # A row from the second call must not land its values under the
        # first call's columns
        assert all(r["CommandLine"] != "SECRETUSER" for r in rows)
        zircore.close()

    def test_append_to_empty_file_produces_valid_json(
        self, field_mappings_file, tmp_path, test_logger
    ):
        out = tmp_path / "out.json"
        out.write_text("")
        zircore = self._make_core(field_mappings_file, test_logger)
        zircore.execute_ruleset(str(out), write_mode="a", last_ruleset=True)
        with open(out) as f:
            results = json.load(f)
        assert len(results) == 1
        zircore.close()

    def test_append_to_empty_array_produces_valid_json(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """Appending to '[]' must not produce '[, ...]'."""
        out = tmp_path / "out.json"
        out.write_text("[]")
        zircore = self._make_core(field_mappings_file, test_logger)
        zircore.execute_ruleset(str(out), write_mode="a", last_ruleset=True)
        with open(out) as f:
            results = json.load(f)
        assert len(results) == 1
        zircore.close()

    def test_two_appends_produce_valid_json_with_both_results(
        self, field_mappings_file, tmp_path, test_logger
    ):
        out = str(tmp_path / "out.json")
        zircore = self._make_core(field_mappings_file, test_logger)
        zircore.execute_ruleset(out, write_mode="w", last_ruleset=True)
        zircore.execute_ruleset(out, write_mode="a", last_ruleset=True)
        with open(out) as f:
            results = json.load(f)
        assert len(results) == 2
        zircore.close()

    def test_csv_append_writes_header_once(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """CSV append across two execute_ruleset calls must not duplicate the header."""
        out = str(tmp_path / "out.csv")
        zircore = self._make_core(field_mappings_file, test_logger, csv_mode=True)
        zircore.execute_ruleset(out, write_mode="w", last_ruleset=True)
        zircore.execute_ruleset(out, write_mode="a", last_ruleset=True)
        with open(out) as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        header_count = sum(1 for ln in lines if ln.startswith("rule_title"))
        assert header_count == 1
        zircore.close()


class TestRunRuleTestsTyping:
    """run_rule_tests must build typed schemas matching production semantics."""

    def test_numeric_range_predicate_matches_production(self, field_mappings_file, tmp_path, test_logger):
        """A >= predicate must behave numerically (all-TEXT schemas compare lexicographically)."""
        test_file = tmp_path / "tests.json"
        test_cases = [{
            "title": "Range Rule",
            "true_positive": [{"EventID": 10001}],
            "true_negative": [{"EventID": 9999}],
        }]
        test_file.write_text(json.dumps(test_cases))

        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.ruleset = [{
            "title": "Range Rule",
            "id": "range-1",
            "rule": ["SELECT * FROM logs WHERE EventID >= 10000"],
        }]
        results = zircore.run_rule_tests(str(test_file))
        assert len(results) == 1
        assert results[0]["tp_pass"] is True
        assert results[0]["tn_pass"] is True
        zircore.close()

    def test_text_predicate_case_insensitive_matches_production(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """Production TEXT columns are COLLATE NOCASE; '=' must ignore case here too."""
        test_file = tmp_path / "tests.json"
        test_cases = [{
            "title": "Case Rule",
            "true_positive": [{"CommandLine": "POWERSHELL.EXE"}],
            "true_negative": [{"CommandLine": "cmd.exe"}],
        }]
        test_file.write_text(json.dumps(test_cases))

        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.ruleset = [{
            "title": "Case Rule",
            "id": "case-1",
            "rule": ["SELECT * FROM logs WHERE CommandLine = 'powershell.exe'"],
        }]
        results = zircore.run_rule_tests(str(test_file))
        assert len(results) == 1
        assert results[0]["tp_pass"] is True
        assert results[0]["tn_pass"] is True
        zircore.close()

    def test_sql_keyword_event_key_is_inserted(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """Event keys that are SQL keywords (e.g. 'Group') must insert and match."""
        test_file = tmp_path / "tests.json"
        test_cases = [{
            "title": "Group Rule",
            "true_positive": [{"Group": "admins"}],
            "true_negative": [{"Group": "users"}],
        }]
        test_file.write_text(json.dumps(test_cases))

        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.ruleset = [{
            "title": "Group Rule",
            "id": "group-1",
            "rule": ["SELECT * FROM logs WHERE \"Group\" = 'admins'"],
        }]
        results = zircore.run_rule_tests(str(test_file))
        assert len(results) == 1
        assert results[0]["error"] == ""
        assert results[0]["tp_pass"] is True
        assert results[0]["tn_pass"] is True
        zircore.close()

    def test_insert_failure_is_reported_as_error(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """A failed test-event insert must surface as an error, not a silent miss."""
        test_file = tmp_path / "tests.json"
        test_cases = [{
            "title": "Broken Insert",
            "true_positive": [{"CommandLine": "cmd.exe"}],
            "true_negative": [],
        }]
        test_file.write_text(json.dumps(test_cases))

        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.ruleset = [{
            "title": "Broken Insert",
            "id": "broken-1",
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%cmd%'"],
        }]
        with patch.object(ZircoliteCore, "insert_data_to_db", return_value=False):
            results = zircore.run_rule_tests(str(test_file))
        assert len(results) == 1
        assert results[0]["tp_pass"] is False
        assert "insert" in results[0]["error"].lower()
        zircore.close()

    def test_non_dict_test_case_entries_are_ignored(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """Malformed (non-object) entries must be skipped, not crash the run."""
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps([
            "junk",
            {
                "title": "Test Rule",
                "true_positive": [{"CommandLine": "cmd.exe"}],
                "true_negative": [],
            },
        ]))

        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.ruleset = [{
            "title": "Test Rule",
            "id": "t1",
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%cmd%'"],
        }]
        results = zircore.run_rule_tests(str(test_file))
        assert any(r["title"] == "Test Rule" and r["tp_pass"] for r in results)
        zircore.close()


class TestCoreRobustness:
    """Regression tests for core robustness fixes."""

    def test_load_db_in_memory_missing_file_raises(self, field_mappings_file, test_logger, tmp_path):
        """A missing DB path must raise instead of creating a 0-byte file."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        missing = str(tmp_path / "nope.db")
        with pytest.raises(RuntimeError, match="does not exist"):
            zircore.load_db_in_memory(missing)
        assert not Path(missing).exists()
        zircore.close()

    def test_load_db_in_memory_reapplies_auto_index(
        self, field_mappings_file, test_logger, tmp_path
    ):
        """Each loaded DB must get auto-indexes; backup() replaces the whole in-memory DB."""
        def make_db(path):
            conn = sqlite3.connect(str(path))
            conn.execute(
                "CREATE TABLE logs (row_id INTEGER PRIMARY KEY, CommandLine TEXT)"
            )
            conn.execute("INSERT INTO logs (CommandLine) VALUES ('powershell.exe')")
            conn.commit()
            conn.close()

        db1 = tmp_path / "a.db"
        db2 = tmp_path / "b.db"
        make_db(db1)
        make_db(db2)

        proc_config = ProcessingConfig(auto_index_top_n=5, disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger,
        )
        zircore.load_ruleset_from_var(
            [{
                "title": "PS Rule", "id": "ps-1", "description": "d",
                "level": "high", "tags": [],
                "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%powershell%' ESCAPE '\\'"],
            }],
            rule_filters=None,
        )

        def index_names():
            cur = zircore.db_connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
            )
            return {row[0] for row in cur.fetchall()}

        zircore.load_db_in_memory(str(db1))
        zircore.apply_auto_index()
        assert index_names()

        zircore.load_db_in_memory(str(db2))
        zircore.apply_auto_index()
        assert index_names()
        zircore.close()

    def test_execute_rule_with_string_rule_value_yields_nothing(self, field_mappings_file, test_logger):
        """A 'rule' given as a string must be rejected, not iterated by character."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.create_db("'CommandLine' TEXT COLLATE NOCASE,\n")
        result = zircore.execute_rule({"title": "Bad", "rule": "SELECT * FROM logs"})
        assert result == {}
        zircore.close()

    def test_run_rule_tests_reports_orphan_cases(self, field_mappings_file, tmp_path, test_logger):
        """Test cases referencing missing rules must appear in results."""
        test_file = tmp_path / "tests.json"
        test_file.write_text(json.dumps([
            {"title": "Ghost Rule", "true_positive": [{"CommandLine": "x"}]},
        ]))
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.ruleset = [{
            "title": "Real Rule", "id": "r1",
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%x%'"],
        }]
        results = zircore.run_rule_tests(str(test_file))
        orphan = [r for r in results if r["title"] == "Ghost Rule"]
        assert len(orphan) == 1
        assert orphan[0]["error"] == "no matching rule in ruleset"
        zircore.close()


class TestAutoIndexRespectsRemoveIndex:
    """--auto-index must not resurrect an index --remove-index dropped."""

    def _core(self, tmp_path, field_mappings_file, remove_index):
        from zircolite import ProcessingConfig, ZircoliteCore

        core = ZircoliteCore(
            config=str(field_mappings_file),
            processing_config=ProcessingConfig(
                auto_index_top_n=5, remove_index=remove_index
            ),
        )
        core.ruleset = [{
            "title": "t",
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%x%' "
                     "AND Computer = 'a'"],
        }]
        return core

    def test_dropped_index_is_not_a_candidate(self, tmp_path, field_mappings_file):
        core = self._core(tmp_path, field_mappings_file, ["idx_CommandLine"])
        try:
            candidates = core._auto_index_candidates(["CommandLine", "Computer"])
        finally:
            core.close()

        assert "CommandLine" not in candidates
        assert "Computer" in candidates

    def test_other_columns_are_untouched(self, tmp_path, field_mappings_file):
        core = self._core(tmp_path, field_mappings_file, [])
        try:
            candidates = core._auto_index_candidates(["CommandLine", "Computer"])
        finally:
            core.close()

        assert set(candidates) == {"CommandLine", "Computer"}


class TestRulesThatSilentlyMatchedNothing:
    """Regressions for rules that returned zero while reporting no error.

    A detection tool that finds nothing and says nothing is indistinguishable
    from a clean estate, so each of these must either match or be listed in
    ``rules_in_error``.
    """

    def _core(self, field_mappings_file, test_logger):
        core = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        core.create_db('"Channel" TEXT COLLATE NOCASE, "CommandLine" TEXT COLLATE NOCASE')
        core.db_connection.execute(
            "INSERT INTO logs (Channel, CommandLine) VALUES (?, ?)",
            ("Security", "c:/evil.exe"),
        )
        core.db_connection.commit()
        return core

    def test_backtick_quoted_field_is_widened_and_matches(
        self, field_mappings_file, test_logger
    ):
        """ECS field names are backtick-quoted, and were invisible to widening.

        pysigma-backend-sqlite quotes every field name that is not
        ``^[a-zA-Z0-9_]*$``, which is every ``winlog.*`` / ``event.code`` /
        ``@timestamp`` name. A regex matching only bare identifiers never saw
        them, so the column was never added and the whole rule lost.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            query = (
                "SELECT * FROM logs WHERE Channel='Security' "
                "AND (`event.code`='4688' OR CommandLine LIKE '%evil%')"
            )
            results = core.execute_select_query(query, rule_title="ecs rule")

            assert len(results) == 1
            assert "event.code" in core._get_table_columns()
        finally:
            core.close()

    def test_text_inside_a_string_literal_is_not_a_column(
        self, field_mappings_file, test_logger
    ):
        """``LIKE '%user=bob%'`` names one column, not two.

        A column invented out of a CommandLine pattern is ALTERed into the
        table, where it pollutes the CSV header and skews index ranking.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            query = (
                "SELECT * FROM logs WHERE CommandLine LIKE '%user=bob%' "
                "OR NewProcessName='x'"
            )
            core.execute_select_query(query, rule_title="literal rule")

            assert core._query_columns(query) == {"CommandLine", "NewProcessName"}
            assert "user" not in core._get_table_columns()
        finally:
            core.close()

    def test_rule_referencing_only_absent_fields_is_still_widened(
        self, field_mappings_file, test_logger
    ):
        """``|exists: false`` becomes ``IS NULL``, which matches once widened."""
        core = self._core(field_mappings_file, test_logger)
        try:
            results = core.execute_select_query(
                "SELECT * FROM logs WHERE Foo IS NULL", rule_title="exists-false rule"
            )

            assert len(results) == 1
        finally:
            core.close()

    def test_uncompilable_regex_is_reported_not_silently_empty(
        self, field_mappings_file, test_logger
    ):
        """A PCRE-only pattern must be flagged, not read as a clean non-match.

        Catching re.error inside the UDF returns 0 per row, which is exactly
        what a genuine non-match looks like.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            results = core.execute_select_query(
                "SELECT * FROM logs WHERE CommandLine REGEXP '(?<bad'",
                rule_title="bad regex rule",
            )

            assert results == []
            assert "bad regex rule" in core.rules_in_error
            assert "invalid regex" in core.rules_in_error["bad regex rule"]
        finally:
            core.close()

    def test_valid_regex_still_matches(self, field_mappings_file, test_logger):
        core = self._core(field_mappings_file, test_logger)
        try:
            results = core.execute_select_query(
                "SELECT * FROM logs WHERE CommandLine REGEXP 'evil'",
                rule_title="good regex rule",
            )

            assert len(results) == 1
            assert core.rules_in_error == {}
        finally:
            core.close()

    def test_test_rules_schema_matches_how_ingestion_stores_booleans(self):
        """--test-rules must not fail a rule that fires in a real run.

        Ingestion writes booleans as 'true'/'false' strings; inferring INTEGER
        here reported a working rule as a false negative.
        """
        events = [{"IsExecutable": True, "EventID": 1}]

        statement = ZircoliteCore._infer_field_statement(events)
        normalised = ZircoliteCore._as_ingested(events[0])

        assert '"IsExecutable" INTEGER' not in statement
        assert normalised["IsExecutable"] == "true"
        assert normalised["EventID"] == 1


class TestQueryPlannerStatistics:
    """Widening the table for a rule must not cost the planner its bearings.

    A rule naming a field the dataset never produced has that column added as
    NULL, which more than doubled the column count on a real corpus. With no
    statistics SQLite prices a row by its column count alone, so the wider table
    moved every query off the selective index -- several times the wall clock
    for exactly the same detections.
    """

    # 5,000 rows, 20 distinct EventIDs and 2 distinct Channels, so a lookup on
    # EventID returns 250 rows where one on Channel returns 2,500.
    ROWS = 5000
    EVENTID_ROWS_PER_KEY = 250
    CHANNEL_ROWS_PER_KEY = 2500

    SELECTIVE_QUERY = "SELECT * FROM logs WHERE Channel = 'Security' AND EventID = '4601'"

    RULESET: ClassVar[list[dict]] = [
        {
            "title": "channel and one eventid",
            "id": "aaaaaaaa-0000-0000-0000-000000000001",
            "level": "high",
            "tags": [],
            "rule": [SELECTIVE_QUERY],
        },
        {
            "title": "channel and an eventid list",
            "id": "aaaaaaaa-0000-0000-0000-000000000002",
            "level": "medium",
            "tags": [],
            "rule": [
                "SELECT * FROM logs WHERE Channel = 'Security' AND "
                "(EventID = '4601' OR EventID = '4603' OR EventID = '4605')"
            ],
        },
        {
            "title": "a substring of the command line",
            "id": "aaaaaaaa-0000-0000-0000-000000000003",
            "level": "low",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE CommandLine LIKE '%evil%' ESCAPE '\\'"],
        },
        {
            "title": "a field this dataset never produced",
            "id": "aaaaaaaa-0000-0000-0000-000000000004",
            "level": "informational",
            "tags": [],
            "rule": ["SELECT * FROM logs WHERE OriginalFileName IS NULL"],
        },
    ]

    def _core(self, field_mappings_file, test_logger):
        """A corpus shaped like a real one: EventID is selective, Channel is not."""
        core = ZircoliteCore(
            config=field_mappings_file,
            processing_config=ProcessingConfig(disable_progress=True, no_output=True),
            logger=test_logger,
        )
        core.create_db(
            '"EventID" TEXT COLLATE NOCASE, "Channel" TEXT COLLATE NOCASE, '
            '"CommandLine" TEXT COLLATE NOCASE'
        )
        core.db_connection.executemany(
            "INSERT INTO logs (EventID, Channel, CommandLine) VALUES (?, ?, ?)",
            [
                (str(4600 + i % 20), "Security" if i % 2 else "System", "c:/evil.exe")
                for i in range(self.ROWS)
            ],
        )
        core.db_connection.commit()
        core.create_index()
        return core

    def _run_ruleset(self, core):
        core.load_ruleset_from_var(self.RULESET, rule_filters=None)
        core.execute_ruleset("", write_mode="w", last_ruleset=True, show_table=False)

    def _stat1(self, core):
        """What ANALYZE recorded for the logs table, keyed by index name."""
        return {
            idx: stat
            for idx, stat in core.db_connection.execute(
                "SELECT idx, stat FROM sqlite_stat1 WHERE tbl = 'logs'"
            )
            if idx
        }

    def _rows_per_key(self, core, index_name):
        return int(self._stat1(core)[index_name].split()[1])

    def _plan(self, core, query):
        return " | ".join(
            row[3] for row in core.db_connection.execute("EXPLAIN QUERY PLAN " + query)
        )

    def test_execute_ruleset_measures_the_statistics_instead_of_sampling_them(
        self, field_mappings_file, test_logger
    ):
        """Sampled statistics stop discriminating exactly when the corpus grows.

        ``PRAGMA optimize`` samples at an implicit ``analysis_limit``, so its
        figures are capped rather than counted -- and once a corpus is large
        enough for both indexes to hit that cap they report the same number, the
        one thing the planner needed to tell them apart. A small
        ``analysis_limit`` reproduces the bad plan for the same reason, so this
        pins the counted values, not merely that some statistics exist.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            self._run_ruleset(core)

            assert self._rows_per_key(core, "idx_eventid") == self.EVENTID_ROWS_PER_KEY
            assert (
                self._rows_per_key(core, "idx_channel_eventid")
                == self.CHANNEL_ROWS_PER_KEY
            )
        finally:
            core.close()

    def test_execute_ruleset_leaves_statistics_for_the_logs_table(
        self, field_mappings_file, test_logger
    ):
        core = self._core(field_mappings_file, test_logger)
        try:
            self._run_ruleset(core)

            analysed = core.db_connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'sqlite_stat1'"
            ).fetchone()
            assert analysed, "the logs table was never analysed"
            assert set(self._stat1(core)) >= {"idx_eventid", "idx_channel_eventid"}
        finally:
            core.close()

    def test_the_statistics_tell_the_selective_index_from_the_broad_one(
        self, field_mappings_file, test_logger
    ):
        """A channel is the broad key here, an eventID the narrow one.

        ``_rows_per_key`` reads the leading column, so the composite is being
        priced as the channel lookup it starts with.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            self._run_ruleset(core)

            assert self._rows_per_key(core, "idx_eventid") < self._rows_per_key(
                core, "idx_channel_eventid"
            )
        finally:
            core.close()

    def test_a_rule_naming_eventid_and_channel_searches_on_both(
        self, field_mappings_file, test_logger
    ):
        """Only the post-condition: which index the planner guesses without
        statistics is its own business, and changes between SQLite releases.

        Both columns must appear in the seek. A plan naming the composite but
        constraining only ``Channel`` would still be fetching and re-checking
        every row of that channel, which is the cost the composite exists to
        remove.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            self._run_ruleset(core)
            plan = self._plan(core, self.SELECTIVE_QUERY)

            assert "idx_channel_eventid" in plan
            assert "Channel=? AND EventID=?" in plan
        finally:
            core.close()

    def test_the_composite_narrows_further_than_either_column_alone(
        self, field_mappings_file, test_logger
    ):
        """Why it replaced the channel-only index rather than joining it."""
        core = self._core(field_mappings_file, test_logger)
        try:
            self._run_ruleset(core)
            composite = self._stat1(core)["idx_channel_eventid"].split()
            both_columns = int(composite[2])

            assert both_columns < int(composite[1])  # narrower than Channel alone
            assert both_columns <= self._rows_per_key(core, "idx_eventid")
        finally:
            core.close()

    def test_widening_the_table_does_not_discard_the_statistics(
        self, field_mappings_file, test_logger
    ):
        """One pass before the rule loop is enough only if ADD COLUMN spares them.

        This is what would fail if the analysis were ever moved after the loop,
        or a mid-loop invalidation added.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            self._run_ruleset(core)
            before = self._stat1(core)

            widening_rule = "SELECT * FROM logs WHERE " + " OR ".join(
                f"pad{i} IS NULL" for i in range(120)
            )
            core.execute_select_query(widening_rule, rule_title="a very absent rule")

            assert len(core._get_table_columns()) >= 120
            assert self._stat1(core) == before
            assert "idx_channel_eventid" in self._plan(core, self.SELECTIVE_QUERY)
        finally:
            core.close()

    def test_the_same_rules_match_the_same_events_before_and_after_analyze(
        self, field_mappings_file, test_logger
    ):
        """A set comparison on purpose, never an order or byte one.

        Driving a query from a different index returns the same rows in a
        different order, and ``execute_rule`` reports them as SQLite hands them
        over. Counts and matched events are what must not move.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            core.load_ruleset_from_var(self.RULESET, rule_filters=None)

            def matched():
                found = {}
                for rule in core.ruleset:
                    results = core.execute_rule(rule)
                    if results:
                        found[results["title"]] = {
                            row["row_id"] for row in results["matches"]
                        }
                return found

            before = matched()
            core.db_connection.execute("ANALYZE logs")
            after = matched()

            assert before, "the fixture ruleset should match something"
            assert before == after
        finally:
            core.close()

    def test_a_field_the_dataset_never_produced_is_added_and_still_matches_is_null(
        self, field_mappings_file, test_logger
    ):
        core = self._core(field_mappings_file, test_logger)
        try:
            self._run_ruleset(core)

            assert "OriginalFileName" in core._get_table_columns()
            results = core.execute_select_query(
                "SELECT * FROM logs WHERE OriginalFileName IS NULL", rule_title="absent"
            )
            assert len(results) == self.ROWS
        finally:
            core.close()

    def test_an_added_column_matches_only_the_is_null_test(
        self, field_mappings_file, test_logger
    ):
        """``IS NULL`` is the one construct widening changes the answer to.

        Giving the added column a DEFAULT instead of NULL would look harmless and
        would turn every ``|exists: false`` rule into a corpus-wide false positive.
        """
        core = self._core(field_mappings_file, test_logger)
        try:
            core.execute_select_query(
                "SELECT * FROM logs WHERE Absent IS NULL", rule_title="widen it"
            )
            assert "Absent" in core._get_table_columns()

            silent = [
                "SELECT * FROM logs WHERE NOT Absent = Absent",
                "SELECT * FROM logs WHERE Absent = 'v'",
                "SELECT * FROM logs WHERE Absent LIKE '%v%'",
                "SELECT * FROM logs WHERE NOT (Absent LIKE '%v%')",
            ]
            for query in silent:
                assert core.execute_select_query(query, rule_title="quiet") == []
        finally:
            core.close()


class TestTheRulesetIsLexedOnce:
    """Rule SQL is read once per statement, not once per statement per file.

    Reading a ruleset is dominated by lexing it, and per-file and parallel modes
    run the same ruleset against every input file. The scan cache used to be an
    LRU far smaller than a real ruleset, read in a fixed order, so it evicted
    every entry just before it was needed and each file re-lexed everything.
    """

    RULE_COUNT = 300

    def _ruleset(self):
        return [
            {
                "title": f"rule {i}",
                "id": f"id-{i}",
                "level": "medium",
                "rule": [
                    "SELECT * FROM logs WHERE Channel = 'Security' "
                    f"AND EventID = {4000 + i}"
                ],
            }
            for i in range(self.RULE_COUNT)
        ]

    def _core(self, field_mappings_file, test_logger):
        core = ZircoliteCore(
            config=field_mappings_file,
            processing_config=ProcessingConfig(no_output=True, disable_progress=True),
            logger=test_logger,
        )
        core.create_db('"Channel" TEXT COLLATE NOCASE, "EventID" INTEGER COLLATE NOCASE')
        core.db_connection.execute(
            "INSERT INTO logs (Channel, EventID) VALUES ('Security', 4001)"
        )
        core.db_connection.commit()
        core.load_ruleset_from_var(ruleset=self._ruleset(), rule_filters=None)
        return core

    def _counting_lexer(self, monkeypatch):
        """Count statements lexed, not seconds spent -- timings are not evidence."""
        lexed = []
        original = sqlscan._typed_tokens

        def counting(sql):
            lexed.append(sql)
            return original(sql)

        monkeypatch.setattr(sqlscan, "_typed_tokens", counting)
        return lexed

    def test_a_second_ruleset_run_lexes_nothing(
        self, field_mappings_file, test_logger, tmp_path, monkeypatch
    ):
        sqlscan.clear_scan_cache()
        core = self._core(field_mappings_file, test_logger)
        lexed = self._counting_lexer(monkeypatch)
        try:
            core.execute_ruleset(str(tmp_path / "a.json"), disable_progress=True)
            first = len(lexed)
            lexed.clear()
            core.execute_ruleset(str(tmp_path / "b.json"), disable_progress=True)

            assert first > 0, "the first run must actually lex the ruleset"
            assert lexed == []
        finally:
            core.close()

    def test_the_next_file_lexes_nothing(
        self, field_mappings_file, test_logger, tmp_path, monkeypatch
    ):
        """``reset_logs_table`` is what per-file mode does between inputs.

        It drops the table, so index and schema state must be rebuilt -- but the
        rule SQL has not changed, and re-reading it is pure waste.
        """
        sqlscan.clear_scan_cache()
        core = self._core(field_mappings_file, test_logger)
        lexed = self._counting_lexer(monkeypatch)
        try:
            core.execute_ruleset(str(tmp_path / "file1.json"), disable_progress=True)
            assert len(lexed) > 0

            core.reset_logs_table()
            core.create_db(
                '"Channel" TEXT COLLATE NOCASE, "EventID" INTEGER COLLATE NOCASE'
            )
            core.db_connection.execute(
                "INSERT INTO logs (Channel, EventID) VALUES ('Security', 4002)"
            )
            core.db_connection.commit()
            lexed.clear()
            core.execute_ruleset(str(tmp_path / "file2.json"), disable_progress=True)

            assert lexed == []
        finally:
            core.close()

    def test_widening_reuses_the_scan_the_regex_check_already_took(
        self, field_mappings_file, test_logger, monkeypatch
    ):
        """Both sites read the same statement in one ``execute_select_query``."""
        sqlscan.clear_scan_cache()
        core = self._core(field_mappings_file, test_logger)
        lexed = self._counting_lexer(monkeypatch)
        try:
            query = "SELECT * FROM logs WHERE Channel = 'Security' AND Absent IS NULL"
            core.execute_select_query(query, rule_title="widens once")

            assert "Absent" in core._get_table_columns()
            assert lexed == [query]
        finally:
            core.close()


class TestBatchSizeReachesTheProcessor:
    """``ProcessingConfig.batch_size`` must survive the trip into streaming.

    ``run_streaming`` builds a fresh ``ProcessingConfig`` for the processor, and
    every field it forgets to copy is silently replaced by a default -- the
    caller's value is accepted without complaint and never used.
    """

    def test_a_configured_batch_size_is_what_streaming_inserts_with(
        self, field_mappings_file, test_logger, tmp_path
    ):
        events = tmp_path / "events.json"
        events.write_text(
            "\n".join(
                json.dumps(
                    {
                        "Event": {
                            "System": {
                                "Channel": "Security",
                                "EventID": 4624,
                                "SystemTime": "2024-01-01T00:00:00Z",
                            }
                        }
                    }
                )
                for _ in range(7)
            ),
            encoding="utf-8",
        )
        core = ZircoliteCore(
            config=field_mappings_file,
            processing_config=ProcessingConfig(
                batch_size=3, disable_progress=True, no_output=True
            ),
            logger=test_logger,
        )
        seen = []
        try:
            original = StreamingEventProcessor._insert_batch

            def spy(processor, connection, cursor, batch):
                seen.append(len(batch))
                return original(processor, connection, cursor, batch)

            with patch.object(StreamingEventProcessor, "_insert_batch", spy):
                core.run_streaming(
                    [str(events)],
                    input_type="json",
                    args_config=None,
                    disable_progress=True,
                )
        finally:
            core.close()

        assert seen == [3, 3, 1]

    def test_the_default_is_unchanged_when_nothing_asks_for_one(
        self, field_mappings_file, test_logger
    ):
        core = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        try:
            assert core.batch_size == ProcessingConfig().batch_size
        finally:
            core.close()
