"""
Tests for the ZircoliteCore class.
"""

import gc
import json
import pytest
import re
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import ZircoliteCore, ProcessingConfig
from zircolite.core import _compile_regex


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

    def test_create_index_with_channel_column_creates_idx_channel(self, field_mappings_file, test_logger):
        """When logs table has Channel column, create_index creates idx_channel."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )
        field_stmt = "'eventid' TEXT, 'Channel' TEXT"
        zircore.create_db(field_stmt)
        zircore.create_index()
        cursor = zircore.db_connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_channel'")
        assert cursor.fetchone() is not None
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
        assert "idx_channel" in names  # auto-created when Channel column exists
        assert "idx_SystemTime" in names  # from add_index (idx_Channel may be skipped if same as idx_channel)
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

    def test_create_connection_returns_none_on_sqlite_error(
        self, field_mappings_file, tmp_path, test_logger
    ):
        """When sqlite3.connect raises Error, create_connection returns None."""
        with patch('zircolite.core.sqlite3.connect', side_effect=sqlite3.Error("mock")):
            proc_config = ProcessingConfig(db_location=str(tmp_path / "fail.db"))
            zircore = ZircoliteCore(
                config=field_mappings_file,
                processing_config=proc_config,
                logger=test_logger,
            )
            assert zircore.db_connection is None

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
    
    def test_load_ruleset_from_file(self, field_mappings_file, sample_ruleset_file, test_logger):
        """Test loading ruleset from JSON file."""
        zircore = ZircoliteCore(
            config=field_mappings_file,
            logger=test_logger
        )
        
        zircore.load_ruleset_from_file(sample_ruleset_file, rule_filters=None)
        
        # sample_ruleset fixture has 3 rules
        assert len(zircore.ruleset) == 3
        zircore.close()

    def test_load_ruleset_from_file_invalid_json(self, field_mappings_file, tmp_path, test_logger):
        """Loading invalid JSON ruleset logs error and does not raise."""
        bad_ruleset = tmp_path / "bad_ruleset.json"
        bad_ruleset.write_text("{ invalid json }")
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        zircore.load_ruleset_from_file(str(bad_ruleset), rule_filters=None)
        assert zircore.ruleset == []
        zircore.close()
    
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
            for event in events:
                f.write(json.dumps(event) + "\n")
        
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
