"""
Tests for the ZircoliteCore class.
"""

import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import ZircoliteCore, ProcessingConfig


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
    
    def test_insert_flattened_json_to_db(self, field_mappings_file, test_logger):
        """Test batch inserting flattened JSON data."""
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        
        # Create table
        field_stmt = "'EventID' TEXT COLLATE NOCASE,\n'CommandLine' TEXT COLLATE NOCASE,\n'Computer' TEXT COLLATE NOCASE,\n"
        zircore.create_db(field_stmt)
        
        # Insert batch data
        data = [
            {"EventID": "1", "CommandLine": "test1.exe", "Computer": "PC1"},
            {"EventID": "2", "CommandLine": "test2.exe", "Computer": "PC2"},
            {"EventID": "3", "CommandLine": "test3.exe", "Computer": "PC3"},
        ]
        
        zircore.insert_flattened_json_to_db(data)
        
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
        data = [{"EventID": "1", "LargeValue": large_int}]
        
        zircore.insert_flattened_json_to_db(data)
        
        results = zircore.execute_select_query("SELECT * FROM logs")
        assert len(results) == 1
        
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
        
        # In normal mode, None values should be removed from matches
        if results.get("matches"):
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


class TestZircoliteCoreRuleLevelFormatting:
    """Tests for rule level color formatting."""
    
    def test_rule_level_informational(self, field_mappings_file, test_logger):
        """Test informational level formatting."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        result = zircore.rule_level_print_formatter("informational")
        assert "informational" in result
        zircore.close()
    
    def test_rule_level_low(self, field_mappings_file, test_logger):
        """Test low level formatting."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        result = zircore.rule_level_print_formatter("low")
        assert "low" in result
        zircore.close()
    
    def test_rule_level_medium(self, field_mappings_file, test_logger):
        """Test medium level formatting."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        result = zircore.rule_level_print_formatter("medium")
        assert "medium" in result
        zircore.close()
    
    def test_rule_level_high(self, field_mappings_file, test_logger):
        """Test high level formatting."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        result = zircore.rule_level_print_formatter("high")
        assert "high" in result
        zircore.close()
    
    def test_rule_level_critical(self, field_mappings_file, test_logger):
        """Test critical level formatting."""
        zircore = ZircoliteCore(config=field_mappings_file, logger=test_logger)
        result = zircore.rule_level_print_formatter("critical")
        assert "critical" in result
        zircore.close()


class TestZircoliteCoreRegexSupport:
    """Tests for regex support in SQL queries."""
    
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


class TestZircoliteCoreSaveFlattenedJSON:
    """Tests for saving flattened JSON to file."""
    
    def test_save_flattened_json_to_file(self, field_mappings_file, tmp_path, test_logger):
        """Test saving flattened JSON data to file."""
        proc_config = ProcessingConfig(disable_progress=True)
        zircore = ZircoliteCore(
            config=field_mappings_file,
            processing_config=proc_config,
            logger=test_logger
        )
        
        data = [
            {"EventID": "1", "CommandLine": "test1.exe"},
            {"EventID": "2", "CommandLine": "test2.exe"},
        ]
        
        output_file = str(tmp_path / "flattened.json")
        zircore.save_flattened_json_to_file(data, output_file)
        
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            lines = f.readlines()
        
        assert len(lines) == 2
        assert "test1.exe" in lines[0]
        
        zircore.close()


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
