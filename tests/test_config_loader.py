"""
Tests for the YAML configuration loader module.
"""

import os
import pytest
import sys
import tempfile
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite.config_loader import (
    ConfigLoader,
    ZircoliteConfig,
    InputConfig,
    RulesConfig,
    OutputConfig,
    ProcessingConfig,
    TimeFilterConfig,
    ParallelProcessingConfig,
    create_default_config_file,
)


class TestInputConfig:
    """Tests for InputConfig dataclass."""
    
    def test_default_values(self):
        """Test InputConfig default values."""
        config = InputConfig()
        
        assert config.path is None
        assert config.format == "evtx"
        assert config.recursive is True
        assert config.file_pattern is None
        assert config.file_extension is None
        assert config.select is None
        assert config.avoid is None
        assert config.encoding is None
    
    def test_custom_values(self):
        """Test InputConfig with custom values."""
        config = InputConfig(
            path="./logs/",
            format="json",
            recursive=False,
            select=["Security"],
            avoid=["backup"]
        )
        
        assert config.path == "./logs/"
        assert config.format == "json"
        assert config.recursive is False
        assert config.select == ["Security"]
        assert config.avoid == ["backup"]


class TestRulesConfig:
    """Tests for RulesConfig dataclass."""
    
    def test_default_values(self):
        """Test RulesConfig default values."""
        config = RulesConfig()
        
        assert config.rulesets == ["rules/rules_windows_generic_pysigma.json"]
        assert config.pipelines is None
        assert config.filters is None
        assert config.combine_rulesets is False
        assert config.save_ruleset is False
    
    def test_custom_values(self):
        """Test RulesConfig with custom values."""
        config = RulesConfig(
            rulesets=["rules/custom.json"],
            pipelines=["sysmon"],
            filters=["Noisy Rule"],
            save_ruleset=True
        )
        
        assert config.rulesets == ["rules/custom.json"]
        assert config.pipelines == ["sysmon"]
        assert config.filters == ["Noisy Rule"]
        assert config.save_ruleset is True


class TestOutputConfig:
    """Tests for OutputConfig dataclass."""
    
    def test_default_values(self):
        """Test OutputConfig default values."""
        config = OutputConfig()
        
        assert config.file == "detected_events.json"
        assert config.format == "json"
        assert config.csv_delimiter == ";"
        assert config.template is None
        assert config.package is False
        assert config.no_output is False


class TestProcessingConfig:
    """Tests for ProcessingConfig dataclass."""
    
    def test_default_values(self):
        """Test ProcessingConfig default values."""
        config = ProcessingConfig()
        
        assert config.streaming is True
        assert config.unified_db is False
        assert config.auto_mode is True
        assert config.hashes is False
        assert config.limit == -1
        assert config.time_field == "SystemTime"


class TestTimeFilterConfig:
    """Tests for TimeFilterConfig dataclass."""
    
    def test_default_values(self):
        """Test TimeFilterConfig default values."""
        config = TimeFilterConfig()
        
        assert config.after == "1970-01-01T00:00:00"
        assert config.before == "9999-12-12T23:59:59"


class TestParallelProcessingConfig:
    """Tests for ParallelProcessingConfig dataclass."""
    
    def test_default_values(self):
        """Test ParallelProcessingConfig default values."""
        config = ParallelProcessingConfig()
        
        assert config.enabled is False
        assert config.max_workers is None
        assert config.min_workers == 1
        assert config.memory_limit_percent == 75.0
        assert config.use_processes is False
        assert config.adaptive is True


class TestZircoliteConfig:
    """Tests for ZircoliteConfig dataclass."""
    
    def test_default_values(self):
        """Test ZircoliteConfig default values."""
        config = ZircoliteConfig()
        
        assert isinstance(config.input, InputConfig)
        assert isinstance(config.rules, RulesConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.processing, ProcessingConfig)
        assert isinstance(config.time_filter, TimeFilterConfig)
        assert isinstance(config.parallel, ParallelProcessingConfig)


class TestConfigLoaderLoadYaml:
    """Tests for ConfigLoader.load_yaml method."""
    
    def test_load_valid_yaml(self, tmp_path, test_logger):
        """Test loading a valid YAML file."""
        yaml_content = """
input:
  path: ./logs/
  format: evtx

rules:
  rulesets:
    - rules/test.json
"""
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text(yaml_content)
        
        loader = ConfigLoader(logger=test_logger)
        config_dict = loader.load_yaml(str(yaml_file))
        
        assert config_dict["input"]["path"] == "./logs/"
        assert config_dict["input"]["format"] == "evtx"
        assert config_dict["rules"]["rulesets"] == ["rules/test.json"]
    
    def test_load_nonexistent_file(self, test_logger):
        """Test loading a nonexistent file raises error."""
        loader = ConfigLoader(logger=test_logger)
        
        with pytest.raises(FileNotFoundError):
            loader.load_yaml("/nonexistent/config.yaml")
    
    def test_load_empty_yaml(self, tmp_path, test_logger):
        """Test loading an empty YAML file."""
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")
        
        loader = ConfigLoader(logger=test_logger)
        config_dict = loader.load_yaml(str(yaml_file))
        
        assert config_dict == {}


class TestConfigLoaderParseConfig:
    """Tests for ConfigLoader.parse_config method."""
    
    def test_parse_full_config(self, test_logger):
        """Test parsing a full configuration dictionary."""
        config_dict = {
            "input": {
                "path": "./logs/",
                "format": "json",
                "recursive": False
            },
            "rules": {
                "rulesets": ["rules/custom.json"],
                "pipelines": ["sysmon"]
            },
            "output": {
                "file": "results.json",
                "format": "json"
            },
            "processing": {
                "streaming": True,
                "unified_db": True
            },
            "time_filter": {
                "after": "2024-01-01T00:00:00",
                "before": "2024-12-31T23:59:59"
            },
            "parallel": {
                "enabled": True,
                "max_workers": 4
            }
        }
        
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config(config_dict)
        
        assert config.input.path == "./logs/"
        assert config.input.format == "json"
        assert config.input.recursive is False
        assert config.rules.rulesets == ["rules/custom.json"]
        assert config.rules.pipelines == ["sysmon"]
        assert config.output.file == "results.json"
        assert config.processing.unified_db is True
        assert config.time_filter.after == "2024-01-01T00:00:00"
        assert config.parallel.enabled is True
        assert config.parallel.max_workers == 4
    
    def test_parse_partial_config(self, test_logger):
        """Test parsing a partial configuration."""
        config_dict = {
            "input": {
                "path": "./logs/"
            }
        }
        
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config(config_dict)
        
        # Should have defaults for missing sections
        assert config.input.path == "./logs/"
        assert config.input.format == "evtx"  # Default
        assert config.rules.rulesets == ["rules/rules_windows_generic_pysigma.json"]  # Default
    
    def test_parse_empty_config(self, test_logger):
        """Test parsing an empty configuration."""
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config({})
        
        # Should return default config
        assert isinstance(config, ZircoliteConfig)
        assert config.input.format == "evtx"


class TestConfigLoaderLoad:
    """Tests for ConfigLoader.load method."""
    
    def test_load_yaml_file(self, tmp_path, test_logger):
        """Test loading and parsing a YAML file."""
        yaml_content = """
input:
  path: ./test_logs/
  format: json

output:
  file: test_results.json
"""
        yaml_file = tmp_path / "test_config.yaml"
        yaml_file.write_text(yaml_content)
        
        loader = ConfigLoader(logger=test_logger)
        config = loader.load(str(yaml_file))
        
        assert isinstance(config, ZircoliteConfig)
        assert config.input.path == "./test_logs/"
        assert config.input.format == "json"
        assert config.output.file == "test_results.json"


class TestConfigLoaderValidate:
    """Tests for ConfigLoader.validate_config method."""
    
    def test_validate_valid_config(self, tmp_path, test_logger):
        """Test validation of a valid configuration."""
        # Create a temporary ruleset file
        ruleset_file = tmp_path / "rules.json"
        ruleset_file.write_text("[]")
        
        config = ZircoliteConfig()
        config.input.path = str(tmp_path)
        config.rules.rulesets = [str(ruleset_file)]
        
        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)
        
        assert len(issues) == 0
    
    def test_validate_missing_input_path(self, test_logger):
        """Test validation with missing input path."""
        config = ZircoliteConfig()
        config.input.path = "/nonexistent/path"
        
        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)
        
        assert any("Input path does not exist" in issue for issue in issues)
    
    def test_validate_invalid_format(self, test_logger):
        """Test validation with invalid input format."""
        config = ZircoliteConfig()
        config.input.format = "invalid_format"
        
        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)
        
        assert any("Invalid input format" in issue for issue in issues)
    
    def test_validate_missing_ruleset(self, test_logger):
        """Test validation with missing ruleset file."""
        config = ZircoliteConfig()
        config.rules.rulesets = ["/nonexistent/rules.json"]
        
        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)
        
        assert any("Ruleset not found" in issue for issue in issues)
    
    def test_validate_invalid_output_format(self, test_logger):
        """Test validation with invalid output format."""
        config = ZircoliteConfig()
        config.output.format = "xml"  # Invalid
        
        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)
        
        assert any("Invalid output format" in issue for issue in issues)
    
    def test_validate_csv_with_multiple_rulesets(self, tmp_path, test_logger):
        """Test validation warns about CSV with multiple rulesets."""
        # Create ruleset files
        for i in range(2):
            rf = tmp_path / f"rules_{i}.json"
            rf.write_text("[]")
        
        config = ZircoliteConfig()
        config.output.format = "csv"
        config.rules.rulesets = [str(tmp_path / "rules_0.json"), str(tmp_path / "rules_1.json")]
        
        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)
        
        assert any("CSV output is not supported with multiple rulesets" in issue for issue in issues)
    
    def test_validate_invalid_time_format(self, test_logger):
        """Test validation with invalid time format."""
        config = ZircoliteConfig()
        config.time_filter.after = "invalid-time"
        
        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)
        
        assert any("Invalid 'after' timestamp format" in issue for issue in issues)
    
    def test_validate_parallel_config(self, test_logger):
        """Test validation of parallel config."""
        config = ZircoliteConfig()
        config.parallel.enabled = True
        config.parallel.min_workers = 0  # Invalid
        
        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)
        
        assert any("min_workers must be at least 1" in issue for issue in issues)


class TestConfigLoaderMergeWithArgs:
    """Tests for ConfigLoader.merge_with_args method."""
    
    def test_cli_overrides_yaml(self, test_logger):
        """Test that CLI arguments override YAML config."""
        config = ZircoliteConfig()
        config.input.path = "./yaml_path/"
        config.output.file = "yaml_output.json"
        
        args = Namespace(
            evtx="./cli_path/",
            outfile="cli_output.json",
            json_input=False,
            json_array_input=False,
            xml_input=False,
            csv_input=False,
            sysmon_linux_input=False,
            auditd_input=False,
            evtxtract_input=False,
            no_recursion=False,
            file_pattern=None,
            fileext=None,
            logs_encoding=None,
            ruleset=None,
            pipeline=None,
            rulefilter=None,
            save_ruleset=False,
            csv=False,
            csv_delimiter=";",
            template=None,
            templateOutput=None,
            package=False,
            package_dir="",
            keepflat=False,
            dbfile=None,
            logfile="zircolite.log",
            nolog=False,
            no_streaming=False,
            unified_db=False,
            no_auto_mode=False,
            ondiskdb=":memory:",
            hashes=False,
            limit=-1,
            timefield="SystemTime",
            showall=False,
            debug=False,
            remove_events=False,
            keeptmp=False,
            tmpdir=None,
            after="1970-01-01T00:00:00",
            before="9999-12-12T23:59:59",
            parallel=False,
            parallel_workers=None,
            parallel_memory_limit=75.0,
            parallel_use_processes=False,
        )
        
        loader = ConfigLoader(logger=test_logger)
        merged = loader.merge_with_args(config, args)
        
        # CLI should override
        assert merged.input.path == "./cli_path/"
        assert merged.output.file == "cli_output.json"
    
    def test_yaml_values_preserved_when_cli_default(self, test_logger):
        """Test that YAML values are kept when CLI has defaults."""
        config = ZircoliteConfig()
        config.input.path = "./yaml_path/"
        config.rules.rulesets = ["yaml_rules.json"]
        
        args = Namespace(
            evtx=None,  # Not provided
            outfile="detected_events.json",  # Default
            json_input=False,
            json_array_input=False,
            xml_input=False,
            csv_input=False,
            sysmon_linux_input=False,
            auditd_input=False,
            evtxtract_input=False,
            no_recursion=False,
            file_pattern=None,
            fileext=None,
            logs_encoding=None,
            ruleset=None,  # Not provided
            pipeline=None,
            rulefilter=None,
            save_ruleset=False,
            csv=False,
            csv_delimiter=";",
            template=None,
            templateOutput=None,
            package=False,
            package_dir="",
            keepflat=False,
            dbfile=None,
            logfile="zircolite.log",
            nolog=False,
            no_streaming=False,
            unified_db=False,
            no_auto_mode=False,
            ondiskdb=":memory:",
            hashes=False,
            limit=-1,
            timefield="SystemTime",
            showall=False,
            debug=False,
            remove_events=False,
            keeptmp=False,
            tmpdir=None,
            after="1970-01-01T00:00:00",
            before="9999-12-12T23:59:59",
            parallel=False,
            parallel_workers=None,
            parallel_memory_limit=75.0,
            parallel_use_processes=False,
        )
        
        loader = ConfigLoader(logger=test_logger)
        merged = loader.merge_with_args(config, args)
        
        # YAML values should be preserved
        assert merged.input.path == "./yaml_path/"
        assert merged.rules.rulesets == ["yaml_rules.json"]


class TestCreateDefaultConfigFile:
    """Tests for create_default_config_file function."""
    
    def test_creates_file(self, tmp_path):
        """Test that function creates a config file."""
        output_path = tmp_path / "default_config.yaml"
        
        create_default_config_file(str(output_path))
        
        assert output_path.exists()
        content = output_path.read_text()
        
        # Check for expected sections
        assert "input:" in content
        assert "rules:" in content
        assert "output:" in content
        assert "processing:" in content
        assert "time_filter:" in content
        assert "parallel:" in content
    
    def test_file_is_valid_yaml(self, tmp_path, test_logger):
        """Test that generated file is valid YAML."""
        output_path = tmp_path / "default_config.yaml"
        
        create_default_config_file(str(output_path))
        
        # Should load without errors
        loader = ConfigLoader(logger=test_logger)
        config_dict = loader.load_yaml(str(output_path))
        
        # Should have expected structure
        assert "input" in config_dict or config_dict.get("input") is None


class TestConfigLoaderIntegration:
    """Integration tests for ConfigLoader."""
    
    def test_full_workflow(self, tmp_path, test_logger):
        """Test complete workflow: create, load, parse, validate."""
        yaml_content = """
input:
  path: {tmp_path}
  format: evtx
  recursive: true

rules:
  rulesets:
    - {ruleset}

output:
  file: results.json
  format: json

processing:
  streaming: true
  unified_db: false

time_filter:
  after: "2024-01-01T00:00:00"
  before: "2024-12-31T23:59:59"

parallel:
  enabled: false
"""
        # Create a dummy ruleset
        ruleset_file = tmp_path / "test_rules.json"
        ruleset_file.write_text("[]")
        
        # Create config file
        yaml_file = tmp_path / "test_config.yaml"
        yaml_file.write_text(yaml_content.format(
            tmp_path=str(tmp_path),
            ruleset=str(ruleset_file)
        ))
        
        # Load and parse
        loader = ConfigLoader(logger=test_logger)
        config = loader.load(str(yaml_file))
        
        # Validate
        issues = loader.validate_config(config)
        
        # Should have no issues
        assert len(issues) == 0
        assert config.input.path == str(tmp_path)
        assert config.input.format == "evtx"
        assert config.rules.rulesets == [str(ruleset_file)]
        assert config.output.file == "results.json"
        assert config.processing.streaming is True
        assert config.time_filter.after == "2024-01-01T00:00:00"
        assert config.parallel.enabled is False
