"""
Tests for the YAML configuration loader module.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite.config_loader import (
    ConfigLoader,
    InputConfig,
    OutputConfig,
    ParallelProcessingConfig,
    RulesConfig,
    TimeFilterConfig,
    YamlProcessingConfig,
    ZircoliteConfig,
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

        # Empty, not the bundled ruleset: the CLI needs "no rules section" to
        # stay distinguishable so it can resolve the installed copy instead.
        assert config.rulesets == []
        assert config.pipelines is None
        assert config.filters is None
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
        assert config.package is False
        assert config.no_output is False


class TestProcessingConfig:
    """Tests for ProcessingConfig dataclass."""

    def test_default_values(self):
        """Test ProcessingConfig default values."""
        config = YamlProcessingConfig()

        assert config.unified_db is False
        assert config.auto_mode is True
        assert config.hashes is False
        assert config.limit == -1
        assert config.time_field == "SystemTime"
        assert config.strict_evtx is False


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

        # Parallel auto-mode is enabled by default; YAML 'enabled: false' opts out
        assert config.enabled is True
        assert config.max_workers is None
        assert config.min_workers == 1
        assert config.memory_limit_percent == 85.0
        assert config.adaptive is True


class TestZircoliteConfig:
    """Tests for ZircoliteConfig dataclass."""

    def test_default_values(self):
        """Test ZircoliteConfig default values."""
        config = ZircoliteConfig()

        assert isinstance(config.input, InputConfig)
        assert isinstance(config.rules, RulesConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.processing, YamlProcessingConfig)
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
        assert config.rules.rulesets == []  # No rules section given

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
        config = loader.parse_config(loader.load_yaml(str(yaml_file)))

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

    def test_validate_accepts_a_shipped_ruleset_from_any_directory(
        self, test_logger, tmp_path, monkeypatch
    ):
        """A config file is written once and run from anywhere; rules/ has to follow."""
        monkeypatch.chdir(tmp_path)
        config = ZircoliteConfig()
        config.rules.rulesets = ["rules/rules_windows_generic.json"]

        issues = ConfigLoader(logger=test_logger).validate_config(config)

        assert not any("Ruleset not found" in issue for issue in issues)

    def test_validate_accepts_a_shipped_template_from_any_directory(
        self, test_logger, tmp_path, monkeypatch
    ):
        """Same for output.templates, which the run resolves the same way."""
        monkeypatch.chdir(tmp_path)
        config = ZircoliteConfig()
        config.output.templates = [
            {"template": "templates/exportForSplunk.tmpl", "output": "out.json"}
        ]

        issues = ConfigLoader(logger=test_logger).validate_config(config)

        assert not any("Template file not found" in issue for issue in issues)

    def test_validate_still_rejects_a_ruleset_outside_the_shipped_directory(
        self, test_logger, tmp_path, monkeypatch
    ):
        """The fallback must not make a typo'd directory validate."""
        monkeypatch.chdir(tmp_path)
        config = ZircoliteConfig()
        config.rules.rulesets = ["myrules/rules_windows_generic.json"]

        issues = ConfigLoader(logger=test_logger).validate_config(config)

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


class TestConfigLoaderValidateExtended:
    """Additional validation tests for better coverage."""

    def test_validate_invalid_before_timestamp(self, test_logger):
        """Cover line 315-316: invalid 'before' timestamp."""
        config = ZircoliteConfig()
        config.time_filter.before = "not-a-timestamp"

        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)

        assert any("Invalid 'before' timestamp format" in issue for issue in issues)

    def test_validate_parallel_max_workers_less_than_1(self, test_logger):
        """Cover line 323: max_workers < 1."""
        config = ZircoliteConfig()
        config.parallel.enabled = True
        config.parallel.max_workers = 0

        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)

        assert any("max_workers must be at least 1" in issue for issue in issues)

    def test_validate_parallel_memory_limit_out_of_range(self, test_logger):
        """Cover line 325: memory_limit_percent not in (0, 100]."""
        config = ZircoliteConfig()
        config.parallel.enabled = True
        config.parallel.memory_limit_percent = 0

        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)

        assert any("memory_limit_percent" in issue for issue in issues)

    def test_validate_template_missing_keys(self, tmp_path, test_logger):
        """Cover lines 300-302: template entry without required keys."""
        config = ZircoliteConfig()
        config.input.path = str(tmp_path)
        config.output.templates = [{"template": "only_template"}]  # Missing 'output'

        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)

        assert any("Template entries must have" in issue for issue in issues)

    def test_validate_template_file_not_found(self, tmp_path, test_logger):
        """Cover lines 303-304: template file does not exist."""
        config = ZircoliteConfig()
        config.input.path = str(tmp_path)
        config.output.templates = [{"template": "/nonexistent/tmpl.html", "output": "out.html"}]

        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)

        assert any("Template file not found" in issue for issue in issues)

    def test_validate_template_valid(self, tmp_path, test_logger):
        """Templates with valid entries should pass validation."""
        tmpl = tmp_path / "valid.tmpl"
        tmpl.write_text("{{ data }}")
        ruleset = tmp_path / "rules.json"
        ruleset.write_text("[]")

        config = ZircoliteConfig()
        config.input.path = str(tmp_path)
        config.rules.rulesets = [str(ruleset)]
        config.output.templates = [{"template": str(tmpl), "output": "out.html"}]

        loader = ConfigLoader(logger=test_logger)
        issues = loader.validate_config(config)

        # Should have no template-related issues
        template_issues = [i for i in issues if "Template" in i or "template" in i]
        assert len(template_issues) == 0


class TestConfigLoaderParseConfigExtended:
    """Additional parse_config tests for edge cases."""

    def test_parse_string_rulesets_converted_to_list(self, test_logger):
        """Cover line 184: string rulesets converted to list."""
        config_dict = {
            "rules": {
                "rulesets": "rules/single_ruleset.json"
            }
        }
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config(config_dict)
        assert isinstance(config.rules.rulesets, list)
        assert config.rules.rulesets == ["rules/single_ruleset.json"]

    def test_parse_config_with_templates(self, test_logger):
        """Cover line 198: templates extracted from output section."""
        config_dict = {
            "output": {
                "templates": [
                    {"template": "tmpl.html", "output": "out.html"}
                ]
            }
        }
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config(config_dict)
        assert config.output.templates == [{"template": "tmpl.html", "output": "out.html"}]

    def test_parse_config_strict_evtx(self, test_logger):
        """strict_evtx parsed from processing section."""
        config_dict = {"processing": {"strict_evtx": True}}
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config(config_dict)
        assert config.processing.strict_evtx is True

    def test_parse_config_strict_evtx_default(self, test_logger):
        """strict_evtx defaults to False when not in YAML."""
        config_dict = {"processing": {}}
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config(config_dict)
        assert config.processing.strict_evtx is False

    def test_parse_config_template_append_default(self, test_logger):
        """template_append defaults to False when not in YAML."""
        config_dict = {"output": {}}
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config(config_dict)
        assert config.output.template_append is False

    def test_parse_config_template_append_true(self, test_logger):
        """template_append is parsed from output section."""
        config_dict = {"output": {"template_append": True}}
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config(config_dict)
        assert config.output.template_append is True

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
        config = loader.parse_config(loader.load_yaml(str(yaml_file)))

        # Validate
        issues = loader.validate_config(config)

        # Should have no issues
        assert len(issues) == 0
        assert config.input.path == str(tmp_path)
        assert config.input.format == "evtx"
        assert config.rules.rulesets == [str(ruleset_file)]
        assert config.output.file == "results.json"
        assert config.time_filter.after == "2024-01-01T00:00:00"
        assert config.parallel.enabled is False


class TestConfigLoaderBugFixes:
    """Tests for specific bug fixes in config_loader."""

    def test_validate_config_list_path(self, test_logger, tmp_path):
        """validate_config rejects list-type input.path with a clear message."""
        loader = ConfigLoader(logger=test_logger)
        config = ZircoliteConfig()
        config.input.path = [str(tmp_path), "/nonexistent"]
        issues = loader.validate_config(config)
        assert any("single path string" in i for i in issues)

    def test_parse_config_null_rulesets_stays_empty(self, test_logger):
        """A 'rulesets: null' entry must not crash parsing/validation."""
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config({'rules': {'rulesets': None}})
        assert config.rules.rulesets == []
        # validate_config must not raise TypeError iterating None
        loader.validate_config(config)



class TestExampleConfigStaysComplete:
    """config/zircolite_example.yaml documents the schema, so it must match it.

    It previously advertised a `processing.streaming` key the loader ignored
    entirely, and omitted eleven keys that do exist.
    """

    EXAMPLE = Path(__file__).parent.parent / "config" / "zircolite_example.yaml"

    def _parsed(self):
        import yaml
        return yaml.safe_load(self.EXAMPLE.read_text())

    def test_it_has_no_unknown_keys(self):
        from zircolite.config_loader import unknown_yaml_keys

        assert unknown_yaml_keys(self._parsed()) == []

    def test_it_covers_every_key(self):
        """Every key is documented, set or shown commented out.

        A conditional default has to ship commented: written out, it counts as
        a deliberate choice and switches off the very detection it describes.
        It is still documented, and still one character from being enabled.
        """
        import re
        from dataclasses import fields as dc_fields

        from zircolite.config_loader import SECTIONS

        parsed = self._parsed()
        text = self.EXAMPLE.read_text()
        commented = set(re.findall(r"^\s*#\s*([a-z_]+):", text, re.MULTILINE))
        for section, cls in SECTIONS.items():
            present = set((parsed.get(section) or {}).keys()) | commented
            known = {f.name for f in dc_fields(cls)}
            assert known - present == set(), f"{section} is missing keys"

    def test_it_matches_what_generate_config_writes(self, tmp_path):
        """The example is the generator's output; regenerate rather than edit."""
        from zircolite.config_loader import create_default_config_file

        generated = tmp_path / "generated.yaml"
        create_default_config_file(str(generated))

        def body(text):
            # The example carries a longer preamble; compare from the first key
            return text[text.index("# Input configuration"):]

        assert body(generated.read_text()) == body(self.EXAMPLE.read_text())

    def test_it_loads_and_validates(self, test_logger):
        loader = ConfigLoader(logger=test_logger)
        config = loader.parse_config(loader.load_yaml(str(self.EXAMPLE)))
        issues = loader.validate_config(config)

        assert not any("Unknown configuration key" in i for i in issues)
