"""
Tests for the load_field_mappings utility function.

Tests JSON and YAML format support for field mappings configuration files.
"""

import json
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import load_field_mappings


class TestLoadFieldMappingsJSON:
    """Tests for loading JSON format field mappings."""
    
    def test_load_json_file(self, field_mappings_file, minimal_field_mappings):
        """Test loading a JSON field mappings file."""
        config = load_field_mappings(field_mappings_file)
        
        assert config is not None
        assert config["exclusions"] == minimal_field_mappings["exclusions"]
        assert config["mappings"] == minimal_field_mappings["mappings"]
        assert config["transforms_enabled"] == minimal_field_mappings["transforms_enabled"]
    
    def test_load_json_with_transforms(self, field_mappings_file_with_transforms, field_mappings_with_transforms):
        """Test loading JSON with transforms enabled."""
        config = load_field_mappings(field_mappings_file_with_transforms)
        
        assert config["transforms_enabled"] is True
        assert "proctitle" in config["transforms"]
        assert config["transforms"]["proctitle"][0]["enabled"] is True
    
    def test_load_json_all_keys_present(self, field_mappings_file):
        """Test that all required keys are present in loaded config."""
        config = load_field_mappings(field_mappings_file)
        
        required_keys = ["exclusions", "useless", "mappings", "alias", "split", "transforms", "transforms_enabled"]
        for key in required_keys:
            assert key in config, f"Missing required key: {key}"


class TestLoadFieldMappingsYAML:
    """Tests for loading YAML format field mappings."""
    
    def test_load_yaml_file(self, field_mappings_yaml_file, minimal_field_mappings):
        """Test loading a YAML field mappings file (.yaml extension)."""
        config = load_field_mappings(field_mappings_yaml_file)
        
        assert config is not None
        assert config["exclusions"] == minimal_field_mappings["exclusions"]
        assert config["mappings"] == minimal_field_mappings["mappings"]
        assert config["transforms_enabled"] == minimal_field_mappings["transforms_enabled"]
    
    def test_load_yml_file(self, field_mappings_yml_file, minimal_field_mappings):
        """Test loading a YAML field mappings file (.yml extension)."""
        config = load_field_mappings(field_mappings_yml_file)
        
        assert config is not None
        assert config["exclusions"] == minimal_field_mappings["exclusions"]
        assert config["mappings"] == minimal_field_mappings["mappings"]
    
    def test_load_yaml_with_transforms(self, field_mappings_yaml_with_transforms, field_mappings_with_transforms):
        """Test loading YAML with transforms enabled."""
        config = load_field_mappings(field_mappings_yaml_with_transforms)
        
        assert config["transforms_enabled"] is True
        assert "proctitle" in config["transforms"]
        assert config["transforms"]["proctitle"][0]["enabled"] is True
    
    def test_load_yaml_with_comments(self, field_mappings_yaml_with_comments):
        """Test that YAML files with comments load correctly."""
        config = load_field_mappings(field_mappings_yaml_with_comments)
        
        assert config is not None
        assert "xmlns" in config["exclusions"]
        assert "EventID" in config["mappings"].values()
    
    def test_load_yaml_all_keys_present(self, field_mappings_yaml_file):
        """Test that all required keys are present in loaded YAML config."""
        config = load_field_mappings(field_mappings_yaml_file)
        
        required_keys = ["exclusions", "useless", "mappings", "alias", "split", "transforms", "transforms_enabled"]
        for key in required_keys:
            assert key in config, f"Missing required key: {key}"


class TestLoadFieldMappingsAutoDetect:
    """Tests for auto-detection of file format."""
    
    def test_autodetect_json_content(self, tmp_path, minimal_field_mappings):
        """Test auto-detection of JSON content without extension."""
        config_file = tmp_path / "config_no_ext"
        config_file.write_text(json.dumps(minimal_field_mappings))
        
        config = load_field_mappings(str(config_file))
        
        assert config is not None
        assert config["exclusions"] == minimal_field_mappings["exclusions"]
    
    def test_autodetect_yaml_content(self, tmp_path, minimal_field_mappings):
        """Test auto-detection of YAML content without extension."""
        config_file = tmp_path / "config_no_ext"
        # YAML that isn't valid JSON
        yaml_content = """
exclusions:
  - xmlns
useless:
  - null
  - ""
mappings:
  Event.System.EventID: EventID
alias: {}
split: {}
transforms_enabled: false
transforms: {}
"""
        config_file.write_text(yaml_content)
        
        config = load_field_mappings(str(config_file))
        
        assert config is not None
        assert "xmlns" in config["exclusions"]


class TestLoadFieldMappingsEquivalence:
    """Tests to ensure JSON and YAML produce equivalent results."""
    
    def test_json_yaml_equivalence(self, field_mappings_file, field_mappings_yaml_file):
        """Test that JSON and YAML files with same content produce same result."""
        json_config = load_field_mappings(field_mappings_file)
        yaml_config = load_field_mappings(field_mappings_yaml_file)
        
        assert json_config["exclusions"] == yaml_config["exclusions"]
        assert json_config["mappings"] == yaml_config["mappings"]
        assert json_config["transforms_enabled"] == yaml_config["transforms_enabled"]
        assert json_config["alias"] == yaml_config["alias"]
        assert json_config["split"] == yaml_config["split"]
    
    def test_transforms_equivalence(self, field_mappings_file_with_transforms, field_mappings_yaml_with_transforms):
        """Test that transforms are equivalent between JSON and YAML."""
        json_config = load_field_mappings(field_mappings_file_with_transforms)
        yaml_config = load_field_mappings(field_mappings_yaml_with_transforms)
        
        assert json_config["transforms_enabled"] == yaml_config["transforms_enabled"]
        assert set(json_config["transforms"].keys()) == set(yaml_config["transforms"].keys())


class TestLoadFieldMappingsDefaults:
    """Tests for default value handling."""
    
    def test_missing_keys_get_defaults(self, tmp_path):
        """Test that missing keys get default values."""
        # Create minimal JSON with only some keys
        config_file = tmp_path / "minimal.json"
        config_file.write_text(json.dumps({
            "exclusions": ["test"],
            "mappings": {}
        }))
        
        config = load_field_mappings(str(config_file))
        
        # Check defaults are applied
        assert "useless" in config
        assert "alias" in config
        assert "split" in config
        assert "transforms" in config
        assert "transforms_enabled" in config
    
    def test_empty_config_gets_all_defaults(self, tmp_path):
        """Test that empty config file gets all default values."""
        config_file = tmp_path / "empty.json"
        config_file.write_text("{}")
        
        config = load_field_mappings(str(config_file))
        
        assert config["exclusions"] == []
        assert config["transforms_enabled"] is False


class TestLoadFieldMappingsErrors:
    """Tests for error handling."""
    
    def test_file_not_found(self):
        """Test that FileNotFoundError is raised for missing file."""
        with pytest.raises(FileNotFoundError):
            load_field_mappings("/nonexistent/path/config.json")
    
    def test_invalid_json(self, tmp_path):
        """Test that ValueError is raised for invalid JSON."""
        config_file = tmp_path / "invalid.json"
        config_file.write_text("{ invalid json }")
        
        with pytest.raises(ValueError) as exc_info:
            load_field_mappings(str(config_file))
        
        assert "Invalid JSON" in str(exc_info.value)
    
    def test_invalid_yaml(self, tmp_path):
        """Test that ValueError is raised for invalid YAML."""
        config_file = tmp_path / "invalid.yaml"
        config_file.write_text("key: value:\n  - invalid: yaml: here")
        
        with pytest.raises(ValueError) as exc_info:
            load_field_mappings(str(config_file))
        
        assert "Invalid YAML" in str(exc_info.value)
    
    def test_unknown_extension_invalid_content(self, tmp_path):
        """Test error for unknown extension with unparseable content."""
        config_file = tmp_path / "config.xyz"
        config_file.write_text("this is not json or yaml {{{")
        
        with pytest.raises(ValueError) as exc_info:
            load_field_mappings(str(config_file))
        
        # Either "Unable to parse" or "Invalid field mappings file format" 
        # depending on whether YAML parses it as a string
        assert "Unable to parse" in str(exc_info.value) or "Invalid field mappings file format" in str(exc_info.value)
    
    def test_non_dict_yaml_content(self, tmp_path):
        """Test error when YAML content is not a dictionary."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("just a string value")
        
        with pytest.raises(ValueError) as exc_info:
            load_field_mappings(str(config_file))
        
        assert "Invalid field mappings file format" in str(exc_info.value)


class TestLoadFieldMappingsIntegration:
    """Integration tests with actual config files from the project."""
    
    def test_load_project_json_config(self):
        """Test loading the actual project JSON config file."""
        config_path = Path(__file__).parent.parent / "config" / "fieldMappings.json"
        if config_path.exists():
            config = load_field_mappings(str(config_path))
            
            assert config is not None
            assert len(config["mappings"]) > 0
            assert "xmlns" in config["exclusions"]
    
    def test_load_project_yaml_config(self):
        """Test loading the actual project YAML config file."""
        config_path = Path(__file__).parent.parent / "config" / "fieldMappings.yaml"
        if config_path.exists():
            config = load_field_mappings(str(config_path))
            
            assert config is not None
            assert len(config["mappings"]) > 0
            assert "xmlns" in config["exclusions"]
    
    def test_project_json_yaml_equivalence(self):
        """Test that project JSON and YAML configs are equivalent."""
        json_path = Path(__file__).parent.parent / "config" / "fieldMappings.json"
        yaml_path = Path(__file__).parent.parent / "config" / "fieldMappings.yaml"
        
        if json_path.exists() and yaml_path.exists():
            json_config = load_field_mappings(str(json_path))
            yaml_config = load_field_mappings(str(yaml_path))
            
            # Check key counts match
            assert len(json_config["mappings"]) == len(yaml_config["mappings"])
            assert json_config["transforms_enabled"] == yaml_config["transforms_enabled"]
