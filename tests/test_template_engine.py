"""
Tests for the TemplateEngine class.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import TemplateEngine, TemplateConfig


class TestTemplateEngineInit:
    """Tests for TemplateEngine initialization."""
    
    def test_init_defaults(self, test_logger):
        """Test TemplateEngine initialization with defaults."""
        engine = TemplateEngine(logger=test_logger)
        
        assert engine.template == []
        assert engine.template_output == []
        assert engine.time_field == ""
    
    def test_init_with_templates(self, simple_template, tmp_path, test_logger):
        """Test TemplateEngine initialization with templates."""
        output_file = str(tmp_path / "output.txt")
        
        tmpl_config = TemplateConfig(
            template=[[simple_template]],
            template_output=[[output_file]],
            time_field="SystemTime"
        )
        engine = TemplateEngine(template_config=tmpl_config, logger=test_logger)
        
        assert len(engine.template) == 1
        assert len(engine.template_output) == 1
        assert engine.time_field == "SystemTime"


class TestTemplateEngineGenerate:
    """Tests for template generation."""
    
    def test_generate_simple_template(self, simple_template, tmp_path, test_logger, sample_detection_results):
        """Test generating output from simple template."""
        output_file = str(tmp_path / "output.txt")
        
        tmpl_config = TemplateConfig(
            template=[[simple_template]],
            template_output=[[output_file]]
        )
        engine = TemplateEngine(template_config=tmpl_config, logger=test_logger)
        
        engine.generate_from_template(simple_template, output_file, sample_detection_results)
        
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            content = f.read()
        
        assert "Suspicious PowerShell Command" in content
        assert "high" in content
        assert "2" in content  # count
    
    def test_generate_json_template(self, json_template, tmp_path, test_logger, sample_detection_results):
        """Test generating JSON output from template."""
        output_file = str(tmp_path / "output.json")
        
        tmpl_config = TemplateConfig(
            template=[[json_template]],
            template_output=[[output_file]]
        )
        engine = TemplateEngine(template_config=tmpl_config, logger=test_logger)
        
        engine.generate_from_template(json_template, output_file, sample_detection_results)
        
        assert Path(output_file).exists()
        
        with open(output_file) as f:
            content = f.read()
        
        # Should be valid JSON-like structure
        assert '"title":' in content
        assert '"level":' in content
    
    def test_generate_appends_to_file(self, simple_template, tmp_path, test_logger, sample_detection_results):
        """Test that generate_from_template appends to existing file."""
        output_file = str(tmp_path / "output.txt")
        
        # Write initial content
        with open(output_file, 'w') as f:
            f.write("Initial content\n")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(simple_template, output_file, sample_detection_results)
        
        with open(output_file) as f:
            content = f.read()
        
        assert "Initial content" in content
        assert "Suspicious PowerShell Command" in content
    
    def test_generate_with_time_field(self, tmp_path, test_logger, sample_detection_results):
        """Test that timeField is passed to template."""
        template_content = """Time Field: {{ timeField }}
{% for elem in data %}
Rule: {{ elem.title }}
{% endfor %}
"""
        template_file = tmp_path / "time_template.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.txt")
        
        tmpl_config = TemplateConfig(time_field="SystemTime")
        engine = TemplateEngine(template_config=tmpl_config, logger=test_logger)
        
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        
        with open(output_file) as f:
            content = f.read()
        
        assert "Time Field: SystemTime" in content
    
    def test_generate_handles_empty_data(self, simple_template, tmp_path, test_logger):
        """Test template generation with empty data."""
        output_file = str(tmp_path / "output.txt")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(simple_template, output_file, [])
        
        assert Path(output_file).exists()
    
    def test_generate_handles_template_error(self, tmp_path, test_logger, sample_detection_results):
        """Test handling of template syntax errors."""
        # Create template with syntax error
        bad_template = tmp_path / "bad.tmpl"
        bad_template.write_text("{% for elem in data %}{{ undefined_var.nested }}{% endfor %}")
        
        output_file = str(tmp_path / "output.txt")
        
        engine = TemplateEngine(logger=test_logger)
        
        # Should not raise exception
        engine.generate_from_template(str(bad_template), output_file, sample_detection_results)


class TestTemplateEngineRun:
    """Tests for the run method."""
    
    def test_run_processes_all_templates(self, tmp_path, test_logger, sample_detection_results):
        """Test that run processes all configured templates."""
        # Create two templates
        template1 = tmp_path / "template1.tmpl"
        template1.write_text("Template 1: {{ data | length }} results")
        
        template2 = tmp_path / "template2.tmpl"
        template2.write_text("Template 2: {{ data[0].title if data else 'empty' }}")
        
        output1 = str(tmp_path / "output1.txt")
        output2 = str(tmp_path / "output2.txt")
        
        tmpl_config = TemplateConfig(
            template=[[str(template1)], [str(template2)]],
            template_output=[[output1], [output2]]
        )
        engine = TemplateEngine(template_config=tmpl_config, logger=test_logger)
        
        engine.run(sample_detection_results)
        
        assert Path(output1).exists()
        assert Path(output2).exists()
        
        with open(output1) as f:
            assert "Template 1:" in f.read()
        
        with open(output2) as f:
            assert "Template 2:" in f.read()
    
    def test_run_with_no_templates(self, test_logger, sample_detection_results):
        """Test run with no templates configured."""
        tmpl_config = TemplateConfig(template=[], template_output=[])
        engine = TemplateEngine(template_config=tmpl_config, logger=test_logger)
        
        # Should not raise exception
        engine.run(sample_detection_results)


class TestTemplateEngineJinjaFeatures:
    """Tests for Jinja2 template features."""
    
    def test_template_filters(self, tmp_path, test_logger, sample_detection_results):
        """Test Jinja2 filters in templates."""
        template_content = """
{% for elem in data %}
Title Upper: {{ elem.title | upper }}
Title Length: {{ elem.title | length }}
{% endfor %}
"""
        template_file = tmp_path / "filters.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.txt")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        
        with open(output_file) as f:
            content = f.read()
        
        assert "SUSPICIOUS POWERSHELL COMMAND" in content
    
    def test_template_conditionals(self, tmp_path, test_logger, sample_detection_results):
        """Test Jinja2 conditionals in templates."""
        template_content = """
{% for elem in data %}
{% if elem.rule_level == "high" %}
HIGH SEVERITY: {{ elem.title }}
{% elif elem.rule_level == "medium" %}
MEDIUM SEVERITY: {{ elem.title }}
{% endif %}
{% endfor %}
"""
        template_file = tmp_path / "conditionals.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.txt")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        
        with open(output_file) as f:
            content = f.read()
        
        assert "HIGH SEVERITY: Suspicious PowerShell Command" in content
        assert "MEDIUM SEVERITY: CMD Execution" in content
    
    def test_template_loops_with_matches(self, tmp_path, test_logger, sample_detection_results):
        """Test iterating over matches in template."""
        template_content = """
{% for elem in data %}
Rule: {{ elem.title }}
Matches:
{% for match in elem.matches %}
  - {{ match.CommandLine | default('N/A') }}
{% endfor %}
{% endfor %}
"""
        template_file = tmp_path / "matches.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.txt")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        
        with open(output_file) as f:
            content = f.read()
        
        assert "powershell.exe -c whoami" in content
        assert "powershell.exe -encodedCommand abc" in content
    
    def test_template_tojson_filter(self, tmp_path, test_logger, sample_detection_results):
        """Test Jinja2 tojson filter."""
        template_content = """
{% for elem in data %}
{
    "title": {{ elem.title | tojson }},
    "tags": {{ elem.tags | tojson }}
}
{% endfor %}
"""
        template_file = tmp_path / "json.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.txt")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        
        with open(output_file) as f:
            content = f.read()
        
        # tojson should properly escape strings
        assert '"Suspicious PowerShell Command"' in content
    
    def test_template_with_special_characters(self, tmp_path, test_logger):
        """Test template handling of special characters in data."""
        data = [{
            "title": "Rule with 'quotes' and \"double quotes\"",
            "rule_level": "high",
            "count": 1,
            "matches": [{"CommandLine": "cmd.exe /c \"echo test\""}]
        }]
        
        template_content = """
{% for elem in data %}
Title: {{ elem.title }}
{% for match in elem.matches %}
Cmd: {{ match.CommandLine }}
{% endfor %}
{% endfor %}
"""
        template_file = tmp_path / "special.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.txt")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, data)
        
        assert Path(output_file).exists()
    
    def test_template_with_unicode(self, tmp_path, test_logger):
        """Test template handling of unicode content."""
        data = [{
            "title": "Unicode Rule 日本語 中文",
            "rule_level": "high",
            "count": 1,
            "matches": [{"CommandLine": "echo 你好世界"}]
        }]
        
        template_content = """
{% for elem in data %}
Title: {{ elem.title }}
{% endfor %}
"""
        template_file = tmp_path / "unicode.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.txt")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, data)
        
        with open(output_file, encoding='utf-8') as f:
            content = f.read()
        
        assert "日本語" in content
        assert "中文" in content


class TestTemplateEngineExportFormats:
    """Tests for different export template formats."""
    
    def test_splunk_style_template(self, tmp_path, test_logger, sample_detection_results):
        """Test Splunk-style export template."""
        template_content = """{% for elem in data %}{% for match in elem.matches %}
{{ match | tojson }}
{% endfor %}{% endfor %}"""
        
        template_file = tmp_path / "splunk.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.txt")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        
        assert Path(output_file).exists()
    
    def test_csv_style_template(self, tmp_path, test_logger, sample_detection_results):
        """Test CSV-style export template."""
        template_content = """title,level,count
{% for elem in data -%}
{{ elem.title }},{{ elem.rule_level }},{{ elem.count }}
{% endfor %}"""
        
        template_file = tmp_path / "csv.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.csv")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        
        with open(output_file) as f:
            content = f.read()
        
        assert "title,level,count" in content
        assert "Suspicious PowerShell Command,high,2" in content
    
    def test_elk_style_template(self, tmp_path, test_logger, sample_detection_results):
        """Test Elasticsearch/ELK-style bulk export template."""
        template_content = """{% for elem in data %}{% for match in elem.matches %}
{"index":{}}
{"rule_title":{{ elem.title | tojson }},"rule_level":{{ elem.rule_level | tojson }},"event":{{ match | tojson }}}
{% endfor %}{% endfor %}"""
        
        template_file = tmp_path / "elk.tmpl"
        template_file.write_text(template_content)
        
        output_file = str(tmp_path / "output.ndjson")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        
        with open(output_file) as f:
            content = f.read()
        
        assert '{"index":{}}' in content
        assert '"rule_title":' in content
