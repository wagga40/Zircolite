"""
Tests for the TemplateEngine and ZircoliteGuiGenerator classes.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import TemplateEngine, TemplateConfig
from zircolite.templates import ZircoliteGuiGenerator


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
    
    def test_generate_overwrites_existing_file(self, simple_template, tmp_path, test_logger, sample_detection_results):
        """Test that generate_from_template overwrites (not appends to) existing file."""
        output_file = str(tmp_path / "output.txt")
        
        # Write initial content
        with open(output_file, 'w') as f:
            f.write("Initial content\n")
        
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(simple_template, output_file, sample_detection_results)
        
        with open(output_file) as f:
            content = f.read()
        
        assert "Initial content" not in content
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
    
    def test_timesketch_template_uses_sanitized_timefield(self, tmp_path, test_logger):
        """Timesketch template must populate 'datetime' using the sanitized time field.

        Reproduces the bug where ECS/Elastic JSON events have '@timestamp' in
        the raw data, but the streaming processor stores it as 'timestamp'
        (stripping the '@'). The template's timeField must match the column name.
        """
        ts_value = "2024-03-01T23:05:25.150Z"
        data = [{
            "title": "Test Rule",
            "id": "abc-123",
            "description": "Test",
            "rule_level": "high",
            "matches": [
                {
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": "11",
                    "timestamp": ts_value,
                    "EventTime": "2024-03-01T23:05:27.220Z",
                    "Image": "C:\\test.exe",
                }
            ],
        }]

        template_file = Path(__file__).parent.parent / "templates" / "exportForTimesketch.tmpl"
        if not template_file.exists():
            pytest.skip("Timesketch template not found")

        output_file = str(tmp_path / "timesketch.json")

        # 'timestamp' is the sanitized name (what the streaming processor stores)
        tmpl_config = TemplateConfig(time_field="timestamp")
        engine = TemplateEngine(template_config=tmpl_config, logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, data)

        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                assert record["datetime"] == ts_value, (
                    f"datetime should be '{ts_value}', got '{record['datetime']}'"
                )

    def test_timesketch_template_empty_with_unsanitized_field(self, tmp_path, test_logger):
        """Demonstrate the original bug: '@timestamp' as timeField yields empty datetime."""
        data = [{
            "title": "Test Rule",
            "id": "abc-123",
            "description": "Test",
            "rule_level": "high",
            "matches": [
                {
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "timestamp": "2024-03-01T23:05:25.150Z",
                }
            ],
        }]

        template_file = Path(__file__).parent.parent / "templates" / "exportForTimesketch.tmpl"
        if not template_file.exists():
            pytest.skip("Timesketch template not found")

        output_file = str(tmp_path / "timesketch_bad.json")

        # '@timestamp' would NOT match the 'timestamp' column — the old bug
        tmpl_config = TemplateConfig(time_field="@timestamp")
        engine = TemplateEngine(template_config=tmpl_config, logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, data)

        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                assert record["datetime"] == "", (
                    "With unsanitized '@timestamp', datetime should be empty"
                )

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


# =============================================================================
# ZircoliteGuiGenerator
# =============================================================================

class TestZircoliteGuiGenerator:
    """Tests for ZircoliteGuiGenerator.generate() with mocks."""

    def test_generate_directory_nonexistent_logs_error(self, sample_detection_results):
        """When directory is given but does not exist, error is logged and fallback used."""
        mock_logger = MagicMock()
        gen = ZircoliteGuiGenerator(logger=mock_logger)
        gen.packageDir = __file__  # exists but not a zip
        with patch("zircolite.templates.os.path.exists", return_value=False):
            with patch("zircolite.templates.shutil.unpack_archive", side_effect=ValueError("not a zip")):
                gen.generate(sample_detection_results, directory="/nonexistent/path")
        mock_logger.error.assert_called()

    def test_generate_exception_calls_finally_cleanup(self, test_logger, sample_detection_results, tmp_path):
        """When unpack_archive raises, finally block still runs and cleans tmpDir."""
        gen = ZircoliteGuiGenerator(logger=test_logger)
        gen.packageDir = str(tmp_path / "package.zip")
        gen.tmpDir = str(tmp_path / "tmp-zircogui-abc1")
        Path(gen.tmpDir).mkdir(parents=True)

        with patch("zircolite.templates.shutil.unpack_archive", side_effect=RuntimeError("bad archive")):
            gen.generate(sample_detection_results, directory="")
        assert not Path(gen.tmpDir).exists()

    def test_generate_success_mocks(self, test_logger, sample_detection_results, tmp_path):
        """Generate with mocked unpack, TemplateEngine, move and make_archive."""
        (tmp_path / "pkg.zip").write_bytes(b"x")
        gen = ZircoliteGuiGenerator(logger=test_logger)
        gen.packageDir = str(tmp_path / "pkg.zip")
        gen.templateFile = str(tmp_path / "tmpl.js")
        gen.tmpFile = str(tmp_path / "data.js")
        gen.outputFile = "zircogui-output"
        gen.tmpDir = str(tmp_path / "tmp-zircogui-xyz")
        Path(gen.templateFile).write_text("{{ data }}")

        with patch("zircolite.templates.shutil.unpack_archive") as mock_unpack:
            def mkdirs(archive, path, fmt):
                Path(path).mkdir(parents=True)
                (Path(path) / "zircogui").mkdir()
            mock_unpack.side_effect = mkdirs
            with patch("zircolite.templates.shutil.move"):
                with patch("zircolite.templates.shutil.make_archive") as mock_make:
                    gen.generate(sample_detection_results, directory="")
                    mock_make.assert_called_once()
        assert not Path(gen.tmpDir).exists()


class TestGuiGeneratorHappyPath:
    """ZircoliteGuiGenerator.generate() end-to-end: real zip produced with expected content."""

    def test_generates_zip_with_data(self, test_logger, sample_detection_results, tmp_path):
        import zipfile
        gui_dir = tmp_path / "zircogui"
        gui_dir.mkdir()
        (gui_dir / "index.html").write_text("<html></html>")
        package_zip = tmp_path / "package.zip"
        with zipfile.ZipFile(package_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in gui_dir.rglob("*"):
                if f.is_file():
                    zf.write(f, f.relative_to(gui_dir.parent))

        template_file = tmp_path / "export.js.tmpl"
        template_file.write_text("var data = {{ data | tojson }};")
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        gen = ZircoliteGuiGenerator(logger=test_logger)
        gen.packageDir = str(package_zip)
        gen.templateFile = str(template_file)
        gen.outputFile = "zircogui-result"
        gen.generate(sample_detection_results, directory=str(out_dir))

        zip_path = out_dir / "zircogui-result.zip"
        if not zip_path.exists():
            zip_path = Path(gen.outputFile + ".zip")
        assert zip_path.exists()
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            assert "data.js" in names or any("data.js" in n for n in names)


class TestTemplateEngineAttackNavigatorHelpers:
    """Tests for ATT&CK Navigator helpers used in templates (_extract_attack_techniques, collect_navigator_techniques)."""

    def test_extract_attack_techniques_filter(self, tmp_path, test_logger, sample_detection_results):
        """Template filter extract_attack_techniques returns technique IDs from tags."""
        template_content = """{% for elem in data %}
Techniques: {{ elem.tags | extract_attack_techniques | join(',') }}
{% endfor %}"""
        template_file = tmp_path / "attack.tmpl"
        template_file.write_text(template_content)
        output_file = str(tmp_path / "attack_out.txt")
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        with open(output_file) as f:
            content = f.read()
        assert "T1059.001" in content

    def test_collect_navigator_techniques_global(self, tmp_path, test_logger, sample_detection_results):
        """Template global collect_navigator_techniques builds Navigator technique list."""
        template_content = """{% set nav = collect_navigator_techniques(data) %}
{% for t in nav %}
{{ t.techniqueID }}: {{ t.score }} {{ t.color }}
{% endfor %}"""
        template_file = tmp_path / "navigator.tmpl"
        template_file.write_text(template_content)
        output_file = str(tmp_path / "nav_out.txt")
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        with open(output_file) as f:
            content = f.read()
        assert "T1059.001" in content
        assert "#" in content
        assert "2" in content

    def test_collect_navigator_techniques_merges_same_technique(self, tmp_path, test_logger):
        """When two detections share the same technique, score is summed and level is max."""
        data = [
            {"title": "Rule A", "tags": ["attack.t1059.001"], "rule_level": "medium", "count": 1},
            {"title": "Rule B", "tags": ["attack.t1059.001"], "rule_level": "high", "count": 2},
        ]
        template_content = """{% set nav = collect_navigator_techniques(data) %}
{% for t in nav %}{{ t.techniqueID }}|{{ t.score }}|{{ t.color }}{% endfor %}"""
        template_file = tmp_path / "nav_merge.tmpl"
        template_file.write_text(template_content)
        output_file = str(tmp_path / "nav_merge_out.txt")
        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), output_file, data)
        with open(output_file) as f:
            content = f.read()
        assert "T1059.001" in content
        assert "|3|" in content
        assert "#ff6600" in content

    def test_generate_from_template_missing_file_logs_error(self, tmp_path, sample_detection_results):
        """When template file is missing, error and debug are logged."""
        mock_logger = MagicMock()
        output_file = str(tmp_path / "out.txt")
        engine = TemplateEngine(logger=mock_logger)
        engine.generate_from_template("/nonexistent/template.tmpl", output_file, sample_detection_results)
        mock_logger.error.assert_called_once()
        mock_logger.debug.assert_called_once()

    def test_generate_from_template_overwrites_existing(self, tmp_path, sample_detection_results):
        """Template output should overwrite (not append to) existing files."""
        template_file = tmp_path / "tmpl.tmpl"
        template_file.write_text("{{ data | length }}")
        output_file = str(tmp_path / "out.txt")

        engine = TemplateEngine()
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)

        content = open(output_file).read()
        expected = str(len(sample_detection_results))
        assert content == expected
