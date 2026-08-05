"""
Tests for the TemplateEngine and ZircoliteGuiGenerator classes.
"""

import json
import logging
import re
import sys
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import TemplateConfig, TemplateEngine
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

        # A broken template must be reported and skipped, not abort the run and
        # not leave a half-written file behind pretending to be output.
        engine.generate_from_template(str(bad_template), output_file, sample_detection_results)

        assert not Path(output_file).exists()


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

        # Nothing configured means nothing rendered, and a clean success rather
        # than a crash or a reported failure
        assert engine.run(sample_detection_results) is True


class TestTemplateEngineAppendMode:
    """Tests for the append=True option (issue #132)."""

    def test_default_overwrites(self, simple_template, tmp_path, test_logger, sample_detection_results):
        """By default the engine still overwrites; append flag is False."""
        output_file = str(tmp_path / "out.txt")
        Path(output_file).write_text("preexisting\n")

        engine = TemplateEngine(logger=test_logger)
        assert engine.append is False
        engine.generate_from_template(simple_template, output_file, sample_detection_results)

        content = Path(output_file).read_text()
        assert "preexisting" not in content

    def test_append_via_config_accumulates(self, tmp_path, test_logger, sample_detection_results):
        """Engine-wide append=True keeps previous content and appends."""
        template_file = tmp_path / "tmpl.tmpl"
        template_file.write_text("X")
        output_file = str(tmp_path / "out.txt")

        cfg = TemplateConfig(
            template=[[str(template_file)]],
            template_output=[[output_file]],
            append=True,
        )
        engine = TemplateEngine(template_config=cfg, logger=test_logger)

        engine.generate_from_template(str(template_file), output_file, sample_detection_results)
        engine.generate_from_template(str(template_file), output_file, sample_detection_results)

        assert Path(output_file).read_text() == "XX"

    def test_append_preserves_existing_content(self, tmp_path, test_logger, sample_detection_results):
        """append=True keeps any pre-existing file content untouched."""
        template_file = tmp_path / "tmpl.tmpl"
        template_file.write_text("rendered")
        output_file = tmp_path / "out.txt"
        output_file.write_text("old data\n")

        cfg = TemplateConfig(append=True)
        engine = TemplateEngine(template_config=cfg, logger=test_logger)
        engine.generate_from_template(str(template_file), str(output_file), sample_detection_results)

        assert output_file.read_text() == "old data\nrendered"

    def test_append_per_call_override(self, tmp_path, test_logger, sample_detection_results):
        """The append parameter on generate_from_template overrides the engine setting."""
        template_file = tmp_path / "tmpl.tmpl"
        template_file.write_text("Y")
        output_file = tmp_path / "out.txt"

        engine = TemplateEngine(logger=test_logger)
        # First write
        engine.generate_from_template(str(template_file), str(output_file), sample_detection_results)
        # Force append for the second call
        engine.generate_from_template(
            str(template_file), str(output_file), sample_detection_results, append=True
        )

        assert output_file.read_text() == "YY"

    def test_run_uses_append_setting(self, tmp_path, test_logger, sample_detection_results):
        """run() honours the engine-wide append flag for every configured template."""
        template_file = tmp_path / "tmpl.tmpl"
        template_file.write_text("Z")
        output_file = str(tmp_path / "out.txt")
        Path(output_file).write_text("seed\n")

        cfg = TemplateConfig(
            template=[[str(template_file)]],
            template_output=[[output_file]],
            append=True,
        )
        engine = TemplateEngine(template_config=cfg, logger=test_logger)
        engine.run(sample_detection_results)
        engine.run(sample_detection_results)

        assert Path(output_file).read_text() == "seed\nZZ"


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
        assert template_file.exists(), (
            f"Shipped Timesketch template missing at {template_file} — packaging bug"
        )

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
        assert template_file.exists(), (
            f"Shipped Timesketch template missing at {template_file} — packaging bug"
        )

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
        """Test the Elasticsearch/ELK export template, which is plain NDJSON."""
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
        """A --package-dir that does not exist is an error, not a silent fallback."""
        mock_logger = MagicMock()
        gen = ZircoliteGuiGenerator(logger=mock_logger)
        gen.source_archive = __file__  # exists but not a zip

        assert gen.generate(sample_detection_results, directory="/nonexistent/path") is False

        assert any(
            "does not exist" in str(call) for call in mock_logger.error.call_args_list
        )

    def test_generate_rejects_a_package_dir_that_is_a_file(
        self, sample_detection_results, tmp_path
    ):
        """os.path.exists() accepted a file, which then failed inside shutil.move."""
        target = tmp_path / "not-a-directory"
        target.write_text("", encoding="utf-8")
        mock_logger = MagicMock()
        gen = ZircoliteGuiGenerator(logger=mock_logger)

        assert gen.generate(sample_detection_results, directory=str(target)) is False

        assert any(
            "is not a directory" in str(call) for call in mock_logger.error.call_args_list
        )

    def test_generate_names_the_template_when_it_produces_nothing(
        self, sample_detection_results, tmp_path
    ):
        """The failure used to surface as a missing data-XXXX.js two lines later."""
        (tmp_path / "pkg.zip").write_bytes(b"x")
        mock_logger = MagicMock()
        gen = ZircoliteGuiGenerator(logger=mock_logger)
        gen.source_archive = str(tmp_path / "pkg.zip")
        gen.templateFile = str(tmp_path / "broken.tmpl")
        gen.tmpFile = str(tmp_path / "data.js")
        gen.tmpDir = str(tmp_path / "tmp-zircogui-xyz")

        with patch("zircolite.templates.shutil.unpack_archive"), \
             patch.object(TemplateEngine, "generate_from_template", return_value=False), \
             patch("zircolite.templates.shutil.move") as mock_move, \
             patch("zircolite.templates.shutil.make_archive") as mock_archive:
            assert gen.generate(sample_detection_results, directory="") is False

        # A partial data.js must never reach the package
        mock_move.assert_not_called()
        mock_archive.assert_not_called()
        assert any(
            "broken.tmpl" in str(call) for call in mock_logger.error.call_args_list
        )

    def test_generate_exception_calls_finally_cleanup(self, test_logger, sample_detection_results, tmp_path):
        """When unpack_archive raises, finally block still runs and cleans tmpDir."""
        gen = ZircoliteGuiGenerator(logger=test_logger)
        gen.source_archive = str(tmp_path / "package.zip")
        gen.tmpDir = str(tmp_path / "tmp-zircogui-abc1")
        Path(gen.tmpDir).mkdir(parents=True)

        with patch("zircolite.templates.shutil.unpack_archive", side_effect=RuntimeError("bad archive")):
            gen.generate(sample_detection_results, directory="")
        assert not Path(gen.tmpDir).exists()

    def test_generate_success_mocks(self, test_logger, sample_detection_results, tmp_path):
        """Generate with mocked unpack, TemplateEngine, move and make_archive."""
        (tmp_path / "pkg.zip").write_bytes(b"x")
        gen = ZircoliteGuiGenerator(logger=test_logger)
        gen.source_archive = str(tmp_path / "pkg.zip")
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
        gen.source_archive = str(package_zip)
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

    def test_attack_navigator_template_outputs_structured_layer(self, tmp_path, test_logger):
        """The shipped Navigator template emits parseable severity-based layer JSON."""
        data = [
            {
                "title": "Rule A",
                "id": "rule-a",
                "tags": ["attack.execution", "attack.t1059.001"],
                "rule_level": "medium",
                "count": 1,
            },
            {
                "title": "Rule B",
                "id": "rule-b",
                "tags": ["attack.execution", "attack.t1059.001"],
                "rule_level": "high",
                "count": 2,
            },
        ]
        template_file = Path(__file__).parent.parent / "templates" / "exportForAttackNavigator.tmpl"
        output_file = tmp_path / "navigator.json"

        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), str(output_file), data)

        layer = json.loads(output_file.read_text())
        assert layer["name"] == "Zircolite Detected ATT&CK Techniques"
        assert layer["description"] == "ATT&CK techniques detected by Zircolite, colored by maximum rule severity"
        assert {item["label"] for item in layer["legendItems"]} >= {"High", "Medium", "Low"}

        technique = layer["techniques"][0]
        assert technique["techniqueID"] == "T1059.001"
        assert technique["tactic"] == "execution"
        assert technique["score"] == 3
        assert technique["color"] == "#ff6600"
        assert technique["comment"] == "3 hits across 2 rules; max severity: high"
        assert technique["metadata"] == [
            {"name": "Event Count", "value": "3"},
            {"name": "Max Severity", "value": "high"},
            {"name": "Rule Count", "value": "2"},
            {"name": "Rules", "value": "Rule B (rule-b); Rule A (rule-a)"},
        ]

    def test_attack_navigator_template_handles_empty_data(self, tmp_path, test_logger):
        """Navigator export still creates a valid empty layer."""
        template_file = Path(__file__).parent.parent / "templates" / "exportForAttackNavigator.tmpl"
        output_file = tmp_path / "navigator_empty.json"

        engine = TemplateEngine(logger=test_logger)
        engine.generate_from_template(str(template_file), str(output_file), [])

        layer = json.loads(output_file.read_text())
        assert layer["techniques"] == []

    def test_generate_from_template_reports_the_real_error(self, tmp_path, sample_detection_results):
        """A failure must return False and name the cause, not just 'template error'.

        The generic message sent the real exception to debug only, so a pipeline
        whose export silently produced nothing had to re-run the whole analysis
        with --debug to find out why.
        """
        mock_logger = MagicMock()
        output_file = str(tmp_path / "out.txt")
        engine = TemplateEngine(logger=mock_logger)

        written = engine.generate_from_template(
            "/nonexistent/template.tmpl", output_file, sample_detection_results
        )

        assert written is False
        mock_logger.error.assert_called_once()
        message = mock_logger.error.call_args[0][0]
        assert "out.txt" in message
        assert "No such file" in message

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


class TestSummaryCsvTemplateIsParseableCsv:
    """The shipped CSV summary must survive a CSV reader.

    It escaped every text column with `tojson`, which escapes for JSON: an
    apostrophe in a rule title came out as \\u0027, an ampersand as \\u0026, and
    an embedded double quote as \\" rather than the doubled "" a CSV reader
    expects -- so the row silently lost its column boundaries.
    """

    TEMPLATE = Path(__file__).parent.parent / "templates" / "exportSummaryCSV.tmpl"

    def _render(self, tmp_path, data):
        from zircolite.config import TemplateConfig
        from zircolite.templates import TemplateEngine

        out = tmp_path / "summary.csv"
        engine = TemplateEngine(
            TemplateConfig(template=[[str(self.TEMPLATE)]], template_output=[[str(out)]]),
            logger=logging.getLogger("test"),
        )
        engine.run(data)
        return out.read_text()

    def test_quotes_apostrophes_and_separators_survive_a_csv_reader(self, tmp_path):
        import csv
        import io

        data = [{
            "title": 'Rule with "quotes", a comma and an apostrophe\'s tail',
            "id": "rule-001",
            "rule_level": "high",
            "count": 3,
            "description": "A & B <tag>\nsecond line",
        }]

        rendered = self._render(tmp_path, data)
        rows = [r for r in csv.reader(io.StringIO(rendered)) if r]

        assert rows[0] == [
            "rule_title", "rule_id", "rule_level", "count", "description"
        ]
        assert len(rows[1]) == 5, f"row split into {len(rows[1])} columns: {rows[1]}"
        assert rows[1][0] == 'Rule with "quotes", a comma and an apostrophe\'s tail'
        assert rows[1][3] == "3"
        assert "\\u0027" not in rendered and "\\u0026" not in rendered
        # Folded to one row so a multi-line description cannot break the table
        assert rows[1][4] == "A & B <tag> second line"


class TestZircoGuiTacticBuckets:
    """Every ATT&CK tactic the rulesets emit must reach a Mini-GUI lane.

    The template used to test hardcoded underscored tag names
    (``attack.privilege_escalation``) while the rulesets emit hyphenated ones,
    so seven of the fifteen tactic lanes could never populate. Routing the test
    through ``extract_attack_tactics`` makes ``zircolite.attack`` the only place
    tag spellings are known.
    """

    TEMPLATE = Path(__file__).parent.parent / "templates" / "exportForZircoGui.tmpl"

    # Mini-GUI array name -> the tactic shortnames that must land in it.
    LANES: ClassVar[dict[str, list[str]]] = {
        "Reconnaissance": ["reconnaissance"],
        "ResourceDevelopment": ["resource-development"],
        "InitialAccess": ["initial-access"],
        "Execution": ["execution"],
        "Persistence": ["persistence"],
        "PrivilegeEscalation": ["privilege-escalation"],
        # v19 retired Defense Evasion; this lane carries both successors.
        "DefenseEvasion": ["stealth", "defense-impairment"],
        "CredentialAccess": ["credential-access"],
        "Discovery": ["discovery"],
        "LateralMovement": ["lateral-movement"],
        "Collection": ["collection"],
        "CommandAndControl": ["command-and-control"],
        "Exfiltration": ["exfiltration"],
        "Impact": ["impact"],
    }

    def _render(self, tmp_path, data):
        from zircolite.config import TemplateConfig
        from zircolite.templates import TemplateEngine

        out = tmp_path / "data.js"
        engine = TemplateEngine(
            TemplateConfig(
                template=[[str(self.TEMPLATE)]],
                template_output=[[str(out)]],
                time_field="SystemTime",
            ),
            logger=logging.getLogger("test"),
        )
        assert engine.generate_from_template(str(self.TEMPLATE), str(out), data)
        return out.read_text()

    @staticmethod
    def _detection(title, tags):
        return {
            "title": title,
            "rule_level": "high",
            "sigmafile": "",
            "description": "d",
            "tags": tags,
            "matches": [{"row_id": 1, "SystemTime": "2026-01-01T00:00:00Z"}],
        }

    @staticmethod
    def _titles_in(rendered, lane):
        body = re.search(rf"var {lane}Data = \[(.*?)\n\];", rendered, re.DOTALL).group(1)
        return re.findall(r'"title":"(.*?)"', body)

    def test_every_tactic_lane_receives_its_detections(self, tmp_path):
        shortname_to_tag = {
            s: f"attack.{s}" for lane in self.LANES.values() for s in lane
        }
        data = [
            self._detection(f"rule-{s}", [tag, "attack.t1059"])
            for s, tag in shortname_to_tag.items()
        ]

        rendered = self._render(tmp_path, data)

        for lane, shortnames in self.LANES.items():
            assert sorted(self._titles_in(rendered, lane)) == sorted(
                f"rule-{s}" for s in shortnames
            ), f"{lane}Data did not receive its detections"

    def test_legacy_tag_spellings_still_route(self, tmp_path):
        data = [
            self._detection("underscored", ["attack.privilege_escalation"]),
            self._detection("retired", ["attack.defense-evasion"]),
        ]

        rendered = self._render(tmp_path, data)

        assert self._titles_in(rendered, "PrivilegeEscalation") == ["underscored"]
        assert self._titles_in(rendered, "DefenseEvasion") == ["retired"]

    def test_a_rule_with_no_resolvable_tactic_lands_in_other(self, tmp_path):
        """'Other' tested ``tags == []``, so a rule with only technique tags
        fell out of every lane instead of into this one."""
        data = [self._detection("orphan", ["attack.t1059.001", "cve.2024.1234"])]

        rendered = self._render(tmp_path, data)

        assert self._titles_in(rendered, "Other") == ["orphan"]
