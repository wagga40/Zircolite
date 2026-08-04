"""
Template engine and GUI generator for Zircolite.

This module contains:
- TemplateEngine: Jinja2 template rendering for output generation
- ZircoliteGuiGenerator: Mini GUI package generator
"""

import logging
import os
import shutil
from pathlib import Path
from typing import Any

from jinja2 import Environment

from .attack import extract_attack_tactics, extract_attack_techniques
from .config import GuiConfig, TemplateConfig
from .utils import random_suffix

_LEVEL_ORDER = {'unknown': -1, 'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
_LEVEL_COLOR = {
    'critical': '#ff0000',
    'high': '#ff6600',
    'medium': '#ffcc00',
    'low': '#66ff66',
    'informational': '#aaffaa',
}


def _count_label(count: int, singular: str) -> str:
    return singular if count == 1 else f"{singular}s"


def _format_rule_summary(rule: dict) -> str:
    title = rule.get('title') or 'Unknown Rule'
    rule_id = rule.get('id')
    return f"{title} ({rule_id})" if rule_id else title


def _rule_sort_key(rule: dict) -> tuple:
    return (-_LEVEL_ORDER.get(rule.get('level', 'unknown'), -1), _format_rule_summary(rule))


def _collect_navigator_techniques(data: list) -> list:
    """Build a deduplicated ATT&CK Navigator technique list from detection results.

    For each unique technique/tactic pair found across all detections, the
    entry carries the total event count and the highest severity level seen.
    """
    merged: dict = {}
    for elem in data:
        tags = elem.get('tags', [])
        tactics = extract_attack_tactics(tags) or [None]
        techniques = extract_attack_techniques(tags)
        level = str(elem.get('rule_level') or 'unknown').lower()
        count = int(elem.get('count') or 0)
        rule = {
            'title': elem.get('title', ''),
            'id': elem.get('id', ''),
            'level': level,
        }

        for tid in techniques:
            for tactic in tactics:
                key = (tid, tactic)
                if key not in merged:
                    merged[key] = {
                        'techniqueID': tid,
                        'tactic': tactic,
                        'score': 0,
                        'level': level,
                        'rules': {},
                    }

                entry = merged[key]
                entry['score'] += count
                if _LEVEL_ORDER.get(level, -1) > _LEVEL_ORDER.get(entry['level'], -1):
                    entry['level'] = level
                entry['rules'][(_format_rule_summary(rule), level)] = rule

    entries = []
    for info in merged.values():
        rules = sorted(info['rules'].values(), key=_rule_sort_key)
        rule_count = len(rules)
        score = info['score']
        level = info['level']
        entry = {
            'techniqueID': info['techniqueID'],
            'tactic': info['tactic'],
            'score': score,
            'color': _LEVEL_COLOR.get(level, '#aaaaaa'),
            'comment': (
                f"{score} {_count_label(score, 'hit')} across "
                f"{rule_count} {_count_label(rule_count, 'rule')}; max severity: {level}"
            ),
            'metadata': [
                {'name': 'Event Count', 'value': str(score)},
                {'name': 'Max Severity', 'value': level},
                {'name': 'Rule Count', 'value': str(rule_count)},
                {'name': 'Rules', 'value': '; '.join(_format_rule_summary(rule) for rule in rules[:5])},
            ],
        }
        entries.append(entry)
    return entries


def csv_field(value: Any) -> str:
    """Quote *value* for a CSV field, RFC 4180 style.

    ``tojson`` is the wrong tool here even though the surrounding template is
    text: it escapes for JSON, so an apostrophe in a rule title arrives as
    ``\\u0027`` and an embedded double quote as ``\\"`` rather than the doubled
    ``""`` a CSV reader expects. Newlines are folded to spaces so one rule stays
    on one row.
    """
    text = "" if value is None else str(value)
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return '"' + text.replace('"', '""') + '"'


def _make_jinja2_env() -> Environment:
    """Create a Jinja2 Environment with Zircolite-specific filters.

    Autoescaping stays off deliberately. Every template renders a machine
    format -- JSON for Splunk, Elastic, Zinc and the Mini-GUI, NDJSON for
    Timesketch, JSON for SARIF and ATT&CK Navigator, CSV for the summary --
    and HTML-escaping a command line inside a JSON string would corrupt it.
    Values are escaped for their real target instead: ``tojson`` for the JSON
    formats, ``csv_field`` for the CSV one.

    A template that emits HTML would need `autoescape=True`; none ships, and
    the Mini-GUI loads its data as JavaScript rather than interpolating it.
    """
    env = Environment(autoescape=False)  # noqa: S701 - see docstring
    env.filters['csv_field'] = csv_field
    env.filters['extract_attack_techniques'] = extract_attack_techniques
    env.filters['extract_attack_tactics'] = extract_attack_tactics
    env.globals['collect_navigator_techniques'] = _collect_navigator_techniques
    return env


class TemplateEngine:
    """Engine for generating output from Jinja2 templates."""

    def __init__(
        self,
        template_config: TemplateConfig | None = None,
        *,
        logger: logging.Logger | None = None
    ):
        """
        Initialize TemplateEngine.

        Args:
            template_config: Template configuration (uses defaults if None)
            logger: Logger instance (creates default if None)
        """
        cfg = template_config or TemplateConfig()

        self.logger = logger or logging.getLogger(__name__)
        self.template = cfg.template
        self.template_output = cfg.template_output
        self.time_field = cfg.time_field
        self.append = cfg.append

    def generate_from_template(
        self,
        template_file: str,
        output_filename: str,
        data: list[dict[str, Any]],
        append: bool | None = None,
    ) -> bool:
        """Use Jinja2 to output data in a specific format. True when written.

        If ``append`` is ``None``, the engine-wide ``self.append`` setting is
        used. Pass ``True``/``False`` explicitly to override per-call.
        """
        try:
            with open(template_file, encoding='utf-8') as tmpl:
                template = _make_jinja2_env().from_string(tmpl.read())

            # Render before opening the output file so a render failure does
            # not leave a truncated/empty file behind
            rendered = template.render(data=data, timeField=self.time_field)
            mode = 'a' if (self.append if append is None else append) else 'w'
            with open(output_filename, mode, encoding='utf-8') as tpl:
                tpl.write(rendered)
            return True
        except Exception as e:
            # The message has to name the cause: a pipeline that consumes the
            # template output cannot re-run the whole analysis with --debug
            self.logger.error(
                f"[red]    [-] Template error writing '{output_filename}': {e}[/]"
            )
            return False

    def run(self, data: list[dict[str, Any]]) -> bool:
        """Run template generation for all configured templates. True if all wrote."""
        succeeded = True
        for template_spec, output_spec in zip(
            self.template, self.template_output, strict=True
        ):
            mode_label = "appending" if self.append else "writing"
            self.logger.info(
                f'[+] Applying template "{template_spec[0]}", {mode_label} to : {output_spec[0]}'
            )
            if not self.generate_from_template(
                template_spec[0], output_spec[0], data
            ):
                succeeded = False
        return succeeded


class ZircoliteGuiGenerator:
    """Generate the mini GUI."""

    def __init__(
        self,
        gui_config: GuiConfig | None = None,
        *,
        logger: logging.Logger | None = None
    ):
        """
        Initialize ZircoliteGuiGenerator.

        Args:
            gui_config: GUI configuration (uses defaults if None)
            logger: Logger instance (creates default if None)
        """
        cfg = gui_config or GuiConfig()

        self.logger = logger or logging.getLogger(__name__)
        self.templateFile = cfg.template_file
        self.tmpDir = f'tmp-zircogui-{random_suffix(4)}'
        self.tmpFile = f'data-{random_suffix(4)}.js'
        self.outputFile = f'zircogui-output-{random_suffix(4)}'
        self.source_archive = cfg.source_archive
        self.timeField = cfg.time_field

    def generate(
        self, data: list[dict[str, Any]], directory: str = ""
    ) -> bool:
        """Write the Mini-GUI package. False if it could not be written.

        The caller folds this into the exit code: a package the user asked for
        and did not get is a failed run, and it used to be reported only as a
        line of log output on an otherwise successful exit.
        """
        # An empty value means the working directory. Path normalises the
        # trailing separator that rstrip used to have to special-case, including
        # on the filesystem root, where stripping it meant the working directory.
        package_dir: Path | None = None
        if directory:
            candidate = Path(directory)
            if not candidate.is_dir():
                # Writing to the working directory instead would put the package
                # somewhere the user did not ask for and would not think to look.
                reason = "is not a directory" if candidate.exists() else "does not exist"
                self.logger.error(
                    f"[red]    [-] Cannot create GUI package: {directory} {reason}[/]"
                )
                return False
            package_dir = candidate

        try:
            # Extract the GUI package
            shutil.unpack_archive(self.source_archive, self.tmpDir, "zip")

            # Generate data file
            target_name = f"{self.outputFile}.zip"
            target_display = str(package_dir / target_name) if package_dir else target_name
            self.logger.info(f"[+] Generating ZircoGui package to: {target_display}")
            tmpl_config = TemplateConfig(
                template=[[self.templateFile]],
                template_output=[[self.tmpFile]],
                time_field=self.timeField
            )
            export_for_zircogui_tmpl = TemplateEngine(tmpl_config, logger=self.logger)
            if not export_for_zircogui_tmpl.generate_from_template(
                self.templateFile, self.tmpFile, data
            ):
                # Reported two lines down as a missing data-XXXX.js otherwise,
                # which names neither the template nor what went wrong with it.
                self.logger.error(
                    "[red]    [-] Cannot create GUI package: "
                    f"{self.templateFile} produced no data file[/]"
                )
                return False

            # Move data file to package directory
            shutil.move(self.tmpFile, os.path.join(self.tmpDir, "zircogui", "data.js"))

            # Create zip archive
            shutil.make_archive(self.outputFile, 'zip', f"{self.tmpDir}/zircogui")

            # Move to final destination if specified
            if package_dir:
                shutil.move(target_name, package_dir / target_name)

        except Exception as e:
            self.logger.error(f"[red]    [-] {e}[/]")
            return False
        finally:
            # Clean up temporary directory and any leftover data file
            if os.path.exists(self.tmpDir):
                shutil.rmtree(self.tmpDir)
            if os.path.exists(self.tmpFile):
                os.remove(self.tmpFile)
        return True
