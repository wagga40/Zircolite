#!python3
"""
Template engine and GUI generator for Zircolite.

This module contains:
- TemplateEngine: Jinja2 template rendering for output generation
- ZircoliteGuiGenerator: Mini GUI package generator
"""

import logging
import os
import shutil
from typing import Any, Dict, List, Optional

from jinja2 import Environment

from .attack import extract_attack_tactics, extract_attack_techniques
from .config import TemplateConfig, GuiConfig
from .utils import random_suffix


_LEVEL_ORDER = {'unknown': -1, 'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
_LEVEL_COLOR = {
    'critical': '#ff0000',
    'high': '#ff6600',
    'medium': '#ffcc00',
    'low': '#66ff66',
    'informational': '#aaffaa',
}


def _extract_attack_techniques(tags: list) -> list:
    """Extract ATT&CK technique IDs from Sigma tags.

    Converts tags like ``'attack.t1059.001'`` to ``'T1059.001'``.
    Duplicate IDs are removed while preserving order.
    """
    return extract_attack_techniques(tags)


def _extract_attack_tactics(tags: list) -> list:
    """Extract ATT&CK tactic IDs from Sigma tags."""
    return extract_attack_tactics(tags)


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
        tactics = _extract_attack_tactics(tags) or [None]
        techniques = _extract_attack_techniques(tags)
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


def _make_jinja2_env() -> Environment:
    """Create a Jinja2 Environment with Zircolite-specific filters."""
    env = Environment()
    env.filters['extract_attack_techniques'] = _extract_attack_techniques
    env.filters['extract_attack_tactics'] = _extract_attack_tactics
    env.globals['collect_navigator_techniques'] = _collect_navigator_techniques
    return env


class TemplateEngine:
    """Engine for generating output from Jinja2 templates."""
    
    def __init__(
        self,
        template_config: Optional[TemplateConfig] = None,
        *,
        logger: Optional[logging.Logger] = None
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
    
    def generate_from_template(
        self,
        template_file: str,
        output_filename: str,
        data: List[Dict[str, Any]],
    ) -> None:
        """Use Jinja2 to output data in a specific format."""
        try:
            with open(template_file, 'r', encoding='utf-8') as tmpl:
                template = _make_jinja2_env().from_string(tmpl.read())

            with open(output_filename, 'w', encoding='utf-8') as tpl:
                tpl.write(template.render(data=data, timeField=self.time_field))
        except Exception as e:
            self.logger.error("[red]    [-] Template error, activate debug mode to check for errors[/]")
            self.logger.debug(f"    [-] {e}")

    def run(self, data: List[Dict[str, Any]]) -> None:
        """Run template generation for all configured templates."""
        for template_spec, output_spec in zip(self.template, self.template_output):
            self.logger.info(f'[+] Applying template "{template_spec[0]}", outputting to : {output_spec[0]}')
            self.generate_from_template(template_spec[0], output_spec[0], data)


class ZircoliteGuiGenerator:
    """Generate the mini GUI."""
    
    def __init__(
        self,
        gui_config: Optional[GuiConfig] = None,
        *,
        logger: Optional[logging.Logger] = None
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
        self.packageDir = cfg.package_dir
        self.timeField = cfg.time_field

    def generate(
        self, data: List[Dict[str, Any]], directory: str = ""
    ) -> None:
        # Check if directory exists, fallback to current directory if not
        final_directory = directory.rstrip("/") if os.path.exists(directory) else ""
        if directory and not final_directory:
            self.logger.error(f"[red]    [-] {directory} does not exist, fallback to current directory[/]")
        
        try:
            # Extract the GUI package
            shutil.unpack_archive(self.packageDir, self.tmpDir, "zip")
            
            # Generate data file
            self.logger.info(f"[+] Generating ZircoGui package to: {final_directory}/{self.outputFile}.zip")
            tmpl_config = TemplateConfig(
                template=[[self.templateFile]],
                template_output=[[self.tmpFile]],
                time_field=self.timeField
            )
            export_for_zircogui_tmpl = TemplateEngine(tmpl_config, logger=self.logger)
            export_for_zircogui_tmpl.generate_from_template(self.templateFile, self.tmpFile, data)
            
            # Move data file to package directory
            shutil.move(self.tmpFile, f'{self.tmpDir}/zircogui/data.js')
            
            # Create zip archive
            shutil.make_archive(self.outputFile, 'zip', f"{self.tmpDir}/zircogui")
            
            # Move to final destination if specified
            if final_directory:
                shutil.move(f"{self.outputFile}.zip", f"{final_directory}/{self.outputFile}.zip")
                
        except Exception as e:
            self.logger.error(f"[red]    [-] {e}[/]")
        finally:
            # Clean up temporary directory
            if os.path.exists(self.tmpDir):
                shutil.rmtree(self.tmpDir)
