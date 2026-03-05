#!python3
"""
Template engine and GUI generator for Zircolite.

This module contains:
- TemplateEngine: Jinja2 template rendering for output generation
- ZircoliteGuiGenerator: Mini GUI package generator
"""

import logging
import os
import re
import shutil
from typing import Any, Dict, List, Optional

from jinja2 import Environment

from .config import TemplateConfig, GuiConfig
from .utils import random_suffix


def _extract_attack_techniques(tags: list) -> list:
    """Extract ATT&CK technique IDs from Sigma tags.

    Converts tags like ``'attack.t1059.001'`` to ``'T1059.001'``.
    Duplicate IDs are removed while preserving order.
    """
    _TECH_RE = re.compile(r'^attack\.(t\d{4}(?:\.\d{3})?)', re.IGNORECASE)
    seen: dict = {}
    for tag in (tags or []):
        m = _TECH_RE.match(tag)
        if m:
            tid = m.group(1).upper()
            seen[tid] = None  # dict preserves insertion order (Python 3.7+)
    return list(seen)


def _collect_navigator_techniques(data: list) -> list:
    """Build a deduplicated ATT&CK Navigator technique list from detection results.

    For each unique technique ID found across all detections, the entry carries
    the maximum event count and the highest severity level seen.
    """
    _LEVEL_ORDER = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    _LEVEL_COLOR = {
        'critical': '#ff0000',
        'high': '#ff6600',
        'medium': '#ffcc00',
        'low': '#66ff66',
        'informational': '#aaffaa',
    }

    merged: dict = {}  # tid -> {score, level, comment}
    for elem in data:
        for tid in _extract_attack_techniques(elem.get('tags', [])):
            lvl = elem.get('rule_level', 'informational').lower()
            cnt = elem.get('count', 0)
            title = elem.get('title', '')
            if tid not in merged:
                merged[tid] = {'score': cnt, 'level': lvl, 'comment': title}
            else:
                existing = merged[tid]
                # Accumulate score; keep highest severity level
                existing['score'] += cnt
                if _LEVEL_ORDER.get(lvl, 0) > _LEVEL_ORDER.get(existing['level'], 0):
                    existing['level'] = lvl
                    existing['comment'] = title

    entries = []
    for tid, info in merged.items():
        entries.append({
            'techniqueID': tid,
            'score': info['score'],
            'color': _LEVEL_COLOR.get(info['level'], '#aaaaaa'),
            'comment': f"{info['comment']} ({info['level']})",
        })
    return entries


def _make_jinja2_env() -> Environment:
    """Create a Jinja2 Environment with Zircolite-specific filters."""
    env = Environment()
    env.filters['extract_attack_techniques'] = _extract_attack_techniques
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
