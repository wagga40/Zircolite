#!python3
"""
Template engine and GUI generator for Zircolite.

This module contains:
- TemplateEngine: Jinja2 template rendering for output generation
- ZircoliteGuiGenerator: Mini GUI package generator
"""

import logging
import os
import random
import shutil
import string
from typing import Optional

# Rich console for styled output  
from jinja2 import Template

from .config import TemplateConfig, GuiConfig


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
    
    def generate_from_template(self, template_file, output_filename, data):
        """Use Jinja2 to output data in a specific format."""
        try:
            with open(template_file, 'r', encoding='utf-8') as tmpl:
                template = Template(tmpl.read())
            
            with open(output_filename, 'a', encoding='utf-8') as tpl:
                tpl.write(template.render(data=data, timeField=self.time_field))
        except Exception as e:
            self.logger.error("[red]   [-] Template error, activate debug mode to check for errors[/]")
            self.logger.debug(f"   [-] {e}")

    def run(self, data):
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
        self.tmpDir = f'tmp-zircogui-{self._randString()}'
        self.tmpFile = f'data-{self._randString()}.js'
        self.outputFile = f'zircogui-output-{self._randString()}'
        self.packageDir = cfg.package_dir
        self.timeField = cfg.time_field

    def _randString(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))

    def generate(self, data, directory=""):
        # Check if directory exists, fallback to current directory if not
        final_directory = directory.rstrip("/") if os.path.exists(directory) else ""
        if directory and not final_directory:
            self.logger.error(f"[red]   [-] {directory} does not exist, fallback to current directory[/]")
        
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
            self.logger.error(f"[red]   [-] {e}[/]")
        finally:
            # Clean up temporary directory
            if os.path.exists(self.tmpDir):
                shutil.rmtree(self.tmpDir)
