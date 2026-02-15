#!python3
"""
Configuration dataclasses for Zircolite.

This module provides typed configuration containers using dataclasses
for cleaner, more maintainable class initialization across the codebase.
"""

from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class ProcessingConfig:
    """
    Configuration for event processing operations.
    
    Used by ZircoliteCore and StreamingEventProcessor
    for shared processing parameters.
    """
    # Time filtering
    time_after: str = "1970-01-01T00:00:00"
    time_before: str = "9999-12-12T23:59:59"
    time_field: Optional[str] = None
    
    # Processing options
    hashes: bool = False
    disable_progress: bool = False
    
    # Database options
    db_location: str = ":memory:"
    batch_size: int = 5000
    
    # Output options
    no_output: bool = False
    csv_mode: bool = False
    delimiter: str = ";"
    limit: int = -1


@dataclass
class ExtractorConfig:
    """
    Configuration for log extraction operations.
    
    Used by EvtxExtractor for specifying input format and options.
    """
    # Input format flags (mutually exclusive in practice)
    xml_logs: bool = False
    sysmon4linux: bool = False
    auditd_logs: bool = False
    evtxtract: bool = False
    csv_input: bool = False
    
    # Processing options
    tmp_dir: Optional[str] = None
    encoding: Optional[str] = None
    
    def __post_init__(self):
        """Set default encoding based on input type if not specified."""
        if self.encoding is None:
            if self.sysmon4linux:
                self.encoding = "ISO-8859-1"
            elif self.auditd_logs or self.evtxtract or self.xml_logs:
                self.encoding = "utf-8"


@dataclass
class RulesetConfig:
    """
    Configuration for ruleset handling operations.
    
    Used by RulesetHandler for ruleset parsing and conversion.
    """
    ruleset: List[str] = field(default_factory=list)
    pipeline: Optional[List[List[str]]] = None
    save_ruleset: bool = False


@dataclass 
class TemplateConfig:
    """
    Configuration for template engine operations.
    
    Used by TemplateEngine and ZircoliteGuiGenerator.
    """
    template: List[List[str]] = field(default_factory=list)
    template_output: List[List[str]] = field(default_factory=list)
    time_field: str = ""


@dataclass
class GuiConfig:
    """
    Configuration for GUI generator.
    
    Used by ZircoliteGuiGenerator.
    """
    package_dir: str = ""
    template_file: str = ""
    time_field: str = ""
