#!python3
"""
YAML configuration file loader for Zircolite.

This module provides:
- YAML configuration file parsing
- Configuration validation
- Merging of file config with CLI arguments
- Default value handling
"""

import logging
from dataclasses import dataclass, field, fields

from .formats import YAML_INPUT_FORMATS, is_valid_yaml_format
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Defaults shared by the dataclasses below and by the CLI. argparse declares
# these options with `default=None` so that "the user passed the default
# explicitly" stays distinguishable from "the user passed nothing"; the value
# is filled in here instead, at the end of the resolution chain.
DEFAULT_OUTFILE = "detected_events.json"
DEFAULT_CSV_DELIMITER = ";"
DEFAULT_LOG_FILE = "zircolite.log"
DEFAULT_LIMIT = -1
DEFAULT_TIME_FIELD = "SystemTime"
DEFAULT_AFTER = "1970-01-01T00:00:00"
DEFAULT_BEFORE = "9999-12-12T23:59:59"
DEFAULT_MEMORY_LIMIT_PERCENT = 85.0
DEFAULT_PACKAGE_DIR = ""


@dataclass
class InputConfig:
    """Configuration for input files and formats."""
    path: Optional[str] = None
    format: str = "evtx"  # see zircolite.formats.YAML_INPUT_FORMATS
    recursive: bool = True
    file_pattern: Optional[str] = None
    file_extension: Optional[str] = None
    select: Optional[List[str]] = None  # Include only files matching these strings
    avoid: Optional[List[str]] = None  # Exclude files matching these strings
    encoding: Optional[str] = None


@dataclass
class RulesConfig:
    """Configuration for rules and rulesets."""
    # Empty on purpose: an absent `rules:` section must stay distinguishable
    # from an explicit choice, so that the CLI can still fall back to the
    # ruleset bundled with the install rather than a bare relative path.
    rulesets: List[str] = field(default_factory=list)
    pipelines: Optional[List[str]] = None
    filters: Optional[List[str]] = None  # Rule title filters to exclude
    save_ruleset: bool = False


@dataclass
class OutputConfig:
    """Configuration for output files and formats."""
    file: str = DEFAULT_OUTFILE
    format: str = "json"  # json, csv
    csv_delimiter: str = DEFAULT_CSV_DELIMITER
    templates: Optional[List[Dict[str, str]]] = None  # List of {template, output} pairs
    template_append: bool = False
    package: bool = False
    package_dir: str = DEFAULT_PACKAGE_DIR
    keep_flat: bool = False
    db_file: Optional[str] = None
    log_file: str = DEFAULT_LOG_FILE
    no_output: bool = False


@dataclass
class YamlProcessingConfig:
    """Configuration for processing options."""
    unified_db: bool = False
    auto_mode: bool = True
    hashes: bool = False
    limit: int = DEFAULT_LIMIT
    time_field: str = DEFAULT_TIME_FIELD
    event_filter_enabled: bool = True  # Enable event filtering based on channel/eventID
    debug: bool = False
    remove_events: bool = False
    all_transforms: bool = False
    transform_categories: Optional[list] = None
    add_index: Optional[List[str]] = None
    remove_index: Optional[List[str]] = None
    auto_index: int = 0
    strict_evtx: bool = False


@dataclass
class TimeFilterConfig:
    """Configuration for time-based event filtering."""
    after: str = DEFAULT_AFTER
    before: str = DEFAULT_BEFORE


@dataclass
class ParallelProcessingConfig:
    """Configuration for parallel processing."""
    enabled: bool = True  # parallel auto-mode is on unless explicitly disabled
    max_workers: Optional[int] = None  # None = auto-detect
    min_workers: int = 1
    memory_limit_percent: float = DEFAULT_MEMORY_LIMIT_PERCENT
    adaptive: bool = True


@dataclass
class ZircoliteConfig:
    """Complete Zircolite configuration."""
    input: InputConfig = field(default_factory=InputConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    processing: YamlProcessingConfig = field(default_factory=YamlProcessingConfig)
    time_filter: TimeFilterConfig = field(default_factory=TimeFilterConfig)
    parallel: ParallelProcessingConfig = field(default_factory=ParallelProcessingConfig)
    # Dotted keys found in the YAML file that no section recognises. Reported
    # by validate_config so a typo does not silently do nothing.
    unknown_keys: List[str] = field(default_factory=list)


# Section name -> dataclass. Every accepted YAML key is a field of one of these,
# which is what makes unknown-key detection drift-proof: adding a field to a
# dataclass is the only way to add a key, so the two cannot disagree.
SECTIONS: Dict[str, Any] = {
    'input': InputConfig,
    'rules': RulesConfig,
    'output': OutputConfig,
    'processing': YamlProcessingConfig,
    'time_filter': TimeFilterConfig,
    'parallel': ParallelProcessingConfig,
}


def unknown_yaml_keys(config_dict: Dict[str, Any]) -> List[str]:
    """Dotted keys in *config_dict* that no configuration section defines.

    Many YAML names deliberately differ from their CLI flag (``--keepflat`` is
    ``keep_flat``, ``--nolog`` is ``no_output``), so a typo is easy to make and
    would otherwise do nothing at all.
    """
    unknown: List[str] = []
    for name, value in (config_dict or {}).items():
        if name not in SECTIONS:
            unknown.append(name)
            continue
        known = {f.name for f in fields(SECTIONS[name])}
        for key in (value or {}):
            if key not in known:
                unknown.append(f"{name}.{key}")
    return unknown


class ConfigLoader:
    """
    Load and validate Zircolite configuration from YAML files.
    
    Supports:
    - Full YAML configuration files
    - Merging with CLI arguments (CLI takes precedence)
    - Default value handling
    - Configuration validation
    """

    def __init__(self, *, logger: Optional[logging.Logger] = None):
        """
        Initialize ConfigLoader.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)

    def load_yaml(self, config_path: str) -> Dict[str, Any]:
        """
        Load YAML configuration file.
        
        Args:
            config_path: Path to YAML configuration file
            
        Returns:
            Dictionary with configuration values
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If YAML is invalid
        """
        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_file, 'r', encoding='utf-8') as f:
            config_dict = yaml.safe_load(f)
        
        if config_dict is None:
            config_dict = {}
        
        self.logger.info(f"[cyan][+] Loaded configuration from: {config_path}[/]")
        return config_dict

    def parse_config(self, config_dict: Dict[str, Any]) -> ZircoliteConfig:
        """
        Parse configuration dictionary into ZircoliteConfig dataclass.
        
        Args:
            config_dict: Raw configuration dictionary
            
        Returns:
            ZircoliteConfig instance
        """
        config = ZircoliteConfig()
        config.unknown_keys = unknown_yaml_keys(config_dict)

        # A present-but-empty section (`processing:` with nothing under it) parses
        # as None, so every section is read through `or {}`.

        # Parse input section
        if 'input' in config_dict:
            inp = config_dict['input'] or {}
            config.input = InputConfig(
                path=inp.get('path'),
                format=inp.get('format', 'evtx'),
                recursive=inp.get('recursive', True),
                file_pattern=inp.get('file_pattern'),
                file_extension=inp.get('file_extension'),
                select=inp.get('select'),
                avoid=inp.get('avoid'),
                encoding=inp.get('encoding')
            )
        
        # Parse rules section
        if 'rules' in config_dict:
            rules = config_dict['rules'] or {}
            # dict.get returns None when the key is present-but-null (rulesets:)
            rulesets = rules.get('rulesets') or []
            if isinstance(rulesets, str):
                rulesets = [rulesets]
            config.rules = RulesConfig(
                rulesets=rulesets,
                pipelines=rules.get('pipelines'),
                filters=rules.get('filters'),
                save_ruleset=rules.get('save_ruleset', False)
            )
        
        # Parse output section
        if 'output' in config_dict:
            out = config_dict['output'] or {}
            templates = out.get('templates')
            config.output = OutputConfig(
                file=out.get('file', DEFAULT_OUTFILE),
                format=out.get('format', 'json'),
                csv_delimiter=out.get('csv_delimiter', DEFAULT_CSV_DELIMITER),
                templates=templates,
                template_append=out.get('template_append', False),
                package=out.get('package', False),
                package_dir=out.get('package_dir', ''),
                keep_flat=out.get('keep_flat', False),
                db_file=out.get('db_file'),
                log_file=out.get('log_file', DEFAULT_LOG_FILE),
                no_output=out.get('no_output', False)
            )

        # Parse processing section
        if 'processing' in config_dict:
            proc = config_dict['processing'] or {}
            config.processing = YamlProcessingConfig(
                unified_db=proc.get('unified_db', False),
                auto_mode=proc.get('auto_mode', True),
                hashes=proc.get('hashes', False),
                limit=proc.get('limit', DEFAULT_LIMIT),
                time_field=proc.get('time_field', DEFAULT_TIME_FIELD),
                event_filter_enabled=proc.get('event_filter_enabled', True),
                debug=proc.get('debug', False),
                remove_events=proc.get('remove_events', False),
                all_transforms=proc.get('all_transforms', False),
                transform_categories=proc.get('transform_categories'),
                add_index=proc.get('add_index'),
                remove_index=proc.get('remove_index'),
                auto_index=int(proc.get('auto_index', 0) or 0),
                strict_evtx=proc.get('strict_evtx', False),
            )
        
        # Parse time_filter section
        if 'time_filter' in config_dict:
            tf = config_dict['time_filter'] or {}
            config.time_filter = TimeFilterConfig(
                after=tf.get('after', DEFAULT_AFTER),
                before=tf.get('before', DEFAULT_BEFORE)
            )

        # Parse parallel section
        if 'parallel' in config_dict:
            par = config_dict['parallel'] or {}
            config.parallel = ParallelProcessingConfig(
                enabled=par.get('enabled', True),
                max_workers=par.get('max_workers'),
                min_workers=par.get('min_workers', 1),
                memory_limit_percent=par.get(
                    'memory_limit_percent', DEFAULT_MEMORY_LIMIT_PERCENT
                ),
                adaptive=par.get('adaptive', True)
            )

        return config

    def load(self, config_path: str) -> ZircoliteConfig:
        """
        Load and parse YAML configuration file.
        
        Args:
            config_path: Path to YAML configuration file
            
        Returns:
            ZircoliteConfig instance
        """
        config_dict = self.load_yaml(config_path)
        return self.parse_config(config_dict)

    def validate_config(self, config: ZircoliteConfig) -> List[str]:
        """
        Validate configuration and return list of issues.
        
        Args:
            config: Configuration to validate
            
        Returns:
            List of validation error messages (empty if valid)
        """
        issues = []

        for key in config.unknown_keys:
            issues.append(f"Unknown configuration key (ignored): {key}")

        # Validate input
        if isinstance(config.input.path, list):
            issues.append("input.path must be a single path string, not a list")
        elif config.input.path and not Path(config.input.path).exists():
            issues.append(f"Input path does not exist: {config.input.path}")
        
        if not is_valid_yaml_format(config.input.format):
            issues.append(
                f"Invalid input format: {config.input.format}. "
                f"Must be one of: {sorted(YAML_INPUT_FORMATS)}"
            )
        
        # Validate rules
        for ruleset in config.rules.rulesets:
            if not Path(ruleset).exists():
                issues.append(f"Ruleset not found: {ruleset}")
        
        # Validate output
        if config.output.format not in ['json', 'csv']:
            issues.append(f"Invalid output format: {config.output.format}. Must be 'json' or 'csv'")
        
        if config.output.format == 'csv' and len(config.rules.rulesets) > 1:
            issues.append("CSV output is not supported with multiple rulesets")
        
        # Validate templates
        if config.output.templates:
            for tmpl in config.output.templates:
                if 'template' not in tmpl or 'output' not in tmpl:
                    issues.append("Template entries must have 'template' and 'output' keys")
                elif not Path(tmpl['template']).exists():
                    issues.append(f"Template file not found: {tmpl['template']}")
        
        # Validate time filters
        import time
        try:
            time.strptime(config.time_filter.after, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            issues.append(f"Invalid 'after' timestamp format: {config.time_filter.after}")
        
        try:
            time.strptime(config.time_filter.before, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            issues.append(f"Invalid 'before' timestamp format: {config.time_filter.before}")
        
        # Validate parallel config
        if config.parallel.enabled:
            if config.parallel.min_workers < 1:
                issues.append("min_workers must be at least 1")
            if config.parallel.max_workers is not None and config.parallel.max_workers < 1:
                issues.append("max_workers must be at least 1")
            if not (0 < config.parallel.memory_limit_percent <= 100):
                issues.append("memory_limit_percent must be between 0 and 100")
        
        return issues

def create_default_config_file(output_path: str = "zircolite_config.yaml") -> None:
    """
    Create a default configuration file with all options documented.
    
    Args:
        output_path: Path to write the configuration file
    """
    default_config = f"""# Zircolite Configuration File
# All options can be overridden by command-line arguments

# Input configuration
input:
  # Path to log file or directory containing log files
  path: null  # Required: set this or use -e/--evtx CLI argument
  
  # Input format: {", ".join(YAML_INPUT_FORMATS)}
  format: evtx
  
  # Search recursively in directories
  recursive: true
  
  # File glob pattern (e.g., "*.evtx", "Security*.evtx")
  file_pattern: null
  
  # File extension filter
  file_extension: null
  
  # Include only files containing these strings in filename
  select: null  # Example: ["Security", "Sysmon"]
  
  # Exclude files containing these strings in filename
  avoid: null  # Example: ["backup", "old"]
  
  # File encoding (for Sysmon Linux/Auditd)
  encoding: null

# Rules and rulesets configuration
rules:
  # List of ruleset files or directories
  rulesets:
    - rules/rules_windows_generic.json
  
  # pySigma pipelines for native Sigma rules
  pipelines: null  # Example: ["sysmon", "windows-logsources"]
  
  # Rule title filters (exclude rules matching these strings)
  filters: null  # Example: ["Noisy Rule", "Test"]
  
  # Save converted ruleset to disk
  save_ruleset: false

# Output configuration
output:
  # Output file path
  file: detected_events.json
  
  # Output format: json, csv
  format: json
  
  # CSV delimiter
  csv_delimiter: ";"
  
  # Jinja2 templates (list of template/output pairs)
  templates: null
  # Example:
  # templates:
  #   - template: templates/exportForSplunk.tmpl
  #     output: splunk_events.json
  #   - template: templates/exportForELK.tmpl
  #     output: elk_events.json

  # Append to template output files instead of overwriting them on each run.
  # Useful for accumulating results across multiple runs (e.g. cumulative
  # NDJSON exports). Not all templates produce append-safe output: single-
  # document JSON exports (such as the ATT&CK Navigator layer) become
  # invalid when concatenated.
  template_append: false
  
  # Create Mini-GUI package
  package: false
  package_dir: ""
  
  # Save flattened JSON events
  keep_flat: false
  
  # Save SQLite database to file
  db_file: null
  
  # Log file path
  log_file: zircolite.log
  
  # Disable output files
  no_output: false

# Processing configuration
processing:
  # Use unified database for all files (enables cross-file correlation)
  unified_db: false
  
  # Automatic mode selection based on file analysis
  auto_mode: true
  
  # Add xxhash of original log lines
  hashes: false
  
  # Limit results per rule (-1 = no limit)
  limit: -1
  
  # Time field for event timestamps (auto-detects if not found)
  time_field: SystemTime
  
  # Enable early event filtering based on channel/eventID from rules
  # This improves performance by skipping events that won't match any rules
  event_filter_enabled: true
  
  # Enable debug logging
  debug: false
  
  # Remove log files after processing (use with caution!)
  remove_events: false

  # Enable all transforms (overrides enabled_transforms list)
  # all_transforms: false

  # Enable transforms by category (see config/config.yaml for category definitions)
  # transform_categories:
  #   - commandline
  #   - process

  # Strict EVTX parsing: stop on corrupted or malformed chunks (default: false)
  # When false (lenient), recovers as many events as possible from damaged files
  strict_evtx: false

  # Database indexes — Zircolite always indexes `eventid` and indexes `Channel`
  # automatically when the column is present.
  # add_index: ["SystemTime", "Computer"]   # extra columns to index
  # remove_index: ["idx_channel"]           # SQLite index names to drop after creation
  # auto_index: 0                            # >0 = auto-index the top-N columns
                                              # referenced by the loaded ruleset
                                              # (5 is a reasonable default)

# Time-based event filtering
time_filter:
  # Process events after this timestamp (UTC)
  after: "1970-01-01T00:00:00"
  
  # Process events before this timestamp (UTC)
  before: "9999-12-12T23:59:59"

# Parallel processing configuration
# Parallel is enabled by default when beneficial (multiple files, sufficient memory)
parallel:
  # Set to false to disable automatic parallel processing
  enabled: true
  
  # Maximum number of workers (null = auto-detect based on CPU/memory)
  max_workers: null
  
  # Minimum number of workers
  min_workers: 1
  
  # Memory usage threshold to trigger throttling (percent)
  memory_limit_percent: 85.0
  
  # Dynamically adjust workers based on memory usage
  adaptive: true
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(default_config)
    
    from .console import console
    console.print(f"[green]\\[✓][/] Created default configuration file: [cyan]{output_path}[/]")
