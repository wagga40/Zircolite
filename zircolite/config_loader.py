#!python3
"""
YAML configuration file loader for Zircolite.

This module provides:
- YAML configuration file parsing
- Configuration validation
- Merging of file config with CLI arguments
- Default value handling
"""

import argparse
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
# Rich console for styled output


@dataclass
class InputConfig:
    """Configuration for input files and formats."""
    path: Optional[str] = None
    format: str = "evtx"  # evtx, json, json_array, xml, csv, sysmon_linux, auditd, evtxtract
    recursive: bool = True
    file_pattern: Optional[str] = None
    file_extension: Optional[str] = None
    select: Optional[List[str]] = None  # Include only files matching these strings
    avoid: Optional[List[str]] = None  # Exclude files matching these strings
    encoding: Optional[str] = None


@dataclass
class RulesConfig:
    """Configuration for rules and rulesets."""
    rulesets: List[str] = field(default_factory=lambda: ["rules/rules_windows_generic.json"])
    pipelines: Optional[List[str]] = None
    filters: Optional[List[str]] = None  # Rule title filters to exclude
    save_ruleset: bool = False


@dataclass
class OutputConfig:
    """Configuration for output files and formats."""
    file: str = "detected_events.json"
    format: str = "json"  # json, csv
    csv_delimiter: str = ";"
    template: Optional[str] = None
    template_output: Optional[str] = None
    templates: Optional[List[Dict[str, str]]] = None  # List of {template, output} pairs
    package: bool = False
    package_dir: str = ""
    keep_flat: bool = False
    db_file: Optional[str] = None
    log_file: str = "zircolite.log"
    no_output: bool = False


@dataclass
class ProcessingConfig:
    """Configuration for processing options."""
    unified_db: bool = False
    auto_mode: bool = True
    hashes: bool = False
    limit: int = -1
    time_field: str = "SystemTime"
    event_filter_enabled: bool = True  # Enable event filtering based on channel/eventID
    debug: bool = False
    remove_events: bool = False
    all_transforms: bool = False
    transform_categories: Optional[list] = None
    add_index: Optional[List[str]] = None
    remove_index: Optional[List[str]] = None
    strict_evtx: bool = False


@dataclass
class TimeFilterConfig:
    """Configuration for time-based event filtering."""
    after: str = "1970-01-01T00:00:00"
    before: str = "9999-12-12T23:59:59"


@dataclass
class ParallelProcessingConfig:
    """Configuration for parallel processing."""
    enabled: bool = False
    max_workers: Optional[int] = None  # None = auto-detect
    min_workers: int = 1
    memory_limit_percent: float = 85.0
    adaptive: bool = True


@dataclass
class ZircoliteConfig:
    """Complete Zircolite configuration."""
    input: InputConfig = field(default_factory=InputConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    processing: ProcessingConfig = field(default_factory=ProcessingConfig)
    time_filter: TimeFilterConfig = field(default_factory=TimeFilterConfig)
    parallel: ParallelProcessingConfig = field(default_factory=ParallelProcessingConfig)


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
        
        # Parse input section
        if 'input' in config_dict:
            inp = config_dict['input']
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
            rules = config_dict['rules']
            rulesets = rules.get('rulesets', ["rules/rules_windows_generic.json"])
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
            out = config_dict['output']
            templates = None
            if 'templates' in out:
                templates = out['templates']
            config.output = OutputConfig(
                file=out.get('file', 'detected_events.json'),
                format=out.get('format', 'json'),
                csv_delimiter=out.get('csv_delimiter', ';'),
                template=out.get('template'),
                template_output=out.get('template_output'),
                templates=templates,
                package=out.get('package', False),
                package_dir=out.get('package_dir', ''),
                keep_flat=out.get('keep_flat', False),
                db_file=out.get('db_file'),
                log_file=out.get('log_file', 'zircolite.log'),
                no_output=out.get('no_output', False)
            )
        
        # Parse processing section
        if 'processing' in config_dict:
            proc = config_dict['processing']
            config.processing = ProcessingConfig(
                unified_db=proc.get('unified_db', False),
                auto_mode=proc.get('auto_mode', True),
                hashes=proc.get('hashes', False),
                limit=proc.get('limit', -1),
                time_field=proc.get('time_field', 'SystemTime'),
                event_filter_enabled=proc.get('event_filter_enabled', True),
                debug=proc.get('debug', False),
                remove_events=proc.get('remove_events', False),
                all_transforms=proc.get('all_transforms', False),
                transform_categories=proc.get('transform_categories'),
                add_index=proc.get('add_index'),
                remove_index=proc.get('remove_index'),
                strict_evtx=proc.get('strict_evtx', False),
            )
        
        # Parse time_filter section
        if 'time_filter' in config_dict:
            tf = config_dict['time_filter']
            config.time_filter = TimeFilterConfig(
                after=tf.get('after', '1970-01-01T00:00:00'),
                before=tf.get('before', '9999-12-12T23:59:59')
            )
        
        # Parse parallel section
        if 'parallel' in config_dict:
            par = config_dict['parallel']
            config.parallel = ParallelProcessingConfig(
                enabled=par.get('enabled', False),
                max_workers=par.get('max_workers'),
                min_workers=par.get('min_workers', 1),
                memory_limit_percent=par.get('memory_limit_percent', 85.0),
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
        
        # Validate input
        if config.input.path:
            if isinstance(config.input.path, str) and not Path(config.input.path).exists():
                issues.append(f"Input path does not exist: {config.input.path}")
            elif isinstance(config.input.path, list):
                for p in config.input.path:
                    if not Path(p).exists():
                        issues.append(f"Input path does not exist: {p}")
        
        valid_formats = ['evtx', 'json', 'json_array', 'xml', 'csv', 'sysmon_linux', 'auditd', 'evtxtract']
        if config.input.format not in valid_formats:
            issues.append(f"Invalid input format: {config.input.format}. Must be one of: {valid_formats}")
        
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

    def merge_with_args(
        self, config: ZircoliteConfig, args: argparse.Namespace
    ) -> ZircoliteConfig:
        """
        Merge YAML config with CLI arguments. CLI arguments take precedence.
        
        Args:
            config: Base configuration from YAML
            args: argparse namespace with CLI arguments
            
        Returns:
            Merged configuration
        """
        # Input overrides
        if hasattr(args, 'evtx') and args.evtx:
            config.input.path = args.evtx
        
        if hasattr(args, 'json_input') and args.json_input:
            config.input.format = 'json'
        elif hasattr(args, 'json_array_input') and args.json_array_input:
            config.input.format = 'json_array'
        elif hasattr(args, 'xml_input') and args.xml_input:
            config.input.format = 'xml'
        elif hasattr(args, 'csv_input') and args.csv_input:
            config.input.format = 'csv'
        elif hasattr(args, 'sysmon_linux_input') and args.sysmon_linux_input:
            config.input.format = 'sysmon_linux'
        elif hasattr(args, 'auditd_input') and args.auditd_input:
            config.input.format = 'auditd'
        elif hasattr(args, 'evtxtract_input') and args.evtxtract_input:
            config.input.format = 'evtxtract'
        
        if hasattr(args, 'no_recursion') and args.no_recursion:
            config.input.recursive = False
        if hasattr(args, 'file_pattern') and args.file_pattern:
            config.input.file_pattern = args.file_pattern
        if hasattr(args, 'fileext') and args.fileext:
            config.input.file_extension = args.fileext
        if hasattr(args, 'select') and args.select:
            config.input.select = [s[0] for s in args.select]
        if hasattr(args, 'avoid') and args.avoid:
            config.input.avoid = [a[0] for a in args.avoid]
        if hasattr(args, 'logs_encoding') and args.logs_encoding:
            config.input.encoding = args.logs_encoding
        
        # Rules overrides
        if hasattr(args, 'ruleset') and args.ruleset:
            config.rules.rulesets = args.ruleset
        if hasattr(args, 'pipeline') and args.pipeline:
            config.rules.pipelines = [p for pl in args.pipeline for p in pl]
        if hasattr(args, 'rulefilter') and args.rulefilter:
            config.rules.filters = [f for fl in args.rulefilter for f in fl]
        if hasattr(args, 'save_ruleset') and args.save_ruleset:
            config.rules.save_ruleset = True
        
        # Output overrides
        if hasattr(args, 'outfile') and args.outfile != "detected_events.json":
            config.output.file = args.outfile
        if hasattr(args, 'csv') and args.csv:
            config.output.format = 'csv'
        if hasattr(args, 'csv_delimiter') and args.csv_delimiter != ';':
            config.output.csv_delimiter = args.csv_delimiter
        if hasattr(args, 'template') and args.template:
            # Convert template list format
            config.output.templates = []
            for i, tmpl in enumerate(args.template):
                if args.templateOutput and i < len(args.templateOutput) and args.templateOutput[i]:
                    output = args.templateOutput[i][0]
                else:
                    output = f"output_{i}.txt"
                config.output.templates.append({'template': tmpl[0], 'output': output})
        if hasattr(args, 'package') and args.package:
            config.output.package = True
        if hasattr(args, 'package_dir') and args.package_dir:
            config.output.package_dir = args.package_dir
        if hasattr(args, 'keepflat') and args.keepflat:
            config.output.keep_flat = True
        if hasattr(args, 'dbfile') and args.dbfile:
            config.output.db_file = args.dbfile
        if hasattr(args, 'logfile') and args.logfile != 'zircolite.log':
            config.output.log_file = args.logfile
        if hasattr(args, 'nolog') and args.nolog:
            config.output.no_output = True
        
        # Processing overrides
        if hasattr(args, 'unified_db') and args.unified_db:
            config.processing.unified_db = True
        if hasattr(args, 'no_auto_mode') and args.no_auto_mode:
            config.processing.auto_mode = False
        if hasattr(args, 'hashes') and args.hashes:
            config.processing.hashes = True
        if hasattr(args, 'limit') and args.limit != -1:
            config.processing.limit = args.limit
        if hasattr(args, 'timefield') and args.timefield != 'SystemTime':
            config.processing.time_field = args.timefield
        if hasattr(args, 'no_event_filter') and args.no_event_filter:
            config.processing.event_filter_enabled = False
        if hasattr(args, 'debug') and args.debug:
            config.processing.debug = True
        if hasattr(args, 'remove_events') and args.remove_events:
            config.processing.remove_events = True
        if hasattr(args, 'all_transforms') and args.all_transforms:
            config.processing.all_transforms = True
        if hasattr(args, 'transform_categories') and args.transform_categories:
            config.processing.transform_categories = args.transform_categories
        if getattr(args, 'add_index', None):
            config.processing.add_index = [x for group in args.add_index for x in group]
        if getattr(args, 'remove_index', None):
            config.processing.remove_index = [x for group in args.remove_index for x in group]
        if hasattr(args, 'strict') and args.strict:
            config.processing.strict_evtx = True

        # Time filter overrides
        if hasattr(args, 'after') and args.after != '1970-01-01T00:00:00':
            config.time_filter.after = args.after
        if hasattr(args, 'before') and args.before != '9999-12-12T23:59:59':
            config.time_filter.before = args.before
        
        # Parallel processing overrides
        if hasattr(args, 'parallel') and args.parallel:
            config.parallel.enabled = True
        if hasattr(args, 'parallel_workers') and args.parallel_workers:
            config.parallel.max_workers = args.parallel_workers
        
        return config


def create_default_config_file(output_path: str = "zircolite_config.yaml") -> None:
    """
    Create a default configuration file with all options documented.
    
    Args:
        output_path: Path to write the configuration file
    """
    default_config = """# Zircolite Configuration File
# All options can be overridden by command-line arguments

# Input configuration
input:
  # Path to log file or directory containing log files
  path: null  # Required: set this or use -e/--evtx CLI argument
  
  # Input format: evtx, json, json_array, xml, csv, sysmon_linux, auditd, evtxtract
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
