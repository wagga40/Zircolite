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
from pathlib import Path
from typing import Any

import yaml

from .assets import resolve_shipped_ruleset, resolve_shipped_template
from .formats import YAML_INPUT_FORMATS, is_valid_yaml_format

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
    path: str | None = None
    format: str = "evtx"  # see zircolite.formats.YAML_INPUT_FORMATS
    recursive: bool = True
    file_pattern: str | None = None
    file_extension: str | None = None
    select: list[str] | None = None  # Include only files matching these strings
    avoid: list[str] | None = None  # Exclude files matching these strings
    encoding: str | None = None


@dataclass
class RulesConfig:
    """Configuration for rules and rulesets."""
    # Empty on purpose: an absent `rules:` section must stay distinguishable
    # from an explicit choice, so that the CLI can still fall back to the
    # ruleset bundled with the install rather than a bare relative path.
    rulesets: list[str] = field(default_factory=list)
    pipelines: list[str] | None = None
    filters: list[str] | None = None  # Rule title filters to exclude
    save_ruleset: bool = False


@dataclass
class OutputConfig:
    """Configuration for output files and formats."""
    file: str = DEFAULT_OUTFILE
    format: str = "json"  # json, csv
    csv_delimiter: str = DEFAULT_CSV_DELIMITER
    templates: list[dict[str, str]] | None = None  # List of {template, output} pairs
    template_append: bool = False
    package: bool = False
    package_dir: str = DEFAULT_PACKAGE_DIR
    keep_flat: bool = False
    db_file: str | None = None
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
    transform_categories: list | None = None
    add_index: list[str] | None = None
    remove_index: list[str] | None = None
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
    max_workers: int | None = None  # None = auto-detect
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
    unknown_keys: list[str] = field(default_factory=list)


# Section name -> dataclass. Every accepted YAML key is a field of one of these,
# which is what makes unknown-key detection drift-proof: adding a field to a
# dataclass is the only way to add a key, so the two cannot disagree.
SECTIONS: dict[str, Any] = {
    'input': InputConfig,
    'rules': RulesConfig,
    'output': OutputConfig,
    'processing': YamlProcessingConfig,
    'time_filter': TimeFilterConfig,
    'parallel': ParallelProcessingConfig,
}


def unknown_yaml_keys(config_dict: dict[str, Any]) -> list[str]:
    """Dotted keys in *config_dict* that no configuration section defines.

    Many YAML names deliberately differ from their CLI flag (``--keepflat`` is
    ``keep_flat``, ``--nolog`` is ``no_output``), so a typo is easy to make and
    would otherwise do nothing at all.
    """
    unknown: list[str] = []
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

    def __init__(self, *, logger: logging.Logger | None = None):
        """
        Initialize ConfigLoader.

        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)

    def load_yaml(self, config_path: str) -> dict[str, Any]:
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

        with open(config_file, encoding='utf-8') as f:
            config_dict = yaml.safe_load(f)

        if config_dict is None:
            config_dict = {}

        self.logger.info(f"[cyan][+] Loaded configuration from: {config_path}[/]")
        return config_dict

    def parse_config(self, config_dict: dict[str, Any]) -> ZircoliteConfig:
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

    def validate_config(self, config: ZircoliteConfig) -> list[str]:
        """
        Validate configuration and return list of issues.

        Args:
            config: Configuration to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        issues = []

        for key in config.unknown_keys:
            issues.append(f"Unknown configuration key: {key}")

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

        # Validate rules. A configuration file is written once and run from
        # anywhere, so a relative rules/ or templates/ entry has to be tested
        # where the run will actually look for it, not only in the CWD.
        for ruleset in config.rules.rulesets:
            if not Path(resolve_shipped_ruleset(ruleset)).exists():
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
                elif not Path(resolve_shipped_template(tmpl['template'])).exists():
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


# One line of prose per format for the generated config file. A format with no
# entry is still listed, so a new one cannot silently go undescribed.
_FORMAT_NOTES: dict[str, str] = {
    "evtx": "Windows Event Log files (default)",
    "json": "JSON Lines (JSONL/NDJSON), one event per line",
    "json_array": "a single JSON array of events",
    "xml": "EVTX exported to XML",
    "csv": "CSV, with the delimiter sniffed from the first lines",
    "sysmon_linux": "Sysmon for Linux (syslog header plus XML)",
    "auditd": "Linux auditd logs",
    "evtxtract": "EVTXtract recovery output",
    "sqlite": "a database saved by a previous run (same as --db-input)",
}


def _format_comment_block() -> str:
    """Comment lines describing every registered input format."""
    width = max(len(name) for name in YAML_INPUT_FORMATS)
    return "\n".join(
        f"  #   {name.ljust(width)}  {_FORMAT_NOTES.get(name, '')}".rstrip()
        for name in YAML_INPUT_FORMATS
    )


def create_default_config_file(output_path: str = "zircolite_config.yaml") -> None:
    """
    Create a default configuration file with all options documented.

    Args:
        output_path: Path to write the configuration file
    """
    default_config = f"""# Zircolite Configuration File
# =============================
# Every supported key appears below at its default value.
#
#   Use with:  python3 zircolite.py --yaml-config my_config.yaml
#   Regenerate: python3 zircolite.py --generate-config my_config.yaml
#
# CLI arguments override this file, with three deliberate exceptions --
# transform_categories, add_index and remove_index are *added* to whatever this
# file lists rather than replacing it, because they name things to include
# rather than which things to use.
#
# This is a *run* configuration: which logs to read, which rules to apply and
# where to write. It is unrelated to -c/--config, which points at the field
# mappings and transforms configuration (config/config.yaml).

# Input configuration
input:
  # Path to log file or directory containing log files
  path: null  # Required: set this or use -e/--evtx CLI argument

  # Input format:
{_format_comment_block()}
  format: evtx

  # Search recursively in directories
  recursive: true

  # File glob pattern, applied instead of the format's default extension
  file_pattern: null  # Example: "Security*.evtx"

  # File extension filter, an alternative to file_pattern
  file_extension: null  # Example: evtx

  # Include only files whose *filename* contains one of these strings.
  # Matching is on the filename alone, not the directory path.
  select: null  # Example: ["Security", "Sysmon"]

  # Exclude files whose filename contains one of these strings, applied
  # after `select`.
  avoid: null  # Example: ["backup", "old"]

  # Encoding for the formats read as text (Sysmon for Linux, Auditd,
  # EVTXtract, CSV). null uses the per-format default. XML always uses the
  # encoding declared in the document, and JSON is always read as UTF-8.
  encoding: null  # Example: ISO-8859-1

# Rules and rulesets configuration
rules:
  # Ruleset files or directories. Accepts both the Zircolite JSON format and
  # directories of native Sigma YAML rules.
  rulesets:
    - rules/rules_windows_generic.json
    # - rules/rules_windows_sysmon.json
    # - /path/to/sigma/rules/windows/process_creation/

  # pySigma pipelines applied when converting native Sigma rules.
  # Run `--pipeline-list` to see what is installed.
  pipelines: null  # Example: ["sysmon", "windows-logsources"]

  # Drop rules whose title contains one of these strings (case sensitive)
  filters: null  # Example: ["Noisy Rule", "Test"]

  # Write the converted Sigma -> Zircolite ruleset to disk
  save_ruleset: false

# Output configuration
output:
  # Output file path. Left unset it is detected_events.json, or
  # detected_events.csv with format: csv. Naming a file here fixes it for both,
  # which is why it ships commented out.
  # file: detected_events.json

  # Output format: json, csv
  # CSV takes its header from every column of the events table, so a rule
  # returning wider rows than the ones before it does not lose fields.
  # CSV rejects more than one ruleset.
  format: json

  # Delimiter used when format is csv
  csv_delimiter: ";"

  # Jinja2 templates, as template/output pairs
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

  # Create the Mini-GUI package
  package: false
  package_dir: ""  # Where to write it; empty means the working directory

  # Also write the flattened events as JSONL. Only events Zircolite actually
  # processed are included, so events dropped by early event filtering or by
  # the time filter are absent; combine with event_filter_enabled: false to
  # capture everything.
  keep_flat: false

  # Keep the SQLite database, for debugging or to re-analyse with input
  # format `sqlite` later. Zircolite refuses to overwrite an existing file.
  db_file: null  # Example: events.db

  # Log file path
  log_file: zircolite.log

  # Write no log or result files at all
  no_output: false

# Processing configuration
processing:
  # One database for every file instead of one per file. Required for Sigma
  # correlation rules that need to see events across files, at the cost of
  # holding everything in memory at once.
  unified_db: false

  # Let Zircolite pick the processing mode from file count, file sizes,
  # available RAM and CPU count. Set false to force per-file mode.
  auto_mode: true

  # Add an xxhash64 of the original log line to every event
  hashes: false

  # Discard results from any rule matching more than this many events, which
  # keeps a single noisy rule from dominating the output. -1 disables it.
  limit: -1

  # Field holding the event timestamp. Left unset it is auto-detected from the
  # events, falling back to SystemTime. Naming one here pins it and turns that
  # detection off, which is why it ships commented out.
  # time_field: SystemTime

  # Skip events whose Channel/EventID cannot match any loaded rule, before
  # the expensive flattening step. Applies to Windows-shaped inputs only.
  event_filter_enabled: true

  # Enable debug logging
  debug: false

  # Delete the source log files after a successful run (use with caution!)
  remove_events: false

  # Run every transform defined in config/config.yaml, ignoring its
  # enabled_transforms list
  all_transforms: false

  # Enable transforms by category. Categories are defined in the
  # transform_categories section of config/config.yaml; `--transform-list`
  # prints them. Added to any passed with --transform-category.
  transform_categories: []  # Example: ["commandline", "process"]

  # Strict EVTX parsing: abort the run on a corrupted or malformed chunk.
  # When false (lenient), keeps as many events as can be recovered from a
  # damaged file and warns.
  strict_evtx: false

  # Database indexes. Zircolite always indexes `eventid`, and indexes
  # `Channel` when that column is present. Like transform_categories, these
  # are added to their CLI equivalents rather than replaced by them.
  add_index: []       # Extra columns to index, e.g. ["SystemTime", "Computer"]
  remove_index: []    # SQLite index names to drop after creation
  auto_index: 0       # >0 = also index the top-N columns that the most rules
                      # filter on (5 is a reasonable value). Ranked by rule
                      # count, not by how often a column appears.
                      # Never recreates an index listed in remove_index.

# Time-based event filtering
time_filter:
  # Process only events at or after this timestamp, inclusive (UTC)
  # Format: YYYY-MM-DDTHH:MM:SS
  after: "1970-01-01T00:00:00"

  # Process only events at or before this timestamp, inclusive (UTC)
  before: "9999-12-12T23:59:59"

# Parallel processing configuration
# Files are processed concurrently when that is likely to help. Zircolite
# enables it automatically unless:
#   - there is only one file
#   - less than 1 GB of RAM is available
#   - the estimated worker count comes out at 1
#   - the largest single file would need more than 60% of usable RAM
parallel:
  # Set false to disable automatic parallel processing entirely
  enabled: true

  # Maximum number of workers. null = auto-detect, which takes the smallest of:
  #   - memory:    (available RAM x 0.85) / estimated memory per file
  #   - CPU:       2x CPU cores, since the work is largely I/O bound
  #   - file count: at most 3x CPU cores, and never more than the file count
  # then applies a floor of half the CPU cores when memory is not the
  # constraint, and a hard ceiling of 32 to avoid context-switching overhead.
  max_workers: null

  # Never drop below this many workers
  min_workers: 1

  # System memory usage above which new file submissions are deferred
  memory_limit_percent: {DEFAULT_MEMORY_LIMIT_PERCENT}

  # Recalibrate the memory-per-file estimate from what the first completed
  # file actually used, instead of trusting the size-based heuristic alone.
  adaptive: true

# Memory per file is estimated from the average input size, since smaller
# files carry proportionally more per-event overhead:
#   < 10 MB  -> 5.0x    < 50 MB -> 4.0x    >= 50 MB -> 3.5x
# These multipliers are informational; they are not configurable.
"""

    target = Path(output_path)
    if target.exists():
        raise FileExistsError(
            f"Refusing to overwrite existing file: {output_path}"
        )

    with open(target, 'w', encoding='utf-8') as f:
        f.write(default_config)

    from .console import console
    console.print(f"[green]\\[✓][/] Created default configuration file: [cyan]{output_path}[/]")
