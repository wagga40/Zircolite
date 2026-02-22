#!python3
"""
Zircolite - Standalone SIGMA-Based Detection Tool for EVTX, Auditd, Sysmon Linux, and more.

This is the main entry point for Zircolite. The core functionality has been modularized into
the zircolite/ package for better maintainability and code organization.

Package structure:
- zircolite/core.py: ZircoliteCore class for database and rule execution
- zircolite/streaming.py: StreamingEventProcessor for single-pass processing
- zircolite/extractor.py: EvtxExtractor for log format conversion
- zircolite/rules.py: RulesetHandler and RulesUpdater for rule management
- zircolite/templates.py: TemplateEngine and ZircoliteGuiGenerator for output
- zircolite/utils.py: Utility functions and MemoryTracker
"""

# Standard libs
import argparse
import logging
import os
import random
import string
import sys
import time
from pathlib import Path
from typing import List, Optional

# Force UTF-8 on Windows so argparse help and banner (Unicode/emojis) don't raise
# UnicodeEncodeError when the console uses cp1252 (see PYI-1448 / PYI-4560).
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        elif hasattr(sys.stdout, "buffer"):
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

# External libs - Rich for styled terminal output
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

# Rich argparse for colored --help output
try:
    from rich_argparse import RichHelpFormatter
    _HAS_RICH_ARGPARSE = True
except ImportError:
    _HAS_RICH_ARGPARSE = False

# Import from package
from zircolite import (
    RulesetHandler,
    RulesUpdater,
    TemplateEngine,
    ZircoliteGuiGenerator,
    MemoryTracker,
    init_logger,
    quit_on_error,
    check_if_exists,
    select_files,
    avoid_files,
    analyze_files_and_recommend_mode,
    print_mode_recommendation,
    # Config dataclasses
    RulesetConfig,
    TemplateConfig,
    GuiConfig,
    # Log type detection
    LogTypeDetector,
    DetectionResult,
    # YAML configuration
    ConfigLoader,
    create_default_config_file,
    # Rich console
    console,
    DetectionStats,
    LEVEL_PRIORITY,
    # UI/UX helpers
    set_quiet_mode,
    is_quiet,
    print_banner,
    print_section,
    print_error_panel,
    build_attack_summary,
    make_file_link,
)

# Processing modes and context (from the dedicated processing module)
from zircolite.processing import (
    ProcessingContext,
    create_extractor,
    process_unified_streaming,
    process_perfile_streaming,
    process_db_input,
    process_parallel_streaming,
)


################################################################
# NOTE: ProcessingContext and all process_* functions live in
# zircolite/processing.py – imported above.
################################################################


################################################################
# ARGUMENT PARSING
################################################################
def parse_arguments():
    """Parse command line arguments."""
    kwargs = {}
    if _HAS_RICH_ARGPARSE:
        kwargs["formatter_class"] = RichHelpFormatter
    parser = argparse.ArgumentParser(**kwargs)
    
    # Input files and filtering/selection options
    logs_input_args = parser.add_argument_group('📁 INPUT FILES AND FILTERING')
    logs_input_args.add_argument("-e", "--evtx", "--events", help="Path to log file or directory containing log files in supported format", type=str)
    logs_input_args.add_argument("-s", "--select", help="Process only files with filenames containing the specified string (applied before exclusions)", action='append', nargs='+')
    logs_input_args.add_argument("-a", "--avoid", help="Skip files with filenames containing the specified string", action='append', nargs='+')
    logs_input_args.add_argument("-f", "--fileext", help="File extension of the log files to process", type=str)    
    logs_input_args.add_argument("-fp", "--file-pattern", help="Python Glob pattern to select files (only works with directories)", type=str)
    logs_input_args.add_argument("--no-recursion", help="Search for log files only in the specified directory (disable recursive search)", action="store_true")

    # Events filtering options
    event_args = parser.add_argument_group('🔍 EVENTS FILTERING')
    event_args.add_argument("-A", "--after", help="Process only events after this timestamp (UTC format: 1970-01-01T00:00:00)", type=str, default="1970-01-01T00:00:00")
    event_args.add_argument("-B", "--before", help="Process only events before this timestamp (UTC format: 1970-01-01T00:00:00)", type=str, default="9999-12-12T23:59:59")
    event_args.add_argument("--no-event-filter", help="Disable early event filtering based on channel/eventID (process all events)", action='store_true')
    
    # Event and log formats options
    event_formats_args = parser.add_mutually_exclusive_group()
    event_formats_args.add_argument("-j", "--json-input", "--jsononly", "--jsonline", "--jsonl", help="Input logs are in JSON lines format", action='store_true')
    event_formats_args.add_argument("--json-array-input", "--jsonarray", "--json-array", help="Input logs are in JSON array format", action='store_true')
    event_formats_args.add_argument("--db-input", "-D", "--dbonly", help="Use a previously saved database file (time range filters will not work)", action='store_true')
    event_formats_args.add_argument("-S", "--sysmon-linux-input", "--sysmon4linux", "--sysmon-linux", help="Process Sysmon for Linux log files (default extension: '.log')", action='store_true')
    event_formats_args.add_argument("-AU", "--auditd-input", "--auditd", help="Process Auditd log files (default extension: '.log')", action='store_true')
    event_formats_args.add_argument("-x", "--xml-input", "--xml", help="Process EVTX files converted to XML format (default extension: '.xml')", action='store_true')
    event_formats_args.add_argument("--evtxtract-input", "--evtxtract", help="Process log files extracted with EVTXtract (default extension: '.log')", action='store_true')
    event_formats_args.add_argument("--csv-input", "--csvonly", help="Process log files in CSV format (extension: '.csv')", action='store_true')
    
    # Ruleset options
    rulesets_formats_args = parser.add_argument_group('📋 RULES AND RULESETS')  
    rulesets_formats_args.add_argument("-r", "--ruleset", help="Sigma ruleset in JSON (Zircolite format) or YAML/directory of YAML files (Native Sigma format)", action='append', nargs='+')
    rulesets_formats_args.add_argument("-cr", "--combine-rulesets", help="Merge all provided rulesets into one", action='store_true')
    rulesets_formats_args.add_argument("-sr", "--save-ruleset", help="Save converted ruleset (from Sigma to Zircolite format) to disk", action='store_true')
    rulesets_formats_args.add_argument("-p", "--pipeline", help="Use specified pipeline for native Sigma rulesets (YAML). Examples: 'sysmon', 'windows-logsources', 'windows-audit'. Use '--pipeline-list' to see available pipelines.", action='append', nargs='+')
    rulesets_formats_args.add_argument("-pl", "--pipeline-list", help="List all installed pysigma pipelines", action='store_true')
    rulesets_formats_args.add_argument("-R", "--rulefilter", help="Remove rules from ruleset by matching rule title (case sensitive)", action='append', nargs='*')
    
    # Output formats and output files options
    output_formats_args = parser.add_argument_group('💾 OUTPUT FORMATS AND FILES')
    output_formats_args.add_argument("-o", "--outfile", help="Output file for detected events", type=str, default="detected_events.json")
    output_formats_args.add_argument("--csv", "--csv-output", help="Output results in CSV format (empty fields will be included)", action='store_true')
    output_formats_args.add_argument("--csv-delimiter", help="Delimiter for CSV output", type=str, default=";")
    output_formats_args.add_argument("--keepflat", "--keep-flat", help="Save flattened events as JSON", action='store_true')
    output_formats_args.add_argument("-d", "--dbfile", "--db-file", help="Save all logs to a SQLite database file", type=str)
    output_formats_args.add_argument("-l", "--logfile", "--log-file", help="Log file name", default="zircolite.log", type=str)
    output_formats_args.add_argument("--hashes", help="Add xxhash64 of the original log event to each event", action='store_true')
    output_formats_args.add_argument("-L", "--limit", "--limit-results", help="Discard results exceeding this limit from output file", type=int, default=-1)
    
    # Advanced configuration options
    config_formats_args = parser.add_argument_group('⚙️  ADVANCED CONFIGURATION')  
    config_formats_args.add_argument("-c", "--config", help="JSON or YAML file containing field mappings and exclusions", type=str, default="config/config.yaml")
    config_formats_args.add_argument("-LE", "--logs-encoding", help="Specify encoding for Sysmon for Linux or Auditd files", type=str)
    config_formats_args.add_argument("-q", "--quiet", help="Quiet mode: suppress banner, progress, and info messages. Only the summary panel and errors are shown.", action='store_true')
    config_formats_args.add_argument("--debug", help="Enable debug logging", action='store_true')
    config_formats_args.add_argument("-n", "--nolog", "--no-log", help="Don't create log or result files", action='store_true')
    config_formats_args.add_argument("-RE", "--remove-events", help="Remove processed log files after successful analysis (use with caution)", action='store_true')
    config_formats_args.add_argument("-U", "--update-rules", help="Update rulesets in the 'rules' directory", action='store_true')
    config_formats_args.add_argument("-v", "--version", help="Display Zircolite version", action='store_true')
    config_formats_args.add_argument("--timefield", "--time-field", help="Specify time field name for time filtering (default: 'SystemTime', auto-detects if not found)", type=str, default="SystemTime")
    config_formats_args.add_argument("--unified-db", "--all-in-one", help="Force unified database mode (all files in one DB, enables cross-file correlation)", action='store_true')
    config_formats_args.add_argument("--no-auto-mode", help="Disable automatic processing mode selection based on file analysis", action='store_true')
    config_formats_args.add_argument("--no-auto-detect", help="Disable automatic log type and timestamp detection (use explicit format flags instead)", action='store_true')
    
    # Transform options
    transform_args = parser.add_argument_group('🔄 TRANSFORMS')
    transform_args.add_argument("--all-transforms", help="Enable all defined transforms (overrides enabled_transforms list)", action='store_true')
    transform_args.add_argument("--transform-category", help="Enable transforms by category name (can be repeated). Use '--transform-list' to see available categories.", action='append', dest='transform_categories')
    transform_args.add_argument("--transform-list", help="List available transform categories and their transforms, then exit", action='store_true')

    # YAML configuration file options
    yaml_config_args = parser.add_argument_group('📄 YAML CONFIGURATION FILE')
    yaml_config_args.add_argument("--yaml-config", "-Y", help="YAML configuration file (CLI arguments override file settings)", type=str)
    yaml_config_args.add_argument("--generate-config", help="Generate a default YAML configuration file and exit", type=str, metavar="OUTPUT_FILE")
    
    # Parallel processing options
    parallel_args = parser.add_argument_group('⚡ PARALLEL PROCESSING')
    parallel_args.add_argument("-P", "--no-parallel", help="Disable automatic parallel processing (parallel is enabled by default when beneficial)", action='store_true')
    parallel_args.add_argument("-w", "--parallel-workers", help="Maximum number of parallel workers (default: auto-detect based on CPU/memory)", type=int)
    parallel_args.add_argument("--parallel-memory-limit", help="Memory usage threshold percentage before throttling (default: 75)", type=float, default=75.0)
    
    # Templating and Mini GUI options
    templating_formats_args = parser.add_argument_group('🎨 TEMPLATING AND MINI GUI')
    templating_formats_args.add_argument("-t", "--template", help="Jinja2 template to use for output generation", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("-T", "--templateOutput", "--template-output", help="Output file for Jinja2 template results", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("--timesketch", help="Shortcut: use Timesketch template and write to timesketch-<RAND>.json", action='store_true')
    templating_formats_args.add_argument("-G", "--package", help="Create a ZircoGui/Mini GUI package", action='store_true')
    templating_formats_args.add_argument("--package-dir", help="Directory to save the ZircoGui/Mini GUI package", type=str, default="")
    
    return parser.parse_args()


################################################################
# FILE DISCOVERY AND INPUT TYPE DETECTION
################################################################
def get_file_extension(args) -> str:
    """Determine file extension based on input type."""
    if args.fileext:
        return args.fileext
    if args.json_input or args.json_array_input:
        return "json"
    if args.sysmon_linux_input or args.auditd_input:
        return "log"
    if args.xml_input:
        return "xml"
    if args.csv_input:
        return "csv"
    return "evtx"


def _has_explicit_format_flag(args) -> bool:
    """Check if the user has set an explicit format flag on the CLI."""
    return any([
        args.json_input, args.json_array_input, args.xml_input,
        args.sysmon_linux_input, args.auditd_input,
        args.csv_input, args.evtxtract_input, args.db_input,
    ])


def discover_files(args, logger) -> List[Path]:
    """Discover log files based on path and filters."""
    args.fileext = get_file_extension(args)
    
    log_path = Path(args.evtx)
    if log_path.is_dir():
        pattern = args.file_pattern if args.file_pattern else f"*.{args.fileext}"
        fn_glob = log_path.rglob if not args.no_recursion else log_path.glob
        log_list = list(fn_glob(pattern))
    elif log_path.is_file():
        log_list = [log_path]
    else:
        quit_on_error("[red]   [-] Unable to find events from submitted path[/]", logger)
    
    file_list = avoid_files(select_files(log_list, args.select), args.avoid)
    if not file_list:
        quit_on_error("[red]   [-] No file found. Please verify filters, directory or the extension with '--fileext' or '--file-pattern'[/]", logger)
    
    return file_list


def get_input_type(args) -> str:
    """Determine input type for streaming processor from explicit CLI flags."""
    if args.json_input:
        return 'json'
    if args.json_array_input:
        return 'json_array'
    if args.xml_input:
        return 'xml'
    if args.sysmon_linux_input:
        return 'sysmon_linux'
    if args.auditd_input:
        return 'auditd'
    if args.csv_input:
        return 'csv'
    if args.evtxtract_input:
        return 'evtxtract'
    return 'evtx'


def _apply_detection_result(args, detection: 'DetectionResult', logger) -> str:
    """
    Apply a DetectionResult to the args namespace and return the input_type.
    
    Sets the appropriate CLI flag on args so that downstream code
    (extractor creation, file extension logic, etc.) works correctly.
    When detection failed (log_source "unknown"), keeps default evtx and does
    not set any format flag.
    """
    if detection.log_source == "unknown":
        return "evtx"

    input_type = detection.input_type

    # Map input_type back to the args flag
    flag_map = {
        'json': 'json_input',
        'json_array': 'json_array_input',
        'xml': 'xml_input',
        'sysmon_linux': 'sysmon_linux_input',
        'auditd': 'auditd_input',
        'csv': 'csv_input',
        'evtxtract': 'evtxtract_input',
    }
    
    if input_type in flag_map:
        setattr(args, flag_map[input_type], True)
    
    # Update timefield if detection found a timestamp and user didn't override
    if detection.timestamp_field and args.timefield == "SystemTime":
        args.timefield = detection.timestamp_field
    
    return input_type


def auto_detect_log_type(
    file_list: List[Path], args, logger,
    field_mappings_config: Optional[dict] = None,
) -> str:
    """
    Automatically detect log type from the provided files.
    
    Analyzes file content and structure to determine the log format.
    If an explicit format flag was set by the user, this is skipped.
    
    Args:
        file_list: List of discovered log files
        args: Parsed CLI arguments
        logger: Logger instance
        field_mappings_config: Optional field mappings config (for timestamp detection fields)
        
    Returns:
        The detected input_type string
    """
    # If user set an explicit format flag, respect it
    if _has_explicit_format_flag(args):
        input_type = get_input_type(args)
        logger.debug(f"Using explicit format flag: {input_type}")
        return input_type
    
    # If auto-detect is disabled, fall back to flag-based detection
    if getattr(args, 'no_auto_detect', False):
        input_type = get_input_type(args)
        logger.debug(f"Auto-detect disabled, using default: {input_type}")
        return input_type
    
    # Load timestamp detection fields from config if available
    ts_fields = None
    if field_mappings_config:
        ts_config = field_mappings_config.get("timestamp_detection", {})
        ts_fields = ts_config.get("detection_fields")
    
    detector = LogTypeDetector(logger=logger, timestamp_detection_fields=ts_fields)
    
    # Use batch detection for better accuracy
    detection = detector.detect_batch(file_list)
    
    logger.info(
        f"[+] Auto-detected log type: "
        f"[cyan]{detection.log_source}[/] "
        f"([yellow]{detection.input_type}[/]) "
        f"- confidence: [{'green' if detection.confidence == 'high' else 'yellow' if detection.confidence == 'medium' else 'red'}]"
        f"{detection.confidence}[/]"
    )
    if detection.details:
        logger.debug(f"    Detection details: {detection.details}")
    if detection.timestamp_field:
        logger.info(f"[+] Auto-detected timestamp field: [cyan]{detection.timestamp_field}[/]")
    if detection.suggested_pipeline:
        logger.debug(f"    Suggested pipeline: {detection.suggested_pipeline}")
    
    if detection.confidence == "low":
        logger.warning(
            "[yellow]   [!] Low confidence detection. "
            "Consider using explicit format flags (-j, -x, -S, -AU, etc.)[/]"
        )
    
    # Apply detection result to args
    input_type = _apply_detection_result(args, detection, logger)
    
    # If detection changed the format from default, update the file extension
    # for directory scanning (re-discover files if needed)
    return input_type


################################################################
# YAML CONFIGURATION – split into per-section helpers
################################################################
def _apply_yaml_input_config(yaml_config, args):
    """Apply YAML input section to CLI args."""
    if yaml_config.input.path and not args.evtx:
        args.evtx = yaml_config.input.path

    if not any([args.json_input, args.json_array_input, args.xml_input,
                args.csv_input, args.sysmon_linux_input, args.auditd_input, args.evtxtract_input]):
        format_map = {
            'json': 'json_input', 'json_array': 'json_array_input',
            'xml': 'xml_input', 'csv': 'csv_input',
            'sysmon_linux': 'sysmon_linux_input', 'auditd': 'auditd_input',
            'evtxtract': 'evtxtract_input',
        }
        if yaml_config.input.format in format_map:
            setattr(args, format_map[yaml_config.input.format], True)

    if yaml_config.input.recursive is False:
        args.no_recursion = True
    if yaml_config.input.file_pattern:
        args.file_pattern = args.file_pattern or yaml_config.input.file_pattern
    if yaml_config.input.file_extension:
        args.fileext = args.fileext or yaml_config.input.file_extension
    if yaml_config.input.encoding:
        args.logs_encoding = args.logs_encoding or yaml_config.input.encoding


def _apply_yaml_rules_config(yaml_config, args):
    """Apply YAML rules section to CLI args."""
    if not args.ruleset or args.ruleset == ["rules/rules_windows_generic.json"]:
        args.ruleset = yaml_config.rules.rulesets
    if yaml_config.rules.pipelines and not args.pipeline:
        args.pipeline = [[p] for p in yaml_config.rules.pipelines]
    if yaml_config.rules.filters and not args.rulefilter:
        args.rulefilter = [[f] for f in yaml_config.rules.filters]
    if yaml_config.rules.save_ruleset:
        args.save_ruleset = True


def _apply_yaml_output_config(yaml_config, args):
    """Apply YAML output section to CLI args."""
    if args.outfile == "detected_events.json":
        args.outfile = yaml_config.output.file
    if yaml_config.output.format == 'csv':
        args.csv = True
    if yaml_config.output.csv_delimiter != ';':
        args.csv_delimiter = yaml_config.output.csv_delimiter
    if yaml_config.output.templates and not args.template:
        args.template = [[t['template']] for t in yaml_config.output.templates]
        args.templateOutput = [[t['output']] for t in yaml_config.output.templates]
    if yaml_config.output.package:
        args.package = True
    if yaml_config.output.package_dir:
        args.package_dir = yaml_config.output.package_dir
    if yaml_config.output.keep_flat:
        args.keepflat = True
    if yaml_config.output.db_file:
        args.dbfile = yaml_config.output.db_file
    if yaml_config.output.log_file != 'zircolite.log':
        args.logfile = yaml_config.output.log_file
    if yaml_config.output.no_output:
        args.nolog = True


def _apply_yaml_processing_config(yaml_config, args):
    """Apply YAML processing + time-filter + parallel sections to CLI args."""
    # Processing
    if yaml_config.processing.unified_db:
        args.unified_db = True
    if not yaml_config.processing.auto_mode:
        args.no_auto_mode = True
    if yaml_config.processing.hashes:
        args.hashes = True
    if yaml_config.processing.limit != -1:
        args.limit = yaml_config.processing.limit
    if yaml_config.processing.time_field != 'SystemTime':
        args.timefield = yaml_config.processing.time_field
    if yaml_config.processing.debug:
        args.debug = True
    if yaml_config.processing.remove_events:
        args.remove_events = True
    if yaml_config.processing.all_transforms:
        args.all_transforms = True
    if yaml_config.processing.transform_categories:
        # Merge with any CLI-provided categories
        existing = getattr(args, 'transform_categories', None) or []
        args.transform_categories = existing + yaml_config.processing.transform_categories
    # Time filters
    if yaml_config.time_filter.after != '1970-01-01T00:00:00':
        args.after = yaml_config.time_filter.after
    if yaml_config.time_filter.before != '9999-12-12T23:59:59':
        args.before = yaml_config.time_filter.before

    # Parallel
    if yaml_config.parallel.enabled is False:
        args.no_parallel = True
    if yaml_config.parallel.max_workers:
        args.parallel_workers = yaml_config.parallel.max_workers
    if yaml_config.parallel.memory_limit_percent != 75.0:
        args.parallel_memory_limit = yaml_config.parallel.memory_limit_percent


def _print_transform_categories(config_path: str, logger):
    """Print available transform categories and their transforms, then exit."""
    from zircolite.utils import load_field_mappings
    try:
        config = load_field_mappings(config_path, logger=logger)
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"[red]   [-] {e}[/]")
        return

    categories = config.get("transform_categories", {})
    if not categories:
        logger.info("[yellow]   [!] No transform categories defined in config.[/]")
        return

    table = Table(title="Transform Categories", show_lines=True)
    table.add_column("Category", style="cyan", min_width=15)
    table.add_column("Transforms", style="white")
    table.add_column("Count", style="green", justify="right")

    for cat_name, cat_transforms in sorted(categories.items()):
        table.add_row(cat_name, ", ".join(cat_transforms), str(len(cat_transforms)))

    console.print(table)


def load_yaml_config_and_merge(args, logger) -> argparse.Namespace:
    """Load YAML config file and merge with CLI arguments."""
    if not args.yaml_config:
        return args

    try:
        config_loader = ConfigLoader(logger=logger)
        yaml_config = config_loader.load(args.yaml_config)

        issues = config_loader.validate_config(yaml_config)
        if issues:
            for issue in issues:
                logger.warning(f"[yellow]   [!] Config warning: {issue}[/]")

        yaml_config = config_loader.merge_with_args(yaml_config, args)

        _apply_yaml_input_config(yaml_config, args)
        _apply_yaml_rules_config(yaml_config, args)
        _apply_yaml_output_config(yaml_config, args)
        _apply_yaml_processing_config(yaml_config, args)

        logger.info(f"[+] Configuration loaded and merged from: [cyan]{args.yaml_config}[/]")

    except FileNotFoundError as e:
        logger.error(f"[red]   [-] {e}[/]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"[red]   [-] Error loading YAML config: {e}[/]")
        if logger.isEnabledFor(logging.DEBUG):
            console.print_exception(show_locals=False)
        sys.exit(1)

    return args


################################################################
# POST-PROCESSING
################################################################
def handle_templating(ctx: ProcessingContext, results: list, args):
    """Handle template generation and package creation."""
    if ctx.ready_for_templating and results:
        tmpl_config = TemplateConfig(
            template=args.template,
            template_output=args.templateOutput,
            time_field=ctx.time_field
        )
        template_generator = TemplateEngine(tmpl_config, logger=ctx.logger)
        template_generator.run(results)
    
    if ctx.package and results:
        template_path = Path("templates/exportForZircoGui.tmpl")
        gui_zip_path = Path("gui/zircogui.zip")
        if template_path.is_file() and gui_zip_path.is_file():
            gui_config = GuiConfig(
                package_dir=str(gui_zip_path),
                template_file=str(template_path),
                time_field=ctx.time_field
            )
            packager = ZircoliteGuiGenerator(gui_config, logger=ctx.logger)
            packager.generate(results, args.package_dir)


def cleanup(args, logger, log_list=None):
    """Clean up temporary files and optionally remove original events."""
    if args.remove_events and log_list:
        logger.info("[+] Cleaning")
        for evtx in log_list:
            try:
                os.remove(evtx)
            except OSError as e:
                logger.error(f"[red]   [-] Cannot remove file {e}[/]")


def print_stats(memory_tracker: MemoryTracker, start_time: float, logger, 
                all_results: list = None, files_processed: int = 0, 
                total_events: int = 0, workers_used: int = 1,
                filtered_events: int = 0, total_rules: int = 0,
                phase_times: dict = None, has_template: bool = False,
                has_package: bool = False, outfile: str = None):
    """Print final execution statistics with a Rich summary dashboard."""
    memory_tracker.sample()
    peak_memory, avg_memory = memory_tracker.get_stats()
    processing_time = time.time() - start_time
    
    # Build summary table
    summary_table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    summary_table.add_column("Metric", style="dim", width=16)
    summary_table.add_column("Value", style="bold", ratio=1)
    
    # ── Duration with phase breakdown ──
    if processing_time >= 60:
        time_str = f"{int(processing_time // 60)}m {int(processing_time % 60)}s"
    else:
        time_str = f"{processing_time:.1f}s"
    summary_table.add_row("⏱  Duration", f"[yellow]{time_str}[/]")
    
    # Phase timing breakdown
    if phase_times and processing_time > 0:
        bar_width = 16
        for phase_name, phase_secs in phase_times.items():
            if phase_secs <= 0:
                continue
            pct = phase_secs / processing_time
            filled = max(1, int(bar_width * pct))
            bar = "\u2588" * filled + "\u2591" * (bar_width - filled)
            if phase_secs >= 60:
                t_str = f"{int(phase_secs // 60)}m {int(phase_secs % 60)}s"
            else:
                t_str = f"{phase_secs:.1f}s"
            summary_table.add_row("", f"  [dim]\u251c\u2500 {phase_name}  {bar}  {t_str} ({pct:.0%})[/]")
    
    # ── Files ──
    if files_processed > 0:
        summary_table.add_row("📁 Files", f"[cyan]{files_processed:,}[/]")
    
    # ── Events with filter efficiency (#5) ──
    if total_events > 0:
        events_text = f"[magenta]{total_events:,}[/]"
        if filtered_events > 0:
            total_scanned = total_events + filtered_events
            match_rate = (total_events / total_scanned * 100) if total_scanned > 0 else 0
            events_text += f" [dim]({filtered_events:,} filtered out — {match_rate:.1f}% match rate)[/]"
        summary_table.add_row("📊 Events", events_text)
    
    # ── Throughput ──
    if processing_time > 0 and total_events > 0:
        throughput = total_events / processing_time
        summary_table.add_row("⚡ Throughput", f"[green]{throughput:,.0f}[/] events/s")
    
    # Workers (if parallel)
    if workers_used > 1:
        summary_table.add_row("👥 Workers", f"[yellow]{workers_used}[/]")
    
    # Memory
    if peak_memory > 0:
        mem_str = memory_tracker.format_memory(peak_memory)
        summary_table.add_row("💾 Peak Memory", f"[cyan]{mem_str}[/]")
    
    # ── Detection summary ──
    if all_results:
        det_stats = DetectionStats()
        for result in all_results:
            level = result.get("rule_level", "unknown")
            count = result.get("count", 0)
            det_stats.add_detection(level, count)
        
        detection_parts = []
        if det_stats.critical > 0:
            detection_parts.append(f"[bold red]{det_stats.critical} CRIT[/]")
        if det_stats.high > 0:
            detection_parts.append(f"[bold magenta]{det_stats.high} HIGH[/]")
        if det_stats.medium > 0:
            detection_parts.append(f"[bold yellow]{det_stats.medium} MED[/]")
        if det_stats.low > 0:
            detection_parts.append(f"[green]{det_stats.low} LOW[/]")
        if det_stats.informational > 0:
            detection_parts.append(f"[dim]{det_stats.informational} INFO[/]")
        
        if detection_parts:
            summary_table.add_row("🎯 Detections", " │ ".join(detection_parts))
        else:
            summary_table.add_row("🎯 Detections", "[dim]None[/]")
        
        # Rule coverage bar
        if total_rules > 0:
            matched_rules = det_stats.total_rules_matched
            coverage_pct = matched_rules / total_rules * 100
            bar_w = 16
            filled = max(0, int(bar_w * matched_rules / total_rules))
            cov_bar = "\u2588" * filled + "\u2591" * (bar_w - filled)
            summary_table.add_row(
                "\U0001f4cf Coverage",
                f"[cyan]{matched_rules}[/]/[cyan]{total_rules}[/] rules matched ({coverage_pct:.1f}%)  [dim]{cov_bar}[/]"
            )
        
        # Total matched events
        if det_stats.total_events > 0:
            summary_table.add_row(
                "🔍 Matched", 
                f"[magenta]{det_stats.total_events:,}[/] events across [cyan]{det_stats.total_rules_matched}[/] rules"
            )
        
        # Top-N detections by severity (most critical first)
        sorted_results = sorted(
            all_results,
            key=lambda r: (LEVEL_PRIORITY.get(r.get("rule_level", "unknown").lower(), 5), -r.get("count", 0))
        )
        top_n = sorted_results[:5]
        if top_n:
            _level_abbrev = {
                "critical": "CRIT", "high": "HIGH", "medium": " MED",
                "low": " LOW", "informational": "INFO",
            }
            _level_style = {
                "critical": "bold white on red", "high": "bold white on magenta",
                "medium": "bold black on yellow", "low": "bold white on green",
                "informational": "white on bright_black",
            }
            top_lines = []
            for r in top_n:
                level = r.get("rule_level", "unknown")
                style = _level_style.get(level.lower(), "cyan")
                title = r.get("title", "Unknown")
                count = r.get("count", 0)
                abbrev = _level_abbrev.get(level.lower(), level.upper()[:4])
                if len(title) > 50:
                    title = title[:47] + "..."
                top_lines.append(f"[{style}]{abbrev}[/] {title} [dim]({count:,})[/]")
            summary_table.add_row("\U0001f4cb Top Hits", top_lines[0])
            for line in top_lines[1:]:
                summary_table.add_row("", line)
    else:
        summary_table.add_row("\U0001f3af Detections", "[dim]None[/]")
    
    # Section separator before summary
    print_section("Results")
    
    # Print summary panel
    console.print()
    panel = Panel(
        summary_table,
        title="[bold]\u2728 Summary[/]",
        border_style="cyan",
        padding=(1, 2),
        expand=True,
    )

    console.print(panel)

    # ATT&CK Coverage panel - always full width, stacked below summary
    if all_results:
        attack_panel = build_attack_summary(all_results)
        if attack_panel:
            console.print(attack_panel)
    
    # Output file location - prominent and always visible
    if outfile:
        console.print()
        console.print(f"  [bold green]\u2192[/] Output: {make_file_link(outfile)}")

################################################################
# PROCESSING DISPATCH
################################################################
def _run_processing(ctx, args, logger, memory_tracker):
    """Run the main processing pipeline and return all state needed by main().

    Returns:
        (zircolite_core, all_results, extractor, use_streaming, log_list, phase_setup_end)
    """
    zircolite_core = None
    extractor = None
    log_list = None
    all_results = []

    # Load field mappings config early (needed for auto-detection)
    field_mappings_config = None
    if not args.db_input:
        from zircolite.utils import load_field_mappings
        try:
            field_mappings_config = load_field_mappings(args.config, logger=logger)
        except Exception:
            field_mappings_config = None

    phase_setup_end = time.time()

    # ----- DB input mode -----
    if args.db_input:
        zircolite_core, all_results = process_db_input(ctx, args)
        return zircolite_core, all_results, extractor, log_list, phase_setup_end

    # ----- File input mode -----
    check_if_exists(
        args.config,
        "[red]   [-] Cannot find mapping file, you can get the default one here : "
        "https://github.com/wagga40/Zircolite/blob/master/config/config.yaml [/]",
        logger,
    )

    file_list = discover_files(args, logger)
    log_list = file_list

    # Auto-detect log type
    if not is_quiet() and not _has_explicit_format_flag(args) and not getattr(args, 'no_auto_detect', False):
        with console.status("[bold cyan]Auto-detecting log type...", spinner="dots"):
            input_type = auto_detect_log_type(file_list, args, logger, field_mappings_config)
    else:
        input_type = auto_detect_log_type(file_list, args, logger, field_mappings_config)

    # Re-discover files if auto-detection changed the extension
    if Path(args.evtx).is_dir() and not args.fileext and not args.file_pattern:
        new_ext = get_file_extension(args)
        if new_ext != "evtx":
            args.fileext = new_ext
            old_count = len(file_list)
            file_list = discover_files(args, logger)
            log_list = file_list
            if len(file_list) != old_count:
                logger.info(
                    f"[+] Re-discovered [yellow]{len(file_list)}[/] file(s) "
                    f"with extension '.{new_ext}'"
                )

    ctx.time_field = args.timefield

    # Auto-select processing mode
    use_parallel = False
    parallel_workers = 1

    if not args.no_auto_mode and not args.unified_db:
        recommended_mode, reason, stats = analyze_files_and_recommend_mode(file_list, logger)
        print_mode_recommendation(recommended_mode, reason, stats, logger, show_parallel=True)
        if recommended_mode == 'unified':
            args.unified_db = True
        if not args.unified_db and not getattr(args, 'no_parallel', False):
            if stats.get('parallel_recommended', False):
                use_parallel = True
                parallel_workers = stats.get('parallel_workers', 1)
    elif args.unified_db:
        logger.info("[+] [cyan]Database mode:[/] [green]UNIFIED[/] (forced)")
        logger.info("")
    else:
        if not getattr(args, 'no_parallel', False) and len(file_list) > 1:
            _, _, stats = analyze_files_and_recommend_mode(file_list, logger)
            if stats.get('parallel_recommended', False):
                use_parallel = True
                parallel_workers = stats.get('parallel_workers', 1)

    # Streaming processing (single-pass pipeline)
    extractor = create_extractor(args, logger, input_type)

    if use_parallel and not args.unified_db and len(file_list) > 1:
        zircolite_core, all_results = process_parallel_streaming(
            ctx, file_list, input_type, extractor, args, parallel_workers
        )
    elif args.unified_db:
        zircolite_core, all_results = process_unified_streaming(
            ctx, file_list, input_type, extractor, args
        )
    else:
        zircolite_core, all_results = process_perfile_streaming(
            ctx, file_list, input_type, extractor, args
        )

    return zircolite_core, all_results, extractor, log_list, phase_setup_end


################################################################
# MAIN
################################################################
def main():
    version = "3.2.0"
    args = parse_arguments()

    # Handle generate-config before logging setup
    if args.generate_config:
        create_default_config_file(args.generate_config)
        sys.exit(0)

    # Set up quiet mode before any output
    if args.quiet:
        set_quiet_mode(True)

    # Init logging
    if args.nolog: 
        args.logfile = None
    logger = init_logger(args.debug, args.logfile)

    # In quiet mode, suppress INFO-level console output (file handler keeps everything)
    if args.quiet:
        for handler in logger.handlers:
            if isinstance(handler, RichHandler):
                handler.setLevel(logging.WARNING)

    # Print Rich banner (single source of truth from console module)
    print_banner(version)

    # Handle special commands
    if args.version: 
        logger.info(f"Zircolite - v{version}")
        sys.exit(0)

    if args.update_rules:
        logger.info("[+] Updating rules")
        RulesUpdater(logger=logger).run()
        sys.exit(0)

    if args.transform_list:
        _print_transform_categories(args.config, logger)
        sys.exit(0)
    
    # Load YAML configuration if provided
    if args.yaml_config:
        args = load_yaml_config_and_merge(args, logger)

    # Apply --timesketch shortcut
    if getattr(args, 'timesketch', False):
        rand_4 = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))
        out_name = f"timesketch-{rand_4}.json"
        if args.template is None:
            args.template = []
            args.templateOutput = []
        args.template.append(["templates/exportForTimesketch.tmpl"])
        args.templateOutput.append([out_name])

    # Handle rulesets
    if args.ruleset:
        args.ruleset = [item for sublist in args.ruleset for item in sublist]
    else: 
        args.ruleset = ["rules/rules_windows_generic.json"]

    # Load rulesets (with spinner for visual feedback during pySigma conversion)
    logger.info("[+] Loading ruleset(s)")
    ruleset_config = RulesetConfig(
        ruleset=args.ruleset,
        pipeline=args.pipeline,
        save_ruleset=args.save_ruleset
    )
    if not is_quiet():
        with console.status("[bold cyan]Loading and converting rulesets...", spinner="dots"):
            rulesets_manager = RulesetHandler(ruleset_config, logger=logger, list_pipelines_only=args.pipeline_list)
    else:
        rulesets_manager = RulesetHandler(ruleset_config, logger=logger, list_pipelines_only=args.pipeline_list)
    if args.pipeline_list:
        sys.exit(0)

    # Validate required arguments
    if not args.evtx:
        print_error_panel(
            "Missing Input",
            "No events source path provided.",
            "Use '-e <PATH TO LOGS>' or '--events <PATH TO LOGS>'"
        )
        sys.exit(2)
    if args.csv and len(args.ruleset) > 1:
        print_error_panel(
            "Invalid Configuration",
            "CSV output is not supported with multiple rulesets.",
            "Fields in results can change between rulesets. Use a single ruleset with --csv."
        )
        sys.exit(2)
    
    logger.info("[+] Checking prerequisites")

    # Parse timestamps
    try:
        events_after = time.strptime(args.after, '%Y-%m-%dT%H:%M:%S')
        events_before = time.strptime(args.before, '%Y-%m-%dT%H:%M:%S')
    except Exception:
        quit_on_error("[red]   [-] Wrong timestamp format. Please use 'YYYY-MM-DDTHH:MM:SS'", logger)

    # Check templates
    ready_for_templating = False
    if args.template is not None:
        if args.csv: 
            quit_on_error("[red]   [-] You cannot use templates in CSV mode[/]", logger)
        if args.templateOutput is None or len(args.template) != len(args.templateOutput):
            quit_on_error("[red]   [-] Number of templates output must match number of templates[/]", logger)
        for template in args.template:
            check_if_exists(template[0], f"[red]   [-] Cannot find template: {template[0]}. Default templates are available here: https://github.com/wagga40/Zircolite/tree/master/templates[/]", logger)
        ready_for_templating = True
    
    # CSV mode adjustments
    if args.csv: 
        ready_for_templating = False
        if args.outfile == "detected_events.json": 
            args.outfile = "detected_events.csv"

    # Flatten rule filters
    if args.rulefilter: 
        args.rulefilter = [item for sublist in args.rulefilter for item in sublist]

    # Section separator before processing
    print_section("Processing")

    # Start timing and memory tracking
    start_time = time.time()
    memory_tracker = MemoryTracker(logger=logger)
    memory_tracker.sample()

    # Handle event filter configuration
    active_event_filter = None
    if not getattr(args, 'no_event_filter', False):
        active_event_filter = rulesets_manager.event_filter
    else:
        logger.info("[+] Event filtering disabled (--no-event-filter)")
    
    # Create processing context
    ctx = ProcessingContext(
        config=args.config,
        logger=logger,
        no_output=args.nolog, 
        events_after=events_after,
        events_before=events_before,
        limit=args.limit, 
        csv_mode=args.csv, 
        time_field=args.timefield, 
        hashes=args.hashes, 
        db_location=":memory:",
        delimiter=args.csv_delimiter,
        rulesets=rulesets_manager.rulesets,
        rule_filters=args.rulefilter,
        outfile=args.outfile,
        ready_for_templating=ready_for_templating,
        package=args.package,
        dbfile=args.dbfile,
        keepflat=args.keepflat,
        memory_tracker=memory_tracker,
        event_filter=active_event_filter
    )

    # Run processing and collect results
    zircolite_core, all_results, extractor, log_list, phase_setup_end = (
        _run_processing(ctx, args, logger, memory_tracker)
    )

    # Handle templating and package generation
    handle_templating(ctx, all_results, args)

    # Cleanup
    cleanup(args, logger, log_list)
    if extractor is not None:
        try:
            extractor.cleanup()
        except Exception as e:
            logger.debug(f"Extractor cleanup: {e}")

    # Close database connection
    if zircolite_core is not None:
        zircolite_core.close()
    
    # Build phase timing breakdown
    now = time.time()
    phase_times = None
    if phase_setup_end is not None:
        setup_time = phase_setup_end - start_time
        processing_time = now - phase_setup_end
        if setup_time > 0.5 or processing_time > 0.5:
            phase_times = {}
            if setup_time > 0.5:
                phase_times["Setup"] = setup_time
            if processing_time > 0.5:
                phase_times["Processing"] = processing_time
    
    # Print final stats with summary dashboard (always shown, even in quiet mode)
    files_processed = len(log_list) if log_list else 1
    print_stats(
        memory_tracker, 
        start_time, 
        logger,
        all_results=all_results,
        files_processed=files_processed,
        total_events=ctx.total_events,
        workers_used=ctx.workers_used,
        filtered_events=ctx.total_filtered_events,
        total_rules=len(ctx.rulesets) if ctx.rulesets else 0,
        phase_times=phase_times,
        has_template=ctx.ready_for_templating,
        has_package=ctx.package,
        outfile=ctx.outfile if not ctx.no_output else None,
    )


if __name__ == "__main__":
    main()
