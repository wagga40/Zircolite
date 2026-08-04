"""
Command-line interface for Zircolite.

Argument parsing, file discovery, log type detection and run orchestration.
The processing modes themselves live in ``zircolite/processing.py``; this
module wires them to the flags. ``zircolite.py`` at the repository root is a
shim that calls :func:`main`, as is ``python -m zircolite``.
"""

# Standard libs
import argparse
import logging
import os
import random
import re
import string
import sys
import time
from pathlib import Path
from typing import Any

# External libs - Rich for styled terminal output
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

# Rich argparse for colored --help output
try:
    from rich_argparse import RichHelpFormatter
    _HAS_RICH_ARGPARSE = True
except ImportError:
    RichHelpFormatter = None  # type: ignore[assignment,misc]
    _HAS_RICH_ARGPARSE = False

# Import from package
from zircolite import (
    LEVEL_PRIORITY,
    # YAML configuration
    ConfigLoader,
    DetectionResult,
    DetectionStats,
    GuiConfig,
    # Log type detection
    LogTypeDetector,
    MemoryTracker,
    # Config dataclasses
    RulesetConfig,
    RulesetHandler,
    RulesUpdater,
    StrictParseError,
    TemplateConfig,
    TemplateEngine,
    ZircoliteGuiGenerator,
    __version__,
    analyze_files_and_recommend_mode,
    avoid_files,
    build_attack_summary,
    check_if_exists,
    # Rich console
    console,
    create_default_config_file,
    format_by_name,
    format_from_args,
    has_explicit_format,
    init_logger,
    is_quiet,
    make_file_link,
    print_banner,
    print_error_panel,
    print_mode_recommendation,
    print_section,
    quit_on_error,
    run_config,
    select_files,
    # UI/UX helpers
    set_quiet_mode,
)

# Bundled asset resolution
from zircolite.assets import (
    bundled_asset,
    resolve_default_path,
    resolve_shipped_ruleset,
    resolve_shipped_template,
)

# Input format registry
from zircolite.formats import DEFAULT_EXTENSION

# Processing modes and context (from the dedicated processing module)
from zircolite.processing import (
    ProcessingContext,
    create_extractor,
    expand_db_path,
    process_db_input,
    process_parallel_streaming,
    process_perfile_streaming,
    process_unified_streaming,
)
from zircolite.run_config import DEFAULTS, EARLY_DESTS, flatten_groups
from zircolite.shutdown import (
    install_signal_handler,
    is_shutdown_requested,
    request_shutdown,
)

################################################################
# NOTE: ProcessingContext and all process_* functions live in
# zircolite/processing.py – imported above.
################################################################


################################################################
# ARGUMENT PARSING
################################################################
def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    if _HAS_RICH_ARGPARSE:
        parser = argparse.ArgumentParser(formatter_class=RichHelpFormatter)
    else:
        parser = argparse.ArgumentParser()

    # Input files and filtering/selection options
    logs_input_args = parser.add_argument_group('📁 INPUT FILES AND FILTERING')
    logs_input_args.add_argument("-e", "--evtx", "--events", help="Path to log file or directory containing log files in supported format", type=str)
    logs_input_args.add_argument("-s", "--select", help="Process only files with filenames containing the specified string (applied before exclusions)", action='append', nargs='+')
    logs_input_args.add_argument("-a", "--avoid", help="Skip files with filenames containing the specified string", action='append', nargs='+')
    logs_input_args.add_argument("-f", "--fileext", help="File extension of the log files to process", type=str)
    logs_input_args.add_argument("-fp", "--file-pattern", help="Python Glob pattern to select files (only works with directories)", type=str)
    logs_input_args.add_argument("--no-recursion", help="Search for log files only in the specified directory (disable recursive search)", action="store_true")
    logs_input_args.add_argument("--archive-password", help="Password for encrypted ZIP or 7-Zip archives", type=str, metavar="PASSWORD")

    # Events filtering options
    event_args = parser.add_argument_group('🔍 EVENTS FILTERING')
    event_args.add_argument("-A", "--after", help=f"Process only events at or after this timestamp, inclusive (UTC format: 1970-01-01T00:00:00, default: {DEFAULTS['after']})", type=str, default=None)
    event_args.add_argument("-B", "--before", help=f"Process only events at or before this timestamp, inclusive (UTC format: 1970-01-01T00:00:00, default: {DEFAULTS['before']})", type=str, default=None)
    event_args.add_argument("--no-event-filter", help="Disable early event filtering based on channel/eventID (process all events)", action='store_true')

    # Attached to a titled group rather than the parser root, so the format
    # flags appear under their own heading in --help alongside every other
    # group instead of above them under a bare "Options:".
    event_formats_args = parser.add_argument_group(
        '📥 INPUT FORMATS'
    ).add_mutually_exclusive_group()
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
    rulesets_formats_args.add_argument("-sr", "--save-ruleset", help="Save converted ruleset (from Sigma to Zircolite format) to disk", action='store_true')
    rulesets_formats_args.add_argument("-p", "--pipeline", help="Use specified pipeline for native Sigma rulesets (YAML). Examples: 'sysmon', 'windows-logsources', 'windows-audit'. Use '--pipeline-list' to see available pipelines.", action='append', nargs='+')
    rulesets_formats_args.add_argument("-pl", "--pipeline-list", help="List all installed pysigma pipelines", action='store_true')
    rulesets_formats_args.add_argument("-R", "--rulefilter", help="Remove rules from ruleset by matching rule title (case sensitive)", action='append', nargs='*')
    rulesets_formats_args.add_argument("--test-rules", help="JSON file with rule test cases (true-positive / true-negative events per rule)", type=str, metavar="TEST_FILE")

    # Output formats and output files options
    output_formats_args = parser.add_argument_group('💾 OUTPUT FORMATS AND FILES')
    output_formats_args.add_argument("-o", "--outfile", help="Output file for detected events (default: detected_events.json, or detected_events.csv with --csv)", type=str, default=None)
    output_formats_args.add_argument(
        "--csv",
        "--csv-output",
        help=(
            "Output results in CSV format (empty fields included). "
            "The header covers every column of the events table, so a rule returning "
            "wider rows than the ones before it does not lose fields. Rejects more "
            "than one ruleset."
        ),
        action="store_true",
    )
    output_formats_args.add_argument("--csv-delimiter", help=f"Delimiter for CSV output (default: '{DEFAULTS['csv_delimiter']}')", type=str, default=None)
    output_formats_args.add_argument("--keepflat", "--keep-flat", help="Save the flattened events as JSONL to flattened_events_<RAND>.json", action='store_true')
    output_formats_args.add_argument("--profile-rules", help="Time each rule execution and print a performance report at the end", action='store_true')
    output_formats_args.add_argument("-d", "--dbfile", "--db-file", help="Save all logs to a SQLite database file", type=str)
    output_formats_args.add_argument("-l", "--logfile", "--log-file", help=f"Log file name (default: {DEFAULTS['logfile']})", default=None, type=str)
    output_formats_args.add_argument("--hashes", help="Add xxhash64 of the original log event to each event", action='store_true')
    output_formats_args.add_argument("-L", "--limit", "--limit-results", help=f"Discard rules matching more events than this, per input database — so per file in the default mode, and across the whole corpus with --unified-db (default: {DEFAULTS['limit']}, i.e. no limit)", type=int, default=None)

    # Advanced configuration options
    config_formats_args = parser.add_argument_group('⚙️  ADVANCED CONFIGURATION')
    config_formats_args.add_argument("-c", "--config", help="JSON or YAML file containing field mappings and exclusions", type=str, default="config/config.yaml")
    config_formats_args.add_argument("-LE", "--logs-encoding", help="Encoding of the source files, for the formats read as text: Sysmon for Linux, Auditd, EVTXtract and CSV (XML uses the encoding declared in the document, JSON is read as UTF-8)", type=str)
    config_formats_args.add_argument("-q", "--quiet", help="Quiet mode: suppress banner, progress, and info messages. Only the summary panel and errors are shown.", action='store_true')
    config_formats_args.add_argument("--debug", help="Enable debug logging", action='store_true')
    config_formats_args.add_argument("-n", "--nolog", "--no-log", help="Don't create the log file or the detections output file (files requested explicitly with --template, --dbfile, --keepflat or --package are still written)", action='store_true')
    config_formats_args.add_argument("-RE", "--remove-events", help="Remove input log files that were read successfully; files that failed to parse are kept (use with caution)", action='store_true')
    config_formats_args.add_argument("-U", "--update-rules", help="Update rulesets in the 'rules' directory", action='store_true')
    config_formats_args.add_argument("-v", "--version", help="Display Zircolite version", action='store_true')
    config_formats_args.add_argument("--timefield", "--time-field", help="Specify time field name for time filtering (default: 'SystemTime', auto-detects if not found)", type=str, default=None)
    config_formats_args.add_argument("--unified-db", "--all-in-one", help="Force unified database mode (all files in one DB, enables cross-file correlation)", action='store_true')
    config_formats_args.add_argument("--no-auto-mode", help="Disable automatic processing mode selection based on file analysis", action='store_true')
    config_formats_args.add_argument("--no-auto-detect", help="Disable automatic log type and timestamp detection (use explicit format flags instead)", action='store_true')
    config_formats_args.add_argument("--strict", help="Strict EVTX parsing: stop on corrupted or malformed chunks instead of skipping them. Forces sequential processing (default: lenient, recovers as many events as possible)", action='store_true')
    config_formats_args.add_argument("--add-index", help="Create an index on the given column(s). Can be repeated or list multiple columns (e.g. --add-index Channel EventID).", action='append', nargs='+', metavar="COL", default=None)
    config_formats_args.add_argument("--remove-index", help="Drop the given index name(s) after creation. Can be repeated or list multiple (e.g. --remove-index idx_channel idx_eventid).", action='append', nargs='+', metavar="IDX", default=None)
    config_formats_args.add_argument("--auto-index", help="Inspect the loaded ruleset and auto-create indices on the top-N columns that the most rules filter on (default N=5 when used without an explicit number). Combine with --add-index for additional manually chosen columns.", type=int, nargs='?', const=5, default=None, metavar="N")

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
    parallel_args.add_argument("--parallel-memory-limit", help=f"Memory usage threshold percentage before throttling (default: {DEFAULTS['parallel_memory_limit']:g})", type=float, default=None)

    # Templating and Mini GUI options
    templating_formats_args = parser.add_argument_group('🎨 TEMPLATING AND MINI GUI')
    templating_formats_args.add_argument("-t", "--template", help="Jinja2 template to use for output generation", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("-T", "--templateOutput", "--template-output", help="Output file for Jinja2 template results", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("--template-append", help="Append to template output files instead of overwriting them. Useful for accumulating results across multiple runs (e.g. cumulative NDJSON exports). Note: not all templates produce append-safe output (single-document JSON layers will become invalid).", action='store_true', dest='template_append')
    templating_formats_args.add_argument("--timesketch", help="Shortcut: use Timesketch template and write to timesketch-<RAND>.json", action='store_true')
    templating_formats_args.add_argument("--navigator-output", help="Shortcut: generate ATT&CK Navigator layer JSON and write to navigator-<RAND>.json (or specify a custom filename)", type=str, metavar="OUTPUT_FILE", nargs='?', const="")
    templating_formats_args.add_argument("-G", "--package", help="Create a ZircoGui/Mini GUI package", action='store_true')
    templating_formats_args.add_argument("--package-dir", help="Directory to save the ZircoGui/Mini GUI package", type=str, default=None)

    return parser.parse_args()


################################################################
# FILE DISCOVERY AND INPUT TYPE DETECTION
################################################################
def _format_flag_extension(args: argparse.Namespace) -> str:
    """Extension implied by the format flags alone (ignores args.fileext)."""
    spec = format_from_args(args)
    # A format without its own extension (SQLite) must not narrow a directory
    # scan, so it falls back to the default format's extension.
    return spec.default_extension or DEFAULT_EXTENSION


def get_file_extension(args: argparse.Namespace) -> str:
    """Determine file extension based on input type."""
    if args.fileext:
        return args.fileext
    return _format_flag_extension(args)


def _has_explicit_format_flag(args: argparse.Namespace) -> bool:
    """Check if the user has set an explicit format flag on the CLI."""
    return has_explicit_format(args)


def _is_explicit(args: argparse.Namespace, dest: str, unset: Any = None) -> bool:
    """Whether *dest* was set by the user rather than left at its default.

    ``run_config.resolve`` records this on the namespace. Namespaces built by
    hand (library callers, tests) never went through it, so they fall back to
    comparing against the value that means "not set".
    """
    explicit = getattr(args, "_explicit", None)
    if explicit is None:
        return getattr(args, dest, unset) != unset
    return dest in explicit


def _fileext_is_explicit(args: argparse.Namespace) -> bool:
    """Whether --fileext (or its YAML equivalent) was set by the user.

    ``discover_files`` overwrites ``args.fileext`` with the format-derived
    default, so callers cannot recover this from the namespace afterwards.
    """
    return _is_explicit(args, "fileext")


def discover_files(
    args: argparse.Namespace, logger: logging.Logger
) -> list[Path]:
    """Discover log files based on path and filters."""
    explicit_ext = _fileext_is_explicit(args)
    args.fileext = get_file_extension(args)

    log_path = Path(args.evtx)
    log_list: list[Path] = []
    if log_path.is_dir():
        pattern = args.file_pattern or f"*.{args.fileext}"
        fn_glob = log_path.rglob if not args.no_recursion else log_path.glob
        log_list = list(fn_glob(pattern))
        if not log_list and not explicit_ext and not args.file_pattern:
            # The extension is only a guess until auto-detection has run, so an
            # empty result here usually means the directory holds another
            # format. Widen to every file so detection gets something to look
            # at; the caller re-discovers with the detected extension after.
            log_list = [p for p in fn_glob("*") if p.is_file()]
    elif log_path.is_file():
        log_list = [log_path]
    else:
        quit_on_error("[red]    [-] Unable to find events from submitted path[/]", logger)

    file_list = avoid_files(select_files(log_list, args.select), args.avoid)
    if not file_list:
        quit_on_error("[red]    [-] No file found. Please verify filters, directory or the extension with '--fileext' or '--file-pattern'[/]", logger)

    return [Path(p) for p in file_list]


def get_input_type(args: argparse.Namespace) -> str:
    """Determine input type for streaming processor from explicit CLI flags."""
    return format_from_args(args).name


_TIMEFIELD_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9]")


def _apply_detection_result(
    args: argparse.Namespace,
    detection: "DetectionResult",
    logger: logging.Logger,
) -> str:
    """
    Apply a DetectionResult to the args namespace and return the input_type.

    Sets the appropriate CLI flag on args so that downstream code
    (extractor creation, file extension logic, etc.) works correctly.
    When detection failed (log_source "unknown"), still use detection.input_type
    if it is a known format (e.g. json from extension fallback), otherwise
    default to evtx.
    """
    input_type = detection.input_type
    spec = format_by_name(input_type)
    # EVTX has no flag of its own, so an unknown source that resolves to it
    # (or to nothing) is indistinguishable from a failed detection.
    if spec is None or not spec.has_cli_flag:
        if detection.log_source == "unknown":
            return "evtx"
    else:
        setattr(args, spec.args_flag, True)

    # Update timefield if detection found a timestamp and user didn't override.
    # The streaming processor strips non-alphanumeric characters from field
    # names (e.g. "@timestamp" → "timestamp") when storing events in SQLite,
    # so the timefield must be sanitized the same way to match the column name.
    if detection.timestamp_field and not _is_explicit(args, "timefield", "SystemTime"):
        args.timefield = _TIMEFIELD_SANITIZE_RE.sub("", detection.timestamp_field)

    return input_type


def auto_detect_log_type(
    file_list: list[Path], args, logger,
    field_mappings_config: dict | None = None,
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

    detector = LogTypeDetector(
        logger=logger,
        timestamp_detection_fields=ts_fields,
        archive_password=getattr(args, 'archive_password', None),
    )

    # Use batch detection for better accuracy. The early timestamp detection
    # in main() already ran detect_batch over the same files: reuse it instead
    # of reading every file twice.
    detection = getattr(args, '_early_detection', None)
    early_files = getattr(args, '_early_detection_files', None)
    if (
        detection is not None
        and early_files is not None
        and set(map(str, early_files)) != set(map(str, file_list))
    ):
        detection = None  # file set changed (re-discovery): re-run
    if detection is None:
        try:
            detection = detector.detect_batch(file_list)
        except ValueError as e:
            # e.g. password-protected archive without --archive-password
            quit_on_error(f"[red]    [-] {e}[/]", logger)

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
# YAML CONFIGURATION
################################################################


def _print_transform_categories(config_path: str, logger) -> bool:
    """Print available transform categories and their transforms.

    Returns True on success, False when the config cannot be loaded or
    contains no categories.
    """
    from zircolite.utils import load_field_mappings
    try:
        config = load_field_mappings(config_path, logger=logger)
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"[red]    [-] {e}[/]")
        return False

    categories = config.get("transform_categories", {})
    if not categories:
        logger.info("[yellow]    [!] No transform categories defined in config.[/]")
        return False

    table = Table(title="Transform Categories", show_lines=True)
    table.add_column("Category", style="cyan", min_width=15)
    table.add_column("Transforms", style="white")
    table.add_column("Count", style="green", justify="right")

    for cat_name, cat_transforms in sorted(categories.items()):
        table.add_row(cat_name, ", ".join(cat_transforms), str(len(cat_transforms)))

    console.print(table)
    return True


def _read_yaml_quietly(path: str | None) -> dict:
    """Best-effort YAML read for the pre-logger phase.

    Any problem here is left for :func:`resolve_run_config`, which has a logger
    and reports it properly.
    """
    if not path:
        return {}
    try:
        import yaml

        with open(path, encoding='utf-8') as f:
            raw = yaml.safe_load(f) or {}
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def resolve_logging_args(args: argparse.Namespace) -> None:
    """Resolve the settings the logger is built from, before it exists.

    ``debug``, ``no_output`` and ``log_file`` decide how the logger is
    constructed, so they cannot wait for the validated merge. Everything else
    is resolved by :func:`resolve_run_config`.
    """
    run_config.resolve(args, _read_yaml_quietly(args.yaml_config), only=EARLY_DESTS)


def resolve_run_config(args, logger) -> argparse.Namespace:
    """Resolve CLI arguments against the YAML config file, if one was given."""
    if not args.yaml_config:
        return run_config.resolve(args, {}, skip=EARLY_DESTS)

    try:
        config_loader = ConfigLoader(logger=logger)
        raw = config_loader.load_yaml(args.yaml_config)
        yaml_config = config_loader.parse_config(raw)

        # Every issue here names something the run cannot honour: a key that
        # will be ignored, a ruleset that is not there, a format that does not
        # exist. Warning and carrying on meant Zircolite ran with something
        # other than what the file asked for and still exited 0 -- a typo'd
        # `input.format` fell back to EVTX and reported zero detections. All of
        # them are reported together so one run names every problem.
        issues = config_loader.validate_config(yaml_config)
        if issues:
            for issue in issues:
                logger.error(f"[red]    [-] Config error: {issue}[/]")
            sys.exit(1)

        run_config.resolve(args, raw, skip=EARLY_DESTS)

        logger.info(f"[+] Configuration loaded and merged from: {make_file_link(args.yaml_config)}")

    except FileNotFoundError as e:
        logger.error(f"[red]    [-] {e}[/]")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"[red]    [-] Error loading YAML config: {e}[/]")
        if logger.isEnabledFor(logging.DEBUG):
            console.print_exception(show_locals=False)
        sys.exit(1)

    return args


################################################################
# POST-PROCESSING
################################################################
def handle_templating(
    ctx: ProcessingContext,
    results: list[Any],
    args: argparse.Namespace,
) -> bool:
    """Handle template generation and package creation. False if a template failed."""
    succeeded = True
    if ctx.ready_for_templating:
        tmpl_config = TemplateConfig(
            template=args.template,
            template_output=args.templateOutput,
            time_field=ctx.time_field,
            append=getattr(args, 'template_append', False),
        )
        template_generator = TemplateEngine(tmpl_config, logger=ctx.logger)
        succeeded = template_generator.run(results)


    if ctx.package:
        if not results:
            ctx.logger.info(
                "[yellow]   [!] No detections: skipping GUI package creation[/]"
            )
        else:
            # Deliberately not resolve_default_path: the template and the archive
            # have to come from the same build, and a copy of only one of them in
            # the working directory would pair a new data.js with an old GUI.
            template_path = bundled_asset("templates", "exportForZircoGui.tmpl")
            gui_zip_path = bundled_asset("gui", "zircogui.zip")
            if template_path.is_file() and gui_zip_path.is_file():
                gui_config = GuiConfig(
                    source_archive=str(gui_zip_path),
                    template_file=str(template_path),
                    time_field=ctx.time_field
                )
                packager = ZircoliteGuiGenerator(gui_config, logger=ctx.logger)
                # A package the user asked for and did not get is a failed run
                succeeded = packager.generate(results, args.package_dir) and succeeded
            else:
                missing = []
                if not template_path.is_file():
                    missing.append(str(template_path))
                if not gui_zip_path.is_file():
                    missing.append(str(gui_zip_path))
                ctx.logger.error(
                    f"[red]    [-] Cannot create GUI package: missing file(s): {', '.join(missing)}[/]"
                )
                succeeded = False
    return succeeded


def cleanup(
    args: argparse.Namespace,
    logger: logging.Logger,
    log_list: list[Path] | None = None,
    failed: set[str] | None = None,
) -> None:
    """Remove the original event files, as ``--remove-events`` asks.

    Files whose ingestion failed are kept: their events are absent from the
    results, so deleting them would destroy evidence nothing ever analysed.
    """
    if args.remove_events and log_list:
        logger.info("[+] Cleaning")
        failed = failed or set()
        for evtx in log_list:
            if str(evtx) in failed:
                logger.warning(
                    f"[yellow]   [!] Keeping {evtx}: it failed to process, so its "
                    "events are not in the results[/]"
                )
                continue
            try:
                os.remove(evtx)
            except OSError as e:
                logger.error(f"[red]    [-] Cannot remove file {e}[/]")


def collapse_results_by_rule(all_results: list[Any]) -> list[dict[str, Any]]:
    """One entry per rule, with its per-file counts summed.

    Per-file, parallel and multi---dbfile input each append a result entry per
    file, so a rule matching in three files arrived three times. Counting those
    entries reported `3/1 rules matched (300.0%)` and listed the same rule three
    times under Top Hits. Only --unified-db was ever free of it.
    """
    collapsed: dict[Any, dict[str, Any]] = {}
    for result in all_results or []:
        if not isinstance(result, dict):
            continue
        key = result.get("id") or result.get("title")
        existing = collapsed.get(key)
        if existing is None:
            collapsed[key] = dict(result)
        else:
            existing["count"] = existing.get("count", 0) + result.get("count", 0)
    return list(collapsed.values())


def print_stats(
    memory_tracker: MemoryTracker,
    start_time: float,
    all_results: list[Any] | None = None,
    files_processed: int = 0,
    total_events: int = 0,
    workers_used: int = 1,
    filtered_events: int = 0,
    time_filtered_events: int = 0,
    event_filter_active: bool = False,
    total_rules: int = 0,
    phase_times: dict | None = None,
    outfile: str | None = None,
) -> None:
    """Print final execution statistics with a Rich summary dashboard."""
    memory_tracker.sample()
    peak_memory, _ = memory_tracker.get_stats()
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
            summary_table.add_row("", f"    [dim]\u251c\u2500 {phase_name}  {bar}  {t_str} ({pct:.0%})[/]")

    # ── Files ──
    if files_processed > 0:
        summary_table.add_row("📁 Files", f"[cyan]{files_processed:,}[/]")

    # ── Events with filter efficiency ──
    # Report whenever a filter was active, not only when it dropped something:
    # a silent line makes "dropped nothing" look like "never ran".
    if total_events > 0:
        events_text = f"[magenta]{total_events:,}[/]"
        if event_filter_active:
            total_scanned = total_events + filtered_events + time_filtered_events
            match_rate = (total_events / total_scanned * 100) if total_scanned > 0 else 0
            if filtered_events > 0:
                events_text += (
                    f" [dim]({filtered_events:,} filtered out — "
                    f"{match_rate:.1f}% match rate)[/]"
                )
            else:
                events_text += " [dim](0 filtered out — every event matched a rule's log source)[/]"
        elif filtered_events > 0:
            total_scanned = total_events + filtered_events + time_filtered_events
            match_rate = (total_events / total_scanned * 100) if total_scanned > 0 else 0
            events_text += f" [dim]({filtered_events:,} filtered out — {match_rate:.1f}% match rate)[/]"
        summary_table.add_row("📊 Events", events_text)

    # ── Time range ──
    if time_filtered_events > 0:
        summary_table.add_row(
            "🕐 Time range", f"[dim]{time_filtered_events:,} events outside --after/--before[/]"
        )

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
        all_results = collapse_results_by_rule(all_results)
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
            # Clamped: a stale total would otherwise render a bar wider than
            # its column rather than simply reading oddly.
            filled = min(bar_w, max(0, int(bar_w * matched_rules / total_rules)))
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
        console.print(f"    [bold green]\u2192[/] Output: {make_file_link(outfile)}")

################################################################
# PROCESSING DISPATCH
################################################################
def _warn_ignored_db_flags(
    args: argparse.Namespace, logger: logging.Logger
) -> None:
    """Warn when CLI flags incompatible with DB input mode were supplied."""
    ignored: list[str] = []
    if args.unified_db:
        ignored.append("--unified-db")
    if getattr(args, 'no_auto_mode', False):
        ignored.append("--no-auto-mode")
    if getattr(args, 'no_parallel', False):
        ignored.append("--no-parallel")
    if getattr(args, 'add_index', None):
        ignored.append("--add-index")
    if getattr(args, 'remove_index', None):
        ignored.append("--remove-index")
    if getattr(args, 'hashes', False):
        ignored.append("--hashes")
    if getattr(args, 'keepflat', False):
        ignored.append("--keepflat")
    if getattr(args, 'dbfile', None):
        ignored.append("--dbfile")
    if getattr(args, 'strict', False):
        ignored.append("--strict")
    if getattr(args, 'archive_password', None):
        ignored.append("--archive-password")
    if getattr(args, 'no_event_filter', False):
        ignored.append("--no-event-filter")
    if getattr(args, 'logs_encoding', None):
        ignored.append("--logs-encoding")
    # Time filtering happens during ingestion, which DB input skips entirely.
    # --timefield is not listed: it still drives templates and correlation SQL.
    if getattr(args, 'after', None) not in (None, DEFAULTS['after']):
        ignored.append("--after")
    if getattr(args, 'before', None) not in (None, DEFAULTS['before']):
        ignored.append("--before")
    if ignored:
        logger.warning(
            f"[yellow]DB input mode: the following flags have no effect and will be "
            f"ignored: {', '.join(ignored)}[/]"
        )


def _run_processing(
    ctx: ProcessingContext,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> tuple[Any, Any, list[Path] | None, float]:
    """Run the main processing pipeline and return all state needed by main().

    Returns:
        (zircolite_core, all_results, log_list, phase_setup_end)
    """
    zircolite_core = None
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

    # ----- DB input mode (explicit -D) -----
    if args.db_input:
        _warn_ignored_db_flags(args, logger)
        db_files = expand_db_path(Path(args.evtx), args, logger)
        zircolite_core, all_results = process_db_input(ctx, args, file_list=db_files)
        # Report the databases actually scanned, not a hardcoded 1
        return zircolite_core, all_results, db_files, phase_setup_end

    # ----- File input mode -----
    check_if_exists(
        args.config,
        "[red]    [-] Cannot find mapping file, you can get the default one here : "
        "https://github.com/wagga40/Zircolite/blob/master/config/config.yaml [/]",
        logger,
    )

    # The extension in force before auto-detection may run. Reading the
    # registry rather than assuming EVTX keeps an explicit format flag from
    # looking like a change and triggering a needless second directory walk.
    original_ext = args.fileext or _format_flag_extension(args)
    fileext_from_cli = _fileext_is_explicit(args)
    file_list = discover_files(args, logger)
    log_list = file_list

    # Auto-detect log type
    if not is_quiet() and not _has_explicit_format_flag(args) and not getattr(args, 'no_auto_detect', False):
        with console.status("[bold cyan]Auto-detecting log type...", spinner="dots"):
            input_type = auto_detect_log_type(file_list, args, logger, field_mappings_config)
    else:
        input_type = auto_detect_log_type(file_list, args, logger, field_mappings_config)

    # Re-discover files if auto-detection changed the expected extension.
    # Only when the extension was auto-derived: an explicit --fileext wins.
    if Path(args.evtx).is_dir() and not args.file_pattern and not fileext_from_cli:
        new_ext = _format_flag_extension(args)
        if new_ext != original_ext:
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

    # DB input mode (auto-detected SQLite file)
    if args.db_input:
        _warn_ignored_db_flags(args, logger)
        zircolite_core, all_results = process_db_input(ctx, args, file_list=file_list)
        return zircolite_core, all_results, log_list, phase_setup_end

    # Auto-select processing mode
    use_parallel = False
    parallel_workers = 1

    # Flags whose contract needs one file at a time. --strict has to abort the
    # whole run on a parse error, but a worker exception can only be logged and
    # counted, so in parallel the flag would quietly do nothing.
    # --profile-rules times rules against one database at a time.
    sequential_reasons = [
        flag
        for flag, enabled in (
            ("--strict", getattr(args, 'strict', False)),
            ("--profile-rules", getattr(args, 'profile_rules', False)),
        )
        if enabled
    ]
    force_sequential = bool(sequential_reasons)

    if not args.no_auto_mode and not args.unified_db:
        recommended_mode, reason, stats = analyze_files_and_recommend_mode(file_list)
        forced_workers = getattr(args, 'parallel_workers', None)
        print_mode_recommendation(
            recommended_mode, reason, stats,
            show_parallel=True, forced_workers=forced_workers,
        )
        if recommended_mode == 'unified':
            args.unified_db = True
        if not args.unified_db and not getattr(args, 'no_parallel', False) and not force_sequential:
            if stats.get('parallel_recommended', False):
                use_parallel = True
                parallel_workers = stats.get('parallel_workers', 1)
            elif forced_workers and forced_workers > 1 and len(file_list) > 1:
                use_parallel = True
                parallel_workers = forced_workers
    elif args.unified_db:
        logger.info("[+] [cyan]Database mode:[/] [green]UNIFIED[/] (forced)")
        logger.info("")
    else:
        if not getattr(args, 'no_parallel', False) and not force_sequential and len(file_list) > 1:
            _, _, stats = analyze_files_and_recommend_mode(file_list)
            forced_workers = getattr(args, 'parallel_workers', None)
            if stats.get('parallel_recommended', False):
                use_parallel = True
                parallel_workers = stats.get('parallel_workers', 1)
            elif forced_workers and forced_workers > 1:
                # An explicit worker count is a deliberate override, exactly as
                # in the auto-mode branch above
                use_parallel = True
                parallel_workers = forced_workers

    if force_sequential and len(file_list) > 1:
        logger.info(
            f"[+] [cyan]Sequential mode:[/] {' and '.join(sequential_reasons)} "
            "requires one file at a time (parallel disabled)."
        )
    if getattr(args, 'profile_rules', False):
        if args.unified_db:
            logger.info(
                "[+] [cyan]Note:[/] --profile-rules with --unified-db reports per-rule "
                "timings against the combined dataset, not per-file breakdowns."
            )
        logger.info("")

    # Streaming processing (single-pass pipeline)
    extractor = create_extractor(args, logger, input_type)

    if use_parallel and len(file_list) > 1 and getattr(args, "dbfile", None):
        logger.error(
            "[red]    [-] Saving the database to a file (--dbfile) is not supported when "
            "processing multiple files in parallel. Use --unified-db to get a single "
            "database file, or disable parallel with --no-parallel to save one database per file.[/]"
        )
        sys.exit(2)

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

    return zircolite_core, all_results, log_list, phase_setup_end


################################################################
# MAIN
################################################################
def main() -> None:
    version = __version__
    args = parse_arguments()

    install_signal_handler()

    # Handle generate-config before logging setup
    if args.generate_config:
        try:
            create_default_config_file(args.generate_config)
        except (FileExistsError, OSError) as e:
            print_error_panel(
                "Cannot Write Configuration",
                str(e),
                "Choose a different path or remove the existing file.",
            )
            sys.exit(2)
        sys.exit(0)

    # Set up quiet mode before any output
    if args.quiet:
        set_quiet_mode(True)

    # Init logging. A YAML config can set debug/log_file/no_output, and those
    # have to be known before the logger exists
    resolve_logging_args(args)
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
        updater = RulesUpdater(logger=logger)
        logger.info(f"[+] Updating rules in {make_file_link(str(updater.rules_dir))}")
        updater.run()
        sys.exit(0)

    # A relative --config names a file shipped in config/, so it has to resolve
    # from the install as well as from the working directory -- the default is
    # the most common such value, not the only one. Only a value already rooted
    # at config/ may fall back, or `-c mine/config.yaml` would quietly load the
    # bundled one instead of reporting that it is missing.
    config_path = Path(args.config)
    if not config_path.is_absolute() and config_path.parent == Path("config"):
        args.config = resolve_default_path(args.config, "config", config_path.name)

    if args.transform_list:
        sys.exit(0 if _print_transform_categories(args.config, logger) else 1)

    # Resolve CLI arguments against the YAML configuration file, if any. This
    # also applies the built-in defaults, so it must run even without -Y.
    args = resolve_run_config(args, logger)

    # Apply --timesketch shortcut
    if getattr(args, 'timesketch', False):
        rand_4 = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))
        out_name = f"timesketch-{rand_4}.json"
        if args.template is None:
            args.template = []
        if args.templateOutput is None:
            args.templateOutput = []
        args.template.append([resolve_default_path(
            "templates/exportForTimesketch.tmpl", "templates", "exportForTimesketch.tmpl"
        )])
        args.templateOutput.append([out_name])

    # Apply --navigator-output shortcut
    if getattr(args, 'navigator_output', None) is not None:
        rand_4 = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))
        nav_out = args.navigator_output or f"navigator-{rand_4}.json"
        if args.template is None:
            args.template = []
        if args.templateOutput is None:
            args.templateOutput = []
        args.template.append([resolve_default_path(
            "templates/exportForAttackNavigator.tmpl", "templates", "exportForAttackNavigator.tmpl"
        )])
        args.templateOutput.append([nav_out])

    # Handle rulesets
    if args.ruleset:
        flattened = [item for sublist in args.ruleset for item in sublist]
        args.ruleset = [resolve_shipped_ruleset(item) for item in flattened]
    else:
        args.ruleset = [
            resolve_default_path(
                "rules/rules_windows_generic.json",
                "rules", "rules_windows_generic.json",
            )
        ]

    # Early timestamp detection: resolve the effective time field *before* ruleset
    # conversion so that correlation rule SQL references the correct column name.
    # The full auto_detect_log_type still runs later inside _run_processing for
    # format flags, file re-discovery, etc.; this only updates args.timefield.
    if (
        args.evtx
        and not _is_explicit(args, "timefield", "SystemTime")
        and not _has_explicit_format_flag(args)
        and not getattr(args, 'no_auto_detect', False)
        and Path(args.evtx).exists()
    ):
        try:
            from zircolite.utils import load_field_mappings
            _fm = load_field_mappings(args.config, logger=logger)
        except Exception:
            _fm = None
        _ts_fields = None
        if _fm:
            _ts_cfg = _fm.get("timestamp_detection", {})
            _ts_fields = _ts_cfg.get("detection_fields")
        _early_files = list(discover_files(args, logger))
        if _early_files:
            _detector = LogTypeDetector(
                logger=logger,
                timestamp_detection_fields=_ts_fields,
                archive_password=getattr(args, 'archive_password', None),
            )
            try:
                _detection = _detector.detect_batch(_early_files)
            except ValueError as e:
                # e.g. password-protected archive without --archive-password
                quit_on_error(f"[red]    [-] {e}[/]", logger)
            # Cache for auto_detect_log_type so detection does not run twice
            args._early_detection = _detection
            args._early_detection_files = _early_files
            if _detection.timestamp_field:
                args.timefield = _TIMEFIELD_SANITIZE_RE.sub(
                    "", _detection.timestamp_field
                )

    # Load rulesets (with spinner for visual feedback during pySigma conversion)
    logger.info("[+] Loading ruleset(s)")
    ruleset_config = RulesetConfig(
        ruleset=args.ruleset,
        pipeline=args.pipeline,
        save_ruleset=args.save_ruleset,
        time_field=args.timefield,
    )
    if not is_quiet():
        with console.status("[bold cyan]Loading and converting rulesets...", spinner="dots"):
            rulesets_manager = RulesetHandler(ruleset_config, logger=logger, list_pipelines_only=args.pipeline_list)
    else:
        rulesets_manager = RulesetHandler(ruleset_config, logger=logger, list_pipelines_only=args.pipeline_list)
    if args.pipeline_list:
        sys.exit(0)

    # Nothing was going to be applied to the events. The empty result file this
    # would otherwise write is indistinguishable from a clean run that found
    # nothing, so anything reading the exit code calls a failed run a success.
    if not rulesets_manager.rulesets:
        quit_on_error(
            "[red]    [-] No rules to execute: check the ruleset(s) given to "
            "[cyan]--ruleset[/][/]",
            logger,
        )

    # Flatten rule filters (must happen before any ruleset filtering below)
    if args.rulefilter:
        args.rulefilter = [item for sublist in args.rulefilter for item in sublist]

    # Handle --test-rules: validate rules against test cases and exit
    if getattr(args, 'test_rules', None):
        from zircolite.console import print_rule_test_results
        from zircolite.core import ZircoliteCore
        check_if_exists(args.test_rules, f"[red]    [-] Cannot find test file: {args.test_rules}[/]", logger)
        logger.info(f"[+] Running rule tests from: {make_file_link(args.test_rules)}")
        _test_core = ZircoliteCore(args.config, logger=logger)
        _test_core.load_ruleset_from_var(rulesets_manager.rulesets, args.rulefilter)
        try:
            test_results = _test_core.run_rule_tests(args.test_rules)
        except ValueError as e:
            _test_core.close()
            quit_on_error(f"[red]    [-] {e}[/]", logger)
        _test_core.close()
        print_section("Rule Testing")
        print_rule_test_results(test_results)
        # A test case naming a rule that is not in the ruleset never runs, so
        # treating it as a pass would hide typos in the test file from CI
        orphan_cases = [
            r for r in test_results
            if r.get('error') == 'no matching rule in ruleset'
        ]
        if orphan_cases:
            logger.error(
                f"[red]    [-] {len(orphan_cases)} test case(s) match no rule in "
                f"the ruleset: {', '.join(r.get('title') or r.get('id') or '?' for r in orphan_cases[:5])}"
                f"{' ...' if len(orphan_cases) > 5 else ''}[/]"
            )
        tests_failed = bool(orphan_cases) or any(
            r.get('tp_pass') is False or r.get('tn_pass') is False
            for r in test_results
        )
        sys.exit(1 if tests_failed else 0)

    # Validate required arguments
    if not args.evtx:
        print_error_panel(
            "Missing Input",
            "No events source path provided.",
            "Use '-e <PATH TO LOGS>' or '--events <PATH TO LOGS>'"
        )
        sys.exit(2)
    if args.csv and len(args.ruleset) > 1:
        csv_source = (
            "the configuration file (output.format: csv)"
            if getattr(args, '_csv_from_yaml', False)
            else "--csv"
        )
        print_error_panel(
            "Invalid Configuration",
            "CSV output is not supported with multiple rulesets.",
            f"CSV output was enabled via {csv_source}. Use a single ruleset for CSV output."
        )
        sys.exit(2)

    # Only when CSV is actually being written: a delimiter set in a config file
    # otherwise aborted an unrelated JSON run over a value nothing would read.
    if args.csv and len(args.csv_delimiter) != 1:
        # csv.DictWriter would raise mid-run, after the output file was opened
        # and truncated, leaving a zero-byte CSV and a bare traceback
        print_error_panel(
            "Invalid Configuration",
            f"The CSV delimiter must be exactly one character (got {args.csv_delimiter!r}).",
            "Use a single character, e.g. --csv-delimiter ';'"
        )
        sys.exit(2)

    # "All" already includes every category, so passing both means one of them
    # was going to be ignored. Silently is the wrong way to do that.
    if args.all_transforms and args.transform_categories:
        print_error_panel(
            "Invalid Configuration",
            "--all-transforms and --transform-category cannot be combined: "
            "--all-transforms already enables every category.",
            "Drop one of the two."
        )
        sys.exit(2)

    logger.info("[+] Checking prerequisites")

    # Parse timestamps
    for flag, value in (('--after', args.after), ('--before', args.before)):
        try:
            time.strptime(value, '%Y-%m-%dT%H:%M:%S')
        except Exception:
            quit_on_error(f"[red]    [-] Wrong timestamp format for {flag}: '{value}'. Expected 'YYYY-MM-DDTHH:MM:SS'[/]", logger)
    events_after = time.strptime(args.after, '%Y-%m-%dT%H:%M:%S')
    events_before = time.strptime(args.before, '%Y-%m-%dT%H:%M:%S')
    if events_after >= events_before:
        quit_on_error(f"[red]    [-] --after '{args.after}' must be earlier than --before '{args.before}'[/]", logger)

    # Check templates
    ready_for_templating = False
    if args.template is None and args.templateOutput is not None:
        quit_on_error(
            "[red]    [-] --templateOutput requires --template (-t) to be set[/]",
            logger,
        )
    if args.template is not None:
        # A relative templates/... path has to resolve from the install as well,
        # so a -t or a YAML config written once works from any directory.
        args.template = [
            [resolve_shipped_template(entry) for entry in template]
            for template in args.template
        ]
        if args.csv:
            quit_on_error("[red]    [-] You cannot use templates in CSV mode[/]", logger)
        if args.templateOutput is None or len(args.template) != len(args.templateOutput):
            n_tmpl = len(args.template)
            n_out = len(args.templateOutput) if args.templateOutput else 0
            quit_on_error(f"[red]    [-] Number of --templateOutput values ({n_out}) must match --template count ({n_tmpl})[/]", logger)
        for template in args.template:
            if len(template) > 1:
                quit_on_error(
                    f"[red]    [-] Only one template per -t/--template flag is supported (got: {' '.join(template)})[/]",
                    logger,
                )
            check_if_exists(template[0], f"[red]    [-] Cannot find template: {template[0]}. Default templates are available here: https://github.com/wagga40/Zircolite/tree/master/templates[/]", logger)
        for output_spec in args.templateOutput:
            if len(output_spec) > 1:
                quit_on_error(
                    f"[red]    [-] Only one output file per -T/--templateOutput flag is supported (got: {' '.join(output_spec)})[/]",
                    logger,
                )
        ready_for_templating = True

    # --limit -1 disables the limit; any other non-positive value would silently
    # discard every detection (execute_ruleset drops results with count > limit)
    if args.limit == 0 or args.limit < -1:
        quit_on_error(
            "[red]    [-] --limit must be a positive integer (or -1 to disable)[/]",
            logger,
        )

    # CSV mode adjustments (the .csv output name is applied while resolving)
    if args.csv:
        ready_for_templating = False

    if args.dbfile and Path(args.dbfile).exists():
        print_error_panel(
            "Database File Exists",
            f"The database file '{args.dbfile}' already exists.",
            "Remove the existing file or choose a different path with --dbfile."
        )
        sys.exit(2)

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
        event_filter=active_event_filter,
        profile_rules=getattr(args, 'profile_rules', False),
        archive_password=getattr(args, 'archive_password', None),
        add_index=flatten_groups(getattr(args, 'add_index', None)),
        remove_index=flatten_groups(getattr(args, 'remove_index', None)),
        auto_index_top_n=getattr(args, 'auto_index', 0),
        strict_evtx=getattr(args, 'strict', False),
    )

    zircolite_core = None
    log_list: list[Path] | None = None
    all_results: list[Any] = []
    phase_setup_end = 0.0
    strict_error = None
    templating_ok = True

    try:
        zircolite_core, all_results, log_list, phase_setup_end = _run_processing(
            ctx, args, logger
        )

        if not is_shutdown_requested():
            # Print rule profiling report if requested
            if getattr(args, 'profile_rules', False) and zircolite_core is not None:
                from zircolite.console import print_profiling_report
                print_section("Rule Performance")
                print_profiling_report(zircolite_core.get_profiling_report())

            # Handle templating and package generation
            templating_ok = handle_templating(ctx, all_results, args)
    except StrictParseError as e:
        strict_error = str(e)
    except KeyboardInterrupt:
        request_shutdown()
    finally:
        try:
            # An interrupted run stops at the next checkpoint and returns
            # normally, so log_list still names every discovered file -- including
            # the ones nothing opened. Deleting those would destroy evidence that
            # never reached the results.
            if is_shutdown_requested():
                if args.remove_events and log_list:
                    logger.warning(
                        "[yellow]   [!] Keeping the input files: the run was "
                        "interrupted, so not every event was analysed[/]"
                    )
            else:
                cleanup(args, logger, log_list, failed=ctx.failed_files)
        except Exception as e:
            logger.debug(f"Cleanup: {e}")
        if zircolite_core is not None:
            try:
                zircolite_core.close()
            except Exception as e:
                logger.debug(f"Core close: {e}")

    if strict_error is not None:
        quit_on_error(
            f"[red]    [-] {strict_error}[/]\n"
            "[yellow]   [!] Aborted because [cyan]--strict[/] is set; "
            "omit it to skip malformed chunks and keep the events read so far.[/]",
            logger,
        )

    if is_shutdown_requested():
        logger.info("[yellow][!] Shutdown complete.[/]")
        sys.exit(130)

    # Build phase timing breakdown
    now = time.time()
    phase_times = None
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
        all_results=all_results,
        files_processed=files_processed,
        total_events=ctx.total_events,
        workers_used=ctx.workers_used,
        filtered_events=ctx.total_filtered_events,
        time_filtered_events=ctx.total_time_filtered_events,
        event_filter_active=ctx.event_filter is not None and ctx.event_filter.is_enabled,
        total_rules=len(ctx.rulesets) if ctx.rulesets else 0,
        phase_times=phase_times,
        outfile=ctx.outfile if not ctx.no_output else None,
    )

    # A template that did not write is a failed run: whatever consumes that file
    # would otherwise read a stale one, or nothing, and call it success
    if not templating_ok:
        sys.exit(1)
