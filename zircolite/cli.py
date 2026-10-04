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
import shutil
import string
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# External libs - Rich for styled terminal output
from rich.logging import RichHandler
from rich.markup import escape
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
    UnknownPipelineError,
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
    resolve_default_path,
    resolve_shipped_ruleset,
    resolve_shipped_template,
)
from zircolite.config import RULE_LEVELS
from zircolite.console import literal
from zircolite.correlations import TIMESTAMP_FORMATS

# Input format registry
from zircolite.formats import ALIAS_EXTENSIONS, DEFAULT_EXTENSION, EXTENSION_FALLBACKS
from zircolite.package_spool import PackageError, PackageSpool, rule_index
from zircolite.performance import STAGE_LABELS, aggregate_stages, write_performance_report

# Processing modes and context (from the dedicated processing module)
from zircolite.processing import (
    OutputPathConflict,
    ProcessingContext,
    check_output_paths,
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
from zircolite.utils import COMPRESSED_SUFFIXES

################################################################
# NOTE: ProcessingContext and all process_* functions live in
# zircolite/processing.py – imported above.
################################################################


################################################################
# ARGUMENT PARSING
################################################################
# Environment variable read for the archive password when neither
# --archive-password nor --ask-archive-password is given. Unlike argv, the
# environment of a process is readable only by its owner (and root).
ARCHIVE_PASSWORD_ENV = "ZIRCOLITE_ARCHIVE_PASSWORD"  # noqa: S105 -- a variable name, not a secret


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
    archive_password_args = logs_input_args.add_mutually_exclusive_group()
    archive_password_args.add_argument("--archive-password", help=f"Password for encrypted ZIP or 7-Zip archives. Visible to other local users in the process list: prefer --ask-archive-password or the {ARCHIVE_PASSWORD_ENV} environment variable", type=str, metavar="PASSWORD")
    archive_password_args.add_argument("--ask-archive-password", help="Prompt for the password of encrypted ZIP or 7-Zip archives without echoing it", action="store_true")

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
    rulesets_formats_args.add_argument("--timestamp-format", choices=TIMESTAMP_FORMATS, default=None, help=f"How the time field is written, for correlation rules converted from native Sigma rulesets (YAML): ISO 8601 (iso) or Unix seconds, milliseconds or microseconds (default: {DEFAULTS['timestamp_format']}). Compiled JSON rulesets keep the format they were converted with")
    rulesets_formats_args.add_argument("-pl", "--pipeline-list", help="List all installed pysigma pipelines", action='store_true')
    rulesets_formats_args.add_argument("--min-level", choices=RULE_LEVELS, default=None, help="Load only the rules at this level or above; a rule without a level counts as informational")
    rulesets_formats_args.add_argument("-R", "--rulefilter", help="Remove rules from ruleset by matching rule title (case sensitive)", action='append', nargs='*')
    rulesets_formats_args.add_argument("--test-rules", help="JSON file with rule test cases (true-positive / true-negative events per rule)", type=str, metavar="TEST_FILE")

    # Output formats and output files options
    output_formats_args = parser.add_argument_group('💾 OUTPUT FORMATS AND FILES')
    output_formats_args.add_argument("-o", "--outfile", help="Output file for detected events (default: detected_events.json, or detected_events.csv with --csv)", type=str, default=None)
    output_formats_args.add_argument(
        "--csv",
        "--csv-output",
        help=(
            "Output results in CSV format, one row per matched event with every result "
            "field as a column (empty fields included). Rejects more than one ruleset."
        ),
        action="store_true",
    )
    output_formats_args.add_argument("--csv-delimiter", help=f"Delimiter for CSV output (default: '{DEFAULTS['csv_delimiter']}')", type=str, default=None)
    output_formats_args.add_argument("--keepflat", "--keep-flat", help="Save the flattened events as JSONL to flattened_events_<RAND>.json", action='store_true')
    output_formats_args.add_argument("--profile-rules", help="Time each rule execution and print a performance report at the end", action='store_true')
    output_formats_args.add_argument("-d", "--dbfile", "--db-file", help="Save all logs to a SQLite database file", type=str)
    output_formats_args.add_argument("-l", "--logfile", "--log-file", help=f"Log file name (default: {DEFAULTS['logfile']})", default=None, type=str)
    output_formats_args.add_argument("-L", "--limit", "--limit-results", help=f"Discard rules matching more events than this (alerts, for a correlation rule), per input database: per file in per-file mode, across the whole corpus when the run uses one database (--unified-db, or auto mode choosing it) (default: {DEFAULTS['limit']}, i.e. no limit)", type=int, default=None)

    # Advanced configuration options
    config_formats_args = parser.add_argument_group('⚙️  ADVANCED CONFIGURATION')
    config_formats_args.add_argument("-c", "--config", help="JSON or YAML file containing field mappings and exclusions", type=str, default="config/config.yaml")
    config_formats_args.add_argument("-LE", "--logs-encoding", help="Encoding of the source files, for the formats read as text: Sysmon for Linux, Auditd, EVTXtract and CSV (XML uses the encoding declared in the document, JSON is read as UTF-8)", type=str)
    config_formats_args.add_argument("-q", "--quiet", help="Quiet mode: suppress banner, progress, and info messages. Only the summary panel and errors are shown.", action='store_true')
    config_formats_args.add_argument("--debug", help="Enable debug logging", action='store_true')
    config_formats_args.add_argument("-n", "--nolog", "--no-log", help="Don't create the log file or the detections output file (files requested explicitly with --template, --dbfile, --keepflat or --package are still written)", action='store_true')
    config_formats_args.add_argument("-U", "--update-rules", help="Update rulesets in the 'rules' directory", action='store_true')
    config_formats_args.add_argument("-v", "--version", help="Display Zircolite version", action='store_true')
    config_formats_args.add_argument("--timefield", "--time-field", help="Field holding the event timestamp, after field mappings. Left unset it is auto-detected, falling back to 'SystemTime'; naming one pins it", type=str, default=None)
    config_formats_args.add_argument("--unified-db", "--all-in-one", help="Force unified database mode (all files in one DB, enables cross-file correlation)", action='store_true')
    config_formats_args.add_argument("--no-auto-mode", help="Disable automatic processing mode selection based on file analysis", action='store_true')
    config_formats_args.add_argument("--strict", help="Strict EVTX parsing: stop on corrupted or malformed chunks instead of skipping them. Forces sequential processing (default: lenient, recovers as many events as possible)", action='store_true')
    config_formats_args.add_argument("--add-index", help="Create an index on the given column(s). Can be repeated or list multiple columns (e.g. --add-index Channel EventID).", action='append', nargs='+', metavar="COL", default=None)
    config_formats_args.add_argument("--remove-index", help="Drop the given index name(s) after creation. Can be repeated or list multiple (e.g. --remove-index idx_channel idx_eventid).", action='append', nargs='+', metavar="IDX", default=None)
    config_formats_args.add_argument("--auto-index", help="Inspect the loaded ruleset and auto-create indices on the top-N columns that the most rules filter on (default N=5 when used without an explicit number). Combine with --add-index for additional manually chosen columns.", type=int, nargs='?', const=5, default=None, metavar="N")

    performance_args = parser.add_argument_group('PERFORMANCE')
    performance_args.add_argument("--performance-json", default=None, metavar="PATH", help="Write timings, accelerator status and sampled memory to a JSON report")
    performance_args.add_argument("--working-db", choices=("memory", "disk"), default=None, help="Working database storage (default: memory); independent of --dbfile export")
    performance_args.add_argument("--working-db-dir", default=None, metavar="DIR", help="Existing directory for temporary working databases (default: system temporary directory)")
    performance_args.add_argument("--sqlite-cache-mib", type=int, default=None, metavar="MIB", help="Page cache budget per disk database in MiB (default: 64); not a process memory limit")
    performance_args.add_argument("--flatten-backend", choices=("auto", "python", "cython"), default=None, help="Flattening implementation (default: auto uses Cython when built, otherwise Python)")
    performance_args.add_argument("--rule-prefilter", choices=("auto", "off", "literal"), default=None, help="Literal candidate filtering verified by SQLite (default: auto for sufficiently large databases and rulesets)")

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
    parallel_args.add_argument("--executor", choices=("auto", "thread", "process"), default=None, help="File worker executor (default: auto selects processes for 32 MiB or more of input when CPU and memory allow two workers)")
    parallel_args.add_argument("--parallel-memory-limit", help=f"Memory usage threshold percentage before throttling (default: {DEFAULTS['parallel_memory_limit']:g})", type=float, default=None)

    # Templating and package options
    templating_formats_args = parser.add_argument_group('🎨 TEMPLATING AND PACKAGE')
    templating_formats_args.add_argument("-t", "--template", help="Jinja2 template to use for output generation", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("-T", "--templateOutput", "--template-output", help="Output file for Jinja2 template results", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("--template-append", help="Append to template output files instead of overwriting them. Useful for accumulating results across multiple runs (e.g. cumulative NDJSON exports). Note: not all templates produce append-safe output (single-document JSON layers will become invalid).", action='store_true', dest='template_append')
    templating_formats_args.add_argument("--timesketch", help="Shortcut: use Timesketch template and write to timesketch-<RAND>.json", action='store_true')
    templating_formats_args.add_argument("--navigator-output", help="Shortcut: generate ATT&CK Navigator layer JSON and write to navigator-<RAND>.json (or specify a custom filename)", type=str, metavar="OUTPUT_FILE", nargs='?', const="")
    templating_formats_args.add_argument("-G", "--package", help="Create a package for the offline viewer: every event of the run plus the detections, in one zip opened with a web browser", action='store_true')
    templating_formats_args.add_argument("--package-dir", help="Existing directory to write the package to (default: the working directory)", type=str, default=None)

    return parser.parse_args()


def resolve_archive_password(
    args: argparse.Namespace, logger: logging.Logger
) -> None:
    """Fill ``args.archive_password`` from the first channel that has one.

    Order: ``--archive-password`` (kept for compatibility, with a warning,
    since argv is world-readable through /proc and ps and lands in shell
    history), then ``--ask-archive-password`` (an interactive prompt), then
    the :data:`ARCHIVE_PASSWORD_ENV` environment variable. Records which
    one was used in ``args.archive_unlock_channel``.
    """
    if getattr(args, 'archive_password', None) is not None:
        args.archive_unlock_channel = "argv"
        logger.warning(
            "[!] --archive-password exposes the password to other local users "
            "through the process list and keeps it in shell history. Prefer "
            f"--ask-archive-password or the {ARCHIVE_PASSWORD_ENV} environment variable."
        )
        return
    if getattr(args, 'ask_archive_password', False):
        import getpass

        args.archive_password = getpass.getpass("Archive password: ") or None
        args.archive_unlock_channel = "prompt"
        return
    from_env = os.environ.get(ARCHIVE_PASSWORD_ENV)
    if from_env:
        args.archive_password = from_env
        args.archive_unlock_channel = "env"


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
        fn_glob = log_path.rglob if not args.no_recursion else log_path.glob
        if args.file_pattern or explicit_ext:
            pattern = args.file_pattern or f"*.{args.fileext}"
            log_list = [p for p in fn_glob(pattern) if p.is_file()]
        else:
            spec = format_from_args(args)
            extensions = {f".{args.fileext}"}
            extensions.update(
                ext for ext in ALIAS_EXTENSIONS
                if EXTENSION_FALLBACKS[ext].format_name == spec.name
            )
            suffixes = tuple(
                ext + compression
                for ext in extensions
                for compression in ("", *COMPRESSED_SUFFIXES)
            )
            candidates = [p for p in fn_glob("*") if p.is_file()]
            log_list = [p for p in candidates if p.name.lower().endswith(suffixes)]
            # The extension is only a guess until auto-detection has run, so an
            # empty result here usually means the directory holds another
            # format. Widen to every file so detection gets something to look
            # at; the caller re-discovers with the detected format's suffixes.
            if not log_list:
                log_list = candidates
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


def _mapped_timestamp_field(
    field: str, config: dict | None, *, raw: bool, path: str | None = None,
) -> str:
    """Map raw timestamp names while preserving conventional flattened names."""
    mapped = (config or {}).get("mappings", {}).get(path or field) if path or raw else None
    return mapped if mapped is not None else _TIMEFIELD_SANITIZE_RE.sub("", field)


def _apply_detection_result(
    args: argparse.Namespace,
    detection: "DetectionResult",
    logger: logging.Logger,
    field_mappings_config: dict | None = None,
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
    # Explicit mappings take precedence over the flattener's name sanitization.
    if detection.timestamp_field and not _is_explicit(args, "timefield", "SystemTime"):
        args.timefield = _mapped_timestamp_field(
            detection.timestamp_field, field_mappings_config,
            raw=detection.timestamp_field_is_raw, path=detection.timestamp_field_path,
        )

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
        # The name can come from the log's own keys, so it is evidence.
        logger.info(f"[+] Auto-detected timestamp field: [cyan]{literal(detection.timestamp_field)}[/]")
    if detection.suggested_pipeline:
        logger.debug(f"    Suggested pipeline: {detection.suggested_pipeline}")

    if detection.confidence == "low":
        logger.warning(
            "[yellow]   [!] Low confidence detection. "
            "Consider using explicit format flags (-j, -x, -S, -AU, etc.)[/]"
        )

    # Apply detection result to args
    input_type = _apply_detection_result(args, detection, logger, field_mappings_config)

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
        logger.error(f"[red]    [-] {literal(e)}[/]")
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
        from zircolite.utils import safe_load

        with open(path, encoding='utf-8') as f:
            raw = safe_load(f) or {}
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
        logger.error(f"[red]    [-] {literal(e)}[/]")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"[red]    [-] Error loading YAML config: {literal(e)}[/]")
        if logger.isEnabledFor(logging.DEBUG):
            console.print_exception(show_locals=False)
        sys.exit(1)

    return args


################################################################
# POST-PROCESSING
################################################################
def _prepare_package(args: argparse.Namespace, rulesets: list[Any], logger: logging.Logger) -> PackageSpool:
    """Check what --package needs before any file is read, then open its spool.

    A missing viewer or a duckdb that cannot write Parquet used to surface
    only after a long run; the package directory is where the spool lives, so
    the final move into place is a rename on one filesystem.
    """
    target = Path(args.package_dir) if args.package_dir else Path(".")
    if args.package_dir and not target.is_dir():
        reason = "is not a directory" if target.exists() else "does not exist"
        quit_on_error(f"[red]    [-] Cannot create the package: {literal(args.package_dir)} {reason}[/]", logger)
    try:
        from zircolite import package
        package.check_duckdb()
        package.find_viewer()
    except (ImportError, PackageError) as exc:
        quit_on_error(f"[red]    [-] Cannot create the package: {literal(exc)}[/]", logger)
    try:
        directory = Path(tempfile.mkdtemp(prefix="tmp-zircolite-package-", dir=target)).resolve()
    except OSError as exc:
        quit_on_error(f"[red]    [-] Cannot create the package: {literal(exc)}[/]", logger)
    return PackageSpool(
        directory=str(directory),
        time_field=args.timefield or "",
        timestamp_format=getattr(args, "timestamp_format", None) or "iso",
        rule_keys=rule_index(rulesets),
    )


def _write_package(ctx: ProcessingContext, args: argparse.Namespace) -> bool:
    """Build the package from the spooled parts. False if it was not written."""
    from zircolite import package
    from zircolite.core import runnable_rules

    spool = ctx.package_spool
    if spool is None:
        ctx.logger.error("[red]    [-] Cannot create the package: no spool was prepared for this run[/]")
        return False
    if ctx.package_errors:
        for error in ctx.package_errors[:5]:
            ctx.logger.error(f"[red]    [-] Cannot create the package: {literal(error)}[/]")
        return False
    if args.db_input:
        mode = "database input"
    elif args.unified_db:
        mode = "unified"
    elif ctx.workers_used > 1:
        mode = "per-file, parallel"
    else:
        mode = "per-file"
    # Database input ignores --after and --before (_warn_ignored_db_flags says so).
    applied = not args.db_input
    run = package.RunInfo(
        zircolite_version=__version__, mode=mode,
        executor=args.executor if ctx.workers_used > 1 else "sequential",
        timestamp_format=spool.timestamp_format,
        after=ctx.time_after_str if applied else None, before=ctx.time_before_str if applied else None,
        limit=ctx.limit, rules_loaded=len(runnable_rules(ctx.rulesets or [], ctx.rule_filters)),
    )
    failed = sorted({source for record in ctx.performance_files if record.get("status") == "failed"
                     for source in record.get("sources") or ()})
    destination = Path(args.package_dir) if args.package_dir else Path(".")
    ctx.logger.info("[+] Building the package")
    try:
        target = package.PackageBuilder(spool, logger=ctx.logger).build(
            viewer=package.find_viewer(), parts=ctx.package_parts, rulesets=ctx.rulesets, run=run,
            failed_sources=failed, expected_events=ctx.total_events, destination=destination)
    except (PackageError, OSError) as exc:
        ctx.logger.error(f"[red]    [-] Cannot create the package: {literal(exc)}[/]")
        return False
    ctx.logger.info(f"[+] Package written to: {make_file_link(str(target))}")
    return True


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
        # A package the user asked for and did not get is a failed run
        succeeded = _write_package(ctx, args) and succeeded
    return succeeded


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
            for field in ("count", "alert_count", "event_count"):
                if field in result or field in existing:
                    existing[field] = existing.get(field, 0) + result.get(field, 0)
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
    outfile: str | None = None,
    performance: dict | None = None,
) -> None:
    """Print final execution statistics with a Rich summary dashboard."""
    memory_tracker.sample()
    peak_memory, _ = memory_tracker.get_stats()
    processing_time = performance["wall_seconds"] if performance else time.time() - start_time

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
    if performance:
        summary_table.add_row("", "[dim]Stage times (summed across workers; stages can overlap):[/]" if workers_used > 1 else "[dim]Stage times:[/]")
        for name, seconds in performance["stage_seconds"].items():
            summary_table.add_row("", f"    [dim]{STAGE_LABELS[name]}: {seconds:.3f}s[/]")
        backends: dict[str, int] = {}
        filters = []
        for record in performance["files"]:
            info = record["flattening"]
            label = f"{info['requested']} → {info['selected']}"
            if info.get("reason"):
                label += f" ({info['reason']})"
            backends[label] = backends.get(label, 0) + 1
            filters.extend(record["prefilter"])
        summary_table.add_row("Flattening", "; ".join(backends) or "unused")
        applied = sum(item.get("applied_queries", 0) for item in filters)
        eligible = sum(item.get("eligible_queries", 0) for item in filters)
        broad = sum(item.get("broad_bypasses", 0) for item in filters)
        reasons = sorted({item["reason"] for item in filters if item.get("reason")}
                         | {reason for item in filters for reason in item.get("skipped_columns", {}).values()})
        summary_table.add_row("Literal filter", f"{applied:,} queries filtered / {eligible:,} eligible; {broad:,} broad bypasses")
        if reasons:
            summary_table.add_row("", "[dim]" + "; ".join(reasons) + "[/]")
        summary_table.add_row("Executor", performance["settings"]["executor_selected"])

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
        memory_label = "Sampled peak RSS" if performance else "💾 Peak Memory"
        scope = " (process tree)" if memory_tracker.complete_scope else " (incomplete process tree)"
        summary_table.add_row(memory_label, f"[cyan]{mem_str}[/]" + (scope if performance else ""))

    # ── Detection summary ──
    if all_results:
        all_results = collapse_results_by_rule(all_results)
        det_stats = DetectionStats()
        for result in all_results:
            level = result.get("rule_level", "unknown")
            count = result.get("count", 0)
            det_stats.add_detection(level, count, alerts=result.get("result_type") == "correlation")

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

        # Total matched events, and correlation alerts, which are not events
        if det_stats.total_events or det_stats.total_alerts:
            matched = []
            if det_stats.total_events:
                matched.append(f"[magenta]{det_stats.total_events:,}[/] events")
            if det_stats.total_alerts:
                matched.append(f"[magenta]{det_stats.total_alerts:,}[/] correlation alerts")
            summary_table.add_row(
                "🔍 Matched",
                f"{' and '.join(matched)} across [cyan]{det_stats.total_rules_matched}[/] rules"
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
    if getattr(args, 'keepflat', False):
        ignored.append("--keepflat")
    if getattr(args, 'dbfile', None):
        ignored.append("--dbfile")
    if getattr(args, 'strict', False):
        ignored.append("--strict")
    # A password taken from the environment was not asked for on this run,
    # so it is not reported as an ignored flag.
    if getattr(args, 'archive_password', None):
        channel = getattr(args, "archive_unlock_channel", "argv")
        if channel == "argv":
            ignored.append("--archive-password")
        elif channel == "prompt":
            ignored.append("--ask-archive-password")
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


def _correlation_rule_count(rulesets: list[dict[str, Any]], rule_filters: list[str] | None) -> int:
    """Correlation rules left once -R has removed the rules it names."""
    return sum(
        1 for rule in rulesets
        if rule.get("correlation") and not any(f in rule.get("title", "") for f in rule_filters or ())
    )


def _warn_correlations_across_databases(count: int, databases: int, logger: logging.Logger) -> None:
    if count and databases > 1:
        logger.warning(
            f"[yellow]   [!] Each of the {databases} databases is analysed on its own: the "
            f"{count} correlation rule(s) do not see events across databases[/]"
        )


def _template_outputs(args: argparse.Namespace) -> list[str]:
    """Every -T path, including the ones --timesketch and --navigator-output add."""
    return [output for spec in args.templateOutput or () for output in spec]


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

    phase_setup_end = time.perf_counter()

    correlations = _correlation_rule_count(ctx.rulesets, getattr(args, "rulefilter", None))

    # ----- DB input mode (explicit -D) -----
    if args.db_input:
        _warn_ignored_db_flags(args, logger)
        db_files = expand_db_path(Path(args.evtx), args, logger)
        check_output_paths(_template_outputs(args), db_files, "Template output")
        _warn_correlations_across_databases(correlations, len(db_files), logger)
        ctx.parent_metrics.data["seconds"]["setup"] += time.perf_counter() - phase_setup_end
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
    if not is_quiet() and not _has_explicit_format_flag(args):
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
                    f"for input format '{input_type}'"
                )

    check_output_paths(_template_outputs(args), file_list, "Template output")
    ctx.time_field = args.timefield
    if ctx.package_spool is not None:
        # Auto-detection may have chosen the time field after the spool was opened.
        ctx.package_spool.time_field = ctx.time_field

    # DB input mode (auto-detected SQLite file)
    if args.db_input:
        _warn_ignored_db_flags(args, logger)
        _warn_correlations_across_databases(correlations, len(file_list), logger)
        ctx.parent_metrics.data["seconds"]["setup"] += time.perf_counter() - phase_setup_end
        zircolite_core, all_results = process_db_input(ctx, args, file_list=file_list)
        return zircolite_core, all_results, log_list, phase_setup_end

    # Auto-select processing mode
    use_parallel = False
    parallel_workers = 1
    stats: dict[str, Any] = {}

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

    # A correlation only sees the events of its database, and per-file and
    # parallel modes give every file a database of its own.
    unified_for_correlations = False
    if correlations and len(file_list) > 1 and not args.unified_db:
        if args.no_auto_mode:
            logger.warning(
                f"[yellow]   [!] --no-auto-mode keeps one database per file, so the {correlations} "
                "correlation rule(s) see one file at a time: add --unified-db to correlate across files[/]"
            )
        else:
            args.unified_db = unified_for_correlations = True
            ignored = [
                flag for flag, applies in (
                    ("--executor process", getattr(args, "executor", None) == "process" and _is_explicit(args, "executor")),
                    ("--parallel-workers", _is_explicit(args, "parallel_workers")),
                ) if applies
            ]
            if ignored:
                logger.warning(
                    f"[yellow]   [!] {' and '.join(ignored)} ignored: correlation rules need "
                    "every file in one database[/]"
                )

    if not args.no_auto_mode and not args.unified_db:
        recommended_mode, reason, stats = analyze_files_and_recommend_mode(
            file_list, getattr(args, "executor", "thread"),
            auto_mode=True, max_workers=getattr(args, "parallel_workers", None),
        )
        forced_workers = getattr(args, 'parallel_workers', None)
        print_mode_recommendation(
            recommended_mode, reason, stats,
            show_parallel=True, forced_workers=forced_workers,
        )
        if recommended_mode == 'unified' and getattr(args, 'executor', 'thread') != 'process':
            args.unified_db = True
        if not args.unified_db and not getattr(args, 'no_parallel', False) and not force_sequential:
            if stats.get('parallel_recommended', False):
                use_parallel = True
                parallel_workers = stats.get('parallel_workers', 1)
            elif forced_workers and forced_workers > 1 and len(file_list) > 1:
                use_parallel = True
                parallel_workers = forced_workers
    elif args.unified_db:
        reason = (
            f"{correlations} correlation rule(s) need every file in one database"
            if unified_for_correlations else "forced"
        )
        logger.info(f"[+] [cyan]Database mode:[/] [green]UNIFIED[/] ({reason})")
        logger.info("")
    else:
        if not getattr(args, 'no_parallel', False) and not force_sequential and len(file_list) > 1:
            _, _, stats = analyze_files_and_recommend_mode(
                file_list, getattr(args, "executor", "thread"),
                auto_mode=False, max_workers=getattr(args, "parallel_workers", None),
            )
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
    if (getattr(args, 'executor', 'thread') == 'process' and len(file_list) > 1
            and not args.unified_db and not args.no_parallel and not force_sequential):
        use_parallel = True
    if use_parallel:
        # The workload analysis sized its worker count for this executor.
        args.executor, executor_reason = stats["executor"], stats["executor_reason"]
        logger.info(f"[+] Executor: {args.executor} ({executor_reason})")
    elif getattr(args, "executor", "thread") == "auto":
        args.executor = "thread"
    extractor = create_extractor(args, logger, input_type)

    if use_parallel and len(file_list) > 1 and getattr(args, "dbfile", None):
        logger.error(
            "[red]    [-] Saving the database to a file (--dbfile) is not supported when "
            "processing multiple files in parallel. Use --unified-db to get a single "
            "database file, or disable parallel with --no-parallel to save one database per file.[/]"
        )
        sys.exit(2)

    ctx.parent_metrics.data["seconds"]["setup"] += time.perf_counter() - phase_setup_end
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
    # PyInstaller workers re-enter the executable; divert them before argparse.
    from multiprocessing import freeze_support
    freeze_support()
    started = time.perf_counter()
    memory_tracker = MemoryTracker()
    try:
        _main(memory_tracker, started)
    finally:
        memory_tracker.stop()
        from zircolite.prefilter import clear_prepared_rules

        clear_prepared_rules()


def _main(memory_tracker, start_time) -> None:
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
    memory_tracker.logger = logger

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
        # A failed update must fail the command: an image build that runs -U
        # would otherwise ship the rulesets it already had.
        sys.exit(0 if updater.run() else 1)

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
    resolve_archive_password(args, logger)

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
                "rules/rules_windows_merged.json",
                "rules", "rules_windows_merged.json",
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
                args.timefield = _mapped_timestamp_field(
                    _detection.timestamp_field, _fm,
                    raw=_detection.timestamp_field_is_raw, path=_detection.timestamp_field_path,
                )

    # Load rulesets (with spinner for visual feedback during pySigma conversion)
    logger.info("[+] Loading ruleset(s)")
    ruleset_config = RulesetConfig(
        ruleset=args.ruleset,
        pipeline=args.pipeline,
        save_ruleset=args.save_ruleset,
        time_field=args.timefield,
        timestamp_format=args.timestamp_format,
        min_level=args.min_level,
    )
    try:
        if not is_quiet():
            with console.status("[bold cyan]Loading and converting rulesets...", spinner="dots"):
                rulesets_manager = RulesetHandler(ruleset_config, logger=logger, list_pipelines_only=args.pipeline_list)
        else:
            rulesets_manager = RulesetHandler(ruleset_config, logger=logger, list_pipelines_only=args.pipeline_list)
    except UnknownPipelineError as e:
        print_error_panel(
            "Unknown Pipeline",
            escape(str(e)),
            f"List installed pipelines with '--pipeline-list'. {e.hint}.",
        )
        sys.exit(2)
    if args.pipeline_list:
        sys.exit(0)
    if _is_explicit(args, "timestamp_format") and not rulesets_manager.yaml_paths:
        logger.warning(
            "[yellow]   [!] --timestamp-format only applies to rules converted from native Sigma "
            "rulesets (YAML): compiled JSON rulesets keep the format they were converted with[/]"
        )

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
            f"CSV output was enabled via {literal(csv_source)}. Use a single ruleset for CSV output."
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

    from zircolite.config import ProcessingConfig

    try:
        processing_options = ProcessingConfig(**{
            name: getattr(args, name) for name in (
                "working_db", "working_db_dir", "sqlite_cache_mib",
                "flatten_backend", "rule_prefilter",
            )
        })
        if processing_options.flatten_backend == "cython":
            from zircolite.streaming import select_flatten_kernel

            select_flatten_kernel("cython")
    except (ValueError, RuntimeError, OSError) as exc:
        quit_on_error(f"[red]    [-] {exc}[/]", logger)

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
            f"The database file '{literal(args.dbfile)}' already exists.",
            "Remove the existing file or choose a different path with --dbfile."
        )
        sys.exit(2)

    # Section separator before processing
    print_section("Processing")

    # The run timer already includes configuration and rule loading. Between
    # phase boundaries memory is sampled only for a report or a process pool.
    if args.performance_json is not None:
        memory_tracker.start()
    else:
        memory_tracker.sample()
    if args.performance_json is not None:
        try:
            report_path = Path(args.performance_json).resolve()
            protected = [args.evtx, args.config, args.yaml_config, args.outfile, args.dbfile, args.logfile]
            protected.extend(flatten_groups(args.ruleset))
            if any(report_path == Path(path).resolve() for path in protected if path):
                raise ValueError("performance report must be separate from inputs, rules and other outputs")
            source = Path(args.evtx).resolve()
            if source.is_dir() and report_path.is_relative_to(source):
                raise ValueError("performance report must be outside the input directory")
            if not report_path.parent.is_dir() or report_path.is_dir():
                raise ValueError("performance report must name a file in an existing directory")
        except (TypeError, ValueError, OSError) as exc:
            quit_on_error(f"Invalid --performance-json: {exc}", logger)

    package_spool = _prepare_package(args, rulesets_manager.rulesets, logger) if args.package else None

    # Handle event filter configuration
    active_event_filter = None
    if args.package:
        # The filter drops events no rule can match; a package explores them all.
        logger.info("[+] Event filtering disabled: --package keeps every event")
    elif not getattr(args, 'no_event_filter', False):
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
        retain_results=ready_for_templating,
        working_db=args.working_db,
        working_db_dir=args.working_db_dir,
        sqlite_cache_mib=args.sqlite_cache_mib,
        flatten_backend=args.flatten_backend,
        rule_prefilter=args.rule_prefilter,
        package_spool=package_spool,
    )

    zircolite_core = None
    log_list: list[Path] | None = None
    all_results: list[Any] = []
    strict_error = None
    templating_ok = True
    processing_failed = False
    report_failed = False
    requested_executor = args.executor
    setup_seconds = time.perf_counter() - start_time
    finalization_seconds = 0.0

    try:
        zircolite_core, all_results, log_list, _phase_setup_end = _run_processing(
            ctx, args, logger
        )

        if not is_shutdown_requested():
            # Print rule profiling report if requested
            if getattr(args, 'profile_rules', False) and zircolite_core is not None:
                from zircolite.console import print_profiling_report
                print_section("Rule Performance")
                print_profiling_report(zircolite_core.get_profiling_report())

            # Handle templating and package generation
            finalization_start = time.perf_counter()
            try:
                templating_ok = handle_templating(ctx, all_results, args)
            finally:
                finalization_seconds += time.perf_counter() - finalization_start
    except OutputPathConflict as exc:
        processing_failed = True
        print_error_panel("Invalid Output Path", literal(exc), "Write the output to a separate file.")
        sys.exit(2)
    except StrictParseError as e:
        strict_error = str(e)
    except KeyboardInterrupt:
        request_shutdown()
    except BaseException:
        processing_failed = True
        raise
    finally:
        finalization_start = time.perf_counter()
        if zircolite_core is not None:
            try:
                zircolite_core.close()
            except Exception as e:
                logger.debug(f"Core close: {e}")
        if package_spool is not None:
            shutil.rmtree(package_spool.directory, ignore_errors=True)
        finalization_seconds += time.perf_counter() - finalization_start
        memory_tracker.stop()
        status = "interrupted" if is_shutdown_requested() else "failed" if strict_error is not None or processing_failed or not templating_ok else "partial" if any(record["status"] in ("partial", "failed", "running") for record in ctx.performance_files) else "complete"
        stages = aggregate_stages([*ctx.performance_files, ctx.parent_metrics.data])
        stages["setup"] += setup_seconds
        stages["finalization"] += finalization_seconds
        peak, average = memory_tracker.get_stats()
        performance = {
            "schema_version": 1, "status": status,
            "wall_seconds": time.perf_counter() - start_time,
            "stage_time_scope": "sum of exclusive stages across workers plus parent stages; workers may overlap",
            "stage_seconds": stages, "files": ctx.performance_files,
            "settings": {"executor_requested": requested_executor,
                         "executor_selected": args.executor if ctx.workers_used > 1 else "sequential",
                         "workers": ctx.workers_used, "flatten_backend": args.flatten_backend,
                         "rule_prefilter": args.rule_prefilter, "working_db": args.working_db},
            "events": ctx.total_events, "filtered_events": ctx.total_filtered_events,
            "time_filtered_events": ctx.total_time_filtered_events,
            "memory": {"sampled_peak_rss_mib": peak, "average_rss_mib": average,
                       "scope": "process-tree", "complete_scope": memory_tracker.complete_scope,
                       "sample_interval_seconds": 0.1},
        }
        if args.performance_json:
            try:
                write_performance_report(args.performance_json, performance)
            except (OSError, ValueError, TypeError) as exc:
                logger.error(f"Could not write performance report: {literal(exc)}")
                report_failed = True

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
        outfile=ctx.outfile if not ctx.no_output else None,
        performance=performance,
    )

    # A template that did not write is a failed run: whatever consumes that file
    # would otherwise read a stale one, or nothing, and call it success
    if not templating_ok or report_failed:
        sys.exit(1)
