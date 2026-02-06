#!python3
"""
Zircolite - Standalone SIGMA-Based Detection Tool for EVTX, Auditd, Sysmon Linux, and more.

This is the main entry point for Zircolite. The core functionality has been modularized into
the zircolite/ package for better maintainability and code organization.

Package structure:
- zircolite/core.py: ZircoliteCore class for database and rule execution
- zircolite/streaming.py: StreamingEventProcessor for single-pass processing
- zircolite/flattener.py: JSONFlattener for log flattening
- zircolite/extractor.py: EvtxExtractor for log format conversion
- zircolite/rules.py: RulesetHandler and RulesUpdater for rule management
- zircolite/templates.py: TemplateEngine and ZircoliteGuiGenerator for output
- zircolite/utils.py: Utility functions and MemoryTracker
"""

# Standard libs
import argparse
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# External libs - Rich for styled terminal output
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn

# Import from package
from zircolite import (
    ZircoliteCore,
    EvtxExtractor,
    RulesetHandler,
    RulesUpdater,
    EventFilter,
    TemplateEngine,
    ZircoliteGuiGenerator,
    MemoryTracker,
    init_logger,
    create_silent_logger,
    quit_on_error,
    check_if_exists,
    select_files,
    avoid_files,
    analyze_files_and_recommend_mode,
    print_mode_recommendation,
    # Config dataclasses
    ProcessingConfig,
    ExtractorConfig,
    RulesetConfig,
    TemplateConfig,
    GuiConfig,
    # Parallel processing
    ParallelConfig,
    MemoryAwareParallelProcessor,
    # YAML configuration
    ConfigLoader,
    create_default_config_file,
    # Rich console
    console,
    DetectionStats,
)


################################################################
# CONFIGURATION AND CONTEXT
################################################################
@dataclass
class ProcessingContext:
    """Holds all configuration needed for processing."""
    config: str
    logger: any
    no_output: bool
    events_after: time.struct_time
    events_before: time.struct_time
    limit: int
    csv_mode: bool
    time_field: str
    hashes: bool
    db_location: str
    delimiter: str
    rulesets: list
    rule_filters: Optional[list]
    outfile: str
    showall: bool
    ready_for_templating: bool
    package: bool
    dbfile: Optional[str]
    keepflat: bool
    memory_tracker: MemoryTracker
    event_filter: Optional[EventFilter] = None


################################################################
# ARGUMENT PARSING
################################################################
def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    
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
    output_formats_args.add_argument("-t", "--tmpdir", "--tmp-dir", help="Temporary directory for JSON-converted events (parent directories must exist)", type=str)
    output_formats_args.add_argument("-k", "--keeptmp", "--keep-tmp", help="Keep the temporary directory with JSON-converted events", action='store_true')
    output_formats_args.add_argument("--keepflat", "--keep-flat", help="Save flattened events as JSON", action='store_true')
    output_formats_args.add_argument("-d", "--dbfile", "--db-file", help="Save all logs to a SQLite database file", type=str)
    output_formats_args.add_argument("-l", "--logfile", "--log-file", help="Log file name", default="zircolite.log", type=str)
    output_formats_args.add_argument("--hashes", help="Add xxhash64 of the original log event to each event", action='store_true')
    output_formats_args.add_argument("-L", "--limit", "--limit-results", help="Discard results exceeding this limit from output file", type=int, default=-1)
    
    # Advanced configuration options
    config_formats_args = parser.add_argument_group('⚙️  ADVANCED CONFIGURATION')  
    config_formats_args.add_argument("-c", "--config", help="JSON or YAML file containing field mappings and exclusions", type=str, default="config/fieldMappings.yaml")
    config_formats_args.add_argument("-LE", "--logs-encoding", help="Specify encoding for Sysmon for Linux or Auditd files", type=str)
    config_formats_args.add_argument("--debug", help="Enable debug logging", action='store_true')
    config_formats_args.add_argument("--showall", "--show-all", help="Show all rules being executed", action='store_true')
    config_formats_args.add_argument("-n", "--nolog", "--no-log", help="Don't create log or result files", action='store_true')
    config_formats_args.add_argument("--ondiskdb", "--on-disk-db", help="Use on-disk database instead of in-memory (slower but uses less RAM)", type=str, default=":memory:")
    config_formats_args.add_argument("-RE", "--remove-events", help="Remove processed log files after successful analysis (use with caution)", action='store_true')
    config_formats_args.add_argument("-U", "--update-rules", help="Update rulesets in the 'rules' directory", action='store_true')
    config_formats_args.add_argument("-v", "--version", help="Display Zircolite version", action='store_true')
    config_formats_args.add_argument("--timefield", "--time-field", help="Specify time field name for time filtering (default: 'SystemTime', auto-detects if not found)", type=str, default="SystemTime")
    config_formats_args.add_argument("--no-streaming", help="Disable streaming mode and use traditional multi-pass processing (for debugging)", action='store_true')
    config_formats_args.add_argument("--unified-db", "--all-in-one", help="Force unified database mode (all files in one DB, enables cross-file correlation)", action='store_true')
    config_formats_args.add_argument("--no-auto-mode", help="Disable automatic processing mode selection based on file analysis", action='store_true')
    
    # YAML configuration file options
    yaml_config_args = parser.add_argument_group('📄 YAML CONFIGURATION FILE')
    yaml_config_args.add_argument("--yaml-config", "-Y", help="YAML configuration file (CLI arguments override file settings)", type=str)
    yaml_config_args.add_argument("--generate-config", help="Generate a default YAML configuration file and exit", type=str, metavar="OUTPUT_FILE")
    
    # Parallel processing options
    parallel_args = parser.add_argument_group('⚡ PARALLEL PROCESSING')
    parallel_args.add_argument("--no-parallel", help="Disable automatic parallel processing (parallel is enabled by default when beneficial)", action='store_true')
    parallel_args.add_argument("--parallel-workers", help="Maximum number of parallel workers (default: auto-detect based on CPU/memory)", type=int)
    parallel_args.add_argument("--parallel-memory-limit", help="Memory usage threshold percentage before throttling (default: 75)", type=float, default=75.0)
    
    # Templating and Mini GUI options
    templating_formats_args = parser.add_argument_group('🎨 TEMPLATING AND MINI GUI')
    templating_formats_args.add_argument("--template", help="Jinja2 template to use for output generation", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("--templateOutput", "--template-output", help="Output file for Jinja2 template results", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("--package", help="Create a ZircoGui/Mini GUI package", action='store_true')
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
    """Determine input type for streaming processor."""
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


def create_extractor(args, logger, input_type: str) -> Optional[EvtxExtractor]:
    """Create extractor for formats that need conversion."""
    if input_type in ('xml', 'sysmon_linux', 'auditd', 'evtxtract'):
        extractor_config = ExtractorConfig(
            xml_logs=args.xml_input,
            sysmon4linux=args.sysmon_linux_input,
            auditd_logs=args.auditd_input,
            evtxtract=args.evtxtract_input,
            csv_input=args.csv_input,
            tmp_dir=args.tmpdir,
            encoding=args.logs_encoding
        )
        return EvtxExtractor(extractor_config, logger=logger)
    return None


################################################################
# ZIRCOLITE CORE FACTORY
################################################################
def create_zircolite_core(ctx: ProcessingContext, db_location: str = None, disable_progress: bool = False) -> ZircoliteCore:
    """Create a ZircoliteCore instance with standard configuration."""
    # Convert time.struct_time to ISO string format for ProcessingConfig
    time_after_str = time.strftime('%Y-%m-%dT%H:%M:%S', ctx.events_after)
    time_before_str = time.strftime('%Y-%m-%dT%H:%M:%S', ctx.events_before)
    
    proc_config = ProcessingConfig(
        time_after=time_after_str,
        time_before=time_before_str,
        time_field=ctx.time_field,
        hashes=ctx.hashes,
        disable_progress=disable_progress,
        db_location=db_location or ctx.db_location,
        no_output=ctx.no_output,
        csv_mode=ctx.csv_mode,
        delimiter=ctx.delimiter,
        limit=ctx.limit
    )
    return ZircoliteCore(ctx.config, proc_config, logger=ctx.logger)


################################################################
# PROCESSING MODES
################################################################
def process_unified_streaming(ctx: ProcessingContext, file_list: List[Path], input_type: str, extractor, args) -> tuple:
    """Process all files into a single database using streaming mode."""
    ctx.logger.info(f"[+] Loading all [yellow]{len(file_list)}[/] file(s) into a single unified database")
    
    disable_nested = len(file_list) > 1
    zircolite_core = create_zircolite_core(ctx, disable_progress=disable_nested)
    
    total_events = zircolite_core.run_streaming(
        file_list,
        input_type=input_type,
        args_config=args,
        extractor=extractor,
        disable_progress=disable_nested,
        event_filter=ctx.event_filter
    )
    ctx.memory_tracker.sample()
    
    if ctx.dbfile:
        zircolite_core.save_db_to_disk(ctx.dbfile)
        ctx.logger.info(f"[+] Saved unified database to: [cyan]{ctx.dbfile}[/]")
        ctx.memory_tracker.sample()
    
    zircolite_core.load_ruleset_from_var(ruleset=ctx.rulesets, rule_filters=ctx.rule_filters)
    
    if ctx.limit > 0:
        ctx.logger.info(f"[+] Limited mode: detections with more than [yellow]{ctx.limit}[/] events will be discarded")
    
    ctx.logger.info(f"[+] Executing ruleset against unified database ([magenta]{total_events:,}[/] events) - [yellow]{len(zircolite_core.ruleset)}[/] rules")
    zircolite_core.execute_ruleset(
        ctx.outfile,
        write_mode='w',
        show_all=ctx.showall,
        keep_results=(ctx.ready_for_templating or ctx.package),
        last_ruleset=True
    )
    ctx.memory_tracker.sample()
    
    results = list(zircolite_core.full_results) if zircolite_core.full_results else []
    ctx.logger.info(f"[+] Results written in: [cyan]{ctx.outfile}[/]")
    
    return zircolite_core, results


def process_perfile_streaming(ctx: ProcessingContext, file_list: List[Path], input_type: str, extractor, args) -> tuple:
    """Process each file separately using streaming mode."""
    ctx.logger.info(f"[+] Processing [yellow]{len(file_list)}[/] file(s) separately in streaming mode")
    
    disable_nested = len(file_list) > 1
    all_results = []
    first_file = True
    
    for file_idx, log_file in enumerate(file_list):
        file_name = Path(log_file).name
        if len(file_list) > 1:
            ctx.logger.info(f"[+] Processing file [cyan]{file_idx + 1}[/]/[cyan]{len(file_list)}[/]: [cyan]{file_name}[/]")
        else:
            ctx.logger.info(f"[+] Processing file: [cyan]{file_name}[/]")
        
        zircolite_core = create_zircolite_core(ctx, db_location=":memory:", disable_progress=disable_nested)
        
        zircolite_core.run_streaming(
            [log_file],
            input_type=input_type,
            args_config=args,
            extractor=extractor,
            disable_progress=disable_nested,
            event_filter=ctx.event_filter
        )
        ctx.memory_tracker.sample()
        
        if ctx.dbfile:
            file_db_name = f"{Path(ctx.dbfile).stem}_{file_name}{Path(ctx.dbfile).suffix}"
            zircolite_core.save_db_to_disk(file_db_name)
            ctx.logger.info(f"[+] Saved database for [cyan]{file_name}[/] to: [cyan]{file_db_name}[/]")
            ctx.memory_tracker.sample()
        
        zircolite_core.load_ruleset_from_var(ruleset=ctx.rulesets, rule_filters=ctx.rule_filters)
        
        if ctx.limit > 0 and first_file:
            ctx.logger.info(f"[+] Limited mode: detections with more than [yellow]{ctx.limit}[/] events will be discarded")
        
        is_last_file = (file_idx == len(file_list) - 1)
        write_mode = 'w' if first_file else 'a'
        
        ctx.logger.info(f"[+] Executing ruleset for [cyan]{file_name}[/] - [yellow]{len(zircolite_core.ruleset)}[/] rules")
        zircolite_core.execute_ruleset(
            ctx.outfile,
            write_mode=write_mode,
            show_all=ctx.showall,
            keep_results=(ctx.ready_for_templating or ctx.package),
            last_ruleset=is_last_file
        )
        ctx.memory_tracker.sample()
        
        if zircolite_core.full_results:
            all_results.extend(zircolite_core.full_results)
        
        zircolite_core.close()
        first_file = False
    
    ctx.logger.info(f"[+] Results written in: [cyan]{ctx.outfile}[/]")
    return None, all_results


def process_unified_traditional(ctx: ProcessingContext, file_list: List[Path], args) -> tuple:
    """Process all files into a single database using traditional mode."""
    ctx.logger.info(f"[+] Loading all [yellow]{len(file_list)}[/] file(s) into a single unified database")
    
    disable_nested = len(file_list) > 1
    zircolite_core = create_zircolite_core(ctx, disable_progress=disable_nested)
    
    zircolite_core.run(file_list, insert_to_db=True, save_to_file=ctx.keepflat, args_config=args, disable_progress=disable_nested, event_filter=ctx.event_filter)
    ctx.memory_tracker.sample()
    
    if ctx.dbfile:
        zircolite_core.save_db_to_disk(ctx.dbfile)
        ctx.logger.info(f"[+] Saved unified database to: [cyan]{ctx.dbfile}[/]")
        ctx.memory_tracker.sample()
    
    zircolite_core.load_ruleset_from_var(ruleset=ctx.rulesets, rule_filters=ctx.rule_filters)
    
    if ctx.limit > 0:
        ctx.logger.info(f"[+] Limited mode: detections with more than [yellow]{ctx.limit}[/] events will be discarded")
    
    ctx.logger.info(f"[+] Executing ruleset against unified database - [yellow]{len(zircolite_core.ruleset)}[/] rules")
    zircolite_core.execute_ruleset(
        ctx.outfile,
        write_mode='w',
        show_all=ctx.showall,
        keep_results=(ctx.ready_for_templating or ctx.package),
        last_ruleset=True
    )
    ctx.memory_tracker.sample()
    
    results = list(zircolite_core.full_results) if zircolite_core.full_results else []
    ctx.logger.info(f"[+] Results written in: [cyan]{ctx.outfile}[/]")
    
    return zircolite_core, results


def process_perfile_traditional(ctx: ProcessingContext, file_list: List[Path], args) -> tuple:
    """Process each file separately using traditional mode."""
    ctx.logger.info(f"[+] Processing [yellow]{len(file_list)}[/] file(s) separately")
    
    disable_nested = len(file_list) > 1
    all_results = []
    first_file = True
    
    for file_idx, json_file in enumerate(file_list):
        file_name = Path(json_file).name
        if len(file_list) > 1:
            ctx.logger.info(f"[+] Processing file [cyan]{file_idx + 1}[/]/[cyan]{len(file_list)}[/]: [cyan]{file_name}[/]")
        else:
            ctx.logger.info(f"[+] Processing file: [cyan]{file_name}[/]")
        
        zircolite_core = create_zircolite_core(ctx, db_location=":memory:", disable_progress=disable_nested)
        
        zircolite_core.run([json_file], insert_to_db=True, save_to_file=ctx.keepflat, args_config=args, disable_progress=disable_nested, event_filter=ctx.event_filter)
        ctx.memory_tracker.sample()
        
        if ctx.dbfile:
            file_db_name = f"{Path(ctx.dbfile).stem}_{file_name}{Path(ctx.dbfile).suffix}"
            zircolite_core.save_db_to_disk(file_db_name)
            ctx.logger.info(f"[+] Saved database for [cyan]{file_name}[/] to: [cyan]{file_db_name}[/]")
            ctx.memory_tracker.sample()
        
        zircolite_core.load_ruleset_from_var(ruleset=ctx.rulesets, rule_filters=ctx.rule_filters)
        
        if ctx.limit > 0 and first_file:
            ctx.logger.info(f"[+] Limited mode: detections with more than [yellow]{ctx.limit}[/] events will be discarded")
        
        is_last_file = (file_idx == len(file_list) - 1)
        write_mode = 'w' if first_file else 'a'
        
        ctx.logger.info(f"[+] Executing ruleset for [cyan]{file_name}[/] - [yellow]{len(zircolite_core.ruleset)}[/] rules")
        zircolite_core.execute_ruleset(
            ctx.outfile,
            write_mode=write_mode,
            show_all=ctx.showall,
            keep_results=(ctx.ready_for_templating or ctx.package),
            last_ruleset=is_last_file
        )
        ctx.memory_tracker.sample()
        
        if zircolite_core.full_results:
            all_results.extend(zircolite_core.full_results)
        
        zircolite_core.close()
        first_file = False
    
    ctx.logger.info(f"[+] Results written in: [cyan]{ctx.outfile}[/]")
    return None, all_results


def process_db_input(ctx: ProcessingContext, args) -> tuple:
    """Process from an existing database file."""
    ctx.logger.info(f"[+] Creating model from disk: [cyan]{args.evtx}[/]")
    
    zircolite_core = create_zircolite_core(ctx)
    zircolite_core.load_db_in_memory(args.evtx)
    ctx.memory_tracker.sample()
    
    zircolite_core.load_ruleset_from_var(ruleset=ctx.rulesets, rule_filters=ctx.rule_filters)
    
    if ctx.limit > 0:
        ctx.logger.info(f"[+] Limited mode: detections with more than [yellow]{ctx.limit}[/] events will be discarded")
    
    ctx.logger.info(f"[+] Executing ruleset - [yellow]{len(zircolite_core.ruleset)}[/] rules")
    zircolite_core.execute_ruleset(
        ctx.outfile,
        write_mode='w',
        show_all=ctx.showall,
        keep_results=(ctx.ready_for_templating or ctx.package),
        last_ruleset=True
    )
    ctx.memory_tracker.sample()
    
    results = list(zircolite_core.full_results) if zircolite_core.full_results else []
    ctx.logger.info(f"[+] Results written in: [cyan]{ctx.outfile}[/]")
    
    return zircolite_core, results


################################################################
# PARALLEL PROCESSING MODE
################################################################
def create_worker_core(ctx: ProcessingContext, worker_id: int) -> ZircoliteCore:
    """Create a ZircoliteCore instance with a silent logger for parallel workers."""
    # Create a silent logger for this worker to avoid interleaved output
    silent_logger = create_silent_logger(f'zircolite_worker_{worker_id}')
    
    # Convert time.struct_time to ISO string format for ProcessingConfig
    time_after_str = time.strftime('%Y-%m-%dT%H:%M:%S', ctx.events_after)
    time_before_str = time.strftime('%Y-%m-%dT%H:%M:%S', ctx.events_before)
    
    proc_config = ProcessingConfig(
        time_after=time_after_str,
        time_before=time_before_str,
        time_field=ctx.time_field,
        hashes=ctx.hashes,
        disable_progress=True,
        db_location=":memory:",
        no_output=True,  # Workers don't write output directly
        csv_mode=ctx.csv_mode,
        delimiter=ctx.delimiter,
        limit=ctx.limit
    )
    return ZircoliteCore(ctx.config, proc_config, logger=silent_logger)


def process_parallel_streaming(ctx: ProcessingContext, file_list: List[Path], input_type: str, extractor, args, recommended_workers: int = None) -> tuple:
    """Process files in parallel using memory-aware parallel processor."""
    import threading
    
    # Create parallel config from args
    parallel_config = ParallelConfig(
        max_workers=getattr(args, 'parallel_workers', None) or recommended_workers,
        memory_limit_percent=getattr(args, 'parallel_memory_limit', 75.0),
        use_processes=False,  # Always use threads (process-based doesn't work well)
        adaptive_workers=True
    )
    
    # Double-check viability (should already be checked by heuristics)
    if len(file_list) < 2:
        return process_perfile_streaming(ctx, file_list, input_type, extractor, args)
    
    # Thread-local storage for ZircoliteCore instances
    thread_local = threading.local()
    worker_counter = [0]  # Use list for mutable counter across closures
    counter_lock = threading.Lock()
    all_results = []
    errors = []  # Collect errors for later reporting
    total_filtered_count = [0]  # Track filtered events across all workers
    
    def get_thread_core():
        """Get or create a ZircoliteCore instance for this thread."""
        if not hasattr(thread_local, 'core'):
            with counter_lock:
                worker_id = worker_counter[0]
                worker_counter[0] += 1
            thread_local.core = create_worker_core(ctx, worker_id)
        return thread_local.core
    
    def process_single_file(log_file: Path) -> tuple:
        """Process a single file and return (event_count, results)."""
        try:
            # Get thread-local core (with silent logger)
            core = get_thread_core()
            
            # Clear previous data by recreating the database
            core.db_connection.execute("DROP TABLE IF EXISTS logs")
            core._cursor = None
            
            # Process file (silently)
            event_count, filtered_count = core.run_streaming(
                [log_file],
                input_type=input_type,
                args_config=args,
                extractor=extractor,
                disable_progress=True,
                event_filter=ctx.event_filter,
                return_filtered_count=True
            )
            
            # Aggregate filtered count
            with counter_lock:
                total_filtered_count[0] += filtered_count
            
            if event_count == 0:
                return (0, [])
            
            # Load and execute ruleset
            core.load_ruleset_from_var(ruleset=ctx.rulesets, rule_filters=ctx.rule_filters)
            core.full_results = []  # Clear previous results
            core.first_json_output = True
            
            # Execute rules (silently, don't write to file)
            core.execute_ruleset(
                ctx.outfile,
                write_mode='w',
                show_all=False,
                keep_results=True,
                last_ruleset=True
            )
            
            file_results = list(core.full_results) if core.full_results else []
            
            return (event_count, file_results)
            
        except Exception as e:
            # Store error for later - don't log during parallel processing
            errors.append((Path(log_file).name, str(e)))
            return (0, [])
    
    # Create parallel processor
    processor = MemoryAwareParallelProcessor(config=parallel_config, logger=ctx.logger)
    
    # Process files in parallel
    results_list, stats = processor.process_files_parallel(
        file_list,
        process_single_file,
        desc="Processing",
        disable_progress=False
    )
    
    # Report any errors that occurred
    if errors:
        ctx.logger.error(f"[!] {len(errors)} file(s) failed to process:")
        for fname, err in errors[:3]:
            ctx.logger.error(f"    → {fname}: {err}")
        if len(errors) > 3:
            ctx.logger.error(f"    → ... and {len(errors) - 3} more")
    
    # Collect all results (event counts are tracked in stats.total_events)
    for file_results in results_list:
        if file_results:
            all_results.extend(file_results)
    
    ctx.memory_tracker.sample()
    
    # Display detection results summary (aggregate by rule title)
    if all_results:
        ctx.logger.info(f"[+] Executing ruleset - [yellow]{len(ctx.rulesets)}[/] rules")
        
        # Aggregate results by rule title
        rule_summary = {}
        for result in all_results:
            title = result.get("title", "Unknown Rule")
            level = result.get("rule_level", "unknown")
            count = result.get("count", 0)
            
            if title in rule_summary:
                rule_summary[title]["count"] += count
            else:
                rule_summary[title] = {"level": level, "count": count}
        
        # Level priority for sorting (critical first, informational last)
        level_priority = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "informational": 4,
        }
        
        # Sort by level priority, then by count (descending)
        def sort_key(item):
            title, info = item
            level = info["level"].lower()
            priority = level_priority.get(level, 5)  # Unknown levels at the end
            return (priority, -info["count"])  # Negative count for descending order
        
        # Display each rule's detections (same format as non-parallel mode)
        for title, info in sorted(rule_summary.items(), key=sort_key):
            level = info["level"]
            count = info["count"]
            # Format level with color using Rich markup
            level_styles = {
                "critical": "bold white on red",
                "high": "bold magenta",
                "medium": "bold yellow",
                "low": "green",
                "informational": "dim",
            }
            level_style = level_styles.get(level.lower(), "cyan")
            ctx.logger.info(f'[cyan]    • {title} [[{level_style}]{level}[/][cyan]] : [magenta]{count:,}[/cyan] events[/]')
    
    # Display filtered events statistics after detection results
    total_events = stats.total_events
    filtered_count = total_filtered_count[0]
    if filtered_count > 0:
        ctx.logger.info(
            f"[+] Total events processed: [magenta]{total_events:,}[/] "
            f"([dim]{filtered_count:,} events filtered out[/])"
        )
    
    # Write combined results to output file
    if all_results and not ctx.no_output:
        import orjson as json
        with open(ctx.outfile, 'w', encoding='utf-8') as f:
            f.write('[')
            for i, result in enumerate(all_results):
                if i > 0:
                    f.write(',\n')
                json_bytes = json.dumps(result, option=json.OPT_INDENT_2)
                f.write(json_bytes.decode('utf-8'))
            f.write(']')
    
    ctx.logger.info(f"[+] Results written in: [cyan]{ctx.outfile}[/]")
    
    return None, all_results


def load_yaml_config_and_merge(args, logger) -> argparse.Namespace:
    """Load YAML config file and merge with CLI arguments."""
    if not args.yaml_config:
        return args
    
    try:
        config_loader = ConfigLoader(logger=logger)
        yaml_config = config_loader.load(args.yaml_config)
        
        # Validate configuration
        issues = config_loader.validate_config(yaml_config)
        if issues:
            for issue in issues:
                logger.warning(f"[yellow]   [!] Config warning: {issue}[/]")
        
        # Merge with CLI args (CLI takes precedence)
        yaml_config = config_loader.merge_with_args(yaml_config, args)
        
        # Apply YAML config back to args namespace for compatibility
        # Input settings
        if yaml_config.input.path and not args.evtx:
            args.evtx = yaml_config.input.path
        
        # Set input format flags based on YAML config
        if not any([args.json_input, args.json_array_input, args.xml_input, 
                    args.csv_input, args.sysmon_linux_input, args.auditd_input, args.evtxtract_input]):
            format_map = {
                'json': 'json_input',
                'json_array': 'json_array_input',
                'xml': 'xml_input',
                'csv': 'csv_input',
                'sysmon_linux': 'sysmon_linux_input',
                'auditd': 'auditd_input',
                'evtxtract': 'evtxtract_input'
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
        
        # Rules settings
        if not args.ruleset or args.ruleset == ["rules/rules_windows_generic_pysigma.json"]:
            args.ruleset = yaml_config.rules.rulesets
        if yaml_config.rules.pipelines and not args.pipeline:
            args.pipeline = [[p] for p in yaml_config.rules.pipelines]
        if yaml_config.rules.filters and not args.rulefilter:
            args.rulefilter = [[f] for f in yaml_config.rules.filters]
        if yaml_config.rules.save_ruleset:
            args.save_ruleset = True
        
        # Output settings
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
        
        # Processing settings
        if not yaml_config.processing.streaming:
            args.no_streaming = True
        if yaml_config.processing.unified_db:
            args.unified_db = True
        if not yaml_config.processing.auto_mode:
            args.no_auto_mode = True
        if yaml_config.processing.on_disk_db:
            args.ondiskdb = yaml_config.processing.on_disk_db
        if yaml_config.processing.hashes:
            args.hashes = True
        if yaml_config.processing.limit != -1:
            args.limit = yaml_config.processing.limit
        if yaml_config.processing.time_field != 'SystemTime':
            args.timefield = yaml_config.processing.time_field
        if yaml_config.processing.show_all:
            args.showall = True
        if yaml_config.processing.debug:
            args.debug = True
        if yaml_config.processing.remove_events:
            args.remove_events = True
        if yaml_config.processing.keep_tmp:
            args.keeptmp = True
        if yaml_config.processing.tmp_dir:
            args.tmpdir = yaml_config.processing.tmp_dir
        
        # Time filter settings
        if yaml_config.time_filter.after != '1970-01-01T00:00:00':
            args.after = yaml_config.time_filter.after
        if yaml_config.time_filter.before != '9999-12-12T23:59:59':
            args.before = yaml_config.time_filter.before
        
        # Parallel processing settings
        if yaml_config.parallel.enabled is False:
            args.no_parallel = True
        if yaml_config.parallel.max_workers:
            args.parallel_workers = yaml_config.parallel.max_workers
        if yaml_config.parallel.memory_limit_percent != 75.0:
            args.parallel_memory_limit = yaml_config.parallel.memory_limit_percent
        # Note: use_processes is deprecated and ignored
        
        logger.info(f"[+] Configuration loaded and merged from: [cyan]{args.yaml_config}[/]")
        
    except FileNotFoundError as e:
        logger.error(f"[red]   [-] {e}[/]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"[red]   [-] Error loading YAML config: {e}[/]")
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


def cleanup(args, extractor, use_streaming: bool, logger, log_list=None):
    """Clean up temporary files and optionally remove original events."""
    if not args.keeptmp:
        logger.info("[+] Cleaning")
        try:
            if extractor is not None and not use_streaming:
                extractor.cleanup()
        except (OSError, AttributeError, NameError) as e:
            logger.debug(f"   [-] Cleanup not needed or error: {e}")
    
    if args.remove_events and log_list:
        for evtx in log_list:
            try:
                os.remove(evtx)
            except OSError as e:
                logger.error(f"[red]   [-] Cannot remove file {e}[/]")


def print_stats(memory_tracker: MemoryTracker, start_time: float, logger, 
                all_results: list = None, files_processed: int = 0, 
                total_events: int = 0, workers_used: int = 1):
    """Print final execution statistics with a Rich summary dashboard."""
    memory_tracker.sample()
    peak_memory, avg_memory = memory_tracker.get_stats()
    processing_time = time.time() - start_time
    
    # Build summary table
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Metric", style="dim")
    summary_table.add_column("Value", style="bold")
    
    # Time
    if processing_time >= 60:
        time_str = f"{int(processing_time // 60)}m {int(processing_time % 60)}s"
    else:
        time_str = f"{processing_time:.1f}s"
    summary_table.add_row("⏱  Duration", f"[yellow]{time_str}[/]")
    
    # Files
    if files_processed > 0:
        summary_table.add_row("📁 Files", f"[cyan]{files_processed:,}[/]")
    
    # Events
    if total_events > 0:
        summary_table.add_row("📊 Events", f"[magenta]{total_events:,}[/]")
    
    # Throughput
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
    
    # Detection summary by severity
    if all_results:
        det_stats = DetectionStats()
        for result in all_results:
            level = result.get("rule_level", "unknown")
            count = result.get("count", 0)
            det_stats.add_detection(level, count)
        
        detection_parts = []
        if det_stats.critical > 0:
            detection_parts.append(f"[bold white on red]{det_stats.critical} CRIT[/]")
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
        
        # Total matched events
        if det_stats.total_events > 0:
            summary_table.add_row(
                "🔍 Matched", 
                f"[magenta]{det_stats.total_events:,}[/] events across [cyan]{det_stats.total_rules_matched}[/] rules"
            )
    
    # Print panel
    console.print()
    panel = Panel(
        summary_table,
        title="[bold]✨ Summary[/]",
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(panel)


################################################################
# MAIN
################################################################
def main():
    version = "3.0.2"
    args = parse_arguments()

    # Handle generate-config before logging setup
    if args.generate_config:
        create_default_config_file(args.generate_config)
        sys.exit(0)

    # Init logging
    if args.nolog: 
        args.logfile = None
    logger = init_logger(args.debug, args.logfile)

    # Print Rich banner
    banner = """
[bold cyan]███████╗██╗██████╗  ██████╗ ██████╗ ██╗     ██╗████████╗███████╗[/]
[cyan]╚══███╔╝██║██╔══██╗██╔════╝██╔═══██╗██║     ██║╚══██╔══╝██╔════╝[/]
[bold blue]  ███╔╝ ██║██████╔╝██║     ██║   ██║██║     ██║   ██║   █████╗[/]
[blue] ███╔╝  ██║██╔══██╗██║     ██║   ██║██║     ██║   ██║   ██╔══╝[/]
[bold magenta]███████╗██║██║  ██║╚██████╗╚██████╔╝███████╗██║   ██║   ███████╗[/]
[magenta]╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝[/]
[dim]-= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-[/]
"""
    console.print(banner)
    console.print(f"                              [dim]v{version}[/]\n")

    # Handle special commands
    if args.version: 
        logger.info(f"Zircolite - v{version}")
        sys.exit(0)

    if args.update_rules:
        logger.info("[+] Updating rules")
        RulesUpdater(logger=logger).run()
        sys.exit(0)
    
    # Load YAML configuration if provided
    if args.yaml_config:
        args = load_yaml_config_and_merge(args, logger)

    # Handle rulesets
    if args.ruleset:
        args.ruleset = [item for sublist in args.ruleset for item in sublist]
    else: 
        args.ruleset = ["rules/rules_windows_generic_pysigma.json"]

    # Load rulesets
    logger.info("[+] Loading ruleset(s)")
    ruleset_config = RulesetConfig(
        ruleset=args.ruleset,
        pipeline=args.pipeline,
        save_ruleset=args.save_ruleset
    )
    rulesets_manager = RulesetHandler(ruleset_config, logger=logger, list_pipelines_only=args.pipeline_list)
    if args.pipeline_list:
        sys.exit(0)

    # Validate required arguments
    if not args.evtx: 
        logger.error("[red]   [-] No events source path provided. Use '-e <PATH TO LOGS>', '--events <PATH TO LOGS>'[/]")
        sys.exit(2)
    if args.csv and len(args.ruleset) > 1: 
        logger.error("[red]   [-] Since fields in results can change between rulesets, it is not possible to have CSV output when using multiple rulesets[/]")
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

    # Check on-disk DB doesn't already exist
    if args.ondiskdb != ":memory:" and Path(args.ondiskdb).is_file():
        quit_on_error("[red]   [-] On-disk database already exists[/]", logger)

    # Flatten rule filters
    if args.rulefilter: 
        args.rulefilter = [item for sublist in args.rulefilter for item in sublist]

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
        db_location=args.ondiskdb if args.ondiskdb != ":memory:" else ":memory:",
        delimiter=args.csv_delimiter,
        rulesets=rulesets_manager.rulesets,
        rule_filters=args.rulefilter,
        outfile=args.outfile,
        showall=args.showall,
        ready_for_templating=ready_for_templating,
        package=args.package,
        dbfile=args.dbfile,
        keepflat=args.keepflat,
        memory_tracker=memory_tracker,
        event_filter=active_event_filter
    )

    # Initialize tracking variables
    zircolite_core = None
    extractor = None
    use_streaming = False
    log_list = None
    all_results = []

    # Process based on input mode
    if args.db_input:
        # DB input mode
        zircolite_core, all_results = process_db_input(ctx, args)
    else:
        # File input mode
        check_if_exists(args.config, "[red]   [-] Cannot find mapping file, you can get the default one here : https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json [/]", logger)
        
        file_list = discover_files(args, logger)
        log_list = file_list  # Keep reference for cleanup
        
        # Auto-select processing mode (database mode + parallel processing)
        use_parallel = False
        parallel_workers = 1
        
        if not args.no_auto_mode and not args.unified_db:
            recommended_mode, reason, stats = analyze_files_and_recommend_mode(file_list, logger)
            print_mode_recommendation(recommended_mode, reason, stats, logger, show_parallel=True)
            
            if recommended_mode == 'unified':
                args.unified_db = True
            
            # Check parallel recommendation (only for per-file mode)
            if not args.unified_db and not getattr(args, 'no_parallel', False):
                if stats.get('parallel_recommended', False):
                    use_parallel = True
                    parallel_workers = stats.get('parallel_workers', 1)
        elif args.unified_db:
            logger.info("[+] [cyan]Database mode:[/] [green]UNIFIED[/] (forced)")
            logger.info("")
        else:
            # Manual per-file mode, check if we should enable parallel
            if not getattr(args, 'no_parallel', False) and len(file_list) > 1:
                _, _, stats = analyze_files_and_recommend_mode(file_list, logger)
                if stats.get('parallel_recommended', False):
                    use_parallel = True
                    parallel_workers = stats.get('parallel_workers', 1)
        
        # Determine streaming mode
        use_streaming = not args.no_streaming and not args.keepflat
        
        if use_streaming:
            input_type = get_input_type(args)
            extractor = create_extractor(args, logger, input_type)
            
            if use_parallel and not args.unified_db and len(file_list) > 1:
                # Parallel processing (only for per-file mode)
                zircolite_core, all_results = process_parallel_streaming(ctx, file_list, input_type, extractor, args, parallel_workers)
            elif args.unified_db:
                zircolite_core, all_results = process_unified_streaming(ctx, file_list, input_type, extractor, args)
            else:
                zircolite_core, all_results = process_perfile_streaming(ctx, file_list, input_type, extractor, args)
        else:
            logger.info("[+] Using traditional mode (multi-pass processing)")
            
            # Extract events if needed
            if args.json_input or args.json_array_input:
                log_json_list = file_list
            else:
                extractor_config = ExtractorConfig(
                    xml_logs=args.xml_input,
                    sysmon4linux=args.sysmon_linux_input,
                    auditd_logs=args.auditd_input,
                    evtxtract=args.evtxtract_input,
                    csv_input=args.csv_input,
                    tmp_dir=args.tmpdir,
                    encoding=args.logs_encoding
                )
                extractor = EvtxExtractor(extractor_config, logger=logger)
                
                logger.info(f"[+] Extracting events using '[cyan]{extractor.tmpDir}[/]' directory")
                
                # Use Rich progress bar for extraction
                extract_progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    MofNCompleteColumn(),
                    TextColumn("•"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                )
                with extract_progress:
                    task_id = extract_progress.add_task("Extracting", total=len(file_list))
                    for evtx in file_list:
                        extractor.run(evtx)
                        memory_tracker.sample()
                        extract_progress.update(task_id, advance=1)
                    
                log_json_list = list(Path(extractor.tmpDir).rglob("*.json"))
                memory_tracker.sample()
            
            if not log_json_list:
                quit_on_error("[red]   [-] No files containing logs found.[/]", logger)
            
            if args.unified_db:
                zircolite_core, all_results = process_unified_traditional(ctx, log_json_list, args)
            else:
                zircolite_core, all_results = process_perfile_traditional(ctx, log_json_list, args)

    # Handle templating and package generation
    handle_templating(ctx, all_results, args)

    # Cleanup
    cleanup(args, extractor, use_streaming, logger, log_list)

    # Close database connection
    if zircolite_core is not None:
        zircolite_core.close()
    
    # Print final stats with summary dashboard
    files_processed = len(log_list) if log_list else 1
    print_stats(
        memory_tracker, 
        start_time, 
        logger,
        all_results=all_results,
        files_processed=files_processed
    )


if __name__ == "__main__":
    main()
