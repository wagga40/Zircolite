"""
Zircolite - Standalone SIGMA-Based Detection Tool for EVTX, Auditd, Sysmon Linux, and more.

This package provides modular components for log processing and SIGMA rule detection:

Modules:
- assets: Resolution of the shipped config/, rules/, templates/ and gui/
- attack: MITRE ATT&CK technique and tactic IDs from Sigma tags
- config: Configuration dataclasses for all components
- config_loader: YAML configuration file support
- console: Rich output -- theme, detection tables, ATT&CK panels, reports
- core: ZircoliteCore class for database and rule execution
- detector: LogTypeDetector for format, log source and timestamp detection
- event_filter: EventFilter, the early per-channel event filter
- extractor: EvtxExtractor for log format conversion
- formats: The input-format registry every format switch reads from
- parallel: Memory-aware parallel file processing
- processing: Per-file, unified and parallel run coordination
- rules: RulesetHandler and RulesUpdater for rule management
- run_config: SETTINGS -- one row per option: YAML key, default, merge rule
- shutdown: Graceful Ctrl+C handling
- sqlscan: Quote-aware rule-SQL reader and OR-chain depth repair
- streaming: StreamingEventProcessor for single-pass processing
- templates: TemplateEngine for output generation
- utils: Utility functions and MemoryTracker
- cli: The command line interface, reached through zircolite.py or `python -m`

`cli` is deliberately not imported below. It consumes this module, so
re-exporting it would put it inside the package's own import graph, and mypy
then resolves `from zircolite import console` to the submodule rather than to
the Console object defined in it -- ten errors that describe nothing real.

`rules` and `templates` load on first use: they bring in pySigma, requests and
Jinja2, which a process worker unpickling its context never needs.
"""

import importlib
import logging
from typing import TYPE_CHECKING, Any

from .config import (
    ExtractorConfig,
    ProcessingConfig,
    RulesetConfig,
    TemplateConfig,
)
from .config_loader import (
    ConfigLoader,
    InputConfig,
    OutputConfig,
    ParallelProcessingConfig,
    TimeFilterConfig,
    ZircoliteConfig,
    create_default_config_file,
)
from .console import (
    LEVEL_PRIORITY,
    DetectionStats,
    build_attack_summary,
    build_detection_table,
    build_file_tree,
    console,
    get_rich_logger,
    is_quiet,
    # Live display helpers
    make_detection_counter,
    make_file_link,
    # Severity badges
    make_severity_badge,
    # Banner
    print_banner,
    print_error_panel,
    print_no_detections,
    # Section separators & panels
    print_section,
    # Quiet mode
    set_quiet_mode,
)
from .core import ZircoliteCore
from .detector import (
    DetectionResult,
    LogTypeDetector,
)
from .event_filter import EventFilter
from .extractor import EvtxExtractor
from .formats import (
    DEFAULT_INPUT_FORMAT,
    INPUT_FORMATS,
    NON_WINDOWS_INPUT_FLAGS,
    YAML_INPUT_FORMATS,
    InputFormat,
    format_by_name,
    format_by_yaml,
    format_from_args,
    has_explicit_format,
    is_valid_yaml_format,
)
from .parallel import (
    MemoryAwareParallelProcessor,
    ParallelConfig,
    ParallelStats,
    calculate_optimal_workers,
)
from .processing import (
    ProcessingContext,
    create_extractor,
    create_worker_core,
    create_zircolite_core,
    process_db_input,
    process_parallel_streaming,
    process_perfile_streaming,
    process_single_file_worker,
    process_unified_streaming,
)
from .streaming import StreamingEventProcessor, StrictParseError
from .utils import (
    MemoryTracker,
    analyze_files_and_recommend_mode,
    avoid_files,
    check_if_exists,
    create_silent_logger,
    format_size,
    init_logger,
    load_field_mappings,
    open_maybe_compressed,
    print_mode_recommendation,
    quit_on_error,
    select_files,
)

if TYPE_CHECKING:
    from .rules import RulesetHandler, RulesUpdater, UnknownPipelineError
    from .templates import TemplateEngine

_LAZY_EXPORTS = {
    "RulesetHandler": ".rules",
    "RulesUpdater": ".rules",
    "UnknownPipelineError": ".rules",
    "TemplateEngine": ".templates",
}


def __getattr__(name: str) -> Any:
    module = _LAZY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module, __name__), name)
    globals()[name] = value
    return value


# Configure NullHandler for library-safe logging
# This prevents "No handler found" warnings when the package is used as a library
# without explicit logging configuration by the consuming application
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'DEFAULT_INPUT_FORMAT',
    'INPUT_FORMATS',
    # Severity ordering
    'LEVEL_PRIORITY',
    'NON_WINDOWS_INPUT_FLAGS',
    'YAML_INPUT_FORMATS',
    # YAML configuration
    'ConfigLoader',
    'DetectionResult',
    'DetectionStats',
    'EventFilter',
    'EvtxExtractor',
    'ExtractorConfig',
    'InputConfig',
    # Input format registry
    'InputFormat',
    # Log type detection
    'LogTypeDetector',
    'MemoryAwareParallelProcessor',
    'MemoryTracker',
    'OutputConfig',
    # Parallel processing
    'ParallelConfig',
    'ParallelProcessingConfig',
    'ParallelStats',
    # Configuration dataclasses
    'ProcessingConfig',
    # Processing context & modes
    'ProcessingContext',
    'RulesUpdater',
    'RulesetConfig',
    'RulesetHandler',
    'StreamingEventProcessor',
    'StrictParseError',
    'TemplateConfig',
    'TemplateEngine',
    'TimeFilterConfig',
    'UnknownPipelineError',
    'ZircoliteConfig',
    # Core classes
    'ZircoliteCore',
    'analyze_files_and_recommend_mode',
    'avoid_files',
    'build_attack_summary',
    'build_detection_table',
    'build_file_tree',
    'calculate_optimal_workers',
    'check_if_exists',
    # Rich console output
    'console',
    'create_default_config_file',
    'create_extractor',
    'create_silent_logger',
    'create_worker_core',
    'create_zircolite_core',
    'format_by_name',
    'format_by_yaml',
    'format_from_args',
    'format_size',
    'get_rich_logger',
    'has_explicit_format',
    # Utility functions
    'init_logger',
    'is_quiet',
    'is_valid_yaml_format',
    'load_field_mappings',
    # Live display helpers
    'make_detection_counter',
    'make_file_link',
    # Severity badges
    'make_severity_badge',
    'open_maybe_compressed',
    # Banner
    'print_banner',
    'print_error_panel',
    'print_mode_recommendation',
    'print_no_detections',
    # Section separators & panels
    'print_section',
    'process_db_input',
    'process_parallel_streaming',
    'process_perfile_streaming',
    'process_single_file_worker',
    'process_unified_streaming',
    'quit_on_error',
    'select_files',
    # Quiet mode
    'set_quiet_mode',
]

__version__ = "4.5.0"
