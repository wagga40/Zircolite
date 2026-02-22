#!python3
"""
Zircolite - Standalone SIGMA-Based Detection Tool for EVTX, Auditd, Sysmon Linux, and more.

This package provides modular components for log processing and SIGMA rule detection:

Modules:
- config: Configuration dataclasses for all components
- core: ZircoliteCore class for database and rule execution
- streaming: StreamingEventProcessor for single-pass processing
- extractor: EvtxExtractor for log format conversion
- rules: RulesetHandler and RulesUpdater for rule management
- templates: TemplateEngine and ZircoliteGuiGenerator for output generation
- utils: Utility functions and MemoryTracker
- parallel: Memory-aware parallel file processing
- config_loader: YAML configuration file support
"""

import logging

from .config import (
    ProcessingConfig,
    ExtractorConfig,
    RulesetConfig,
    TemplateConfig,
    GuiConfig,
)
from .core import ZircoliteCore
from .streaming import StreamingEventProcessor
from .extractor import EvtxExtractor
from .rules import RulesetHandler, RulesUpdater, EventFilter
from .templates import TemplateEngine, ZircoliteGuiGenerator
from .utils import (
    init_logger,
    create_silent_logger,
    quit_on_error,
    check_if_exists,
    select_files,
    avoid_files,
    MemoryTracker,
    format_size,
    analyze_files_and_recommend_mode,
    print_mode_recommendation,
    load_field_mappings,
)
from .processing import (
    ProcessingContext,
    create_zircolite_core,
    create_worker_core,
    create_extractor,
    process_unified_streaming,
    process_perfile_streaming,
    process_db_input,
    process_parallel_streaming,
    process_single_file_worker,
)
from .console import (
    console,
    ZircoliteConsole,
    RichProgressTracker,
    DetectionStats,
    ProcessingStats,
    get_rich_logger,
    format_level,
    LEVEL_PRIORITY,
    LEVEL_STYLES,
    # Quiet mode
    set_quiet_mode,
    is_quiet,
    # Banner
    print_banner,
    # Section separators & panels
    print_section,
    print_error_panel,
    print_no_detections,
    # Severity badges
    make_severity_badge,
    # Live display helpers
    make_detection_counter,
    build_file_tree,
    build_attack_summary,
    build_detection_table,
    make_file_link,
    # CLI helper functions
    print_step,
    print_substep,
    print_info,
    print_success,
    print_warning,
    print_error,
    print_file,
    print_count,
    print_detection,
)
from .parallel import (
    ParallelConfig,
    ParallelStats,
    MemoryAwareParallelProcessor,
    process_files_with_memory_awareness,
    estimate_parallel_viability,
    calculate_optimal_workers,
)
from .detector import (
    LogTypeDetector,
    DetectionResult,
)
from .config_loader import (
    ConfigLoader,
    ZircoliteConfig,
    InputConfig,
    RulesConfig as YamlRulesConfig,
    OutputConfig,
    TimeFilterConfig,
    ParallelProcessingConfig,
    create_default_config_file,
)

# Configure NullHandler for library-safe logging
# This prevents "No handler found" warnings when the package is used as a library
# without explicit logging configuration by the consuming application
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    # Configuration dataclasses
    'ProcessingConfig',
    'ExtractorConfig',
    'RulesetConfig',
    'TemplateConfig',
    'GuiConfig',
    # Processing context & modes
    'ProcessingContext',
    'create_zircolite_core',
    'create_worker_core',
    'create_extractor',
    'process_unified_streaming',
    'process_perfile_streaming',
    'process_db_input',
    'process_parallel_streaming',
    'process_single_file_worker',
    # Core classes
    'ZircoliteCore',
    'StreamingEventProcessor',
    'EvtxExtractor',
    'RulesetHandler',
    'RulesUpdater',
    'EventFilter',
    'TemplateEngine',
    'ZircoliteGuiGenerator',
    'MemoryTracker',
    # Utility functions
    'init_logger',
    'create_silent_logger',
    'quit_on_error',
    'check_if_exists',
    'select_files',
    'avoid_files',
    'format_size',
    'analyze_files_and_recommend_mode',
    'print_mode_recommendation',
    'load_field_mappings',
    # Parallel processing
    'ParallelConfig',
    'ParallelStats',
    'MemoryAwareParallelProcessor',
    'process_files_with_memory_awareness',
    'estimate_parallel_viability',
    'calculate_optimal_workers',
    # Log type detection
    'LogTypeDetector',
    'DetectionResult',
    # YAML configuration
    'ConfigLoader',
    'ZircoliteConfig',
    'InputConfig',
    'YamlRulesConfig',
    'OutputConfig',
    'TimeFilterConfig',
    'ParallelProcessingConfig',
    'create_default_config_file',
    # Rich console output
    'console',
    'ZircoliteConsole',
    'RichProgressTracker',
    'DetectionStats',
    'ProcessingStats',
    'get_rich_logger',
    'format_level',
    'LEVEL_STYLES',
    # Severity ordering
    'LEVEL_PRIORITY',
    # Quiet mode
    'set_quiet_mode',
    'is_quiet',
    # Banner
    'print_banner',
    # Section separators & panels
    'print_section',
    'print_error_panel',
    'print_no_detections',
    # Severity badges
    'make_severity_badge',
    # Live display helpers
    'make_detection_counter',
    'build_file_tree',
    'build_attack_summary',
    'build_detection_table',
    'make_file_link',
    # CLI helper functions
    'print_step',
    'print_substep',
    'print_info',
    'print_success',
    'print_warning',
    'print_error',
    'print_file',
    'print_count',
    'print_detection',
]

__version__ = "3.2.0"
