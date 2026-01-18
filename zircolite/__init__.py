#!python3
"""
Zircolite - Standalone SIGMA-Based Detection Tool for EVTX, Auditd, Sysmon Linux, and more.

This package provides modular components for log processing and SIGMA rule detection:

Modules:
- config: Configuration dataclasses for all components
- core: ZircoliteCore class for database and rule execution
- streaming: StreamingEventProcessor for single-pass processing
- flattener: JSONFlattener for log flattening
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
from .flattener import JSONFlattener
from .extractor import EvtxExtractor
from .rules import RulesetHandler, RulesUpdater
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
from .console import (
    console,
    ZircoliteConsole,
    RichProgressTracker,
    DetectionStats,
    ProcessingStats,
    get_rich_logger,
    format_level,
    LEVEL_STYLES,
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
    # Core classes
    'ZircoliteCore',
    'StreamingEventProcessor',
    'JSONFlattener',
    'EvtxExtractor',
    'RulesetHandler',
    'RulesUpdater',
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

__version__ = "3.0.0"
