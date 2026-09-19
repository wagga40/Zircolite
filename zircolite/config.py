"""
Configuration dataclasses for Zircolite.

This module provides typed configuration containers using dataclasses
for cleaner, more maintainable class initialization across the codebase.
"""

from dataclasses import dataclass, field

from .formats import INPUT_FORMATS


@dataclass
class ProcessingConfig:
    """
    Configuration for event processing operations.

    Used by ZircoliteCore and StreamingEventProcessor
    for shared processing parameters.
    """
    # Time filtering
    time_after: str = "1970-01-01T00:00:00"
    time_before: str = "9999-12-12T23:59:59"
    time_field: str | None = None

    # Processing options
    hashes: bool = False
    disable_progress: bool = False

    # Database options
    db_location: str = ":memory:"
    batch_size: int = 5000
    working_db: str = "memory"
    working_db_dir: str | None = None
    sqlite_cache_mib: int = 64
    flatten_backend: str = "auto"
    rule_prefilter: str = "auto"

    # Output options
    no_output: bool = False
    csv_mode: bool = False
    delimiter: str = ";"
    limit: int = -1

    # Performance options
    profile_rules: bool = False

    # Database indexes: columns to index (add), index names to drop (remove)
    add_index: list[str] = field(default_factory=list)
    remove_index: list[str] = field(default_factory=list)

    # When > 0, scan the loaded ruleset and create indices on the top-N
    # most-referenced columns from WHERE clauses (in addition to add_index).
    auto_index_top_n: int = 0

    # Archive decryption
    archive_password: str | None = None

    # EVTX parsing strictness (False = lenient/skip bad chunks, True = stop on errors)
    strict_evtx: bool = False
    # None leaves parser defaults intact; file workers share a CPU budget.
    evtx_threads: int | None = None

    def __post_init__(self) -> None:
        from pathlib import Path

        for name, choices in (
            ("working_db", ("memory", "disk")),
            ("flatten_backend", ("auto", "python", "cython")),
            ("rule_prefilter", ("auto", "off", "literal")),
        ):
            if getattr(self, name) not in choices:
                raise ValueError(f"Unknown {name}: {getattr(self, name)}")
        if isinstance(self.sqlite_cache_mib, bool) or not isinstance(self.sqlite_cache_mib, int) or self.sqlite_cache_mib < 1:
            raise ValueError("sqlite_cache_mib must be a positive integer")
        if self.working_db_dir is not None and not Path(self.working_db_dir).is_dir():
            raise ValueError("working_db_dir must name an existing directory")


@dataclass
class ExtractorConfig:
    """
    Configuration for log line conversion.

    Used by EvtxExtractor for specifying input format and options.
    """
    # Input format flags (mutually exclusive in practice)
    xml_logs: bool = False
    sysmon4linux: bool = False
    auditd_logs: bool = False
    evtxtract: bool = False

    # Encoding used when the streaming processor opens the source file
    encoding: str | None = None

    def __post_init__(self) -> None:
        """Take the encoding from the format registry unless one was given."""
        if self.encoding is not None:
            return
        for spec in INPUT_FORMATS:
            if spec.extractor_flag and getattr(self, spec.extractor_flag, False):
                self.encoding = spec.default_encoding
                return


@dataclass
class RulesetConfig:
    """
    Configuration for ruleset handling operations.

    Used by RulesetHandler for ruleset parsing and conversion.
    """
    ruleset: list[str] = field(default_factory=list)
    pipeline: list[list[str]] | None = None
    save_ruleset: bool = False
    time_field: str = "SystemTime"


@dataclass
class TemplateConfig:
    """
    Configuration for template engine operations.

    Used by TemplateEngine and ZircoliteGuiGenerator.
    """
    template: list[list[str]] = field(default_factory=list)
    template_output: list[list[str]] = field(default_factory=list)
    time_field: str = ""
    # When True, template output files are opened in append mode rather than
    # being overwritten. Useful for accumulating results across multiple runs
    # (e.g. cumulative NDJSON exports). See issue #132.
    append: bool = False


@dataclass
class GuiConfig:
    """
    Configuration for GUI generator.

    Used by ZircoliteGuiGenerator.
    """
    # Path to the gui/zircogui.zip that gets unpacked, not the output
    # directory -- that arrives separately as generate()'s second argument.
    source_archive: str = ""
    template_file: str = ""
    time_field: str = ""
