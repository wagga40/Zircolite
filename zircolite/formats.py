"""
Input format registry for Zircolite.

Everything Zircolite knows about an input format lives in one table here:
the CLI flag that selects it, the value accepted in a YAML config, the
default file extension used to glob a directory, the streaming generator
that reads it, and whether it needs an extractor first.

This module deliberately imports nothing from the rest of the package.
``config_loader`` is otherwise dependency-free, so keeping the registry a
leaf lets every other module consume it without an import cycle.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class InputFormat:
    """Everything Zircolite needs to know about one input format."""

    name: str  # canonical input_type used across the pipeline
    args_flag: str  # attribute set on the argparse namespace
    yaml_format: str  # accepted value for `input.format`
    has_cli_flag: bool = True  # False for EVTX: it is the implicit default
    default_extension: str | None = None
    stream_method: str | None = None  # StreamingEventProcessor generator
    extractor_flag: str | None = None  # ExtractorConfig field to enable
    # Encoding used to open the file when --logs-encoding is not given. None
    # for the binary formats, which carry their own.
    default_encoding: str | None = None
    reads_json: bool = False
    json_array: bool = False
    windows_event_semantics: bool = True  # Channel/EventID early filtering applies


# The default format is where every extension fallback lands, so unlike a
# per-format extension this one is never absent. Naming it lets callers use it
# without re-proving that.
DEFAULT_EXTENSION: str = "evtx"

# Order is the resolution precedence when several *_input flags are truthy.
# The CLI puts the format flags in a mutually exclusive group, so this only
# matters for library callers that build a namespace by hand.
INPUT_FORMATS: tuple[InputFormat, ...] = (
    InputFormat(
        name="sqlite",
        args_flag="db_input",
        yaml_format="sqlite",
        # No extension on purpose: a database is named explicitly with -D, so
        # letting it narrow a directory glob would hide the very file it points at.
        default_extension=None,
    ),
    InputFormat(
        name="json",
        args_flag="json_input",
        yaml_format="json",
        default_extension="json",
        stream_method="stream_json_events",
        default_encoding="utf-8-sig",
        reads_json=True,
    ),
    InputFormat(
        name="json_array",
        args_flag="json_array_input",
        yaml_format="json_array",
        default_extension="json",
        stream_method="stream_json_events",
        default_encoding="utf-8-sig",
        reads_json=True,
        json_array=True,
    ),
    InputFormat(
        name="xml",
        args_flag="xml_input",
        yaml_format="xml",
        default_extension="xml",
        stream_method="stream_xml_events",
        extractor_flag="xml_logs",
        default_encoding="utf-8",
    ),
    InputFormat(
        name="sysmon_linux",
        args_flag="sysmon_linux_input",
        yaml_format="sysmon_linux",
        default_extension="log",
        stream_method="stream_sysmon_linux_events",
        extractor_flag="sysmon4linux",
        default_encoding="ISO-8859-1",
        windows_event_semantics=False,
    ),
    InputFormat(
        name="auditd",
        args_flag="auditd_input",
        yaml_format="auditd",
        default_extension="log",
        stream_method="stream_auditd_events",
        extractor_flag="auditd_logs",
        default_encoding="utf-8",
        windows_event_semantics=False,
    ),
    InputFormat(
        name="csv",
        args_flag="csv_input",
        yaml_format="csv",
        default_extension="csv",
        stream_method="stream_csv_events",
        default_encoding="utf-8-sig",
    ),
    InputFormat(
        name="evtxtract",
        args_flag="evtxtract_input",
        yaml_format="evtxtract",
        default_extension="log",
        stream_method="stream_evtxtract_events",
        extractor_flag="evtxtract",
        default_encoding="utf-8",
    ),
    InputFormat(
        name="evtx",
        args_flag="evtx_input",
        yaml_format="evtx",
        # There is no --evtx-input option: -e/--evtx is the input *path*, and
        # EVTX is what you get when no format flag is set. The flag name still
        # exists as a transform `source_condition` value.
        has_cli_flag=False,
        default_extension=DEFAULT_EXTENSION,
        stream_method="stream_evtx_events",
    ),
)

_BY_NAME: dict[str, InputFormat] = {f.name: f for f in INPUT_FORMATS}
_BY_YAML: dict[str, InputFormat] = {f.yaml_format: f for f in INPUT_FORMATS}

DEFAULT_INPUT_FORMAT: InputFormat = _BY_NAME["evtx"]

YAML_INPUT_FORMATS: tuple[str, ...] = tuple(f.yaml_format for f in INPUT_FORMATS)

# Formats without Channel/EventID semantics: event filtering is skipped for
# these unless event_filter.filter_all_sources is enabled in the config.
NON_WINDOWS_INPUT_FLAGS: frozenset[str] = frozenset(
    f.args_flag for f in INPUT_FORMATS if not f.windows_event_semantics
)


@dataclass(frozen=True)
class ExtensionFallback:
    """Best guess for a file extension once content analysis has failed."""

    format_name: str
    log_source: str
    timestamp_field: str | None = None
    pipeline: str | None = None


# Deliberately not derived from `default_extension`: that mapping is
# format -> extension and its inverse is not a function. Three formats glob
# ".log" and two glob ".json", so this table records which one a blind guess
# picks, and is only ever consulted after content analysis has given up.
EXTENSION_FALLBACKS: Mapping[str, ExtensionFallback] = {
    ".evtx": ExtensionFallback("evtx", "windows_evtx", "SystemTime", "sysmon"),
    ".xml": ExtensionFallback("xml", "windows_evtx_xml", "SystemTime", "sysmon"),
    ".csv": ExtensionFallback("csv", "generic_csv"),
    ".tsv": ExtensionFallback("csv", "generic_csv"),
    # JSON lines rather than json_array: the former reads a single-line array
    # too, so it is the safer guess of the two.
    ".json": ExtensionFallback("json", "generic_json"),
    ".jsonl": ExtensionFallback("json", "generic_json"),
    ".ndjson": ExtensionFallback("json", "generic_json"),
    # Shared by sysmon_linux, auditd and evtxtract. Reaching here means none of
    # their content markers were found, so a readable text format is the least
    # bad answer.
    ".log": ExtensionFallback("json", "generic_json"),
}

# Extensions with no `default_extension` claim in the registry above.
ALIAS_EXTENSIONS: frozenset[str] = frozenset({".jsonl", ".ndjson", ".tsv"})


def format_by_name(name: str) -> InputFormat | None:
    """Look up a format by its canonical input_type."""
    return _BY_NAME.get(name)


def format_by_yaml(value: str) -> InputFormat | None:
    """Look up a format by the value accepted in `input.format`."""
    return _BY_YAML.get(value)


def is_valid_yaml_format(value: str) -> bool:
    """Whether *value* is an accepted `input.format`."""
    return value in _BY_YAML


def format_from_args(args: Any) -> InputFormat:
    """First format whose flag is set on *args*, EVTX when none is.

    Missing attributes count as unset so that partial namespaces built by
    library callers resolve instead of raising.
    """
    for spec in INPUT_FORMATS:
        if getattr(args, spec.args_flag, False):
            return spec
    return DEFAULT_INPUT_FORMAT


def json_array_requested(args: Any) -> bool:
    """Whether any format flag on *args* asks for JSON-array reading.

    Not `format_from_args(args).json_array`: a namespace with both the lines
    and the array flag set resolves to the lines format by precedence, but the
    array request still has to be honoured.
    """
    return any(
        getattr(args, spec.args_flag, False)
        for spec in INPUT_FORMATS
        if spec.json_array
    )


def has_explicit_format(args: Any) -> bool:
    """Whether the user selected a format explicitly (EVTX is the default)."""
    return any(
        getattr(args, spec.args_flag, False)
        for spec in INPUT_FORMATS
        if spec.has_cli_flag
    )
