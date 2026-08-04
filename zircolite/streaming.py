"""
Streaming event processor for Zircolite.

This module contains the StreamingEventProcessor class for:
- Single-pass streaming of events from various log formats
- Dynamic schema discovery during streaming
- Batch database insertion
- Early event filtering based on channel/eventID
"""

import base64
import contextlib
import csv as csv_module
import logging
import math
import operator
import os
import re
import shutil
import tempfile
from collections.abc import Generator
from functools import wraps
from itertools import chain, islice
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    NamedTuple,
    Optional,
)

import chardet
import orjson as json
import xxhash

# Rich console for styled output
from evtx import PyEvtxParser
from RestrictedPython import compile_restricted, limited_builtins, safe_builtins, utility_builtins
from RestrictedPython.Eval import default_guarded_getiter
from RestrictedPython.Guards import guarded_iter_unpack_sequence

from .config import ProcessingConfig
from .formats import (
    DEFAULT_INPUT_FORMAT,
    NON_WINDOWS_INPUT_FLAGS,
    format_by_name,
    format_from_args,
)
from .shutdown import is_shutdown_requested
from .utils import (
    COMPRESSED_SUFFIXES,
    load_field_mappings,
    open_maybe_compressed,
    parse_timestamp,
    sniff_csv_delimiter,
)

if TYPE_CHECKING:
    from .extractor import EvtxExtractor
    from .rules import EventFilter


# ---------------------------------------------------------------------------
# Module-level constants – built once, shared across all instances
# ---------------------------------------------------------------------------

# Pre-compiled regex for stripping non-alphanumeric characters
_NON_ALNUM_RE = re.compile(r"[^a-zA-Z0-9]")

# Sentinel for excluded paths in the path resolution cache
_EXCLUDED_SENTINEL = object()

# Upper bound for one buffered JSON object in the chunked array reader:
# bounds memory usage on permanently malformed content while staying
# generous for legitimate large events
_MAX_JSON_OBJECT_BUFFER_CHARS = 64 * 1024 * 1024

# Input formats without Channel/EventID semantics: event filtering is skipped
# for these unless event_filter.filter_all_sources is enabled in the config
_NON_WINDOWS_INPUTS = NON_WINDOWS_INPUT_FLAGS


class StrictParseError(Exception):
    """A parse error that --strict asked us to stop on.

    Distinct from the generic per-file failure so that the run aborts instead
    of continuing over a partially ingested file.
    """


def _json_array_encoding() -> str:
    """Default encoding for JSON arrays, per the format registry."""
    spec = format_by_name("json_array")
    return (spec.default_encoding if spec else None) or "utf-8"


def marks_degraded(label: str):
    """Wrap a reader so aborting mid-file is recorded, not merely logged.

    A reader that catches, logs and returns leaves every caller believing the
    file was read to the end: the event count looks healthy, the path never
    reaches ``failed_files``, and ``--remove-events`` then deletes the only copy
    of a log nothing ever finished analysing. Marking the run degraded is what
    keeps that file on disk.

    Every reader is wrapped, so a new one inherits the guarantee rather than
    having to remember it. ``stream_evtx_events`` handles its own errors first
    -- it distinguishes a truncated EVTX from an archive of the wrong format --
    and re-raises whatever it cannot explain into this.
    """

    def decorate(reader):
        @wraps(reader)
        def wrapper(self, source, *args, **kwargs):
            try:
                yield from reader(self, source, *args, **kwargs)
            except StrictParseError:
                raise
            except Exception as exc:
                self._had_parse_error = True
                self.logger.error(
                    f"[red]    [-] Error streaming {label} file {source}: {exc}[/]"
                )

        return wrapper

    return decorate


def _quote_identifier(name: str) -> str:
    """Quote a SQL identifier, escaping embedded double quotes.

    Column names are derived from event data (attacker-controlled), so they
    must never be interpolated into SQL unescaped.
    """
    return '"' + name.replace('"', '""') + '"'


def _dedupe_case_variant_columns(
    columns: frozenset[str], canonical: dict[str, str]
) -> tuple[str, ...]:
    """Sort columns, collapsing names that differ only by case.

    SQLite identifiers are case-insensitive: "EventID" and "eventid" are the
    same column. Keeping both in an INSERT would silently drop one binding.
    Where two spellings really do collide here, the survivor is the one the
    schema recorded a type under, so the column keeps its type instead of
    falling back to TEXT.

    A column with only one spelling in this batch keeps that spelling, even
    when the schema knows another. ``canonical`` spans the whole run, so
    rewriting unconditionally renamed columns to a spelling the events in this
    batch do not carry -- and the row builder then either raised KeyError and
    abandoned the file, or wrote NULL into every one of those cells. SQLite
    matches the identifier case-insensitively either way.
    """
    spellings_per_name: dict[str, int] = {}
    for col in columns:
        col_lower = col.lower()
        spellings_per_name[col_lower] = spellings_per_name.get(col_lower, 0) + 1

    result: list[str] = []
    seen_lower: set[str] = set()
    for col in sorted(columns):
        col_lower = col.lower()
        if col_lower in seen_lower:
            continue
        seen_lower.add(col_lower)
        collided = spellings_per_name[col_lower] > 1
        result.append(canonical.get(col_lower, col) if collided else col)
    return tuple(result)


class _TransformSpec(NamedTuple):
    """Baked transform config for fast attribute access in the hot path."""

    alias_name: str
    alias: bool
    source_condition: frozenset[str]
    enabled: bool
    code: str

# Fallback when a transform file is missing or invalid (no-op pass-through)
_NOOP_TRANSFORM_CODE = "def transform(param):\n    return param"


def _build_restricted_builtins() -> dict:
    """Build RestrictedPython builtins dict once at module level."""

    def _default_guarded_getitem(ob, index):
        return ob[index]

    def _safe_write_(obj):
        """Allow writes to safe container types (dict, list, set) only."""
        if isinstance(obj, (dict, list, set)):
            return obj
        raise TypeError(f"Write access to {type(obj).__name__} is not allowed")

    _INPLACE_OPS = {
        "+=": lambda x, y: x + y,
        "-=": lambda x, y: x - y,
        "*=": lambda x, y: x * y,
        "/=": lambda x, y: x / y,
        "//=": lambda x, y: x // y,
        "%=": lambda x, y: x % y,
        "**=": lambda x, y: x**y,
        "|=": lambda x, y: x | y,
        "&=": lambda x, y: x & y,
        "^=": lambda x, y: x ^ y,
    }

    def _inplacevar_(op, x, y):
        """Handle augmented assignment operators (+=, -=, *=, etc.)."""
        fn = _INPLACE_OPS.get(op)
        if fn is None:
            raise TypeError(f"Unsupported in-place operator: {op}")
        return fn(x, y)

    builtins = {
        "__name__": "script",
        "_getiter_": default_guarded_getiter,
        "_getattr_": getattr,
        "_getitem_": _default_guarded_getitem,
        "_write_": _safe_write_,
        "_inplacevar_": _inplacevar_,
        "base64": base64,
        "math": math,
        "re": re,
        "chardet": chardet,
        "_iter_unpack_sequence_": guarded_iter_unpack_sequence,
    }
    builtins.update(safe_builtins)
    builtins.update(limited_builtins)
    builtins.update(utility_builtins)
    return builtins


# Shared builtins constant (identical for all StreamingEventProcessor
# instances – avoids rebuilding per-instance).
_RESTRICTED_BUILTINS = _build_restricted_builtins()


class StreamingEventProcessor:
    """
    Single-pass streaming processor that combines extraction, flattening, and DB insertion.

    This eliminates intermediate file I/O and double JSON parsing by processing events
    as they are extracted from EVTX/XML/Auditd sources and directly inserting them
    into the SQLite database in batches.

    Supports early event filtering based on channel/eventID to skip events that won't
    match any detection rules.
    """

    __slots__ = (
        "RestrictedPython_BUILTINS",
        # Event filter config (from the field-mappings config)
        "_channel_field_paths",
        # Last field path that yielded a Channel/EventID value; tried first on
        # the next event since a file's schema is stable
        "_channel_path_hint",
        # DB column caching
        "_db_columns",
        "_detected_time_field",
        "_event_filter_config_enabled",
        "_eventid_field_paths",
        "_eventid_path_hint",
        "_events_filtered_count",
        "_events_time_filtered_count",
        "_failed_splits",
        "_failed_transforms",
        "_filter_all_sources",
        "_filtering_enabled",
        "_had_parse_error",
        # Time filter cache – includes string bounds for comparison
        "_has_time_filter",
        "_ignore_source_condition",
        # Sorted-column caching for _insert_batch
        "_last_column_frozenset",
        "_last_insert_columns",
        "_last_insert_stmt",
        "_last_sorted_columns",
        # Path resolution cache – maps (raw_field_name, last_part) to resolved
        # (raw_name, mapped_key) or _EXCLUDED_SENTINEL; avoids repeated
        # exclusion/mapping lookups per leaf
        "_resolve_path",
        # Leaf keys whose schema bookkeeping is already done (skip repeat work)
        "_seen_leaf_keys",
        "_skipped_records",
        # Field names that need alias/split/transform handling. Leaves whose
        # mapped or raw name is absent here take the ultra-fast leaf path.
        "_special_fields",
        "_time_after",
        "_time_before",
        # One-shot flag: warn once when --timefield value is absent from events
        "_timefield_warned",
        "_timestamp_auto_detect",
        # Timestamp config (from the field-mappings config)
        "_timestamp_detection_fields",
        "_transform_func_cache",
        "_transforms_baked",
        "aliases",
        # Archive password for encrypted zip/7z files
        "archive_password",
        "args_config",
        "batch_size",
        "chosen_input",
        # Caches
        "compiled_code_cache",
        "config_file",
        # Schema tracking
        "discovered_fields",
        "enabled_transforms_set",
        # Event filtering (early skip based on channel/eventID)
        "event_filter",
        # Config data (loaded once)
        "field_exclusions",
        "field_mappings",
        "field_split_list",
        "field_types",
        "hashes",
        "logger",
        # EVTX parsing strictness
        "strict_evtx",
        "time_field",
        "transform_categories",
        "transforms",
        "transforms_dir",
        "transforms_enabled",
        "useless_values",
    )
    enabled_transforms_set: frozenset[Any] | None
    _detected_time_field: str | None

    def __init__(
        self,
        config_file: str,
        args_config: Any,
        processing_config: ProcessingConfig | None = None,
        *,
        logger: logging.Logger | None = None,
        event_filter: "EventFilter | None" = None,
        _raw_config: dict | None = None,
    ):
        """
        Initialize StreamingEventProcessor.

        Args:
            config_file: Path to field mappings configuration file
            args_config: Argparse namespace with input format options
            processing_config: Processing configuration (uses defaults if None)
            logger: Logger instance (creates default if None)
            event_filter: Optional EventFilter for early event filtering based on channel/eventID
            _raw_config: Pre-parsed field mappings dict – when provided, skips
                         re-reading ``config_file`` from disk (used by parallel
                         workers to avoid redundant I/O).
        """
        proc = processing_config or ProcessingConfig()

        self.logger = logger or logging.getLogger(__name__)
        self.config_file = config_file
        self.time_field = proc.time_field
        self.hashes = proc.hashes
        self.args_config = args_config
        self.batch_size = proc.batch_size
        self.archive_password = proc.archive_password
        self.strict_evtx = proc.strict_evtx

        # Event filter for early filtering based on channel/eventID
        self.event_filter = event_filter
        self._events_filtered_count = 0
        self._events_time_filtered_count = 0
        self._skipped_records = 0
        self._had_parse_error = False
        # Pre-compute filtering enabled flag (avoids repeated checks in hot loop)
        self._filtering_enabled = event_filter is not None and event_filter.is_enabled

        # Schema tracking - fields discovered during streaming
        self.discovered_fields: dict = {}  # field_name_lower -> original_field_name
        # field_name -> SQLite declaration. Both carry COLLATE NOCASE: a field
        # is typed from the first value ever seen for it, so a numeric first
        # value would otherwise leave the column comparing text case-sensitively
        # for the rest of the run -- and a later string value silently stopped
        # matching. NOCASE on an INTEGER column costs nothing: numeric equality
        # and range comparisons are unaffected.
        self.field_types: dict = {}
        # Leaf keys already passed through schema bookkeeping. Shares the
        # lifetime of discovered_fields (never cleared mid-instance).
        self._seen_leaf_keys: set = set()

        # Event-filter path hints (populated lazily during streaming)
        self._channel_path_hint: tuple | None = None
        self._eventid_path_hint: tuple | None = None

        # Caches for transforms
        self.compiled_code_cache: dict = {}
        self._transform_func_cache: dict = {}
        self._failed_transforms: set[str] = set()
        self._failed_splits: set[str] = set()

        # DB column caching for batch inserts (avoid repeated PRAGMA queries)
        self._db_columns: set | None = (
            None  # Set of known columns in DB, None = needs refresh
        )
        self._last_insert_stmt: str | None = None  # Cached INSERT statement
        self._last_insert_columns: tuple | None = (
            None  # Columns used in cached statement (as tuple for comparison)
        )

        # Pre-parse the bounds once; events are parsed to the same type per event
        self._has_time_filter = (
            proc.time_after != "1970-01-01T00:00:00"
            or proc.time_before != "9999-12-12T23:59:59"
        )
        if self._has_time_filter:
            self._time_after = parse_timestamp(proc.time_after)
            self._time_before = parse_timestamp(proc.time_before)
        else:
            self._time_after = None
            self._time_before = None

        # Deterministic precedence when several *_input flags are truthy (API
        # edge; the CLI always sets exactly one)
        self.chosen_input = (
            format_from_args(args_config).args_flag
            if args_config
            else DEFAULT_INPUT_FORMAT.args_flag
        )

        # Sorted-column caching for _insert_batch
        self._last_column_frozenset: frozenset = frozenset()
        self._last_sorted_columns: tuple[str, ...] = ()

        # Use module-level RestrictedPython builtins. Must be set before
        # _load_config(), which eagerly compiles transforms via _get_transform_func.
        self.RestrictedPython_BUILTINS = _RESTRICTED_BUILTINS

        # Load field mappings config (includes event_filter and timestamp_detection)
        self._load_config(_raw_config=_raw_config)

        # Recompute after config load: event_filter.enabled can disable filtering
        self._filtering_enabled = (
            self._filtering_enabled and self._event_filter_config_enabled
        )

        # Timestamp auto-detection state
        self._detected_time_field = None
        self._timefield_warned = False

        from functools import lru_cache

        @lru_cache(maxsize=10000)
        def _resolve_path(raw_field_name: str, last_part: str):
            for exclusion in self.field_exclusions:
                if exclusion in raw_field_name:
                    return _EXCLUDED_SENTINEL
            mapped_key = self.field_mappings.get(raw_field_name)
            if mapped_key is None:
                mapped_key = _NON_ALNUM_RE.sub("", last_part)
            return (raw_field_name, mapped_key)

        self._resolve_path = _resolve_path

    def _load_config(self, *, _raw_config: dict | None = None):
        """Load field mappings configuration (supports JSON and YAML formats).

        When *_raw_config* is provided the disk read is skipped, which
        eliminates redundant I/O when many parallel workers share the
        same configuration file.
        """
        config = _raw_config or load_field_mappings(
            self.config_file, logger=self.logger
        )
        self.field_exclusions = tuple(config["exclusions"])
        self.field_mappings = config["mappings"]
        self.useless_values = (
            frozenset(config["useless"]) if config["useless"] else frozenset()
        )
        self.aliases = config["alias"]
        self.field_split_list = config["split"]
        self.transforms = config["transforms"]
        self.transforms_enabled = config["transforms_enabled"]

        # Resolve transforms_dir (default: transforms/ relative to config file)
        transforms_dir_raw = config.get("transforms_dir", "transforms/")
        config_dir = Path(self.config_file).parent
        self.transforms_dir = (config_dir / transforms_dir_raw).resolve()

        # Resolve external file-based transforms (type: python_file)
        self._resolve_file_transforms()

        # Load enabled_transforms list for quick enable/disable control
        # If present, only transforms in this list are enabled (overrides per-transform 'enabled' flag)
        enabled_list = config.get("enabled_transforms", None)
        if enabled_list is not None:
            self.enabled_transforms_set = frozenset(enabled_list)
        else:
            # If no list provided, fall back to per-transform 'enabled' flag (set to None)
            self.enabled_transforms_set = None

        # Load transform categories for --transform-category support
        self.transform_categories = config.get("transform_categories", {})

        # --all-transforms bypasses per-transform source_condition gating
        self._ignore_source_condition = False

        # Handle CLI overrides: --all-transforms and --transform-category
        if self.args_config:
            if getattr(self.args_config, "all_transforms", False):
                # Enable ALL defined transforms by collecting every alias_name
                all_aliases = []
                for field_name, field_transforms in self.transforms.items():
                    for t in field_transforms:
                        alias = t.get("alias_name", "")
                        if alias:
                            all_aliases.append(alias)
                        elif not t.get("alias", True):
                            # Non-alias transforms are identified by field name
                            all_aliases.append(field_name)
                self.enabled_transforms_set = frozenset(all_aliases)
                # Also ensure transforms engine is on
                self.transforms_enabled = True
                # "All" means all: no shipped transform lists xml_input or
                # csv_input in its source_condition, so honouring that gate here
                # would make the flag a no-op for those formats.
                self._ignore_source_condition = True
            elif getattr(self.args_config, "transform_categories", None):
                # Enable transforms belonging to the requested categories
                requested = self.args_config.transform_categories
                combined = (
                    set(self.enabled_transforms_set)
                    if self.enabled_transforms_set
                    else set()
                )
                for cat_name in requested:
                    cat_transforms = self.transform_categories.get(cat_name, [])
                    if not cat_transforms:
                        self.logger.warning(
                            f"    [!] Unknown transform category: '{cat_name}'"
                        )
                    combined.update(cat_transforms)
                self.enabled_transforms_set = frozenset(combined)
                self.transforms_enabled = True
                self._warn_if_no_transform_applies(requested)

        # Load event filter field paths from config (defaults provided by load_field_mappings)
        # Pre-split dot-notation paths into tuples for nested access
        event_filter_cfg = config.get("event_filter", {})
        self._event_filter_config_enabled = event_filter_cfg.get("enabled", True)
        self._filter_all_sources = event_filter_cfg.get("filter_all_sources", False)
        self._channel_field_paths = tuple(
            tuple(p.split(".")) for p in event_filter_cfg.get("channel_fields", [])
        )
        self._eventid_field_paths = tuple(
            tuple(p.split(".")) for p in event_filter_cfg.get("eventid_fields", [])
        )

        # Load timestamp detection config (defaults provided by load_field_mappings)
        timestamp = config.get("timestamp_detection", {})
        self._timestamp_detection_fields = tuple(timestamp.get("detection_fields", []))
        self._timestamp_auto_detect = timestamp.get("auto_detect", True)
        if not self.time_field:
            # Honor the config's default timestamp field when none was requested
            self.time_field = timestamp.get("default_field", "SystemTime")

        # Bake transform dicts to NamedTuples for fast access in the hot path
        self._transforms_baked: dict[str, list[_TransformSpec]] = {}
        for field_name, field_transforms in self.transforms.items():
            for t in field_transforms:
                if not t.get("source_condition"):
                    # An empty source_condition matches no input type: the
                    # transform would be silently skipped for every event
                    self.logger.warning(
                        f"    [!] Transform on field '{field_name}' has no "
                        f"source_condition and will never run"
                    )
            self._transforms_baked[field_name] = [
                _TransformSpec(
                    alias_name=t.get("alias_name", ""),
                    alias=t.get("alias", True),
                    source_condition=frozenset(t.get("source_condition", [])),
                    enabled=t.get("enabled", True),
                    code=t.get("code", ""),
                )
                for t in field_transforms
            ]

        # Warm the transform function cache so the per-event hot path never
        # pays the compile_restricted/exec cost. Failures fall through to the
        # lazy path which logs and skips the offending transform.
        if self.transforms_enabled:
            seen_codes: set[str] = set()
            for specs in self._transforms_baked.values():
                for spec in specs:
                    if spec.code and spec.code not in seen_codes:
                        seen_codes.add(spec.code)
                        self._get_transform_func(spec.code)

        # Fields that require alias, split, or transform handling. A leaf whose
        # mapped key and raw name are both absent here cannot produce extra
        # columns, so it skips the alias/split/transform lookups entirely.
        # Transform fields only count when the engine is enabled, mirroring the
        # ``not transforms_enabled`` short-circuit in the per-leaf fast path.
        special_fields = set(self.aliases) | set(self.field_split_list)
        if self.transforms_enabled:
            special_fields |= set(self._transforms_baked)
        self._special_fields = special_fields

    def _resolve_file_transforms(self):
        """Resolve python_file transforms by loading code from external files.

        Transforms with ``type: python_file`` have their ``file`` key resolved
        relative to ``self.transforms_dir``.  The file contents are stored in the
        ``code`` key so that the rest of the processing pipeline (compilation,
        caching, execution) remains unchanged.

        Transforms with ``type: python`` (or missing type) are left untouched
        (backward compatible).
        """
        for field_name, field_transforms in self.transforms.items():
            for transform in field_transforms:
                ttype = transform.get("type", "python")
                if ttype != "python_file":
                    continue
                rel_path = transform.get("file", "")
                if not rel_path:
                    self.logger.warning(
                        f"    [!] Transform for '{field_name}' has type python_file but no 'file' key – skipped"
                    )
                    transform["code"] = _NOOP_TRANSFORM_CODE
                    continue
                file_path = Path(rel_path)
                if not file_path.is_absolute():
                    file_path = self.transforms_dir / file_path
                try:
                    transform["code"] = file_path.read_text(encoding="utf-8")
                except FileNotFoundError:
                    self.logger.error(
                        f"    [!] Transform file not found: {file_path} (field '{field_name}')"
                    )
                    transform["code"] = _NOOP_TRANSFORM_CODE
                except Exception as exc:
                    self.logger.error(
                        f"    [!] Error reading transform file {file_path}: {exc}"
                    )
                    transform["code"] = _NOOP_TRANSFORM_CODE

    def _extract_event_filter_fields(self, event_dict: dict) -> tuple:
        """
        Extract Channel and EventID from raw event data for early filtering.

        This method tries to extract these fields using configured field paths.
        Paths are tried in order until a value is found.

        The field paths support:
        - Dot notation for nested fields (e.g., "Event.System.Channel")
        - Direct field names (e.g., "Channel")
        - Special handling for EventID which may be a dict with '#text'

        Args:
            event_dict: Raw event dictionary (not yet flattened)

        Returns:
            Tuple of (channel, eventid) where eventid is int or None
        """
        channel, self._channel_path_hint = self._extract_field_value_hinted(
            event_dict, self._channel_field_paths, self._channel_path_hint
        )
        eventid, self._eventid_path_hint = self._extract_field_value_hinted(
            event_dict, self._eventid_field_paths, self._eventid_path_hint
        )

        # Both values are handed to a set membership test, so they have to come
        # back hashable. XML-derived events carry them as {"#text": ...} or
        # {"#attributes": {...}} when the element had attributes.
        if isinstance(channel, dict):
            channel = channel.get("#text")
        if not isinstance(channel, (str, type(None))):
            channel = None
        if channel == "":
            # Too little information to discard the event; the filter keeps None
            channel = None

        # Convert eventid to int if possible (guarantees int or None for caller)
        if eventid is not None:
            # Handle EventID as dict with '#text' (XML style)
            if isinstance(eventid, dict):
                eventid = eventid.get("#text")
            try:
                eventid = int(eventid) if eventid is not None else None
            except (ValueError, TypeError):
                eventid = None

        return channel, eventid

    def _extract_field_value_hinted(
        self, event_dict: dict, field_paths: tuple, hint: tuple | None
    ) -> tuple:
        """
        Extract a field value, trying the last winning path first.

        Paths support dot notation for nested access (e.g. "Event.System.Channel")
        and are otherwise tried in order until one yields a non-None value.

        A log file's schema is stable, so the path that produced a value on the
        previous event almost always produces it again. Probing that path first
        avoids re-walking earlier candidate paths that are absent from the
        event. On a miss the full ordered scan runs as before, keeping results
        identical to a plain first-match scan.

        An empty value does not count as found: a present-but-blank field would
        otherwise stop the scan and then fail the filter, silently discarding
        events whose real channel sits in a later candidate path.

        Returns:
            Tuple of (value, winning_path). ``winning_path`` is the path that
            produced the value (the new hint), or the unchanged hint when no
            path matched.
        """
        if hint is not None:
            value = self._get_nested_value(event_dict, hint)
            if value is not None and value != "":
                return value, hint
        for path in field_paths:
            value = self._get_nested_value(event_dict, path)
            if value is not None and value != "":
                return value, path
        return None, hint

    def _get_nested_value(self, obj: dict, parts: tuple) -> Any:
        """
        Get a value from a nested dictionary using pre-split path parts.

        Args:
            obj: The dictionary to search
            parts: Pre-split path tuple (e.g., ("Event", "System", "Channel"))

        Returns:
            The value at the path, or None if not found
        """
        if not parts or not isinstance(obj, dict):
            return None

        current: Any = obj

        for part in parts:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
            if current is None:
                return None

        return current

    def _detect_timestamp_field(self, flattened_event: dict) -> str | None:
        """
        Auto-detect the timestamp field from a flattened event.

        Tries the default time_field first, then falls back to configured
        detection fields in order of priority.

        Args:
            flattened_event: A flattened event dictionary

        Returns:
            The name of the detected timestamp field, or None if not found
        """
        # First, try the explicitly configured time_field (if set)
        if self.time_field and self.time_field in flattened_event:
            return self.time_field

        # If auto-detect is enabled, try detection fields from config
        if self._timestamp_auto_detect:
            for field in self._timestamp_detection_fields:
                if field in flattened_event:
                    return field

        return None

    def _should_process_event(self, event_dict: dict) -> bool:
        """
        Check if an event should be processed based on the event filter.

        This is a fast check performed before expensive flattening operations.

        Args:
            event_dict: Raw event dictionary

        Returns:
            True if the event should be processed, False if it can be skipped
        """
        # Fast path: use pre-computed flag instead of repeated attribute checks
        if not self._filtering_enabled:
            return True
        if self.event_filter is None:
            return True
        # channel/eventID semantics are Windows-specific; unless the config
        # opts in (filter_all_sources), skip filtering for non-Windows inputs
        if not self._filter_all_sources and self.chosen_input in _NON_WINDOWS_INPUTS:
            return True

        channel, eventid = self._extract_event_filter_fields(event_dict)
        should_process = self.event_filter.should_process_event(channel, eventid)

        if not should_process:
            self._events_filtered_count += 1

        return should_process

    @property
    def events_filtered_count(self) -> int:
        """Return the number of events skipped by the event filter."""
        return self._events_filtered_count

    @property
    def has_time_filter(self) -> bool:
        """Return True when --after/--before narrow the range being processed."""
        return self._has_time_filter

    @property
    def events_time_filtered_count(self) -> int:
        """Return the number of events skipped by --after/--before.

        Kept separate from the channel/eventID count: the two drop events at
        different stages and conflating them would make the per-file "filtered"
        column ambiguous.
        """
        return self._events_time_filtered_count

    def _warn_if_no_transform_applies(self, requested: list[str]) -> None:
        """Warn when the selected transforms all exclude the current input format.

        Every transform is gated on ``source_condition``, so asking for a
        category that names none of them produces no enrichment at all -- and
        silently, which reads as "these transforms found nothing".
        """
        selected = self.enabled_transforms_set or frozenset()
        for field_transforms in self.transforms.values():
            for transform in field_transforms:
                name = transform.get("alias_name") or ""
                if (name or "") in selected and self.chosen_input in transform.get(
                    "source_condition", []
                ):
                    return
        self.logger.warning(
            f"[yellow]   [!] No transform in {', '.join(requested)} applies to "
            f"{self.chosen_input} input; no enrichment field will be created[/]"
        )

    @property
    def ingest_degraded(self) -> bool:
        """Whether the last file failed to ingest fully.

        Used to decide whether --remove-events may delete the source: a file
        Zircolite could not read in full must survive the run.
        """
        return self._had_parse_error or (self._skipped_records > 0)

    def _note_skipped_record(self, source: str, exc: Exception) -> None:
        """Record an unparsable record. A silent skip reads as 'no events here'."""
        self._skipped_records += 1
        if self._skipped_records == 1:
            self.logger.debug(f"Skipping unparsable record in {source}: {exc}")

    def _get_transform_func(self, code):
        """Get or create cached transform function."""
        func = self._transform_func_cache.get(code)
        if func is not None:
            return func
        try:
            byte_code = self.compiled_code_cache.get(code)
            if byte_code is None:
                byte_code = compile_restricted(
                    code, filename="<inline code>", mode="exec"
                )
                self.compiled_code_cache[code] = byte_code
            transform_ns: dict[str, Any] = {}
            exec(byte_code, self.RestrictedPython_BUILTINS, transform_ns)
            func = transform_ns.get("transform")
            if func:
                self._transform_func_cache[code] = func
            return func
        except Exception as e:
            # Warn once, not once per value: a transform on CommandLine that
            # fails to compile would otherwise emit one line per event.
            if code not in self._failed_transforms:
                self._failed_transforms.add(code)
                snippet = code[:80].replace("\n", " ")
                self.logger.warning(
                    f"[yellow]   [!] Transform compilation failed: {e} "
                    f"(code: {snippet!r})[/]"
                )
            return None

    def _transform_value(self, code, param):
        """Transform a value using cached transform function.

        A failing transform falls back to the untransformed value rather than
        losing the event, but it is reported: an alias column quietly holding raw
        values makes every rule written against the derived field stop matching.
        """
        try:
            func = self._get_transform_func(code)
            if func:
                return func(param)
            return param
        except Exception as exc:
            if code not in self._failed_transforms:
                self._failed_transforms.add(code)
                snippet = code[:80].replace("\n", " ")
                self.logger.warning(
                    f"[yellow]   [!] Transform failed at runtime, values left "
                    f"untransformed: {exc} (code: {snippet!r})[/]"
                )
            return param

    def _flatten_event(
        self, event_dict: dict, filename: str, raw_bytes: bytes | None = None
    ) -> dict | None:
        """
        Flatten a single event dictionary and track discovered fields.
        Returns flattened dict or None if filtered out.
        """
        # Add metadata
        event_dict["OriginalLogfile"] = filename
        if self.hashes:
            # CSV, EVTXtract and JSON-array rows never reach here with a source
            # line: the readers hand over a parsed record. Hashing a canonical
            # form of that record keeps --hashes meaningful for every format
            # rather than silently producing no column at all for three of them.
            if raw_bytes is None:
                with contextlib.suppress(TypeError, json.JSONEncodeError):
                    raw_bytes = json.dumps(event_dict, option=json.OPT_SORT_KEYS)
            if raw_bytes:
                event_dict["OriginalLogLinexxHash"] = xxhash.xxh64_hexdigest(raw_bytes)

        # Cache references for hot loop (local vars are faster than attribute access)
        useless_values = self.useless_values
        aliases_get = self.aliases.get
        field_split_list = self.field_split_list
        field_split_list_get = field_split_list.get
        transforms_get = self._transforms_baked.get
        transforms_enabled = self.transforms_enabled
        enabled_transforms_set = self.enabled_transforms_set
        chosen_input = self.chosen_input
        ignore_source_condition = self._ignore_source_condition
        discovered_fields = self.discovered_fields
        field_types = self.field_types
        transform_value = self._transform_value
        resolve_path = self._resolve_path
        special_fields = self._special_fields
        seen_leaf_keys = self._seen_leaf_keys
        _sentinel = _EXCLUDED_SENTINEL

        # Result dict
        json_line: dict[str, Any] = {}

        def process_leaf(raw_field_name: str, last_part: str, obj: Any) -> None:
            cached = resolve_path(raw_field_name, last_part)
            if cached is _sentinel:
                return
            raw_field_name, mapped_key = cached  # type: ignore[misc]
            if isinstance(obj, list):
                value = str(obj)
            elif obj is True or obj is False:
                # SQLite has no boolean type and Sigma rules compare against the
                # lowercase JSON spelling, so storing 1/0 makes them unmatchable.
                value = "true" if obj else "false"
            else:
                value = obj
            if value in useless_values:
                return
            key = mapped_key

            # Ultra-fast path: the vast majority of leaves have no alias, split
            # rule, or active transform. They only need a value assignment plus a
            # one-time column-type record, so they skip the lookups below.
            if key not in special_fields and raw_field_name not in special_fields:
                # Past SQLite's INTEGER range the value has to go in as text
                is_int = isinstance(value, int)
                if isinstance(value, int) and abs(value) > 9223372036854775807:
                    value = str(value)
                    is_int = False
                json_line[key] = value
                if key not in seen_leaf_keys:
                    key_lower = key.lower()
                    if key_lower not in discovered_fields:
                        discovered_fields[key_lower] = key
                        field_types[key] = (
                            "INTEGER COLLATE NOCASE" if is_int else "TEXT COLLATE NOCASE"
                        )
                    seen_leaf_keys.add(key)
                return

            alias_key = aliases_get(key)
            alias_raw = aliases_get(raw_field_name)
            split_config = field_split_list_get(
                raw_field_name
            ) or field_split_list_get(key)
            keys = [key]
            if alias_key is not None:
                keys.append(alias_key)
            if alias_raw is not None:
                keys.append(alias_raw)
            transformed_keys: set | None = None
            transformed_values: dict[str, Any] = {}
            if transforms_enabled:
                for field_name in (key, raw_field_name):
                    field_transforms = transforms_get(field_name)
                    if field_transforms:
                        for transform in field_transforms:
                            alias_name = transform.alias_name
                            if enabled_transforms_set is not None:
                                # Non-alias transforms have an empty alias_name;
                                # enabled_transforms and categories name them by field
                                if (alias_name or field_name) not in enabled_transforms_set:
                                    continue
                            else:
                                if not transform.enabled:
                                    continue
                            if (
                                not ignore_source_condition
                                and chosen_input not in transform.source_condition
                            ):
                                continue
                            transform_code = transform.code
                            if transform.alias:
                                keys.append(alias_name)
                                if transformed_keys is None:
                                    transformed_keys = set()
                                transformed_keys.add(alias_name)
                                transformed_values[alias_name] = transform_value(
                                    transform_code, value
                                )
                            else:
                                value = transform_value(transform_code, value)
            if split_config:
                try:
                    separator = split_config["separator"]
                    equal_sign = split_config["equal"]
                    # One malformed pair must not cost the remaining ones: split
                    # on the first separator only and skip pairs that have none.
                    for split_field in value.split(separator):
                        k, found, v = split_field.partition(equal_sign)
                        if not found:
                            continue
                        json_line[k] = v
                        if k not in seen_leaf_keys:
                            key_lower = k.lower()
                            if key_lower not in discovered_fields:
                                discovered_fields[key_lower] = k
                                field_types[k] = "TEXT COLLATE NOCASE"
                            seen_leaf_keys.add(k)
                except (KeyError, AttributeError) as exc:
                    # A missing separator/equal key or a non-string value drops
                    # every derived column, and every hash-based IOC rule then
                    # matches nothing. Say so once per field rather than never.
                    if last_part not in self._failed_splits:
                        self._failed_splits.add(last_part)
                        self.logger.warning(
                            f"[yellow]   [!] Cannot split field "
                            f"[cyan]{last_part}[/]: {exc}; no derived field "
                            f"will be created for it[/]"
                        )
            # Past SQLite's INTEGER range the value has to go in as text
            is_int = isinstance(value, int)
            if isinstance(value, int) and abs(value) > 9223372036854775807:
                value = str(value)
                is_int = False
            for k in keys:
                if transformed_keys is not None and k in transformed_keys:
                    json_line[k] = transformed_values[k]
                else:
                    json_line[k] = value
                if k not in seen_leaf_keys:
                    key_lower = k.lower()
                    if key_lower not in discovered_fields:
                        discovered_fields[key_lower] = k
                        field_types[k] = "INTEGER COLLATE NOCASE" if is_int else "TEXT COLLATE NOCASE"
                    seen_leaf_keys.add(k)

        # Descend through the event tree, carrying the dotted path as a string
        # (cheaper than re-allocating a path tuple at every node). Leaves are
        # processed without an extra stack push/pop.
        # Only dicts are ever pushed, so every popped node is one.
        stack: list[tuple[dict[str, Any], str]] = [(event_dict, "")]
        while stack:
            obj, raw_path = stack.pop()
            if raw_path:
                for k, v in obj.items():
                    new_path = f"{raw_path}.{k}"
                    if isinstance(v, dict):
                        stack.append((v, new_path))
                    else:
                        process_leaf(new_path, k, v)
            else:
                for k, v in obj.items():
                    if isinstance(v, dict):
                        stack.append((v, k))
                    else:
                        process_leaf(k, k, v)

        # Time filtering (with pre-parsed bounds)
        if self._has_time_filter:
            # Use configured time_field or auto-detect
            effective_time_field = self.time_field

            # Auto-detect timestamp field if not found or not set
            if not effective_time_field or effective_time_field not in json_line:
                if effective_time_field and not self._timefield_warned:
                    self._timefield_warned = True
                    self.logger.warning(
                        f"[yellow]Configured time field '{effective_time_field}' not found in event; "
                        f"falling back to auto-detection. Time filters (--after/--before) "
                        f"may not apply as expected.[/]"
                    )
                if self._detected_time_field and self._detected_time_field in json_line:
                    effective_time_field = self._detected_time_field
                elif self._timestamp_auto_detect:
                    detected = self._detect_timestamp_field(json_line)
                    if detected is not None:
                        self._detected_time_field = detected
                        effective_time_field = detected
                        self.logger.debug(f"Auto-detected timestamp field: {detected}")

            if effective_time_field:
                ts_value = json_line.get(effective_time_field)
                if ts_value:
                    # Bounds are inclusive. An unparsable timestamp keeps the
                    # event: dropping it would hide data behind a format quirk.
                    moment = parse_timestamp(ts_value)
                    if (
                        moment is not None
                        and self._time_after is not None
                        and self._time_before is not None
                        and not (self._time_after <= moment <= self._time_before)
                    ):
                        self._events_time_filtered_count += 1
                        return None

        return json_line

    def stream_evtx_events(self, evtx_file: str) -> Generator[dict, None, None]:
        """Stream and flatten events from an EVTX file (supports .evtx inside .gz/.bz2/.zip/.7z)."""
        tmp_path = None
        try:
            filepath = Path(evtx_file)
            filename = filepath.name
            path_to_parse = str(filepath)
            suffix = filepath.suffix.lower()

            if suffix in COMPRESSED_SUFFIXES:
                with open_maybe_compressed(
                    evtx_file, password=self.archive_password
                ) as f:
                    fd, tmp_path = tempfile.mkstemp(suffix=".evtx")
                    fd_handle: int | None = fd
                    try:
                        # Chunked copy keeps memory bounded for large
                        # compressed EVTX members
                        with os.fdopen(fd, "wb") as out:
                            fd_handle = None  # os.fdopen takes ownership of fd
                            shutil.copyfileobj(f, out)
                        path_to_parse = tmp_path
                    except Exception:
                        if fd_handle is not None:
                            with contextlib.suppress(OSError):
                                os.close(fd_handle)
                        if tmp_path and os.path.exists(tmp_path):
                            with contextlib.suppress(OSError):
                                os.unlink(tmp_path)
                        raise

            parser = PyEvtxParser(path_to_parse)
            flatten = self._flatten_event  # Local reference for speed
            json_loads = json.loads
            should_process = self._should_process_event  # Local reference for speed

            for record in parser.records_json():
                if record is None:
                    continue
                try:
                    raw_data = record.get("data")
                    if raw_data is None:
                        continue
                    if isinstance(raw_data, str):
                        raw_bytes = raw_data.encode("utf-8")
                        event_dict = json_loads(raw_bytes)
                    else:
                        raw_bytes = raw_data
                        event_dict = json_loads(raw_data)

                    # Early filter check before expensive flattening
                    if not should_process(event_dict):
                        continue

                    flattened = flatten(event_dict, filename, raw_bytes)
                    if flattened:
                        yield flattened
                except Exception as e:
                    self.logger.debug(f"Error processing EVTX record: {e}")
                    continue
        except Exception as e:
            err_msg = str(e)
            if (
                "Invalid EVTX" in err_msg or "ElfFile0" in err_msg
            ) and Path(evtx_file).suffix.lower() == ".7z":
                    self.logger.error(
                        f"[red]    [-] Error streaming EVTX file {evtx_file}: {e}[/]\n"
                        "[yellow]   [!] This archive contains non-EVTX data (e.g. JSON). "
                        "Use [cyan]-e/--events[/] without forcing EVTX so auto-detect can run, or [cyan]--json-input[/] for JSON in archives.[/]"
                    )
                    self._had_parse_error = True
                    return
            if self.strict_evtx:
                raise StrictParseError(
                    f"Error streaming EVTX file {evtx_file}: {e}"
                ) from e
            self._had_parse_error = True
            self.logger.warning(
                f"[yellow]    [!] EVTX parsing error in {evtx_file}: {e} — "
                "recovered events before the error were kept (use [cyan]--strict[/] to abort on parse errors)[/]"
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)

    @marks_degraded("JSON")
    def stream_json_events(self, json_file: str) -> Generator[dict, None, None]:
        """Stream and flatten events from a JSONL file, line by line.

        Arrays go to :meth:`stream_json_array_chunked`, which isolates errors
        per event instead of losing the whole file to one bad element.
        """
        filename = os.path.basename(json_file)
        flatten = self._flatten_event  # Local reference
        should_process = self._should_process_event  # Local reference

        with open_maybe_compressed(json_file, password=self.archive_password) as f:
            for line in f:
                line = line.rstrip(b"\n\r")
                if not line:
                    continue
                if line.startswith(b"\xef\xbb\xbf"):  # UTF-8 BOM (first line)
                    line = line[3:]
                try:
                    event_dict = json.loads(line)
                    # Early filter check before expensive flattening
                    if not should_process(event_dict):
                        continue
                    flattened = flatten(event_dict, filename, line)
                    if flattened:
                        yield flattened
                except Exception as exc:
                    self._note_skipped_record(json_file, exc)
                    continue

    @marks_degraded("XML")
    def stream_xml_events(
        self, xml_file: str, extractor: "EvtxExtractor"
    ) -> Generator[dict, None, None]:
        """Stream and flatten events from an XML file using incremental parsing."""
        from lxml import etree  # type: ignore[attr-defined]

        _fh = None  # Track compressed file handle for cleanup
        try:
            filename = Path(xml_file).name
            flatten = self._flatten_event  # Local reference
            should_process = self._should_process_event  # Local reference
            xml_to_dict = extractor.xml_to_dict

            # For compressed/archived XML files, open a decompressed stream for iterparse
            _suffix = Path(xml_file).suffix.lower()
            if _suffix in COMPRESSED_SUFFIXES:
                _fh = open_maybe_compressed(xml_file, password=self.archive_password)
                context = etree.iterparse(_fh, events=("end",), recover=True)
            else:
                context = etree.iterparse(xml_file, events=("end",), recover=True)
            seen_events = False
            for _action, elem in context:
                if elem.tag.endswith("Event"):
                    seen_events = True
                    try:
                        ns = ""
                        if "}" in elem.tag:
                            ns = elem.tag.split("}")[0] + "}"

                        event_dict = xml_to_dict(elem, ns)
                        if event_dict:
                            # Early filter check before expensive flattening
                            if not should_process(event_dict):
                                elem.clear()
                                while elem.getprevious() is not None:
                                    del elem.getparent()[0]
                                continue

                            raw_bytes = etree.tostring(elem) if self.hashes else None
                            flattened = flatten(event_dict, filename, raw_bytes)
                            if flattened:
                                yield flattened
                    except Exception as exc:
                        self._note_skipped_record(xml_file, exc)

                    # Clear element to save memory
                    elem.clear()
                    while elem.getprevious() is not None:
                        del elem.getparent()[0]

            if not seen_events:
                # Deliberately no --logs-encoding hint: XML is parsed with the
                # encoding declared in the document, so that flag changes
                # nothing here.
                self.logger.warning(
                    f"[yellow]    [!] No <Event> documents found in "
                    f"{Path(xml_file).name}; check that it is an EVTX-to-XML "
                    f"export and that its encoding declaration is correct[/]"
                )

        finally:
            if _fh is not None:
                with contextlib.suppress(Exception):
                    _fh.close()

    def _stream_line_events(
        self, log_file: str, extractor: "EvtxExtractor", convert, label: str
    ) -> Generator[dict, None, None]:
        """Stream a one-event-per-line text log through *convert*.

        Shared by the Sysmon-for-Linux and Auditd readers, which differ only
        in the converter and the wording of the error.
        """
        filename = Path(log_file).name
        flatten = self._flatten_event  # Local reference
        should_process = self._should_process_event  # Local reference

        with open_maybe_compressed(
            log_file,
            "rt",
            encoding=extractor.encoding,
            password=self.archive_password,
        ) as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    event_dict = convert(line)
                    if not event_dict:
                        # A line the converter makes nothing of is a skipped
                        # record, not an absent one. Pointing --sysmon-linux at
                        # a plain syslog file yields one per line and would
                        # otherwise report a clean run over zero events.
                        self._note_skipped_record(
                            log_file, ValueError(f"{label} line yielded no event")
                        )
                        continue
                    # Early filter check before expensive flattening
                    if not should_process(event_dict):
                        continue
                    flattened = flatten(event_dict, filename, line.encode("utf-8"))
                    if flattened:
                        yield flattened
                except Exception as exc:
                    self._note_skipped_record(log_file, exc)
                    continue

    @marks_degraded("Sysmon Linux")
    def stream_sysmon_linux_events(
        self, log_file: str, extractor: "EvtxExtractor"
    ) -> Generator[dict, None, None]:
        """Stream and flatten events from a Sysmon for Linux log file."""
        yield from self._stream_line_events(
            log_file, extractor, extractor.sysmon_xml_line_to_json, "Sysmon Linux"
        )

    @marks_degraded("Auditd")
    def stream_auditd_events(
        self, log_file: str, extractor: "EvtxExtractor"
    ) -> Generator[dict, None, None]:
        """Stream and flatten events from an Auditd log file."""
        yield from self._stream_line_events(
            log_file, extractor, extractor.auditd_line_to_json, "Auditd"
        )

    @marks_degraded("CSV")
    def stream_csv_events(self, csv_file: str) -> Generator[dict, None, None]:
        """
        Stream and flatten events from a CSV file.

        Memory-efficient: reads one row at a time using csv.DictReader.
        The delimiter is sniffed from the first lines so semicolon, tab and
        pipe separated exports are not collapsed into a single column.
        """
        filename = os.path.basename(csv_file)
        flatten = self._flatten_event  # Local reference
        should_process = self._should_process_event  # Local reference
        encoding = getattr(
            self.args_config, "logs_encoding", None
        ) or format_from_args(self.args_config).default_encoding

        with open_maybe_compressed(
            csv_file, "rt", encoding=encoding, password=self.archive_password
        ) as f:
            # Buffer the sample instead of seeking: archive-backed streams
            # are not reliably seekable. DictReader accepts any iterable of
            # lines, so the sample is chained back in front of the rest.
            sample_lines = list(islice(f, 5))
            delimiter = sniff_csv_delimiter("".join(sample_lines))
            # A row with more values than the header would otherwise land
            # under the key None, which breaks flattening and silently
            # discards the whole row; restkey gives it a real name.
            reader = csv_module.DictReader(
                chain(sample_lines, f),
                delimiter=delimiter,
                restkey="_extra_values",
                restval="",
            )
            for row in reader:
                try:
                    # CSV rows are already flat dicts, check filter on them directly
                    if not should_process(row):
                        continue
                    flattened = flatten(row, filename, None)
                    if flattened:
                        yield flattened
                except Exception as exc:
                    self._note_skipped_record(csv_file, exc)
                    continue

    @marks_degraded("EVTXtract")
    def stream_evtxtract_events(
        self, log_file: str, extractor: "EvtxExtractor"
    ) -> Generator[dict, None, None]:
        """
        Stream and flatten events from an EVTXtract output file.

        EVTXtract output is not well-formed XML, so it cannot be parsed
        incrementally: the whole file is read, wrapped in a root element and
        recovered in one pass.
        """
        from lxml import etree  # type: ignore[attr-defined]

        filename = Path(log_file).name
        flatten = self._flatten_event  # Local reference
        should_process = self._should_process_event  # Local reference
        xml_to_dict = extractor.xml_to_dict

        # Read and clean the file content
        with open_maybe_compressed(
            log_file,
            "rt",
            encoding=extractor.encoding,
            password=self.archive_password,
        ) as f:
            data = f.read()

        # Clean non-UTF-8 characters
        data = bytes(data.replace("\x00", "").replace("\x0b", ""), "utf-8").decode(
            "utf-8", "ignore"
        )
        data = f"<evtxtract>\n{data}\n</evtxtract>"

        # Parse with recovery mode for malformed XML
        parser = etree.XMLParser(recover=True)
        root = etree.fromstring(data, parser=parser)

        # Stream events from parsed tree
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        for event in root.getchildren():
            if "Event" in event.tag:
                try:
                    event_dict = xml_to_dict(event, ns)
                    if event_dict:
                        # Early filter check before expensive flattening
                        if not should_process(event_dict):
                            continue
                        flattened = flatten(event_dict, filename, None)
                        if flattened:
                            yield flattened
                except Exception as exc:
                    self._note_skipped_record(log_file, exc)
                    continue

        # Free memory from parsed tree
        root.clear()

    @marks_degraded("JSON array")
    def stream_json_array_chunked(self, json_file: str) -> Generator[dict, None, None]:
        """
        Stream and flatten events from a large JSON array file incrementally.

        For very large JSON arrays, this parses incrementally using raw_decode.
        Falls back to standard parsing if file is small enough.

        Yields events incrementally rather than all at once.
        Includes early event filtering based on channel/eventID.
        """
        filename = os.path.basename(json_file)
        flatten = self._flatten_event  # Local reference
        should_process = self._should_process_event  # Local reference

        def process_one(event_dict: dict) -> dict | None:
            """Filter and flatten one event, isolating per-event failures.

            Without this, a single malformed event aborts the rest of the
            file instead of being skipped like the other readers do.
            """
            try:
                if not should_process(event_dict):
                    return None
                return flatten(event_dict, filename, None)
            except Exception as exc:
                self._note_skipped_record(json_file, exc)
                return None

        file_size = os.path.getsize(json_file)

        # For files under 50MB, use standard single-load approach (faster)
        if file_size < 50 * 1024 * 1024:
            with open_maybe_compressed(
                json_file, password=self.archive_password
            ) as f:
                data = f.read()
            if data.startswith(b"\xef\xbb\xbf"):  # UTF-8 BOM
                data = data[3:]
            logs = json.loads(data)
            for event_dict in logs:
                if not isinstance(event_dict, dict):
                    continue
                flattened = process_one(event_dict)
                if flattened:
                    yield flattened
            return

        # For larger files, use incremental parsing
        self.logger.debug(
            f"Large JSON array ({file_size / 1024 / 1024:.1f}MB), using incremental processing"
        )

        import json as std_json

        decoder = std_json.JSONDecoder()

        with open_maybe_compressed(
            json_file,
            "rt",
            encoding=_json_array_encoding(),
            password=self.archive_password,
        ) as f:
            # Find the start of the array
            while True:
                char = f.read(1)
                if not char:
                    return
                if char == "[":
                    break

            buffer = ""
            while True:
                chunk = f.read(65536)
                if not chunk:
                    # Process remaining buffer if any
                    buffer = buffer.lstrip(" \t\n\r,")
                    if buffer and not buffer.startswith("]"):
                        try:
                            obj, _ = decoder.raw_decode(buffer)
                        except Exception:
                            obj = None
                        if isinstance(obj, dict):
                            flattened = process_one(obj)
                            if flattened:
                                yield flattened
                    break

                buffer += chunk
                if len(buffer) > _MAX_JSON_OBJECT_BUFFER_CHARS:
                    # raw_decode keeps failing (truncated/malformed content):
                    # fail fast instead of buffering the rest of the file
                    self._had_parse_error = True
                    self.logger.error(
                        f"[red]    [-] Cannot parse JSON array in {json_file}: "
                        f"invalid or truncated content near current position[/]"
                    )
                    return

                while True:
                    buffer = buffer.lstrip(" \t\n\r,")
                    if not buffer:
                        break
                    if buffer.startswith("]"):
                        # End of array
                        return

                    try:
                        obj, idx = decoder.raw_decode(buffer)
                    except std_json.JSONDecodeError:
                        # Need more data
                        break
                    if isinstance(obj, dict):
                        flattened = process_one(obj)
                        if flattened:
                            yield flattened
                    buffer = buffer[idx:]

    def process_file_streaming(
        self,
        db_connection,
        log_file: str,
        input_type: str = "evtx",
        extractor: Optional["EvtxExtractor"] = None,
        json_array: bool = False,
        keepflat_file=None,
        progress_callback=None,
    ) -> int:
        """
        Process a single log file with streaming, directly inserting into database.

        Args:
            db_connection: SQLite database connection
            log_file: Path to the log file to process
            input_type: Canonical format name (see zircolite.formats)
            extractor: EvtxExtractor instance (required for formats that need conversion)
            json_array: If True, treat a 'json' file as an array instead of JSONL
            keepflat_file: If provided, an open file handle to write flattened events to (JSONL)
            progress_callback: Optional callable(event_count) invoked every batch for live progress

        Returns the number of events processed.
        """
        # Per-file counters: one processor serves every file in unified mode
        self._skipped_records = 0
        self._had_parse_error = False

        # Dispatch to the appropriate stream method
        spec = format_by_name(input_type)
        needs_extractor = spec is not None and spec.extractor_flag is not None
        if spec is None or spec.stream_method is None or (needs_extractor and extractor is None):
            self.logger.error(
                f"[error]    [-] Unsupported input type: {input_type}[/]"
            )
            return 0

        if spec.reads_json:
            # json_array is both a format of its own and a modifier on 'json'
            as_array = spec.json_array or json_array
            if as_array:
                event_stream = self.stream_json_array_chunked(log_file)
            else:
                event_stream = self.stream_json_events(log_file)
        elif needs_extractor:
            event_stream = getattr(self, spec.stream_method)(log_file, extractor)
        else:
            event_stream = getattr(self, spec.stream_method)(log_file)

        # Batch processing with local variable caching
        batch: list[dict[str, Any]] = []
        batch_append = batch.append
        batch_size = self.batch_size
        event_count = 0
        cursor = db_connection.cursor()
        insert_batch = self._insert_batch

        # Events already committed when a later batch fails. Reporting 0 for
        # the whole file would contradict the rows rules then match against.
        inserted_count = 0

        try:
            for event in event_stream:
                batch_append(event)
                event_count += 1

                # Write flattened event to keepflat file if requested.
                # In parallel mode the shared handle's lock covers exactly one
                # write() call, so each event must be emitted in a single write.
                if keepflat_file is not None:
                    keepflat_file.write(json.dumps(event) + b"\n")

                if len(batch) >= batch_size:
                    insert_batch(db_connection, cursor, batch)
                    inserted_count = event_count
                    batch = []
                    batch_append = batch.append  # Rebind after list replacement
                    if progress_callback is not None:
                        progress_callback(event_count)
                    if is_shutdown_requested():
                        return event_count

            # Insert remaining batch
            if batch:
                insert_batch(db_connection, cursor, batch)
                inserted_count = event_count
                if progress_callback is not None:
                    progress_callback(event_count)

            if event_count == 0 and self._skipped_records:
                # "0 events" on its own looks like an empty file rather than an
                # encoding or format mismatch that lost every record.
                self.logger.warning(
                    f"[yellow]   [!] No event could be parsed from "
                    f"{os.path.basename(log_file)}: {self._skipped_records:,} "
                    f"record(s) were skipped. Check the format and encoding "
                    f"(--debug shows the first error)[/]"
                )
            return event_count
        except StrictParseError:
            raise
        except Exception as e:
            if inserted_count == 0:
                raise
            # The committed rows stay, but the file was not read to the end:
            # --remove-events must not treat this as a completed ingest.
            self._had_parse_error = True
            self.logger.error(
                f"[red]    [-] Partial ingest of {os.path.basename(log_file)}: "
                f"{e}[/]\n"
                f"[yellow]   [!] {inserted_count:,} event(s) were committed "
                f"before the failure and are included in the results[/]"
            )
            return inserted_count
        finally:
            cursor.close()

    def _insert_batch(self, db_connection, cursor, batch: list[dict]):
        """Insert a batch of events into the database with dynamic schema handling.

        Large-integer normalization is handled upstream in ``_flatten_event``,
        so no per-value type check is needed here.
        """
        if not batch:
            return

        # Collect all columns from the full batch.
        # Some log types mix event schemas within a single batch, so comparing
        # only the first and last event can drop columns that appear in the middle.
        # We delay materializing the union set until we know the batch is non-uniform,
        # which is the common case for stable event sources.
        first_keys = batch[0].keys()
        extra_columns: set[str] | None = None
        for event in batch[1:]:
            event_keys = event.keys()
            # dict_keys compares as a set, so this already covers a size change
            if event_keys != first_keys:
                if extra_columns is None:
                    extra_columns = set(first_keys)
                extra_columns.update(event_keys)

        if extra_columns is None:
            all_columns_frozen = frozenset(first_keys)
        else:
            all_columns_frozen = frozenset(extra_columns)

        # Cache sorted columns – only re-sort when the column set changes.
        # Case-variant duplicates (e.g. EventID/eventid) are collapsed here
        # because SQLite identifiers are case-insensitive.
        if all_columns_frozen != self._last_column_frozenset:
            all_columns = _dedupe_case_variant_columns(
                all_columns_frozen, self.discovered_fields
            )
            self._last_column_frozenset = all_columns_frozen
            self._last_sorted_columns = all_columns
        else:
            all_columns = self._last_sorted_columns

        # Check if we need to update schema or INSERT statement
        schema_changed = self._ensure_columns_exist_cached(
            db_connection, cursor, all_columns
        )

        # Reuse INSERT statement if columns haven't changed
        if self._last_insert_columns == all_columns and not schema_changed:
            insert_stmt = self._last_insert_stmt
        else:
            columns_escaped = ", ".join(_quote_identifier(col) for col in all_columns)
            placeholders = ", ".join(["?"] * len(all_columns))
            # Column names go through _quote_identifier; the values are bound
            # parameters and are never interpolated.
            insert_stmt = (
                f"INSERT INTO logs ({columns_escaped}) VALUES ({placeholders})"  # noqa: S608
            )
            self._last_insert_stmt = insert_stmt
            self._last_insert_columns = all_columns

        # Build rows – large-int normalisation already done in _flatten_event.
        # When every event shares the first event's columns (the common case for
        # a stable source), a single itemgetter beats a per-column .get genexpr.
        # Heterogeneous batches keep .get so missing columns map to NULL.
        if len(all_columns) != len(all_columns_frozen):
            # Case-collision batch: merge values across case variants per event
            # (first non-None wins) and bind against the canonical column.
            canonical_lower = tuple(col.lower() for col in all_columns)
            rows = []
            for event in batch:
                merged: dict[str, Any] = {}
                for k, v in event.items():
                    kl = k.lower()
                    if kl not in merged or merged[kl] is None:
                        merged[kl] = v
                rows.append(tuple(merged.get(cl) for cl in canonical_lower))
        elif extra_columns is None and len(all_columns) > 1:
            row_getter = operator.itemgetter(*all_columns)
            rows = [row_getter(event) for event in batch]
        else:
            rows = [tuple(event.get(col) for col in all_columns) for event in batch]

        # Execute batch insert with transaction
        try:
            db_connection.execute("BEGIN TRANSACTION")
            cursor.executemany(insert_stmt, rows)
            db_connection.execute("COMMIT")
        except Exception as e:
            db_connection.execute("ROLLBACK")
            self.logger.debug(f"Batch insert error: {e}")
            raise

    def _ensure_columns_exist_cached(
        self, db_connection, cursor, columns: tuple
    ) -> bool:
        """
        Dynamically add columns to the table if they don't exist.
        Uses cached column set to minimize PRAGMA queries.

        Returns True if schema was modified, False otherwise.
        """
        # Initialize cache if needed
        if self._db_columns is None:
            cursor.execute("PRAGMA table_info(logs)")
            self._db_columns = {row[1].lower() for row in cursor.fetchall()}

        db_columns = self._db_columns
        schema_changed = False
        field_types = self.field_types

        # Add missing columns
        for col in columns:
            col_lower = col.lower()
            if col_lower not in db_columns:
                sql_type = field_types.get(col, "TEXT COLLATE NOCASE")
                try:
                    cursor.execute(f"ALTER TABLE logs ADD COLUMN {_quote_identifier(col)} {sql_type}")
                    db_columns.add(col_lower)
                    schema_changed = True
                except Exception as exc:
                    # Usually the column already exists; refresh from the real
                    # schema and check. If it truly is not there, the INSERT is
                    # about to fail on it, so say which column and why.
                    cursor.execute("PRAGMA table_info(logs)")
                    self._db_columns = {row[1].lower() for row in cursor.fetchall()}
                    db_columns = self._db_columns
                    if col_lower not in db_columns:
                        self.logger.warning(
                            f"[yellow]   [!] Could not add column '{col}' to the "
                            f"events table: {exc}[/]"
                        )

        return schema_changed

    def create_initial_table(self, db_connection):
        """Create the initial logs table with basic structure.

        If the table already exists (e.g. after ``DELETE FROM logs`` for
        worker-core reuse), the column cache is refreshed from the actual
        schema so that ``_ensure_columns_exist_cached`` works correctly.
        """
        cursor = db_connection.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    row_id INTEGER PRIMARY KEY AUTOINCREMENT
                )
            """)
            db_connection.commit()
            # Refresh column cache from actual table state – handles both
            # freshly created tables and reused tables (DELETE FROM path).
            cursor.execute("PRAGMA table_info(logs)")
            self._db_columns = {row[1].lower() for row in cursor.fetchall()}
            self._last_insert_stmt = None
            self._last_insert_columns = None
            self._last_column_frozenset = frozenset()
            self._last_sorted_columns = ()
        except Exception as e:
            self.logger.error(f"[error]    [-] Error creating initial table: {e}[/]")
            raise
        finally:
            cursor.close()
