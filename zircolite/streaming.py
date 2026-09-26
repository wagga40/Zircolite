"""
Streaming event processor for Zircolite.

This module contains the StreamingEventProcessor class for:
- Single-pass streaming of events from various log formats
- Dynamic schema discovery during streaming
- Batch database insertion
- Early event filtering based on channel/eventID
"""

import base64
import codecs
import contextlib
import csv as csv_module
import hashlib
import importlib
import logging
import math
import operator
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Generator
from functools import lru_cache, wraps
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

# Rich console for styled output
from evtx import PyEvtxParser
from RestrictedPython import compile_restricted, limited_builtins, safe_builtins, utility_builtins
from RestrictedPython.Eval import default_guarded_getiter
from RestrictedPython.Guards import guarded_iter_unpack_sequence

from .config import ProcessingConfig
from .console import literal
from .formats import (
    DEFAULT_INPUT_FORMAT,
    NON_WINDOWS_INPUT_FLAGS,
    format_by_name,
    format_from_args,
)
from .jsonstream import iter_json_array
from .shutdown import is_shutdown_requested
from .utils import (
    _EXCLUDED_SENTINEL,
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


@lru_cache(maxsize=1024)
def _compile_transform(code: str):
    """Share immutable bytecode, never mutable transform namespaces."""
    return compile_restricted(code, filename="<inline code>", mode="exec")


@lru_cache(maxsize=256)
def _read_transform(path: str, mtime_ns: int, size: int) -> str:
    """Reload an external transform when its file changes."""
    return Path(path).read_text(encoding="utf-8")


# Input formats without Channel/EventID semantics: event filtering is skipped
# for these unless event_filter.filter_all_sources is enabled in the config
_NON_WINDOWS_INPUTS = NON_WINDOWS_INPUT_FLAGS

# wevtutil qe /f:xml, Get-WinEvent's ToXml() and evtx_dump write <Event> records
# back to back with no element around them, and an XML parser stops at the end
# of the first one, leaving the rest of the file unread without an error. The
# reader puts one synthetic document element around the whole file instead.
# The name must not be "Event", which is how the reader recognises a record.
_XML_WRAPPER_TAG = "ZircoliteXmlDocument"
# How much of a file may precede its first element before the reader gives up
# on wrapping it and parses it as it is
_XML_PROLOG_LIMIT = 1 << 20
_XML_READ_SIZE = 64 * 1024

# Once libxml2's recovering parser has met one error, it stops expanding entity
# references for the rest of the document, so a single malformed record would
# erase every later &gt; &amp; and &lt; (2>&1 read as 21). Character references
# are expanded regardless and mean the same, so the readers hand libxml2 those.
_PREDEFINED_ENTITY_REFS = {
    "amp": "&#38;", "lt": "&#60;", "gt": "&#62;", "quot": "&#34;", "apos": "&#39;",
}
_PREDEFINED_ENTITY_RE = re.compile(r"&(amp|lt|gt|quot|apos);")


def _as_character_references(text: str) -> str:
    """*text* with every predefined entity reference spelled as a character reference."""
    return _PREDEFINED_ENTITY_RE.sub(lambda m: _PREDEFINED_ENTITY_REFS[m.group(1)], text)


class _EntityReferenceRewriter:
    """``_as_character_references`` over a byte stream in one encoding, chunk by chunk.

    A reference cut in two by a read boundary is held back until the next
    chunk completes it. In UTF-16 only matches that start on a code unit
    count: the same bytes read one byte off belong to other characters.
    """

    def __init__(self, codec: str):
        self._unit = 1 if codec == "latin-1" else 2
        self._amp = "&".encode(codec)
        self._refs = {
            f"&{name};".encode(codec): ref.encode(codec)
            for name, ref in _PREDEFINED_ENTITY_REFS.items()
        }
        self._pattern = re.compile(b"|".join(re.escape(ref) for ref in self._refs))
        self._longest = max(map(len, self._refs))
        self._pending = b""
        self._offset = 0  # stream offset of self._pending[0]

    def feed(self, data: bytes) -> bytes:
        data = self._pending + data
        base, unit = self._offset, self._unit
        end = len(data) - (base + len(data)) % unit
        amp = data.rfind(self._amp, max(0, end - self._longest + 1), end)
        cut = end if amp == -1 else amp - (base + amp) % unit
        self._pending, self._offset = data[cut:], base + cut
        return self._rewrite(data[:cut], base)

    def flush(self) -> bytes:
        data, self._pending = self._pending, b""
        return self._rewrite(data, self._offset)

    def _rewrite(self, data: bytes, base: int) -> bytes:
        unit, refs = self._unit, self._refs

        def swap(match: re.Match) -> bytes:
            return match.group() if (base + match.start()) % unit else refs[match.group()]

        return self._pattern.sub(swap, data)


def _xml_byte_layout(head: bytes) -> tuple[int, str] | None:
    """(BOM length, codec) for reading the prolog of an XML byte stream.

    Any ASCII-compatible encoding reads as latin-1, which maps bytes to
    characters one to one, so character offsets are byte offsets. None for
    the encodings the prolog scan cannot be trusted with.
    """
    if head.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return None
    if head.startswith(codecs.BOM_UTF8):
        return len(codecs.BOM_UTF8), "latin-1"
    if head.startswith(codecs.BOM_UTF16_LE):
        return len(codecs.BOM_UTF16_LE), "utf-16-le"
    if head.startswith(codecs.BOM_UTF16_BE):
        return len(codecs.BOM_UTF16_BE), "utf-16-be"
    if head.startswith(b"<\x00"):
        return 0, "utf-16-le"
    if head.startswith(b"\x00<"):
        return 0, "utf-16-be"
    return 0, "latin-1"


def _first_element_offset(prolog: str) -> int | None:
    """Index of the first element's ``<`` in *prolog*.

    The XML declaration, processing instructions and comments are skipped.
    -1 for a DOCTYPE, which cannot sit inside an element, so the file has to
    be parsed exactly as written; None when *prolog* ends before telling.
    """
    i = 0
    while (i := prolog.find("<", i)) != -1:
        if i + 1 == len(prolog):
            return None
        if prolog.startswith("<?", i):
            end, skip = prolog.find("?>", i + 2), 2
        elif prolog.startswith("<!--", i):
            end, skip = prolog.find("-->", i + 4), 3
        elif prolog.startswith("<!", i):
            return -1
        else:
            return i
        if end == -1:
            return None
        i = end + skip
    return None


class _XmlDocumentStream:
    """A binary file read with every top-level element under one root.

    ``head`` is what has already been read from ``raw``; the synthetic start
    tag goes in at ``split``, a byte offset into it, and the end tag after the
    last byte of ``raw``. With a codec, predefined entity references are
    rewritten as character references; without one the bytes pass through.
    """

    def __init__(
        self, raw: Any, head: bytes, split: int | None = None, codec: str | None = None
    ):
        self._raw = raw
        self._head: bytes | None = head
        self._closing = b""
        if codec is not None and split is not None:
            self._head = head[:split] + f"<{_XML_WRAPPER_TAG}>".encode(codec) + head[split:]
            self._closing = f"</{_XML_WRAPPER_TAG}>".encode(codec)
        self._rewriter = _EntityReferenceRewriter(codec) if codec is not None else None
        self._buffer = bytearray()
        self._done = False

    def _fill(self, size: int) -> None:
        while not self._done and (size < 0 or len(self._buffer) < size):
            if self._head is not None:
                piece, self._head = self._head, None
            else:
                piece = self._raw.read(_XML_READ_SIZE)
                if not piece:
                    piece, self._done = self._closing, True
            if self._rewriter is not None:
                piece = self._rewriter.feed(piece)
                if self._done:
                    piece += self._rewriter.flush()
            self._buffer += piece

    def read(self, size: int | None = -1) -> bytes:
        size = -1 if size is None else size
        self._fill(size)
        if size < 0:
            size = len(self._buffer)
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data


def _xml_document_stream(raw: Any) -> _XmlDocumentStream:
    """Wrap *raw* so that records written back to back parse as one document."""
    head = b""
    codec = None
    while len(head) < _XML_PROLOG_LIMIT:
        chunk = raw.read(_XML_READ_SIZE)
        if not chunk:
            break
        head += chunk
        layout = _xml_byte_layout(head)
        if layout is None:
            codec = None
            break
        bom, codec = layout
        body = head[bom:]
        if codec != "latin-1":
            body = body[: len(body) // 2 * 2]
        prolog = body.decode(codec, errors="replace")
        offset = _first_element_offset(prolog)
        if offset == -1:
            break
        if offset is not None:
            split = bom + len(prolog[:offset].encode(codec, errors="replace"))
            return _XmlDocumentStream(raw, head, split, codec)
    return _XmlDocumentStream(raw, head, codec=codec)


# The event filter hands both values to a set membership test, so they have to
# come back hashable. XML-derived events carry them as {"#text": ...}, or as
# {"#attributes": {...}} when the element had attributes and no text.
def _channel_filter_value(value: Any) -> str | None:
    """A Channel the event filter can use: a non-empty string, else None."""
    if isinstance(value, dict):
        value = value.get("#text")
    if isinstance(value, str) and value:
        return value
    return None


def _eventid_filter_value(value: Any) -> int | None:
    """An EventID the event filter can use: an int, else None."""
    if isinstance(value, dict):
        value = value.get("#text")
    try:
        return int(value) if value is not None else None
    except (ValueError, TypeError):
        return None


def _field_path_plan(field_paths: tuple) -> dict:
    """Group pre-split field paths by top-level key: {key: ((rest, path), ...)}."""
    plan: dict[str, list] = {}
    for path in field_paths:
        plan.setdefault(path[0], []).append((path[1:], path))
    return {key: tuple(entries) for key, entries in plan.items()}


def _join_unnamed_event_data(event_dict: Any) -> None:
    """Store an event's unnamed ``<Data>`` values as one string, in place.

    Application-log sources such as MsiInstaller, MSSQL or classic
    PowerShell write their payload as unnamed ``<Data>`` elements, which
    pyevtx-rs reads as ``{"#text": [...]}`` and the XML reader as a list.
    Flattened as they are, either would become the repr of a Python list,
    with every backslash doubled, which rules on ``Data`` cannot match
    reliably. The values are joined with newlines instead: every such rule
    tests ``Data|contains``, which then holds when any one value does.
    Message gets the same text unless the event has one of its own, for the
    rules that read it there.
    """
    event = event_dict.get("Event") if isinstance(event_dict, dict) else None
    section = event.get("EventData") if isinstance(event, dict) else None
    if not isinstance(section, dict):
        return
    data = section.get("Data")
    if isinstance(data, dict) and data.keys() == {"#text"}:
        data = data["#text"]
        values = data if isinstance(data, list) else [data]
    elif isinstance(data, list):
        values = data
    else:
        return
    joined = "\n".join("" if value is None else str(value) for value in values)
    section["Data"] = joined
    section.setdefault("Message", joined)


class StrictParseError(Exception):
    """A parse error that --strict asked us to stop on.

    Distinct from the generic per-file failure so that the run aborts instead
    of continuing over a partially ingested file.
    """


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
                    f"[red]    [-] Error streaming {label} file {literal(source)}: {literal(exc)}[/]"
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


def _build_rows(batch, all_columns, all_columns_frozen, uniform):
    """Bind each event to ``all_columns``; a field the event lacks becomes NULL.

    Large-integer normalisation already happened while flattening. Plain Python on
    purpose: every step here is a C call already, and the compiled kernel measured
    slower (5.4 µs per event against 3.3 µs for ``map`` over ``dict.get``).
    """
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
        return rows
    if uniform and len(all_columns) > 1:
        # Every event shares the first event's columns (a stable source).
        row_getter = operator.itemgetter(*all_columns)
        return [row_getter(event) for event in batch]
    return [tuple(map(event.get, all_columns)) for event in batch]


def _load_native_kernel():
    """Return ``(module, None)``, or ``(None, reason)`` when it cannot be used.

    An extension built from an older ``flatten_kernel.py`` would silently apply
    the old flattening rules, so it counts as unavailable. Frozen builds ship no
    source to compare against; their extension is built in the same job.
    """
    try:
        native = importlib.import_module("zircolite._flatten_native")
    except ImportError as exc:
        return None, (f"native extension unavailable ({exc}); build it by rerunning pdm install, "
                      "uv sync or poetry install with a C compiler available")
    try:
        source = Path(__file__).with_name("flatten_kernel.py").read_bytes()
    except OSError:
        return native, None
    if getattr(native, "SOURCE_SHA256", None) != hashlib.sha256(source).hexdigest():
        return None, ("native extension is older than flatten_kernel.py; rebuild it by rerunning "
                      "pdm install, uv sync or poetry install")
    return native, None


def select_flatten_kernel(backend):
    """Choose native ingestion once; source checkouts need no compiler to run."""
    if backend not in ("auto", "python", "cython"):
        raise ValueError(f"Unknown flatten_backend: {backend}")
    if backend != "python":
        native, reason = _load_native_kernel()
        if native is not None:
            return native
        if backend == "cython":
            raise RuntimeError(f"Cython flattening cannot be used: {reason}, or use --flatten-backend auto")
    from . import flatten_kernel

    return flatten_kernel


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
        "_channel_field_plan",
        # Last field path that yielded a Channel/EventID value; tried first on
        # the next event since a file's schema is stable
        "_channel_path_hint",
        # DB column caching
        "_db_columns",
        "_detected_time_field",
        "_event_filter_config_enabled",
        "_eventid_field_paths",
        "_eventid_field_plan",
        "_eventid_path_hint",
        "_events_filtered_count",
        "_events_time_filtered_count",
        "_failed_splits",
        "_failed_transforms",
        "_filter_all_sources",
        "_filtering_enabled",
        "_flatten_impl",
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
        "evtx_threads",
        # Config data (loaded once)
        "field_exclusions",
        "field_mappings",
        "field_split_list",
        "field_types",
        "flattening_info",
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
        kernel = select_flatten_kernel(proc.flatten_backend)
        self.flattening_info = {
            "requested": proc.flatten_backend,
            "selected": "cython" if kernel.__name__.endswith("_flatten_native") else "python",
            "module": kernel.__name__, "path": kernel.__file__,
        }
        if proc.flatten_backend == "auto" and self.flattening_info["selected"] == "python":
            self.flattening_info["reason"] = _load_native_kernel()[1]
        self._flatten_impl = kernel.flatten_event
        self.archive_password = proc.archive_password
        self.strict_evtx = proc.strict_evtx
        self.evtx_threads = proc.evtx_threads

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
        self._channel_field_plan = _field_path_plan(self._channel_field_paths)
        self._eventid_field_plan = _field_path_plan(self._eventid_field_paths)

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
                        f"    [!] Transform on field '{literal(field_name)}' has no "
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

        # Bake only transforms which can run for this input and selection.
        # This also lets inactive transform fields take the simple leaf path.
        self._transforms_baked = {
            name: [spec for spec in specs if self._transform_applies(name, spec)]
            for name, specs in self._transforms_baked.items()
        } if self.transforms_enabled else {}
        self._transforms_baked = {name: specs for name, specs in self._transforms_baked.items() if specs}
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

    def _transform_applies(self, field_name: str, spec: _TransformSpec) -> bool:
        enabled = ((spec.alias_name or field_name) in self.enabled_transforms_set
                   if self.enabled_transforms_set is not None else spec.enabled)
        return enabled and (self._ignore_source_condition or self.chosen_input in spec.source_condition)

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
                        f"    [!] Transform for '{literal(field_name)}' has type python_file but no 'file' key – skipped"
                    )
                    transform["code"] = _NOOP_TRANSFORM_CODE
                    continue
                file_path = Path(rel_path)
                if not file_path.is_absolute():
                    file_path = self.transforms_dir / file_path
                try:
                    stat = file_path.stat()
                    transform["code"] = _read_transform(str(file_path), stat.st_mtime_ns, stat.st_size)
                except FileNotFoundError:
                    self.logger.error(
                        f"    [!] Transform file not found: {literal(file_path)} (field '{literal(field_name)}')"
                    )
                    transform["code"] = _NOOP_TRANSFORM_CODE
                except Exception as exc:
                    self.logger.error(
                        f"    [!] Error reading transform file {literal(file_path)}: {literal(exc)}"
                    )
                    transform["code"] = _NOOP_TRANSFORM_CODE

    def _extract_event_filter_fields(self, event_dict: dict) -> tuple:
        """
        Extract Channel and EventID from raw event data for early filtering.

        Every configured path is read. When the paths present in the event
        disagree, the value is None and the filter keeps the event: see
        ``_extract_field_value_hinted``.

        The field paths support:
        - Dot notation for nested fields (e.g., "Event.System.Channel")
        - Direct field names (e.g., "Channel")
        - Special handling for EventID which may be a dict with '#text'

        Args:
            event_dict: Raw event dictionary (not yet flattened)

        Returns:
            Tuple of (channel, eventid): channel is a non-empty str or None,
            eventid is int or None
        """
        if not isinstance(event_dict, dict):
            # A JSON line can hold any value; it is not this filter's to drop
            return None, None
        channel, self._channel_path_hint = self._extract_field_value_hinted(
            event_dict, self._channel_field_plan, self._channel_path_hint,
            _channel_filter_value,
        )
        eventid, self._eventid_path_hint = self._extract_field_value_hinted(
            event_dict, self._eventid_field_plan, self._eventid_path_hint,
            _eventid_filter_value,
        )
        return channel, eventid

    def _extract_field_value_hinted(
        self, event_dict: dict, field_plan: dict, hint: tuple | None,
        normalize: Callable[[Any], Any],
    ) -> tuple:
        """
        Extract a field value from every configured path, failing open.

        ``field_plan`` holds the configured paths grouped by top-level key
        (see ``_field_path_plan``); paths support dot notation for nested
        access (e.g. "Event.System.Channel"). Each value found goes through
        ``normalize``, which returns None for a value the filter cannot use.

        The filter runs before flattening, so it cannot read the column the
        rules query. When an event carries several of these paths, which one
        ends up in that column is decided by the flattener's traversal order
        and the field mappings, not by the configured order: a
        top-level ``Channel`` next to ``winlog.channel`` yields the nested
        value. So every path is read, and if two present paths disagree, or
        one holds an unusable value, the result is None and the filter keeps
        the event rather than discard it on a value no rule would have seen.

        An empty value does not count as found: a present-but-blank field would
        otherwise make the event look ambiguous when its real value sits in
        another candidate path.

        A previous winner is not evidence that other fields are absent from
        this event. Keep the hint for callers, but never let it change the
        result on mixed-schema inputs.

        Returns:
            Tuple of (value, winning_path). ``winning_path`` is a path that
            produced the value (the new hint), or the unchanged hint when no
            path matched.
        """
        found = None
        winner = hint
        # Every path is read on every event, and most are absent at their
        # top-level key. Walk whichever is shorter: the event's top-level keys
        # (one for EVTX) or the configured ones.
        keys = event_dict if len(event_dict) < len(field_plan) else field_plan
        for key in keys:
            entries = field_plan.get(key)
            if entries is None:
                continue
            node = event_dict.get(key)
            if node is None:
                continue
            for rest, path in entries:
                raw = node
                for part in rest:
                    if not isinstance(raw, dict):
                        raw = None
                        break
                    raw = raw.get(part)
                    if raw is None:
                        break
                if raw is None or raw == "":
                    continue
                value = normalize(raw)
                if value is None or (found is not None and value != found):
                    return None, winner
                if found is None:
                    found = value
                    winner = path
        return found, winner

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

    def _note_recovered_xml(self, source: str, error_log: Any) -> None:
        """Flag an XML file lxml had to recover: what was read is not what was written.

        Recovery drops the offending characters or markup and carries on, so
        the records around an error arrive incomplete rather than missing. The
        file is marked degraded, which also keeps --remove-events off it.
        """
        from lxml import etree  # type: ignore[attr-defined]

        errors = [e for e in error_log if e.level >= etree.ErrorLevels.ERROR]
        if not errors:
            return
        self._had_parse_error = True
        first = errors[0]
        self.logger.warning(
            f"[yellow]    [!] Recovered from {len(errors):,} XML error(s) in "
            f"{literal(Path(source).name)} (first at line {first.line}: "
            f"{literal(first.message)}); the records concerned may be incomplete[/]"
        )

    def _get_transform_func(self, code):
        """Get or create cached transform function."""
        func = self._transform_func_cache.get(code)
        if func is not None:
            return func
        try:
            byte_code = self.compiled_code_cache.get(code)
            if byte_code is None:
                byte_code = _compile_transform(code)
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
                    f"[yellow]   [!] Transform compilation failed: {literal(e)} "
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
                    f"untransformed: {literal(exc)} (code: {snippet!r})[/]"
                )
            return param

    def _flatten_event(self, event_dict: dict, filename: str, raw_bytes: bytes | None = None) -> dict | None:
        _join_unnamed_event_data(event_dict)
        return self._flatten_impl(self, event_dict, filename, raw_bytes)

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

            parser = (PyEvtxParser(path_to_parse, number_of_threads=self.evtx_threads)
                      if self.evtx_threads is not None else PyEvtxParser(path_to_parse))
            flatten = self._flatten_event  # Local reference for speed
            json_loads = json.loads
            should_process = self._should_process_event  # Local reference for speed

            for record in parser.records_json():
                if record is None:
                    continue
                try:
                    if isinstance(record, Exception):
                        raise record
                    raw_data = record.get("data")
                    if raw_data is None:
                        raise ValueError("EVTX record contains no event data")
                    event_dict = json_loads(raw_data)

                    # Early filter check before expensive flattening
                    if not should_process(event_dict):
                        continue

                    raw_bytes = raw_data.encode("utf-8") if self.hashes and isinstance(raw_data, str) else raw_data if self.hashes else None
                    flattened = flatten(event_dict, filename, raw_bytes)
                    if flattened:
                        yield flattened
                except Exception as e:
                    self._note_skipped_record(evtx_file, e)
                    if self.strict_evtx:
                        raise StrictParseError(f"Error processing EVTX record in {evtx_file}: {e}") from e
                    continue
        except StrictParseError:
            raise
        except Exception as e:
            err_msg = str(e)
            if (
                "Invalid EVTX" in err_msg or "ElfFile0" in err_msg
            ) and Path(evtx_file).suffix.lower() == ".7z":
                    self.logger.error(
                        f"[red]    [-] Error streaming EVTX file {literal(evtx_file)}: {literal(e)}[/]\n"
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
                f"[yellow]    [!] EVTX parsing error in {literal(evtx_file)}: {literal(e)} — "
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

        _fh = None
        try:
            filename = Path(xml_file).name
            flatten = self._flatten_event  # Local reference
            should_process = self._should_process_event  # Local reference
            xml_to_dict = extractor.xml_to_dict

            if Path(xml_file).suffix.lower() in COMPRESSED_SUFFIXES:
                _fh = open_maybe_compressed(xml_file, password=self.archive_password)
            else:
                _fh = open(xml_file, "rb")  # noqa: SIM115 -- closed in the finally below
            context = etree.iterparse(
                _xml_document_stream(_fh), events=("end",), recover=True
            )
            seen_events = False
            for _action, elem in context:
                # The exact name: UserData payloads such as CompatibilityFixEvent
                # belong to the record around them
                if elem.tag == "Event" or elem.tag.endswith("}Event"):
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

            self._note_recovered_xml(xml_file, context.error_log)
            if not seen_events:
                # Deliberately no --logs-encoding hint: XML is parsed with the
                # encoding declared in the document, so that flag changes
                # nothing here.
                self.logger.warning(
                    f"[yellow]    [!] No <Event> documents found in "
                    f"{literal(Path(xml_file).name)}; check that it is an EVTX-to-XML "
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
        data = f"<evtxtract>\n{_as_character_references(data)}\n</evtxtract>"

        # Parse with recovery mode for malformed XML
        parser = etree.XMLParser(recover=True)
        root = etree.fromstring(data, parser=parser)
        self._note_recovered_xml(log_file, parser.error_log)

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

        Uses ijson when installed, with a validating incremental fallback.
        Includes early event filtering based on channel/eventID and detects
        incomplete arrays even after yielding their valid prefix.
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

        with open_maybe_compressed(json_file, password=self.archive_password) as source:
            for event_dict in iter_json_array(source):
                flattened = process_one(event_dict)
                if flattened:
                    yield flattened

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
                    f"{literal(os.path.basename(log_file))}: {self._skipped_records:,} "
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
                f"[red]    [-] Partial ingest of {literal(os.path.basename(log_file))}: "
                f"{literal(e)}[/]\n"
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

        rows = _build_rows(batch, all_columns, all_columns_frozen, extra_columns is None)

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
                            f"events table: {literal(exc)}[/]"
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
            self.logger.error(f"[error]    [-] Error creating initial table: {literal(e)}[/]")
            raise
        finally:
            cursor.close()
