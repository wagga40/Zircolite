"""Row exports of the shipped templates, rendered without Jinja.

The NDJSON, Splunk, ELK, Zinc and Timesketch templates print one JSON object
per match. The command line renders them where the matches are, as a result
sink of every working database, process workers included, so this module needs
only the standard library and orjson. The main process then copies the parts
into each destination; library callers render their results in one go.
"""

import os
import secrets
import shutil
import tempfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

import orjson

ROW_EXPORTS = frozenset({"ndjson", "splunk", "splunk-id", "elk", "zinc", "timesketch"})
_FLAT_EXPORTS = frozenset({"elk", "zinc", "timesketch"})
_NESTED = (dict, list)
_HTML_ESCAPES = ((b"<", b"\\u003c"), (b">", b"\\u003e"), (b"&", b"\\u0026"), (b"'", b"\\u0027"))
_ZINC_ACTION = b'{ "index" : { "_index" : "zircolite" } } \n'
COPY_BYTES = 1 << 20


class ExportError(Exception):
    """A row export the user asked for cannot be written."""


def export_json(value: Any) -> bytes:
    """``value`` as JSON with sorted keys, escaped for HTML like Jinja's ``tojson``.

    ``tojson`` also escapes non-ASCII text as ``\\u`` sequences; this writes
    UTF-8, which every JSON reader decodes to the same text.
    """
    data = orjson.dumps(value, option=orjson.OPT_SORT_KEYS)
    for raw, escaped in _HTML_ESCAPES:
        if raw in data:
            data = data.replace(raw, escaped)
    return data


def flat_json(value: Any) -> Any:
    """A nested value as JSON text, for targets that want one scalar per field.

    Elasticsearch maps every key of a nested object as a field of its own, so a
    correlation alert's evidence would add one field per event column and soon
    exceed the index's field limit; a flat table shows each value as text.
    """
    if isinstance(value, _NESTED):
        return orjson.dumps(value).decode()
    return value


def _metadata(kind: str, result: dict[str, Any]) -> bytes:
    """The rule's fields that open every row, without the closing brace."""
    metadata = {"title": result["title"], "description": result["description"]}
    if kind != "splunk":
        metadata["id"] = result["id"]
    if kind in ("ndjson", "timesketch"):
        metadata["rule_level"] = result["rule_level"]
    if kind == "timesketch":
        metadata.update(message=result["title"], timestamp_desc="Event time")
    return export_json(metadata)[:-1]


def export_rows(kind: str, results: Iterable[dict[str, Any]], time_field: str) -> Iterator[bytes]:
    """The lines ``kind`` prints for ``results``, one per match."""
    flatten = kind in _FLAT_EXPORTS
    for result in results:
        prefix = None
        for match in result.get("matches", ()):
            if prefix is None:
                prefix = _metadata(kind, result)
            row = match
            if flatten and any(isinstance(value, _NESTED) for value in match.values()):
                row = {key: flat_json(value) for key, value in match.items()}
            if kind == "zinc":
                yield _ZINC_ACTION
            # Keep metadata and event fields separate: the original templates
            # emit both when a log field collides with a metadata key.
            fields = b"," + export_json(row)[1:] if row else b"}"
            if kind == "timesketch":
                yield prefix + b',"datetime":' + export_json(match.get(time_field, "")) + fields + b"\n"
            else:
                yield prefix + fields + b"\n"


def _replace(target: Path, chunks: Iterable[bytes]) -> None:
    """Write a sibling temporary file, then rename it over ``target``."""
    target = target.resolve()
    temporary = target.parent / f".zircolite-{secrets.token_hex(8)}.tmp"
    try:
        with temporary.open("xb", buffering=COPY_BYTES) as handle:
            handle.writelines(chunks)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def write_export(destination: str, chunks: Iterable[bytes], append: bool) -> None:
    """Stage bounded chunks before touching the destination, even in append mode."""
    target = Path(destination)
    if append or target.exists():
        # Preserve normal open semantics for hard links, pipes, permissions,
        # and writable files in non-writable directories. Keep the original
        # path: resolving /dev/stdout can turn it into an unopenable pipe name.
        with tempfile.TemporaryFile(buffering=COPY_BYTES) as staged:
            staged.writelines(chunks)
            staged.seek(0)
            with target.open("ab" if append else "wb", buffering=COPY_BYTES) as output:
                shutil.copyfileobj(staged, output, COPY_BYTES)
        return
    _replace(target, chunks)


def write_spooled(destination: str, files: Iterable[str], append: bool,
                  progress: Callable[[int, int], None] | None = None) -> None:
    """Copy finished part files into the destination, in order.

    The parts are complete before the destination is opened, so unlike
    ``write_export`` nothing needs staging first.
    """
    paths = list(files)
    total = sum(os.path.getsize(path) for path in paths)

    def chunks() -> Iterator[bytes]:
        done = 0
        for path in paths:
            with open(path, "rb") as source:
                while block := source.read(COPY_BYTES):
                    yield block
                    done += len(block)
                    if progress is not None:
                        progress(done, total)

    target = Path(destination)
    if append or target.exists():
        with target.open("ab" if append else "wb", buffering=0) as output:
            for block in chunks():
                output.write(block)
        return
    _replace(target, chunks())


@dataclass
class ExportPartRecord:
    """One working database's rendered rows, by export kind. Plain data, for process workers."""

    files: dict[str, str] = field(default_factory=dict)
    rows: int = 0


@dataclass
class ExportSpool:
    """Where the row exports of each working database are written, and how.

    It reaches process workers inside the ProcessingContext payload, so it
    holds plain data only.
    """

    directory: str
    kinds: tuple[str, ...]
    time_field: str

    def open_part(self) -> "ExportPart":
        return ExportPart(self)


class ExportPart:
    """One working database's rows for every row export of the run, written as rules report them."""

    def __init__(self, spool: ExportSpool) -> None:
        self.spool = spool
        self.record = ExportPartRecord()
        self._handles: dict[str, BinaryIO] = {}
        self._error: str | None = None

    def sink(self, result: dict[str, Any]) -> None:
        """A result sink for ``execute_ruleset``.

        A failure is kept rather than raised: an exception here would stop the
        rule loop and lose the detections output with it. After the first one
        nothing more is written, and ``finish`` raises it.
        """
        if self._error is not None or not result.get("matches"):
            return
        try:
            for kind in self.spool.kinds:
                self._handle(kind).writelines(export_rows(kind, (result,), self.spool.time_field))
            self.record.rows += len(result["matches"])
        except (OSError, ValueError, TypeError) as exc:
            self._error = str(exc)

    def _handle(self, kind: str) -> BinaryIO:
        handle = self._handles.get(kind)
        if handle is None:
            fd, path = tempfile.mkstemp(dir=self.spool.directory, prefix=f"{kind}-", suffix=".part")
            self.record.files[kind] = path
            handle = self._handles[kind] = os.fdopen(fd, "wb", buffering=COPY_BYTES)
        return handle

    def _close(self) -> OSError | None:
        first: OSError | None = None
        for handle in self._handles.values():
            try:
                handle.close()
            except OSError as exc:
                first = first or exc
        self._handles.clear()
        return first

    def finish(self) -> ExportPartRecord:
        close_error = self._close()
        if self._error is None and close_error is not None:
            self._error = f"cannot write an export part: {close_error}"
        if self._error is not None:
            self.discard()
            raise ExportError(self._error)
        return self.record

    def discard(self) -> None:
        self._close()
        for path in self.record.files.values():
            Path(path).unlink(missing_ok=True)
