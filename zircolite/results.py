"""Temporary row storage and incremental serialization for detection output."""

import shutil
import tempfile
from typing import Any

import orjson


class RowSpool:
    """A repeatable row iterator backed by an automatically removed file.

    The file is created with the first row. Most rules match nothing, and
    creating and removing a temporary file costs about 0.1 ms per rule.
    """

    def __init__(self):
        self.file = None
        self.count = 0

    def __len__(self):
        return self.count

    def _writable(self):
        if self.file is None:
            self.file = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115 -- owned until close()
        return self.file

    def append(self, row):
        self._writable().write(orjson.dumps(row) + b"\n")
        self.count += 1

    def extend_serialized(self, source, rows):
        """Append ``rows`` rows that ``source`` already holds one JSON line each."""
        shutil.copyfileobj(source, self._writable())
        self.count += rows

    def checkpoint(self):
        return self.count, 0 if self.file is None else self.file.tell()

    def rollback(self, checkpoint):
        self.count, position = checkpoint
        if self.file is not None:
            self.file.seek(position)
            self.file.truncate()

    def __iter__(self):
        if self.file is None:
            return
        self.file.flush()
        self.file.seek(0)
        for line in self.file:
            yield orjson.loads(line)

    def json_chunks(self):
        """Reuse serialized rows when writing JSON; keep each copy bounded."""
        if self.file is None:
            return
        self.file.flush()
        self.file.seek(0)
        first = True
        while lines := self.file.readlines(65536):
            yield (b"\n" if first else b",\n") + b",".join(lines)
            first = False

    def close(self):
        if self.file is not None:
            self.file.close()


def result_summary(result):
    return {k: v for k, v in result.items() if k != "matches"}


RESULT_TAIL = b"\n  ]\n}"


def result_head(metadata):
    """A result's JSON up to the opening of its matches array."""
    return orjson.dumps(metadata, option=orjson.OPT_INDENT_2)[:-1] + b',\n  "matches": ['


def write_result_json(write, result):
    """Write one result as bytes, without materializing its matches array.

    Returns the bytes written before the matches and the bytes of the matches,
    which the matches of other results can be joined to with a comma.
    """
    matches = result.get("matches", ())
    head = result_head(result_summary(result))
    write(head)
    body = 0
    if isinstance(matches, RowSpool):
        for chunk in matches.json_chunks():
            write(chunk)
            body += len(chunk)
    else:
        first = True
        for row in matches:
            chunk = (b"\n" if first else b",\n") + orjson.dumps(row)
            write(chunk)
            body += len(chunk)
            first = False
    write(RESULT_TAIL)
    return len(head), body


def merge_result_spools(parts, destination):
    """Merge the result spools of a file's slices into one, rule by rule.

    ``parts`` lists ``(spool path or None, index)`` in slice order, where each
    index entry is ``(rule position, summary, matches offset, matches length)``
    as ``write_result_json`` laid it out. Each rule's matches are copied from
    every slice in order, without being parsed, under one summary whose count
    is the sum. Rules come in ruleset order, as one database writes them.
    Returns the merged summaries; with ``destination`` None, only those.
    """
    by_rule: dict[int, list[tuple[Any, dict, int, int]]] = {}
    for path, index in parts:
        for position, summary, offset, length in index:
            by_rule.setdefault(position, []).append((path, summary, offset, length))
    summaries = []
    for position in sorted(by_rule):
        entries = by_rule[position]
        merged = dict(entries[0][1])
        merged["count"] = sum(summary.get("count", 0) for _, summary, _, _ in entries)
        summaries.append(merged)
    if destination is None:
        return summaries
    sources: dict[Any, Any] = {}
    try:
        with open(destination, "wb") as out:
            out.write(b"[")
            for number, position in enumerate(sorted(by_rule)):
                if number:
                    out.write(b",\n")
                out.write(result_head(summaries[number]))
                joined = False
                for path, _, offset, length in by_rule[position]:
                    if not length:
                        continue
                    if joined:
                        out.write(b",")
                    source = sources.get(path)
                    if source is None:
                        source = sources[path] = open(path, "rb")  # noqa: SIM115 -- closed below
                    source.seek(offset)
                    _copy_range(source, out, length)
                    joined = True
                out.write(RESULT_TAIL)
            out.write(b"]")
    finally:
        for source in sources.values():
            source.close()
    return summaries


def _copy_range(source, out, length):
    while length:
        chunk = source.read(min(length, 1024 * 1024))
        if not chunk:
            raise OSError("result spool ended early")
        out.write(chunk)
        length -= len(chunk)
