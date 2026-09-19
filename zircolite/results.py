"""Temporary row storage and incremental serialization for detection output."""

import shutil
import tempfile

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


def write_result_json(write, result):
    """Write one result as bytes, without materializing its matches array."""
    matches = result.get("matches", ())
    metadata = result_summary(result)
    write(orjson.dumps(metadata, option=orjson.OPT_INDENT_2)[:-1])
    write(b',\n  "matches": [')
    if isinstance(matches, RowSpool):
        for chunk in matches.json_chunks():
            write(chunk)
    else:
        first = True
        for row in matches:
            if not first:
                write(b",")
            write(b"\n" + orjson.dumps(row))
            first = False
    write(b"\n  ]\n}")
