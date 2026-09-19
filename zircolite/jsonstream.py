"""Validated JSON-array iteration with bounded buffering and optional C parsing."""

import codecs
import json
from decimal import Decimal

try:
    import ijson
except ImportError:
    ijson = None

_CHUNK = 65536
_MAX_OBJECT = 64 * 1024 * 1024


class _PrefixedReader:
    def __init__(self, prefix, source):
        self.prefix = prefix
        self.source = source

    def read(self, size=-1):
        if size == 0:
            return b""
        if size < 0:
            data, self.prefix = self.prefix, b""
            return data + self.source.read()
        data, self.prefix = self.prefix[:size], self.prefix[size:]
        return data + self.source.read(size - len(data))


def _float_values(value):
    """ijson's Decimal default preserves large ints; SQLite expects floats."""
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {k: _float_values(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_float_values(v) for v in value]
    return value


def iter_json_array(source):
    """Yield complete objects, raising on malformed syntax or an incomplete tail.

    Scalars in an otherwise valid array are ignored, matching the log reader's
    existing contract. At most one event plus a read buffer is materialized.
    """
    prefix = source.read(3)
    if prefix == b"\xef\xbb\xbf":
        prefix = b""
    reader = _PrefixedReader(prefix, source)
    while True:
        char = reader.read(1)
        if char not in (b" ", b"\t", b"\r", b"\n"):
            break
    if char != b"[":
        raise ValueError("Expected a JSON array")
    reader = _PrefixedReader(char, reader)
    if ijson is not None:
        # Avoid use_float=True: some C backends then overflow on uint64 values.
        for item in ijson.items(reader, "item", use_float=False):
            if isinstance(item, dict):
                yield _float_values(item)
        return
    yield from _iter_stdlib(reader)


def _iter_stdlib(source):
    decoder = json.JSONDecoder(parse_constant=lambda value: _invalid(value))
    utf8 = codecs.getincrementaldecoder("utf-8")()
    buffer = ""
    eof = False
    state = "start"
    while True:
        buffer = buffer.lstrip(" \t\r\n")
        if state == "done":
            if buffer:
                raise ValueError("Trailing content after JSON array")
            if eof:
                return
        elif buffer:
            if state == "start":
                if buffer[0] != "[":
                    raise ValueError("Expected a JSON array")
                buffer, state = buffer[1:], "first"
                continue
            if state in ("first", "comma") and buffer[0] == "]":
                buffer, state = buffer[1:], "done"
                continue
            if state == "comma":
                if buffer[0] != ",":
                    raise ValueError("Expected comma between JSON array elements")
                buffer, state = buffer[1:], "value"
                continue
            try:
                item, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if eof:
                    raise
            else:
                # A scalar number may continue in the next chunk. Do not emit
                # it until its delimiter has arrived.
                if end < len(buffer) or eof:
                    buffer, state = buffer[end:], "comma"
                    if isinstance(item, dict):
                        yield item
                    continue
        if eof:
            raise ValueError("Incomplete JSON array")
        if len(buffer) > _MAX_OBJECT:
            raise ValueError("JSON array element exceeds 64 MiB")
        chunk = source.read(_CHUNK)
        eof = not chunk
        buffer += utf8.decode(chunk, final=eof)


def _invalid(value):
    raise ValueError(f"Invalid JSON constant: {value}")
