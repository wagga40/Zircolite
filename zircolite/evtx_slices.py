"""Large EVTX files read as several working databases.

EVTX chunks are self-contained: each carries its own string and template
tables. A run of chunks behind a copy of the file header, rewritten to count
only those chunks, is therefore an EVTX file of its own, and the parser reads
it record for record as it reads that part of the whole file. A file big
enough to keep one worker busy long after the others finish is split this way,
so its slices run in parallel and each working database holds a fraction of it.

Slices are sized by records, never by worker count: a column takes its type
from the first value it receives, so the cut must not depend on the machine.
"""

import io
import os
import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from os import PathLike
from pathlib import Path

EVTX_MAGIC = b"ElfFile\x00"
HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_MAGIC = b"ElfChnk\x00"
# A record takes 24 bytes at the very least, so a chunk header claiming more
# than this describes no records: unused chunks carry such numbers.
MAX_CHUNK_RECORDS = CHUNK_SIZE // 24

# Records per slice. A file holding fewer than two slices' worth is read whole.
SLICE_RECORDS = 65536


@dataclass(frozen=True)
class EvtxSlice:
    """Chunks ``chunks`` of ``path``, in the order the parser reads them.

    ``records`` bounds the row IDs the slice can take and ``row_id_base`` is
    the sum of those bounds over the slices before it, so a slice's events
    are numbered after the previous slices' and row IDs stay unique per file.
    ``os.fspath`` gives the file; ``str`` names the slice, which is how runs
    key their work.
    """

    path: str
    index: int
    count: int
    chunks: tuple[int, ...]
    records: int
    row_id_base: int

    def __fspath__(self) -> str:
        return self.path

    def __str__(self) -> str:
        return f"{self.path} [{self.index + 1}/{self.count}]"

    @property
    def name(self) -> str:
        return f"{Path(self.path).name} [{self.index + 1}/{self.count}]"

    @property
    def input_size(self) -> int:
        return HEADER_SIZE + CHUNK_SIZE * len(self.chunks)


def _chunk_headers(path: str | PathLike[str]) -> tuple[bytes, list[tuple[int, int, int, bool]]] | None:
    """The file header and ``(position, first, last, sane)`` per chunk, or None.

    None also means "read it whole": a slot without a chunk before the last
    chunk of the file. The parser skips an empty slot and stops at a garbled
    one, flagging the file; a plan would have to copy both behaviours exactly,
    so it does not try. Empty slots after the last chunk are preallocated
    space. A chunk cut short by the end of the file is never read, here or by
    the parser on the whole file.
    """
    chunks = []
    with open(path, "rb", buffering=0) as source:
        header = source.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE or not header.startswith(EVTX_MAGIC):
            return None
        slots = (os.fstat(source.fileno()).st_size - HEADER_SIZE) // CHUNK_SIZE
        gap = False
        for position in range(slots):
            source.seek(HEADER_SIZE + position * CHUNK_SIZE)
            head = source.read(24)
            if len(head) < 24 or not head.startswith(CHUNK_MAGIC):
                gap = True
                continue
            if gap:
                return None
            first, last = struct.unpack_from("<QQ", head, 8)
            chunks.append((position, first, last, first <= last < first + MAX_CHUNK_RECORDS))
    return header, chunks


def plan_slices(path: str | PathLike[str], records: int = SLICE_RECORDS) -> list[EvtxSlice]:
    """The slices of ``path``, or ``[]`` when it should be read whole.

    The parser starts at the chunk holding the lowest record number and wraps
    around the end of the file, which is where a circular log keeps its
    oldest events, so the slices follow that order.
    """
    try:
        read = _chunk_headers(path)
    except OSError:
        return []
    if read is None:
        return []
    _, chunks = read
    sane = [chunk for chunk in chunks if chunk[3]]
    if sum(last - first + 1 for _, first, last, _ in sane) < 2 * records:
        return []
    start = min(sane, key=lambda chunk: chunk[1])[0]
    ordered = chunks[start:] + chunks[:start]
    groups: list[list[tuple[int, int, int, bool]]] = []
    current: list[tuple[int, int, int, bool]] = []
    held = 0
    for chunk in ordered:
        current.append(chunk)
        if chunk[3]:
            held += chunk[2] - chunk[1] + 1
        if held >= records:
            groups.append(current)
            current, held = [], 0
    if current:
        groups.append(current)
    if len(groups) < 2:
        return []
    slices = []
    base = 0
    for index, group in enumerate(groups):
        # A chunk whose header cannot be trusted may still hold records: it is
        # given room for as many as a chunk can carry.
        bound = sum(last - first + 1 if ok else MAX_CHUNK_RECORDS for _, first, last, ok in group)
        slices.append(EvtxSlice(str(path), index, len(groups), tuple(chunk[0] for chunk in group), bound, base))
        base += bound
    return slices


def slice_header(header: bytes, chunk_count: int) -> bytes:
    """``header`` rewritten for a file of ``chunk_count`` chunks."""
    patched = bytearray(header[:HEADER_SIZE])
    struct.pack_into("<QQ", patched, 8, 0, chunk_count - 1)
    struct.pack_into("<H", patched, 42, chunk_count)
    struct.pack_into("<I", patched, 124, zlib.crc32(bytes(patched[:120])))
    return bytes(patched)


class SliceReader(io.RawIOBase):
    """A slice as a file: the rewritten header, then its chunks back to back."""

    def __init__(self, evtx_slice: EvtxSlice) -> None:
        super().__init__()
        self._source = open(evtx_slice.path, "rb", buffering=0)  # noqa: SIM115 -- closed by close()
        try:
            header = self._source.read(HEADER_SIZE)
            if len(header) < HEADER_SIZE or not header.startswith(EVTX_MAGIC):
                raise ValueError(f"{evtx_slice.path} is no longer an EVTX file")
        except BaseException:
            self._source.close()
            raise
        self._header = slice_header(header, len(evtx_slice.chunks))
        self._chunks = evtx_slice.chunks
        self._size = HEADER_SIZE + CHUNK_SIZE * len(evtx_slice.chunks)
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            position = offset
        elif whence == io.SEEK_CUR:
            position = self._position + offset
        elif whence == io.SEEK_END:
            position = self._size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if position < 0:
            raise ValueError("negative seek position")
        self._position = position
        return position

    def readinto(self, buffer) -> int:  # type: ignore[no-untyped-def]
        view = memoryview(buffer).cast("B")
        done = 0
        for piece in self._pieces(len(view)):
            if isinstance(piece, bytes):
                view[done:done + len(piece)] = piece
                got = len(piece)
            else:
                offset, length = piece
                self._source.seek(offset)
                got = self._source.readinto(view[done:done + length]) or 0
                if got < length:
                    # The next piece belongs after the bytes not read.
                    done += got
                    self._position += got
                    break
            done += got
            self._position += got
        return done

    def _pieces(self, wanted: int) -> Iterator[bytes | tuple[int, int]]:
        """What to copy for the next ``wanted`` bytes: header bytes, or (file offset, length)."""
        position, end = self._position, min(self._size, self._position + wanted)
        while position < end:
            if position < HEADER_SIZE:
                piece = self._header[position:min(HEADER_SIZE, end)]
                yield piece
                position += len(piece)
                continue
            chunk, offset = divmod(position - HEADER_SIZE, CHUNK_SIZE)
            length = min(CHUNK_SIZE - offset, end - position)
            yield HEADER_SIZE + self._chunks[chunk] * CHUNK_SIZE + offset, length
            position += length

    def close(self) -> None:
        if not self.closed:
            self._source.close()
        super().close()
