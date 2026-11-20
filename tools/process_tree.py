"""Process enumeration for benchmark and test observers."""

import ctypes
import os
import sys
from collections.abc import Iterator
from contextlib import suppress
from functools import lru_cache

import psutil


@lru_cache(maxsize=1)
def _mac_list_children():
    function = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True).proc_listchildpids
    function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
    function.restype = ctypes.c_int
    return function


def descendants(process: psutil.Process) -> Iterator[psutil.Process]:
    """Enumerate the measured tree. macOS can list our children without listing every process on the machine."""
    if sys.platform != "darwin":
        yield from process.children(recursive=True)
        return
    list_children = _mac_list_children()
    pending = [process.pid]
    seen = {process.pid}
    while pending:
        pid = pending.pop()
        capacity = 32
        while True:
            children = (ctypes.c_int * capacity)()
            count = list_children(pid, children, ctypes.sizeof(children))
            if count < 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            if count < capacity:
                break
            capacity *= 2
        for child in children[:count]:
            if child not in seen:
                seen.add(child)
                with suppress(psutil.NoSuchProcess):
                    yield psutil.Process(child)
                    pending.append(child)
