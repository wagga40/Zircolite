"""Reuse compressed viewer assets, checking every byte before appending run data."""

import hashlib
import os
import shutil
import tempfile
import zipfile
import zlib
from contextlib import suppress
from pathlib import Path

ZIP_LEVEL = 6
CACHE_VERSION = 1


def _key(entries: dict[str, bytes], context: bytes) -> str:
    digest = hashlib.sha256(f"{CACHE_VERSION}:{ZIP_LEVEL}:".encode() + context)
    for name, payload in entries.items():
        encoded = name.encode()
        digest.update(len(encoded).to_bytes(8, "big") + encoded)
        digest.update(len(payload).to_bytes(8, "big") + hashlib.sha256(payload).digest())
    return digest.hexdigest()


def _valid(path: Path, entries: dict[str, bytes]) -> bool:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) != len(entries) or {item.filename for item in members} != set(entries):
            return False
        for item in members:
            expected = entries[item.filename]
            if (item.file_size != len(expected) or item.compress_type != zipfile.ZIP_DEFLATED
                    or item.flag_bits & 1 or archive.read(item) != expected):
                return False
    return True


def _write_static(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=ZIP_LEVEL) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)


def _publish(source: Path, target: Path) -> None:
    """Publish a complete ZIP; competing exports can safely replace the same key."""
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".assets-", delete=False) as handle:
            staging = Path(handle.name)
            with source.open("rb") as incoming:
                shutil.copyfileobj(incoming, handle)
        os.replace(staging, target)
        versions = sorted(target.parent.glob("*.zip"), key=lambda path: path.stat().st_mtime_ns, reverse=True)
        others = [path for path in versions if path != target]
        for old in others[1:]:
            with suppress(OSError):
                old.unlink()
    finally:
        if staging is not None:
            with suppress(OSError):
                staging.unlink()


def prepare_archive(path: Path, entries: dict[str, bytes], *, context: bytes,
                    cache_directory: Path | None = None) -> None:
    """Copy and verify the cache in the build directory, or compress fresh assets.

    The cache contains only public viewer assets. No file from a run is ever
    published here, and verification uses the current bundled source bytes.
    """
    cached = None
    if cache_directory is not None and not os.environ.get("ZIRCOLITE_NO_CACHE"):
        cached = cache_directory / "package-assets" / f"{_key(entries, context)}.zip"
        try:
            shutil.copyfile(cached, path)
            if _valid(path, entries):
                return
        except (OSError, zipfile.BadZipFile, RuntimeError, ValueError, zlib.error):
            pass
    _write_static(path, entries)
    if cached is not None:
        with suppress(OSError):
            _publish(path, cached)
