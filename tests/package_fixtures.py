"""Helpers shared by the package tests: working databases in, packages out."""

import base64
import gzip
import re
import sqlite3
import zipfile
from pathlib import Path
from typing import Any

import orjson

_CHUNK = re.compile(rb'^__zircolite\.chunk\(("(?:[^"\\]|\\.)*"),(\d+),"([A-Za-z0-9+/=]*)"\);\n$', re.DOTALL)


def quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def make_logs(rows: list[dict[str, Any]], *, types: dict[str, str] | None = None,
              columns: list[str] | None = None) -> sqlite3.Connection:
    """A working database shaped like Zircolite's: row_id first, TEXT NOCASE columns.

    ``types`` overrides a column's declaration; an empty string declares no
    affinity, so integers and reals keep their type as they do in saved databases.
    """
    connection = sqlite3.connect(":memory:")
    names = columns or list(dict.fromkeys(key for row in rows for key in row))
    declared = ", ".join(
        f"{quote(name)} {(types or {}).get(name, 'TEXT COLLATE NOCASE')}".rstrip() for name in names)
    connection.execute(
        f"CREATE TABLE logs (row_id INTEGER PRIMARY KEY AUTOINCREMENT{', ' + declared if declared else ''})")
    for row in rows:
        keys = list(row)
        connection.execute(
            f"INSERT INTO logs ({', '.join(quote(key) for key in keys)}) VALUES ({', '.join('?' for _ in keys)})",
            [row[key] for key in keys])
    connection.commit()
    return connection


def read_spool(paths: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        with gzip.open(path, "rb") as handle:
            rows.extend(orjson.loads(line) for line in handle)
    return rows


def read_package(path: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    """The manifest of a package zip, and every wrapped file reassembled from its chunks."""
    with zipfile.ZipFile(path) as archive:
        script = archive.read("data/manifest.js")
        assert script.startswith(b"__zircolite.manifest(") and script.endswith(b");\n")
        manifest = orjson.loads(script[len(b"__zircolite.manifest("):-len(b");\n")])
        files: dict[str, bytes] = {}
        for entry in manifest["files"]:
            pieces = []
            for sequence, chunk in enumerate(entry["chunks"]):
                match = _CHUNK.match(archive.read(chunk))
                assert match is not None, chunk
                assert orjson.loads(match.group(1)) == entry["name"]
                assert int(match.group(2)) == sequence
                pieces.append(base64.b64decode(match.group(3)))
            files[entry["name"]] = b"".join(pieces)
    return manifest, files


def parquet_rows(data: bytes, tmp_path: Path, sql: str = "SELECT * FROM t") -> tuple[list[str], list[tuple]]:
    """Query Parquet bytes with duckdb as table ``t``: (column names, rows)."""
    import duckdb

    target = tmp_path / f"q-{abs(hash(data))}.parquet"
    target.write_bytes(data)
    connection = duckdb.connect(config={"autoinstall_known_extensions": False, "autoload_known_extensions": False})
    try:
        # A view cannot take a prepared parameter.
        quoted = "'" + str(target).replace("'", "''") + "'"
        connection.execute(f"CREATE VIEW t AS SELECT * FROM read_parquet({quoted})")
        cursor = connection.execute(sql)
        return [column[0] for column in cursor.description], cursor.fetchall()
    finally:
        connection.close()
