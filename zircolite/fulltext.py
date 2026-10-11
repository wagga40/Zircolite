"""Private source-value search text and its SQLite provenance."""

import sqlite3
from typing import Any

FIELD = "_sigma_fulltext"
PROVENANCE = "_zircolite_fulltext"
REPRESENTATION = "source-values-v1"


def source_values(event: Any) -> str:
    """Serialize decoded scalar leaves before metadata, mapping or flattening.

    Iterative, and indifferent to key names: what an event contains must never
    be a reason to drop it.
    """
    values: list[str] = []
    stack: list[Any] = [event]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node[key] for key in sorted(node, reverse=True))
        elif isinstance(node, (list, tuple)):
            stack.extend(reversed(node))
        elif isinstance(node, str):
            values.append(node)
        elif isinstance(node, bool):
            values.append("true" if node else "false")
        elif node is not None and isinstance(node, (int, float)):
            values.append(str(node))
    return "\n".join(values)


def _provenance_exists(connection: sqlite3.Connection) -> bool:
    existing = connection.execute(
        "SELECT type FROM sqlite_master WHERE lower(name)=lower(?)", (PROVENANCE,)
    ).fetchone()
    if existing is None:
        return False
    columns = connection.execute(f'PRAGMA table_info("{PROVENANCE}")').fetchall()
    shape = [(row[1], row[2].upper(), row[3], row[4], row[5]) for row in columns]
    if existing[0] != "table" or shape != [
        ("source_table", "TEXT", 0, None, 1),
        ("field", "TEXT", 1, None, 0),
        ("representation", "TEXT", 1, None, 0),
    ]:
        raise ValueError("Keyword search provenance table is unrelated; re-ingest events")
    rows = connection.execute(
        'SELECT source_table, field, representation FROM "_zircolite_fulltext"'
    ).fetchall()
    if rows != [("logs", FIELD, REPRESENTATION)]:
        raise ValueError("Keyword search provenance table is unrelated; re-ingest events")
    return True


def ensure_provenance(connection: sqlite3.Connection) -> None:
    """Record the representation without adopting an unrelated private table."""
    if not _provenance_exists(connection):
        if connection.execute("SELECT 1 FROM logs LIMIT 1").fetchone() is not None:
            raise ValueError("Existing logs lack keyword search provenance; re-ingest events")
        connection.execute(
            f'CREATE TABLE "{PROVENANCE}" ('
            'source_table TEXT PRIMARY KEY, field TEXT NOT NULL, representation TEXT NOT NULL)'
        )
        connection.execute(
            'INSERT INTO "_zircolite_fulltext" VALUES (?, ?, ?)',
            ("logs", FIELD, REPRESENTATION),
        )


def reset_provenance(connection: sqlite3.Connection) -> None:
    """Drop only Zircolite's own provenance when resetting captured logs."""
    if _provenance_exists(connection):
        connection.execute('DROP TABLE "_zircolite_fulltext"')


def require_provenance(connection: sqlite3.Connection, requirements: list[dict]) -> None:
    """Reject old or foreign databases before a keyword rule runs."""
    for item in requirements:
        if item.get("table", "").strip('"').lower() != "logs" or item.get("field", "").lower() != FIELD:
            raise ValueError("Keyword search source is unavailable; re-ingest events with Zircolite")
    if not _provenance_exists(connection):
        raise ValueError("Keyword search provenance is unavailable; re-ingest events with Zircolite")


def clean(value: Any) -> Any:
    """Remove private search text from ordinary rows and nested evidence."""
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items()
                if not (isinstance(key, str) and key.lower() == FIELD)}
    if isinstance(value, list):
        return [clean(item) for item in value]
    return value
