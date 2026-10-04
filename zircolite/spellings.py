"""Field spellings that differ from the ``logs`` column holding them.

SQLite column names are case-insensitive, so ``ProcessId`` and ``ProcessID``
share one column, named after whichever spelling reached that database first.
Which one that is depends on the files the database holds, so the same event
would be printed one way per file and another way unified. Ingestion records
the rows that carried another spelling, and output gives each one back.
"""

import sqlite3
from typing import Any

import orjson
from pyroaring import BitMap64

# Saved databases may contain negative row IDs; bitmaps hold unsigned ones.
_UNSIGNED = (1 << 64) - 1


def record_spellings(cursor: sqlite3.Cursor, first_row_id: int,
                     spelled: list[tuple[int, tuple[str, ...]]]) -> None:
    """Record the spellings of rows just inserted from ``first_row_id`` onward.

    ``spelled`` holds ``(position in the batch, spellings)`` pairs. Run it in
    the batch's transaction: a batch that rolls back must take its record too.
    """
    cursor.execute("CREATE TABLE IF NOT EXISTS field_spellings "
                   "(id INTEGER PRIMARY KEY, names TEXT NOT NULL UNIQUE)")
    cursor.execute("CREATE TABLE IF NOT EXISTS logs_spelling "
                   "(row_id INTEGER PRIMARY KEY, spelling INTEGER NOT NULL)")
    ids: dict[tuple[str, ...], int] = {}
    rows = []
    for position, names in spelled:
        spelling = ids.get(names)
        if spelling is None:
            text = orjson.dumps(names).decode()
            cursor.execute("INSERT OR IGNORE INTO field_spellings(names) VALUES (?)", (text,))
            spelling = ids[names] = cursor.execute(
                "SELECT id FROM field_spellings WHERE names = ?", (text,)).fetchone()[0]
        rows.append((first_row_id + position, spelling))
    cursor.executemany("INSERT INTO logs_spelling(row_id, spelling) VALUES (?, ?)", rows)


def drop_spellings(connection: sqlite3.Connection) -> None:
    """Forget every record; the next table numbers its rows from one again."""
    connection.execute("DROP TABLE IF EXISTS logs_spelling")
    connection.execute("DROP TABLE IF EXISTS field_spellings")


class FieldSpellings:
    """The names rows read back from ``logs`` are printed under.

    Each event keeps its own spelling, except the run's time field, which
    always carries the name the run gives it: templates and the package viewer look
    the time up by that name.
    """

    __slots__ = ("_any", "_others", "_renamed", "_spellings", "_time")

    def __init__(self, recorded: list[tuple[Any, dict[str, str]]], time_field: str | None, time_column: str | None):
        self._time = {time_field.lower(): time_field} if time_field else {}
        self._spellings = [(rows, {**names, **self._time}) for rows, names in recorded]
        # Rows with no record of their own still carry the time column's spelling.
        self._renamed = self._time if time_column is not None and time_column != time_field else {}
        self._any = BitMap64()
        self._others: dict[str, set[str]] = {}
        for rows, names in recorded:
            self._any |= rows
            for lower, name in names.items():
                self._others.setdefault(lower, set()).add(name)

    @classmethod
    def load(cls, connection: sqlite3.Connection, time_field: str | None = None) -> "FieldSpellings | None":
        """How this database's rows are to be named, or None when they keep the column names."""
        tables = {name for (name,) in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name IN ('field_spellings', 'logs_spelling')")}
        recorded = []
        if len(tables) == 2:
            names = {spelling: orjson.loads(text)
                     for spelling, text in connection.execute("SELECT id, names FROM field_spellings")}
            rows: dict[int, list[int]] = {spelling: [] for spelling in names}
            for row_id, spelling in connection.execute("SELECT row_id, spelling FROM logs_spelling"):
                if spelling in rows:
                    rows[spelling].append(row_id & _UNSIGNED)
            recorded = [(BitMap64(rows[spelling]), {name.lower(): name for name in names[spelling]})
                        for spelling in names]
        time_column = None
        if time_field:
            lower = time_field.lower()
            time_column = next((column for _, column, *_ in connection.execute("PRAGMA table_info(logs)")
                                if column.lower() == lower), None)
        spellings = cls(recorded, time_field, time_column)
        return spellings if recorded or spellings._renamed else None

    def names_for(self, column: str) -> list[str]:
        """Every name rows print ``column``'s values under."""
        lower = column.lower()
        if lower in self._time:
            return [self._time[lower]]
        return [column, *sorted(self._others.get(lower, set()) - {column})]

    def restore(self, event: dict[str, Any]) -> dict[str, Any]:
        """``event`` under the names it is printed with."""
        row_id = event.get("row_id")
        if isinstance(row_id, int):
            identity = row_id & _UNSIGNED
            if identity in self._any:
                for rows, names in self._spellings:
                    if identity in rows:
                        return {names.get(key.lower(), key): value for key, value in event.items()}
        renamed = self._renamed
        if not renamed:
            return event
        return {renamed.get(key.lower(), key): value for key, value in event.items()}
