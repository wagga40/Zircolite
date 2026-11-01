"""Stage one's event copy, serial and parallel, against a plain row-by-row copy.

``reference`` walks every column of every row, with none of the shortcuts the
real copy takes. Every way of copying has to give the same lines, in the same
order, and the same census.
"""

import errno
import random
import sqlite3
from concurrent.futures import Future
from concurrent.futures.process import BrokenProcessPool
from itertools import pairwise
from pathlib import Path
from typing import Any

import orjson
import pytest

from tests.package_fixtures import make_logs, open_spool
from zircolite import package_spool
from zircolite.package_spool import (
    FULLTEXT_FIELD,
    TYPE_BITS,
    PackageError,
    PackageSpool,
    _event_time,
    _ranges,
    _row_spellings,
    _spelling_without,
    _text,
    ascii_lower,
)
from zircolite.spellings import record_spellings


def reference(connection: sqlite3.Connection, time_field: str = "SystemTime",
              timestamp_format: str = "iso", part: int = 0) -> tuple[list[bytes], dict[str, Any]]:
    """Every line a column-by-column walk of each row writes, and the census it records."""
    columns = [row[1] for row in connection.execute("PRAGMA table_info(logs)")]
    private = [name for name in columns if ascii_lower(name) == FULLTEXT_FIELD]
    if private:
        columns = [name for name in columns if name not in private]
    projection = ", ".join('"' + name.replace('"', '""') + '"' for name in columns) if private else "*"
    names = columns[1:]
    keys = [ascii_lower(name) for name in names]
    time_key = ascii_lower(time_field)
    time_at = keys.index(time_key) + 1 if time_key in keys else None
    channel_at = keys.index("channel") + 1 if "channel" in keys else None
    eventid_at = keys.index("eventid") + 1 if "eventid" in keys else None
    masks = [0] * len(keys)
    counts = [0] * len(keys)
    families: dict[tuple[str | None, str | None], set[int]] = {}
    time_stats: dict[str, Any] = {"column": names[time_at - 1] if time_at else None,
                                  "min": None, "max": None, "unparsed": 0, "missing": 0}
    spellings: dict[str, str | None] = {}
    spelled = _row_spellings(connection)
    pending = next(spelled, None)
    lines = []
    for row in connection.execute(f"SELECT {projection} FROM logs ORDER BY row_id"):
        row_id = row[0]
        record: dict[str, Any] = {"_zl_part": part, "_zl_rid": row_id}
        present: list[int] = []
        for index in range(1, len(row)):
            value = row[index]
            if value is None:
                continue
            kind = type(value)
            masks[index - 1] |= TYPE_BITS[kind]
            counts[index - 1] += 1
            record[keys[index - 1]] = value.hex() if kind is bytes else value
            present.append(index - 1)
        record["_zl_time"] = _event_time(row, time_at, timestamp_format, time_stats)
        while pending is not None and pending[0] < row_id:
            pending = next(spelled, None)
        if pending is not None and pending[0] == row_id:
            spelling = _spelling_without(pending[1], time_key, spellings, row_id)
            if spelling is not None:
                record["_zl_spelling"] = spelling
        family = (_text(row[channel_at]) if channel_at else None, _text(row[eventid_at]) if eventid_at else None)
        families.setdefault(family, set()).update(present)
        lines.append(orjson.dumps(record))
    return lines, {
        "events": len(lines),
        "longest_line": max(map(len, lines), default=0),
        "columns": [{"name": names[i], "key": keys[i], "mask": masks[i], "count": counts[i]}
                    for i in range(len(keys)) if counts[i]],
        "families": [{"channel": channel, "eventid": eventid, "keys": sorted(keys[i] for i in indexes)}
                     for (channel, eventid), indexes in families.items()],
        "time": time_stats,
    }


def spooled(record) -> list[bytes]:
    lines: list[bytes] = []
    for path in record.event_files:
        with open_spool(path) as handle:
            lines.extend(line.rstrip(b"\n") for line in handle)
    return lines


def census(record) -> dict[str, Any]:
    return {"events": record.events, "longest_line": record.longest_line, "columns": record.columns,
            "families": record.families, "time": record.time}


def assert_same_as_reference(record, connection, **options):
    lines, expected = reference(connection, **options)
    assert spooled(record) == lines
    assert census(record) == expected


def seeded(seed: Any) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test inputs


CHANNELS = [None, "Security", "Microsoft-Windows-Sysmon/Operational", "", 1, 1.0, "1", -0.0, 0]
EVENTIDS = [None, 4624, "4624", 1, 1.5, "1", 0, b"\x01"]
TIMES = [None, "2021-06-03T06:36:55.9282437Z", "2021-06-03 06:36:55", "not a time", "", "1622700000123",
         1622700000, 1622700000.5, 1e30, b"\x00"]
EXTRA = ["Computer", "CommandLine", "naïve", 'Quo"ted', "with space", "Num", "Real", "Raw", "MiXeD",
         "É", "é", "rowid", "oid", "Rare", "Empty"]


def value(rng: random.Random) -> Any:
    return rng.choice([
        rng.randint(-5, 5), rng.randint(-(1 << 63), (1 << 63) - 1), rng.random() * 10 ** rng.randint(-5, 300),
        0.1 + 0.2, float("inf"), -0.0, "", "x", "é\n\"tab\t\\", "a" * rng.randint(0, 300), "4624",
        bytes(rng.randrange(256) for _ in range(rng.randint(0, 6))),
    ])


def random_table(rng: random.Random, count: int, *, path: Path | None = None,
                 fulltext: bool = False) -> sqlite3.Connection:
    """Rows mostly cut from a few templates, as event families are, with random strays."""
    extra = rng.sample(EXTRA, rng.randint(3, len(EXTRA)))
    templates = [(rng.choice(CHANNELS), rng.choice(EVENTIDS), [n for n in extra if rng.random() < 0.4])
                 for _ in range(rng.randint(1, 6))]
    rows = []
    for _ in range(count):
        channel, eventid, filled = rng.choice(templates)
        if rng.random() < 0.2:
            filled = [n for n in extra if rng.random() < 0.3]
        if rng.random() < 0.1:
            channel, eventid = rng.choice(CHANNELS), rng.choice(EVENTIDS)
        row = {"Channel": channel, "EventID": eventid, "SystemTime": rng.choice(TIMES)}
        row.update({name: value(rng) for name in filled})
        if fulltext:
            row[FULLTEXT_FIELD] = "private words"
        rows.append(row)
    columns = ["Channel", "EventID", "SystemTime", *extra, *([FULLTEXT_FIELD] if fulltext else [])]
    # Mostly no affinity, so values keep their type; some columns as Zircolite declares them.
    types = {name: rng.choice(["", "", "TEXT COLLATE NOCASE", "INTEGER", "REAL"]) for name in columns}
    connection = make_logs(rows, types=types, columns=columns, path=path)
    spelled = [(position, tuple(rng.sample(["ProcessID", "SYSTEMTIME", "systemtime", "CommandLINE"],
                                           rng.randint(1, 3))))
               for position in sorted(rng.sample(range(count), count // 7))]
    if spelled:
        record_spellings(connection.cursor(), 1, spelled)
        connection.commit()
    return connection


@pytest.fixture
def spool(tmp_path):
    directory = tmp_path / "spool"
    directory.mkdir()
    return PackageSpool(directory=str(directory), time_field="SystemTime")


def export(spool, connection, part=0, progress=None):
    writer = spool.open_part(part, ["input"])
    writer.export_events(connection, progress)
    return writer


@pytest.fixture
def parallel(monkeypatch):
    """Copy any file-backed part in parallel, over a few processes, cutting files short."""
    monkeypatch.setattr(package_spool, "PARALLEL_MIN_ROWS", 1)
    monkeypatch.setattr(package_spool, "PARALLEL_MAX_WORKERS", 3)
    monkeypatch.setattr(package_spool, "_usable_cpus", lambda: 4)
    monkeypatch.setattr(package_spool, "ROWS_PER_SPOOL_FILE", 7)
    monkeypatch.setattr(package_spool, "SPOOL_WRITE_BYTES", 256)
    # Several batches per range, so the processes narrow their reads too.
    monkeypatch.setattr(package_spool, "FETCH_ROWS", 4)


def range_files(record) -> bool:
    return bool(record.event_files) and all("-r" in Path(path).name for path in record.event_files)


@pytest.fixture
def narrowed(monkeypatch):
    """Count the narrow views a copy reads batches through."""
    seen = {"views": 0}

    class Counted(package_spool._View):
        __slots__ = ()

        def __init__(self, layout, indexes=None):
            super().__init__(layout, indexes)
            seen["views"] += indexes is not None

    monkeypatch.setattr(package_spool, "_View", Counted)
    return seen


class TestSerialCopy:
    @pytest.mark.parametrize("batch", [2000, 16, 3])
    @pytest.mark.parametrize("seed", range(30))
    def test_matches_the_row_by_row_copy(self, spool, monkeypatch, narrowed, seed, batch):
        monkeypatch.setattr(package_spool, "FETCH_ROWS", batch)
        rng = seeded(seed)
        connection = random_table(rng, rng.randint(0, 400), fulltext=seed % 5 == 0)

        writer = export(spool, connection, part=seed)

        assert_same_as_reference(writer.record, connection, part=seed)
        assert not range_files(writer.record)
        if batch == 2000:
            assert narrowed["views"] == 0

    def test_batches_read_only_the_columns_rows_fill(self, spool, monkeypatch, narrowed):
        monkeypatch.setattr(package_spool, "FETCH_ROWS", 4)
        # Two families in runs, as files fill a unified database, and a stray
        # value in a column the batch before left empty.
        rows = [{"Channel": "a", "A": str(n)} for n in range(10)] + [
            {"Channel": "b", "B": str(n), "C": n} for n in range(10)]
        rows[6]["Z"] = b"\x00\xff"
        connection = make_logs(rows, types={"C": "", "Z": ""}, columns=["Channel", "A", "B", "C", "Z", "Empty"])
        statements: list[str] = []
        connection.set_trace_callback(statements.append)

        writer = export(spool, connection)

        connection.set_trace_callback(None)
        assert_same_as_reference(writer.record, connection)
        assert {column["key"]: column["mask"] for column in writer.record.columns}["z"] == 8
        # Rows 1-4 read every column, 5-8 Channel and A; row 7 holds Z as well.
        # Rows 9-12 add Z, and rows 11 and 12 start a family with B and C:
        # half that batch read twice, so rows 13-16 read every column again.
        assert narrowed["views"] == 3
        reread = [int(sql.rsplit("= ", 1)[1]) for sql in statements if "WHERE row_id = " in sql]
        assert reread == [7, 11, 12]

    def test_columns_left_out_are_checked_in_groups_sqlite_accepts(self, spool, monkeypatch):
        monkeypatch.setattr(package_spool, "FETCH_ROWS", 2)
        names = [f"C{n}" for n in range(250)]
        rows = [{"C0": "a"}, {"C0": "b"}, {"C0": "c"}, {"C249": "d"}]
        connection = make_logs(rows, columns=names)
        # As old SQLite builds allow: 127 arguments by default, 100 here.
        connection.setlimit(sqlite3.SQLITE_LIMIT_FUNCTION_ARG, 100)

        assert_same_as_reference(export(spool, connection).record, connection)

    def test_a_batch_mostly_read_again_reads_every_column_next(self, spool, monkeypatch, narrowed):
        monkeypatch.setattr(package_spool, "FETCH_ROWS", 4)
        # Each batch fills columns the one before did not.
        names = [f"F{n}" for n in range(12)]
        rows = [{"Channel": "c", names[n // 4 % 12]: str(n)} for n in range(48)]
        connection = make_logs(rows, columns=["Channel", *names])

        assert_same_as_reference(export(spool, connection).record, connection)
        # Every other batch: the one after a batch read twice reads every column.
        assert narrowed["views"] == 6

    def test_an_unreadable_value_outside_the_batch_columns_names_its_row(self, spool, monkeypatch, tmp_path):
        rows = [{"A": str(n)} for n in range(9)] + [{"A": "9", "B": "x"}, {"A": "10"}]
        connection = make_logs(rows, columns=["A", "B"])
        connection.execute("UPDATE logs SET B = CAST(X'80' AS TEXT) WHERE row_id = 10")
        whole = PackageSpool(directory=str(tmp_path), time_field="SystemTime")
        with pytest.raises(PackageError) as one_batch:
            export(whole, connection)
        monkeypatch.setattr(package_spool, "FETCH_ROWS", 3)

        with pytest.raises(PackageError) as batches:
            export(spool, connection)

        assert "event row 10 cannot be read" in str(one_batch.value)
        assert str(batches.value) == str(one_batch.value)

    @pytest.mark.parametrize("fmt", ["unix", "unix_ms", "unix_us"])
    def test_matches_with_every_timestamp_format(self, tmp_path, fmt):
        connection = random_table(seeded(fmt), 200)
        spool = PackageSpool(directory=str(tmp_path), time_field="SystemTime", timestamp_format=fmt)

        writer = export(spool, connection)

        assert_same_as_reference(writer.record, connection, timestamp_format=fmt)

    def test_matches_when_the_guesses_are_forgotten_all_the_time(self, spool, monkeypatch):
        monkeypatch.setattr(package_spool, "GUESS_LIMIT", 1)
        monkeypatch.setattr(package_spool, "KINDS_LIMIT", 1)
        connection = random_table(seeded(7), 400)

        assert_same_as_reference(export(spool, connection).record, connection)

    def test_rows_of_one_family_filling_different_columns(self, spool):
        # Same family and as many NULLs each time, so every guess is wrong once.
        rows = [{"Channel": "c", "A": "a" if n % 2 else None, "B": None if n % 2 else "b", "C": n % 3 or None}
                for n in range(40)]
        connection = make_logs(rows, types={"C": ""})

        writer = export(spool, connection)

        assert_same_as_reference(writer.record, connection)
        assert writer.record.families == [{"channel": "c", "eventid": None, "keys": ["a", "b", "c", "channel"]}]

    def test_values_that_compare_equal_are_still_separate_families(self, spool):
        connection = make_logs([{"Channel": 1, "A": "x"}, {"Channel": 1.0, "B": "y"}, {"Channel": "1", "C": "z"}],
                               types={"Channel": ""})

        writer = export(spool, connection)

        assert_same_as_reference(writer.record, connection)
        assert [(f["channel"], f["keys"]) for f in writer.record.families] == [
            ("1", ["a", "c", "channel"]), ("1.0", ["b", "channel"])]

    def test_a_row_with_no_values_and_a_table_with_no_columns(self, spool, tmp_path):
        connection = make_logs([{"A": None}, {"A": "x"}, {"A": None}])
        assert_same_as_reference(export(spool, connection).record, connection)

        bare = sqlite3.connect(":memory:")
        bare.execute("CREATE TABLE logs (row_id INTEGER PRIMARY KEY AUTOINCREMENT)")
        bare.executemany("INSERT INTO logs DEFAULT VALUES", [()] * 3)
        other = PackageSpool(directory=str(tmp_path), time_field="SystemTime")
        assert_same_as_reference(export(other, bare, part=1).record, bare, part=1)


class TestRanges:
    @pytest.mark.parametrize(("first", "last", "count"), [(1, 10, 3), (1, 1, 4), (0, 2_055_325, 32), (7, 8, 5)])
    def test_ranges_cover_every_row_id_once(self, first, last, count):
        ranges = _ranges(first, last, count)

        assert ranges[0][0] == first and ranges[-1][1] == last + 1
        assert all(low < high for low, high in ranges)
        assert all(a[1] == b[0] for a, b in pairwise(ranges))
        assert len(ranges) == min(count, last - first + 1)
        widths = [high - low for low, high in ranges]
        assert max(widths) - min(widths) <= 1


class TestUsableCpus:
    @pytest.mark.parametrize(("quota", "cpus"), [
        ("max 100000\n", None),
        ("200000 100000\n", 2),
        ("150000 100000\n", 2),
        ("50000 100000\n", 1),
        ("100000 0\n", None),
        ("unexpected\n", None),
    ])
    def test_a_cgroup_quota_counts_whole_cpus(self, tmp_path, monkeypatch, quota, cpus):
        path = tmp_path / "cpu.max"
        path.write_text(quota)
        monkeypatch.setattr(package_spool, "CGROUP_CPU_MAX", path)

        assert package_spool._cgroup_cpus() == cpus

    def test_no_cgroup_file_means_no_quota(self, tmp_path, monkeypatch):
        monkeypatch.setattr(package_spool, "CGROUP_CPU_MAX", tmp_path / "missing")

        assert package_spool._cgroup_cpus() is None

    def test_a_quota_caps_the_cpu_count(self, tmp_path, monkeypatch):
        path = tmp_path / "cpu.max"
        path.write_text("100000 100000\n")
        monkeypatch.setattr(package_spool, "CGROUP_CPU_MAX", path)

        assert package_spool._usable_cpus() == 1


class TestPlan:
    def plan(self, spool, connection):
        return spool.open_part(0, ["x"])._parallel_plan(connection)

    def test_a_committed_file_is_split(self, spool, parallel, tmp_path):
        connection = make_logs([{"A": str(n)} for n in range(10)], path=tmp_path / "w.db")

        plan = self.plan(spool, connection)

        assert plan is not None and plan.workers == 3 and plan.rows == 10
        assert plan.ranges == _ranges(1, 10, 12)
        assert plan.uri.startswith("file:") and plan.uri.endswith("?mode=ro")

    def test_memory_databases_stay_serial(self, spool, parallel):
        assert self.plan(spool, make_logs([{"A": "1"}, {"A": "2"}])) is None

    def test_small_parts_stay_serial(self, spool, parallel, tmp_path, monkeypatch):
        monkeypatch.setattr(package_spool, "PARALLEL_MIN_ROWS", 11)

        assert self.plan(spool, make_logs([{"A": str(n)} for n in range(10)], path=tmp_path / "w.db")) is None

    def test_parts_written_beside_other_writers_stay_serial(self, spool, parallel, tmp_path):
        spool.concurrent_writers = 2

        assert self.plan(spool, make_logs([{"A": "1"}], path=tmp_path / "w.db")) is None

    def test_one_cpu_stays_serial(self, spool, parallel, tmp_path, monkeypatch):
        monkeypatch.setattr(package_spool, "_usable_cpus", lambda: 1)

        assert self.plan(spool, make_logs([{"A": "1"}], path=tmp_path / "w.db")) is None

    def test_no_parallel_stays_serial(self, spool, parallel, tmp_path):
        spool.max_processes = 1

        assert self.plan(spool, make_logs([{"A": str(n)} for n in range(10)], path=tmp_path / "w.db")) is None

    def test_parallel_workers_caps_the_processes(self, spool, parallel, tmp_path):
        spool.max_processes = 2

        plan = self.plan(spool, make_logs([{"A": str(n)} for n in range(10)], path=tmp_path / "w.db"))

        assert plan is not None and plan.workers == 2 and plan.ranges == _ranges(1, 10, 8)

    def test_uncommitted_rows_stay_serial(self, spool, parallel, tmp_path):
        connection = make_logs([{"A": "1"}], path=tmp_path / "w.db")
        connection.execute("INSERT INTO logs (A) VALUES ('2')")

        assert connection.in_transaction
        assert self.plan(spool, connection) is None

    @pytest.mark.parametrize("ddl", [
        "CREATE TABLE logs (row_id TEXT, A TEXT)",
        "CREATE TABLE logs (row_id INTEGER PRIMARY KEY DESC, A TEXT)",
        "CREATE TABLE logs (row_id INTEGER PRIMARY KEY, A TEXT) WITHOUT ROWID",
        "CREATE TABLE logs (row_id INT PRIMARY KEY, A TEXT)",
    ])
    def test_a_row_id_that_is_not_the_rowid_stays_serial(self, spool, parallel, tmp_path, ddl):
        connection = sqlite3.connect(tmp_path / "w.db")
        connection.execute(ddl)
        connection.executemany("INSERT INTO logs VALUES (?, 'x')", [(n,) for n in range(1, 6)])
        connection.commit()

        assert self.plan(spool, connection) is None

    def test_a_temporary_logs_table_stays_serial(self, spool, parallel, tmp_path):
        connection = make_logs([{"A": "1"}], path=tmp_path / "w.db")
        connection.execute("CREATE TEMP TABLE logs (row_id INTEGER PRIMARY KEY, A TEXT)")

        assert self.plan(spool, connection) is None

    def test_row_ids_the_viewer_cannot_address_stay_serial_and_are_refused(self, spool, parallel, tmp_path):
        connection = make_logs([{"A": "1"}], path=tmp_path / "w.db")
        connection.execute("INSERT INTO logs (row_id, A) VALUES (?, 'y')", (1 << 32,))
        connection.commit()

        assert self.plan(spool, connection) is None
        with pytest.raises(PackageError, match="row_id 4294967296 is outside"):
            export(spool, connection)

    def test_a_database_another_connection_cannot_read_stays_serial(self, spool, parallel, tmp_path):
        connection = make_logs([{"A": "1"}], path=tmp_path / "w.db")
        connection.execute("PRAGMA locking_mode = EXCLUSIVE")
        connection.execute("BEGIN EXCLUSIVE")
        connection.execute("COMMIT")

        assert self.plan(spool, connection) is None


class TestParallelCopy:
    @pytest.mark.parametrize("seed", range(3))
    def test_matches_the_row_by_row_copy(self, spool, parallel, tmp_path, seed):
        rng = seeded(100 + seed)
        connection = random_table(rng, 300, path=tmp_path / "w.db", fulltext=seed == 1)

        writer = export(spool, connection, part=seed)

        assert range_files(writer.record)
        # Cut every 7 rows within each range: more files than ranges.
        assert len(writer.record.event_files) > 12
        assert_same_as_reference(writer.record, connection, part=seed)

    def test_progress_follows_the_ranges_to_the_last_row(self, spool, parallel, tmp_path):
        connection = make_logs([{"A": str(n)} for n in range(50)], path=tmp_path / "w.db")
        seen: list[tuple[int, int]] = []

        export(spool, connection, progress=lambda done, total: seen.append((done, total)))

        assert len(seen) == 12 and seen[-1] == (50, 50)
        assert [done for done, _ in seen] == sorted(done for done, _ in seen)

    def test_the_first_unreadable_row_is_reported_as_a_serial_copy_reports_it(self, spool, parallel, tmp_path):
        connection = make_logs([{"A": str(n)} for n in range(60)], path=tmp_path / "w.db")
        for row_id in (55, 30):
            connection.execute("UPDATE logs SET A = CAST(X'80' AS TEXT) WHERE row_id = ?", (row_id,))
        connection.commit()
        memory = sqlite3.connect(":memory:")
        connection.backup(memory)
        with pytest.raises(PackageError) as serial:
            export(PackageSpool(directory=str(tmp_path), time_field="SystemTime"), memory)
        writer = spool.open_part(0, ["x"])

        with pytest.raises(PackageError) as parallel_error:
            writer.export_events(connection)

        assert str(parallel_error.value) == str(serial.value)
        assert "event row 30 cannot be read" in str(serial.value)
        written = {str(path) for path in Path(spool.directory).iterdir()}
        assert written and set(writer.record.event_files) == written
        writer.discard()
        assert list(Path(spool.directory).iterdir()) == []

    def test_a_broken_spelling_table_fails_as_it_does_serially(self, spool, parallel, tmp_path):
        connection = make_logs([{"A": str(n)} for n in range(20)], path=tmp_path / "w.db")
        connection.execute("CREATE TABLE logs_spelling (row_id INTEGER, spelling INTEGER)")
        connection.execute("CREATE TABLE field_spellings (wrong TEXT)")
        connection.commit()
        writer = spool.open_part(4, ["x"])

        with pytest.raises(PackageError, match=r"^cannot spool the events of part 4: no such column: f\.names$"):
            writer.export_events(connection)

        writer.discard()
        assert list(Path(spool.directory).iterdir()) == []

    def test_an_unreadable_spelling_record_names_its_row(self, spool, parallel, tmp_path):
        connection = make_logs([{"A": str(n)} for n in range(40)], path=tmp_path / "w.db")
        connection.execute("CREATE TABLE field_spellings (id INTEGER PRIMARY KEY, names TEXT NOT NULL UNIQUE)")
        connection.execute("CREATE TABLE logs_spelling (row_id INTEGER PRIMARY KEY, spelling INTEGER NOT NULL)")
        connection.execute("INSERT INTO field_spellings VALUES (1, 'not json')")
        connection.executemany("INSERT INTO logs_spelling VALUES (?, 1)", [(33,), (38,)])
        connection.commit()

        with pytest.raises(PackageError, match="event row 33 has an unreadable spelling record"):
            export(spool, connection)

    def test_reserved_names_are_refused_before_any_process_starts(self, spool, parallel, tmp_path, monkeypatch):
        def no_pool(*args, **kwargs):
            raise AssertionError("no process may start")

        monkeypatch.setattr(package_spool, "ProcessPoolExecutor", no_pool)
        connection = make_logs([{"_ZL_x": "1"}], path=tmp_path / "w.db")

        with pytest.raises(PackageError, match="_ZL_x"):
            export(spool, connection)

    @pytest.mark.parametrize("working", [0, 1])
    def test_a_pool_that_breaks_falls_back_to_a_serial_copy(self, spool, parallel, tmp_path, monkeypatch, working):
        class Breaking:
            """Runs the first ``working`` ranges here, then breaks as a pool whose process died."""

            def __init__(self, *args, **kwargs):
                self.started = 0

            def submit(self, function, task):
                future: Future = Future()
                if self.started < working:
                    future.set_result(function(task))
                else:
                    future.set_exception(BrokenProcessPool("a process died"))
                self.started += 1
                return future

            def shutdown(self, wait=True, cancel_futures=False):
                pass

        monkeypatch.setattr(package_spool, "ProcessPoolExecutor", Breaking)
        connection = random_table(seeded(5), 100, path=tmp_path / "w.db")

        writer = export(spool, connection)

        assert not range_files(writer.record)
        assert {str(path) for path in Path(spool.directory).iterdir()} == set(writer.record.event_files)
        assert_same_as_reference(writer.record, connection)

    @pytest.mark.parametrize("error", [OSError(errno.ENOSYS, "Function not implemented"),
                                       NotImplementedError("no multiprocessing.synchronize")])
    def test_a_pool_that_cannot_be_created_falls_back_to_a_serial_copy(self, spool, parallel, tmp_path,
                                                                        monkeypatch, error):
        def no_semaphores(*args, **kwargs):
            raise error

        monkeypatch.setattr(package_spool, "ProcessPoolExecutor", no_semaphores)
        connection = random_table(seeded(6), 100, path=tmp_path / "w.db")

        writer = export(spool, connection)

        assert not range_files(writer.record)
        assert_same_as_reference(writer.record, connection)

    def test_an_interrupted_copy_lists_every_file_it_wrote(self, spool, parallel, tmp_path, monkeypatch):
        real = package_spool.as_completed

        def interrupted(futures):
            for future in real(futures):
                yield future
                raise KeyboardInterrupt

        monkeypatch.setattr(package_spool, "as_completed", interrupted)
        connection = make_logs([{"A": str(n)} for n in range(200)], path=tmp_path / "w.db")
        writer = spool.open_part(0, ["x"])

        with pytest.raises(KeyboardInterrupt):
            writer.export_events(connection)

        written = {str(path) for path in Path(spool.directory).iterdir()}
        assert written and set(writer.record.event_files) == written
        writer.discard()
        assert list(Path(spool.directory).iterdir()) == []
