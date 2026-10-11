"""What Zircolite reads out of rule SQL, kept on disk between runs.

Normalising, planning and scanning a 4,500-rule ruleset costs about two
seconds, and every process worker used to pay it again. All three are pure
functions of the statement text and of this package's own analysis code, so a
run reloads them from the user's cache directory instead. The file is JSON and
is validated field by field: a damaged or foreign file is ignored and the
analysis recomputed, never trusted in part.

Only the command line enables the cache; a library caller computes everything
in memory as before. Process workers inherit the directory through
``ZIRCOLITE_ANALYSIS_CACHE``.
"""

import hashlib
import logging
import os
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import orjson

from . import prefilter, sqlscan
from .prefilter import rule_queries
from .sqlscan import QueryScan

FORMAT = 4
ENV_DIRECTORY = "ZIRCOLITE_ANALYSIS_CACHE"
# Files kept per directory; each holds one ruleset combination.
KEEP = 8

logger = logging.getLogger(__name__)


def default_directory() -> Path | None:
    """The per-user cache directory, or None when caching is switched off."""
    if os.environ.get("ZIRCOLITE_NO_CACHE"):
        return None
    override = os.environ.get("ZIRCOLITE_CACHE_DIR")
    if override:
        return Path(override)
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Caches" / "Zircolite"
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / "Zircolite" / "Cache" if base else home / "AppData" / "Local" / "Zircolite" / "Cache"
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else home / ".cache") / "zircolite"


def enable(directory: Path | None = None) -> Path | None:
    """Turn the cache on for this process and the workers it spawns."""
    directory = directory or default_directory()
    if directory is None:
        os.environ.pop(ENV_DIRECTORY, None)
        return None
    os.environ[ENV_DIRECTORY] = str(directory)
    return directory


def _code_fingerprint() -> bytes:
    """Changes whenever the code that produced a cached answer may have."""
    digest = hashlib.sha256()
    try:
        for module in (sqlscan, prefilter, sys.modules[__name__]):
            digest.update(Path(module.__file__ or "").read_bytes())
    except OSError:
        # A frozen build ships no sources; its executable stands for them.
        stat = Path(sys.executable).stat()
        digest.update(f"{sys.executable}:{stat.st_size}:{stat.st_mtime_ns}".encode())
    digest.update(f"{sys.version_info[0]}.{sys.version_info[1]}".encode())
    return digest.digest()


def cache_key(queries: tuple[str, ...]) -> str:
    digest = hashlib.sha256(f"zircolite-analysis-{FORMAT}".encode())
    digest.update(_code_fingerprint())
    for query in queries:
        digest.update(query.encode("utf-8", "surrogatepass"))
        digest.update(b"\0")
    return digest.hexdigest()


def warm(rules: list[dict[str, Any]] | None) -> bool:
    """Seed the in-memory analysis of ``rules`` from disk, or compute and save it.

    True when the analysis came from disk. Does nothing unless enabled.
    """
    directory = os.environ.get(ENV_DIRECTORY)
    if not directory or not rules:
        return False
    queries = rule_queries(rules)
    if not queries:
        return False
    path = Path(directory) / f"analysis-{cache_key(queries)[:40]}.json"
    try:
        loaded = _decode(path.read_bytes(), queries)
    except FileNotFoundError:
        loaded = None
    except (OSError, ValueError, TypeError, KeyError, IndexError) as exc:
        logger.debug(f"Rule analysis cache ignored ({path.name}): {exc}")
        loaded = None
    if loaded is not None:
        normalized, plans, scans = loaded
        sqlscan._NORMALIZED.update(normalized)
        sqlscan._SCANS.update(scans)
        for text, raw in plans.items():
            if text in prefilter._PLANS:
                continue
            if raw == b"null":
                prefilter._PLANS[text] = None
            else:
                prefilter._PENDING_PLANS[text] = raw
        return True
    _analyse(queries)
    _save(path, queries)
    return False


def _analyse(queries: tuple[str, ...]) -> None:
    """Everything a run asks of these statements, computed once, eagerly."""
    for query in queries:
        text = sqlscan.normalize_rule_sql(query)
        sqlscan.scan_query(query)
        sqlscan.scan_query(text)
        plan = prefilter._plan_for(text)
        if plan is not None and plan.sql != text:
            sqlscan.scan_query(plan.sql)


def _scan_entry(scan: QueryScan) -> list[Any]:
    return [None if scan.channels is None else sorted(scan.channels),
            None if scan.eventids is None else sorted(scan.eventids),
            sorted(scan.columns), list(scan.regex_patterns), scan.row_preserving]


def _lines(queries: tuple[str, ...]) -> Iterator[bytes]:
    """Two lines per statement, by position, so the file never repeats the SQL.

    The first holds what every run reads; the second, the plan, stays bytes
    until the filter asks for it.
    """
    for query in queries:
        text = sqlscan._NORMALIZED[query]
        plan = prefilter._PLANS[text]
        plan_scan = None if plan is None or plan.sql in (query, text) else _scan_entry(sqlscan._SCANS[plan.sql])
        yield orjson.dumps([
            None if text == query else text, _scan_entry(sqlscan._SCANS[query]),
            None if text == query else _scan_entry(sqlscan._SCANS[text]), plan_scan,
        ])
        yield orjson.dumps(None if plan is None else prefilter.plan_to_json(plan, text))


def _save(path: Path, queries: tuple[str, ...]) -> None:
    try:
        # A line per statement: decoding them one at a time never holds the
        # whole file as Python objects.
        data = b"\n".join([orjson.dumps({"format": FORMAT, "count": len(queries)}), *_lines(queries)])
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".analysis-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        _prune(path.parent)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        logger.debug(f"Rule analysis cache not written: {exc}")


def _prune(directory: Path) -> None:
    files = sorted(directory.glob("analysis-*.json"), key=lambda entry: entry.stat().st_mtime, reverse=True)
    for stale in files[KEEP:]:
        stale.unlink(missing_ok=True)


def _strings(values: Any) -> frozenset[str]:
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("bad strings")
    # Column and channel names repeat across thousands of statements.
    return frozenset(map(sys.intern, values))


def _decode_scan(entry: Any) -> QueryScan:
    channels, eventids, columns, patterns, row_preserving = entry
    if eventids is not None and not all(type(value) is int for value in eventids):
        raise ValueError("bad eventids")
    if not isinstance(patterns, list) or not all(isinstance(value, str) for value in patterns):
        raise ValueError("bad patterns")
    if not isinstance(row_preserving, bool):
        raise ValueError("bad row_preserving")
    return QueryScan(None if channels is None else _strings(channels),
                     None if eventids is None else frozenset(eventids),
                     _strings(columns), tuple(patterns), row_preserving)


def _decode(data: bytes, queries: tuple[str, ...]) -> tuple[
        dict[str, str], dict[str, bytes], dict[str, QueryScan]]:
    lines = data.split(b"\n")
    header = orjson.loads(lines[0])
    if not isinstance(header, dict) or header.get("format") != FORMAT:
        raise ValueError("unknown format")
    if header.get("count") != len(queries) or len(lines) != 2 * len(queries) + 1:
        raise ValueError("entries do not match the ruleset")
    normalized: dict[str, str] = {}
    plans: dict[str, bytes] = {}
    scans: dict[str, QueryScan] = {}
    for index, query in enumerate(queries):
        text, query_scan, text_scan, plan_scan = orjson.loads(lines[2 * index + 1])
        if text is None:
            text = query
        elif not isinstance(text, str):
            raise ValueError("bad normalized text")
        normalized[query] = text
        scans[query] = _decode_scan(query_scan)
        scans[text] = scans[query] if text_scan is None else _decode_scan(text_scan)
        raw = lines[2 * index + 2]
        plans[text] = raw
        if plan_scan is not None:
            plan = prefilter.plan_from_json(orjson.loads(raw), text)
            scans[plan.sql] = _decode_scan(plan_scan)
    return normalized, plans, scans
