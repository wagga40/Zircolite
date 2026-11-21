"""What Zircolite reads out of rule SQL, kept on disk between runs.

Normalising, planning and scanning thousands of rules costs seconds,
which every process worker would pay again. All three are pure
functions of the statement text and of this package's own analysis code, so a
run reloads them from the user's cache directory instead. The file is JSON and
is validated field by field: a damaged or foreign file is ignored and the
analysis recomputed, never trusted in part.

Only the command line enables the cache; a library caller computes everything
in memory. Process workers inherit the directory through
``ZIRCOLITE_ANALYSIS_CACHE``.
"""

import hashlib
import logging
import os
import sys
import tempfile
from collections.abc import Iterable, Iterator
from functools import cache
from pathlib import Path
from typing import Any

import orjson

from . import prefilter, sqlscan
from .prefilter import rule_queries
from .sqlscan import QueryScan

FORMAT = 5
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


def _query_index(queries: tuple[str, ...]) -> dict[str, str]:
    return {hashlib.sha256(query.encode("utf-8", "surrogatepass")).hexdigest(): query
            for query in dict.fromkeys(queries)}


def _selection_key(fingerprint: bytes, query_ids: Iterable[str]) -> str:
    digest = hashlib.sha256(f"zircolite-analysis-{FORMAT}".encode())
    digest.update(fingerprint)
    digest.update("".join(query_ids).encode("ascii"))
    return digest.hexdigest()


def cache_key(queries: tuple[str, ...]) -> str:
    return _selection_key(_code_fingerprint(), _query_index(queries))


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
    wanted = _query_index(queries)
    fingerprint = _code_fingerprint()
    path = Path(directory) / f"analysis-{_selection_key(fingerprint, wanted)[:40]}.json"
    if _load(path, wanted, fingerprint, exact=True):
        return True

    missing = wanted.copy()
    recovered: dict[str, tuple[bytes, bytes]] = {}
    for other in _recent_files(path.parent)[:KEEP]:
        if other == path:
            continue
        entries = _load(other, missing, fingerprint)
        recovered.update(entries)
        for query_id in entries:
            del missing[query_id]
        if not missing:
            break
    if missing:
        _analyse(tuple(missing.values()))
    _save(path, wanted, recovered)
    return not missing


def _load(
    path: Path, wanted: dict[str, str], fingerprint: bytes, *, exact: bool = False,
) -> dict[str, tuple[bytes, bytes]]:
    """Read only a compatible selection. No in-memory state changes until its entries decode."""
    try:
        with path.open("rb") as handle:
            header = orjson.loads(handle.readline())
            if not isinstance(header, dict) or header.get("format") != FORMAT:
                return {}
            ids = header["queries"]
            if exact:
                if ids != list(wanted):
                    raise ValueError("index does not match the ruleset")
            else:
                if not isinstance(ids, list) or not all(isinstance(i, str) and len(i) == 64 for i in ids):
                    raise ValueError("bad query index")
                if wanted.keys().isdisjoint(ids):
                    return {}
                # Check the analyzer version and the integrity of the positional index.
                if path.name != f"analysis-{_selection_key(fingerprint, ids)[:40]}.json":
                    return {}
            payload = handle.read()
        if hashlib.sha256(payload).hexdigest() != header.get("sha256"):
            raise ValueError("damaged analysis payload")
        lines = payload.split(b"\n")
        del payload
        if len(lines) != 2 * len(ids):
            raise ValueError("entries do not match the index")
        entries = {key: (lines[2 * i], lines[2 * i + 1]) for i, key in enumerate(ids) if key in wanted}
        _restore(entries, wanted)
        return entries
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError) as exc:
        logger.debug(f"Rule analysis cache ignored ({path.name}): {exc}")
        return {}


def _analyse(queries: tuple[str, ...]) -> None:
    """Everything a run asks of these statements, computed once, eagerly."""
    @cache
    def spans(sql: str) -> list[sqlscan.TokenSpan]:
        try:
            return list(sqlscan.iter_tokens(sql))
        except sqlscan._Unsupported:
            # No complete token stream: none of the readers can derive facts.
            return []

    for query in dict.fromkeys(queries):
        text = sqlscan.normalize_rule_sql(query, tokenize=spans)
        sqlscan.scan_query(query, tokenize=spans)
        if text != query:
            sqlscan.scan_query(text, tokenize=spans)
        plan = prefilter._plan_for(text, tokenize=spans)
        if plan is not None and plan.sql != text:
            sqlscan.scan_query(plan.sql, tokenize=spans)
        spans.cache_clear()


def _scan_entry(scan: QueryScan) -> list[Any]:
    return [None if scan.channels is None else sorted(scan.channels),
            None if scan.eventids is None else sorted(scan.eventids),
            sorted(scan.columns), list(scan.regex_patterns), scan.row_preserving]


def _lines(index: dict[str, str], recovered: dict[str, tuple[bytes, bytes]]) -> Iterator[bytes]:
    """Two lines per statement, by position, so the file never repeats the SQL.

    The first holds what every run reads; the second, the plan, stays bytes
    until the filter asks for it.
    """
    for query_id, query in index.items():
        if query_id in recovered:
            # Copy the original pair so a reused prefilter plan can stay lazy.
            yield from recovered[query_id]
            continue
        text = sqlscan._NORMALIZED[query]
        plan = prefilter._PLANS[text]
        plan_scan = None if plan is None or plan.sql in (query, text) else _scan_entry(sqlscan._SCANS[plan.sql])
        yield orjson.dumps([
            None if text == query else text, _scan_entry(sqlscan._SCANS[query]),
            None if text == query else _scan_entry(sqlscan._SCANS[text]), plan_scan,
        ])
        yield orjson.dumps(None if plan is None else prefilter.plan_to_json(plan, text))


def _save(path: Path, index: dict[str, str], recovered: dict[str, tuple[bytes, bytes]]) -> None:
    try:
        # Line by line: decoding them one at a time never holds the whole
        # file as Python objects.
        payload = b"\n".join(_lines(index, recovered))
        header = orjson.dumps({"format": FORMAT, "queries": list(index),
                               "sha256": hashlib.sha256(payload).hexdigest()})
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".analysis-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(header + b"\n")
                handle.write(payload)
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        for stale in _recent_files(path.parent)[KEEP:]:
            stale.unlink(missing_ok=True)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        logger.debug(f"Rule analysis cache not written: {exc}")


def _recent_files(directory: Path) -> list[Path]:
    try:
        return sorted(directory.glob("analysis-*.json"), key=lambda entry: entry.stat().st_mtime_ns, reverse=True)
    except OSError:
        # Another process may prune a file between the listing and stat.
        return []


def _strings(values: Any) -> frozenset[str]:
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("bad strings")
    # Column and channel names repeat across thousands of statements.
    return frozenset(map(sys.intern, values))


def _decode_scan(entry: Any) -> QueryScan:
    channels, eventids, columns, patterns, row_preserving = entry
    if eventids is not None and (not isinstance(eventids, list) or not all(type(value) is int for value in eventids)):
        raise ValueError("bad eventids")
    if not isinstance(patterns, list) or not all(isinstance(value, str) for value in patterns):
        raise ValueError("bad patterns")
    if not isinstance(row_preserving, bool):
        raise ValueError("bad row_preserving")
    return QueryScan(None if channels is None else _strings(channels),
                     None if eventids is None else frozenset(eventids),
                     _strings(columns), tuple(patterns), row_preserving)


def _decode_metadata(meta: bytes) -> tuple[str | None, QueryScan, QueryScan, QueryScan | None]:
    text, query_scan, text_scan, plan_scan = orjson.loads(meta)
    if text is not None and not isinstance(text, str):
        raise ValueError("bad normalized text")
    if (text is None) != (text_scan is None):
        raise ValueError("normalized SQL and scan must be stored together")
    original = _decode_scan(query_scan)
    return (text, original, original if text_scan is None else _decode_scan(text_scan),
            None if plan_scan is None else _decode_scan(plan_scan))


def _restore(entries: dict[str, tuple[bytes, bytes]], wanted: dict[str, str]) -> None:
    normalized: dict[str, str] = {}
    plans: dict[str, bytes] = {}
    scans: dict[str, QueryScan] = {}
    # Thousands of rules share exactly the same bounds and columns. Decode each
    # distinct metadata line once per file; QueryScan is immutable.
    decode = cache(_decode_metadata)
    for query_id, (meta, raw) in entries.items():
        query = wanted[query_id]
        text, original, normalized_scan, plan_scan = decode(meta)
        if text is None:
            text = query
        normalized[query] = text
        scans[query] = original
        scans[text] = normalized_scan
        plans[text] = raw
        if plan_scan is not None:
            plan = prefilter.plan_from_json(orjson.loads(raw), text)
            scans[plan.sql] = plan_scan
    sqlscan._NORMALIZED.update(normalized)
    sqlscan._SCANS.update(scans)
    for text, raw in plans.items():
        if text in prefilter._PLANS:
            continue
        if raw == b"null":
            prefilter._PLANS[text] = None
        else:
            prefilter._PENDING_PLANS[text] = raw
