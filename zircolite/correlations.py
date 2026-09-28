"""Sigma correlation plans: what can run here, and how their alerts are reported.

A correlation rule converted by pySigma's SQLite backend (schema version 2)
carries a ``correlation_plan``: ordered SELECT stages that the backend's
runtime materialises as indexed TEMP tables, a result query, and diagnostic
queries. Each result row is an alert summary -- a group, a window, a metric
and the events behind it -- not an event from ``logs``.
"""

import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

PLAN_VERSION = 2

# How a time field can be written, as the backend's timestamp_format names it:
# ISO 8601 text, or Unix seconds, milliseconds or microseconds.
TIMESTAMP_FORMATS = ("iso", "unix", "unix_ms", "unix_us")

# Alert summary columns, in the order the backend reports them, then the
# fields Zircolite adds.
CORRELATION_COLUMNS = [
    "result_type",
    "alert_id",
    "group_keys",
    "occurrence_time",
    "window_start",
    "window_end",
    "metric_name",
    "metric_value",
    "event_count",
    "event_ids",
    "child_alert_ids",
    "evidence",
]

_PLAN_KEYS = ("prepare", "query", "diagnostics", "required_fields", "source_tables", "event_id_field")

DIAGNOSTIC_LABELS = {
    "invalid_timestamp": "event(s) without a valid timestamp",
    "missing_group_key": "event(s) missing a group-by field",
    "incomplete_window": "absence window(s) still open at the end of the input",
}


def is_correlation_plan_rule(rule: dict[str, Any]) -> bool:
    """True for a rule that runs through its plan rather than its SQL."""
    return rule.get("correlation_plan") is not None


def _version_tuple(text: str) -> tuple[int, ...] | None:
    if not isinstance(text, str) or not re.fullmatch(r"\d+(\.\d+)*", text):
        return None
    return tuple(int(part) for part in text.split("."))


def required_sqlite(plan: dict[str, Any]) -> tuple[int, ...]:
    """The SQLite version a plan declares it needs; 3.38.0 when it names none."""
    return _version_tuple(plan.get("sqlite_min_version", "")) or (3, 38, 0)


def plan_problem(plan: Any) -> str | None:
    """Why this plan cannot run here, or None if it can."""
    if not isinstance(plan, dict):
        return "correlation_plan is not an object"
    if plan.get("version") != PLAN_VERSION:
        return (
            f"correlation plan version {plan.get('version')!r} is not supported "
            f"(this Zircolite runs version {PLAN_VERSION})"
        )
    missing = [key for key in _PLAN_KEYS if key not in plan]
    if missing:
        return f"correlation plan lacks {', '.join(missing)}"
    if "sqlite_min_version" in plan and _version_tuple(plan["sqlite_min_version"]) is None:
        return f"correlation plan names an unreadable SQLite version {plan['sqlite_min_version']!r}"
    needed = required_sqlite(plan)
    if sqlite3.sqlite_version_info < needed:
        return (
            f"correlation plans need SQLite >= {'.'.join(map(str, needed))} with JSON "
            f"functions; this Python links SQLite {sqlite3.sqlite_version}"
        )
    return None


def occurrence_iso(seconds: float) -> str | None:
    """Unix seconds as ISO 8601 UTC with milliseconds, or None past datetime's range."""
    try:
        moment = datetime.fromtimestamp(seconds, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def alert_rows(rows: list[dict[str, Any]], time_field: str) -> list[dict[str, Any]]:
    """Alert summaries as Zircolite match rows.

    Each row gains ``result_type`` and the run's time field, set to when the
    alert occurred, so timelines, Timesketch and sorting place it like an
    event. A row that already carries that name keeps it: the name is a group
    key there, not a time.
    """
    reported = []
    for row in rows:
        alert = {"result_type": "correlation", **row}
        occurrence = row.get("occurrence_time")
        if time_field not in alert and isinstance(occurrence, (int, float)):
            iso = occurrence_iso(occurrence)
            if iso is not None:
                alert[time_field] = iso
        reported.append(alert)
    return reported


def distinct_events(rows: list[dict[str, Any]]) -> int:
    """Physical events behind a rule's alerts, each counted once."""
    return len({event_id for row in rows for event_id in row.get("event_ids") or ()})


def describe_diagnostics(diagnostics: dict[str, int]) -> str:
    """``{'invalid_timestamp': 3}`` as '3 event(s) without a valid timestamp'."""
    return ", ".join(
        f"{count:,} {DIAGNOSTIC_LABELS.get(reason, reason.replace('_', ' '))}"
        for reason, count in sorted(diagnostics.items())
        if count
    )
