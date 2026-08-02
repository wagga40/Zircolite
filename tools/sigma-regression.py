#!/usr/bin/env python3
"""
Run Sigma regression_data tests with Zircolite.

Uses the Sigma repository's regression_data (see
https://github.com/SigmaHQ/sigma/tree/master/regression_data): each test case
directory contains an info.yml (rule metadata and test paths), plus EVTX and/or
JSON files. This script runs detection on those files and checks that the
referenced rules fire.

Rules are resolved by Sigma id, falling back to title, and every pipeline
variant an id resolves to is run against a single ingest of the data file. See
`expectation_met` for what counts as a pass -- `match_count` states that the
rule fired, not how many records it fired on.

Requires:
- A regression data directory and a rules path (or Zircolite ruleset file).
- Zircolite and its dependencies (including pySigma and pipelines such as
  pysigma-pipeline-sysmon, pysigma-backend-sqlite).

Example:
  pdm run python tools/sigma-regression.py --regression-data ../sigma/regression_data/rules/windows -r ../sigma/rules/windows
  pdm run python tools/sigma-regression.py --regression-data ../sigma/regression_data/rules/windows -r rules/rules_windows_sysmon.json
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.theme import Theme

# Zircolite package (run from project root or with PYTHONPATH)
try:
    from zircolite.config import ProcessingConfig, RulesetConfig
    from zircolite.console import make_file_link, set_quiet_mode
    from zircolite.core import ZircoliteCore
    from zircolite.rules import RulesetHandler
    from zircolite.sqlscan import column_refs
    from zircolite.utils import init_logger
except ImportError:
    # Allow running from repo root: add parent to path
    _root = Path(__file__).resolve().parent.parent
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))
    from zircolite.config import ProcessingConfig, RulesetConfig
    from zircolite.console import make_file_link, set_quiet_mode
    from zircolite.core import ZircoliteCore
    from zircolite.rules import RulesetHandler
    from zircolite.sqlscan import column_refs
    from zircolite.utils import init_logger

# Rich theme aligned with Zircolite
REGRESSION_THEME = Theme({
    "info": "cyan",
    "success": "bold green",
    "warning": "yellow",
    "error": "bold red",
    "file": "cyan",
    "count": "bold magenta",
    "header": "bold cyan",
})
console = Console(theme=REGRESSION_THEME, highlight=False)

BANNER = """\
[bold white]-= Sigma regression_data tests =-[/]"""

# -----------------------------------------------------------------------------
# Regression data structures (from Sigma info.yml)
# -----------------------------------------------------------------------------

@dataclass
class RuleRef:
    """Reference to a rule from info.yml rule_metadata."""
    id: str
    title: str


@dataclass
class RegressionTestEntry:
    """A single regression test from info.yml regression_tests_info."""
    name: str
    type: str  # 'evtx' or 'json'
    path: str  # relative to sigma repo root
    match_count: int
    provider: str | None = None


@dataclass
class TestCase:
    """One test case directory: info.yml + rule refs + test entries."""
    dir_path: Path
    rule_refs: list[RuleRef]
    tests: list[RegressionTestEntry]


def expectation_met(entry: RegressionTestEntry, count: int) -> bool:
    """Whether *count* matches satisfies *entry*.

    Sigma's ``match_count`` says the rule fired, not how many records it fired
    on: every entry in regression_data is a positive test declaring ``1``, and
    a sample commonly carries several records that all legitimately match --
    the IE Change Domain Zone capture holds three. Zircolite counts matching
    events, so demanding equality fails correct detections. A positive test
    therefore passes on *at least* the declared count; only a negative one
    (``match_count: 0``) demands silence.
    """
    if entry.match_count == 0:
        return count == 0
    return count >= entry.match_count


def expectation_label(entry: RegressionTestEntry) -> str:
    """How the expectation reads in the console and the report."""
    if entry.match_count == 0:
        return "0"
    return f"≥{entry.match_count}"


def load_info_yml(path: Path) -> dict[str, Any] | None:
    """Load and parse an info.yml file."""
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def parse_test_case(dir_path: Path) -> TestCase | None:
    """
    Parse a test case directory: read info.yml and build TestCase.
    Paths in info.yml are relative to the Sigma repo root.
    """
    info_path = dir_path / "info.yml"
    data = load_info_yml(info_path)
    if not data:
        return None

    rule_refs: list[RuleRef] = []
    for item in data.get("rule_metadata") or []:
        if isinstance(item, dict):
            rule_id = item.get("id") or ""
            title = item.get("title") or ""
            if title:
                rule_refs.append(RuleRef(id=rule_id, title=title))

    tests: list[RegressionTestEntry] = []
    for item in data.get("regression_tests_info") or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or "Unnamed"
        typ = (item.get("type") or "evtx").lower()
        path_str = item.get("path") or ""
        if "match_count" in item and item["match_count"] is not None:
            match_count = int(item["match_count"])
        else:
            # Sigma info.yml often omits match_count; the test name carries the
            # intent. An unrecognised name counts as positive: a test that
            # silently expects nothing would pass on a rule that never fires.
            match_count = 0 if "negative" in name.lower() else 1
        provider = item.get("provider")
        if path_str and typ in ("evtx", "json"):
            tests.append(
                RegressionTestEntry(
                    name=name,
                    type=typ,
                    path=path_str,
                    match_count=match_count,
                    provider=provider,
                )
            )

    if not rule_refs or not tests:
        return None
    return TestCase(dir_path=dir_path, rule_refs=rule_refs, tests=tests)


def discover_test_cases(regression_data_root: Path) -> list[TestCase]:
    """
    Discover all test cases under the given path (recursively).
    Each directory that contains an info.yml is a test case.
    """
    if not regression_data_root.is_dir():
        return []

    cases: list[TestCase] = []
    for info_file in regression_data_root.rglob("info.yml"):
        dir_path = info_file.parent
        case = parse_test_case(dir_path)
        if case:
            cases.append(case)
    return cases


def resolve_data_file(
    regression_data_root: Path, test_entry: RegressionTestEntry, case_dir: Path
) -> Path | None:
    """
    Resolve the data file (EVTX or JSON) for a test entry.
    Tries: path relative to regression_data, then relative to case dir, then filename in case dir.
    """
    path_str = test_entry.path.replace("\\", "/")
    base = Path(path_str).name

    candidate = (regression_data_root / path_str).resolve()
    if candidate.exists():
        return candidate
    candidate = (case_dir / path_str).resolve()
    if candidate.exists():
        return candidate
    local = case_dir / base
    if local.exists():
        return local
    return None


class RulesIndex:
    """Ruleset lookup by Sigma rule id, falling back to title.

    A merged Zircolite ruleset carries one rule per pipeline variant, all
    sharing the Sigma id but suffixing the title -- "… - Generic" and
    "… - Sysmon". Keying on the title alone therefore misses most of a merged
    ruleset: against rules_windows_merged.json, 112 of 136 regression cases
    resolve by id and by id only. Titles still matter because a converted
    ruleset need not carry ids.
    """

    def __init__(self, ruleset: list[dict[str, Any]]):
        self.by_id: dict[str, list[dict[str, Any]]] = {}
        self.by_title: dict[str, list[dict[str, Any]]] = {}
        for rule in ruleset:
            rule_id = rule.get("id")
            if isinstance(rule_id, str) and rule_id:
                self.by_id.setdefault(rule_id, []).append(rule)
            title = rule.get("title")
            if isinstance(title, str) and title:
                self.by_title.setdefault(title, []).append(rule)

    def find(self, refs: list[RuleRef]) -> list[dict[str, Any]]:
        """Every rule the refs resolve to, in ruleset order, without duplicates."""
        matched: list[dict[str, Any]] = []
        seen: set[int] = set()
        for ref in refs:
            for rule in self.by_id.get(ref.id) or self.by_title.get(ref.title, []):
                if id(rule) in seen:
                    continue
                seen.add(id(rule))
                matched.append(rule)
        return matched


# Column where case name starts on line 1: prefix "    " + "[!] " = 8. Continuation lines use same indent.
_FAILED_RULE_ALIGN = 8


def _columns_used_in_sql(sql_list: list[str]) -> set[str]:
    """Column names the rule SQL compares against."""
    columns: set[str] = set()
    for sql in sql_list or []:
        if sql and sql.strip():
            columns |= column_refs(sql)
    return columns


def _filter_events_to_rule_fields(
    events: list[dict[str, Any]],
    rule_sql: list[str],
) -> list[dict[str, Any]]:
    """Return events with only keys that appear in the rule SQL."""
    used = _columns_used_in_sql(rule_sql or [])
    if not used:
        return events
    # Case-insensitive match: event keys may differ in casing from SQL/Sigma
    used_lower = {u.lower(): u for u in used}
    filtered = []
    for evt in events:
        kept = {k: v for k, v in evt.items() if k and k.lower() in used_lower}
        filtered.append(kept)
    # If filtering removed everything, return original events so report is never empty
    if events and all(not f for f in filtered):
        return events
    return filtered


def _beautify_sql(sql: str) -> str:
    """Break rule SQL over several lines so the report stays readable."""
    if not sql or not sql.strip():
        return sql
    s = sql.strip()
    s = re.sub(r"\s+FROM\s+", "\nFROM ", s, flags=re.IGNORECASE)
    s = re.sub(r"\s+WHERE\s+", "\nWHERE ", s, flags=re.IGNORECASE)
    s = re.sub(r"\s+AND\s+", "\n  AND ", s, flags=re.IGNORECASE)
    s = re.sub(r"\s+OR\s+", "\n  OR ", s, flags=re.IGNORECASE)
    return s


def format_failed_rule_lines(
    case_dir_path: Path,
    data_file_path: Path,
    rule_title: str,
    rule_id: str,
    detail: str,
    prefix: str = "    ",
    icon: str = "!",
    style: str = "yellow",
) -> list[str]:
    """Format a failed-rule message as multiple lines; rule title and detail align with case name."""
    continuation = " " * _FAILED_RULE_ALIGN
    icon_markup = f"[{style}]\\[{icon}][/]"
    case_link = make_file_link(str(case_dir_path), case_dir_path.name)
    file_link = make_file_link(str(data_file_path), data_file_path.name)
    return [
        f"{prefix}{icon_markup} {case_link} ({file_link})",
        f"{continuation}[dim]{rule_title}[/] [dim](id: {rule_id})[/]",
        f"{continuation}[{style}]{detail}[/]",
    ]


def build_sigma_yaml_index(sigma_rules_dir: Path | None) -> dict[str, str]:
    """Build a map of Sigma rule title -> YAML content."""
    index: dict[str, str] = {}
    if sigma_rules_dir is None:
        return index

    for yml_path in sorted(sigma_rules_dir.rglob("*.y*ml")):
        try:
            content = yml_path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
        except Exception:
            continue
        if isinstance(data, dict):
            title = data.get("title")
            if isinstance(title, str) and title:
                index.setdefault(title, content)
    return index


def find_sigma_yaml_for_rule(sigma_yaml_index: dict[str, str], rule_title: str) -> str | None:
    """Return Sigma YAML for a rule title from a prebuilt index."""
    return sigma_yaml_index.get(rule_title)


def detect_rules_type(rules_path: Path) -> tuple[str, Path]:
    """
    Detect whether the path is a Zircolite JSON ruleset or a Sigma YAML rules directory.
    Returns ('zircolite', path) or ('sigma', path).
    Raises SystemExit if the path is invalid or ambiguous.
    """
    resolved = rules_path.resolve()
    if resolved.is_file():
        if resolved.suffix.lower() == ".json":
            return "zircolite", resolved
        try:
            with open(resolved, "rb") as f:
                head = f.read(100)
            if head.lstrip().startswith(b"["):
                return "zircolite", resolved
        except OSError:
            pass
        print(f"Error: rules path is a file but not a JSON ruleset: {resolved}", file=sys.stderr)
        raise SystemExit(1)
    if resolved.is_dir():
        return "sigma", resolved
    print(f"Error: rules path not found or not a file/directory: {resolved}", file=sys.stderr)
    raise SystemExit(1)


def write_report_markdown(
    path: Path,
    report: dict[str, Any],
    elapsed_seconds: float,
) -> None:
    """Write a human-readable Markdown report with full failed-test details (SQL, YAML, events)."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Sigma Regression Test Report\n\n")
        f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}  \n")
        f.write(f"**Duration:** {elapsed_seconds:.1f}s\n\n")
        f.write("---\n\n")
        f.write("## Summary\n\n")
        f.write("| Result  | Count |\n")
        f.write("|---------|-------|\n")
        f.write(f"| Passed  | {report['passed']} |\n")
        f.write(f"| Failed  | {report['failed']} |\n")
        f.write(f"| Skipped | {report['skipped']} |\n")
        f.write(f"| **Total** | **{report['total']}** |\n\n")
        failed_list = report.get("failed_tests") or []
        if failed_list:
            f.write("## Failed Tests\n\n")
            f.write("| # | Rule Title | Rule ID | Case | Expected | Got |\n")
            f.write("|---|------------|---------|------|----------|-----|\n")
            for i, t in enumerate(failed_list, 1):
                title = (t.get("rule_title") or "").replace("|", "\\|")
                f.write(f"| {i} | {title} | `{t.get('rule_id', '')}` | {t.get('case_name', '')} | {t.get('expected', '')} | {t.get('got', '')} |\n")
            f.write("\n---\n\n")
            for i, t in enumerate(failed_list, 1):
                f.write(f"### Failed test #{i}: {t.get('rule_title', '')}\n\n")
                f.write(f"- **Test case:** `{t.get('case_name', '')}`  \n")
                f.write(f"- **Data file:** `{t.get('data_file', '')}`  \n")
                f.write(f"- **Rule id:** `{t.get('rule_id', '')}`  \n")
                f.write(f"- **Expected:** {t.get('expected', '')} match(es)  \n")
                f.write(f"- **Got:** {t.get('got', '')} match(es)  \n")
                variants = t.get("variants") or []
                if len(variants) > 1:
                    counts = ", ".join(f"{v['title']}: {v['count']}" for v in variants)
                    f.write(f"- **Per rule variant:** {counts}  \n")
                if t.get("error"):
                    f.write(f"- **Error:** {t.get('error')}  \n")
                f.write("\n#### Rule (SQL)\n\n```sql\n")
                f.write("\n\n".join(_beautify_sql(q.strip()) for q in t.get("rule_sql") or []))
                f.write("\n```\n\n")
                f.write("#### Rule (Sigma YAML)\n\n```yaml\n")
                f.write((t.get("sigma_yaml") or "# Sigma YAML not found for this rule title.\n").rstrip() + "\n")
                f.write("```\n\n")
                f.write("#### Events (from DB, flattened)\n\n")
                events = t.get("events") or []
                if events:
                    f.write("```yaml\n")
                    yaml.dump(events, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                    f.write("```\n\n")
                else:
                    f.write("*No events in DB.*\n\n")
        f.write("---\n\n")
        if report.get("filtered_event_fields"):
            f.write("\n*Events in this report show only fields referenced in the rule SQL.*\n")


def write_report_json(path: Path, report: dict[str, Any]) -> None:
    """Write a structured JSON report including full failed-test data (rule_sql, sigma_yaml, events)."""
    out = {k: v for k, v in report.items() if k != "failed_tests"}
    if report.get("failed_tests"):
        out["failed_tests"] = [
            {
                "case_name": t.get("case_name"),
                "data_file": t.get("data_file"),
                "rule_title": t.get("rule_title"),
                "rule_id": t.get("rule_id"),
                "expected": t.get("expected"),
                "got": t.get("got"),
                "variants": t.get("variants"),
                "error": t.get("error"),
                "rule_sql": t.get("rule_sql"),
                "sigma_yaml": t.get("sigma_yaml"),
                "events": t.get("events"),
            }
            for t in report["failed_tests"]
        ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)


def run_single_test(
    data_file: Path,
    input_type: str,
    rules: list[dict[str, Any]],
    config_path: str,
    logger: logging.Logger,
    json_array: bool = True,
    quiet: bool = True,
    return_events_on_fail: bool = False,
) -> tuple[dict[str, int], str, list[dict[str, Any]] | None]:
    """
    Run Zircolite once on one file with every variant of the rule loaded.

    A Sigma id resolves to one rule per pipeline in a merged ruleset, and the
    sample only carries one provider, so all of them are executed against a
    single ingest of the file rather than re-reading it per variant.

    Returns (match count per rule title, error_message, events_from_db).
    events_from_db is set when return_events_on_fail=True (for --report).
    """
    if quiet:
        set_quiet_mode(True)
        test_logger = logging.getLogger("zircolite.regression")
        test_logger.setLevel(logging.WARNING)
        test_logger.handlers = []
        test_logger.propagate = False
    else:
        test_logger = logger
    try:
        proc_config = ProcessingConfig(
            db_location=":memory:",
            disable_progress=True,
            no_output=True,
        )
        core = ZircoliteCore(config_path, proc_config, logger=test_logger)
        events_from_db: list[dict[str, Any]] | None = None
        try:
            # Minimal args for streaming (no transforms needed for regression).
            # A Namespace, not a class: attributes declared on a class body are
            # invisible to vars(), which used to make the format resolve to the
            # default no matter what was asked for.
            args_ns = argparse.Namespace(
                json_array_input=json_array,
                all_transforms=False,
                transform_categories=None,
            )

            core.run_streaming(
                [str(data_file)],
                input_type=input_type,
                args_config=args_ns,
                extractor=None,
                disable_progress=True,
            )
            core.load_ruleset_from_var(ruleset=rules, rule_filters=None)
            core.execute_ruleset(
                "",  # no output
                write_mode="w",
                keep_results=True,
                last_ruleset=True,
                show_table=False,
            )
            if return_events_on_fail:
                events_from_db = core.execute_select_query("SELECT * FROM logs")
            # full_results holds one entry per rule that matched; a rule that
            # fired on nothing is absent, hence the 0 default at the call site.
            counts: dict[str, int] = {}
            for res in core.full_results:
                title = res.get("title")
                if isinstance(title, str):
                    counts[title] = max(counts.get(title, 0), res.get("count", 0))
            return counts, "", events_from_db
        except Exception as e:
            if return_events_on_fail and core.db_connection:
                try:
                    events_from_db = core.execute_select_query("SELECT * FROM logs")
                except Exception:
                    events_from_db = []
            return {}, str(e), events_from_db
        finally:
            core.close()
    finally:
        if quiet:
            set_quiet_mode(False)


def build_failed_result(
    case_name: str,
    data_file: Path,
    ref: RuleRef,
    rules: list[dict[str, Any]],
    counts: dict[str, int],
    expected: str,
    got: int,
    error: str,
    events: list[dict[str, Any]] | None,
    sigma_yaml_index: dict[str, str],
    include_report_data: bool,
) -> dict[str, Any]:
    """Build a normalized failed-test payload for console/report output."""
    result = {
        "case_name": case_name,
        "data_file": str(data_file),
        "rule_title": ref.title,
        "rule_id": ref.id,
        "expected": expected,
        "got": got,
        "error": error,
        "events": events or [],
        # Which encoding of the rule saw what, so a report reader can tell a
        # Sysmon-only miss from a rule that fired nowhere.
        "variants": [
            {"title": r.get("title", ""), "count": counts.get(r.get("title", ""), 0)}
            for r in rules
        ],
    }
    if include_report_data:
        result["rule_sql"] = [sql for r in rules for sql in (r.get("rule") or [])]
        result["sigma_yaml"] = find_sigma_yaml_for_rule(sigma_yaml_index, ref.title)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Sigma regression_data detection tests with Zircolite.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--regression-data",
        type=Path,
        required=True,
        help="Path to regression_data directory (test cases discovered recursively under this path)",
    )
    parser.add_argument(
        "--rules",
        "-r",
        type=Path,
        required=True,
        metavar="PATH",
        dest="rules",
        help="Path to rules: a Zircolite JSON ruleset file (.json) or a Sigma YAML rules directory (auto-detected).",
    )
    parser.add_argument(
        "--zircolite-config",
        type=Path,
        default=None,
        help="Path to Zircolite field mappings config (default: project config/config.yaml)",
    )
    parser.add_argument(
        "--pipeline",
        type=str,
        action="append",
        default=None,
        dest="pipelines",
        help="pySigma pipeline(s) for converting Sigma YAML (can be repeated). Default: sysmon, windows-logsources",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose logging",
    )
    parser.add_argument(
        "--report",
        "-o",
        type=Path,
        default=None,
        metavar="PATH",
        dest="report",
        help="Write report: PATH.md and PATH.json (summary + full failed-test data: SQL, YAML, events). PATH is base without extension.",
    )
    parser.add_argument(
        "--report-all-event-fields",
        "-rae",
        action="store_true",
        help="In the report, include all event fields. By default only fields referenced in the rule SQL are included.",
    )
    parser.add_argument(
        "--fail-on-skip",
        action="store_true",
        help="Exit non-zero when any test was skipped. A skipped test asserts nothing, so a run that skips most of its cases still reports success without this.",
    )
    args = parser.parse_args()

    regression_data = args.regression_data.resolve()
    if not regression_data.is_dir():
        print(f"Error: regression_data not found: {regression_data}", file=sys.stderr)
        return 1

    try:
        rules_type, rules_path = detect_rules_type(args.rules)
    except SystemExit:
        return 1
    sigma_rules: Path | None = rules_path if rules_type == "sigma" else None

    # Zircolite config: prefer project root config/config.yaml
    if args.zircolite_config:
        config_path = str(args.zircolite_config.resolve())
    else:
        project_root = Path(__file__).resolve().parent.parent
        default_config = project_root / "config" / "config.yaml"
        if default_config.exists():
            config_path = str(default_config)
        else:
            print(f"Error: Zircolite config not found: {default_config}", file=sys.stderr)
            return 1

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = init_logger(debug_mode=(log_level == logging.DEBUG), log_file=None)
    start_time = time.time()

    # ---- Banner ----
    console.print()
    console.print(BANNER)
    console.print()

    # ---- Loading ruleset ----
    console.print(Rule("[bold cyan]Loading ruleset[/]", style="dim"))
    if rules_type == "zircolite":
        console.print("[bold white]\\[+][/] Loading Zircolite ruleset (no conversion)…")
        try:
            with open(rules_path, encoding="utf-8") as f:
                full_ruleset = json.load(f)
        except Exception as e:
            console.print(f"[red]\\[-][/] Failed to load ruleset: {e}")
            return 1
        if not isinstance(full_ruleset, list):
            console.print("[red]\\[-][/] Zircolite ruleset must be a JSON array of rules")
            return 1
        if not full_ruleset:
            console.print(f"[red]\\[-][/] No rules in {make_file_link(str(rules_path))}")
            return 1
        console.print(f"    [>] Loaded [bold magenta]{len(full_ruleset)}[/] rules from {make_file_link(str(rules_path), rules_path.name)}\n")
    else:
        pipelines = args.pipelines or ["sysmon", "windows-logsources"]
        ruleset_config = RulesetConfig(
            ruleset=[str(rules_path)],
            pipeline=[[p] for p in pipelines],
            save_ruleset=False,
        )
        console.print("[bold white]\\[+][/] Converting Sigma rules (YAML → Zircolite)…")
        try:
            handler = RulesetHandler(ruleset_config, logger=logger)
            full_ruleset = handler.rulesets
        except Exception as e:
            console.print(f"[red]\\[-][/] Failed to load ruleset: {e}")
            return 1
        if not full_ruleset:
            console.print(f"[red]\\[-][/] No rules loaded from {make_file_link(str(rules_path))}")
            return 1
        console.print(f"    [>] Loaded [bold magenta]{len(full_ruleset)}[/] rules\n")

    # ---- Discovering test cases ----
    console.print(Rule("[bold cyan]Discovering test cases[/]", style="dim"))
    cases = discover_test_cases(regression_data)
    console.print(f"[bold white]\\[+][/] Found [bold magenta]{len(cases)}[/] test case(s) under {make_file_link(str(regression_data))}")
    console.print()

    # ---- Running tests ----
    console.print(Rule("[bold cyan]Running tests[/]", style="dim"))
    console.print("[bold white]\\[+][/] Executing regression tests…")
    passed = 0
    failed = 0
    skipped = 0
    quiet_tests = not args.verbose
    failed_results: list[dict[str, Any]] = []
    total_tests = sum(len(c.tests) for c in cases)
    need_events = bool(args.report)
    rules_index = RulesIndex(full_ruleset)
    sigma_yaml_index = build_sigma_yaml_index(sigma_rules) if need_events else {}
    buffered_lines: list[str] = []  # Rich markup strings to print after progress

    # Batch progress updates to reduce flicker (update every N tests, not every test)
    progress_batch_size = max(1, min(10, total_tests // 15)) if total_tests else 1

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=24, complete_style="green", finished_style="bold green"),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
        refresh_per_second=4,
        disable=args.verbose,
    )
    progress.start()
    task_id = progress.add_task("Executing", total=total_tests)
    pending_advance = 0

    for case in cases:
        rules = rules_index.find(case.rule_refs)
        if not rules:
            titles = [r.title for r in case.rule_refs]
            buffered_lines.append(f"    [yellow]\\[!][/] No matching rules for {make_file_link(str(case.dir_path), case.dir_path.name)} (titles: {titles})")
            skipped += len(case.tests)
            pending_advance += len(case.tests)
            if pending_advance >= progress_batch_size:
                progress.advance(task_id, advance=pending_advance)
                pending_advance = 0
            continue

        ref = case.rule_refs[0]
        for test_entry in case.tests:
            pending_advance += 1
            if pending_advance >= progress_batch_size:
                progress.advance(task_id, advance=pending_advance)
                pending_advance = 0
            data_file = resolve_data_file(regression_data, test_entry, case.dir_path)
            if not data_file:
                buffered_lines.append(f"    [yellow]\\[!][/] Data file not found: {make_file_link(str(case.dir_path), case.dir_path.name)} ([dim]{test_entry.path}[/])")
                skipped += 1
                continue

            input_type = test_entry.type
            counts, err, events_from_db = run_single_test(
                data_file,
                input_type,
                rules,
                config_path,
                logger,
                json_array=input_type == "json",
                quiet=quiet_tests,
                return_events_on_fail=need_events,
            )
            # The best any encoding of the rule managed. A positive test needs
            # one variant to fire; a negative one needs the maximum to be 0,
            # which is the same as every variant staying silent.
            count = max((counts.get(r.get("title", ""), 0) for r in rules), default=0)
            expected_label = expectation_label(test_entry)

            if err:
                buffered_lines.extend(
                    format_failed_rule_lines(
                        case.dir_path, data_file, ref.title, ref.id, err,
                        icon="-", style="red",
                    )
                )
                failed += 1
                failed_results.append(build_failed_result(
                    case_name=case.dir_path.name,
                    data_file=data_file,
                    ref=ref,
                    rules=rules,
                    counts=counts,
                    expected=expected_label,
                    got=count,
                    error=err,
                    events=events_from_db,
                    sigma_yaml_index=sigma_yaml_index,
                    include_report_data=need_events,
                ))
                continue

            if expectation_met(test_entry, count):
                passed += 1
                if args.verbose:
                    buffered_lines.append(f"    [green]\\[✓][/] {make_file_link(str(case.dir_path), case.dir_path.name)} ({make_file_link(str(data_file), data_file.name)}) [green]rule[/] [dim]{ref.title}[/] [dim](id: {ref.id})[/] [green]→ {count} matches[/]")
            else:
                failed += 1
                buffered_lines.extend(
                    format_failed_rule_lines(
                        case.dir_path, data_file, ref.title, ref.id,
                        f"expected {expected_label}, got {count}"
                        + (f" across {len(rules)} rule variants" if len(rules) > 1 else ""),
                        icon="!", style="yellow",
                    )
                )
                failed_results.append(build_failed_result(
                    case_name=case.dir_path.name,
                    data_file=data_file,
                    ref=ref,
                    rules=rules,
                    counts=counts,
                    expected=expected_label,
                    got=count,
                    error="",
                    events=events_from_db,
                    sigma_yaml_index=sigma_yaml_index,
                    include_report_data=need_events,
                ))

    if pending_advance > 0:
        progress.advance(task_id, advance=pending_advance)
    progress.stop()
    for line in buffered_lines:
        console.print(line)
    elapsed = time.time() - start_time

    total = passed + failed + skipped

    # ---- Summary panel ----
    summary_table = Table(show_header=False, box=None, padding=(0, 2), expand=False)
    summary_table.add_column("Label", style="dim")
    summary_table.add_column("Value", style="bold")
    summary_table.add_row("Passed", f"[green]{passed}[/]")
    summary_table.add_row("Failed", f"[red]{failed}[/]" if failed else f"[dim]{failed}[/]")
    # A skipped test asserts nothing, so a large skip count is a result in its
    # own right, not a footnote: it is what a title-matched run used to hide.
    skipped_style = "red" if (skipped and args.fail_on_skip) else ("yellow" if skipped else "dim")
    skipped_note = f" [dim]({skipped / total:.0%} of total)[/]" if skipped and total else ""
    summary_table.add_row("Skipped", f"[{skipped_style}]{skipped}[/]{skipped_note}")
    summary_table.add_row("Total", f"[bold magenta]{total}[/]")
    summary_table.add_row("Duration", f"[dim]{elapsed:.1f}s[/]")

    if failed_results:
        summary_table.add_row("", "")
        summary_table.add_row("Failed rules", "")
        for fr in failed_results:
            summary_table.add_row("  •", f"[cyan]{fr['rule_title']}[/] [dim](id: {fr['rule_id']})[/]")

    skip_fails = bool(skipped) and args.fail_on_skip
    if failed:
        result_text = f"{failed} test(s) failed"
    elif skip_fails:
        result_text = f"{skipped} test(s) skipped"
    else:
        result_text = "All tests passed"
    result_style = "green" if not (failed or skip_fails) else "red"
    console.print()
    console.print(Panel(summary_table, title=f"[bold] Summary · {result_text} [/]", border_style=result_style, padding=(1, 2)))
    console.print()

    # ---- Report files (Markdown + JSON, with full failed-test data) ----
    if args.report:
        base = args.report.resolve()
        if base.suffix.lower() in (".md", ".json"):
            base = base.with_suffix("")
        md_path = base.with_suffix(".md")
        json_path = base.with_suffix(".json")
        report_all_fields = args.report_all_event_fields
        failed_tests_for_report = []
        for fr in failed_results:
            entry = dict(fr)
            if not report_all_fields and entry.get("events"):
                entry["events"] = _filter_events_to_rule_fields(
                    entry["events"],
                    entry.get("rule_sql") or [],
                )
            failed_tests_for_report.append(entry)
        report = {
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "total": total,
            "elapsed_seconds": round(elapsed, 2),
            "regression_data": str(regression_data),
            "filtered_event_fields": not report_all_fields,
            "failed_tests": failed_tests_for_report,
        }
        write_report_markdown(md_path, report, elapsed)
        write_report_json(json_path, report)
        console.print(f"[bold white]\\[+][/] Report: {make_file_link(str(md_path))}  [dim]|[/]  {make_file_link(str(json_path))}")
        console.print()

    return 0 if not (failed or skip_fails) else 1


if __name__ == "__main__":
    sys.exit(main())
