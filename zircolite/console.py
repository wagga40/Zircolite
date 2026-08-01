"""
Rich-based console output for Zircolite.

This module provides styled terminal output using the Rich library:
- The shared ``console`` instance and the Zircolite theme
- Banners, section separators and error panels
- Renderables for detection tables, file trees and ATT&CK summaries

Progress bars and live displays are built inline by the callers that own
them (``zircolite.core`` and ``zircolite.processing``).
"""

import contextlib
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.bar import Bar
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.tree import Tree

from .attack import extract_attack_tactics, extract_attack_techniques

# Custom Zircolite theme
ZIRCOLITE_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "critical": "bold red reverse",
    "high": "bold magenta",
    "medium": "bold yellow",
    "low": "green",
    "informational": "dim white",
    "file": "cyan",
    "count": "bold magenta",
    "time": "yellow",
    "header": "bold cyan",
    "progress.description": "cyan",
    "progress.percentage": "green",
    "progress.remaining": "yellow",
    "rule.title": "cyan",
    "rule.level.critical": "bold red",
    "rule.level.high": "bold magenta",
    "rule.level.medium": "bold yellow",
    "rule.level.low": "green",
    "rule.level.informational": "dim",
    "stat.label": "dim",
    "stat.value": "bold cyan",
})

# On Windows, redirected stdout/stderr default to the legacy ANSI codepage
# (e.g. cp1252) and crash on the banner/checkmark glyphs. Reconfigure to UTF-8
# so piped output works; errors are replaced rather than raised.
if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError, OSError):
            _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

# Global console instance for consistent output
console = Console(theme=ZIRCOLITE_THEME, highlight=False)


# ============================================================================
# QUIET MODE SUPPORT
# ============================================================================

_quiet_mode: bool = False


def set_quiet_mode(quiet: bool = True):
    """Enable/disable quiet mode globally.

    When quiet mode is active, non-essential output (banners, progress info,
    detection listings) is suppressed. Errors, warnings, and the final
    summary panel still display.
    """
    global _quiet_mode
    _quiet_mode = quiet


def is_quiet() -> bool:
    """Check if quiet mode is active."""
    return _quiet_mode


# ============================================================================
# BANNER
# ============================================================================

_BANNER = """\
[bold cyan]███████╗██╗██████╗  ██████╗ ██████╗ ██╗     ██╗████████╗███████╗[/]
[cyan]╚══███╔╝██║██╔══██╗██╔════╝██╔═══██╗██║     ██║╚══██╔══╝██╔════╝[/]
[bold blue]  ███╔╝ ██║██████╔╝██║     ██║   ██║██║     ██║   ██║   █████╗[/]
[blue] ███╔╝  ██║██╔══██╗██║     ██║   ██║██║     ██║   ██║   ██╔══╝[/]
[bold magenta]███████╗██║██║  ██║╚██████╗╚██████╔╝███████╗██║   ██║   ███████╗[/]
[magenta]╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝[/]
[dim]-= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-[/]"""


def print_banner(version: str):
    """Print the Zircolite ASCII banner with version number."""
    if _quiet_mode:
        return
    console.print()
    console.print(_BANNER)
    console.print(f"                              [dim]v{version}[/]\n")


# ============================================================================
# SECTION SEPARATORS
# ============================================================================

def print_section(title: str = ""):
    """Print a section separator with an optional centered title.

    Uses ``rich.rule.Rule`` to draw a horizontal line across the terminal,
    providing clear visual boundaries between processing phases.
    Suppressed in quiet mode.
    """
    if _quiet_mode:
        return
    if title:
        console.print(Rule(f"[bold cyan]{title}[/]", style="dim"))
    else:
        console.print(Rule(style="dim"))


# ============================================================================
# ERROR PANEL
# ============================================================================

def print_error_panel(title: str, message: str, suggestion: str = ""):
    """Display a fatal error inside a prominent red-bordered panel.

    Always shown regardless of quiet mode – errors must never be hidden.

    Args:
        title: Short error category (e.g. "Missing File")
        message: Detailed error description
        suggestion: Optional remediation hint shown below the message
    """
    content = f"[bold red]{message}[/]"
    if suggestion:
        content += f"\n\n[dim]Suggestion: {suggestion}[/]"
    console.print()
    console.print(
        Panel(
            content,
            title=f"[bold red]Error: {title}[/]",
            border_style="red",
            padding=(1, 2),
        )
    )


# ============================================================================
# "NO DETECTIONS" ZERO-STATE
# ============================================================================

def print_no_detections():
    """Display a styled zero-state panel when no rules matched.

    Gives the user clear visual confirmation that analysis completed
    cleanly rather than a single dim log line.  Suppressed in quiet mode.
    """
    if _quiet_mode:
        return
    console.print()
    console.print(
        Panel(
            "[bold green]No detections found[/]\n"
            "[dim]All rules executed \u2014 no matches in the provided logs.[/]",
            border_style="green",
            padding=(1, 2),
        )
    )


@dataclass
class DetectionStats:
    """Statistics for detection tracking."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total_events: int = 0
    total_rules_matched: int = 0

    def add_detection(self, level: str, count: int):
        """Add a detection to the stats."""
        level_lower = level.lower()
        if level_lower == "critical":
            self.critical += count
        elif level_lower == "high":
            self.high += count
        elif level_lower == "medium":
            self.medium += count
        elif level_lower == "low":
            self.low += count
        elif level_lower == "informational":
            self.informational += count
        self.total_events += count
        self.total_rules_matched += 1


def get_rich_logger(name: str = "zircolite", debug: bool = False, log_file: str | None = None) -> logging.Logger:
    """
    Create a logger with Rich handler for styled console output.

    Args:
        name: Logger name
        debug: Enable debug level logging
        log_file: Optional file path for persistent logging

    Returns:
        Configured logger with Rich handler
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    # Close existing handlers before clearing to avoid leaking open log files
    for handler in logger.handlers:
        with contextlib.suppress(Exception):
            handler.close()
    logger.handlers.clear()
    logger.propagate = False

    # Rich console handler - hide level prefix for clean output
    rich_handler = RichHandler(
        console=console,
        show_path=False,
        show_time=False,
        show_level=False,  # Don't show INFO/DEBUG/etc prefix
        markup=True,
        rich_tracebacks=True,
    )
    rich_handler.setLevel(logging.INFO)
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(rich_handler)

    # File handler (if requested)
    if log_file:
        file_format = "%(asctime)s %(levelname)-8s %(message)s"
        if debug:
            file_format = "%(asctime)s %(levelname)-8s %(module)s:%(lineno)s %(funcName)s %(message)s"
        file_handler = logging.FileHandler(log_file, encoding="utf-8", errors="replace")
        file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
        file_handler.setFormatter(logging.Formatter(file_format, datefmt='%Y-%m-%d %H:%M:%S'))
        logger.addHandler(file_handler)

    return logger


# ============================================================================
# LIVE DETECTION COUNTER (for rule execution progress)
# ============================================================================

def make_detection_counter(counts: dict[str, int]) -> Text:
    """
    Build a live detection severity counter for display under a progress bar.

    Args:
        counts: Dict mapping severity levels to matching-event counts, the same
            unit the final summary panel reports

    Returns:
        Rich Text renderable showing detection summary
    """
    parts = []
    if counts.get("critical", 0):
        parts.append(f"[bold red]{counts['critical']} CRIT[/]")
    if counts.get("high", 0):
        parts.append(f"[bold magenta]{counts['high']} HIGH[/]")
    if counts.get("medium", 0):
        parts.append(f"[bold yellow]{counts['medium']} MED[/]")
    if counts.get("low", 0):
        parts.append(f"[green]{counts['low']} LOW[/]")
    if counts.get("informational", 0):
        parts.append(f"[dim]{counts['informational']} INFO[/]")

    if parts:
        return Text.from_markup("    " + "  ".join(parts))
    return Text("    No detections yet", style="dim")


# ============================================================================
# FILE TREE VIEW (for multi-file per-file processing)
# ============================================================================

def _format_file_node(fs: dict[str, Any]) -> str:
    """Format a single file stat dict as a Rich-markup tree label."""
    name = Path(fs["name"]).name
    events = fs.get("events", 0)
    detections = fs.get("detections", 0)
    filtered = fs.get("filtered", 0)

    # Color-code detection count
    if detections == 0:
        det_style = "green"
    elif detections < 5:
        det_style = "yellow"
    else:
        det_style = "red"

    det_label = "detection" if detections == 1 else "detections"
    det_text = f"[{det_style}]{detections} {det_label}[/]"

    full_path = fs.get("path")
    name_markup = make_file_link(full_path, name) if full_path else f"[cyan]{name}[/]"
    parts = [name_markup, f"[magenta]{events:,}[/] events", det_text]
    if filtered > 0:
        parts.append(f"[dim]{filtered:,} filtered[/]")

    return " \u2014 ".join(parts)


def build_file_tree(label: str, file_stats: list[dict[str, Any]]) -> Tree:
    """
    Build a Rich Tree showing per-file processing results.

    When files come from multiple directories, they are automatically
    grouped by parent directory for a nested, navigable tree.

    Args:
        label: Root label for the tree
        file_stats: List of dicts with keys: name, events, detections, filtered (optional)

    Returns:
        Rich Tree renderable
    """
    tree = Tree(f"[bold]{label}[/]")

    # Group by parent directory
    by_dir: dict[str, list] = {}
    for fs in file_stats:
        parent = str(Path(fs["name"]).parent)
        by_dir.setdefault(parent, []).append(fs)

    for dir_path, files in sorted(by_dir.items()):
        if dir_path == "." and len(by_dir) == 1:
            # Flat – add directly to root
            for fs in files:
                tree.add(_format_file_node(fs))
        else:
            branch = tree.add(f"[dim]{dir_path}/[/]")
            for fs in files:
                branch.add(_format_file_node(fs))

    return tree


# ============================================================================
# SEVERITY STYLES AND FORMATTERS
# ============================================================================

# Sort-order priority for severity levels (critical first, informational last).
# Canonical source – import this wherever results need severity-ordering.
LEVEL_PRIORITY = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


def sort_key_severity(result: dict[str, Any]) -> tuple[int, int]:
    """Sort key for a detection row: critical first, then descending count."""
    level = result.get("rule_level", "unknown").lower()
    return (LEVEL_PRIORITY.get(level, 5), -result.get("count", 0))


def make_severity_badge(level: str) -> Text:
    """Return a fixed-width, styled severity badge.

    Every severity level gets a contrasting background colour so that
    the badge is visually consistent across all rows and instantly
    scannable.  The label is centered inside the ``Text`` renderable
    using ``justify="center"`` so it aligns correctly regardless of
    the column width.

    Args:
        level: Severity level string (e.g. "critical", "high", ...)

    Returns:
        ``rich.text.Text`` renderable with consistent width and styling.
    """
    _BADGES = {
        "critical":      ("CRITICAL", "bold white on red"),
        "high":          ("HIGH",     "bold white on magenta"),
        "medium":        ("MEDIUM",   "bold black on yellow"),
        "low":           ("LOW",      "bold white on green"),
        "informational": ("INFO",     "white on bright_black"),
    }
    label, style = _BADGES.get(level.lower(), (level.upper(), ""))
    # Pad to fixed width so badges are visually uniform, then center
    badge = Text(f" {label} ", style=style, justify="center")
    return badge


# ============================================================================
# MITRE ATT&CK TACTICS SUMMARY
# ============================================================================

# ATT&CK tactic tag suffix -> display name
_ATTACK_TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def build_attack_summary(results: list[dict[str, Any]]) -> Panel | None:
    """
    Build a MITRE ATT&CK tactics summary panel from detection results.

    Extracts ATT&CK tags from detection results and groups techniques
    by tactic, showing a visual heatmap of coverage.

    Args:
        results: List of detection result dicts (with "tags" and "count" keys)

    Returns:
        Rich Panel with ATT&CK summary, or None if no ATT&CK tags found
    """
    tactic_techniques: dict[str, set] = {}
    tactic_hits: dict[str, int] = {}

    for result in results:
        tags = result.get("tags", [])
        count = result.get("count", 0)
        if not tags:
            continue

        tactics = extract_attack_tactics(tags)
        techniques = extract_attack_techniques(tags)

        for tactic in tactics:
            # attack.py owns the alias list; an entry added there and not here
            # must not take down the summary panel of an otherwise good run
            display_name = _ATTACK_TACTICS.get(tactic) or tactic.replace(
                "-", " "
            ).title()
            if display_name not in tactic_techniques:
                tactic_techniques[display_name] = set()
                tactic_hits[display_name] = 0
            tactic_techniques[display_name].update(techniques)
            tactic_hits[display_name] += count

    if not tactic_hits:
        return None

    sorted_tactics = sorted(tactic_hits.items(), key=lambda x: -x[1])
    max_hits = max(tactic_hits.values()) if tactic_hits else 1

    table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    table.add_column("Tactic", style="cyan", width=22, no_wrap=True)
    table.add_column("Bar", width=20)
    table.add_column("Details", style="dim", ratio=1)

    for tactic, hits in sorted_tactics:
        techs = tactic_techniques.get(tactic, set())
        bar = Bar(size=max_hits, begin=0, end=hits, width=16, color="yellow", bgcolor="bright_black")

        tech_count = len(techs)
        tech_label = "technique" if tech_count == 1 else "techniques"
        hit_label = "hit" if hits == 1 else "hits"
        detail = f"{tech_count} {tech_label} ({hits:,} {hit_label})"

        table.add_row(tactic, bar, detail)

    return Panel(table, title="[bold]🗺  ATT&CK Coverage[/]", border_style="yellow", padding=(0, 1), expand=True)


# ============================================================================
# DETECTION RESULTS TABLE
# ============================================================================

def build_detection_table(results: list[dict[str, Any]], title: str | None = None) -> Table:
    """
    Build a Rich Table showing detection results with severity, rule name,
    event count, and ATT&CK technique IDs.

    Args:
        results: List of detection result dicts, pre-sorted by severity
        title: Optional table title (e.g. filename for per-file mode)

    Returns:
        Rich Table renderable
    """
    table = Table(
        show_header=True,
        header_style="bold",
        border_style="dim",
        padding=(0, 1),
        title=f"[bold cyan]{title}[/]" if title else None,
        expand=True,
    )
    table.add_column("Severity", justify="center", width=14, no_wrap=True)
    table.add_column("Rule", no_wrap=False, ratio=1)
    table.add_column("Events", justify="right", style="magenta", width=8)
    table.add_column("ATT&CK", style="dim", width=22, no_wrap=True)

    for result in results:
        level = result.get("rule_level", "unknown")
        rule_title = result.get("title", "Unknown")
        count = result.get("count", 0)
        tags = result.get("tags", [])

        # Fixed-width severity badge with background highlighting
        level_text = make_severity_badge(level)

        attack_ids = extract_attack_techniques(tags)

        if len(attack_ids) > 3:
            attack_str = ", ".join(attack_ids[:3]) + f" +{len(attack_ids) - 3}"
        else:
            attack_str = ", ".join(attack_ids)

        table.add_row(level_text, rule_title, f"{count:,}", attack_str)

    return table


# ============================================================================
# TERMINAL HYPERLINKS
# ============================================================================

def print_rule_test_results(results: list[dict[str, Any]]) -> None:
    """Print rule test results as a Rich table.

    Args:
        results: List returned by ``ZircoliteCore.run_rule_tests()``.
    """
    if not results:
        console.print("[dim]No test results to display.[/]")
        return

    table = Table(
        title="[bold]Rule Test Results[/]",
        show_header=True,
        header_style="bold",
        border_style="dim",
        expand=True,
    )
    table.add_column("Rule", no_wrap=False, ratio=1)
    table.add_column("TP", justify="center", width=6)
    table.add_column("TN", justify="center", width=6)
    table.add_column("Notes", style="dim", width=30)

    passed = failed = skipped = 0
    for r in results:
        tp = r.get('tp_pass')
        tn = r.get('tn_pass')
        title = r.get('title', r.get('id', '?'))
        error = r.get('error', '')

        if tp is None and tn is None:
            # No test case
            tp_str = tn_str = "[dim]—[/]"
            notes = "[dim]no test case[/]"
            skipped += 1
        elif tp is False or tn is False:
            tp_str = "[green]✓[/]" if tp else "[bold red]✗[/]"
            tn_str = "[green]✓[/]" if tn else "[bold red]✗[/]"
            notes = error or (
                f"[red]TP={r.get('tp_count',0)}, TN={r.get('tn_count',0)}[/]"
            )
            failed += 1
        else:
            tp_str = "[green]✓[/]" if tp else "[dim]—[/]"
            tn_str = "[green]✓[/]" if tn else "[dim]—[/]"
            notes = ""
            passed += 1

        table.add_row(title, tp_str, tn_str, notes)

    console.print()
    console.print(table)
    console.print(
        f"    [dim]Passed: [green]{passed}[/]  "
        f"Failed: [red]{failed}[/]  "
        f"No test case: [yellow]{skipped}[/][/]"
    )


def print_profiling_report(report: list[dict[str, Any]], top_n: int = 20) -> None:
    """Print a rule performance report as a Rich table.

    Args:
        report: List of dicts returned by ``ZircoliteCore.get_profiling_report()``.
        top_n: Maximum number of rules to display.
    """
    if not report:
        console.print("[dim]No profiling data available.[/]")
        return

    table = Table(
        title="[bold]Rule Performance Report[/]",
        show_header=True,
        header_style="bold",
        border_style="dim",
        expand=True,
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Rule", no_wrap=False, ratio=1)
    table.add_column("Time (ms)", justify="right", width=12)

    for rank, entry in enumerate(report[:top_n], start=1):
        elapsed = entry["elapsed_ms"]
        title = entry["title"]
        if elapsed >= 500:
            time_str = f"[bold red]{elapsed:.1f}[/]"
        elif elapsed >= 100:
            time_str = f"[bold yellow]{elapsed:.1f}[/]"
        else:
            time_str = f"{elapsed:.1f}"
        table.add_row(str(rank), title, time_str)

    console.print()
    console.print(table)
    total_ms = sum(e["elapsed_ms"] for e in report)
    console.print(
        f"    [dim]Total rule execution time: [cyan]{total_ms:.1f}[/] ms "
        f"across [cyan]{len(report)}[/] rules.[/]"
    )


def make_file_link(path: str, display: str | None = None) -> str:
    """
    Create a Rich markup string with a clickable file:// hyperlink.

    Works in terminals supporting OSC 8 hyperlinks (iTerm2, Windows Terminal,
    modern GNOME/KDE terminals). Falls back to plain text in others.

    Args:
        path: File path (relative or absolute) used for the link target
        display: Text shown to the user. Defaults to *path* when ``None``.

    Returns:
        Rich markup string with clickable link
    """
    text = display if display is not None else path
    try:
        abs_path = Path(path).resolve()
        uri = abs_path.as_uri()
        return f"[link={uri}][cyan]{text}[/][/link]"
    except (ValueError, OSError):
        return f"[cyan]{text}[/]"


