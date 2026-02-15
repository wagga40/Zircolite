#!python3
"""
Rich-based console output for Zircolite.

This module provides styled terminal output using the Rich library:
- Console output with colors and formatting
- Progress bars with live status updates
- Summary dashboards and tables
- Real-time detection tracking
"""

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.bar import Bar
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.tree import Tree

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


# ============================================================================
# CLI-STYLE HELPER FUNCTIONS
# ============================================================================

def print_step(message: str):
    """Print a step message with [+] prefix. Suppressed in quiet mode."""
    if not _quiet_mode:
        console.print(f"[bold white]\\[+][/] {message}")


def print_substep(message: str, style: str = "dim"):
    """Print a sub-step message with indentation. Suppressed in quiet mode."""
    if not _quiet_mode:
        console.print(f"    [{style}]\\[>][/] {message}")


def print_info(message: str):
    """Print an info message with [i] prefix. Suppressed in quiet mode."""
    if not _quiet_mode:
        console.print(f"    [dim]\\[i][/] {message}")


def print_success(message: str):
    """Print a success message with checkmark. Suppressed in quiet mode."""
    if not _quiet_mode:
        console.print(f"[green]\\[✓][/] {message}")


def print_warning(message: str):
    """Print a warning message with [!] prefix. Always shown."""
    console.print(f"[yellow]\\[!][/] {message}")


def print_error(message: str):
    """Print an error message with [-] prefix. Always shown."""
    console.print(f"[red]\\[-][/] {message}")


def print_file(label: str, path: str):
    """Print a file path with label. Suppressed in quiet mode."""
    if not _quiet_mode:
        console.print(f"[cyan]\\[+][/] {label}: [cyan]{path}[/]")


def print_count(label: str, count: int, style: str = "magenta"):
    """Print a count with label. Suppressed in quiet mode."""
    if not _quiet_mode:
        console.print(f"[cyan]\\[+][/] {label}: [{style}]{count:,}[/]")


def print_detection(title: str, level: str, count: int):
    """Print a detection result with styled severity level. Suppressed in quiet mode."""
    if _quiet_mode:
        return
    level_styles = {
        "critical": "bold red",
        "high": "bold magenta",
        "medium": "bold yellow",
        "low": "green",
        "informational": "dim",
    }
    level_style = level_styles.get(level.lower(), "cyan")
    console.print(f"    [cyan]•[/] {title} [[{level_style}]{level}[/]] : [magenta]{count:,}[/] events")


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
    
    @property
    def total_by_severity(self) -> Dict[str, int]:
        """Get totals by severity level."""
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "informational": self.informational,
        }


@dataclass
class ProcessingStats:
    """Overall processing statistics."""
    files_total: int = 0
    files_processed: int = 0
    files_failed: int = 0
    events_total: int = 0
    rules_executed: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    peak_memory_mb: float = 0.0
    avg_memory_mb: float = 0.0
    workers_used: int = 1
    detection_stats: DetectionStats = field(default_factory=DetectionStats)
    
    @property
    def elapsed_seconds(self) -> float:
        """Get elapsed time in seconds."""
        end = self.end_time or time.time()
        return end - self.start_time
    
    @property
    def events_per_second(self) -> float:
        """Calculate events processed per second."""
        elapsed = self.elapsed_seconds
        return self.events_total / elapsed if elapsed > 0 else 0


class ZircoliteConsole:
    """
    Rich-based console for Zircolite output.
    
    Provides styled output, progress tracking, and summary dashboards.
    """
    
    def __init__(self, quiet: bool = False, no_color: bool = False):
        """
        Initialize the console.
        
        Args:
            quiet: Suppress non-essential output
            no_color: Disable colors (for CI/piping)
        """
        self.quiet = quiet
        self.console = Console(
            theme=ZIRCOLITE_THEME,
            highlight=False,
            force_terminal=not no_color,
            no_color=no_color
        )
        self.stats = ProcessingStats()
        self._live: Optional[Live] = None
        self._progress: Optional[Progress] = None
        self._current_task: Optional[TaskID] = None
        self._detections: List[Dict[str, Any]] = []
    
    def print_banner(self, version: str):
        """Print the Zircolite ASCII banner."""
        if self.quiet:
            return
        self.console.print()
        self.console.print(_BANNER)
        self.console.print(f"                              [dim]v{version}[/]\n")
    
    def info(self, message: str, prefix: str = "[+]"):
        """Print an info message."""
        if not self.quiet:
            self.console.print(f"[bold white]{prefix}[/] {message}")
    
    def success(self, message: str, prefix: str = "[✓]"):
        """Print a success message."""
        if not self.quiet:
            self.console.print(f"[success]{prefix}[/] {message}")
    
    def warning(self, message: str, prefix: str = "[!]"):
        """Print a warning message."""
        self.console.print(f"[warning]{prefix}[/] {message}")
    
    def error(self, message: str, prefix: str = "[-]"):
        """Print an error message."""
        self.console.print(f"[error]{prefix}[/] {message}")
    
    def print_workload_analysis(
        self, 
        file_count: int,
        total_size: str,
        avg_size: str,
        available_ram: str,
        cpu_count: int,
        db_mode: str,
        db_reason: str,
        parallel_enabled: bool = False,
        parallel_workers: int = 1,
        parallel_reason: str = ""
    ):
        """Print workload analysis with styled output."""
        self.info("Analyzing workload...")
        
        # Create a nice table for workload info
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Label", style="dim")
        table.add_column("Value")
        
        table.add_row("Files", f"[count]{file_count}[/] ([file]{total_size}[/] total, avg [file]{avg_size}[/])")
        table.add_row("System", f"[success]{available_ram}[/] RAM available, [count]{cpu_count}[/] CPUs")
        
        # Database mode
        mode_icon = "🔗" if db_mode == "unified" else "📁"
        mode_style = "success" if db_mode == "unified" else "info"
        table.add_row(
            "DB Mode", 
            f"{mode_icon} [{mode_style}]{db_mode.upper()}[/] [dim]({db_reason})[/]"
        )
        
        # Parallel processing
        if parallel_enabled:
            table.add_row(
                "Parallel",
                f"⚡ [success]ENABLED[/] ([count]{parallel_workers}[/] workers)"
            )
        elif db_mode != "unified":
            table.add_row(
                "Parallel",
                f"⚡ [dim]disabled - {parallel_reason}[/]"
            )
        
        self.console.print(table)
        self.console.print()
    
    def create_file_progress(self, total_files: int, description: str = "Processing") -> Progress:
        """Create a progress bar for file processing."""
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=self.console,
            transient=True,
        )
        return self._progress
    
    def create_rule_progress(self, total_rules: int, description: str = "Executing rules") -> Progress:
        """Create a progress bar for rule execution."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )
    
    @contextmanager
    def live_status(self, status: str = "Processing..."):
        """Context manager for live status updates."""
        with self.console.status(status, spinner="dots") as status_obj:
            yield status_obj
    
    def print_detection(
        self, 
        title: str, 
        level: str, 
        count: int,
        show_immediately: bool = True
    ):
        """Print a detection result with styled output."""
        # Store for summary
        self._detections.append({
            "title": title,
            "level": level,
            "count": count
        })
        
        # Update stats
        self.stats.detection_stats.add_detection(level, count)
        
        if show_immediately and not self.quiet:
            level_style = f"rule.level.{level.lower()}"
            self.console.print(
                f"    [rule.title]•[/] {title} "
                f"[[{level_style}]{level}[/]] : "
                f"[count]{count:,}[/] events"
            )
    
    def print_detection_summary_table(self):
        """Print a summary table of all detections sorted by severity."""
        if not self._detections:
            print_no_detections()
            return
        
        # Sort detections by severity and count
        sorted_detections = sorted(
            self._detections,
            key=lambda d: (LEVEL_PRIORITY.get(d["level"].lower(), 5), -d["count"])
        )
        
        # Create detection table
        table = Table(
            title="[bold]Detection Results[/]",
            show_header=True,
            header_style="bold",
            border_style="dim",
            expand=True,
        )
        table.add_column("Rule", style="cyan", no_wrap=False, ratio=1)
        table.add_column("Level", justify="center", width=14)
        table.add_column("Events", justify="right", style="magenta")
        
        for det in sorted_detections:
            table.add_row(
                det["title"],
                make_severity_badge(det["level"]),
                f"{det['count']:,}"
            )
        
        self.console.print()
        self.console.print(table)
    
    def print_summary_dashboard(
        self,
        processing_time: float,
        files_processed: int,
        total_events: int,
        peak_memory_mb: float,
        avg_memory_mb: float,
        workers_used: int = 1
    ):
        """Print a summary dashboard at the end of processing."""
        # Update stats
        self.stats.end_time = time.time()
        self.stats.files_processed = files_processed
        self.stats.events_total = total_events
        self.stats.peak_memory_mb = peak_memory_mb
        self.stats.avg_memory_mb = avg_memory_mb
        self.stats.workers_used = workers_used
        
        # Create summary table
        summary_table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
        summary_table.add_column("Metric", style="dim", width=16)
        summary_table.add_column("Value", style="bold", ratio=1)
        
        # Time
        if processing_time >= 60:
            time_str = f"{int(processing_time // 60)}m {int(processing_time % 60)}s"
        else:
            time_str = f"{processing_time:.1f}s"
        summary_table.add_row("⏱  Duration", f"[time]{time_str}[/]")
        
        # Files
        summary_table.add_row("📁 Files", f"[file]{files_processed:,}[/]")
        
        # Events
        summary_table.add_row("📊 Events", f"[count]{total_events:,}[/]")
        
        # Throughput
        if processing_time > 0:
            throughput = total_events / processing_time
            summary_table.add_row("⚡ Throughput", f"[success]{throughput:,.0f}[/] events/s")
        
        # Workers (if parallel)
        if workers_used > 1:
            summary_table.add_row("👥 Workers", f"[count]{workers_used}[/]")
        
        # Memory
        if peak_memory_mb > 0:
            if peak_memory_mb >= 1024:
                mem_str = f"{peak_memory_mb / 1024:.2f} GB"
            else:
                mem_str = f"{peak_memory_mb:.0f} MB"
            summary_table.add_row("💾 Peak Memory", f"[info]{mem_str}[/]")
        
        # Detection summary by severity
        det_stats = self.stats.detection_stats
        detection_parts = []
        if det_stats.critical > 0:
            detection_parts.append(f"[rule.level.critical]{det_stats.critical} CRIT[/]")
        if det_stats.high > 0:
            detection_parts.append(f"[rule.level.high]{det_stats.high} HIGH[/]")
        if det_stats.medium > 0:
            detection_parts.append(f"[rule.level.medium]{det_stats.medium} MED[/]")
        if det_stats.low > 0:
            detection_parts.append(f"[rule.level.low]{det_stats.low} LOW[/]")
        if det_stats.informational > 0:
            detection_parts.append(f"[rule.level.informational]{det_stats.informational} INFO[/]")
        
        if detection_parts:
            summary_table.add_row("🎯 Detections", " | ".join(detection_parts))
        else:
            summary_table.add_row("🎯 Detections", "[dim]None[/]")
        
        # Total matched events
        if det_stats.total_events > 0:
            summary_table.add_row(
                "🔍 Matched Events", 
                f"[count]{det_stats.total_events:,}[/] across [count]{det_stats.total_rules_matched}[/] rules"
            )
        
        # Print panel
        self.console.print()
        panel = Panel(
            summary_table,
            title="[bold]Summary[/]",
            border_style="cyan",
            padding=(1, 2),
            expand=True,
        )
        self.console.print(panel)
    
    def clear_detections(self):
        """Clear stored detections for new run."""
        self._detections = []
        self.stats = ProcessingStats()


class RichProgressTracker:
    """
    Progress tracker for real-time updates during processing.
    
    Supports multiple concurrent progress bars and live status updates.
    """
    
    def __init__(self, console: Optional[Console] = None, quiet: bool = False):
        """Initialize the progress tracker."""
        self.console = console or Console(theme=ZIRCOLITE_THEME)
        self.quiet = quiet
        self._progress: Optional[Progress] = None
        self._live: Optional[Live] = None
        self._tasks: Dict[str, TaskID] = {}
        self._detection_count: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, 
            "low": 0, "informational": 0
        }
    
    def create_multi_progress(self) -> Progress:
        """Create a multi-task progress bar."""
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )
        return self._progress
    
    @contextmanager
    def live_progress(self, total: int, description: str = "Processing"):
        """Context manager for live progress updates."""
        if self.quiet:
            yield None
            return
        
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("•"),
            TextColumn("[count]{task.fields[events]:,}[/] events"),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )
        
        with progress:
            task_id = progress.add_task(description, total=total, events=0)
            
            def update(advance: int = 1, events: int = 0):
                progress.update(task_id, advance=advance, events=events)
            
            yield update
    
    @contextmanager
    def live_rule_execution(self, total_rules: int):
        """Context manager for rule execution with live detection updates."""
        if self.quiet:
            yield None, lambda *args, **kwargs: None
            return
        
        # Create progress bar
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )
        
        # Create detection summary table
        def make_detection_table():
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column("Level", width=12)
            table.add_column("Count", justify="right", width=8)
            
            if self._detection_count["critical"] > 0:
                table.add_row("[rule.level.critical]CRITICAL[/]", str(self._detection_count["critical"]))
            if self._detection_count["high"] > 0:
                table.add_row("[rule.level.high]HIGH[/]", str(self._detection_count["high"]))
            if self._detection_count["medium"] > 0:
                table.add_row("[rule.level.medium]MEDIUM[/]", str(self._detection_count["medium"]))
            if self._detection_count["low"] > 0:
                table.add_row("[rule.level.low]LOW[/]", str(self._detection_count["low"]))
            if self._detection_count["informational"] > 0:
                table.add_row("[rule.level.informational]INFO[/]", str(self._detection_count["informational"]))
            
            return table
        
        # Group progress and detections
        task_id = None
        
        with Live(console=self.console, refresh_per_second=10, transient=True) as live:
            progress.start()
            task_id = progress.add_task("Executing rules", total=total_rules)
            
            def update(advance: int = 1, detection: Optional[Dict] = None):
                progress.update(task_id, advance=advance)
                
                if detection:
                    level = detection.get("level", "unknown").lower()
                    count = detection.get("count", 0)
                    if level in self._detection_count:
                        self._detection_count[level] += count
                
                # Update live display
                group = Group(progress, make_detection_table())
                live.update(group)
            
            yield progress, update
            
            progress.stop()
        
        # Reset for next run
        self._detection_count = {k: 0 for k in self._detection_count}


def get_rich_logger(name: str = "zircolite", debug: bool = False, log_file: Optional[str] = None) -> logging.Logger:
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
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
        file_handler.setFormatter(logging.Formatter(file_format, datefmt='%Y-%m-%d %H:%M:%S'))
        logger.addHandler(file_handler)
    
    return logger


# ============================================================================
# LIVE DETECTION COUNTER (for rule execution progress)
# ============================================================================

def make_detection_counter(counts: Dict[str, int]) -> Text:
    """
    Build a live detection severity counter for display under a progress bar.
    
    Args:
        counts: Dict mapping severity levels to rule-match counts
        
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

def _format_file_node(fs: Dict[str, Any]) -> str:
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

    parts = [f"[cyan]{name}[/]", f"[magenta]{events:,}[/] events", det_text]
    if filtered > 0:
        parts.append(f"[dim]{filtered:,} filtered[/]")

    return " \u2014 ".join(parts)


def build_file_tree(label: str, file_stats: List[Dict[str, Any]]) -> Tree:
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
    by_dir: Dict[str, list] = {}
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

# Color/style mapping for severity levels
LEVEL_STYLES = {
    "critical": "rule.level.critical",
    "high": "rule.level.high", 
    "medium": "rule.level.medium",
    "low": "rule.level.low",
    "informational": "rule.level.informational",
}


def format_level(level: str) -> str:
    """Format a severity level with appropriate style markup."""
    style = LEVEL_STYLES.get(level.lower(), "")
    if style:
        return f"[{style}]{level}[/]"
    return level


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
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def build_attack_summary(results: List[Dict[str, Any]]) -> Optional[Panel]:
    """
    Build a MITRE ATT&CK tactics summary panel from detection results.

    Extracts ATT&CK tags from detection results and groups techniques
    by tactic, showing a visual heatmap of coverage.

    Args:
        results: List of detection result dicts (with "tags" and "count" keys)

    Returns:
        Rich Panel with ATT&CK summary, or None if no ATT&CK tags found
    """
    tactic_techniques: Dict[str, set] = {}
    tactic_hits: Dict[str, int] = {}

    for result in results:
        tags = result.get("tags", [])
        count = result.get("count", 0)
        if not tags:
            continue

        tactics = []
        techniques = []
        for tag in tags:
            tag_lower = tag.lower()
            if not tag_lower.startswith("attack."):
                continue
            suffix = tag_lower[7:]  # Remove "attack." prefix

            if suffix.startswith("t") and len(suffix) > 1 and suffix[1].isdigit():
                techniques.append(suffix.upper())
            elif suffix in _ATTACK_TACTICS:
                tactics.append(suffix)

        for tactic in tactics:
            display_name = _ATTACK_TACTICS[tactic]
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

def build_detection_table(results: List[Dict[str, Any]], title: Optional[str] = None) -> Table:
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

        # Extract ATT&CK technique IDs from tags
        attack_ids = []
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.t") and len(tag_lower) > 8 and tag_lower[8].isdigit():
                attack_ids.append(tag[7:].upper())

        if len(attack_ids) > 3:
            attack_str = ", ".join(attack_ids[:3]) + f" +{len(attack_ids) - 3}"
        else:
            attack_str = ", ".join(attack_ids)

        table.add_row(level_text, rule_title, f"{count:,}", attack_str)

    return table


# ============================================================================
# TERMINAL HYPERLINKS
# ============================================================================

def make_file_link(path: str) -> str:
    """
    Create a Rich markup string with a clickable file:// hyperlink.

    Works in terminals supporting OSC 8 hyperlinks (iTerm2, Windows Terminal,
    modern GNOME/KDE terminals). Falls back to plain text in others.

    Args:
        path: File path (relative or absolute)

    Returns:
        Rich markup string with clickable link
    """
    try:
        abs_path = Path(path).resolve()
        uri = abs_path.as_uri()
        return f"[link={uri}][cyan]{path}[/][/link]"
    except (ValueError, OSError):
        return f"[cyan]{path}[/]"


