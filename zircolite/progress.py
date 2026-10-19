"""Progress of the steps a working database goes through, and where it shows.

A step reports ``(phase, done, total)``, with ``total`` 0 while its size is
unknown. In the main process a ``Steps`` line shows it; a parallel worker
writes it into its slot of a ``WorkerBoard``, which the main process reads to
draw one row per worker. A board slot is a few integers, so process workers
share the board through shared memory instead of sending messages.
"""

from collections.abc import MutableSequence, Sequence
from typing import Any, Protocol, Self

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    Task,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Column
from rich.text import Text

from .console import console, is_quiet, literal

PHASE_LABELS = {
    "reading": "Reading events",
    "indexing": "Building indexes",
    "saving": "Saving the database",
    "loading": "Loading the database",
    "package": "Spooling events for the package",
    "prefilter": "Building the literal index",
    "rules": "Executing rules",
}
# The same steps in a worker's row, where the file name says the rest.
_ROW_LABELS = {
    "reading": "reading", "indexing": "indexing", "saving": "saving", "loading": "loading",
    "package": "package spool", "prefilter": "literal index", "rules": "rules",
}
_ROW_LABEL_WIDTH = max(map(len, _ROW_LABELS.values()))
# Board codes: 0 is a free slot or a worker between steps.
PHASES = ("", *PHASE_LABELS)
_CODES = {phase: code for code, phase in enumerate(PHASES)}
_FIELDS = 5  # file index + 1 (0 when idle), phase code, done, total, events


class Reporter(Protocol):
    def __call__(self, phase: str, done: int = 0, total: int = 0, *,
                 events: int | None = None, item: str | None = None) -> None: ...

    def clear(self) -> None: ...


class _Remaining(TimeRemainingColumn):
    """Nothing, rather than ``-:--:--``, until there is an estimate."""

    def render(self, task: Task) -> Text:
        return Text("") if task.total is None or task.time_remaining is None else super().render(task)


def _unknown_size(progress: Progress, task_id: Any) -> None:
    """Make a task's size unknown again, which ``update`` and ``reset`` cannot."""
    for task in progress.tasks:
        if task.id == task_id:
            task.total = None


def _update(progress: Progress, task_id: Any, total: int, **values: Any) -> None:
    """``Progress.update``, with ``total`` 0 for a size unknown again."""
    if total:
        progress.update(task_id, total=total, **values)
        return
    _unknown_size(progress, task_id)
    progress.update(task_id, **values)


def step_progress(*, disable: bool = False) -> Progress:
    """A transient progress line for one step at a time: a bar and an estimate once its size is known."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn("{task.fields[detail]}"),
        TimeElapsedColumn(),
        _Remaining(),
        console=console,
        transient=True,
        disable=disable,
    )


class Steps:
    """The main process's progress line, shown while a step runs.

    The line is started on the first report and stopped by ``clear``, which
    the rule loop calls before drawing its own display; log lines print above
    it meanwhile. A new step restarts the clock; a new item in the same step,
    the next file of a unified run, only renames it.
    """

    def __init__(self, *, disable: bool | None = None) -> None:
        self.disable = is_quiet() if disable is None else disable
        self._progress: Progress | None = None
        self._task: Any = None
        self._phase = ""

    def __call__(self, phase: str, done: int = 0, total: int = 0, *,
                 events: int | None = None, item: str | None = None) -> None:
        if self.disable:
            return
        description = PHASE_LABELS.get(phase, phase) + (f" [cyan]{literal(item)}[/]" if item else "")
        detail = "" if events is None else f"[magenta]{events:,}[/] events"
        if self._progress is None:
            self._progress = step_progress()
            self._progress.start()
            self._task = self._progress.add_task(description, total=total or None, completed=done, detail=detail)
        elif phase != self._phase:
            # A new step: its own clock and estimate. reset() redraws at once,
            # so an unknown size has to be set before it.
            if not total:
                _unknown_size(self._progress, self._task)
            self._progress.reset(self._task, total=total or None, completed=done, description=description,
                                 detail=detail)
        else:
            _update(self._progress, self._task, total, completed=done, description=description, detail=detail)
        self._phase = phase

    def clear(self) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None
            self._phase = ""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.clear()


class WorkerBoard:
    """One slot of plain integers per worker, which the main process reads to show them.

    ``shared`` puts the slots in shared memory for process workers; it must
    reach them when they start, through the pool's initializer arguments.
    Reads are not locked: a row drawn from two half-updated values is put
    right by the next refresh.
    """

    def __init__(self, slots: int, values: MutableSequence[int] | None = None) -> None:
        self.slots = max(1, slots)
        self.values: MutableSequence[int] = values if values is not None else [0] * (self.slots * _FIELDS)

    @classmethod
    def shared(cls, slots: int, context: Any) -> "WorkerBoard":
        return cls(slots, context.RawArray("q", max(1, slots) * _FIELDS))

    def slot(self, worker: int, file_index: int) -> "BoardSlot":
        return BoardSlot(self.values, (worker % self.slots) * _FIELDS, file_index)

    def rows(self) -> list[tuple[int, str, int, int, int]]:
        """``(file index, phase, done, total, events)`` of every busy slot."""
        values = list(self.values)
        rows = []
        for base in range(0, len(values), _FIELDS):
            file, code, done, total, events = values[base:base + _FIELDS]
            if file:
                rows.append((file - 1, PHASES[code] if 0 <= code < len(PHASES) else "", done, total, events))
        return rows


class BoardSlot:
    """A worker's slot on the board: a ``Reporter`` for the file it is working on."""

    def __init__(self, values: MutableSequence[int], base: int, file_index: int) -> None:
        self.values = values
        self.base = base
        for offset in range(1, _FIELDS):
            values[base + offset] = 0
        values[base] = file_index + 1

    def __call__(self, phase: str, done: int = 0, total: int = 0, *,
                 events: int | None = None, item: str | None = None) -> None:
        values, base = self.values, self.base
        values[base + 1] = _CODES.get(phase, 0)
        values[base + 2] = done
        values[base + 3] = total
        if events is not None:
            values[base + 4] = events

    def clear(self) -> None:
        """Rules follow on the same slot, so there is nothing to take down."""

    def release(self) -> None:
        self.values[self.base] = 0


def worker_progress(*, name_width: int = 20, disable: bool = False) -> Progress:
    """One row per busy worker: its file, its step, and how far the step is.

    Fixed widths keep the bars in place as rows come, go and change step.
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}", table_column=Column(width=name_width, no_wrap=True)),
        TextColumn("[cyan]{task.fields[phase]}[/]", table_column=Column(width=_ROW_LABEL_WIDTH, no_wrap=True)),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TextColumn("{task.fields[detail]}"),
        console=console,
        transient=True,
        disable=disable,
    )


def show_board(progress: Progress, tasks: dict[int, Any], board: WorkerBoard, names: Sequence[str],
               finished: set[int]) -> int:
    """Draw the board's busy slots as rows of ``progress``; returns the events they have read so far.

    ``tasks`` keeps a row per file between calls. A file the main process has
    already counted as finished is skipped, so its events are not counted twice.
    """
    busy: dict[int, tuple[str, int, int, int]] = {}
    for file, phase, done, total, events in board.rows():
        if file not in finished and 0 <= file < len(names):
            busy[file] = (phase, done, total, events)
    for file in [file for file in tasks if file not in busy]:
        progress.remove_task(tasks.pop(file))
    live = 0
    for file, (phase, done, total, events) in busy.items():
        label = _ROW_LABELS.get(phase, "starting")
        detail = f"[magenta]{events:,}[/] events" if events else ""
        if phase == "rules" and total:
            detail = f"{done:,}/{total:,} rules"
        if file not in tasks:
            tasks[file] = progress.add_task(names[file], total=total or None, completed=done, phase=label,
                                            detail=detail)
        else:
            _update(progress, tasks[file], total, completed=done, phase=label, detail=detail)
        live += events
    return live
