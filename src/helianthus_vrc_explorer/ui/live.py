from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime

from rich.console import Console, Group
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.text import Text

from ..scanner.observer import ScanObserver

_PHASE_LABELS: dict[str, str] = {
    "group_discovery": "Group Discovery",
    "instance_discovery": "Instance Discovery",
    "register_scan": "Register Scan",
}


def _now_ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _styled(level: str) -> str:
    if level == "warn":
        return "yellow"
    if level == "error":
        return "red"
    return "white"


@dataclass(slots=True)
class _Task:
    id: int
    phase: str


class NullScanObserver(AbstractContextManager["NullScanObserver"], ScanObserver):
    def __enter__(self) -> NullScanObserver:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def phase_start(self, phase: str, *, total: int) -> None:  # noqa: ARG002
        return None

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:  # noqa: ARG002
        return None

    def phase_set_total(self, phase: str, *, total: int) -> None:  # noqa: ARG002
        return None

    def phase_finish(self, phase: str) -> None:  # noqa: ARG002
        return None

    def status(self, message: str) -> None:  # noqa: ARG002
        return None

    def log(self, message: str, *, level: str = "info") -> None:  # noqa: ARG002
        return None


class RichScanObserver(AbstractContextManager["RichScanObserver"], ScanObserver):
    """Rich-based observer used for interactive scans (TTY)."""

    def __init__(self, *, console: Console, title: str) -> None:
        self._console = console
        self._title = title
        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("{task.fields[status]}", style="dim"),
            console=console,
            transient=True,
            expand=True,
            refresh_per_second=10,
        )
        self._tasks: dict[str, _Task] = {}
        self._current_phase: str | None = None

    def __enter__(self) -> RichScanObserver:
        self._progress.start()
        header = Group(
            Rule(self._title, style="dim"),
            Text(
                "Tip: set `--trace-file` to capture ebusd request/response exchanges.",
                style="dim",
            ),
        )
        self._progress.console.print(header)
        return self

    def __exit__(self, *_exc: object) -> None:
        self._progress.stop()
        return None

    def phase_start(self, phase: str, *, total: int) -> None:
        label = _PHASE_LABELS.get(phase, phase)
        if phase in self._tasks:
            task = self._tasks[phase]
            self._progress.update(task.id, description=label, completed=0, total=total, status="")
        else:
            task_id = self._progress.add_task(label, total=total, status="")
            self._tasks[phase] = _Task(id=task_id, phase=phase)
        self._current_phase = phase

        # Clear other phase status fields so only one "current operation" line shows.
        for other_phase, task in self._tasks.items():
            if other_phase != phase:
                self._progress.update(task.id, status="")

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:
        task = self._tasks.get(phase)
        if task is None:
            return
        self._current_phase = phase
        self._progress.advance(task.id, advance)

    def phase_set_total(self, phase: str, *, total: int) -> None:
        task = self._tasks.get(phase)
        if task is None:
            return
        self._progress.update(task.id, total=total)

    def phase_finish(self, phase: str) -> None:
        task = self._tasks.get(phase)
        if task is None:
            return
        total = self._progress.tasks[task.id].total
        if total is not None:
            self._progress.update(task.id, completed=total)
        self._progress.update(task.id, status="")

    def status(self, message: str) -> None:
        if self._current_phase is None:
            return
        task = self._tasks.get(self._current_phase)
        if task is None:
            return
        self._progress.update(task.id, status=message)

    def log(self, message: str, *, level: str = "info") -> None:
        ts = _now_ts()
        style = _styled(level)
        self._progress.console.print(f"[dim]{ts}[/dim] [{style}]{message}[/{style}]")


def make_scan_observer(*, console: Console, title: str) -> AbstractContextManager[ScanObserver]:
    if console.is_terminal:
        return RichScanObserver(console=console, title=title)
    return NullScanObserver()
