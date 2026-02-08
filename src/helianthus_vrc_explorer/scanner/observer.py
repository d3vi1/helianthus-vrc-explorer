from __future__ import annotations

from typing import Protocol


class ScanObserver(Protocol):
    """Observer for scan progress and user-facing logs.

    Scanner code uses this interface to drive a UI (Rich) or plain text output.
    Implementations must be fast and must not raise.
    """

    def phase_start(self, phase: str, *, total: int) -> None:
        """Start (or reset) a phase progress bar."""

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:
        """Advance a phase progress bar."""

    def phase_set_total(self, phase: str, *, total: int) -> None:
        """Update a phase total."""

    def phase_finish(self, phase: str) -> None:
        """Mark a phase as complete."""

    def status(self, message: str) -> None:
        """Update the current operation status line."""

    def log(self, message: str, *, level: str = "info") -> None:
        """Emit a scrollable log line (info/warn/error)."""
