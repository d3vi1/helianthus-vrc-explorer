from __future__ import annotations

from pathlib import Path

from .base import TransportInterface


class DummyTransport(TransportInterface):
    """Fixture-backed transport used for --dry-run.

    This is intentionally a stub in bootstrap. Follow-up issues will define
    the fixture format and behavior.
    """

    def __init__(self, fixture_path: Path) -> None:
        self._fixture_path = fixture_path

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        raise NotImplementedError("DummyTransport is not implemented yet")
