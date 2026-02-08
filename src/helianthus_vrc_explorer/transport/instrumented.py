from __future__ import annotations

from dataclasses import dataclass

from .base import TransportInterface


@dataclass(slots=True)
class TransportCounters:
    send_calls: int = 0


class CountingTransport(TransportInterface):
    """Transport wrapper that counts `send()` calls.

    Useful for request/second estimates and scan planning.
    """

    def __init__(self, inner: TransportInterface) -> None:
        self._inner = inner
        self.counters = TransportCounters()

    def send(self, dst: int, payload: bytes) -> bytes:
        self.counters.send_calls += 1
        return self._inner.send(dst, payload)

    def trace_label(self, label: str) -> None:
        fn = getattr(self._inner, "trace_label", None)
        if callable(fn):
            fn(label)
