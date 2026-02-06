from __future__ import annotations

from dataclasses import dataclass

from .base import TransportInterface


@dataclass(frozen=True)
class EbusdTcpConfig:
    host: str = "127.0.0.1"
    port: int = 8888


class EbusdTcpTransport(TransportInterface):
    """TCP transport against an ebusd daemon.

    Implementation is intentionally deferred to a follow-up issue.
    """

    def __init__(self, config: EbusdTcpConfig) -> None:
        self._config = config

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        raise NotImplementedError("EbusdTcpTransport is not implemented yet")
