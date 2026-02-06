from __future__ import annotations

from abc import ABC, abstractmethod


class TransportError(Exception):
    """Base class for transport-layer errors."""


class TransportTimeout(TransportError):
    """Raised when a transport request times out."""


class TransportInterface(ABC):
    """Transport interface for sending B524 payloads and receiving raw responses."""

    @abstractmethod
    def send(self, dst: int, payload: bytes) -> bytes:
        """Send a request and return the raw response payload.

        Args:
            dst: Destination address (0x00..0xFF).
            payload: Raw B524 payload bytes (without ebus framing).
        """
