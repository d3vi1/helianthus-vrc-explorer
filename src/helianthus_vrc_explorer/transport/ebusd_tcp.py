from __future__ import annotations

import contextlib
import socket
import string
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from .base import TransportError, TransportInterface, TransportTimeout


@dataclass(frozen=True)
class EbusdTcpConfig:
    host: str = "127.0.0.1"
    port: int = 8888
    timeout_s: float = 5.0
    src: int | None = None
    trace_path: Path | None = None


_PRIMARY_VAILLANT: Final[int] = 0xB5
_SECONDARY_EXTENDED_REGISTER: Final[int] = 0x24
_EBUSD_COMMAND_TERMINATOR: Final[bytes] = b"\n"
_HEX_CHARS: Final[set[str]] = set(string.hexdigits)
_TIMEOUT_RETRY_DELAY_S: Final[float] = 1.0
_POST_RESPONSE_DRAIN_TIMEOUT_S: Final[float] = 0.01
_RETRYABLE_TRANSPORT_ERROR_SUBSTRINGS: Final[tuple[str, ...]] = (
    "syn received",
    "wrong symbol received",
)


def _is_retryable_transport_error(exc: TransportError) -> bool:
    return any(token in str(exc).lower() for token in _RETRYABLE_TRANSPORT_ERROR_SUBSTRINGS)


def _utc_ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _short_hex(blob: bytes, max_bytes: int = 48) -> str:
    hx = blob.hex()
    if len(blob) > max_bytes:
        return hx[: max_bytes * 2] + "..."
    return hx


def _maybe_strip_length_prefix(payload: bytes) -> bytes:
    """Strip ebusd's leading length byte when using the `hex` command.

    In daemon TCP mode, `hex` returns the response data prefixed with a single
    byte indicating the remaining payload length. Higher-level B524 parsing in
    this project expects only the raw response payload bytes.
    """

    # ebusd uses a 1-byte length prefix for `hex` responses. While most B524 replies
    # are >=4 bytes, some error/status replies are shorter; accept those too.
    if len(payload) >= 2 and payload[0] == len(payload) - 1:
        return payload[1:]
    return payload


def _parse_ebusd_response_lines(lines: Sequence[str]) -> bytes:
    """Parse ebusd TCP response lines and return the first hex payload line as bytes.

    ebusd responses are typically terminated with an empty line. Some versions emit
    additional trailing error lines after a valid payload line; these must be ignored.

    Args:
        lines: Response lines (without newline terminators).

    Returns:
        Raw payload bytes parsed from the first hex line.

    Raises:
        TransportTimeout: If the first non-empty line is an ERR timeout.
        TransportError: If the response cannot be parsed.
    """

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        if line.lower().startswith("err"):
            lowered = line.lower()
            if "timeout" in lowered or "timed out" in lowered or "no answer" in lowered:
                raise TransportTimeout(line)
            raise TransportError(line)

        # Accept "0x..." and/or whitespace separated hex.
        if line.lower().startswith("0x"):
            line = line[2:].strip()
        normalized = "".join(line.split())

        if not normalized:
            continue
        if any(ch not in _HEX_CHARS for ch in normalized):
            raise TransportError(f"Unexpected ebusd response line: {raw_line!r}")
        if len(normalized) % 2:
            raise TransportError(f"Odd-length hex payload in ebusd response: {raw_line!r}")

        try:
            return bytes.fromhex(normalized)
        except ValueError as exc:  # pragma: no cover - guarded above, but keep defensive.
            raise TransportError(f"Invalid hex payload in ebusd response: {raw_line!r}") from exc

    raise TransportError("Empty ebusd response")


def _validate_u8(field_name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an int, got {type(value).__name__}")
    if not (0x00 <= value <= 0xFF):
        raise ValueError(f"{field_name} must be in range 0..255, got {value}")


def _build_hex_command(config: EbusdTcpConfig, dst: int, payload: bytes) -> bytes:
    _validate_u8("dst", dst)
    if config.src is not None:
        _validate_u8("src", config.src)
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError(f"payload must be bytes-like, got {type(payload).__name__}")
    if len(payload) > 0xFF:
        raise ValueError(f"payload too large for ebusd hex command: {len(payload)} bytes")

    # ebusd expects hex without CRC, but *with* the data length byte.
    # See `ebusd_rawscan.py` in the parent repo for the same framing.
    payload_len = len(payload)
    payload_hex = payload.hex().upper()
    hex_text = (
        f"{dst:02X}{_PRIMARY_VAILLANT:02X}{_SECONDARY_EXTENDED_REGISTER:02X}"
        f"{payload_len:02X}{payload_hex}"
    )
    cmd = f"hex {hex_text}" if config.src is None else f"hex -s {config.src:02X} {hex_text}"
    return cmd.encode("ascii") + _EBUSD_COMMAND_TERMINATOR


class EbusdTcpTransport(TransportInterface):
    """TCP transport against an ebusd daemon."""

    def __init__(self, config: EbusdTcpConfig) -> None:
        self._config = config
        self._trace_seq = 0

    def _trace(self, message: str) -> None:
        trace_path = self._config.trace_path
        if trace_path is None:
            return
        # Best-effort tracing: never let trace failures break a scan.
        with contextlib.suppress(OSError):
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            with trace_path.open("a", encoding="utf-8") as f:
                f.write(f"{_utc_ts()} {message}\n")

    def send(self, dst: int, payload: bytes) -> bytes:
        self._trace_seq += 1
        seq = self._trace_seq
        last_timeout: TransportTimeout | None = None
        last_retryable_error: TransportError | None = None
        for attempt in range(2):
            try:
                return self._send_once(seq, dst, payload)
            except TransportTimeout as exc:
                last_timeout = exc
                if attempt == 0:
                    time.sleep(_TIMEOUT_RETRY_DELAY_S)
                    continue
                raise
            except TransportError as exc:
                if attempt == 0 and _is_retryable_transport_error(exc):
                    last_retryable_error = exc
                    time.sleep(_TIMEOUT_RETRY_DELAY_S)
                    continue
                raise
        # Defensive: loop returns or raises.
        if last_timeout is not None:
            raise last_timeout
        assert last_retryable_error is not None
        raise last_retryable_error

    def _send_once(self, seq: int, dst: int, payload: bytes) -> bytes:
        cmd = _build_hex_command(self._config, dst, payload)
        cmd_txt = cmd.decode("ascii", errors="replace").rstrip("\r\n")
        self._trace(f"#{seq} SEND attempt_payload={_short_hex(payload)} cmd={cmd_txt}")
        addr = (self._config.host, self._config.port)

        try:
            with socket.create_connection(addr, timeout=self._config.timeout_s) as sock:
                sock.settimeout(self._config.timeout_s)
                with sock.makefile("rwb") as sock_file:
                    sock_file.write(cmd)
                    sock_file.flush()

                    lines: list[str] = []
                    # ebusd typically terminates responses with a blank line. Some versions keep
                    # the socket open after sending a single payload/ERR line; do not block on
                    # waiting for the terminator after we've received a non-empty line.
                    while True:
                        raw = sock_file.readline()
                        if not raw:
                            break
                        text = raw.decode("ascii", errors="replace").rstrip("\r\n")
                        if text == "":
                            break
                        if text.strip() == "":
                            continue
                        lines.append(text)
                        break

                    if lines:
                        # Best-effort: drain any trailing lines (e.g. spurious ERR lines) using a
                        # short timeout. A drain timeout must not be treated as a request timeout.
                        prev_timeout = sock.gettimeout()
                        drain_timeout = _POST_RESPONSE_DRAIN_TIMEOUT_S
                        if prev_timeout is not None:
                            drain_timeout = min(prev_timeout, drain_timeout)
                        sock.settimeout(drain_timeout)
                        try:
                            while True:
                                try:
                                    raw = sock_file.readline()
                                except TimeoutError:
                                    break
                                if not raw:
                                    break
                                text = raw.decode("ascii", errors="replace").rstrip("\r\n")
                                if text == "":
                                    break
                                if text.strip() == "":
                                    continue
                                lines.append(text)
                        finally:
                            sock.settimeout(prev_timeout)
        except TimeoutError as exc:
            # This catches socket read timeouts too: `socket.timeout` is an alias of
            # builtin `TimeoutError` on Python 3.12+ (including `sock.makefile().readline()`).
            raise TransportTimeout(
                f"Timed out talking to ebusd at {self._config.host}:{self._config.port}"
            ) from exc
        except OSError as exc:
            raise TransportError(
                f"Failed talking to ebusd at {self._config.host}:{self._config.port}: {exc}"
            ) from exc

        self._trace(f"#{seq} RECV lines={lines!r}")
        parsed = _parse_ebusd_response_lines(lines)
        self._trace(f"#{seq} PARSED len={len(parsed)} hex={_short_hex(parsed)}")
        stripped = _maybe_strip_length_prefix(parsed)
        if stripped != parsed:
            self._trace(f"#{seq} STRIP in={_short_hex(parsed)} out={_short_hex(stripped)}")
        return stripped
