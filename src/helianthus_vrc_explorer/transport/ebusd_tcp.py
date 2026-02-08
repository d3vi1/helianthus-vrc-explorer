from __future__ import annotations

import contextlib
import io
import socket
import string
import time
from collections.abc import Iterator, Sequence
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
_NO_SIGNAL_RETRY_DELAY_S: Final[float] = 10.0
_POST_RESPONSE_DRAIN_TIMEOUT_S: Final[float] = 0.01
_RETRYABLE_TRANSPORT_ERROR_SUBSTRINGS: Final[tuple[str, ...]] = (
    "syn received",
    "wrong symbol received",
)


def _is_retryable_transport_error(exc: TransportError) -> bool:
    return any(token in str(exc).lower() for token in _RETRYABLE_TRANSPORT_ERROR_SUBSTRINGS)


def _is_no_signal_error(exc: TransportError) -> bool:
    return "no signal" in str(exc).lower()


def _is_connection_level_timeout(exc: TransportTimeout) -> bool:
    return not str(exc).lower().startswith("err:")


def _is_connection_level_error(exc: TransportError) -> bool:
    lowered = str(exc).lower()
    return lowered.startswith("failed talking to ebusd") or lowered == "empty ebusd response"


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


def _parse_ebusd_info_lines(lines: Sequence[str]) -> None:
    """Parse ebusd `info` response lines.

    For health checks we only care whether ebusd returns an `ERR:` line. Any non-ERR
    payload is treated as success.
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
        return
    raise TransportError("Empty ebusd response")


def _validate_u8(field_name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an int, got {type(value).__name__}")
    if not (0x00 <= value <= 0xFF):
        raise ValueError(f"{field_name} must be in range 0..255, got {value}")


def _build_hex_command(config: EbusdTcpConfig, dst: int, payload: bytes) -> bytes:
    return _build_hex_command_custom(
        config,
        dst,
        _PRIMARY_VAILLANT,
        _SECONDARY_EXTENDED_REGISTER,
        payload,
    )


def _build_hex_command_custom(
    config: EbusdTcpConfig,
    dst: int,
    primary: int,
    secondary: int,
    payload: bytes,
) -> bytes:
    _validate_u8("dst", dst)
    _validate_u8("primary", primary)
    _validate_u8("secondary", secondary)
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
    hex_text = f"{dst:02X}{primary:02X}{secondary:02X}{payload_len:02X}{payload_hex}"
    cmd = f"hex {hex_text}" if config.src is None else f"hex -s {config.src:02X} {hex_text}"
    return cmd.encode("ascii") + _EBUSD_COMMAND_TERMINATOR


def _build_info_command() -> bytes:
    # `info` is a lightweight health/status command on the ebusd command port.
    return b"info" + _EBUSD_COMMAND_TERMINATOR


@dataclass(slots=True)
class _EbusdTcpSession:
    sock: socket.socket
    sock_file: io.BufferedRWPair


class EbusdTcpTransport(TransportInterface):
    """TCP transport against an ebusd daemon."""

    def __init__(self, config: EbusdTcpConfig) -> None:
        self._config = config
        self._trace_seq = 0
        self._session_depth = 0
        self._session: _EbusdTcpSession | None = None

    def _trace(self, message: str) -> None:
        trace_path = self._config.trace_path
        if trace_path is None:
            return
        # Best-effort tracing: never let trace failures break a scan.
        with contextlib.suppress(OSError):
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            with trace_path.open("a", encoding="utf-8") as f:
                f.write(f"{_utc_ts()} {message}\n")

    def trace_label(self, label: str) -> None:
        """Emit a human-readable label into the trace log (if enabled)."""

        if not isinstance(label, str):
            raise TypeError(f"label must be a str, got {type(label).__name__}")
        label_txt = label.strip()
        if not label_txt:
            return
        self._trace(f"OP {label_txt}")

    def close(self) -> None:
        session = self._session
        if session is None:
            return
        self._session = None
        with contextlib.suppress(OSError):
            session.sock_file.close()
        with contextlib.suppress(OSError):
            session.sock.close()

    @contextlib.contextmanager
    def session(self) -> Iterator[EbusdTcpTransport]:
        """Enable a persistent TCP session for the duration of this context."""

        self._session_depth += 1
        if self._session_depth == 1:
            self._open_session()
        try:
            yield self
        finally:
            self._session_depth -= 1
            if self._session_depth <= 0:
                self._session_depth = 0
                self.close()

    def _open_session(self) -> None:
        addr = (self._config.host, self._config.port)
        try:
            sock = socket.create_connection(addr, timeout=self._config.timeout_s)
            sock.settimeout(self._config.timeout_s)
            sock_file = sock.makefile("rwb")
            self._session = _EbusdTcpSession(sock=sock, sock_file=sock_file)
        except TimeoutError as exc:
            raise TransportTimeout(
                f"Timed out talking to ebusd at {self._config.host}:{self._config.port}"
            ) from exc
        except OSError as exc:
            raise TransportError(
                f"Failed talking to ebusd at {self._config.host}:{self._config.port}: {exc}"
            ) from exc

    def _ensure_session(self) -> _EbusdTcpSession:
        session = self._session
        if session is not None:
            return session
        self._open_session()
        session = self._session
        assert session is not None
        return session

    def send(self, dst: int, payload: bytes) -> bytes:
        self._trace_seq += 1
        seq = self._trace_seq
        last_timeout: TransportTimeout | None = None
        last_retryable_error: TransportError | None = None
        recovered_no_signal = False
        for attempt in range(2):
            try:
                return self._send_once(seq, dst, payload)
            except TransportTimeout as exc:
                last_timeout = exc
                if attempt == 0:
                    if self._session_depth > 0 and _is_connection_level_timeout(exc):
                        # Connection-level timeouts should reconnect in session mode.
                        self.close()
                    time.sleep(_TIMEOUT_RETRY_DELAY_S)
                    continue
                raise
            except TransportError as exc:
                if attempt == 0 and self._session_depth > 0 and _is_connection_level_error(exc):
                    # Connection-level failures should reconnect in session mode.
                    self.close()
                    time.sleep(_TIMEOUT_RETRY_DELAY_S)
                    continue
                if attempt == 0 and (not recovered_no_signal) and _is_no_signal_error(exc):
                    recovered_no_signal = True
                    self._trace(f"#{seq} RECOVER no_signal sleep_s={_NO_SIGNAL_RETRY_DELAY_S}")
                    time.sleep(_NO_SIGNAL_RETRY_DELAY_S)
                    # Best-effort health check: if `info` still returns "no signal", surface
                    # the problem instead of retrying forever.
                    try:
                        self._send_info_once(seq)
                    except TransportError as info_exc:
                        if _is_no_signal_error(info_exc):
                            raise TransportError(
                                "ERR: no signal (still missing after wait+info check)"
                            ) from exc
                        # Other transport errors from `info` are treated as non-fatal; continue to
                        # retry the last payload once.
                    except TransportTimeout:
                        # `info` timing out is not a definitive signal status; retry last payload
                        # once.
                        pass
                    continue
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

    def _send_info_once(self, seq: int) -> None:
        cmd = _build_info_command()
        cmd_txt = cmd.decode("ascii", errors="replace").rstrip("\r\n")
        self._trace(f"#{seq} INFO cmd={cmd_txt}")
        lines = self._send_command_lines(cmd, read_all=False)
        self._trace(f"#{seq} INFO_RECV lines={lines!r}")
        _parse_ebusd_info_lines(lines)

    def _send_once(self, seq: int, dst: int, payload: bytes) -> bytes:
        cmd = _build_hex_command(self._config, dst, payload)
        cmd_txt = cmd.decode("ascii", errors="replace").rstrip("\r\n")
        self._trace(f"#{seq} SEND attempt_payload={_short_hex(payload)} cmd={cmd_txt}")

        lines = self._send_command_lines(cmd, read_all=False)
        self._trace(f"#{seq} RECV lines={lines!r}")
        parsed = _parse_ebusd_response_lines(lines)
        self._trace(f"#{seq} PARSED len={len(parsed)} hex={_short_hex(parsed)}")
        stripped = _maybe_strip_length_prefix(parsed)
        if stripped != parsed:
            self._trace(f"#{seq} STRIP in={_short_hex(parsed)} out={_short_hex(stripped)}")
        return stripped

    @staticmethod
    def _read_command_response_lines(
        sock: socket.socket,
        sock_file: io.BufferedRWPair,
    ) -> list[str]:
        lines: list[str] = []
        # ebusd typically terminates responses with a blank line. Some versions keep the socket
        # open after sending a single payload/ERR line; do not block on waiting for the terminator
        # after we've received a non-empty line.
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
            # Best-effort: drain any trailing lines (e.g. spurious ERR lines) using a short timeout.
            # A drain timeout must not be treated as a request timeout.
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

        return lines

    @staticmethod
    def _read_command_response_lines_all(
        _sock: socket.socket,
        sock_file: io.BufferedRWPair,
    ) -> list[str]:
        lines: list[str] = []
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
        return lines

    def _send_command_lines(self, cmd: bytes, *, read_all: bool) -> list[str]:
        addr = (self._config.host, self._config.port)
        reader = (
            self._read_command_response_lines_all if read_all else self._read_command_response_lines
        )

        try:
            if self._session_depth > 0:
                session = self._ensure_session()
                session.sock_file.write(cmd)
                session.sock_file.flush()
                return reader(session.sock, session.sock_file)

            with socket.create_connection(addr, timeout=self._config.timeout_s) as sock:
                sock.settimeout(self._config.timeout_s)
                with sock.makefile("rwb") as sock_file:
                    sock_file.write(cmd)
                    sock_file.flush()
                    return reader(sock, sock_file)
        except TimeoutError as exc:
            # This catches socket read timeouts too: `socket.timeout` is an alias of
            # builtin `TimeoutError` on Python 3.12+ (including `sock.makefile().readline()`).
            if self._session_depth > 0:
                self.close()
            raise TransportTimeout(
                f"Timed out talking to ebusd at {self._config.host}:{self._config.port}"
            ) from exc
        except OSError as exc:
            if self._session_depth > 0:
                self.close()
            raise TransportError(
                f"Failed talking to ebusd at {self._config.host}:{self._config.port}: {exc}"
            ) from exc

    def command_lines(self, command: str, *, read_all: bool = False) -> list[str]:
        """Run an arbitrary ebusd command and return response lines."""

        if not isinstance(command, str):
            raise TypeError(f"command must be a str, got {type(command).__name__}")
        cmd = command.encode("ascii", errors="strict") + _EBUSD_COMMAND_TERMINATOR
        return self._send_command_lines(cmd, read_all=read_all)

    def send_proto(
        self,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        *,
        expect_response: bool = True,
    ) -> bytes:
        """Send an ebusd `hex` telegram with arbitrary protocol bytes.

        This supports BASV/broadcast flows (07FE/0704/B509) without changing the
        `TransportInterface.send()` contract, which is B524-focused.
        """

        self._trace_seq += 1
        seq = self._trace_seq
        cmd = _build_hex_command_custom(self._config, dst, primary, secondary, payload)
        cmd_txt = cmd.decode("ascii", errors="replace").rstrip("\r\n")
        self._trace(
            f"#{seq} SEND_PROTO primary=0x{primary:02X} secondary=0x{secondary:02X} "
            f"payload={_short_hex(payload)} cmd={cmd_txt}"
        )

        lines = self._send_command_lines(cmd, read_all=False)
        self._trace(f"#{seq} RECV_PROTO lines={lines!r}")

        if not expect_response:
            # For broadcast messages, ebusd typically replies with a textual status
            # like "done broadcast". Treat it as success; callers may separately
            # read bus activity via other mechanisms if needed.
            return b""

        parsed = _parse_ebusd_response_lines(lines)
        self._trace(f"#{seq} PARSED_PROTO len={len(parsed)} hex={_short_hex(parsed)}")
        stripped = _maybe_strip_length_prefix(parsed)
        if stripped != parsed:
            self._trace(f"#{seq} STRIP_PROTO in={_short_hex(parsed)} out={_short_hex(stripped)}")
        return stripped
