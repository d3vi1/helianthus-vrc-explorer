from __future__ import annotations

import socketserver
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from queue import Queue

import pytest

from helianthus_vrc_explorer.transport.base import TransportTimeout
from helianthus_vrc_explorer.transport.ebusd_tcp import (
    EbusdTcpConfig,
    EbusdTcpTransport,
    _parse_ebusd_response_lines,
)


@dataclass(frozen=True)
class _EbusdTestServerResponse:
    lines: list[str]
    send_terminator: bool = True
    keep_open: bool = False


@contextmanager
def _run_ebusd_test_server(
    responses: list[list[str] | None | _EbusdTestServerResponse],
) -> Iterator[tuple[str, int, list[str]]]:
    """Run a local TCP server that mimics ebusd's command port framing.

    Each connection consumes one entry from `responses`:
    - `list[str]`: response lines (without terminators). A blank line terminator is added.
    - `_EbusdTestServerResponse`: response lines with configurable framing/connection behavior.
    - `None`: accept the command but keep the socket open without responding
      (useful for socket-timeout tests).
    """

    commands: list[str] = []
    queue: Queue[list[str] | None | _EbusdTestServerResponse] = Queue()
    for response in responses:
        queue.put(response)

    stop_event = threading.Event()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:  # noqa: D401 - socketserver signature
            cmd = self.rfile.readline().decode("ascii", errors="replace").rstrip("\r\n")
            commands.append(cmd)

            response = queue.get_nowait()
            if response is None:
                # Keep connection open without responding so the client hits its socket timeout.
                stop_event.wait(timeout=5)
                return

            keep_open = False
            send_terminator = True
            lines = response
            if isinstance(response, _EbusdTestServerResponse):
                keep_open = response.keep_open
                send_terminator = response.send_terminator
                lines = response.lines

            for line in lines:
                self.wfile.write(line.encode("ascii") + b"\n")
            if send_terminator:
                self.wfile.write(b"\n")
            self.wfile.flush()
            if keep_open:
                stop_event.wait(timeout=5)

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        assert isinstance(host, str)
        assert isinstance(port, int)
        yield host, port, commands
    finally:
        stop_event.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_parse_ebusd_response_lines_returns_first_hex_payload_line() -> None:
    lines = [
        "010203",
        "ERR: some trailing noise",
    ]
    assert _parse_ebusd_response_lines(lines) == bytes.fromhex("010203")


@pytest.mark.parametrize("line", ["ERR: timeout", "ERR: timed out", "ERR: no answer"])
def test_parse_ebusd_response_lines_timeout_errors_raise_transport_timeout(line: str) -> None:
    with pytest.raises(TransportTimeout, match=r"ERR:"):
        _parse_ebusd_response_lines([line])


def test_transport_send_parses_multiline_response_and_ignores_trailing_err() -> None:
    with _run_ebusd_test_server([["010203", "ERR: timeout"]]) as (host, port, commands):
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["read -h 15B52406020002000F00"]


def test_transport_send_retries_timeout_once_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    with _run_ebusd_test_server([["ERR: timeout"], ["010203"]]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["read -h 15B52406020002000F00", "read -h 15B52406020002000F00"]
    assert sleep_calls == [1.0]


def test_transport_send_retries_timeout_once_then_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    with _run_ebusd_test_server([["ERR: timeout"], ["ERR: timeout"]]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("020002000F00")
        with pytest.raises(TransportTimeout):
            transport.send(0x15, payload)

    assert commands == ["read -h 15B52406020002000F00", "read -h 15B52406020002000F00"]
    assert sleep_calls == [1.0]


def test_transport_send_retries_socket_timeout_once_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _run_ebusd_test_server([None, ["010203"]]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.05))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["read -h 15B52406020002000F00", "read -h 15B52406020002000F00"]
    assert sleep_calls == [1.0]


def test_transport_send_does_not_timeout_if_ebusd_keeps_socket_open_after_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

    monkeypatch.setattr(ebusd_tcp.time, "sleep", lambda _seconds: None)
    response = _EbusdTestServerResponse(
        lines=["010203"],
        send_terminator=False,
        keep_open=True,
    )
    with _run_ebusd_test_server([response, response]) as (host, port, commands):
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.05))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["read -h 15B52406020002000F00"]
