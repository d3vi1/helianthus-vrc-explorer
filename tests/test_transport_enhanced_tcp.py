from __future__ import annotations

import contextlib
import socket
import socketserver
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from queue import Queue

from helianthus_vrc_explorer.transport.base import TransportError, TransportNack, TransportTimeout
from helianthus_vrc_explorer.transport.enhanced_tcp import (
    _ENH_REQ_INIT,
    _ENH_REQ_SEND,
    _ENH_REQ_START,
    _ENH_RES_ERROR_HOST,
    _ENH_RES_RECEIVED,
    _ENH_RES_RESETTED,
    _ENH_RES_STARTED,
    EnhancedTcpConfig,
    EnhancedTcpTransport,
    _crc,
    _crc_update,
    _encode_enh,
)


def _read_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = conn.recv(size - len(chunks))
        if not chunk:
            raise AssertionError("unexpected EOF while waiting for ENH frame")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_enh_frame(conn: socket.socket) -> tuple[int, int]:
    data = _read_exact(conn, 2)
    byte1, byte2 = data
    if byte1 & 0xC0 != 0xC0:
        raise AssertionError(f"invalid ENH frame start 0x{byte1:02X}")
    if byte2 & 0xC0 != 0x80:
        raise AssertionError(f"invalid ENH frame end 0x{byte2:02X}")
    command = (byte1 >> 2) & 0x0F
    payload = ((byte1 & 0x03) << 6) | (byte2 & 0x3F)
    return command, payload


def _write_enh_frame(conn: socket.socket, command: int, data: int) -> None:
    conn.sendall(_encode_enh(command, data))


def _write_bus_symbol(conn: socket.socket, symbol: int) -> None:
    _write_enh_frame(conn, _ENH_RES_RECEIVED, symbol)


@contextmanager
def _run_ens_test_server(
    handler_fn: Callable[[socket.socket], None],
) -> Iterator[tuple[str, int]]:
    errors: Queue[BaseException] = Queue()

    class _Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:  # noqa: D401 - socketserver signature
            try:
                handler_fn(self.request)
            except BaseException as exc:  # pragma: no cover - surfaced after shutdown
                errors.put(exc)
                raise

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    # VE9: Non-daemon threads so handler exceptions are visible.
    server.daemon_threads = False

    thread = threading.Thread(target=server.serve_forever, daemon=False)
    thread.start()
    try:
        host, port = server.server_address
        assert isinstance(host, str)
        assert isinstance(port, int)
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if not errors.empty():
            raise errors.get()


def test_ens_transport_send_proto_round_trips_identification_request() -> None:
    src = 0xF1
    dst = 0x15
    request = bytes((src, dst, 0x07, 0x04, 0x00, _crc(bytes((src, dst, 0x07, 0x04, 0x00)))))
    response = bytes.fromhex("b556524320373230662f3205071704")
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        _write_bus_symbol(conn, 0x00)
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_ens_transport_send_wraps_b524_request() -> None:
    src = 0xF1
    dst = 0x15
    payload = bytes.fromhex("020002000F00")
    request_without_crc = bytes((src, dst, 0xB5, 0x24, len(payload))) + payload
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01, 0x02, 0x03))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        _write_bus_symbol(conn, 0x00)
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send(dst, payload)

    assert result == response


def test_ens_transport_broadcast_does_not_expect_response() -> None:
    src = 0xF1
    dst = 0xFE
    request_without_crc = bytes((src, dst, 0x07, 0xFE, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0xFE, b"", expect_response=False)

    assert result == b""


def test_internal_enhanced_nack_maps_to_transport_nack() -> None:
    from helianthus_vrc_explorer.transport.enhanced_tcp import _EnhancedNack

    assert issubclass(_EnhancedNack, TransportNack)


def test_ve1_send_payload_containing_escape_byte() -> None:
    """VE1/VE20: Verify that 0xA9 (ESCAPE) in payload sends correctly via ENH.

    The enhanced adapter firmware handles wire escape encoding.  The ENH
    SEND command carries logical bytes -- the client must NOT pre-escape.
    """
    src = 0xF1
    dst = 0x15
    # Payload deliberately contains 0xA9 (eBUS escape) and 0xAA (eBUS SYN).
    payload = bytes((0xA9, 0x42, 0xAA))
    request_without_crc = bytes((src, dst, 0xB5, 0x24, len(payload))) + payload
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        # Adapter receives logical bytes via ENH -- no wire escaping at this layer.
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN (end)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send(dst, payload)

    assert result == response


def test_ve21_response_crc_with_escape_bytes() -> None:
    """VE21/VE25: Verify CRC verification works when response contains 0xA9.

    The _crc() function correctly applies escape expansion to logical bytes
    before CRC computation, matching what the bus target does.

    Note: 0xAA (SYN) cannot appear as a logical data byte in eBUS responses
    because SYN is the bus frame delimiter.  The escape byte 0xA9 CAN appear
    as logical data (wire-escaped to [0xA9, 0x00] and un-escaped by the
    adapter firmware).
    """
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    # Response deliberately contains 0xA9 (eBUS escape) bytes.
    # 0xA9 triggers CRC escape expansion: logical 0xA9 -> wire [0xA9, 0x00].
    response = bytes((0x01, 0xA9, 0x42, 0xA9, 0x03))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        _write_bus_symbol(conn, 0x00)  # ACK
        # Adapter sends logical (un-escaped) response bytes via ENH RECEIVED.
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN (end)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_ve25_crc_escape_expansion_is_correct() -> None:
    """VE25: Verify _crc() correctly handles escape expansion for CRC computation.

    Per eBUS spec, CRC is computed on the wire-expanded form.  Logical 0xA9
    expands to [0xA9, 0x00] and logical 0xAA expands to [0xA9, 0x01].
    """
    # CRC of a single 0xA9 byte = CRC of wire sequence [0xA9, 0x00]
    expected = _crc_update(_crc_update(0, 0xA9), 0x00)
    assert _crc(bytes((0xA9,))) == expected

    # CRC of a single 0xAA byte = CRC of wire sequence [0xA9, 0x01]
    expected_aa = _crc_update(_crc_update(0, 0xA9), 0x01)
    assert _crc(bytes((0xAA,))) == expected_aa

    # Normal bytes pass through unchanged
    expected_42 = _crc_update(0, 0x42)
    assert _crc(bytes((0x42,))) == expected_42

    # Mixed: [0x42, 0xA9, 0x01] -> CRC([0x42, 0xA9, 0x00, 0x01])
    crc = 0
    crc = _crc_update(crc, 0x42)
    crc = _crc_update(crc, 0xA9)
    crc = _crc_update(crc, 0x00)  # escape expansion of 0xA9
    crc = _crc_update(crc, 0x01)
    assert _crc(bytes((0x42, 0xA9, 0x01))) == crc


def test_ve22_concurrent_session_entry() -> None:
    """VE22: _session_depth must be thread-safe under concurrent session() calls."""
    import time as _time

    results: list[bool] = []

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        # Keep connection alive for all threads
        _time.sleep(1.0)

    def _session_user(transport: EnhancedTcpTransport) -> None:
        try:
            with transport.session():
                _time.sleep(0.1)
            results.append(True)
        except Exception:
            results.append(False)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0)
        )
        threads = [
            threading.Thread(target=_session_user, args=(transport,))
            for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

    # At least some threads should succeed
    assert any(results), f"All threads failed: {results}"


def test_ve17_session_depth_never_negative() -> None:
    """VE17: session depth must never go negative even with spurious close calls."""
    transport = EnhancedTcpTransport(
        EnhancedTcpConfig(host="127.0.0.1", port=1, timeout_s=0.1)
    )
    # Depth starts at 0, multiple closes must not drive it negative
    transport._session_depth = 0
    transport.close()
    assert transport._session_depth >= 0
    transport.close()
    assert transport._session_depth >= 0


def test_ve15_malformed_enh_byte_no_immediate_close() -> None:
    """VE15: A single malformed ENH byte should not close the transport."""

    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01, 0x02))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        # Inject a single malformed byte (0x85 has bit pattern 10xxxxxx — invalid start)
        conn.sendall(bytes((0x85,)))

        # Then send valid response
        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_ve2_host_error_not_retried() -> None:
    """VE2: TransportHostError should propagate without retry."""
    import pytest

    from helianthus_vrc_explorer.transport.base import TransportHostError

    call_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal call_count
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, 0xF7)
        # Respond with host error
        _write_enh_frame(conn, _ENH_RES_ERROR_HOST, 0x01)
        call_count += 1

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=1.0, collision_max_retries=3)
        )
        with pytest.raises(TransportHostError):
            transport.send_proto(0x15, 0x07, 0x04, b"")

    # Should have been called exactly once — no retry
    assert call_count == 1


def test_ve6_src_escape_rejected() -> None:
    """VE6: src=0xA9 (ESCAPE) must be rejected."""
    import pytest
    with pytest.raises(ValueError, match="reserved address"):
        EnhancedTcpTransport(EnhancedTcpConfig(src=0xA9))


def test_ve6_src_syn_rejected() -> None:
    """VE6: src=0xAA (SYN) must be rejected."""
    import pytest
    with pytest.raises(ValueError, match="reserved address"):
        EnhancedTcpTransport(EnhancedTcpConfig(src=0xAA))


def test_ve6_src_zero_rejected() -> None:
    """VE6: src=0x00 must be rejected."""
    import pytest
    with pytest.raises(ValueError, match="reserved address"):
        EnhancedTcpTransport(EnhancedTcpConfig(src=0x00))


def test_ve6_src_0xff_rejected() -> None:
    """VE6: src=0xFF must be rejected."""
    import pytest
    with pytest.raises(ValueError, match="reserved address"):
        EnhancedTcpTransport(EnhancedTcpConfig(src=0xFF))


def test_ve7_dst_escape_rejected() -> None:
    """VE7: dst=0xA9 (ESCAPE) must be rejected."""
    import pytest
    transport = EnhancedTcpTransport(EnhancedTcpConfig())
    with pytest.raises(ValueError, match="reserved address"):
        transport.send_proto(0xA9, 0x07, 0x04, b"")


def test_ve7_dst_syn_rejected() -> None:
    """VE7: dst=0xAA (SYN) must be rejected."""
    import pytest
    transport = EnhancedTcpTransport(EnhancedTcpConfig())
    with pytest.raises(ValueError, match="reserved address"):
        transport.send_proto(0xAA, 0x07, 0x04, b"")


def test_ve19r2_negative_timeout_rejected() -> None:
    """VE19-R2: timeout_s <= 0 must be rejected."""
    import pytest
    with pytest.raises(ValueError, match="timeout_s"):
        EnhancedTcpTransport(EnhancedTcpConfig(timeout_s=-1.0))


def test_ve19r2_zero_timeout_rejected() -> None:
    """VE19-R2: timeout_s=0 must be rejected."""
    import pytest
    with pytest.raises(ValueError, match="timeout_s"):
        EnhancedTcpTransport(EnhancedTcpConfig(timeout_s=0.0))


def test_ve19r2_nan_timeout_rejected() -> None:
    """VE19-R2: timeout_s=NaN must be rejected."""
    import pytest
    with pytest.raises(ValueError, match="timeout_s"):
        EnhancedTcpTransport(EnhancedTcpConfig(timeout_s=float("nan")))


def test_ve19r2_port_zero_rejected() -> None:
    """VE19-R2: port=0 must be rejected."""
    import pytest
    with pytest.raises(ValueError, match="port"):
        EnhancedTcpTransport(EnhancedTcpConfig(port=0))


def test_ve19r2_port_too_large_rejected() -> None:
    """VE19-R2: port=99999 must be rejected."""
    import pytest
    with pytest.raises(ValueError, match="port"):
        EnhancedTcpTransport(EnhancedTcpConfig(port=99999))


def test_ve4_nack_retry_without_rearbitration() -> None:
    """VE4: After NACK, retry telegram without re-arbitrating."""
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    start_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal start_count
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        # First (and only) arbitration
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        start_count += 1

        # First telegram send — will be NACKed
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0xFF)  # NACK

        # Local retry — same telegram, NO re-arbitration
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)  # ACK this time

        # Response
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src, nack_max_retries=1)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response
    assert start_count == 1  # Only ONE arbitration


def test_ve23_timeout_retries_accumulate_across_reconnect() -> None:
    """VE23: timeout_retries must not reset after reconnect."""
    import time as _time

    import pytest

    connect_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal connect_count
        connect_count += 1
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        # Never respond to START — causes timeout
        _time.sleep(5.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host, port=port, timeout_s=0.3, src=0xF1,
                timeout_max_retries=1, reconnect_max_retries=1,
                reconnect_delay_s=0.1,
            )
        )
        with pytest.raises((TransportTimeout, TransportError)):
            transport.send_proto(0x15, 0x07, 0x04, b"")

    # With timeout_max_retries=1, reconnect_max_retries=1:
    # Without VE23 fix (timeout reset): would loop indefinitely
    # With VE23 fix: bounded number of connections
    assert connect_count <= 3  # Bounded, not infinite


def test_ve8_cli_default_src() -> None:
    """VE8: CLI default src must match EnhancedTcpConfig default (0xF7)."""
    config = EnhancedTcpConfig()
    assert config.src == 0xF7


# ---------------------------------------------------------------------------
# Adversarial tests added by angry-tester audit
# ---------------------------------------------------------------------------


def test_adv_all_escape_syn_payload() -> None:
    """ADV: Payload where every byte is 0xA9 (ESCAPE) or 0xAA (SYN)."""
    src = 0xF1
    dst = 0x15
    payload = bytes((0xA9, 0xAA, 0xA9, 0xAA))
    request_without_crc = bytes((src, dst, 0xB5, 0x24, len(payload))) + payload
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send(dst, payload)
    assert result == response


def test_adv_crc_value_is_escape_byte() -> None:
    """ADV: Response CRC value itself is 0xA9 (ESCAPE)."""
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x32,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)
    assert response_crc == 0xA9

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")
    assert result == response


def test_adv_crc_value_is_syn_byte_succeeds() -> None:
    """ADV: Response CRC value 0xAA must succeed (not false-timeout).

    In the ENH protocol, 0xAA from _recv_bus_symbol() is a legitimate
    data byte — the adapter decoded wire-escaped [0xA9, 0x01] back to
    logical 0xAA.  Bus SYN loss is reported via _ENH_RES_FAILED, not
    as a RECEIVED frame with data=0xAA.
    """
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x31,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)
    assert response_crc == 0xAA  # This CRC is the SYN byte value

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)  # 0xAA — valid CRC byte

        # Transport should send ACK + SYN (success, not timeout)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_adv_response_data_containing_0xaa() -> None:
    """ADV: Response data byte 0xAA must not trigger false SYN timeout."""
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    # Response contains 0xAA as a data byte
    response = bytes((0xAA, 0x42, 0xA9))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_adv_four_threads_hammering_send_proto() -> None:
    """ADV: 4 threads call send_proto() simultaneously."""
    import time as _time

    src = 0xF1
    completed: list[bool] = []
    errors: list[str] = []

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        for _ in range(4):
            try:
                cmd, data = _read_enh_frame(conn)
                if cmd != _ENH_REQ_START:
                    break
                _write_enh_frame(conn, _ENH_RES_STARTED, data)
                while True:
                    cmd2, data2 = _read_enh_frame(conn)
                    if cmd2 != _ENH_REQ_SEND:
                        break
                    _write_bus_symbol(conn, data2)
                    if data2 == 0xAA:
                        break
            except Exception:
                break
        _time.sleep(0.5)

    def _send_one(transport: EnhancedTcpTransport, idx: int) -> None:
        try:
            transport.send_proto(0xFE, 0x07, 0xFE, b"", expect_response=False)
            completed.append(True)
        except Exception as exc:
            errors.append(f"thread-{idx}: {type(exc).__name__}: {exc}")
            completed.append(False)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        threads = [
            threading.Thread(target=_send_one, args=(transport, i))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
    assert len(completed) == 4
    assert any(completed), f"No thread succeeded: {errors}"


def test_adv_reconnect_storm_disconnect_every_2nd() -> None:
    """ADV: Server disconnects after every 2nd message."""
    import pytest

    connect_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal connect_count
        connect_count += 1
        try:
            _read_enh_frame(conn)
            _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
            _read_enh_frame(conn)
        except Exception:
            pass
        conn.close()

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host, port=port, timeout_s=0.3, src=0xF1,
                timeout_max_retries=0,
                reconnect_max_retries=2,
                reconnect_delay_s=0.05,
            )
        )
        with pytest.raises((TransportError, TransportTimeout)):
            transport.send_proto(0x15, 0x07, 0x04, b"")
    assert connect_count <= 4


def test_adv_stream_of_0xff_to_enh_parser() -> None:
    """ADV: Stream of 0xFF bytes fed to the ENH parser."""
    import pytest

    def _handler(conn: socket.socket) -> None:
        with contextlib.suppress(Exception):
            conn.sendall(bytes([0xFF] * 200))
        import time as _time
        _time.sleep(1.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host, port=port, timeout_s=0.5, src=0xF1,
                timeout_max_retries=0,
                reconnect_max_retries=0,
            )
        )
        with pytest.raises((TransportError, TransportTimeout)):
            transport.send_proto(0x15, 0x07, 0x04, b"")


def test_adv_send_symbol_escape_byte_explicit() -> None:
    """ADV: _send_symbol_with_echo with symbol=0xA9 (ESCAPE) explicitly."""
    src = 0xF1
    dst = 0x15
    payload = bytes((0xA9,))
    request_without_crc = bytes((src, dst, 0xB5, 0x24, len(payload))) + payload
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x42,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)
    symbols_sent: list[int] = []

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        for expected in request[1:]:
            cmd, data = _read_enh_frame(conn)
            assert cmd == _ENH_REQ_SEND
            assert data == expected
            symbols_sent.append(data)
            _write_bus_symbol(conn, data)
        _write_bus_symbol(conn, 0x00)
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send(dst, payload)
    assert result == response
    assert 0xA9 in symbols_sent
