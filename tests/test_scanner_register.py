from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.register import is_instance_present, read_register
from helianthus_vrc_explorer.transport.base import (
    TransportError,
    TransportInterface,
    TransportTimeout,
)


class _FlakyOnceTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        if self.calls == 1:
            raise TransportTimeout("boom")
        # Return a register response header + a u16le value (UIN) so parsing succeeds.
        group = payload[2]
        rr = payload[4:6]
        header = bytes((0x00, group)) + rr
        return header + b"\x01\x00"


class _AlwaysTimeoutTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        raise TransportTimeout("boom")


def test_read_register_retries_timeout_once_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    sleep_calls: list[float] = []

    def _sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    monkeypatch.setattr(register.time, "sleep", _sleep)
    transport = _FlakyOnceTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x02,
        instance=0x00,
        register=0x0002,
        type_hint="UIN",
    )

    assert transport.calls == 2
    assert sleep_calls == [1.0]
    assert entry["error"] is None
    assert entry["type"] == "UIN"
    assert entry["value"] == 1
    assert entry["raw_hex"] == "0100"


def test_read_register_retries_timeout_once_then_returns_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    sleep_calls: list[float] = []

    def _sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    monkeypatch.setattr(register.time, "sleep", _sleep)
    transport = _AlwaysTimeoutTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x02,
        instance=0x00,
        register=0x0002,
        type_hint="UIN",
    )

    assert transport.calls == 2
    assert sleep_calls == [1.0]
    assert entry["error"] == "timeout"
    assert entry["raw_hex"] is None


class _AlwaysDecodeErrorTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        # Wrong echo header triggers decode_error in read_register.
        return b"\x00\x00\x00\x00"


class _AlwaysTransportErrorTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        raise TransportError("nope")


class _StatusOnlyTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        return b"\x00"


def test_read_register_status_only_response_is_not_decode_error() -> None:
    transport = _StatusOnlyTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x00,
        instance=0x00,
        register=0x0000,
    )

    assert entry["raw_hex"] == "00"
    assert entry["type"] is None
    assert entry["value"] is None
    assert entry["error"] == "status_only_response: 0x00"


def test_is_instance_present_group_0c_requires_valid_register_response() -> None:
    transport = _AlwaysDecodeErrorTransport()

    assert is_instance_present(transport, dst=0x15, group=0x0C, instance=0x00) is False
    assert transport.calls == 4


def test_is_instance_present_group_0c_transport_errors_do_not_count_as_present() -> None:
    transport = _AlwaysTransportErrorTransport()

    assert is_instance_present(transport, dst=0x15, group=0x0C, instance=0x00) is False
    assert transport.calls == 4


def test_is_instance_present_group_0c_true_on_first_valid_register_response() -> None:
    transport = _FlakyOnceTransport()

    # Avoid sleeping on the first timeout: this tests presence logic, not retry delay.
    assert is_instance_present(transport, dst=0x15, group=0x0C, instance=0x00) is True
    # First RR=0x0002 read times out then succeeds on retry, so two calls.
    assert transport.calls == 2


def test_is_instance_present_group_09_rejects_nan_values(monkeypatch: pytest.MonkeyPatch) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[int] = []

    def _fake_read_register(*_args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(int(kwargs["register"]))
        return {
            "raw_hex": "00000000",
            "type": "EXP",
            "value": float("nan"),
            "error": None,
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert (
        is_instance_present(
            transport=_StatusOnlyTransport(),
            dst=0x15,
            group=0x09,
            instance=0x00,
        )
        is False
    )
    assert calls == [0x0007, 0x000F]


def test_is_instance_present_group_09_accepts_non_nan_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    values = iter([float("nan"), 1.0])

    def _fake_read_register(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return {
            "raw_hex": "00000000",
            "type": "EXP",
            "value": next(values),
            "error": None,
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert (
        is_instance_present(
            transport=_StatusOnlyTransport(),
            dst=0x15,
            group=0x09,
            instance=0x00,
        )
        is True
    )
