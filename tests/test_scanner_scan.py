from __future__ import annotations

import json
from pathlib import Path

import pytest

from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import TransportInterface
from helianthus_vrc_explorer.transport.dummy import DummyTransport


class RecordingTransport(TransportInterface):
    def __init__(self, inner: TransportInterface) -> None:
        self._inner = inner
        self.register_reads: list[tuple[int, int, int]] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        if len(payload) == 6 and payload[0] in {0x02, 0x06} and payload[1] == 0x00:
            group = payload[2]
            instance = payload[3]
            register = int.from_bytes(payload[4:6], byteorder="little", signed=False)
            self.register_reads.append((group, instance, register))
        return self._inner.send(dst, payload)


class InterruptingTransport(TransportInterface):
    def __init__(self, inner: TransportInterface, interrupt_after: int) -> None:
        self._inner = inner
        self._interrupt_after = interrupt_after
        self._calls = 0

    def send(self, dst: int, payload: bytes) -> bytes:
        self._calls += 1
        if self._calls > self._interrupt_after:
            raise KeyboardInterrupt
        return self._inner.send(dst, payload)


def _write_fixture_group_02(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x05"}},
        "groups": {
            "0x02": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            # Presence probe (UIN)
                            "0x0002": {"raw_hex": "0100"},
                            # Sample float32 (EXP) value
                            "0x000f": {"raw_hex": "9a99d93f"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def test_scan_b524_scans_all_instances_and_register_range(tmp_path: Path) -> None:
    transport = RecordingTransport(DummyTransport(_write_fixture_group_02(tmp_path)))

    artifact = scan_b524(transport, dst=0x15)

    assert artifact["meta"]["destination_address"] == "0x15"
    assert artifact["meta"]["incomplete"] is False

    group = artifact["groups"]["0x02"]
    assert group["descriptor_type"] == 1.0

    instance_00 = group["instances"]["0x00"]
    assert instance_00["present"] is True

    registers = instance_00["registers"]
    assert registers["0x0002"]["type"] == "UIN"
    assert registers["0x0002"]["value"] == 1
    assert registers["0x0002"]["raw_hex"] == "0100"
    assert registers["0x0002"]["error"] is None

    assert registers["0x000f"]["type"] == "EXP"
    assert registers["0x000f"]["value"] == pytest.approx(1.7, abs=1e-6)

    # Phase B/C: instance discovery must scan all II=0x00..ii_max (no early stop at gaps).
    probed_instances = sorted(
        {ii for (gg, ii, rr) in transport.register_reads if gg == 0x02 and rr == 0x0002}
    )
    assert probed_instances == list(range(0x0A + 1))

    # Phase D: register scan must cover RR=0x0000..rr_max for present instances.
    scanned_registers = {
        rr for (gg, ii, rr) in transport.register_reads if gg == 0x02 and ii == 0x00
    }
    assert scanned_registers == set(range(0x21 + 1))


def test_scan_b524_marks_incomplete_on_keyboard_interrupt(tmp_path: Path) -> None:
    inner = DummyTransport(_write_fixture_group_02(tmp_path))
    transport = InterruptingTransport(inner, interrupt_after=10)

    artifact = scan_b524(transport, dst=0x15)

    assert artifact["meta"]["incomplete"] is True
    assert artifact["meta"]["incomplete_reason"] == "user_interrupt"
