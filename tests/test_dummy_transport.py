from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from helianthus_vrc_explorer.protocol.b524 import (
    build_directory_probe_payload,
    build_register_read_payload,
)
from helianthus_vrc_explorer.transport.base import TransportTimeout
from helianthus_vrc_explorer.transport.dummy import DummyTransport


def _write_min_fixture(tmp_path: Path) -> Path:
    fixture = {
        "meta": {},
        "groups": {
            "0x02": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x000f": {"raw_hex": "3412"},
                        }
                    }
                },
            }
        },
    }
    fixture_path = tmp_path / "fixture.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
    return fixture_path


def test_dummy_transport_directory_probe_known_group(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    response = transport.send(0x15, build_directory_probe_payload(0x02))
    assert response == struct.pack("<f", 1.0)


def test_dummy_transport_directory_probe_unknown_group_returns_zero(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    response = transport.send(0x15, build_directory_probe_payload(0x03))
    assert response == struct.pack("<f", 0.0)


def test_dummy_transport_register_read_returns_echo_plus_value(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    payload = build_register_read_payload(0x02, group=0x02, instance=0x00, register=0x000F)
    response = transport.send(0x15, payload)
    assert response == bytes.fromhex("020002003412")


def test_dummy_transport_missing_register_raises_timeout(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    payload = build_register_read_payload(0x02, group=0x02, instance=0x00, register=0x0010)
    with pytest.raises(TransportTimeout):
        transport.send(0x15, payload)
