from __future__ import annotations

import pytest

from helianthus_vrc_explorer.protocol.b509 import build_b509_register_read_payload
from helianthus_vrc_explorer.scanner.b509 import merge_b509_ranges, parse_b509_range


def test_build_b509_register_read_payload() -> None:
    assert build_b509_register_read_payload(0x2701) == bytes.fromhex("0d2701")
    assert build_b509_register_read_payload(0x0000) == bytes.fromhex("0d0000")
    assert build_b509_register_read_payload(0xFFFF) == bytes.fromhex("0dffff")


@pytest.mark.parametrize("value", [-1, 0x10000])
def test_build_b509_register_read_payload_out_of_range(value: int) -> None:
    with pytest.raises(ValueError):
        build_b509_register_read_payload(value)


def test_parse_b509_range_parses_and_normalizes_order() -> None:
    assert parse_b509_range("0x2700..0x27ff") == (0x2700, 0x27FF)
    assert parse_b509_range("0x27ff..0x2700") == (0x2700, 0x27FF)


def test_merge_b509_ranges_merges_overlaps_and_adjacency() -> None:
    assert merge_b509_ranges([(0x2700, 0x2705), (0x2703, 0x2710), (0x2711, 0x2712)]) == [
        (0x2700, 0x2712)
    ]
