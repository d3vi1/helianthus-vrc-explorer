from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.plan import (
    GroupScanPlan,
    estimate_register_requests,
    parse_int_set,
    parse_int_token,
)


def test_parse_int_token_accepts_decimal_and_hex() -> None:
    assert parse_int_token("10") == 10
    assert parse_int_token("0x0a") == 10
    assert parse_int_token("0A") == 10
    assert parse_int_token("ff") == 255


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("0-3", [0, 1, 2, 3]),
        ("1,3,5", [1, 3, 5]),
        ("0-3,7,9-10", [0, 1, 2, 3, 7, 9, 10]),
        ("3-1", [1, 2, 3]),
    ],
)
def test_parse_int_set(spec: str, expected: list[int]) -> None:
    assert parse_int_set(spec, min_value=0, max_value=255) == expected


def test_parse_int_set_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="out of range"):
        parse_int_set("256", min_value=0, max_value=255)


def test_estimate_register_requests() -> None:
    plan = {
        0x02: GroupScanPlan(group=0x02, rr_max=0x0003, instances=(0x00, 0x01)),
        0x01: GroupScanPlan(group=0x01, rr_max=0x0001, instances=(0x00,)),
    }
    # GG=0x02: 2 instances * (3+1) regs = 8
    # GG=0x01: 1 instance * (1+1) regs = 2
    assert estimate_register_requests(plan) == 10
