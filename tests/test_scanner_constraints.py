from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.scan import (
    ConstraintEntry,
    _parse_constraint_entry,
    _resolve_mixer_circuit_type_name,
    _resolve_room_influence_type_name,
)


@pytest.mark.parametrize(
    ("response_hex", "expected_kind", "expected_min", "expected_max", "expected_step"),
    [
        ("06010200000101", "u8_range", 0, 1, 1),
        ("09020200000004000100", "u16_range", 0, 4, 1),
        ("0f030200000070410000f0410000003f", "f32_range", 15.0, 30.0, 0.5),
        ("0c0303000101011f0c63010000", "date_range", "2001-01-01", "2099-12-31", 1),
    ],
)
def test_parse_constraint_entry_known_tt_formats(
    response_hex: str,
    expected_kind: str,
    expected_min: int | float | str,
    expected_max: int | float | str,
    expected_step: int | float,
) -> None:
    response = bytes.fromhex(response_hex)
    entry = _parse_constraint_entry(group=response[1], register=response[2], response=response)

    assert isinstance(entry, ConstraintEntry)
    assert entry.kind == expected_kind
    if isinstance(expected_min, float):
        assert isinstance(entry.min_value, float)
        assert entry.min_value == pytest.approx(expected_min, abs=1e-6)
    else:
        assert entry.min_value == expected_min
    if isinstance(expected_max, float):
        assert isinstance(entry.max_value, float)
        assert entry.max_value == pytest.approx(expected_max, abs=1e-6)
    else:
        assert entry.max_value == expected_max
    if isinstance(expected_step, float):
        assert isinstance(entry.step_value, float)
        assert entry.step_value == pytest.approx(expected_step, abs=1e-6)
    else:
        assert entry.step_value == expected_step


def test_parse_constraint_entry_rejects_header_mismatch() -> None:
    response = bytes.fromhex("09020200000004000100")
    with pytest.raises(ValueError, match="Constraint header mismatch"):
        _parse_constraint_entry(group=0x03, register=0x02, response=response)


def test_parse_constraint_entry_rejects_unsupported_tt() -> None:
    response = bytes.fromhex("01020200000004000100")
    with pytest.raises(ValueError, match="Unsupported constraint TT"):
        _parse_constraint_entry(group=0x02, register=0x02, response=response)


def test_resolve_mixer_circuit_type_name_context_rules() -> None:
    assert _resolve_mixer_circuit_type_name(
        1,
        cooling_enabled=0,
        gg05_present=False,
        system_schema=None,
        pool_sensor_present=False,
    ) == ("HEATING_OR_COOLING", "HEATING")
    assert _resolve_mixer_circuit_type_name(
        1,
        cooling_enabled=1,
        gg05_present=False,
        system_schema=None,
        pool_sensor_present=False,
    ) == ("HEATING_OR_COOLING", "COOLING")
    assert _resolve_mixer_circuit_type_name(
        2,
        cooling_enabled=0,
        gg05_present=False,
        system_schema=8,
        pool_sensor_present=True,
    ) == ("FIXED_VALUE_OR_POOL", "POOL")
    assert _resolve_mixer_circuit_type_name(
        3,
        cooling_enabled=0,
        gg05_present=True,
        system_schema=None,
        pool_sensor_present=False,
    ) == ("DHW_OR_CYLINDER_CHARGING", "CYLINDER_CHARGING")


def test_resolve_room_influence_type_name_rules() -> None:
    assert _resolve_room_influence_type_name(0) == ("INACTIVE", "INACTIVE")
    assert _resolve_room_influence_type_name(1) == ("ACTIVE", "ACTIVE")
    assert _resolve_room_influence_type_name(2) == ("EXTENDED", "EXTENDED")
