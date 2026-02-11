from __future__ import annotations

from pathlib import Path

from helianthus_vrc_explorer.schema.myvaillant_map import MyvaillantRegisterMap


def test_default_zone_desired_room_setpoint_mapping_uses_rr_0x0022() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    desired = schema.lookup(group=0x03, instance=0x00, register=0x0022)
    assert desired is not None
    assert desired.leaf == "desired_room_temperature_setpoint"

    # RR=0x0014 should no longer claim the desired-room-setpoint semantic.
    legacy = schema.lookup(group=0x03, instance=0x00, register=0x0014)
    assert legacy is None
