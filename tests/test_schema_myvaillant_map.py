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


def test_default_heating_circuit_curve_mapping_uses_wildcard_instances() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    curve_ii0 = schema.lookup(group=0x02, instance=0x00, register=0x000F)
    curve_ii2 = schema.lookup(group=0x02, instance=0x02, register=0x000F)
    assert curve_ii0 is not None
    assert curve_ii2 is not None
    assert curve_ii0.leaf == "heating_curve"
    assert curve_ii2.leaf == "heating_curve"


def test_default_heating_circuit_mapping_resolves_ebusd_name_templates() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    flow = schema.lookup(group=0x02, instance=0x01, register=0x0007)
    zone = schema.lookup(group=0x03, instance=0x02, register=0x0016)
    assert flow is not None
    assert zone is not None
    assert flow.resolved_ebusd_name(group=0x02, instance=0x01, register=0x0007) == (
        "Hc2FlowTempDesired"
    )
    assert zone.resolved_ebusd_name(group=0x03, instance=0x02, register=0x0016) == "Zone3Name"


def test_packaged_myvaillant_map_stays_in_sync_with_repo_copy() -> None:
    repo_csv = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    packaged_csv = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "helianthus_vrc_explorer"
        / "data"
        / "myvaillant_register_map.csv"
    )
    assert packaged_csv.read_text(encoding="utf-8") == repo_csv.read_text(encoding="utf-8")
