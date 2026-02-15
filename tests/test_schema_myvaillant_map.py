from __future__ import annotations

from pathlib import Path

from helianthus_vrc_explorer.schema.myvaillant_map import MyvaillantRegisterMap


def test_default_zone_desired_room_setpoint_mapping_uses_rr_0x0022() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    desired = schema.lookup(group=0x03, instance=0x00, register=0x0022)
    assert desired is not None
    assert desired.leaf == "heating_desired_setpoint"

    # RR=0x0014 is a distinct manual setpoint register and must not reuse RR=0x0022 semantics.
    legacy = schema.lookup(group=0x03, instance=0x00, register=0x0014)
    assert legacy is not None
    assert legacy.leaf == "heating_manual_mode_setpoint"


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


def test_default_heating_circuit_type_mapping_uses_rr_0x0001() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    circuit_type = schema.lookup(group=0x02, instance=0x00, register=0x0001)
    assert circuit_type is not None
    assert circuit_type.leaf == "heating_circuit_type"
    assert circuit_type.resolved_ebusd_name(group=0x02, instance=0x01, register=0x0001) == (
        "Hc2CircuitType"
    )


def test_default_mixer_circuit_type_external_mapping_uses_rr_0x0002() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    mixer_type = schema.lookup(group=0x02, instance=0x00, register=0x0002)
    assert mixer_type is not None
    assert mixer_type.leaf == "mixer_circuit_type_external"
    assert mixer_type.resolved_ebusd_name(group=0x02, instance=0x02, register=0x0002) == (
        "Hc3CircuitType"
    )


def test_default_room_influence_type_mapping_uses_rr_0x0003() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    room_influence = schema.lookup(group=0x02, instance=0x00, register=0x0003)
    assert room_influence is not None
    assert room_influence.leaf == "room_influence_type"
    assert room_influence.register_class == "config"
    assert room_influence.resolved_ebusd_name(group=0x02, instance=0x01, register=0x0003) == (
        "Hc2RoomInfluenceType"
    )


def test_default_hc_new_register_mappings_include_class_hints() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    frost = schema.lookup(group=0x02, instance=0x00, register=0x001D)
    mixer_pos = schema.lookup(group=0x02, instance=0x00, register=0x0021)
    pump_starts = schema.lookup(group=0x02, instance=0x00, register=0x0025)
    assert frost is not None
    assert mixer_pos is not None
    assert pump_starts is not None
    assert frost.leaf == "frost_protection_threshold"
    assert frost.register_class == "config_limits"
    assert mixer_pos.leaf == "mixer_position_percentage"
    assert mixer_pos.register_class == "state"
    assert pump_starts.leaf == "pump_starts_count"
    assert pump_starts.register_class == "state"


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
