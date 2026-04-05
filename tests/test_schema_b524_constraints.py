from __future__ import annotations

from pathlib import Path

from helianthus_vrc_explorer.scanner.identity import make_register_identity
from helianthus_vrc_explorer.schema.b524_constraints import (
    constraint_scope_metadata,
    load_b524_constraints_catalog_from_path,
    load_default_b524_constraints_catalog,
    lookup_static_constraint,
)


def test_load_default_b524_constraints_catalog() -> None:
    catalog, source = load_default_b524_constraints_catalog()

    assert source == "static_constraints:b524_constraints_catalog.csv"

    hc_room_setpoint = catalog[0x02][0x0002]
    assert hc_room_setpoint.tt == 0x09
    assert hc_room_setpoint.kind == "u16_range"
    assert hc_room_setpoint.min_value == 0
    assert hc_room_setpoint.max_value == 4
    assert hc_room_setpoint.step_value == 1
    assert hc_room_setpoint.source == "static_catalog"
    assert hc_room_setpoint.scope == "opcode_0x02_default"
    assert hc_room_setpoint.provenance == "catalog_seeded_from_opcode_0x01"
    assert hc_room_setpoint.read_opcodes == (0x02,)

    zone_desired_temp = catalog[0x03][0x0002]
    assert zone_desired_temp.tt == 0x0F
    assert zone_desired_temp.kind == "f32_range"
    assert zone_desired_temp.min_value == 15.0
    assert zone_desired_temp.max_value == 30.0
    assert zone_desired_temp.step_value == 0.5


def test_lookup_static_constraint_defaults_to_opcode_0x02() -> None:
    catalog, _source = load_default_b524_constraints_catalog()

    entry = lookup_static_constraint(
        catalog,
        identity=make_register_identity(
            opcode=0x02,
            group=0x02,
            instance=0x00,
            register=0x0002,
        ),
    )

    assert entry is not None
    assert entry.kind == "u16_range"


def test_lookup_static_constraint_skips_remote_opcode_by_default() -> None:
    catalog, _source = load_default_b524_constraints_catalog()
    remote = lookup_static_constraint(
        catalog,
        identity=make_register_identity(
            opcode=0x06,
            group=0x03,
            instance=0x01,
            register=0x0002,
        ),
    )

    assert remote is None


def test_lookup_static_constraint_accepts_explicit_read_opcode_scope(tmp_path: Path) -> None:
    catalog_path = tmp_path / "constraints.csv"
    catalog_path.write_text(
        "\n".join(
            (
                "group,register,type,min,max,step,read_opcodes",
                "0x03,0x0002,f32_range,15,30,0.5,\"0x02,0x06\"",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    catalog = load_b524_constraints_catalog_from_path(catalog_path)

    local = lookup_static_constraint(
        catalog,
        identity=make_register_identity(
            opcode=0x02,
            group=0x03,
            instance=0x00,
            register=0x0002,
        ),
    )
    remote = lookup_static_constraint(
        catalog,
        identity=make_register_identity(
            opcode=0x06,
            group=0x03,
            instance=0x01,
            register=0x0002,
        ),
    )

    assert local is not None
    assert remote is not None
    assert local == remote
    assert local.scope == "explicit_opcode_0x02_0x06"
    assert local.read_opcodes == (0x02, 0x06)


def test_constraint_scope_metadata_declares_opcode_0x02_default_policy() -> None:
    metadata = constraint_scope_metadata()
    assert metadata["decision"] == "opcode_0x02_default"
    assert metadata["protocol"] == "opcode_0x01"
