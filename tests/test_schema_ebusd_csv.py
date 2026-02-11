from __future__ import annotations

from pathlib import Path

from helianthus_vrc_explorer.schema.ebusd_csv import EbusdCsvSchema


def test_ebusd_csv_schema_parses_b509_register_rows(tmp_path: Path) -> None:
    csv_path = tmp_path / "schema.csv"
    csv_path.write_text(
        "\n".join(
            [
                "# comment",
                "x,x,x,SystemWaterPressure,b509,0d2739,EXP",
                "x,x,x,AnotherName,b509,0d2739,UIN",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    schema = EbusdCsvSchema.from_path(csv_path)
    entry = schema.lookup_b509(register=0x2739)
    assert entry is not None
    # First match wins to keep deterministic behavior with duplicate rows.
    assert entry.name == "SystemWaterPressure"
    assert entry.type_spec == "EXP"
