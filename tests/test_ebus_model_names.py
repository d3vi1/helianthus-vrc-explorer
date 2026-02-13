from __future__ import annotations

import csv
from pathlib import Path


def test_ebus_model_name_map_contains_basv2() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "ebus_model_names.csv"
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        rows = {str(row.get("ebus_model") or "").strip(): row for row in csv.DictReader(handle)}
    assert rows["BASV2"]["friendly_name"] == "Bus Application Software Version 2"


def test_packaged_ebus_model_name_map_stays_in_sync_with_repo_copy() -> None:
    repo_csv = Path(__file__).resolve().parents[1] / "data" / "ebus_model_names.csv"
    packaged_csv = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "helianthus_vrc_explorer"
        / "data"
        / "ebus_model_names.csv"
    )
    assert packaged_csv.read_text(encoding="utf-8") == repo_csv.read_text(encoding="utf-8")
