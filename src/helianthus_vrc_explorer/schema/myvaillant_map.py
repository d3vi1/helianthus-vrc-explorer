from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class MyvaillantRegisterName:
    leaf: str


def _parse_hex_u8(value: str) -> int:
    parsed = int(value, 0)
    if not (0x00 <= parsed <= 0xFF):
        raise ValueError(f"u8 out of range: {value!r}")
    return parsed


def _parse_hex_u16(value: str) -> int:
    parsed = int(value, 0)
    if not (0x0000 <= parsed <= 0xFFFF):
        raise ValueError(f"u16 out of range: {value!r}")
    return parsed


class MyvaillantRegisterMap:
    """Optional register-to-myVaillant leaf-name mapping.

    File format (CSV with header):

        group,instance,register,leaf
        0x03,0x01,0x0016,name

    `instance` may be `*` to match all instances in the group.
    """

    def __init__(
        self,
        *,
        exact: dict[tuple[int, int, int], MyvaillantRegisterName],
        wildcard_instance: dict[tuple[int, int], MyvaillantRegisterName],
    ) -> None:
        self._exact = exact
        self._wildcard_instance = wildcard_instance

    @classmethod
    def from_path(cls, path: Path) -> MyvaillantRegisterMap:
        exact: dict[tuple[int, int, int], MyvaillantRegisterName] = {}
        wildcard_instance: dict[tuple[int, int], MyvaillantRegisterName] = {}

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row:
                    continue
                gg_raw = (row.get("group") or "").strip()
                ii_raw = (row.get("instance") or "").strip()
                rr_raw = (row.get("register") or "").strip()
                leaf = (row.get("leaf") or "").strip()
                if not (gg_raw and ii_raw and rr_raw and leaf):
                    continue

                gg = _parse_hex_u8(gg_raw)
                rr = _parse_hex_u16(rr_raw)
                entry = MyvaillantRegisterName(leaf=leaf)

                if ii_raw == "*":
                    wildcard_instance.setdefault((gg, rr), entry)
                    continue

                ii = _parse_hex_u8(ii_raw)
                exact.setdefault((gg, ii, rr), entry)

        return cls(exact=exact, wildcard_instance=wildcard_instance)

    def lookup(self, *, group: int, instance: int, register: int) -> MyvaillantRegisterName | None:
        entry = self._exact.get((group, instance, register))
        if entry is not None:
            return entry
        return self._wildcard_instance.get((group, register))
