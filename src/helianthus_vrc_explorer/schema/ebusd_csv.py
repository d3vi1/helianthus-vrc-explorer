from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from ..protocol.b524 import B524RegisterSelector, parse_b524_id

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True, slots=True)
class EbusdRegisterSchemaEntry:
    name: str
    type_spec: str | None


def _looks_like_type_spec(value: str) -> bool:
    normalized = value.strip().upper()
    if not normalized:
        return False
    if normalized in {"EXP", "UIN", "UCH", "HTI", "HDA:3", "I8", "I16", "U32", "I32", "BOOL"}:
        return True
    return normalized.startswith(("STR:", "HEX:"))


def _extract_b524_id_hex(fields: list[str]) -> str | None:
    for i, raw in enumerate(fields):
        field = raw.strip()
        if not field:
            continue
        lowered = field.lower()
        if lowered.startswith("b524,"):
            return field[5:].strip()
        if lowered == "b524" and i + 1 < len(fields):
            candidate = fields[i + 1].strip()
            if candidate and _HEX_RE.fullmatch(candidate) and len(candidate) % 2 == 0:
                return candidate
    return None


def _extract_value_type_spec(fields: list[str]) -> str | None:
    for raw in reversed(fields):
        if _looks_like_type_spec(raw):
            return raw.strip().upper()
    return None


class EbusdCsvSchema:
    """Lightweight loader for ebusd configuration CSV files (e.g. `15.720.csv`)."""

    def __init__(
        self,
        *,
        exact: dict[tuple[int, int, int, int], EbusdRegisterSchemaEntry],
        wildcard_instance: dict[tuple[int, int, int], EbusdRegisterSchemaEntry],
    ) -> None:
        self._exact = exact
        self._wildcard_instance = wildcard_instance

    @classmethod
    def from_path(cls, path: Path) -> EbusdCsvSchema:
        exact: dict[tuple[int, int, int, int], EbusdRegisterSchemaEntry] = {}
        wildcard_instance: dict[tuple[int, int, int], EbusdRegisterSchemaEntry] = {}

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                # Skip comment lines.
                if row[0].lstrip().startswith("#"):
                    continue

                name = row[3].strip() if len(row) > 3 else ""
                if not name:
                    continue

                id_hex = _extract_b524_id_hex(row)
                if id_hex is None:
                    continue

                try:
                    selector = parse_b524_id(f"b524,{id_hex}")
                except Exception:
                    continue

                if not isinstance(selector, B524RegisterSelector):
                    continue
                if selector.optype != 0x00:
                    continue

                type_spec = _extract_value_type_spec(row)
                entry = EbusdRegisterSchemaEntry(name=name, type_spec=type_spec)

                if selector.instance == 0xFF:
                    wildcard_key = (selector.opcode, selector.group, selector.register)
                    wildcard_instance.setdefault(wildcard_key, entry)
                else:
                    exact_key = (
                        selector.opcode,
                        selector.group,
                        selector.instance,
                        selector.register,
                    )
                    exact.setdefault(exact_key, entry)

        return cls(exact=exact, wildcard_instance=wildcard_instance)

    def lookup(
        self,
        *,
        opcode: int,
        group: int,
        instance: int,
        register: int,
    ) -> EbusdRegisterSchemaEntry | None:
        entry = self._exact.get((opcode, group, instance, register))
        if entry is not None:
            return entry
        return self._wildcard_instance.get((opcode, group, register))
