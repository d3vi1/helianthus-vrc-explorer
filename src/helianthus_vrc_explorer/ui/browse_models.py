from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

BrowseTab = Literal["config", "config_limits", "state"]


@dataclass(frozen=True, slots=True)
class RegisterAddress:
    group_key: str
    instance_key: str
    register_key: str
    read_opcode: str | None

    @property
    def label(self) -> str:
        suffix = f" {self.read_opcode}" if self.read_opcode else ""
        return f"GG={self.group_key} II={self.instance_key} RR={self.register_key}{suffix}"


@dataclass(frozen=True, slots=True)
class RegisterRow:
    row_id: str
    category_key: str
    category_label: str
    group_key: str
    group_name: str
    instance_key: str
    register_key: str
    name: str
    myvaillant_name: str
    ebusd_name: str
    path: str
    tab: BrowseTab
    address: RegisterAddress
    value_text: str
    raw_hex: str
    unit: str
    access_flags: str
    last_update_text: str
    age_text: str
    change_indicator: str
    search_blob: str


@dataclass(frozen=True, slots=True)
class TreeNodeRef:
    node_id: str
    label: str
    level: Literal["root", "category", "group", "instance", "register"]
    category_key: str | None = None
    group_key: str | None = None
    instance_key: str | None = None
    register_key: str | None = None
