from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .browse_models import BrowseTab, RegisterAddress, RegisterRow, TreeNodeRef

_CATEGORY_NAMES: dict[int, tuple[str, str]] = {
    0x00: ("regulator", "Regulator"),
    0x01: ("hot_water", "Hot Water"),
    0x02: ("heating", "Heating"),
    0x03: ("zones", "Zones"),
    0x04: ("heating", "Heating"),
    0x05: ("hot_water", "Hot Water"),
    0x06: ("heating", "Heating"),
    0x07: ("heating", "Heating"),
    0x09: ("rooms", "Rooms"),
    0x0A: ("rooms", "Rooms"),
    0x0C: ("rooms", "Rooms"),
}


def _safe_int_hex(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        return 0


def _fmt_value(value: object | None) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


def _parse_timestamp(meta: dict[str, Any]) -> datetime | None:
    ts = meta.get("scan_timestamp")
    if not isinstance(ts, str):
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _category_for_group(group_key: str, group_name: str) -> tuple[str, str]:
    gg = _safe_int_hex(group_key)
    mapped = _CATEGORY_NAMES.get(gg)
    if mapped is not None:
        return mapped
    low_name = group_name.lower()
    if "water" in low_name:
        return ("hot_water", "Hot Water")
    if "zone" in low_name or "room" in low_name:
        return ("rooms", "Rooms")
    if "heat" in low_name:
        return ("heating", "Heating")
    return ("other", "Other")


def _tab_from_entry(entry: dict[str, Any]) -> BrowseTab:
    tt_kind = entry.get("tt_kind")
    if tt_kind == "parameter_config":
        return "config"
    if tt_kind == "parameter_limit":
        return "config_limits"
    return "state"


def _access_for_tab(tab: BrowseTab) -> str:
    if tab == "state":
        return "R"
    return "R/W?"


def _address_label(
    group_key: str, instance_key: str, register_key: str, read_opcode: str | None
) -> str:
    op_txt = f" {read_opcode}" if read_opcode else ""
    return f"{group_key}/{instance_key}/{register_key}{op_txt}"


@dataclass(slots=True)
class BrowseStore:
    device_label: str
    rows: list[RegisterRow]
    tree_nodes: list[TreeNodeRef]
    _row_by_id: dict[str, RegisterRow]

    @classmethod
    def from_artifact(cls, artifact: dict[str, Any]) -> BrowseStore:
        meta = artifact.get("meta")
        if not isinstance(meta, dict):
            meta = {}
        dst = meta.get("destination_address")
        dst_txt = dst if isinstance(dst, str) else "0x??"
        device_label = f"Device {dst_txt}"

        last_update_dt = _parse_timestamp(meta)
        last_update_text = (
            last_update_dt.strftime("%Y-%m-%d %H:%M:%SZ") if last_update_dt else "n/a"
        )
        age_text = "n/a"
        if last_update_dt is not None:
            age_s = max(0.0, (datetime.now(UTC) - last_update_dt).total_seconds())
            age_text = f"{age_s:.1f}s"

        rows: list[RegisterRow] = []
        tree_nodes: list[TreeNodeRef] = [
            TreeNodeRef(node_id="root", label=device_label, level="root")
        ]
        row_by_id: dict[str, RegisterRow] = {}
        groups = artifact.get("groups")
        if not isinstance(groups, dict):
            return cls(
                device_label=device_label,
                rows=[],
                tree_nodes=tree_nodes,
                _row_by_id={},
            )

        category_seen: set[str] = set()
        group_seen: set[str] = set()
        instance_seen: set[tuple[str, str]] = set()

        for group_key in sorted((k for k in groups if isinstance(k, str)), key=_safe_int_hex):
            group_obj = groups.get(group_key)
            if not isinstance(group_obj, dict):
                continue
            group_name = str(group_obj.get("name") or "Unknown")
            category_key, category_label = _category_for_group(group_key, group_name)

            if category_key not in category_seen:
                tree_nodes.append(
                    TreeNodeRef(
                        node_id=f"cat:{category_key}",
                        label=category_label,
                        level="category",
                        category_key=category_key,
                    )
                )
                category_seen.add(category_key)

            group_node_id = f"group:{group_key}"
            if group_node_id not in group_seen:
                tree_nodes.append(
                    TreeNodeRef(
                        node_id=group_node_id,
                        label=f"{group_key} {group_name}",
                        level="group",
                        category_key=category_key,
                        group_key=group_key,
                    )
                )
                group_seen.add(group_node_id)

            instances = group_obj.get("instances")
            if not isinstance(instances, dict):
                continue

            for instance_key in sorted(
                (k for k in instances if isinstance(k, str)), key=_safe_int_hex
            ):
                instance_obj = instances.get(instance_key)
                if not isinstance(instance_obj, dict):
                    continue
                if (group_key, instance_key) not in instance_seen:
                    tree_nodes.append(
                        TreeNodeRef(
                            node_id=f"inst:{group_key}:{instance_key}",
                            label=f"{instance_key}",
                            level="instance",
                            category_key=category_key,
                            group_key=group_key,
                            instance_key=instance_key,
                        )
                    )
                    instance_seen.add((group_key, instance_key))

                registers = instance_obj.get("registers")
                if not isinstance(registers, dict):
                    continue
                for register_key in sorted(
                    (k for k in registers if isinstance(k, str)),
                    key=_safe_int_hex,
                ):
                    entry = registers.get(register_key)
                    if not isinstance(entry, dict):
                        continue

                    name = (
                        str(entry.get("myvaillant_name") or "").strip()
                        or str(entry.get("ebusd_name") or "").strip()
                        or register_key
                    )
                    tab = _tab_from_entry(entry)
                    address = RegisterAddress(
                        group_key=group_key,
                        instance_key=instance_key,
                        register_key=register_key,
                        read_opcode=entry.get("read_opcode")
                        if isinstance(entry.get("read_opcode"), str)
                        else None,
                    )
                    value_text = _fmt_value(entry.get("value"))
                    raw_hex = str(entry.get("raw_hex") or "")
                    path = f"{category_label}/{group_name}/{instance_key}/{name}"
                    row_id = f"{group_key}:{instance_key}:{register_key}"
                    row = RegisterRow(
                        row_id=row_id,
                        category_key=category_key,
                        category_label=category_label,
                        group_key=group_key,
                        group_name=group_name,
                        instance_key=instance_key,
                        register_key=register_key,
                        name=name,
                        path=path,
                        tab=tab,
                        address=address,
                        value_text=value_text,
                        raw_hex=raw_hex,
                        unit="n/a",
                        access_flags=_access_for_tab(tab),
                        last_update_text=last_update_text,
                        age_text=age_text,
                        change_indicator="-",
                        search_blob=" ".join(
                            [
                                path.lower(),
                                _address_label(
                                    group_key,
                                    instance_key,
                                    register_key,
                                    address.read_opcode,
                                ).lower(),
                                value_text.lower(),
                                raw_hex.lower(),
                                tab.lower(),
                            ]
                        ),
                    )
                    rows.append(row)
                    row_by_id[row_id] = row
                    tree_nodes.append(
                        TreeNodeRef(
                            node_id=f"reg:{group_key}:{instance_key}:{register_key}",
                            label=f"{register_key} {name}",
                            level="register",
                            category_key=category_key,
                            group_key=group_key,
                            instance_key=instance_key,
                            register_key=register_key,
                        )
                    )

        rows.sort(
            key=lambda r: (
                _safe_int_hex(r.group_key),
                _safe_int_hex(r.instance_key),
                _safe_int_hex(r.register_key),
            )
        )
        return cls(
            device_label=device_label,
            rows=rows,
            tree_nodes=tree_nodes,
            _row_by_id=row_by_id,
        )

    def row_by_id(self, row_id: str) -> RegisterRow | None:
        return self._row_by_id.get(row_id)

    def rows_for_selection(self, node: TreeNodeRef | None, *, tab: BrowseTab) -> list[RegisterRow]:
        selected = [row for row in self.rows if row.tab == tab]
        if node is None or node.level == "root":
            return selected
        if node.level == "category" and node.category_key is not None:
            return [row for row in selected if row.category_key == node.category_key]
        if node.level == "group" and node.group_key is not None:
            return [row for row in selected if row.group_key == node.group_key]
        if (
            node.level == "instance"
            and node.group_key is not None
            and node.instance_key is not None
        ):
            return [
                row
                for row in selected
                if row.group_key == node.group_key and row.instance_key == node.instance_key
            ]
        if (
            node.level == "register"
            and node.group_key is not None
            and node.instance_key is not None
            and node.register_key is not None
        ):
            return [
                row
                for row in selected
                if row.group_key == node.group_key
                and row.instance_key == node.instance_key
                and row.register_key == node.register_key
            ]
        return selected
