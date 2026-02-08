from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text


@dataclass(frozen=True, slots=True)
class _GroupStats:
    group: str
    name: str
    descriptor: float
    instances_total: int
    instances_present: int
    registers_scanned: int
    registers_errors: int


def _iter_register_entries(artifact: dict[str, Any]) -> Iterable[dict[str, Any]]:
    groups = artifact.get("groups", {})
    if not isinstance(groups, dict):
        return
    for group_obj in groups.values():
        if not isinstance(group_obj, dict):
            continue
        instances = group_obj.get("instances", {})
        if not isinstance(instances, dict):
            continue
        for instance_obj in instances.values():
            if not isinstance(instance_obj, dict):
                continue
            registers = instance_obj.get("registers")
            if not isinstance(registers, dict):
                continue
            for entry in registers.values():
                if isinstance(entry, dict):
                    yield entry


def _compute_group_stats(artifact: dict[str, Any]) -> list[_GroupStats]:
    stats: list[_GroupStats] = []
    groups = artifact.get("groups", {})
    if not isinstance(groups, dict):
        return stats

    for group_key, group_obj in groups.items():
        if not isinstance(group_key, str) or not isinstance(group_obj, dict):
            continue
        name = str(group_obj.get("name") or "Unknown")
        descriptor = float(group_obj.get("descriptor_type") or 0.0)

        instances = group_obj.get("instances", {})
        if not isinstance(instances, dict):
            instances = {}

        instances_total = len(instances)
        instances_present = 0
        registers_scanned = 0
        registers_errors = 0

        for instance_obj in instances.values():
            if not isinstance(instance_obj, dict):
                continue
            if instance_obj.get("present") is True:
                instances_present += 1
            registers = instance_obj.get("registers", {})
            if not isinstance(registers, dict):
                continue
            registers_scanned += len(registers)
            for entry in registers.values():
                if not isinstance(entry, dict):
                    continue
                if entry.get("error") is not None:
                    registers_errors += 1

        stats.append(
            _GroupStats(
                group=group_key,
                name=name,
                descriptor=descriptor,
                instances_total=instances_total,
                instances_present=instances_present,
                registers_scanned=registers_scanned,
                registers_errors=registers_errors,
            )
        )

    stats.sort(key=lambda s: int(s.group, 0))
    return stats


def render_summary(console: Console, artifact: dict[str, Any], *, output_path: Path) -> None:
    meta = artifact.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    dst = meta.get("destination_address", "0x??")
    duration = meta.get("scan_duration_seconds")
    incomplete = bool(meta.get("incomplete", False))
    incomplete_reason = meta.get("incomplete_reason")

    title = Text("Scan Summary", style="bold")
    console.print()
    console.print(title)

    header = f"dst={dst}"
    if isinstance(duration, (int, float)) and not isinstance(duration, bool):
        header += f" duration={duration:.3f}s"
    if incomplete:
        header += " incomplete=true"
        if isinstance(incomplete_reason, str) and incomplete_reason:
            header += f" reason={incomplete_reason}"
    console.print(header, style="dim")

    group_stats = _compute_group_stats(artifact)
    total_regs = sum(s.registers_scanned for s in group_stats)
    total_errs = sum(s.registers_errors for s in group_stats)

    console.print(
        f"groups={len(group_stats)} registers={total_regs} errors={total_errs}", style="dim"
    )

    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Group", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Desc", style="white", justify="right", no_wrap=True)
    table.add_column("Instances", style="white", justify="right", no_wrap=True)
    table.add_column("Registers", style="white", justify="right", no_wrap=True)
    table.add_column("Errors", style="white", justify="right", no_wrap=True)

    for s in group_stats:
        instances = (
            f"{s.instances_present}/{s.instances_total}"
            if s.instances_total > 0
            else str(s.instances_present)
        )
        table.add_row(
            s.group,
            s.name,
            f"{s.descriptor:g}",
            instances,
            str(s.registers_scanned),
            str(s.registers_errors),
        )

    console.print(table)
    console.print(f"artifact={output_path}", style="dim")
