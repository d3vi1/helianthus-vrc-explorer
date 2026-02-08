from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from ..transport.base import TransportInterface
from .director import GROUP_CONFIG, classify_groups, discover_groups
from .observer import ScanObserver
from .register import is_instance_present, scan_registers_for_instance


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def scan_b524(
    transport: TransportInterface,
    *,
    dst: int,
    ebusd_host: str | None = None,
    ebusd_port: int | None = None,
    observer: ScanObserver | None = None,
) -> dict[str, Any]:
    """Scan a VRC regulator using B524 and return a JSON-serializable artifact.

    Implements the Phase A/B/C/D algorithm described in `AGENTS.md`:
    - Phase A: group discovery via directory probes
    - Phase B: group classification via GROUP_CONFIG
    - Phase C: instance discovery for desc==1.0 groups using per-group heuristics
    - Phase D: register scan RR=0..rr_max for each present instance

    Partial scans are supported: Ctrl+C yields `meta.incomplete=true`.
    """

    start_perf = time.perf_counter()
    scan_timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    artifact: dict[str, Any] = {
        "meta": {
            "scan_timestamp": scan_timestamp,
            "scan_duration_seconds": 0.0,
            "destination_address": _hex_u8(dst),
            "schema_sources": [],
            "incomplete": False,
        },
        "groups": {},
    }
    if ebusd_host is not None:
        artifact["meta"]["ebusd_host"] = ebusd_host
    if ebusd_port is not None:
        artifact["meta"]["ebusd_port"] = ebusd_port

    incomplete_reason: str | None = None

    try:
        if observer is not None:
            observer.log(f"Starting scan dst={_hex_u8(dst)}", level="info")

        if observer is not None:
            observer.phase_start("group_discovery", total=0x100)
        discovered = discover_groups(transport, dst=dst, observer=observer)
        classified = classify_groups(discovered, observer=observer)
        if observer is not None:
            observer.phase_finish("group_discovery")
            observer.log(f"Discovered {len(classified)} groups", level="info")

        # Phase C: instance discovery (desc==1.0 groups only).
        instance_total = 0
        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            if config is None:
                continue
            if group.descriptor == 1.0:
                instance_total += int(config["ii_max"]) + 1
        if observer is not None:
            observer.phase_start("instance_discovery", total=instance_total or 1)

        for group in classified:
            group_key = _hex_u8(group.group)
            group_obj: dict[str, Any] = {
                "name": group.name,
                "descriptor_type": group.descriptor,
                "instances": {},
            }
            artifact["groups"][group_key] = group_obj

            config = GROUP_CONFIG.get(group.group)
            if config is None:
                if observer is not None:
                    observer.log(
                        f"Skipping GG=0x{group.group:02X} (no group config/ranges yet)",
                        level="warn",
                    )
                continue

            if group.descriptor != 1.0:
                # Singleton / Type 6 groups: no instance enumeration; scan II=0x00 later.
                group_obj["instances"][_hex_u8(0x00)] = {"present": True}
                continue

            ii_max = int(config["ii_max"])
            rr_max = int(config["rr_max"])
            present_count = 0
            for ii in range(0x00, ii_max + 1):
                if observer is not None:
                    observer.status(f"Probe presence GG=0x{group.group:02X} II=0x{ii:02X}")
                present = is_instance_present(
                    transport,
                    dst=dst,
                    group=group.group,
                    instance=ii,
                )
                if present:
                    present_count += 1
                group_obj["instances"][_hex_u8(ii)] = {"present": present}
                if observer is not None:
                    observer.phase_advance("instance_discovery", advance=1)

            if observer is not None:
                observer.log(
                    f"GG=0x{group.group:02X} {group.name}: present {present_count}/{ii_max + 1} "
                    f"rr_max=0x{rr_max:04X} ({rr_max + 1} regs/instance)",
                    level="info",
                )

        if observer is not None:
            observer.phase_finish("instance_discovery")

        # Phase D: register scan for all present instances.
        register_total = 0
        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            if config is None:
                continue

            rr_max = int(config["rr_max"])
            if group.descriptor == 1.0:
                group_obj = artifact["groups"][_hex_u8(group.group)]
                instances = group_obj.get("instances", {})
                present_instances = [
                    ii_key
                    for (ii_key, ii_obj) in instances.items()
                    if isinstance(ii_obj, dict) and ii_obj.get("present") is True
                ]
                register_total += len(present_instances) * (rr_max + 1)
            else:
                register_total += rr_max + 1

        if observer is not None:
            observer.phase_start("register_scan", total=register_total or 1)

        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            if config is None:
                continue
            rr_max = int(config["rr_max"])
            group_key = _hex_u8(group.group)
            group_obj = artifact["groups"][group_key]
            scanned_registers = 0
            scanned_errors = 0
            scanned_instances = 0

            if group.descriptor == 1.0:
                for instance_key, instance_obj in group_obj["instances"].items():
                    if not isinstance(instance_obj, dict):
                        continue
                    if instance_obj.get("present") is not True:
                        continue
                    ii = int(instance_key, 0)
                    registers = scan_registers_for_instance(
                        transport,
                        dst=dst,
                        group=group.group,
                        instance=ii,
                        rr_max=rr_max,
                        observer=observer,
                    )
                    instance_obj["registers"] = registers
                    scanned_instances += 1
                    scanned_registers += len(registers)
                    scanned_errors += sum(
                        1 for entry in registers.values() if entry.get("error") is not None
                    )
                if observer is not None and scanned_instances > 0:
                    observer.log(
                        f"GG=0x{group.group:02X} {group.name}: scanned {scanned_registers} "
                        f"registers across {scanned_instances} instance(s) "
                        f"(errors={scanned_errors})",
                        level="info",
                    )
                continue

            # Singleton / Type 6 groups: scan II=0x00.
            instance_key = _hex_u8(0x00)
            instance_obj = group_obj["instances"][instance_key]
            if isinstance(instance_obj, dict):
                registers = scan_registers_for_instance(
                    transport,
                    dst=dst,
                    group=group.group,
                    instance=0x00,
                    rr_max=rr_max,
                    observer=observer,
                )
                instance_obj["registers"] = registers
                scanned_instances = 1
                scanned_registers = len(registers)
                scanned_errors = sum(
                    1 for entry in registers.values() if entry.get("error") is not None
                )
                if observer is not None:
                    observer.log(
                        f"GG=0x{group.group:02X} {group.name}: scanned {scanned_registers} "
                        f"registers (errors={scanned_errors})",
                        level="info",
                    )

        if observer is not None:
            observer.phase_finish("register_scan")

    except KeyboardInterrupt:
        artifact["meta"]["incomplete"] = True
        incomplete_reason = "user_interrupt"

    artifact["meta"]["scan_duration_seconds"] = round(time.perf_counter() - start_perf, 4)
    if incomplete_reason is not None:
        artifact["meta"]["incomplete_reason"] = incomplete_reason

    return artifact


def default_output_filename(*, dst: int, scan_timestamp: str | None = None) -> str:
    """Return the default artifact file name.

    Format (per `AGENTS.md`): `b524_scan_<DST>_<ISO8601>.json`
    """

    stamp = scan_timestamp
    if stamp is None:
        stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    else:
        # "2026-02-06T19:44:24Z" -> "2026-02-06T194424Z"
        stamp = stamp.replace(":", "")

    return f"b524_scan_{_hex_u8(dst)}_{stamp}.json"
