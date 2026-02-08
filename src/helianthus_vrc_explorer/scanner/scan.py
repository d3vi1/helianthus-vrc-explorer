from __future__ import annotations

import sys
import time
from datetime import UTC, datetime
from typing import Any

from rich.console import Console

from ..transport.base import TransportInterface
from ..transport.instrumented import CountingTransport
from ..ui.planner import PlannerGroup, prompt_scan_plan
from .director import GROUP_CONFIG, classify_groups, discover_groups
from .observer import ScanObserver
from .plan import GroupScanPlan, estimate_register_requests
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
    console: Console | None = None,
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

    counting_transport = CountingTransport(transport)
    transport = counting_transport

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

        group_discovery_requests = 0
        group_discovery_duration_s = 0.0
        instance_discovery_requests = 0
        instance_discovery_duration_s = 0.0

        if observer is not None:
            observer.phase_start("group_discovery", total=0x100)
        group_discovery_start = time.perf_counter()
        group_discovery_start_calls = counting_transport.counters.send_calls
        discovered = discover_groups(transport, dst=dst, observer=observer)
        group_discovery_duration_s = time.perf_counter() - group_discovery_start
        group_discovery_requests = (
            counting_transport.counters.send_calls - group_discovery_start_calls
        )
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

        instance_discovery_start = time.perf_counter()
        instance_discovery_start_calls = counting_transport.counters.send_calls
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
        instance_discovery_duration_s = time.perf_counter() - instance_discovery_start
        instance_discovery_requests = (
            counting_transport.counters.send_calls - instance_discovery_start_calls
        )

        # Interactive scan planner (TTY only): allow users to trim the register scan scope.
        plan: dict[int, GroupScanPlan] = {}
        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            if config is None:
                continue
            rr_max = int(config["rr_max"])

            group_obj = artifact["groups"][_hex_u8(group.group)]
            if group.descriptor == 1.0:
                present_instances: list[int] = []
                for ii_key, ii_obj in group_obj.get("instances", {}).items():
                    if not isinstance(ii_obj, dict):
                        continue
                    if ii_obj.get("present") is True:
                        present_instances.append(int(ii_key, 0))
                plan[group.group] = GroupScanPlan(
                    group=group.group,
                    rr_max=rr_max,
                    instances=tuple(sorted(present_instances)),
                )
            else:
                plan[group.group] = GroupScanPlan(
                    group=group.group,
                    rr_max=rr_max,
                    instances=(0x00,),
                )

        measured_requests = group_discovery_requests + instance_discovery_requests
        measured_duration_s = group_discovery_duration_s + instance_discovery_duration_s
        request_rate_rps: float | None = None
        if measured_requests > 0 and measured_duration_s > 0:
            request_rate_rps = measured_requests / measured_duration_s

        interactive = (
            console is not None
            and console.is_terminal
            and sys.stdin.isatty()
            and observer is not None
        )
        if interactive and console is not None and observer is not None:
            planner_groups: list[PlannerGroup] = []
            for group in classified:
                config = GROUP_CONFIG.get(group.group)
                if config is None:
                    continue
                group_obj = artifact["groups"][_hex_u8(group.group)]
                if group.descriptor == 1.0:
                    ii_max = int(config["ii_max"])
                    present: list[int] = [
                        int(ii_key, 0)
                        for (ii_key, ii_obj) in group_obj.get("instances", {}).items()
                        if isinstance(ii_obj, dict) and ii_obj.get("present") is True
                    ]
                    planner_groups.append(
                        PlannerGroup(
                            group=group.group,
                            name=group.name,
                            descriptor=group.descriptor,
                            ii_max=ii_max,
                            rr_max=int(config["rr_max"]),
                            present_instances=tuple(sorted(present)),
                        )
                    )
                else:
                    planner_groups.append(
                        PlannerGroup(
                            group=group.group,
                            name=group.name,
                            descriptor=group.descriptor,
                            ii_max=None,
                            rr_max=int(config["rr_max"]),
                            present_instances=(0x00,),
                        )
                    )
            with observer.suspend():
                plan = prompt_scan_plan(console, planner_groups, request_rate_rps=request_rate_rps)

        artifact["meta"]["scan_plan"] = {
            "groups": {_hex_u8(gg): gp.to_meta() for (gg, gp) in sorted(plan.items())},
            "estimated_register_requests": estimate_register_requests(plan),
            "measured_request_rate_rps": round(request_rate_rps, 4) if request_rate_rps else None,
        }

        # Phase D: register scan for all present instances.
        register_total = estimate_register_requests(plan)

        if observer is not None:
            observer.phase_start("register_scan", total=register_total or 1)

        for group in classified:
            group_plan = plan.get(group.group)
            if group_plan is None:
                continue
            rr_max = group_plan.rr_max
            group_key = _hex_u8(group.group)
            group_obj = artifact["groups"][group_key]
            scanned_registers = 0
            scanned_errors = 0
            scanned_instances = 0

            if group.descriptor == 1.0:
                for ii in group_plan.instances:
                    instance_key = _hex_u8(ii)
                    instance_obj = group_obj["instances"].get(instance_key)
                    if not isinstance(instance_obj, dict):
                        continue
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
