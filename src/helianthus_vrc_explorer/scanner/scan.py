from __future__ import annotations

import sys
import time
from collections import deque
from datetime import UTC, datetime
from typing import Any

from rich.console import Console

from ..transport.base import TransportInterface
from ..transport.instrumented import CountingTransport
from ..ui.planner import PlannerGroup, prompt_scan_plan
from .director import GROUP_CONFIG, classify_groups, discover_groups
from .observer import ScanObserver
from .plan import GroupScanPlan, RegisterTask, build_work_queue, estimate_register_requests
from .register import is_instance_present, opcode_for_group, read_register


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


def _poll_planner_hotkey() -> bool:
    """Best-effort interactive hotkey: type 'p' + Enter to open the planner."""

    if not sys.stdin.isatty():
        return False
    if sys.platform == "win32":
        return False

    try:
        import select  # noqa: PLC0415

        ready, _w, _x = select.select([sys.stdin], [], [], 0.0)
    except (OSError, ValueError):
        return False

    if not ready:
        return False

    raw = sys.stdin.readline()
    cmd = raw.strip().lower()
    return cmd in {"p", "plan", ":p", ":plan"}


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
                is_present = is_instance_present(
                    transport,
                    dst=dst,
                    group=group.group,
                    instance=ii,
                )
                if is_present:
                    present_count += 1
                group_obj["instances"][_hex_u8(ii)] = {"present": is_present}
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
        planner_groups: list[PlannerGroup] = []
        if interactive and console is not None and observer is not None:
            for group in classified:
                config = GROUP_CONFIG.get(group.group)
                if config is None:
                    continue
                group_obj = artifact["groups"][_hex_u8(group.group)]
                if group.descriptor == 1.0:
                    ii_max = int(config["ii_max"])
                    present_instances_list: list[int] = [
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
                            present_instances=tuple(sorted(present_instances_list)),
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
                plan = prompt_scan_plan(
                    console,
                    planner_groups,
                    request_rate_rps=request_rate_rps,
                    default_plan=plan,
                )

        artifact["meta"]["scan_plan"] = {
            "groups": {_hex_u8(gg): gp.to_meta() for (gg, gp) in sorted(plan.items())},
            "estimated_register_requests": estimate_register_requests(plan),
            "measured_request_rate_rps": round(request_rate_rps, 4) if request_rate_rps else None,
        }

        # Phase D: register scan (supports interactive replanning).
        done: set[RegisterTask] = set()
        work_queue = deque(build_work_queue(plan, done=done))
        if observer is not None:
            observer.phase_start("register_scan", total=len(work_queue) or 1)

        active_start = time.perf_counter()
        active_elapsed = 0.0

        while work_queue:
            if (
                interactive
                and console is not None
                and observer is not None
                and _poll_planner_hotkey()
            ):
                # Pause progress rendering and allow replanning without rewriting scanned data.
                active_elapsed += time.perf_counter() - active_start
                with observer.suspend():
                    plan = prompt_scan_plan(
                        console,
                        planner_groups,
                        request_rate_rps=request_rate_rps,
                        default_plan=plan,
                    )
                artifact["meta"]["scan_plan"]["groups"] = {
                    _hex_u8(gg): gp.to_meta() for (gg, gp) in sorted(plan.items())
                }
                artifact["meta"]["scan_plan"]["estimated_register_requests"] = (
                    estimate_register_requests(plan)
                )
                work_queue = deque(build_work_queue(plan, done=done))
                observer.phase_set_total("register_scan", total=(len(done) + len(work_queue)) or 1)
                remaining = len(work_queue)
                task_rate_rps = (len(done) / active_elapsed) if active_elapsed > 0 else None
                if task_rate_rps is None:
                    observer.log(
                        f"Updated scan plan: remaining {remaining} register reads",
                        level="info",
                    )
                else:
                    eta_s = remaining / task_rate_rps if remaining > 0 else 0.0
                    observer.log(
                        f"Updated scan plan: remaining {remaining} register reads "
                        f"(ETA {eta_s:.1f}s @ {task_rate_rps:.2f} rr/s)",
                        level="info",
                    )
                active_start = time.perf_counter()
                continue

            task = work_queue.popleft()
            opcode = opcode_for_group(task.group)
            if observer is not None:
                if task.register % 8 == 0:
                    observer.status(
                        f"Read GG=0x{task.group:02X} II=0x{task.instance:02X} "
                        f"RR=0x{task.register:04X}"
                    )
                observer.phase_advance("register_scan", advance=1)

            entry = read_register(
                transport,
                dst,
                opcode,
                group=task.group,
                instance=task.instance,
                register=task.register,
            )
            done.add(task)

            group_key = _hex_u8(task.group)
            group_obj = artifact["groups"].setdefault(
                group_key,
                {"name": "Unknown", "descriptor_type": None, "instances": {}},
            )
            instances_obj = group_obj.setdefault("instances", {})
            instance_key = _hex_u8(task.instance)
            instance_obj = instances_obj.setdefault(instance_key, {"present": False})
            if isinstance(instance_obj, dict):
                registers = instance_obj.setdefault("registers", {})
                registers[_hex_u16(task.register)] = entry

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
