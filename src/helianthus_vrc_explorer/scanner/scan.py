from __future__ import annotations

import contextlib
import math
import os
import sys
import time
from collections import deque
from datetime import UTC, datetime
from typing import Any, Literal

from rich.console import Console

from ..protocol.b524 import RegisterOpcode
from ..schema.ebusd_csv import EbusdCsvSchema
from ..schema.myvaillant_map import MyvaillantRegisterMap
from ..transport.base import TransportInterface, emit_trace_label
from ..transport.instrumented import CountingTransport
from ..ui.planner import PlannerGroup, PlannerPreset, build_plan_from_preset, prompt_scan_plan
from .b509 import scan_b509
from .director import GROUP_CONFIG, classify_groups, discover_groups
from .observer import ScanObserver
from .plan import GroupScanPlan, RegisterTask, build_work_queue, estimate_register_requests
from .register import RegisterEntry, is_instance_present, opcode_for_group, read_register


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


_LOCAL_REGISTER_OPCODE: RegisterOpcode = 0x02
_REMOTE_REGISTER_OPCODE: RegisterOpcode = 0x06

PlannerUiMode = Literal["auto", "textual", "classic"]
_KNOWN_DESCRIPTOR_TYPES = frozenset(float(config["desc"]) for config in GROUP_CONFIG.values())


def _entry_has_valid_value(entry: RegisterEntry) -> bool:
    """Return True when a register read produced a meaningful value.

    Used for opcode selection (0x02 vs 0x06) in ambiguous cases.
    """

    if entry.get("error") is not None:
        return False
    if entry.get("tt_kind") == "no_data":
        return False
    raw_hex = entry.get("raw_hex")
    if raw_hex in (None, ""):
        return False
    value = entry.get("value")
    if value is None:
        return False
    return not (isinstance(value, float) and math.isnan(value))


def _resolve_planner_mode(
    *,
    interactive: bool,
    planner_ui: PlannerUiMode,
    observer: ScanObserver | None,
) -> Literal["disabled", "textual", "classic"]:
    if not interactive:
        return "disabled"
    if planner_ui == "classic":
        return "classic"
    if planner_ui == "textual":
        return "textual"
    try:
        import textual  # noqa: F401, PLC0415
    except Exception:
        if observer is not None:
            observer.log("Textual UI unavailable; falling back to classic planner.", level="warn")
        return "classic"
    return "textual"


class _PlannerHotkeyReader(contextlib.AbstractContextManager["_PlannerHotkeyReader"]):
    """Best-effort single-key planner hotkey reader (`p`) for POSIX terminals."""

    def __init__(self, *, enabled: bool) -> None:
        self._enabled = enabled
        self._active = False
        self._fd: int | None = None
        self._old_termios: Any = None

    def __enter__(self) -> _PlannerHotkeyReader:
        self._activate()
        return self

    def _activate(self) -> None:
        if not self._enabled or sys.platform == "win32" or not sys.stdin.isatty():
            return
        if self._active:
            return
        try:
            import termios  # noqa: PLC0415
            import tty  # noqa: PLC0415

            fd = sys.stdin.fileno()
            self._old_termios = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            self._fd = fd
            self._active = True
        except Exception:
            self._active = False

    def _deactivate(self) -> None:
        if not self._active or self._fd is None:
            return
        fd = self._fd
        self._fd = None
        self._active = False
        try:
            import termios  # noqa: PLC0415

            if self._old_termios is not None:
                termios.tcsetattr(fd, termios.TCSADRAIN, self._old_termios)
        except Exception:
            pass

    def __exit__(self, *_exc: object) -> None:
        self._deactivate()
        return None

    def poll(self) -> bool:
        if not self._active or self._fd is None:
            return False
        try:
            import select  # noqa: PLC0415

            ready, _w, _x = select.select([sys.stdin], [], [], 0.0)
            if not ready:
                return False
            raw = os.read(self._fd, 1)
        except (OSError, ValueError):
            return False
        if not raw:
            return False
        ch = raw.decode("utf-8", errors="ignore").lower()
        return ch == "p"

    @contextlib.contextmanager
    def suspend(self) -> Any:
        was_active = self._active
        if was_active:
            self._deactivate()
        try:
            yield None
        finally:
            if was_active:
                self._activate()


def scan_b524(
    transport: TransportInterface,
    *,
    dst: int,
    ebusd_host: str | None = None,
    ebusd_port: int | None = None,
    ebusd_schema: EbusdCsvSchema | None = None,
    myvaillant_map: MyvaillantRegisterMap | None = None,
    observer: ScanObserver | None = None,
    console: Console | None = None,
    planner_ui: PlannerUiMode = "auto",
    planner_preset: PlannerPreset = "recommended",
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
        emit_trace_label(transport, f"Starting scan dst={_hex_u8(dst)}")

        group_discovery_requests = 0
        group_discovery_duration_s = 0.0
        instance_discovery_requests = 0
        instance_discovery_duration_s = 0.0

        if observer is not None:
            observer.phase_start("group_discovery", total=0x100)
        emit_trace_label(transport, "Discovering Groups")
        group_discovery_start = time.perf_counter()
        group_discovery_start_calls = counting_transport.counters.send_calls
        discovered = discover_groups(transport, dst=dst, observer=observer)
        group_discovery_duration_s = time.perf_counter() - group_discovery_start
        group_discovery_requests = (
            counting_transport.counters.send_calls - group_discovery_start_calls
        )
        classified = classify_groups(discovered, observer=observer)
        unknown_groups = sorted(
            group.group for group in classified if group.group not in GROUP_CONFIG
        )
        unknown_descriptor_types = sorted(
            {
                float(group.descriptor)
                for group in classified
                if float(group.descriptor) not in _KNOWN_DESCRIPTOR_TYPES
            }
        )
        if unknown_groups and observer is not None:
            unknown_text = ", ".join(f"0x{gg:02X}" for gg in unknown_groups)
            observer.log(
                f"Found {len(unknown_groups)} unknown groups ({unknown_text}); "
                "skipped by default (enable in planner).",
                level="warn",
            )
        if unknown_descriptor_types and observer is not None:
            descriptor_text = ", ".join(f"{value:g}" for value in unknown_descriptor_types)
            observer.log(
                "Found new descriptor class(es): "
                f"{descriptor_text}. Continue scan, then report with artifact JSON/HTML.",
                level="warn",
            )
        if unknown_groups or unknown_descriptor_types:
            advisory: dict[str, Any] = {
                "kind": "protocol_discovery",
                "suggest_issue": True,
                "attach_artifacts": ["scan_json", "scan_html"],
            }
            if unknown_groups:
                advisory["unknown_groups"] = [f"0x{group:02X}" for group in unknown_groups]
            if unknown_descriptor_types:
                advisory["unknown_descriptor_types"] = unknown_descriptor_types
            artifact["meta"]["issue_suggestion"] = advisory
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
            if group.descriptor == 1.0:
                emit_trace_label(
                    transport,
                    f"Identifying instances in group 0x{group.group:02X}",
                )
            group_key = _hex_u8(group.group)
            group_obj: dict[str, Any] = {
                "name": group.name,
                "descriptor_type": group.descriptor,
                "instances": {},
            }
            artifact["groups"][group_key] = group_obj

            config = GROUP_CONFIG.get(group.group)
            if config is None:
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
                    group_obj["instances"][_hex_u8(ii)] = {"present": True}
                if observer is not None:
                    observer.phase_advance("instance_discovery", advance=1)

            if observer is not None:
                observer.log(
                    f"GG=0x{group.group:02X} {group.name}: "
                    f"{present_count}/{ii_max + 1} present, "
                    f"RR_max=0x{rr_max:04X} ({rr_max + 1} registers/instance)",
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
                present_instances_for_plan: list[int] = []
                for ii_key, ii_obj in group_obj.get("instances", {}).items():
                    if not isinstance(ii_obj, dict):
                        continue
                    if ii_obj.get("present") is True:
                        present_instances_for_plan.append(int(ii_key, 0))
                plan[group.group] = GroupScanPlan(
                    group=group.group,
                    rr_max=rr_max,
                    instances=tuple(sorted(present_instances_for_plan)),
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
        planner_mode = _resolve_planner_mode(
            interactive=interactive,
            planner_ui=planner_ui,
            observer=observer,
        )
        planner_groups: list[PlannerGroup] = []
        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            if config is None:
                rr_max_default = 0x30
                ii_max_default: int | None
                present_instances_default: tuple[int, ...]
                if group.descriptor == 1.0:
                    ii_max_default = 0x0A
                    present_instances_default = tuple(range(0x00, 0x0A + 1))
                else:
                    ii_max_default = None
                    present_instances_default = (0x00,)
                planner_groups.append(
                    PlannerGroup(
                        group=group.group,
                        name=group.name,
                        descriptor=group.descriptor,
                        known=False,
                        ii_max=ii_max_default,
                        rr_max=rr_max_default,
                        present_instances=present_instances_default,
                    )
                )
                continue

            group_obj = artifact["groups"][_hex_u8(group.group)]
            if group.descriptor == 1.0:
                ii_max = int(config["ii_max"])
                present_instances_for_planner: list[int] = [
                    int(ii_key, 0)
                    for (ii_key, ii_obj) in group_obj.get("instances", {}).items()
                    if isinstance(ii_obj, dict) and ii_obj.get("present") is True
                ]
                planner_groups.append(
                    PlannerGroup(
                        group=group.group,
                        name=group.name,
                        descriptor=group.descriptor,
                        known=True,
                        ii_max=ii_max,
                        rr_max=int(config["rr_max"]),
                        present_instances=tuple(sorted(present_instances_for_planner)),
                    )
                )
            else:
                planner_groups.append(
                    PlannerGroup(
                        group=group.group,
                        name=group.name,
                        descriptor=group.descriptor,
                        known=True,
                        ii_max=None,
                        rr_max=int(config["rr_max"]),
                        present_instances=(0x00,),
                    )
                )

        if planner_preset != "custom":
            plan = build_plan_from_preset(
                planner_groups,
                preset=planner_preset,
            )

        if planner_mode != "disabled" and console is not None and observer is not None:
            with observer.suspend():
                planner_default_plan = dict(plan)
                if planner_mode == "textual":
                    try:
                        from ..ui.planner_textual import run_textual_scan_plan
                    except Exception as exc:
                        if planner_ui == "textual":
                            raise RuntimeError(
                                "Textual planner requested but unavailable."
                            ) from exc
                        observer.log(
                            "Textual planner unavailable; falling back to classic planner.",
                            level="warn",
                        )
                        planner_mode = "classic"
                    else:
                        try:
                            selected = run_textual_scan_plan(
                                planner_groups,
                                request_rate_rps=request_rate_rps,
                                default_plan=planner_default_plan,
                                default_preset=planner_preset,
                            )
                        except Exception as exc:
                            if planner_ui == "textual":
                                raise RuntimeError(
                                    "Textual planner requested but failed to start."
                                ) from exc
                            observer.log(
                                "Textual planner failed to start; falling back to classic planner.",
                                level="warn",
                            )
                            planner_mode = "classic"
                        else:
                            if selected is None:
                                raise KeyboardInterrupt
                            plan = selected
                if planner_mode == "classic":
                    plan = prompt_scan_plan(
                        console,
                        planner_groups,
                        request_rate_rps=request_rate_rps,
                        default_plan=planner_default_plan,
                        default_preset=planner_preset,
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
        emit_trace_label(transport, "Register Scan")

        active_start = time.perf_counter()
        active_elapsed = 0.0

        with _PlannerHotkeyReader(enabled=(planner_mode != "disabled")) as hotkeys:
            while work_queue:
                if (
                    planner_mode != "disabled"
                    and console is not None
                    and observer is not None
                    and hotkeys.poll()
                ):
                    # Pause progress rendering and allow replanning without rewriting scanned data.
                    active_elapsed += time.perf_counter() - active_start
                    with hotkeys.suspend(), observer.suspend():
                        if planner_mode == "textual":
                            try:
                                from ..ui.planner_textual import run_textual_scan_plan
                            except Exception as exc:
                                if planner_ui == "textual":
                                    raise RuntimeError(
                                        "Textual planner requested but unavailable."
                                    ) from exc
                                observer.log(
                                    "Textual planner unavailable; falling back to classic planner.",
                                    level="warn",
                                )
                                planner_mode = "classic"
                            else:
                                try:
                                    selected = run_textual_scan_plan(
                                        planner_groups,
                                        request_rate_rps=request_rate_rps,
                                        default_plan=plan,
                                        default_preset=planner_preset,
                                    )
                                except Exception as exc:
                                    if planner_ui == "textual":
                                        raise RuntimeError(
                                            "Textual planner requested but failed to start."
                                        ) from exc
                                    observer.log(
                                        "Textual planner failed to start; "
                                        "falling back to classic planner.",
                                        level="warn",
                                    )
                                    planner_mode = "classic"
                                else:
                                    if selected is None:
                                        raise KeyboardInterrupt
                                    plan = selected
                        if planner_mode == "classic":
                            plan = prompt_scan_plan(
                                console,
                                planner_groups,
                                request_rate_rps=request_rate_rps,
                                default_plan=plan,
                                default_preset=planner_preset,
                            )
                    artifact["meta"]["scan_plan"]["groups"] = {
                        _hex_u8(gg): gp.to_meta() for (gg, gp) in sorted(plan.items())
                    }
                    artifact["meta"]["scan_plan"]["estimated_register_requests"] = (
                        estimate_register_requests(plan)
                    )
                    work_queue = deque(build_work_queue(plan, done=done))
                    observer.phase_set_total(
                        "register_scan",
                        total=(len(done) + len(work_queue)) or 1,
                    )
                    remaining = len(work_queue)
                    task_rate_rps = (len(done) / active_elapsed) if active_elapsed > 0 else None
                    if task_rate_rps is None or task_rate_rps <= 0:
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
                if observer is not None:
                    observer.status(
                        "Read "
                        f"GG=0x{task.group:02X} "
                        f"II=0x{task.instance:02X} "
                        f"RR=0x{task.register:04X}"
                    )
                    observer.phase_advance("register_scan", advance=1)

                # Some groups are ambiguous and may respond to either opcode family (0x02 vs 0x06).
                # When in doubt (unknown group), probe both but keep only the best/most-meaningful
                # reply in the artifact.
                opcodes_to_try: tuple[RegisterOpcode, ...]
                if task.group in GROUP_CONFIG:
                    opcodes_to_try = (opcode_for_group(task.group),)
                else:
                    opcodes_to_try = (_LOCAL_REGISTER_OPCODE, _REMOTE_REGISTER_OPCODE)

                best_entry: RegisterEntry | None = None
                best_quality = -1
                for opcode in opcodes_to_try:
                    schema_entry = (
                        ebusd_schema.lookup(
                            opcode=opcode,
                            group=task.group,
                            instance=task.instance,
                            register=task.register,
                        )
                        if ebusd_schema is not None
                        else None
                    )
                    type_hint = schema_entry.type_spec if schema_entry is not None else None

                    candidate = read_register(
                        transport,
                        dst,
                        opcode,
                        group=task.group,
                        instance=task.instance,
                        register=task.register,
                        type_hint=type_hint,
                    )
                    if schema_entry is not None:
                        candidate["ebusd_name"] = schema_entry.name

                    # Prefer a meaningful value over status-only / no_data replies; otherwise prefer
                    # a clean reply (no error) over transport/decode failures.
                    quality = (
                        2
                        if _entry_has_valid_value(candidate)
                        else (1 if candidate["error"] is None else 0)
                    )
                    if quality > best_quality:
                        best_entry = candidate
                        best_quality = quality
                    if quality == 2:
                        break

                assert best_entry is not None
                entry = best_entry
                if myvaillant_map is not None:
                    mv = myvaillant_map.lookup(
                        group=task.group,
                        instance=task.instance,
                        register=task.register,
                    )
                    if mv is not None:
                        entry["myvaillant_name"] = mv.leaf
                        if entry.get("ebusd_name") is None:
                            mapped_ebusd_name = mv.resolved_ebusd_name(
                                group=task.group,
                                instance=task.instance,
                                register=task.register,
                            )
                            if mapped_ebusd_name:
                                entry["ebusd_name"] = mapped_ebusd_name
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


def scan_vrc(
    transport: TransportInterface,
    *,
    dst: int,
    b509_ranges: list[tuple[int, int]],
    ebusd_host: str | None = None,
    ebusd_port: int | None = None,
    ebusd_schema: EbusdCsvSchema | None = None,
    myvaillant_map: MyvaillantRegisterMap | None = None,
    observer: ScanObserver | None = None,
    console: Console | None = None,
    planner_ui: PlannerUiMode = "auto",
    planner_preset: PlannerPreset = "recommended",
) -> dict[str, Any]:
    """Run the full VRC scan flow: B524 primary scan, then B509 register dump."""

    artifact = scan_b524(
        transport,
        dst=dst,
        ebusd_host=ebusd_host,
        ebusd_port=ebusd_port,
        ebusd_schema=ebusd_schema,
        myvaillant_map=myvaillant_map,
        observer=observer,
        console=console,
        planner_ui=planner_ui,
        planner_preset=planner_preset,
    )
    meta = artifact.get("meta")
    if isinstance(meta, dict) and bool(meta.get("incomplete", False)):
        return artifact

    scan_fn = getattr(transport, "send_proto", None)
    if not callable(scan_fn):
        return artifact

    b509_dump = scan_b509(
        transport,  # type: ignore[arg-type]
        dst=dst,
        ranges=b509_ranges,
        ebusd_schema=ebusd_schema,
        observer=observer,
    )
    artifact["b509_dump"] = b509_dump

    b509_meta = b509_dump.get("meta", {})
    if isinstance(b509_meta, dict) and bool(b509_meta.get("incomplete")) and isinstance(meta, dict):
        meta["incomplete"] = True
        if "incomplete_reason" not in meta:
            reason = b509_meta.get("incomplete_reason")
            if isinstance(reason, str):
                meta["incomplete_reason"] = f"b509_{reason}"

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
