from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from ..transport.base import TransportInterface
from .director import GROUP_CONFIG, classify_groups, discover_groups
from .register import is_instance_present, scan_registers_for_instance


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def scan_b524(
    transport: TransportInterface,
    *,
    dst: int,
    ebusd_host: str | None = None,
    ebusd_port: int | None = None,
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
        discovered = discover_groups(transport, dst=dst)
        classified = classify_groups(discovered)

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
                # Unknown group: preserve discovery info, but skip deep scan (no ranges available).
                continue

            rr_max = int(config["rr_max"])

            if group.descriptor == 1.0:
                ii_max = int(config["ii_max"])
                for ii in range(0x00, ii_max + 1):
                    instance_key = _hex_u8(ii)
                    present = is_instance_present(
                        transport,
                        dst=dst,
                        group=group.group,
                        instance=ii,
                    )
                    instance_obj: dict[str, Any] = {"present": present}
                    if present:
                        instance_obj["registers"] = scan_registers_for_instance(
                            transport,
                            dst=dst,
                            group=group.group,
                            instance=ii,
                            rr_max=rr_max,
                        )
                    group_obj["instances"][instance_key] = instance_obj
                continue

            # Singleton / Type 6 groups: no instance enumeration, but still scan II=0x00.
            instance_key = _hex_u8(0x00)
            group_obj["instances"][instance_key] = {
                "present": True,
                "registers": scan_registers_for_instance(
                    transport, dst=dst, group=group.group, instance=0x00, rr_max=rr_max
                ),
            }

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
