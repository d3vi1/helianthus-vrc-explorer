from __future__ import annotations

import logging
import math
import struct
from dataclasses import dataclass
from typing import Final, TypedDict

from ..protocol.b524 import build_directory_probe_payload
from ..transport.base import TransportInterface

logger = logging.getLogger(__name__)


class GroupConfig(TypedDict):
    desc: float
    name: str
    ii_max: int
    rr_max: int


# Known groups (hardcoded reference, validated against CSV).
# Source of truth: `AGENTS.md` (keep in sync).
GROUP_CONFIG: Final[dict[int, GroupConfig]] = {
    0x00: {"desc": 3.0, "name": "Discovery", "ii_max": 0x00, "rr_max": 0xFF},
    0x01: {"desc": 3.0, "name": "Regulator Parameters", "ii_max": 0x00, "rr_max": 0x8F},
    0x02: {"desc": 1.0, "name": "Heating Circuits", "ii_max": 0x0A, "rr_max": 0x21},
    0x03: {"desc": 1.0, "name": "Zones", "ii_max": 0x0A, "rr_max": 0x2F},
    0x04: {"desc": 6.0, "name": "Solar Circuit", "ii_max": 0x0A, "rr_max": 0x40},
    0x09: {"desc": 1.0, "name": "RoomState", "ii_max": 0x2F, "rr_max": 0x1F},
    0x0A: {"desc": 1.0, "name": "RoomSensors", "ii_max": 0x2F, "rr_max": 0x4F},
    0x0C: {"desc": 1.0, "name": "Unrecognized", "ii_max": 0x2F, "rr_max": 0x4F},
}


@dataclass(frozen=True, slots=True)
class DiscoveredGroup:
    group: int
    descriptor: float


@dataclass(frozen=True, slots=True)
class ClassifiedGroup:
    group: int
    descriptor: float
    name: str
    expected_descriptor: float | None
    descriptor_mismatch: bool


def _parse_directory_descriptor(resp: bytes, group: int) -> float:
    if len(resp) < 4:
        logger.warning(
            "Short directory probe response for GG=0x%02X: expected >=4 bytes, got %d",
            group,
            len(resp),
        )
        return float("nan")
    return struct.unpack("<f", resp[:4])[0]


def discover_groups(transport: TransportInterface, dst: int) -> list[DiscoveredGroup]:
    """Phase A: Probe GG=0x00..0xFF via directory probe (opcode 0x00).

    Terminator logic: stop after 2 consecutive NaN descriptors.
    Holes (descriptor==0.0) are skipped.
    """

    discovered: list[DiscoveredGroup] = []
    nan_streak = 0

    for gg in range(0x00, 0x100):
        payload = build_directory_probe_payload(gg)
        resp = transport.send(dst, payload)
        descriptor = _parse_directory_descriptor(resp, gg)

        if descriptor == 0.0:
            # Hole: skip without resetting the NaN streak.
            continue

        if math.isnan(descriptor):
            nan_streak += 1
            if nan_streak >= 2:
                logger.info("Directory terminator after GG=0x%02X (NaN streak=%d)", gg, nan_streak)
                break
            continue

        nan_streak = 0
        discovered.append(DiscoveredGroup(group=gg, descriptor=descriptor))

    return discovered


def classify_groups(discovered: list[DiscoveredGroup]) -> list[ClassifiedGroup]:
    """Phase C (per issue wording): Map discovered groups using GROUP_CONFIG.

    Emits a warning when a known group's descriptor doesn't match `GROUP_CONFIG`.
    """

    classified: list[ClassifiedGroup] = []
    for group in discovered:
        config = GROUP_CONFIG.get(group.group)
        if config is None:
            classified.append(
                ClassifiedGroup(
                    group=group.group,
                    descriptor=group.descriptor,
                    name="Unknown",
                    expected_descriptor=None,
                    descriptor_mismatch=False,
                )
            )
            continue

        expected = config["desc"]
        mismatch = expected != group.descriptor
        if mismatch:
            logger.warning(
                "Descriptor mismatch for GG=0x%02X: expected %s, got %s",
                group.group,
                expected,
                group.descriptor,
            )
        classified.append(
            ClassifiedGroup(
                group=group.group,
                descriptor=group.descriptor,
                name=config["name"],
                expected_descriptor=expected,
                descriptor_mismatch=mismatch,
            )
        )

    return classified
