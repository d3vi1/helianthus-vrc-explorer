from __future__ import annotations

import string
from dataclasses import dataclass

_HEX_DIGITS = set(string.hexdigits)


def parse_int_token(token: str) -> int:
    """Parse an integer token.

    Accepts:
    - decimal digits (e.g. "10")
    - 0x-prefixed hex (e.g. "0x0A")
    - bare hex with A-F (e.g. "0A")
    """

    raw = token.strip()
    if not raw:
        raise ValueError("Empty integer token")

    lowered = raw.lower()
    if lowered.startswith("0x"):
        return int(lowered, 16)
    if raw.isdigit():
        return int(raw, 10)
    if all(ch in _HEX_DIGITS for ch in raw):
        return int(raw, 16)
    raise ValueError(f"Invalid integer token: {token!r}")


def parse_int_set(spec: str, *, min_value: int, max_value: int) -> list[int]:
    """Parse a comma-separated set of ints and ranges.

    Example inputs:
    - "0-10"
    - "0,2,5"
    - "0-3,7,9-10"
    """

    if min_value > max_value:
        raise ValueError("min_value must be <= max_value")

    result: set[int] = set()
    raw = spec.strip()
    if not raw:
        raise ValueError("Empty set specification")

    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start = parse_int_token(start_s)
            end = parse_int_token(end_s)
            if start > end:
                start, end = end, start
            for value in range(start, end + 1):
                if value < min_value or value > max_value:
                    raise ValueError(
                        f"Value out of range: {value} (allowed {min_value}-{max_value})"
                    )
                result.add(value)
            continue

        value = parse_int_token(token)
        if value < min_value or value > max_value:
            raise ValueError(f"Value out of range: {value} (allowed {min_value}-{max_value})")
        result.add(value)

    return sorted(result)


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


@dataclass(frozen=True, slots=True)
class GroupScanPlan:
    group: int
    rr_max: int
    instances: tuple[int, ...]

    def to_meta(self) -> dict[str, object]:
        return {
            "rr_max": _hex_u16(self.rr_max),
            "instances": [_hex_u8(ii) for ii in self.instances],
        }


def estimate_register_requests(plan: dict[int, GroupScanPlan]) -> int:
    total = 0
    for group_plan in plan.values():
        total += len(group_plan.instances) * (group_plan.rr_max + 1)
    return total


def estimate_eta_seconds(*, requests: int, request_rate_rps: float | None) -> float | None:
    if request_rate_rps is None:
        return None
    if request_rate_rps <= 0:
        return None
    return requests / request_rate_rps
