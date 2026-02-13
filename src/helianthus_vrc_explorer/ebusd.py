from __future__ import annotations

import re
from collections.abc import Sequence

_ADDR_LINE_RE = re.compile(r"^address\s+([0-9a-fA-F]{2}):\s*(.*)$")
_ROLE_TARGET_TOKEN = bytes.fromhex("736c617665").decode("ascii")
_ROLE_SELF_TOKEN = "self"


def parse_ebusd_info_target_addresses(lines: Sequence[str]) -> list[int]:
    """Extract target addresses from ebusd `info` output lines.

    The ebusd command-port `info` output typically includes entries like:

        address 08: <target-role>, scanned Vaillant;BAI00;...

    We keep addresses flagged as device targets and ignore `self` entries.
    """

    addresses: list[int] = []
    seen: set[int] = set()
    for raw in lines:
        if not isinstance(raw, str):
            continue
        m = _ADDR_LINE_RE.match(raw.strip())
        if not m:
            continue
        try:
            addr = int(m.group(1), 16)
        except ValueError:
            continue
        rest = m.group(2).lower()
        if _ROLE_TARGET_TOKEN not in rest:
            continue
        if _ROLE_SELF_TOKEN in rest:
            continue
        if addr in seen:
            continue
        seen.add(addr)
        addresses.append(addr)

    addresses.sort()
    return addresses
