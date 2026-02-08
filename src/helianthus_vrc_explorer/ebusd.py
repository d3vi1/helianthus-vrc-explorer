from __future__ import annotations

import re
from collections.abc import Sequence

_ADDR_LINE_RE = re.compile(r"^address\s+([0-9a-fA-F]{2}):\s*(.*)$")


def parse_ebusd_info_slave_addresses(lines: Sequence[str]) -> list[int]:
    """Extract slave addresses from ebusd `info` output lines.

    The ebusd command-port `info` output typically includes entries like:

        address 08: slave, scanned Vaillant;BAI00;...

    We treat anything containing "slave" as a device address and ignore "self".
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
        if "slave" not in rest:
            continue
        if "self" in rest:
            continue
        if addr in seen:
            continue
        seen.add(addr)
        addresses.append(addr)

    addresses.sort()
    return addresses
