from __future__ import annotations


def build_b509_register_read_payload(register: int) -> bytes:
    """Build a B509 register read payload.

    Layout:
    - 0x0D: read selector
    - addr_hi
    - addr_lo
    """

    if not (0x0000 <= register <= 0xFFFF):
        raise ValueError(f"register out of range 0x0000..0xFFFF: 0x{register:04X}")
    return bytes((0x0D, (register >> 8) & 0xFF, register & 0xFF))
