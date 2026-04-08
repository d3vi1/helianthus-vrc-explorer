from __future__ import annotations

# Canonical register identity key for B524 namespace-aware surfaces.
# Order is opcode-first to avoid GG-centric collisions.
type RegisterIdentity = tuple[int, int, int, int]
type NamespaceIdentity = tuple[int, int]


def make_register_identity(
    *, opcode: int, group: int, instance: int, register: int
) -> RegisterIdentity:
    return (opcode, group, instance, register)


def make_namespace_identity(*, opcode: int, group: int) -> NamespaceIdentity:
    return (opcode, group)


def opcode_label(opcode: int) -> str:
    """Namespace label used by scanner/planner (`0x02` local, `0x06` remote)."""

    if opcode == 0x02:
        return "local"
    if opcode == 0x06:
        return "remote"
    return f"0x{opcode:02x}"


def operation_label(*, opcode: int, optype: int = 0x00) -> str:
    """Canonical B524 operation label used by UI/docs/artifact metadata."""

    if opcode == 0x00:
        return "QueryGroupDirectory"
    if opcode == 0x01:
        return "QueryRegisterConstraints"
    if opcode == 0x02:
        return "WriteControllerRegister" if optype == 0x01 else "ReadControllerRegister"
    if opcode == 0x03:
        return "ReadTimerProgram"
    if opcode == 0x04:
        return "WriteTimerProgram"
    if opcode == 0x06:
        return "WriteDeviceSlotRegister" if optype == 0x01 else "ReadDeviceSlotRegister"
    if opcode == 0x0B:
        return "ReadRegisterTable"
    return f"0x{opcode:02x}"
