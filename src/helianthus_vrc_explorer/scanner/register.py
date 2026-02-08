from __future__ import annotations

import logging
import math
import time
from typing import Final, TypedDict

from ..protocol.b524 import RegisterOpcode, build_register_read_payload
from ..protocol.parser import ValueParseError, parse_typed_value
from ..transport.base import TransportError, TransportInterface, TransportTimeout, emit_trace_label
from .observer import ScanObserver

logger = logging.getLogger(__name__)

_REMOTE_GROUPS: Final[set[int]] = {0x09, 0x0A, 0x0C}
_PRINTABLE_LATIN1: Final[set[int]] = set(range(0x20, 0x7F)) | set(range(0xA0, 0x100))
_TIMEOUT_RETRY_DELAY_S: Final[float] = 1.0


class RegisterEntry(TypedDict):
    # Full raw reply payload (after ebusd length-prefix stripping), if available.
    # For register reads this is typically: <TT> <GG> <RR_LO> <RR_HI> <VALUE_BYTES...>
    reply_hex: str | None
    # TT byte extracted from the reply, if present.
    tt: int | None
    # Interpretation of TT (see user-observed semantics).
    tt_kind: str | None
    # Optional register name annotations.
    ebusd_name: str | None
    myvaillant_name: str | None
    raw_hex: str | None
    type: str | None
    value: object | None
    error: str | None


def opcode_for_group(group: int) -> RegisterOpcode:
    """Return the B524 register opcode family for a group."""

    return 0x06 if group in _REMOTE_GROUPS else 0x02


def _interpret_tt(tt: int) -> str:
    """Interpret the leading TT byte of a B524 register reply.

    User-observed semantics:
    - 0x00: no data / not present / invalid
    - 0x01: live/operational value
    - 0x02: parameter/limit
    - 0x03: parameter/config
    """

    match tt:
        case 0x00:
            return "no_data"
        case 0x01:
            return "live"
        case 0x02:
            return "parameter_limit"
        case 0x03:
            return "parameter_config"
        case _:
            return "unknown"


def _looks_like_nul_terminated_latin1(value_bytes: bytes) -> bool:
    """Heuristic for identifying C strings when the schema is missing.

    We only treat values as strings when they look like NUL-terminated latin1 and
    the bytes before the first NUL are "printable-ish". This avoids misclassifying
    packed binary values.
    """

    if not value_bytes:
        return False

    try:
        nul_index = value_bytes.index(0x00)
    except ValueError:
        return False

    # After the first NUL, allow only more NUL padding.
    if any(b != 0x00 for b in value_bytes[nul_index:]):
        return False

    prefix = value_bytes[:nul_index]
    if not prefix:
        return False
    return all(b in _PRINTABLE_LATIN1 for b in prefix)


def _strip_echo_header(payload: bytes, response: bytes) -> bytes:
    """Strip the 4-byte header from a register read response.

    Empirically, ebusd's B524 register read replies look like:

        <STATUS> <GG> <RR_LO> <RR_HI> <VALUE_BYTES...>

    This differs from the request selector bytes:

        <OPCODE> <OPTYPE> <GG> <II> <RR_LO> <RR_HI>

    We validate that the response's (GG, RR) match the request and then strip
    the 4-byte response header, returning only the register value bytes.
    """

    if len(response) < 4:
        raise ValueError(f"Short register response: expected >=4 bytes, got {len(response)} bytes")
    header = response[:4]

    expected_group = payload[2]
    expected_rr = payload[4:6]
    group = header[1]
    rr = header[2:4]
    if group != expected_group or rr != expected_rr:
        raise ValueError(
            "Register header mismatch: "
            f"expected_gg={expected_group:02x} expected_rr={expected_rr.hex()} "
            f"got={header.hex()} payload={payload.hex()}"
        )
    return response[4:]


def _parse_inferred_value(value_bytes: bytes) -> tuple[str | None, object | None, str | None]:
    """Infer a type from byte length and parse it.

    Returns:
        (type_spec, value, error)
    """

    n = len(value_bytes)
    if n == 0:
        return None, None, None

    def _hex_fallback() -> tuple[str, object, None]:
        spec = f"HEX:{n}"
        return spec, parse_typed_value(spec, value_bytes), None

    if len(value_bytes) == 4:
        try:
            return "EXP", parse_typed_value("EXP", value_bytes), None
        except ValueParseError:
            # Don't drop bytes on the floor: keep a stable representation.
            return _hex_fallback()

    if len(value_bytes) == 2:
        try:
            return "UIN", parse_typed_value("UIN", value_bytes), None
        except ValueParseError:
            return _hex_fallback()

    if len(value_bytes) == 1:
        try:
            return "UCH", parse_typed_value("UCH", value_bytes), None
        except ValueParseError:
            return _hex_fallback()

    if len(value_bytes) == 3:
        for spec in ("HDA:3", "HTI"):
            try:
                return spec, parse_typed_value(spec, value_bytes), None
            except ValueParseError:
                continue
        return _hex_fallback()

    if _looks_like_nul_terminated_latin1(value_bytes):
        try:
            return "STR:*", parse_typed_value("STR:*", value_bytes), None
        except ValueParseError:
            return _hex_fallback()

    return _hex_fallback()


def read_register(
    transport: TransportInterface,
    dst: int,
    opcode: RegisterOpcode,
    group: int,
    instance: int,
    register: int,
    *,
    type_hint: str | None = None,
) -> RegisterEntry:
    """Read a B524 register and parse it into an artifact-ready entry."""

    emit_trace_label(
        transport,
        f"Reading dst=0x{dst:02X} GG=0x{group:02X} II=0x{instance:02X} RR=0x{register:04X}",
    )
    payload = build_register_read_payload(opcode, group=group, instance=instance, register=register)
    response: bytes | None = None
    for attempt in range(2):
        try:
            response = transport.send(dst, payload)
            break
        except TransportTimeout:
            if attempt == 0:
                time.sleep(_TIMEOUT_RETRY_DELAY_S)
                continue
            return {
                "reply_hex": None,
                "tt": None,
                "tt_kind": None,
                "ebusd_name": None,
                "myvaillant_name": None,
                "raw_hex": None,
                "type": None,
                "value": None,
                "error": "timeout",
            }
        except TransportError as exc:
            return {
                "reply_hex": None,
                "tt": None,
                "tt_kind": None,
                "ebusd_name": None,
                "myvaillant_name": None,
                "raw_hex": None,
                "type": None,
                "value": None,
                "error": f"transport_error: {exc}",
            }
    assert response is not None
    reply_hex = response.hex()
    tt: int | None = response[0] if response else None
    tt_kind: str | None = _interpret_tt(tt) if tt is not None else None

    # Some registers respond with a single status byte (no GG/RR echo and no value bytes).
    # We treat this as a valid "no data" reply rather than a decoder bug.
    if len(response) == 1:
        return {
            "reply_hex": reply_hex,
            "tt": tt,
            "tt_kind": tt_kind,
            "ebusd_name": None,
            "myvaillant_name": None,
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": None,
        }

    try:
        value_bytes = _strip_echo_header(payload, response)
    except ValueError as exc:
        return {
            "reply_hex": reply_hex,
            "tt": tt,
            "tt_kind": tt_kind,
            "ebusd_name": None,
            "myvaillant_name": None,
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": f"decode_error: {exc}",
        }

    raw_hex = value_bytes.hex()
    if type_hint is not None:
        try:
            value = parse_typed_value(type_hint, value_bytes)
            return {
                "reply_hex": reply_hex,
                "tt": tt,
                "tt_kind": tt_kind,
                "ebusd_name": None,
                "myvaillant_name": None,
                "raw_hex": raw_hex,
                "type": type_hint,
                "value": value,
                "error": None,
            }
        except ValueParseError as exc:
            return {
                "reply_hex": reply_hex,
                "tt": tt,
                "tt_kind": tt_kind,
                "ebusd_name": None,
                "myvaillant_name": None,
                "raw_hex": raw_hex,
                "type": type_hint,
                "value": None,
                "error": f"parse_error: {exc}",
            }

    inferred_type, inferred_value, inferred_error = _parse_inferred_value(value_bytes)
    return {
        "reply_hex": reply_hex,
        "tt": tt,
        "tt_kind": tt_kind,
        "ebusd_name": None,
        "myvaillant_name": None,
        "raw_hex": raw_hex,
        "type": inferred_type,
        "value": inferred_value,
        "error": inferred_error,
    }


def is_instance_present(transport: TransportInterface, dst: int, group: int, instance: int) -> bool:
    """Presence heuristic for instanced groups (desc==1.0).

    Source of truth: `AGENTS.md` (keep in sync).
    """

    opcode = opcode_for_group(group)

    if group == 0x02:
        entry = read_register(
            transport, dst, opcode, group=group, instance=instance, register=0x0002, type_hint="UIN"
        )
        if entry["error"] is not None:
            return False
        if entry.get("tt_kind") == "no_data":
            return False
        value = entry["value"]
        if value is None:
            return False
        if not isinstance(value, int) or isinstance(value, bool):
            return False
        return value not in {0x0000, 0xFFFF}

    if group == 0x03:
        entry = read_register(
            transport, dst, opcode, group=group, instance=instance, register=0x001C, type_hint="UCH"
        )
        if entry["error"] is not None:
            return False
        if entry.get("tt_kind") == "no_data":
            return False
        value = entry["value"]
        if not isinstance(value, int) or isinstance(value, bool):
            return False
        return value != 0xFF

    if group in {0x09, 0x0A}:
        entry_1 = read_register(
            transport, dst, 0x06, group=group, instance=instance, register=0x0007, type_hint="EXP"
        )
        value_1 = entry_1["value"]
        if (
            entry_1["error"] is None
            and entry_1.get("tt_kind") != "no_data"
            and value_1 is not None
            and not (isinstance(value_1, float) and math.isnan(value_1))
        ):
            return True
        entry_2 = read_register(
            transport, dst, 0x06, group=group, instance=instance, register=0x000F, type_hint="EXP"
        )
        value_2 = entry_2["value"]
        return (
            entry_2["error"] is None
            and entry_2.get("tt_kind") != "no_data"
            and value_2 is not None
            and not (isinstance(value_2, float) and math.isnan(value_2))
        )

    if group == 0x0C:
        for rr in (0x0002, 0x0007, 0x000F, 0x0016):
            entry = read_register(transport, dst, 0x06, group=group, instance=instance, register=rr)
            if entry["error"] is None and entry.get("tt_kind") != "no_data":
                return True
        return False

    logger.debug(
        "No presence heuristic for GG=0x%02X; assuming present for II=0x%02X", group, instance
    )
    return True


def scan_registers_for_instance(
    transport: TransportInterface,
    dst: int,
    group: int,
    instance: int,
    rr_max: int,
    *,
    observer: ScanObserver | None = None,
) -> dict[str, RegisterEntry]:
    """Phase D: scan RR=0x0000..rr_max for a (present) instance."""

    opcode = opcode_for_group(group)
    registers: dict[str, RegisterEntry] = {}
    for rr in range(0x0000, rr_max + 1):
        if observer is not None:
            if rr % 8 == 0:
                observer.status(f"Read GG=0x{group:02X} II=0x{instance:02X} RR=0x{rr:04X}")
            observer.phase_advance("register_scan", advance=1)
        registers[f"0x{rr:04x}"] = read_register(
            transport, dst, opcode, group=group, instance=instance, register=rr
        )
    return registers
