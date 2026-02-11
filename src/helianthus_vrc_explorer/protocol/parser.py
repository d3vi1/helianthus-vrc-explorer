from __future__ import annotations

import math
import struct
from datetime import date


class ValueParseError(Exception):
    """Raised when response bytes cannot be parsed into a typed value."""


def _expect_len(type_spec: str, data: bytes, expected_len: int) -> None:
    if len(data) != expected_len:
        raise ValueParseError(f"{type_spec} expects {expected_len} bytes, got {len(data)} bytes")


def _decode_bcd(type_spec: str, field: str, value: int) -> int:
    """Decode a single byte containing a BCD-encoded decimal number."""

    high = (value >> 4) & 0xF
    low = value & 0xF
    if high > 9 or low > 9:
        raise ValueParseError(f"{type_spec} invalid BCD for {field}: 0x{value:02X}")
    return high * 10 + low


def parse_exp(data: bytes) -> float | None:
    """Parse an `EXP` value (float32le).

    Notes:
        - NaN values are returned as `None` so they can later be rendered as JSON `null`.
    """

    _expect_len("EXP", data, 4)
    value = struct.unpack("<f", data)[0]
    if math.isnan(value):
        return None
    return float(value)


def parse_uin(data: bytes) -> int:
    """Parse an `UIN` value (u16le)."""

    _expect_len("UIN", data, 2)
    return int.from_bytes(data, byteorder="little", signed=False)


def parse_uch(data: bytes) -> int:
    """Parse an `UCH` value (u8)."""

    _expect_len("UCH", data, 1)
    return data[0]


def parse_i8(data: bytes) -> int:
    """Parse an `I8` value (i8)."""

    _expect_len("I8", data, 1)
    return int.from_bytes(data, byteorder="little", signed=True)


def parse_i16(data: bytes) -> int:
    """Parse an `I16` value (i16le)."""

    _expect_len("I16", data, 2)
    return int.from_bytes(data, byteorder="little", signed=True)


def parse_u32(data: bytes) -> int:
    """Parse an `U32` value (u32le)."""

    _expect_len("U32", data, 4)
    return int.from_bytes(data, byteorder="little", signed=False)


def parse_i32(data: bytes) -> int:
    """Parse an `I32` value (i32le)."""

    _expect_len("I32", data, 4)
    return int.from_bytes(data, byteorder="little", signed=True)


def parse_bool(data: bytes) -> bool:
    """Parse a `BOOL` value (u8 -> bool)."""

    _expect_len("BOOL", data, 1)
    return data[0] != 0x00


def parse_hex(type_spec: str, data: bytes, expected_len: int) -> str:
    """Parse a `HEX:n` value as a hex string preserving byte order."""

    _expect_len(type_spec, data, expected_len)
    return "0x" + data.hex()


def parse_str_cstring(data: bytes) -> str:
    """Parse a `STR:*` value (cstring).

    CString semantics stop at the first NUL byte.
    """

    return data.split(b"\x00", 1)[0].decode("latin1")


def parse_hda3_date(data: bytes) -> str:
    """Parse an `HDA:3` value (u24le date encoded as DDMMYY, BCD per byte).

    Returns:
        ISO-ish date string: `YYYY-MM-DD`.

    Notes:
        The underlying schema only gives a 2-digit year. We interpret it as `2000 + YY`
        to match modern VRC firmware dates (2000-2099).
    """

    _expect_len("HDA:3", data, 3)
    day = _decode_bcd("HDA:3", "day", data[0])
    month = _decode_bcd("HDA:3", "month", data[1])
    year_2digit = _decode_bcd("HDA:3", "year", data[2])

    year = 2000 + year_2digit
    try:
        return date(year, month, day).isoformat()
    except ValueError as exc:
        raise ValueParseError(
            f"HDA:3 invalid date DDMMYY={day:02d}{month:02d}{year_2digit:02d}"
        ) from exc


def parse_hti_time(data: bytes) -> str:
    """Parse an `HTI` value (u24le time encoded as HH:MM:SS, BCD per byte).

    Returns:
        ISO-ish time string: `HH:MM:SS`.
    """

    _expect_len("HTI", data, 3)
    hour = _decode_bcd("HTI", "hour", data[0])
    minute = _decode_bcd("HTI", "minute", data[1])
    second = _decode_bcd("HTI", "second", data[2])

    if hour > 23:
        raise ValueParseError(f"HTI hour must be 0..23, got {hour}")
    if minute > 59:
        raise ValueParseError(f"HTI minute must be 0..59, got {minute}")
    if second > 59:
        raise ValueParseError(f"HTI second must be 0..59, got {second}")

    return f"{hour:02d}:{minute:02d}:{second:02d}"


def parse_typed_value(type_spec: str, data: bytes) -> object:
    """Parse a typed value from a B524 response tail.

    The type is taken from the ebusd CSV schema (`type` column). Only the minimal set
    needed for B524 register reads is implemented:

    - `EXP`: float32le (`NaN` -> `None`)
    - `UIN`: u16le
    - `UCH`: u8
    - `STR:*`: cstring (latin1, trailing NULs stripped)
    - `HDA:3`: u24le date encoded as DDMMYY (BCD per byte, `YYYY-MM-DD`)
    - `HTI`: u24le time encoded as HH:MM:SS (BCD per byte, `HH:MM:SS`)

    Args:
        type_spec: Type spec string (e.g. `"EXP"`, `"STR:*"`).
        data: Raw bytes for the value (after stripping the 4-byte echo header).

    Returns:
        Parsed Python value. `EXP` may return `None` if the decoded float is NaN.

    Raises:
        ValueParseError: On unknown type, wrong length, or malformed values.
    """

    normalized = type_spec.strip().upper()

    if normalized.startswith("STR:"):
        return parse_str_cstring(data)

    if normalized.startswith("HEX:"):
        try:
            expected = int(normalized.split(":", 1)[1], 10)
        except ValueError as exc:
            raise ValueParseError(f"Invalid HEX length in type spec: {type_spec!r}") from exc
        return parse_hex(normalized, data, expected_len=expected)

    match normalized:
        case "EXP":
            return parse_exp(data)
        case "UIN":
            return parse_uin(data)
        case "UCH":
            return parse_uch(data)
        case "I8":
            return parse_i8(data)
        case "I16":
            return parse_i16(data)
        case "U32":
            return parse_u32(data)
        case "I32":
            return parse_i32(data)
        case "BOOL":
            return parse_bool(data)
        case "HDA:3":
            return parse_hda3_date(data)
        case "HTI":
            return parse_hti_time(data)
        case _:
            raise ValueParseError(f"Unknown type spec: {type_spec!r}")
