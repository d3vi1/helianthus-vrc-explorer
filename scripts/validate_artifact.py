#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

from helianthus_vrc_explorer.protocol.parser import ValueParseError, parse_typed_value


def _parse_hex_key(key: str) -> int | None:
    try:
        return int(key, 0)
    except ValueError:
        return None


def _iter_register_entries(artifact: dict[str, Any]):
    groups = artifact.get("groups")
    if not isinstance(groups, dict):
        return
    for group_key, group_obj in groups.items():
        if not isinstance(group_key, str) or not isinstance(group_obj, dict):
            continue
        instances = group_obj.get("instances")
        if not isinstance(instances, dict):
            continue
        for instance_key, instance_obj in instances.items():
            if not isinstance(instance_key, str) or not isinstance(instance_obj, dict):
                continue
            registers = instance_obj.get("registers")
            if not isinstance(registers, dict):
                continue
            for rr_key, entry in registers.items():
                if not isinstance(rr_key, str) or not isinstance(entry, dict):
                    continue
                yield group_key, instance_key, rr_key, entry


def validate_scan_artifact(artifact: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    for group_key, instance_key, rr_key, entry in _iter_register_entries(artifact):
        loc = f"{group_key}/{instance_key}/{rr_key}"
        gg = _parse_hex_key(group_key)
        rr = _parse_hex_key(rr_key)
        if gg is None:
            errors.append(f"{loc}: invalid group key")
            continue
        if rr is None:
            errors.append(f"{loc}: invalid register key")
            continue

        reply_hex = entry.get("reply_hex")
        raw_hex = entry.get("raw_hex")
        type_spec = entry.get("type")
        value = entry.get("value")
        error = entry.get("error")

        if isinstance(reply_hex, str) and reply_hex:
            try:
                reply = bytes.fromhex(reply_hex)
            except ValueError:
                errors.append(f"{loc}: invalid reply_hex")
                reply = b""

            if len(reply) == 1:
                # Status-only reply: should not have a value tail.
                if raw_hex not in (None, ""):
                    errors.append(
                        f"{loc}: status-only reply but raw_hex is present"
                    )
            elif len(reply) >= 4 and isinstance(raw_hex, str):
                try:
                    raw = bytes.fromhex(raw_hex)
                except ValueError:
                    errors.append(f"{loc}: invalid raw_hex")
                    raw = b""

                if raw and reply[4:] != raw:
                    errors.append(f"{loc}: reply_hex tail mismatch raw_hex")
                if reply and reply[1] != (gg & 0xFF):
                    errors.append(
                        f"{loc}: reply_hex GG mismatch ({reply[1]:02x})"
                    )
                if reply and rr is not None:
                    rr_le = rr.to_bytes(2, byteorder="little", signed=False)
                    if reply[2:4] != rr_le:
                        errors.append(
                            f"{loc}: reply_hex RR mismatch ({reply[2:4].hex()})"
                        )

        if error is not None:
            # Transport/decode/parse errors: no strict value validation.
            continue

        if isinstance(type_spec, str) and isinstance(raw_hex, str) and raw_hex:
            try:
                value_bytes = bytes.fromhex(raw_hex)
            except ValueError:
                errors.append(f"{loc}: invalid raw_hex for parsing")
                continue
            try:
                parsed = parse_typed_value(type_spec, value_bytes)
            except ValueParseError as exc:
                errors.append(f"{loc}: parse_typed_value failed: {exc}")
                continue

            # JSON round-tripping: floats are approximate, everything else should match exactly.
            if parsed is None:
                if value is not None:
                    errors.append(
                        f"{loc}: expected null value, got {value!r}"
                    )
            elif isinstance(parsed, float):
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    errors.append(
                        f"{loc}: expected numeric float, got {type(value).__name__}"
                    )
                elif not math.isclose(float(value), float(parsed), rel_tol=1e-6, abs_tol=1e-6):
                    errors.append(
                        f"{loc}: float mismatch expected={parsed} got={value}"
                    )
            elif value != parsed:
                errors.append(
                    f"{loc}: value mismatch type={type_spec} expected={parsed!r} got={value!r}"
                )

    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] in {"-h", "--help"}:
        print("Usage: validate_artifact.py <artifact.json>", file=sys.stderr)
        return 2

    path = Path(argv[1])
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"Failed to read: {path} ({exc})", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON: {path} ({exc})", file=sys.stderr)
        return 2

    if not isinstance(artifact, dict):
        print("Invalid artifact root (expected JSON object).", file=sys.stderr)
        return 2

    errors = validate_scan_artifact(artifact)
    if errors:
        for line in errors[:50]:
            print(line, file=sys.stderr)
        if len(errors) > 50:
            print(f"... ({len(errors) - 50} more)", file=sys.stderr)
        return 1

    print(f"OK: validated artifact ({path.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
