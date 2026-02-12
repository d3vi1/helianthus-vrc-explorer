import json
import re
import struct
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from helianthus_vrc_explorer import __version__
from helianthus_vrc_explorer.cli import (
    _build_scan_session_preface,
    _format_fw,
    _load_default_dry_run_fixture_text,
    _probe_scan_identity,
    _resolve_scan_destination,
    app,
)


def test_version_prints_version() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_command_is_present() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", result.stdout)
    assert "planner-ui" in plain
    assert "preset" in plain
    assert "no-tips" in plain
    assert "auto" in plain


def test_scan_invalid_dst_fails_before_transport_setup(monkeypatch) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    def _fail_init(self, *_args, **_kwargs):  # noqa: ANN001
        raise AssertionError("transport should not be initialized for invalid --dst")

    monkeypatch.setattr(cli_mod.EbusdTcpTransport, "__init__", _fail_init)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--dst", "bogus"])
    assert result.exit_code == 2
    assert "Invalid address: 'bogus'" in result.stderr


def test_discover_command_is_present() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["discover", "--help"])
    assert result.exit_code == 0


def test_browse_command_is_present() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["browse", "--help"])
    assert result.exit_code == 0
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", result.stdout)
    assert "--file" in plain
    assert "--live" in plain
    assert "--allow-write" in plain


def test_browse_requires_file_when_not_live() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["browse"])
    assert result.exit_code == 2
    assert "Missing required option: --file <artifact.json>." in result.stderr


def test_browse_non_tty_falls_back_to_summary(tmp_path: Path) -> None:
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_text(
        json.dumps(
            {
                "meta": {
                    "scan_timestamp": "2026-02-11T12:00:00Z",
                    "destination_address": "0x15",
                    "incomplete": False,
                },
                "groups": {},
            }
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(app, ["browse", "--file", str(artifact_path)])
    assert result.exit_code == 0
    assert "Browse UI requires a TTY terminal." in result.stderr


def test_scan_dry_run_writes_scan_artifact(tmp_path: Path) -> None:
    map_path = tmp_path / "myvaillant_register_map.csv"
    map_path.write_text(
        "group,instance,register,leaf\n0x03,0x00,0x000F,current_room_temperature\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
            "--myvaillant-map-path",
            str(map_path),
        ],
    )
    assert result.exit_code == 0

    output_path = Path(result.stdout.strip())
    assert output_path.exists()
    assert output_path.with_suffix(".html").exists()

    artifact = json.loads(output_path.read_text(encoding="utf-8"))
    assert isinstance(artifact, dict)
    assert "meta" in artifact
    assert "groups" in artifact
    assert isinstance(artifact["groups"], dict)

    # myVaillant mapping is loaded when a CSV path is provided (even in --dry-run mode).
    schema_sources = artifact.get("meta", {}).get("schema_sources")
    assert isinstance(schema_sources, list)
    assert "myvaillant_map:myvaillant_register_map.csv" in schema_sources

    raw_hex_values: list[str] = []
    for group in artifact["groups"].values():
        if not isinstance(group, dict):
            continue
        instances = group.get("instances", {})
        if not isinstance(instances, dict):
            continue
        for instance in instances.values():
            if not isinstance(instance, dict):
                continue
            registers = instance.get("registers", {})
            if not isinstance(registers, dict):
                continue
            for register in registers.values():
                if not isinstance(register, dict):
                    continue
                raw_hex = register.get("raw_hex")
                if isinstance(raw_hex, str):
                    raw_hex_values.append(raw_hex)

    assert raw_hex_values
    bytes.fromhex(raw_hex_values[0])


def test_scan_dry_run_loads_default_myvaillant_mapping(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    output_path = Path(result.stdout.strip())
    artifact = json.loads(output_path.read_text(encoding="utf-8"))
    schema_sources = artifact.get("meta", {}).get("schema_sources")
    assert isinstance(schema_sources, list)
    assert "myvaillant_map:myvaillant_register_map.csv" in schema_sources


def test_default_dry_run_fixture_is_bundled() -> None:
    fixture_text, fixture_source = _load_default_dry_run_fixture_text()
    assert fixture_text is not None
    assert fixture_source == "packaged:vrc720_full_scan.json"


def test_format_fw() -> None:
    assert _format_fw("0507", "1704") == "SW 0507 / HW 1704"
    assert _format_fw("", "") == "n/a"
    assert _format_fw("0507", "") == "SW 0507 / HW n/a"


def test_build_scan_session_preface() -> None:
    preface = _build_scan_session_preface(
        dst=0x15,
        endpoint="127.0.0.1:8888",
        identity={
            "device": "VRC 720f/2 (BASV2)",
            "model": "0020262148",
            "serial": "21213400202621480082014267N7",
            "firmware": "SW 0507 / HW 1704",
        },
    )
    assert preface.app_line == f"helianthus-vrc-explorer v{__version__}"
    assert preface.scan_line == "Scanning VRC Regulator (B524) at address 0x15"
    assert ("Device", "VRC 720f/2 (BASV2)") in preface.rows
    assert ("ebusd", "127.0.0.1:8888") in preface.rows


class _FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, bytes]] = []

    def send_proto(self, dst: int, primary: int, secondary: int, payload: bytes) -> bytes:
        self.calls.append((primary, secondary, payload))
        if (primary, secondary) == (0x07, 0x04):
            return bytes.fromhex("b556524320373230662f3205071704")
        qq = payload[0] if payload else 0
        chunks = {
            0x24: b"\x0021213400",
            0x25: b"\x0020262148",
            0x26: b"\x0000820142",
            0x27: b"\x0067N7    ",
        }
        return chunks[qq]


class _AutoResolveTransport:
    def __init__(
        self,
        *,
        info_lines: list[str],
        ident_payloads: dict[int, bytes],
        descriptors: dict[int, bytes],
    ) -> None:
        self._info_lines = info_lines
        self._ident_payloads = ident_payloads
        self._descriptors = descriptors
        self.info_calls = 0
        self.send_proto_calls = 0
        self.send_calls = 0

    def command_lines(self, command: str, *, read_all: bool = False) -> list[str]:
        assert command == "info"
        assert read_all is True
        self.info_calls += 1
        return list(self._info_lines)

    def send_proto(
        self,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        *,
        expect_response: bool = True,
    ) -> bytes:
        self.send_proto_calls += 1
        if (dst, primary, secondary) == (0xFE, 0x07, 0xFE):
            assert expect_response is False
            return b""
        assert (primary, secondary) == (0x07, 0x04)
        return self._ident_payloads[dst]

    def send(self, dst: int, payload: bytes) -> bytes:
        self.send_calls += 1
        return self._descriptors[dst]


def test_probe_scan_identity() -> None:
    identity = _probe_scan_identity(_FakeTransport(), dst=0x15)  # type: ignore[arg-type]
    assert identity["device"] == "VRC 720f/2"
    assert identity["model"] == "0020262148"
    assert identity["serial"] != "n/a"
    assert identity["firmware"] == "SW 0507 / HW 1704"


def test_resolve_scan_destination_explicit_skips_autodiscovery() -> None:
    transport = _AutoResolveTransport(
        info_lines=[],
        ident_payloads={},
        descriptors={},
    )
    assert _resolve_scan_destination(transport, dst="0x15") == 0x15
    assert transport.info_calls == 0
    assert transport.send_proto_calls == 0
    assert transport.send_calls == 0


def test_resolve_scan_destination_auto_prefers_0x15() -> None:
    vaillant_ident = bytes.fromhex("b556524320373230662f3205071704")
    descriptor = struct.pack("<f", 3.0)
    transport = _AutoResolveTransport(
        info_lines=[
            "address 30: slave, scanned Vaillant;XYZ",
            "address 15: slave, scanned Vaillant;XYZ",
        ],
        ident_payloads={
            0x30: vaillant_ident,
            0x15: vaillant_ident,
        },
        descriptors={
            0x30: descriptor,
            0x15: descriptor,
        },
    )
    assert _resolve_scan_destination(transport, dst="auto") == 0x15


def test_resolve_scan_destination_auto_picks_lowest_compatible_non_0x15() -> None:
    vaillant_ident = bytes.fromhex("b556524320373230662f3205071704")
    descriptor = struct.pack("<f", 3.0)
    transport = _AutoResolveTransport(
        info_lines=[
            "address 30: slave, scanned Vaillant;XYZ",
            "address 08: slave, scanned Vaillant;XYZ",
        ],
        ident_payloads={
            0x30: vaillant_ident,
            0x08: vaillant_ident,
        },
        descriptors={
            0x30: descriptor,
            0x08: descriptor,
        },
    )
    assert _resolve_scan_destination(transport, dst="auto") == 0x08


def test_resolve_scan_destination_auto_errors_when_no_compatible_target() -> None:
    # Non-Vaillant 0704 payload (manufacturer byte != 0xB5).
    non_vaillant_ident = bytes.fromhex("105652432d4e4f5001020304")
    transport = _AutoResolveTransport(
        info_lines=["address 08: slave, scanned device"],
        ident_payloads={0x08: non_vaillant_ident},
        descriptors={0x08: struct.pack("<f", 3.0)},
    )
    with pytest.raises(typer.Exit) as exc:
        _resolve_scan_destination(transport, dst="auto")
    assert exc.value.exit_code == 2
