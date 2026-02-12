from __future__ import annotations

import contextlib
import json
import math
import struct
import sys
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import cast

import typer
from rich.console import Console

from . import __version__
from .ebusd import parse_ebusd_info_slave_addresses
from .protocol.b524 import build_directory_probe_payload
from .protocol.basv import parse_scan_identification, parse_vaillant_scan_id_chunks
from .scanner.b509 import parse_b509_range
from .scanner.director import GROUP_CONFIG, classify_groups, discover_groups
from .scanner.register import is_instance_present
from .scanner.scan import PlannerUiMode, default_output_filename, scan_vrc
from .schema.ebusd_csv import EbusdCsvSchema
from .schema.myvaillant_map import MyvaillantRegisterMap
from .transport.base import TransportError, TransportTimeout
from .transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
from .ui.browse_textual import run_browse_from_artifact
from .ui.html_report import render_html_report
from .ui.live import ScanSessionPreface, make_scan_observer
from .ui.planner import PlannerPreset
from .ui.summary import render_summary

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _load_default_myvaillant_map() -> tuple[MyvaillantRegisterMap | None, str | None]:
    """Load bundled default myVaillant mapping for installed/package use."""

    try:
        resource = resources.files("helianthus_vrc_explorer.data").joinpath(
            "myvaillant_register_map.csv"
        )
        with resources.as_file(resource) as map_path:
            return (
                MyvaillantRegisterMap.from_path(map_path),
                f"myvaillant_map:{map_path.name}",
            )
    except Exception:
        # Dev fallback (editable checkout) when package resources are unavailable.
        fallback = Path(__file__).resolve().parents[2] / "data" / "myvaillant_register_map.csv"
        if fallback.exists():
            try:
                return (
                    MyvaillantRegisterMap.from_path(fallback),
                    f"myvaillant_map:{fallback.name}",
                )
            except Exception:
                return (None, None)
        return (None, None)


def _load_default_dry_run_fixture_text() -> tuple[str | None, str | None]:
    """Load bundled default dry-run fixture JSON text."""

    try:
        resource = resources.files("helianthus_vrc_explorer.fixtures").joinpath(
            "vrc720_full_scan.json"
        )
        return (resource.read_text(encoding="utf-8"), "packaged:vrc720_full_scan.json")
    except Exception:
        fallback = Path(__file__).resolve().parents[2] / "fixtures" / "vrc720_full_scan.json"
        if fallback.exists():
            try:
                return (fallback.read_text(encoding="utf-8"), str(fallback))
            except Exception:
                return (None, None)
        return (None, None)


def _na(value: str | None) -> str:
    text = (value or "").strip()
    return text if text else "n/a"


def _format_fw(sw: str | None, hw: str | None) -> str:
    sw_hex = (sw or "").strip().upper()
    hw_hex = (hw or "").strip().upper()
    if not sw_hex and not hw_hex:
        return "n/a"
    return f"SW {sw_hex or 'n/a'} / HW {hw_hex or 'n/a'}"


def _probe_scan_identity(
    transport: EbusdTcpTransport,
    *,
    dst: int,
) -> dict[str, str]:
    identity = {
        "device": "n/a",
        "model": "n/a",
        "serial": "n/a",
        "firmware": "n/a",
    }
    try:
        payload = transport.send_proto(dst, 0x07, 0x04, b"")
        ident = parse_scan_identification(payload)
    except Exception:
        return identity

    identity["device"] = _na(ident.device_id)
    identity["firmware"] = _format_fw(ident.sw, ident.hw)
    if ident.manufacturer != 0xB5:
        return identity

    try:
        chunks = [
            transport.send_proto(dst, 0xB5, 0x09, bytes((qq,))) for qq in (0x24, 0x25, 0x26, 0x27)
        ]
        scan_id = parse_vaillant_scan_id_chunks(chunks)
    except Exception:
        return identity

    identity["model"] = _na(scan_id.model_number)
    identity["serial"] = _na(scan_id.serial_number)
    return identity


def _build_scan_session_preface(
    *,
    dst: int,
    endpoint: str,
    identity: dict[str, str] | None = None,
) -> ScanSessionPreface:
    data = identity or {}
    return ScanSessionPreface(
        app_line=f"helianthus-vrc-explorer v{__version__}",
        scan_line=f"Scanning VRC Regulator (B524) at address 0x{dst:02X}",
        rows=(
            ("Device", _na(data.get("device"))),
            ("Model", _na(data.get("model"))),
            ("Serial", _na(data.get("serial"))),
            ("Firmware", _na(data.get("firmware"))),
            ("ebusd", endpoint),
            ("Started", datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")),
        ),
    )


def _emit_non_tty_session_preface(preface: ScanSessionPreface) -> None:
    typer.echo(preface.app_line, err=True)
    typer.echo(preface.scan_line, err=True)
    for label, value in preface.rows:
        typer.echo(f"{label}: {value}", err=True)


def _can_launch_interactive_browse(console: Console) -> bool:
    return (
        console.is_terminal
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and sys.platform != "win32"
    )


def _probe_group_descriptor(
    transport: EbusdTcpTransport,
    *,
    dst: int,
    group: int,
) -> float | None:
    payload = build_directory_probe_payload(group)
    for _ in range(2):
        try:
            response = transport.send(dst, payload)
        except (TransportError, TransportTimeout):
            continue
        if len(response) < 4:
            continue
        descriptor = struct.unpack("<f", response[:4])[0]
        if math.isnan(descriptor) or descriptor == 0.0:
            continue
        return descriptor
    return None


def _resolve_scan_destination(transport: EbusdTcpTransport, *, dst: str) -> int:
    requested = dst.strip().lower()
    if requested != "auto":
        return _parse_u8_address(dst)

    # Best-effort bus wake-up. Some ebusd setups ignore this and that's fine.
    with contextlib.suppress(TransportError, TransportTimeout):
        transport.send_proto(0xFE, 0x07, 0xFE, b"", expect_response=False)

    addresses = parse_ebusd_info_slave_addresses(transport.command_lines("info", read_all=True))
    if not addresses:
        typer.echo(
            "Auto destination failed: no slave addresses found in ebusd info output.",
            err=True,
        )
        raise typer.Exit(2)

    compatible_addrs: list[int] = []
    for addr in addresses:
        try:
            ident = parse_scan_identification(transport.send_proto(addr, 0x07, 0x04, b""))
        except Exception:
            continue
        if ident.manufacturer != 0xB5:
            continue
        descriptor = _probe_group_descriptor(transport, dst=addr, group=0x00)
        if descriptor is None:
            continue
        compatible_addrs.append(addr)

    if not compatible_addrs:
        typer.echo(
            "Auto destination failed: no compatible VRC/B524 device found. "
            "Retry with --dst 0x..",
            err=True,
        )
        raise typer.Exit(2)

    selected = 0x15 if 0x15 in compatible_addrs else min(compatible_addrs)
    if len(compatible_addrs) > 1:
        candidates = ", ".join(f"0x{addr:02X}" for addr in compatible_addrs)
        typer.echo(
            f"Auto-selected dst=0x{selected:02X} (compatible candidates: {candidates})",
            err=True,
        )
    else:
        typer.echo(f"Auto-selected dst=0x{selected:02X} (compatible B524 target).", err=True)
    return selected


def _parse_u8_address(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise typer.BadParameter(f"Invalid address: {value!r}") from exc

    if not (0x00 <= parsed <= 0xFF):
        raise typer.BadParameter(f"Address out of range 0x00..0xFF: {value!r}")
    return parsed


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Print version and exit.",
        is_eager=True,
    ),
) -> None:
    if version:
        typer.echo(f"helianthus-vrc-explorer {__version__}")
        raise typer.Exit(0)


@app.command()
def scan(
    dst: str = typer.Option(  # noqa: B008
        "auto",
        "--dst",
        help="Destination eBUS address (e.g. 0x15) or auto (default).",
    ),
    host: str = typer.Option(  # noqa: B008
        "127.0.0.1",
        "--host",
        help="ebusd host (TCP).",
    ),
    port: int = typer.Option(  # noqa: B008
        8888,
        "--port",
        help="ebusd port (TCP).",
    ),
    dry_run: bool = typer.Option(  # noqa: B008
        False,
        "--dry-run",
        help="Replay a scan fixture using DummyTransport (no device I/O).",
    ),
    output_dir: Path = typer.Option(  # noqa: B008
        Path("."),
        "--output-dir",
        help="Directory to write the scan JSON artifact to.",
    ),
    ebusd_csv_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--ebusd-csv-path",
        envvar="HELIA_EBUSD_CSV_PATH",
        help="Optional ebusd configuration CSV (e.g. 15.720.csv) used to annotate register names.",
    ),
    myvaillant_map_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--myvaillant-map-path",
        envvar="HELIA_MYVAILLANT_MAP_PATH",
        help="Optional myVaillant-equivalence mapping CSV used to annotate register leaf names.",
    ),
    trace_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--trace-file",
        envvar="HELIA_EBUSD_TRACE_PATH",
        help="Write an ebusd request/response trace log to this file.",
    ),
    b509_range: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--b509-range",
        help=(
            "B509 register range to dump (repeatable), format: 0x2700..0x27FF. "
            "If omitted, defaults to 0x2700..0x27FF."
        ),
    ),
    planner_ui: str = typer.Option(  # noqa: B008
        "auto",
        "--planner-ui",
        help="Interactive planner mode: auto, textual, or classic.",
    ),
    preset: str = typer.Option(  # noqa: B008
        "recommended",
        "--preset",
        help="Planner preset: conservative, recommended, aggressive, or custom.",
    ),
    no_tips: bool = typer.Option(  # noqa: B008
        False,
        "--no-tips",
        help="Hide scan header tips in interactive terminal mode.",
    ),
) -> None:
    """Scan a VRC regulator using B524 (GetExtendedRegisters)."""
    dst_u8: int
    console = Console(stderr=True)
    planner_ui_value = planner_ui.strip().lower()
    if planner_ui_value not in {"auto", "textual", "classic"}:
        typer.echo(
            "Invalid --planner-ui value. Expected one of: auto, textual, classic.",
            err=True,
        )
        raise typer.Exit(2)
    preset_value = preset.strip().lower()
    if preset_value not in {"conservative", "recommended", "aggressive", "custom"}:
        typer.echo(
            "Invalid --preset value. Expected one of: conservative, recommended, "
            "aggressive, custom.",
            err=True,
        )
        raise typer.Exit(2)

    ebusd_schema: EbusdCsvSchema | None = None
    ebusd_schema_source: str | None = None
    if ebusd_csv_path is not None:
        try:
            ebusd_schema = EbusdCsvSchema.from_path(ebusd_csv_path)
            ebusd_schema_source = f"ebusd_csv:{ebusd_csv_path.name}"
        except Exception as exc:
            typer.echo(f"Warning: failed to load ebusd CSV schema: {exc}", err=True)

    myvaillant_map: MyvaillantRegisterMap | None = None
    myvaillant_map_source: str | None = None
    if myvaillant_map_path is not None:
        try:
            myvaillant_map = MyvaillantRegisterMap.from_path(myvaillant_map_path)
            myvaillant_map_source = f"myvaillant_map:{myvaillant_map_path.name}"
        except Exception as exc:
            typer.echo(f"Warning: failed to load myVaillant mapping: {exc}", err=True)
    else:
        myvaillant_map, myvaillant_map_source = _load_default_myvaillant_map()

    if dry_run:
        dst_u8 = 0x15 if dst.strip().lower() == "auto" else _parse_u8_address(dst)
        fixture_text, fixture_source = _load_default_dry_run_fixture_text()
        if fixture_text is None:
            typer.echo("Fixture not found: vrc720_full_scan.json", err=True)
            raise typer.Exit(2)
        try:
            artifact = json.loads(fixture_text)
        except json.JSONDecodeError as exc:
            origin = fixture_source or "vrc720_full_scan.json"
            typer.echo(f"Invalid JSON fixture: {origin} ({exc})", err=True)
            raise typer.Exit(2) from exc
        preface = _build_scan_session_preface(
            dst=dst_u8,
            endpoint="n/a (dry-run fixture)",
            identity=None,
        )
        _emit_non_tty_session_preface(preface)
    else:
        b509_ranges: list[tuple[int, int]] = []
        if b509_range:
            for spec in b509_range:
                try:
                    b509_ranges.append(parse_b509_range(spec))
                except ValueError as exc:
                    typer.echo(f"Invalid --b509-range {spec!r}: {exc}", err=True)
                    raise typer.Exit(2) from exc
        else:
            b509_ranges = [(0x2700, 0x27FF)]

        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, trace_path=trace_file))
        with transport.session():
            dst_u8 = _resolve_scan_destination(transport, dst=dst)
            title = f"helianthus-vrc-explorer scan (B524) dst=0x{dst_u8:02X}"
            subtitle_lines = [f"Planner: {planner_ui_value} (preset={preset_value})"]

            identity = _probe_scan_identity(transport, dst=dst_u8)
            preface = _build_scan_session_preface(
                dst=dst_u8,
                endpoint=f"{host}:{port}",
                identity=identity,
            )
            if not console.is_terminal:
                _emit_non_tty_session_preface(preface)
            with make_scan_observer(
                console=console,
                title=title,
                subtitle_lines=subtitle_lines,
                show_tips=not no_tips,
                session_preface=preface,
            ) as observer:
                artifact = scan_vrc(
                    transport,
                    dst=dst_u8,
                    b509_ranges=b509_ranges,
                    ebusd_host=host,
                    ebusd_port=port,
                    ebusd_schema=ebusd_schema,
                    myvaillant_map=myvaillant_map,
                    observer=observer,
                    console=console,
                    planner_ui=cast(PlannerUiMode, planner_ui_value),
                    planner_preset=cast(PlannerPreset, preset_value),
                )

    meta_obj = artifact.get("meta")
    if isinstance(meta_obj, dict):
        sources_obj = meta_obj.get("schema_sources")
        if isinstance(sources_obj, list):
            if ebusd_schema_source:
                sources_obj.append(ebusd_schema_source)
            if myvaillant_map_source:
                sources_obj.append(myvaillant_map_source)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / default_output_filename(
        dst=dst_u8,
        scan_timestamp=artifact.get("meta", {}).get("scan_timestamp"),
    )
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if _can_launch_interactive_browse(console):
        # Post-scan default UX: enter the new fullscreen browse UI directly.
        run_browse_from_artifact(artifact, allow_write=False)

    html_path = output_path.with_suffix(".html")
    html_path.write_text(
        render_html_report(
            artifact,
            title=f"helianthus-vrc-explorer scan report ({output_path.name})",
        ),
        encoding="utf-8",
    )

    # Summary to stderr; keep stdout stable for scripting (artifact path only).
    render_summary(console, artifact, output_path=output_path)
    typer.echo(str(output_path))


@app.command()
def discover(
    host: str = typer.Option(  # noqa: B008
        "127.0.0.1",
        "--host",
        help="ebusd host (TCP).",
    ),
    port: int = typer.Option(  # noqa: B008
        8888,
        "--port",
        help="ebusd port (TCP).",
    ),
    trace_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--trace-file",
        envvar="HELIA_EBUSD_TRACE_PATH",
        help="Write an ebusd request/response trace log to this file.",
    ),
) -> None:
    """Discover eBUS devices via QueryExistence broadcast and per-address scan (0704)."""

    transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, trace_path=trace_file))
    with transport.session():
        # 1) QueryExistence (broadcast). This is best-effort: some ebusd setups will simply
        # respond with a textual status (e.g. "done broadcast").
        with contextlib.suppress(TransportError, TransportTimeout):
            transport.send_proto(0xFE, 0x07, 0xFE, b"", expect_response=False)

        info_lines = transport.command_lines("info", read_all=True)
        addresses = parse_ebusd_info_slave_addresses(info_lines)
        if not addresses:
            typer.echo("No slave addresses found in ebusd info output.", err=True)
            raise typer.Exit(2)

        devices: dict[int, dict[str, object]] = {}
        for addr in addresses:
            try:
                payload = transport.send_proto(addr, 0x07, 0x04, b"")
            except (TransportError, TransportTimeout):
                continue

            try:
                ident = parse_scan_identification(payload)
            except Exception:
                continue

            entry: dict[str, object] = {
                "manufacturer": ident.manufacturer,
                "device_id": ident.device_id,
                "sw": ident.sw,
                "hw": ident.hw,
            }

            if ident.manufacturer == 0xB5:
                try:
                    chunks = [
                        transport.send_proto(addr, 0xB5, 0x09, bytes((qq,)))
                        for qq in (0x24, 0x25, 0x26, 0x27)
                    ]
                    scan_id = parse_vaillant_scan_id_chunks(chunks)
                    entry["model_number"] = scan_id.model_number
                    entry["serial_number"] = scan_id.serial_number
                except Exception:
                    pass

            devices[addr] = entry

        if not devices:
            typer.echo("No devices responded to scan (0704).", err=True)
            raise typer.Exit(2)

        for addr in sorted(devices):
            entry = devices[addr]
            manufacturer_obj = entry.get("manufacturer")
            manufacturer = (
                manufacturer_obj
                if isinstance(manufacturer_obj, int) and not isinstance(manufacturer_obj, bool)
                else 0
            )
            device_id = str(entry.get("device_id") or "").strip()
            sw = str(entry.get("sw") or "")
            hw = str(entry.get("hw") or "")
            model_number = entry.get("model_number")
            serial_number = entry.get("serial_number")

            line = (
                f"addr=0x{addr:02X} mf=0x{manufacturer:02X} id={device_id or '?'} "
                f"sw={sw or '????'} hw={hw or '????'}"
            )
            if isinstance(model_number, str) and isinstance(serial_number, str):
                line += f" model={model_number} serial={serial_number}"
            typer.echo(line)

        # 4) If a Vaillant device is present at 0x15, run B524 group/instance discovery.
        vrc = devices.get(0x15)
        mf_obj = vrc.get("manufacturer") if isinstance(vrc, dict) else None
        if isinstance(mf_obj, int) and not isinstance(mf_obj, bool) and mf_obj == 0xB5:
            try:
                groups = classify_groups(discover_groups(transport, dst=0x15))
            except Exception as exc:
                typer.echo(f"VRC@0x15 B524 discovery failed: {exc}", err=True)
                raise typer.Exit(1) from exc

            typer.echo("VRC@0x15 B524 instances per group:")
            for group in groups:
                config = GROUP_CONFIG.get(group.group)
                if group.descriptor == 1.0 and config is not None:
                    ii_max = int(config["ii_max"])
                    present = 0
                    for ii in range(0x00, ii_max + 1):
                        try:
                            if is_instance_present(
                                transport,
                                dst=0x15,
                                group=group.group,
                                instance=ii,
                            ):
                                present += 1
                        except Exception:
                            continue
                    typer.echo(
                        f"GG=0x{group.group:02X} name={group.name} desc={group.descriptor:g} "
                        f"instances={present}/{ii_max + 1}"
                    )
                else:
                    typer.echo(
                        f"GG=0x{group.group:02X} name={group.name} desc={group.descriptor:g} "
                        "instances=1"
                    )


@app.command()
def browse(
    file: Path | None = typer.Option(  # noqa: B008
        None,
        "--file",
        help="Path to an existing scan JSON artifact (default browse mode).",
    ),
    live: bool = typer.Option(  # noqa: B008
        False,
        "--live",
        help="Live mode (planned). In P0, only --file mode is implemented.",
    ),
    device: str | None = typer.Option(  # noqa: B008
        None,
        "--device",
        help="Device identifier for --live mode (planned).",
    ),
    allow_write: bool = typer.Option(  # noqa: B008
        False,
        "--allow-write",
        help="Enable write/edit actions in browse UI (P2, planned).",
    ),
) -> None:
    """Browse scan results in fullscreen Textual UI (P0: file mode)."""

    _ = device
    if live:
        typer.echo("Live browse mode is not implemented yet; use --file <artifact.json>.", err=True)
        raise typer.Exit(2)

    if file is None:
        typer.echo("Missing required option: --file <artifact.json>.", err=True)
        raise typer.Exit(2)
    if not file.exists():
        typer.echo(f"Artifact not found: {file}", err=True)
        raise typer.Exit(2)

    try:
        artifact = json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        typer.echo(f"Invalid JSON artifact: {file} ({exc})", err=True)
        raise typer.Exit(2) from exc
    if not isinstance(artifact, dict):
        typer.echo(f"Invalid artifact root object: {file}", err=True)
        raise typer.Exit(2)

    if not Console().is_terminal:
        console = Console(stderr=True)
        render_summary(console, artifact, output_path=file)
        typer.echo("Browse UI requires a TTY terminal.", err=True)
        raise typer.Exit(0)

    run_browse_from_artifact(artifact, allow_write=allow_write)
