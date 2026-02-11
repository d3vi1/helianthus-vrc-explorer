from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import typer
from rich.console import Console

from . import __version__
from .ebusd import parse_ebusd_info_slave_addresses
from .protocol.basv import parse_scan_identification, parse_vaillant_scan_id_chunks
from .scanner.b509 import parse_b509_range
from .scanner.director import GROUP_CONFIG, classify_groups, discover_groups
from .scanner.register import is_instance_present
from .scanner.scan import PlannerUiMode, default_output_filename, scan_vrc
from .schema.ebusd_csv import EbusdCsvSchema
from .schema.myvaillant_map import MyvaillantRegisterMap
from .transport.base import TransportError, TransportTimeout
from .transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
from .ui.html_report import render_html_report
from .ui.live import make_scan_observer
from .ui.planner import PlannerPreset
from .ui.summary import render_summary
from .ui.viewer import run_results_viewer

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


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
        "0x15",
        "--dst",
        help="Destination eBUS address (e.g. 0x15).",
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
    dst_u8 = _parse_u8_address(dst)
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
    resolved_myvaillant_map_path = myvaillant_map_path
    if resolved_myvaillant_map_path is None:
        default_map_path = (
            Path(__file__).resolve().parents[2] / "data" / "myvaillant_register_map.csv"
        )
        if default_map_path.exists():
            resolved_myvaillant_map_path = default_map_path
    if resolved_myvaillant_map_path is not None:
        try:
            myvaillant_map = MyvaillantRegisterMap.from_path(resolved_myvaillant_map_path)
            myvaillant_map_source = f"myvaillant_map:{resolved_myvaillant_map_path.name}"
        except Exception as exc:
            typer.echo(f"Warning: failed to load myVaillant mapping: {exc}", err=True)

    if dry_run:
        fixture_path = Path(__file__).resolve().parents[2] / "fixtures" / "vrc720_full_scan.json"
        if not fixture_path.exists():
            typer.echo(f"Fixture not found: {fixture_path}", err=True)
            raise typer.Exit(2)
        try:
            artifact = json.loads(fixture_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            typer.echo(f"Invalid JSON fixture: {fixture_path} ({exc})", err=True)
            raise typer.Exit(2) from exc
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
        title = f"helianthus-vrc-explorer scan (B524) dst=0x{dst_u8:02X}"
        subtitle_lines = [
            f"Started: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')}",
            f"ebusd: {host}:{port}",
            f"Planner: {planner_ui_value} (preset={preset_value})",
        ]
        with (
            make_scan_observer(
                console=console,
                title=title,
                subtitle_lines=subtitle_lines,
                show_tips=not no_tips,
            ) as observer,
            transport.session(),
        ):
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

    if run_results_viewer(console, artifact):
        output_path.write_text(
            json.dumps(artifact, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

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
