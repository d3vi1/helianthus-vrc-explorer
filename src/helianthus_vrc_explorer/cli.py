from __future__ import annotations

import json
from pathlib import Path

import typer

from . import __version__
from .scanner.scan import default_output_filename, scan_b524
from .transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport

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
    trace_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--trace-file",
        envvar="HELIA_EBUSD_TRACE_PATH",
        help="Write an ebusd request/response trace log to this file.",
    ),
) -> None:
    """Scan a VRC regulator using B524 (GetExtendedRegisters)."""
    dst_u8 = _parse_u8_address(dst)

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
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, trace_path=trace_file))
        artifact = scan_b524(transport, dst=dst_u8, ebusd_host=host, ebusd_port=port)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / default_output_filename(
        dst=dst_u8,
        scan_timestamp=artifact.get("meta", {}).get("scan_timestamp"),
    )
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    typer.echo(str(output_path))
