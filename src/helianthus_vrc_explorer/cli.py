from __future__ import annotations

import json
from pathlib import Path

import typer

from . import __version__

app = typer.Typer(add_completion=False, invoke_without_command=True, no_args_is_help=True)


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
    dry_run: bool = typer.Option(  # noqa: B008
        False,
        "--dry-run",
        help="Replay a scan fixture and write it as the output artifact (no device I/O).",
    ),
    fixture: Path | None = typer.Option(  # noqa: B008
        None,
        "--fixture",
        help=(
            "Path to a scan artifact fixture JSON "
            "(defaults to fixtures/vrc720_full_scan.json in repo)."
        ),
    ),
    output_dir: Path = typer.Option(  # noqa: B008
        Path("."),
        "--output-dir",
        help="Directory to write the scan JSON artifact to.",
    ),
) -> None:
    """Scan a VRC regulator using B524 (GetExtendedRegisters)."""
    if not dry_run:
        typer.echo("scan: not implemented yet (use --dry-run)")
        return

    fixture_path = fixture or (
        Path(__file__).resolve().parents[2] / "fixtures" / "vrc720_full_scan.json"
    )
    if not fixture_path.exists():
        typer.echo(f"Fixture not found: {fixture_path}", err=True)
        raise typer.Exit(2)

    try:
        artifact = json.loads(fixture_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        typer.echo(f"Invalid JSON fixture: {fixture_path} ({exc})", err=True)
        raise typer.Exit(2) from exc

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "scan.json"
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    typer.echo(str(output_path))
