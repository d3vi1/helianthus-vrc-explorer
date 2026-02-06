from __future__ import annotations

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
def scan() -> None:
    """Scan a VRC regulator using B524 (GetExtendedRegisters)."""
    typer.echo("scan: not implemented yet")
