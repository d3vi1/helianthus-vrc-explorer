from typer.testing import CliRunner

from helianthus_vrc_explorer import __version__
from helianthus_vrc_explorer.cli import app


def test_version_prints_version() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_command_is_present() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
