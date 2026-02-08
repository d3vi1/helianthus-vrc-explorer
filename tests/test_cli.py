import json
from pathlib import Path

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
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0


def test_discover_command_is_present() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["discover", "--help"])
    assert result.exit_code == 0


def test_scan_dry_run_writes_scan_artifact(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--dry-run", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0

    output_path = Path(result.stdout.strip())
    assert output_path.exists()
    assert output_path.with_suffix(".html").exists()

    artifact = json.loads(output_path.read_text(encoding="utf-8"))
    assert isinstance(artifact, dict)
    assert "meta" in artifact
    assert "groups" in artifact
    assert isinstance(artifact["groups"], dict)

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
