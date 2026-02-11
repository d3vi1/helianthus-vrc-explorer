# helianthus-vrc-explorer

[![CI](https://github.com/d3vi1/helianthus-vrc-explorer/actions/workflows/ci.yml/badge.svg)](https://github.com/d3vi1/helianthus-vrc-explorer/actions/workflows/ci.yml)

Helianthus VRC Explorer is a professional CLI tool for scanning Vaillant VRC heating regulators via eBUS (B5 24 / B524 GetExtendedRegisters). It focuses on safe, read-oriented discovery and produces a high-quality JSON artifact.

## Goals
- Scan VRC regulators using the B524 protocol family (groups, instances, registers).
- Provide a polished terminal experience (rich formatting, progress, summaries).
- Produce complete JSON artifacts with metadata.
- Keep non-code assets (CSV/JSON fixtures, schemas) as editable data files, not hardcoded into Python.
- CI-gated development: lint + format + tests for every PR.

## Non-goals (for now)
- Shipping a full Home Assistant integration from this repository.
- Writing to devices by default. Any write/control functionality must be explicit and reviewed.

## Quick start (planned interface)
```bash
python -m helianthus_vrc_explorer scan \
  --dst 0x15 \
  --host 127.0.0.1 \
  --port 8888 \
  --planner-ui auto \
  --preset recommended
```

Key scan UX flags:
- `--planner-ui auto|textual|classic`
- `--preset conservative|recommended|aggressive|custom`
- `--no-tips`
- `--trace-file /path/to/trace.log`

## TUI Preview
<picture>
  <source srcset="artifacts/readme/preview.gif" type="image/gif">
  <img src="artifacts/readme/preview.png" alt="helianthus-vrc-explorer terminal preview">
</picture>

Regenerate preview assets from first 5 minutes of autorun, sped up 10x (300s -> 30s):

```bash
./scripts/capture_tui_preview.sh --capture-seconds 300 --speedup 10
```

Optional:
- `--output-seconds 45` to override final animation duration
- `--command "python -m helianthus_vrc_explorer scan ..."` to capture a different run
- `--font-path "/path/to/Anonymous Pro.ttf"` to force font selection

## Development
Requirements: Python 3.12+

```bash
python -m venv venv
source venv/bin/activate

pip install -e ".[dev]"
ruff check .
ruff format .
pytest
```

## Data files
If you need to add or update non-code data (schemas, fixtures, CSV/JSON dumps), keep it as data under `data/` so non-programmers can review and edit it via PRs.

## License
GPL-3.0-or-later. See `LICENSE`.
