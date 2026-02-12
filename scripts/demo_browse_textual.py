#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from helianthus_vrc_explorer.ui.browse_textual import run_browse_from_artifact


def main() -> int:
    artifact = json.loads(Path("fixtures/demo_browse.json").read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise SystemExit("Invalid demo artifact: expected JSON object root")
    run_browse_from_artifact(artifact, allow_write=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
