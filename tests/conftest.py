from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_scanner_time_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep compatibility with legacy scanner timeout tests."""

    import helianthus_vrc_explorer.scanner.register as register

    time_module = getattr(register, "time", None)
    if time_module is not None:
        monkeypatch.setattr(time_module, "sleep", lambda _seconds: None)
