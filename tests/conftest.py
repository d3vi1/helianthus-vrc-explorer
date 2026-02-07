from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_scanner_time_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent unit tests from actually sleeping on scanner timeout retries."""

    import helianthus_vrc_explorer.scanner.register as register

    monkeypatch.setattr(register.time, "sleep", lambda _seconds: None)
