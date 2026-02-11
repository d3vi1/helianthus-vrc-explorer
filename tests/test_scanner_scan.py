from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from helianthus_vrc_explorer.scanner.observer import ScanObserver
from helianthus_vrc_explorer.scanner.plan import GroupScanPlan
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import TransportInterface
from helianthus_vrc_explorer.transport.dummy import DummyTransport


class RecordingTransport(TransportInterface):
    def __init__(self, inner: TransportInterface) -> None:
        self._inner = inner
        self.register_reads: list[tuple[int, int, int]] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        if len(payload) == 6 and payload[0] in {0x02, 0x06} and payload[1] == 0x00:
            group = payload[2]
            instance = payload[3]
            register = int.from_bytes(payload[4:6], byteorder="little", signed=False)
            self.register_reads.append((group, instance, register))
        return self._inner.send(dst, payload)


class InterruptingTransport(TransportInterface):
    def __init__(self, inner: TransportInterface, interrupt_after: int) -> None:
        self._inner = inner
        self._interrupt_after = interrupt_after
        self._calls = 0

    def send(self, dst: int, payload: bytes) -> bytes:
        self._calls += 1
        if self._calls > self._interrupt_after:
            raise KeyboardInterrupt
        return self._inner.send(dst, payload)


def _write_fixture_group_02(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x05"}},
        "groups": {
            "0x02": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            # Presence probe (UIN)
                            "0x0002": {"raw_hex": "0100"},
                            # Sample float32 (EXP) value
                            "0x000f": {"raw_hex": "9a99d93f"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_unknown_group_69(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x6a"}},
        "groups": {
            "0x69": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0000": {"raw_hex": "00"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture_unknown.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


class _NoopObserver(ScanObserver):
    def phase_start(self, phase: str, *, total: int) -> None:  # noqa: ARG002
        return

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:  # noqa: ARG002
        return

    def phase_set_total(self, phase: str, *, total: int) -> None:  # noqa: ARG002
        return

    def phase_finish(self, phase: str) -> None:  # noqa: ARG002
        return

    def status(self, message: str) -> None:  # noqa: ARG002
        return

    def log(self, message: str, *, level: str = "info") -> None:  # noqa: ARG002
        return

    def suspend(self):  # type: ignore[override]
        from contextlib import contextmanager

        @contextmanager
        def _cm():
            yield None

        return _cm()


def test_scan_b524_scans_all_instances_and_register_range(tmp_path: Path) -> None:
    transport = RecordingTransport(DummyTransport(_write_fixture_group_02(tmp_path)))

    artifact = scan_b524(transport, dst=0x15)

    assert artifact["meta"]["destination_address"] == "0x15"
    assert artifact["meta"]["incomplete"] is False

    group = artifact["groups"]["0x02"]
    assert group["descriptor_type"] == 1.0

    instance_00 = group["instances"]["0x00"]
    assert instance_00["present"] is True

    registers = instance_00["registers"]
    assert registers["0x0002"]["type"] == "UIN"
    assert registers["0x0002"]["value"] == 1
    assert registers["0x0002"]["raw_hex"] == "0100"
    assert registers["0x0002"]["error"] is None

    assert registers["0x000f"]["type"] == "EXP"
    assert registers["0x000f"]["value"] == pytest.approx(1.7, abs=1e-6)

    # Phase B/C: instance discovery must scan all II=0x00..ii_max (no early stop at gaps).
    probed_instances = sorted(
        {ii for (gg, ii, rr) in transport.register_reads if gg == 0x02 and rr == 0x0002}
    )
    assert probed_instances == list(range(0x0A + 1))

    # Phase D: register scan must cover RR=0x0000..rr_max for present instances.
    scanned_registers = {
        rr for (gg, ii, rr) in transport.register_reads if gg == 0x02 and ii == 0x00
    }
    assert scanned_registers == set(range(0x21 + 1))


def test_scan_b524_scans_enabled_unknown_group_via_planner(monkeypatch, tmp_path: Path) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = DummyTransport(_write_fixture_unknown_group_69(tmp_path))

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {0x69: GroupScanPlan(group=0x69, rr_max=0x0000, instances=(0x00,))}

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    assert "0x69" in artifact["groups"]
    registers = artifact["groups"]["0x69"]["instances"]["0x00"]["registers"]
    assert registers["0x0000"]["raw_hex"] == "00"


def test_scan_b524_scans_absent_instances_when_planner_overrides(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = RecordingTransport(DummyTransport(_write_fixture_group_02(tmp_path)))

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            0x02: GroupScanPlan(
                group=0x02,
                rr_max=0x0002,
                instances=(
                    0x00,  # present (fixture)
                    0x01,  # absent (forced by planner override)
                ),
            )
        }

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    group = artifact["groups"]["0x02"]
    assert group["instances"]["0x00"]["present"] is True

    absent = group["instances"]["0x01"]
    assert absent["present"] is False
    assert set(absent["registers"].keys()) == {"0x0000", "0x0001", "0x0002"}

    scanned_registers = {
        rr for (gg, ii, rr) in transport.register_reads if gg == 0x02 and ii == 0x01
    }
    assert scanned_registers == set(range(0x0002 + 1))


def test_scan_b524_applies_aggressive_preset_to_textual_default_plan(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    transport = DummyTransport(_write_fixture_unknown_group_69(tmp_path))
    captured: dict[str, object] = {}

    def fake_run_textual_scan_plan(
        _groups,
        *,
        request_rate_rps,
        default_plan,
        default_preset,
    ):
        captured["default_preset"] = default_preset
        captured["default_plan"] = default_plan
        captured["request_rate_rps"] = request_rate_rps
        return {}

    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        fake_run_textual_scan_plan,
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="textual",
        planner_preset="aggressive",
    )

    assert captured["default_preset"] == "aggressive"
    default_plan = captured["default_plan"]
    assert isinstance(default_plan, dict)
    assert 0x69 in default_plan
    group_plan = default_plan[0x69]
    assert group_plan.rr_max == 0x30
    assert group_plan.instances == tuple(range(0x0A + 1))


def test_scan_b524_applies_preset_in_non_interactive_mode(tmp_path: Path) -> None:
    artifact = scan_b524(
        DummyTransport(_write_fixture_unknown_group_69(tmp_path)),
        dst=0x15,
        planner_ui="auto",
        planner_preset="aggressive",
    )

    scan_plan = artifact["meta"]["scan_plan"]["groups"]
    assert "0x69" in scan_plan
    assert scan_plan["0x69"]["rr_max"] == "0x0030"
    assert scan_plan["0x69"]["instances"] == [f"0x{ii:02x}" for ii in range(0x0A + 1)]

    # With aggressive preset we scan unknown groups and all instance slots even when not present.
    scanned_absent_instance = artifact["groups"]["0x69"]["instances"]["0x01"]
    assert scanned_absent_instance["present"] is False
    assert "0x0030" in scanned_absent_instance["registers"]


def test_scan_b524_textual_failure_falls_back_to_classic_in_auto_mode(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = DummyTransport(_write_fixture_unknown_group_69(tmp_path))
    classic_called = {"count": 0}

    def fake_run_textual_scan_plan(*_args, **_kwargs):
        raise RuntimeError("textual init failed")

    def fake_prompt_scan_plan(*_args, **kwargs):
        classic_called["count"] += 1
        default_plan = kwargs.get("default_plan")
        assert isinstance(default_plan, dict)
        return default_plan

    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        fake_run_textual_scan_plan,
    )
    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="auto",
        planner_preset="recommended",
    )

    assert artifact["meta"]["incomplete"] is False
    assert classic_called["count"] >= 1


def test_scan_b524_textual_failure_raises_in_forced_textual_mode(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    transport = DummyTransport(_write_fixture_unknown_group_69(tmp_path))

    def fake_run_textual_scan_plan(*_args, **_kwargs):
        raise RuntimeError("textual init failed")

    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        fake_run_textual_scan_plan,
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    with pytest.raises(RuntimeError, match="Textual planner requested but failed to start"):
        scan_b524(
            transport,
            dst=0x15,
            observer=_NoopObserver(),
            console=Console(force_terminal=True),
            planner_ui="textual",
        )


def test_scan_b524_replan_before_first_completed_task_does_not_divide_by_zero(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys
    from contextlib import contextmanager

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    class _FakeHotkeys:
        def __init__(self, *, enabled: bool) -> None:
            self._enabled = enabled
            self._seen = False

        def __enter__(self) -> _FakeHotkeys:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def poll(self) -> bool:
            if not self._enabled or self._seen:
                return False
            self._seen = True
            return True

        @contextmanager
        def suspend(self):
            yield None

    transport = DummyTransport(_write_fixture_group_02(tmp_path))

    def fake_prompt_scan_plan(*_args, **kwargs):
        default_plan = kwargs.get("default_plan")
        assert isinstance(default_plan, dict)
        return default_plan

    monkeypatch.setattr(scan_mod, "_PlannerHotkeyReader", _FakeHotkeys)
    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    assert artifact["meta"]["incomplete"] is False


def test_scan_b524_marks_incomplete_on_keyboard_interrupt(tmp_path: Path) -> None:
    inner = DummyTransport(_write_fixture_group_02(tmp_path))
    transport = InterruptingTransport(inner, interrupt_after=10)

    artifact = scan_b524(transport, dst=0x15)

    assert artifact["meta"]["incomplete"] is True
    assert artifact["meta"]["incomplete_reason"] == "user_interrupt"
