from __future__ import annotations

from helianthus_vrc_explorer.ui.planner import PlannerGroup
from helianthus_vrc_explorer.ui.planner_textual import (
    _EditableGroup,
    _estimate_footer,
    _parse_instances_spec,
)


def test_parse_instances_spec_accepts_keywords_and_ranges() -> None:
    group = PlannerGroup(
        group=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x0A,
        rr_max=0x21,
        present_instances=(0x00, 0x02, 0x03),
    )
    assert _parse_instances_spec("present", group=group) == (0x00, 0x02, 0x03)
    assert _parse_instances_spec("all", group=group) == tuple(range(0x0A + 1))
    assert _parse_instances_spec("0-2", group=group) == (0x00, 0x01, 0x02)


def test_estimate_footer_reports_requests_and_eta() -> None:
    group = PlannerGroup(
        group=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x0A,
        rr_max=0x02,
        present_instances=(0x00,),
    )
    states = {
        0x02: _EditableGroup(
            group=group,
            enabled=True,
            rr_max=0x02,
            instances=(0x00, 0x01),
        )
    }
    footer = _estimate_footer(states, request_rate_rps=2.0)
    assert "Plan: 6 requests" in footer
    assert "ETA:" in footer
    assert "1 groups selected" in footer
