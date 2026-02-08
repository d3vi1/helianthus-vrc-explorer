from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ..scanner.plan import (
    GroupScanPlan,
    estimate_eta_seconds,
    estimate_register_requests,
    parse_int_set,
    parse_int_token,
)


@dataclass(frozen=True, slots=True)
class PlannerGroup:
    group: int
    name: str
    descriptor: float
    ii_max: int | None
    rr_max: int
    present_instances: tuple[int, ...]


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


def _format_seconds(seconds: float) -> str:
    if seconds < 0:
        return "?"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    rem = seconds - minutes * 60
    if minutes < 60:
        return f"{minutes}m {rem:0.0f}s"
    hours = minutes // 60
    minutes = minutes % 60
    return f"{hours}h {minutes}m"


def prompt_scan_plan(
    console: Console,
    groups: list[PlannerGroup],
    *,
    request_rate_rps: float | None,
) -> dict[int, GroupScanPlan]:
    """Prompt for a scan plan in interactive TTY mode.

    Returns a dict mapping GG -> GroupScanPlan.
    """

    eligible = {g.group: g for g in groups}
    if not eligible:
        return {}

    default_plan: dict[int, GroupScanPlan] = {}
    for g in eligible.values():
        instances = (0x00,) if g.ii_max is None else g.present_instances
        default_plan[g.group] = GroupScanPlan(group=g.group, rr_max=g.rr_max, instances=instances)

    console.print(Rule("Scan Planner", style="dim"))
    console.print(
        Text(
            "Select which groups/instances to scan and optionally override RR_max. "
            "Press Enter to keep defaults.",
            style="dim",
        )
    )

    table = Table(show_lines=False, header_style="bold dim")
    table.add_column("GG", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Desc", style="dim", justify="right", no_wrap=True)
    table.add_column("Present/Total", style="dim", justify="right", no_wrap=True)
    table.add_column("RR_max", style="magenta", justify="right", no_wrap=True)
    for g in sorted(groups, key=lambda x: x.group):
        present_total = "n/a" if g.ii_max is None else f"{len(g.present_instances)}/{g.ii_max + 1}"
        table.add_row(
            _hex_u8(g.group),
            g.name,
            f"{g.descriptor:.1f}",
            present_total,
            _hex_u16(g.rr_max),
        )
    console.print(table)

    default_requests = estimate_register_requests(default_plan)
    default_eta_s = estimate_eta_seconds(
        requests=default_requests,
        request_rate_rps=request_rate_rps,
    )
    default_eta_txt = _format_seconds(default_eta_s) if default_eta_s is not None else "n/a"
    default_rps_txt = f"{request_rate_rps:.2f}" if request_rate_rps is not None else "n/a"
    console.print(
        f"[dim]Default plan:[/dim] {default_requests} requests, ETA {default_eta_txt} "
        f"@ {default_rps_txt} req/s"
    )

    if not Confirm.ask("Customize scan plan?", default=False, console=console):
        plan = default_plan
        if not Confirm.ask("Proceed with register scan?", default=True, console=console):
            raise KeyboardInterrupt
        return plan

    # Step 1: select groups.
    while True:
        raw = Prompt.ask(
            "Groups to scan (e.g. 'all' or '0x02,0x03')",
            default="all",
            show_default=True,
            console=console,
        ).strip()
        lowered = raw.lower()
        if lowered in {"all", "*"}:
            selected_groups = sorted(eligible.keys())
            break
        if lowered in {"none", "no"}:
            selected_groups = []
            break
        try:
            parsed = parse_int_set(raw, min_value=0x00, max_value=0xFF)
        except ValueError as exc:
            console.print(f"[red]Invalid group selection:[/red] {exc}")
            continue
        unknown = [gg for gg in parsed if gg not in eligible]
        if unknown:
            unknown_txt = ", ".join(_hex_u8(gg) for gg in unknown)
            console.print(f"[red]Unknown group(s):[/red] {unknown_txt}")
            continue
        selected_groups = parsed
        break

    plan: dict[int, GroupScanPlan] = {}

    # Step 2: per-group instance selection + rr_max override.
    for gg in selected_groups:
        g = eligible[gg]
        instances: tuple[int, ...]
        if g.ii_max is None:
            instances = (0x00,)
        else:
            default_instances_mode = "present" if g.present_instances else "none"
            while True:
                raw_instances = Prompt.ask(
                    f"{_hex_u8(gg)} instances to scan ('present', 'all', 'none', or '0-10')",
                    default=default_instances_mode,
                    show_default=True,
                    console=console,
                ).strip()
                lowered = raw_instances.lower()
                if lowered in {"present", "p"}:
                    instances = g.present_instances
                    break
                if lowered in {"all", "*"}:
                    instances = tuple(range(0x00, g.ii_max + 1))
                    break
                if lowered in {"none", "no"}:
                    instances = ()
                    break
                try:
                    parsed_instances = parse_int_set(
                        raw_instances,
                        min_value=0x00,
                        max_value=g.ii_max,
                    )
                except ValueError as exc:
                    console.print(f"[red]Invalid instance selection:[/red] {exc}")
                    continue
                instances = tuple(parsed_instances)
                break

        while True:
            raw_rr_max = Prompt.ask(
                f"{_hex_u8(gg)} RR_max override (hex/dec)",
                default=_hex_u16(g.rr_max),
                show_default=True,
                console=console,
            ).strip()
            try:
                rr_max = parse_int_token(raw_rr_max)
            except ValueError as exc:
                console.print(f"[red]Invalid RR_max:[/red] {exc}")
                continue
            if not (0x0000 <= rr_max <= 0xFFFF):
                console.print("[red]RR_max out of range (0x0000..0xFFFF).[/red]")
                continue
            plan[gg] = GroupScanPlan(group=gg, rr_max=rr_max, instances=instances)
            break

    requests = estimate_register_requests(plan)
    eta_s = estimate_eta_seconds(requests=requests, request_rate_rps=request_rate_rps)
    eta_txt = _format_seconds(eta_s) if eta_s is not None else "n/a"
    rps_txt = f"{request_rate_rps:.2f}" if request_rate_rps is not None else "n/a"
    console.print(
        f"[dim]Estimated register requests:[/dim] {requests}  "
        f"[dim]ETA:[/dim] {eta_txt}  "
        f"[dim]rate:[/dim] {rps_txt} req/s"
    )

    if not Confirm.ask("Proceed with register scan?", default=True, console=console):
        raise KeyboardInterrupt

    return plan
