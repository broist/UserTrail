"""Konzolos kimenet (rich táblázat)."""

from __future__ import annotations

from collections.abc import Collection, Sequence
from datetime import tzinfo

from rich.console import Console
from rich.table import Table
from rich.text import Text

from usertrail.alerts import Alert
from usertrail.i18n import ui
from usertrail.models import Role, Severity
from usertrail.query import TimelineRow
from usertrail.report.text import row_description
from usertrail.timeutil import format_display, tz_label

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.INFO: "",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
}

ROLE_STYLE: dict[Role, str] = {
    Role.ACTOR: "bold magenta",
    Role.TARGET: "bold blue",
    Role.BOTH: "bold magenta",
    Role.RELATED: "dim",
    Role.CORRELATED: "italic yellow",
}

ALERT_MARK = "!"


def build_table(
    rows: Sequence[TimelineRow],
    tz: tzinfo | None,
    lang: str,
    title: str,
    alerted: Collection[str] = (),
) -> Table:
    table = Table(
        title=title,
        caption=f"{ui('header.tz', lang)}: {tz_label(tz, lang)}",
        show_lines=False,
        expand=False,
    )
    show_marks = bool(alerted)
    if show_marks:
        table.add_column(ui("col.alert", lang), no_wrap=True, style="bold red")
    table.add_column(ui("col.time", lang), no_wrap=True)
    table.add_column(ui("col.source", lang), no_wrap=True)
    table.add_column(ui("col.host", lang))
    table.add_column(ui("col.event", lang), no_wrap=True)
    table.add_column(ui("col.role", lang), no_wrap=True)
    table.add_column(ui("col.ip", lang), no_wrap=True)
    table.add_column(ui("col.description", lang), overflow="fold")
    for row in rows:
        ev = row.event
        cells: list[str | Text] = []
        if show_marks:
            marked = any(ref in alerted for ref in row.raw_refs)
            cells.append(ALERT_MARK if marked else "")
        event_label = f"{ev.event_id} {ev.action}"
        if row.is_collapsed:
            event_label += f" ×{len(row.members)}"
        cells += [
            format_display(ev.timestamp_utc, tz),
            ev.source,
            ev.host,
            event_label,
            Text(ui(f"role.{row.role.value}", lang), style=ROLE_STYLE[row.role]),
            ev.src_ip or "",
            row_description(row, tz, lang),
        ]
        table.add_row(*cells, style=SEVERITY_STYLE[ev.severity])
    return table


def build_alert_table(alerts: Sequence[Alert], tz: tzinfo | None, lang: str) -> Table:
    table = Table(title=ui("alerts.title", lang), expand=False)
    table.add_column(ui("col.time", lang), no_wrap=True)
    table.add_column(ui("col.severity", lang), no_wrap=True)
    table.add_column(ui("col.rule", lang))
    table.add_column(ui("col.description", lang), overflow="fold")
    for alert in alerts:
        table.add_row(
            format_display(alert.timestamp_utc, tz),
            ui(f"severity.{alert.severity.value}", lang),
            ui(f"rule.{alert.rule}", lang),
            alert.description(lang),
            style=SEVERITY_STYLE[alert.severity],
        )
    return table


def print_timeline(
    rows: Sequence[TimelineRow],
    tz: tzinfo | None,
    lang: str,
    title: str,
    console: Console | None = None,
    alerts: Sequence[Alert] = (),
) -> None:
    console = console or Console()
    if not rows:
        console.print(ui("no_events", lang))
        console.print(f"{ui('header.tz', lang)}: {tz_label(tz, lang)}", style="dim")
    else:
        alerted = {ref for alert in alerts for ref in alert.refs}
        console.print(build_table(rows, tz, lang, title, alerted))
    if alerts:
        console.print(build_alert_table(alerts, tz, lang))
