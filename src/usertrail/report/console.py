"""Konzolos kimenet (rich táblázat)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import tzinfo

from rich.console import Console
from rich.table import Table
from rich.text import Text

from usertrail.i18n import ui
from usertrail.models import Role, Severity
from usertrail.query import TimelineRow
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


def build_table(rows: Sequence[TimelineRow], tz: tzinfo | None, lang: str, title: str) -> Table:
    table = Table(
        title=title,
        caption=f"{ui('header.tz', lang)}: {tz_label(tz, lang)}",
        show_lines=False,
        expand=False,
    )
    table.add_column(ui("col.time", lang), no_wrap=True)
    table.add_column(ui("col.source", lang), no_wrap=True)
    table.add_column(ui("col.host", lang))
    table.add_column(ui("col.event", lang), no_wrap=True)
    table.add_column(ui("col.role", lang), no_wrap=True)
    table.add_column(ui("col.ip", lang), no_wrap=True)
    table.add_column(ui("col.description", lang), overflow="fold")
    for row in rows:
        ev = row.event
        table.add_row(
            format_display(ev.timestamp_utc, tz),
            ev.source,
            ev.host,
            f"{ev.event_id} {ev.action}",
            Text(ui(f"role.{row.role.value}", lang), style=ROLE_STYLE[row.role]),
            ev.src_ip or "",
            ev.description(lang),
            style=SEVERITY_STYLE[ev.severity],
        )
    return table


def print_timeline(
    rows: Sequence[TimelineRow],
    tz: tzinfo | None,
    lang: str,
    title: str,
    console: Console | None = None,
) -> None:
    console = console or Console()
    if not rows:
        console.print(ui("no_events", lang))
        console.print(f"{ui('header.tz', lang)}: {tz_label(tz, lang)}", style="dim")
        return
    console.print(build_table(rows, tz, lang, title))
