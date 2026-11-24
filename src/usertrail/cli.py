"""Command line interface."""

import enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from usertrail import __version__
from usertrail.identity import IdentityQuery, SidMap
from usertrail.models import Category, Severity
from usertrail.parsers.evtx_reader import ReadStats
from usertrail.pipeline import discover_evtx, iter_events
from usertrail.query import TimelineFilter, select
from usertrail.report.console import print_timeline
from usertrail.timeutil import parse_bound, resolve_tz

app = typer.Typer(
    name="usertrail",
    help="Identity-centric Windows forensic timeline builder (EVTX + IIS logs).",
    no_args_is_help=True,
    add_completion=False,
)
err = Console(stderr=True)


class Lang(enum.StrEnum):
    en = "en"
    hu = "hu"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"usertrail {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
        ),
    ] = False,
) -> None:
    """UserTrail builds one chronological timeline around a single AD account."""


def _parse_categories(value: str | None) -> frozenset[Category] | None:
    if not value:
        return None
    result: set[Category] = set()
    for part in value.split(","):
        name = part.strip().upper()
        if not name:
            continue
        try:
            result.add(Category(name))
        except ValueError:
            valid = ", ".join(c.value for c in Category)
            raise typer.BadParameter(
                f"unknown category {part!r}; valid: {valid}", param_hint="--category"
            ) from None
    return frozenset(result)


def _not_yet(milestone: int) -> None:
    err.print(f"[yellow]Not implemented yet (planned for milestone {milestone}).[/yellow]")
    raise typer.Exit(code=2)


@app.command()
def timeline(
    source: Annotated[
        list[Path] | None,
        typer.Option(
            "--source",
            "-s",
            exists=True,
            help="EVTX file or folder to read directly (repeatable, folders are recursive).",
        ),
    ] = None,
    case: Annotated[
        Path | None, typer.Option("--case", help="Case database (available from milestone 4).")
    ] = None,
    user: Annotated[
        str | None, typer.Option("--user", "-u", help="DOMAIN\\user, UPN, or user name.")
    ] = None,
    sid: Annotated[str | None, typer.Option("--sid", help="Account SID.")] = None,
    ip: Annotated[str | None, typer.Option("--ip", help="Source IP address.")] = None,
    from_: Annotated[
        str | None,
        typer.Option("--from", help="Start (date or ISO datetime, in the display time zone)."),
    ] = None,
    to: Annotated[
        str | None,
        typer.Option("--to", help="End (a date includes the whole day)."),
    ] = None,
    tz: Annotated[
        str | None,
        typer.Option("--tz", help="Display time zone, e.g. Europe/Budapest (default: local)."),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option("--category", help="Comma separated list, e.g. AUTHENTICATION,PASSWORD."),
    ] = None,
    min_severity: Annotated[
        Severity, typer.Option("--min-severity", case_sensitive=False)
    ] = Severity.INFO,
    include_machine_accounts: Annotated[
        bool,
        typer.Option("--include-machine-accounts", help="Keep events of accounts ending in $."),
    ] = False,
    lang: Annotated[Lang, typer.Option("--lang", help="Description language.")] = Lang.en,
) -> None:
    """Show the timeline of one account (or of one source IP)."""
    if case is not None:
        _not_yet(4)
    if not source:
        raise typer.BadParameter("give at least one --source path", param_hint="--source")
    if not (user or sid or ip):
        raise typer.BadParameter("give --user, --sid or --ip")

    try:
        display_tz = resolve_tz(tz)
        start = parse_bound(from_, display_tz) if from_ else None
        end = parse_bound(to, display_tz, end=True) if to else None
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    files = discover_evtx(source)
    if not files:
        err.print("[red]No .evtx files found.[/red]")
        raise typer.Exit(code=1)

    stats = ReadStats()
    with err.status(f"Reading {len(files)} EVTX file(s)..."):
        events = list(iter_events(files, stats))

    sid_map = SidMap()
    for event in events:
        sid_map.learn(event.actor)
        sid_map.learn(event.target)

    identity = IdentityQuery.build(user, sid, sid_map) if (user or sid) else None
    flt = TimelineFilter(
        identity=identity,
        ip=ip,
        start=start,
        end=end,
        categories=_parse_categories(category),
        min_severity=min_severity,
        include_machine_accounts=include_machine_accounts,
    )
    rows = select(events, flt)
    title = " / ".join(x for x in (user, sid, ip) if x)
    print_timeline(rows, display_tz, lang.value, f"UserTrail: {title}")

    err.print(
        f"[dim]{stats.records} records read from {len(files)} file(s), "
        f"{len(events)} mapped events, {len(rows)} shown.[/dim]"
    )
    if stats.errors:
        err.print(f"[yellow]{stats.errors} record(s) could not be processed:[/yellow]")
        for sample in stats.error_samples:
            err.print(f"  [yellow]- {sample}[/yellow]")


@app.command()
def ingest(
    paths: Annotated[list[Path], typer.Argument(help="Files or folders to ingest.")],
    case: Annotated[Path, typer.Option("--case", help="Case database file.")],
) -> None:
    """Ingest EVTX and IIS logs into a case database."""
    _not_yet(4)


@app.command()
def sources(case: Annotated[Path, typer.Option("--case")]) -> None:
    """Show which log sources are available in a case and what is missing."""
    _not_yet(9)


@app.command()
def users(case: Annotated[Path, typer.Option("--case")]) -> None:
    """List every identity known in a case."""
    _not_yet(4)


@app.command()
def export(case: Annotated[Path, typer.Option("--case")]) -> None:
    """Export a timeline as CSV, JSON Lines or a self-contained HTML report."""
    _not_yet(8)


if __name__ == "__main__":  # pragma: no cover
    app()
