"""Parancssori felület."""

import enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from usertrail import __version__, cli_hu
from usertrail.identity import IdentityQuery, SidMap
from usertrail.models import Category, Severity
from usertrail.parsers.evtx_reader import ReadStats
from usertrail.pipeline import discover_evtx, iter_events
from usertrail.query import TimelineFilter, select
from usertrail.report.console import print_timeline
from usertrail.timeutil import parse_bound, resolve_tz

cli_hu.apply()

app = typer.Typer(
    name="usertrail",
    help="Felhasználóközpontú Windows forensic idővonal-építő (EVTX- és IIS-naplók).",
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
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Kiírja a verziószámot, majd kilép.",
        ),
    ] = False,
) -> None:
    """A UserTrail egyetlen AD-fiók köré épít időrendi idővonalat."""


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
                f"ismeretlen kategória: {part!r}; lehetséges értékek: {valid}",
                param_hint="--category",
            ) from None
    return frozenset(result)


def _not_yet(milestone: int) -> None:
    err.print(f"[yellow]Ez még nincs kész (a {milestone}. mérföldkőben készül el).[/yellow]")
    raise typer.Exit(code=2)


@app.command()
def timeline(
    source: Annotated[
        list[Path] | None,
        typer.Option(
            "--source",
            "-s",
            exists=True,
            help=(
                "Közvetlenül beolvasandó EVTX-fájl vagy mappa "
                "(többször is megadható, a mappákat rekurzívan bejárja)."
            ),
        ),
    ] = None,
    case: Annotated[
        Path | None, typer.Option("--case", help="Vizsgálati adatbázis (a 4. mérföldkőtől).")
    ] = None,
    user: Annotated[
        str | None,
        typer.Option("--user", "-u", help="DOMAIN\\felhasználó, UPN vagy felhasználónév."),
    ] = None,
    sid: Annotated[str | None, typer.Option("--sid", help="A fiók SID-je.")] = None,
    ip: Annotated[str | None, typer.Option("--ip", help="Forrás-IP-cím.")] = None,
    from_: Annotated[
        str | None,
        typer.Option(
            "--from", help="Kezdete (dátum vagy ISO időpont, a megjelenítési időzónában)."
        ),
    ] = None,
    to: Annotated[
        str | None,
        typer.Option("--to", help="Vége (egy dátum az egész napot jelenti)."),
    ] = None,
    tz: Annotated[
        str | None,
        typer.Option(
            "--tz", help="Megjelenítési időzóna, pl. Europe/Budapest (alapértelmezés: helyi idő)."
        ),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option(
            "--category", help="Kategóriák vesszővel elválasztva, pl. AUTHENTICATION,PASSWORD."
        ),
    ] = None,
    min_severity: Annotated[
        Severity,
        typer.Option(
            "--min-severity",
            case_sensitive=False,
            help="Legalacsonyabb megjelenített súlyosság.",
        ),
    ] = Severity.INFO,
    include_machine_accounts: Annotated[
        bool,
        typer.Option(
            "--include-machine-accounts", help="A $ végű gépfiókok eseményei is látszódjanak."
        ),
    ] = False,
    lang: Annotated[Lang, typer.Option("--lang", help="A leírások nyelve.")] = Lang.hu,
) -> None:
    """Egy fiók (vagy egy forrás-IP) idővonalának megjelenítése."""
    if case is not None:
        _not_yet(4)
    if not source:
        raise typer.BadParameter("adj meg legalább egy --source útvonalat", param_hint="--source")
    if not (user or sid or ip):
        raise typer.BadParameter("adj meg --user, --sid vagy --ip kapcsolót")

    try:
        display_tz = resolve_tz(tz)
    except ValueError:
        raise typer.BadParameter(f"ismeretlen időzóna: {tz}", param_hint="--tz") from None
    try:
        start = parse_bound(from_, display_tz) if from_ else None
    except ValueError:
        raise typer.BadParameter(f"érvénytelen időpont: {from_}", param_hint="--from") from None
    try:
        end = parse_bound(to, display_tz, end=True) if to else None
    except ValueError:
        raise typer.BadParameter(f"érvénytelen időpont: {to}", param_hint="--to") from None

    files = discover_evtx(source)
    if not files:
        err.print("[red]Nem található .evtx fájl.[/red]")
        raise typer.Exit(code=1)

    stats = ReadStats()
    with err.status(f"{len(files)} EVTX-fájl beolvasása..."):
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
        f"[dim]{len(files)} fájlból {stats.records} rekord beolvasva, "
        f"{len(events)} leképezett esemény, ebből {len(rows)} jelenik meg.[/dim]"
    )
    if stats.errors:
        err.print(f"[yellow]{stats.errors} rekordot nem sikerült feldolgozni:[/yellow]")
        for sample in stats.error_samples:
            err.print(f"  [yellow]- {sample}[/yellow]")


@app.command()
def ingest(
    paths: Annotated[list[Path], typer.Argument(help="Beolvasandó fájlok vagy mappák.")],
    case: Annotated[Path, typer.Option("--case", help="Vizsgálati adatbázisfájl.")],
) -> None:
    """EVTX- és IIS-naplók betöltése egy vizsgálati adatbázisba."""
    _not_yet(4)


@app.command()
def sources(case: Annotated[Path, typer.Option("--case")]) -> None:
    """Megmutatja, milyen naplóforrások állnak rendelkezésre, és mi hiányzik."""
    _not_yet(9)


@app.command()
def users(case: Annotated[Path, typer.Option("--case")]) -> None:
    """A vizsgálatban ismert összes identitás listája."""
    _not_yet(4)


@app.command()
def export(case: Annotated[Path, typer.Option("--case")]) -> None:
    """Idővonal exportálása CSV, JSON Lines vagy önálló HTML-riport formában."""
    _not_yet(8)


if __name__ == "__main__":  # pragma: no cover
    app()
