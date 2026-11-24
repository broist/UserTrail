"""Parancssori felület."""

import enum
import sqlite3
from collections.abc import Iterator
from datetime import datetime, time, timedelta, tzinfo
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from usertrail import __version__, cli_hu
from usertrail.alerts import AlertConfig, detect_alerts
from usertrail.correlate import (
    DEFAULT_COLLAPSE_GAP,
    DEFAULT_WINDOW,
    collapse_rows,
    correlate_web,
    pivot_seeds,
    seed_time_range,
)
from usertrail.identity import IdentityQuery, SidMap, resolve_sid_only_names
from usertrail.models import Category, Severity, TimelineEvent
from usertrail.parsers.evtx_reader import ReadStats
from usertrail.pipeline import KIND_IIS, SourceFile, discover_sources, iter_events
from usertrail.query import TimelineFilter, TimelineRow, select
from usertrail.report.console import print_timeline
from usertrail.store import CaseStore, StoreError, sha256_file
from usertrail.timeutil import format_display, parse_bound, resolve_tz, tz_label

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
        Path | None, typer.Option("--case", help="Vizsgálati adatbázis (lásd: ingest).")
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
    collapse: Annotated[
        bool,
        typer.Option(
            "--collapse",
            help=(
                "Az ismétlődő, zajos események (pl. sok hálózati bejelentkezés ugyanarról "
                "az IP-ről) összevonása egy sorba."
            ),
        ),
    ] = False,
    collapse_gap: Annotated[
        int,
        typer.Option(
            "--collapse-gap",
            min=1,
            help="Összevonásnál az egymást követő események közti legnagyobb szünet percben.",
        ),
    ] = int(DEFAULT_COLLAPSE_GAP.total_seconds() // 60),
    no_alerts: Annotated[
        bool, typer.Option("--no-alerts", help="A figyelmeztetések kikapcsolása.")
    ] = False,
    fail_threshold: Annotated[
        int,
        typer.Option(
            "--fail-threshold",
            min=1,
            help="Ennyi sikertelen bejelentkezés a --fail-window időn belül figyelmeztetést ad.",
        ),
    ] = AlertConfig().fail_threshold,
    fail_window: Annotated[
        int,
        typer.Option(
            "--fail-window", min=1, help="A sikertelen bejelentkezések időablaka percben."
        ),
    ] = int(AlertConfig().fail_window.total_seconds() // 60),
    work_hours: Annotated[
        str,
        typer.Option(
            "--work-hours",
            help="Munkaidő ÓÓ:PP-ÓÓ:PP alakban (hétköznap, a --tz időzónájában).",
        ),
    ] = "07:00-19:00",
    pivot_ip: Annotated[
        bool,
        typer.Option(
            "--pivot-ip",
            help=(
                "A felhasználó bejelentkezési IP-címeiről érkező webes (IIS) kérések "
                "bevonása „korrelált” jelöléssel."
            ),
        ),
    ] = False,
    pivot_window: Annotated[
        int,
        typer.Option(
            "--pivot-window",
            min=1,
            help="Az IP-pivot időablaka percben a bejelentkezés előtt és után.",
        ),
    ] = int(DEFAULT_WINDOW.total_seconds() // 60),
    iis_tz: Annotated[
        str | None,
        typer.Option(
            "--iis-tz",
            help=(
                "Az IIS-naplók időzónája, ha a szerveren helyi időre állították "
                "(alapértelmezés: UTC, ahogy az IIS alapból naplóz)."
            ),
        ),
    ] = None,
    lang: Annotated[Lang, typer.Option("--lang", help="A leírások nyelve.")] = Lang.hu,
) -> None:
    """Egy fiók (vagy egy forrás-IP) idővonalának megjelenítése."""
    if case is not None and source:
        raise typer.BadParameter("a --case és a --source közül csak az egyiket add meg")
    if case is None and not source:
        raise typer.BadParameter("adj meg --case adatbázist vagy --source útvonalat")
    if not (user or sid or ip):
        raise typer.BadParameter("adj meg --user, --sid vagy --ip kapcsolót")

    display_tz, start, end = _time_options(tz, from_, to)
    iis_zone = _iis_tz_option(iis_tz)
    work_start, work_end = _work_hours_option(work_hours)
    window = timedelta(minutes=pivot_window)
    web_pool: list[TimelineEvent] = []

    if case is not None:
        with _open_case(case) as store:
            sid_map = store.sid_map()
            identity = IdentityQuery.build(user, sid, sid_map) if (user or sid) else None
            events = store.candidate_events(
                names=identity.names if identity else (),
                sids=identity.sids if identity else (),
                ip=ip,
                start=start,
                end=end,
            )
            summary = f"[dim]{case}: {len(events)} jelölt esemény"
            if pivot_ip and identity is not None:
                web_pool = _web_pool_from_store(store, events, identity, window)
    else:
        assert source is not None
        files = discover_sources(source)
        if not files:
            err.print("[red]Nem található támogatott naplófájl (.evtx vagy IIS .log).[/red]")
            raise typer.Exit(code=1)
        stats = ReadStats()
        with err.status(f"{len(files)} naplófájl beolvasása..."):
            events = list(iter_events(files, stats, iis_zone))
        web_pool = events
        sid_map = SidMap()
        for event in events:
            sid_map.learn_event(event)
        identity = IdentityQuery.build(user, sid, sid_map) if (user or sid) else None
        summary = (
            f"[dim]{len(files)} fájlból {stats.records} rekord beolvasva, "
            f"{len(events)} leképezett esemény"
        )

    for event in events:
        resolve_sid_only_names(event, sid_map)
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
    correlated: list[TimelineRow] = []
    if pivot_ip:
        if identity is None:
            err.print("[yellow]A --pivot-ip csak --user vagy --sid megadásával működik.[/yellow]")
        else:
            correlated = _correlate(events, web_pool, flt, window, rows)
            rows = sorted(rows + correlated, key=lambda row: row.event.sort_key)
    alerts = []
    if not no_alerts:
        # A szabályok a keresett identitás (vagy IP) összes során futnak, a kategória- és
        # súlyosságszűrőtől függetlenül; csak az időszakszűrő érvényes.
        alert_filter = TimelineFilter(
            identity=identity,
            ip=ip,
            start=start,
            end=end,
            include_machine_accounts=include_machine_accounts,
        )
        alert_config = AlertConfig(
            fail_threshold=fail_threshold,
            fail_window=timedelta(minutes=fail_window),
            work_start=work_start,
            work_end=work_end,
            tz=display_tz,
        )
        alerts = detect_alerts(select(events, alert_filter), alert_config)
    if collapse:
        rows = collapse_rows(rows, timedelta(minutes=collapse_gap))
    title = " / ".join(x for x in (user, sid, ip) if x)
    print_timeline(rows, display_tz, lang.value, f"UserTrail: {title}", alerts=alerts)

    err.print(f"{summary}, ebből {len(rows)} jelenik meg.[/dim]")
    if alerts:
        err.print(f"[bold red]{len(alerts)} figyelmeztetés (lásd a Figyelmeztetések táblát).[/]")
    if correlated:
        err.print(
            f"[yellow]{len(correlated)} korrelált webes kérés (±{pivot_window} perc a "
            "bejelentkezésektől). Ezek nem bizonyítják, hogy a kérést ugyanaz a "
            "felhasználó küldte.[/yellow]"
        )
    if case is None and stats.errors:
        _print_errors(stats.errors, stats.error_samples)


def _work_hours_option(value: str) -> tuple[time, time]:
    """A --work-hours értéke (pl. ``07:00-19:00``)."""
    try:
        start_text, end_text = value.split("-", 1)
        start, end = time.fromisoformat(start_text.strip()), time.fromisoformat(end_text.strip())
    except ValueError:
        raise typer.BadParameter(
            f"érvénytelen munkaidő: {value} (várt alak: ÓÓ:PP-ÓÓ:PP)", param_hint="--work-hours"
        ) from None
    if start >= end:
        raise typer.BadParameter(
            "a munkaidő kezdete legyen korábbi a végénél", param_hint="--work-hours"
        )
    return start, end


def _iis_tz_option(iis_tz: str | None) -> tzinfo | None:
    """Az --iis-tz értéke; megadás nélkül UTC (``None`` itt UTC-t jelent)."""
    if iis_tz is None:
        return None
    try:
        zone = resolve_tz(iis_tz)
    except ValueError:
        raise typer.BadParameter(f"ismeretlen időzóna: {iis_tz}", param_hint="--iis-tz") from None
    if zone is None:
        # A "local" itt a gép helyi időzónáját jelenti, rögzített IANA-névvel nem rendelkezik.
        raise typer.BadParameter(
            "az --iis-tz értéke IANA-időzóna legyen, pl. Europe/Budapest", param_hint="--iis-tz"
        )
    return zone


def _seed_rows(
    events: list[TimelineEvent], identity: IdentityQuery, flt_time: TimelineFilter
) -> list[TimelineRow]:
    """A pivotpontokhoz a felhasználó összes sikeres bejelentkezése kell, a kategória- és
    súlyosságszűrőtől függetlenül (az időszakszűrő viszont érvényes)."""
    seed_filter = TimelineFilter(
        identity=identity,
        start=flt_time.start,
        end=flt_time.end,
        include_machine_accounts=True,
    )
    return select(events, seed_filter)


def _correlate(
    events: list[TimelineEvent],
    pool: list[TimelineEvent],
    flt: TimelineFilter,
    window: timedelta,
    direct_rows: list[TimelineRow],
) -> list[TimelineRow]:
    assert flt.identity is not None
    seeds = pivot_seeds(_seed_rows(events, flt.identity, flt))
    web_filter = TimelineFilter(
        start=flt.start,
        end=flt.end,
        categories=flt.categories,
        min_severity=flt.min_severity,
    )
    return correlate_web(
        seeds, pool, web_filter, window, exclude=(row.event.raw_ref for row in direct_rows)
    )


def _web_pool_from_store(
    store: CaseStore,
    events: list[TimelineEvent],
    identity: IdentityQuery,
    window: timedelta,
) -> list[TimelineEvent]:
    seeds = pivot_seeds(
        select(events, TimelineFilter(identity=identity, include_machine_accounts=True))
    )
    bounds = seed_time_range(seeds, window)
    if bounds is None:
        return []
    return store.events_from_ips(
        {seed.ip for seed in seeds}, start=bounds[0], end=bounds[1], source="IIS"
    )


def _time_options(
    tz: str | None, from_: str | None, to: str | None
) -> tuple[tzinfo | None, datetime | None, datetime | None]:
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
    return display_tz, start, end


def _open_case(case: Path, *, create: bool = False) -> CaseStore:
    try:
        return CaseStore.open(case, create=create)
    except StoreError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None
    except sqlite3.DatabaseError as exc:
        err.print(f"[red]A(z) {case} nem olvasható vizsgálati adatbázisként: {exc}[/red]")
        raise typer.Exit(code=1) from None


def _print_errors(count: int, samples: list[str]) -> None:
    err.print(f"[yellow]{count} rekordot nem sikerült feldolgozni:[/yellow]")
    for sample in samples:
        err.print(f"  [yellow]- {sample}[/yellow]")
    if count > len(samples):
        err.print(f"  [yellow]... és további {count - len(samples)}[/yellow]")


@app.command()
def ingest(
    paths: Annotated[
        list[Path], typer.Argument(exists=True, help="Beolvasandó fájlok vagy mappák.")
    ],
    case: Annotated[Path, typer.Option("--case", help="Vizsgálati adatbázisfájl.")],
    iis_tz: Annotated[
        str | None,
        typer.Option(
            "--iis-tz",
            help=(
                "Az IIS-naplók időzónája, ha a szerveren helyi időre állították "
                "(alapértelmezés: UTC, ahogy az IIS alapból naplóz)."
            ),
        ),
    ] = None,
) -> None:
    """EVTX- és IIS-naplók betöltése egy vizsgálati adatbázisba (a mappákat rekurzívan bejárja).

    Minden fájl SHA-256 hash-e feldolgozás előtt rögzítésre kerül; a már betöltött
    fájlokat (azonos hash) kihagyja. Az IIS-naplókat a .log kiterjesztés és a W3C-fejléc
    alapján ismeri fel.
    """
    iis_zone = _iis_tz_option(iis_tz)
    files = discover_sources(paths)
    if not files:
        err.print("[red]Nem található támogatott naplófájl (.evtx vagy IIS .log).[/red]")
        raise typer.Exit(code=1)

    results: list[tuple[str, str, int, int, int]] = []
    total_errors = 0
    with _open_case(case, create=True) as store:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("{task.fields[records]} rekord"),
            TimeElapsedColumn(),
            console=err,
        )
        with progress:
            overall = progress.add_task("Fájlok", total=len(files), records=0)
            for source_file in files:
                path = source_file.path
                progress.update(overall, description=f"Hash: {path.name}")
                digest = sha256_file(path)
                existing = store.find_source(digest)
                if existing is not None and existing.completed:
                    results.append((str(path), "már betöltve", existing.records, 0, 0))
                    progress.advance(overall)
                    continue
                if existing is not None:
                    # Félbeszakadt korábbi feldolgozás: a részleges adatokat eldobjuk.
                    store.discard_source(existing.id)

                progress.update(overall, description=f"Feldolgozás: {path.name}")
                options = {"iis_tz": iis_tz or "UTC"} if source_file.kind == KIND_IIS else {}
                source_id = store.add_source(
                    path, path.stat().st_size, digest, source_file.kind, options
                )
                stats = ReadStats()

                def counted(
                    source_file: SourceFile = source_file, stats: ReadStats = stats
                ) -> Iterator[TimelineEvent]:
                    events = iter_events([source_file], stats, iis_zone)
                    for number, event in enumerate(events, start=1):
                        if number % 1000 == 0:
                            progress.update(overall, records=stats.records)
                        yield event

                inserted = store.insert_events(source_id, counted())
                store.finish_source(
                    source_id, stats.records, inserted, stats.errors, stats.error_samples
                )
                total_errors += stats.errors
                results.append((str(path), "betöltve", stats.records, inserted, stats.errors))
                if stats.errors:
                    _print_errors(stats.errors, stats.error_samples)
                progress.update(overall, records=stats.records)
                progress.advance(overall)
        event_total = store.event_count()

    table = Table(title=f"Betöltés: {case}")
    table.add_column("Fájl")
    table.add_column("Állapot")
    table.add_column("Rekord", justify="right")
    table.add_column("Esemény", justify="right")
    table.add_column("Hiba", justify="right")
    for path_text, status, records, events, errors in results:
        style = "yellow" if errors else ("dim" if status == "már betöltve" else "")
        table.add_row(path_text, status, str(records), str(events), str(errors), style=style)
    Console().print(table)
    err.print(f"[dim]Az adatbázisban összesen {event_total} esemény van.[/dim]")
    if total_errors:
        err.print(f"[yellow]Összesen {total_errors} hibás rekord (lásd fent).[/yellow]")


@app.command()
def sources(case: Annotated[Path, typer.Option("--case")]) -> None:
    """Megmutatja, milyen naplóforrások állnak rendelkezésre, és mi hiányzik."""
    _not_yet(9)


@app.command()
def users(
    case: Annotated[Path, typer.Option("--case", help="Vizsgálati adatbázisfájl.")],
    tz: Annotated[
        str | None,
        typer.Option("--tz", help="Megjelenítési időzóna (alapértelmezés: helyi idő)."),
    ] = None,
    include_machine_accounts: Annotated[
        bool,
        typer.Option("--include-machine-accounts", help="A $ végű gépfiókok is látszódjanak."),
    ] = False,
) -> None:
    """A vizsgálatban ismert összes identitás listája."""
    display_tz, _, _ = _time_options(tz, None, None)
    with _open_case(case) as store:
        identities = store.identities(include_machine_accounts=include_machine_accounts)

    table = Table(title=f"Ismert identitások: {case}", caption=f"Időzóna: {tz_label(display_tz)}")
    table.add_column("Fiók")
    table.add_column("Tartomány")
    table.add_column("SID")
    table.add_column("Szereplő", justify="right")
    table.add_column("Célpont", justify="right")
    table.add_column("Első esemény", no_wrap=True)
    table.add_column("Utolsó esemény", no_wrap=True)
    table.add_column("Megjegyzés")
    for item in identities:
        notes = [n for n in (item.label, "gépfiók" if item.is_machine else None) if n]
        table.add_row(
            " / ".join(sorted(item.names, key=str.casefold)) or "-",
            ", ".join(sorted(item.domains)) or "-",
            item.sid or "-",
            str(item.as_actor),
            str(item.as_target),
            _fmt_stored(item.first_seen, display_tz),
            _fmt_stored(item.last_seen, display_tz),
            ", ".join(notes),
        )
    Console().print(table)
    err.print(f"[dim]{len(identities)} identitás.[/dim]")


def _fmt_stored(value: str | None, display_tz: tzinfo | None) -> str:
    return format_display(datetime.fromisoformat(value), display_tz) if value else "-"


@app.command()
def export(case: Annotated[Path, typer.Option("--case")]) -> None:
    """Idővonal exportálása CSV, JSON Lines vagy önálló HTML-riport formában."""
    _not_yet(8)


if __name__ == "__main__":  # pragma: no cover
    app()
