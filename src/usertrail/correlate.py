"""Korreláció és aggregálás.

**IP-pivot:** a felhasználó bejelentkezési IP-címeiről érkező webes kérések bevonása.

A korrelált események **nem bizonyítékok** arra, hogy a kérést ugyanaz a felhasználó
küldte (ugyanarról az IP-ről más is dolgozhatott, pl. NAT vagy terminálszerver mögül),
ezért ``Role.CORRELATED`` szereppel, külön jelölve kerülnek az idővonalra, és minden
sor megőrzi, melyik bejelentkezéshez kötöttük.

**Aggregálás (--collapse):** az ismétlődő, zajos események (pl. sok hálózati
bejelentkezés vagy Kerberos-jegy ugyanarról az IP-ről) egy sorba vonása. Csak az
információ/alacsony súlyosságú, ``COLLAPSIBLE_ACTIONS`` eseményeket vonja össze; az
összevont sor minden eredeti esemény hivatkozását megőrzi.
"""

from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from usertrail.models import Role, TimelineEvent
from usertrail.netutil import is_external_ip
from usertrail.query import TimelineFilter, TimelineRow, passes_filters

DEFAULT_WINDOW = timedelta(hours=1)
WEB_SOURCE = "IIS"

# Sikeres bejelentkezést jelző műveletek, amelyek forrás-IP-je pivotpont lehet.
# (A Kerberos- és RDP-események a 6. mérföldkőben kapják meg ezeket a műveletneveket.)
SEED_ACTIONS = frozenset({"logon_success", "kerberos_tgt", "rdp_auth_success", "rdp_logon"})
_SEED_ROLES = frozenset({Role.TARGET, Role.ACTOR, Role.BOTH})


@dataclass(frozen=True, slots=True)
class PivotSeed:
    """Egy sikeres bejelentkezés, amelynek IP-címéről a webes kéréseket keressük."""

    ip: str
    timestamp_utc: datetime
    raw_ref: str


def pivot_seeds(rows: Iterable[TimelineRow]) -> list[PivotSeed]:
    """A felhasználó sikeres bejelentkezései külső (nem üres, nem loopback) IP-címmel."""
    seeds = []
    for row in rows:
        event = row.event
        if (
            event.action in SEED_ACTIONS
            and row.role in _SEED_ROLES
            and is_external_ip(event.src_ip)
            and event.src_ip is not None
        ):
            seeds.append(PivotSeed(event.src_ip, event.timestamp_utc, event.raw_ref))
    return seeds


def seed_time_range(
    seeds: Sequence[PivotSeed], window: timedelta = DEFAULT_WINDOW
) -> tuple[datetime, datetime] | None:
    """Az az időtartomány, amelyben korrelált esemény egyáltalán előfordulhat."""
    if not seeds:
        return None
    times = [seed.timestamp_utc for seed in seeds]
    return (min(times) - window, max(times) + window)


def correlate_web(
    seeds: Sequence[PivotSeed],
    pool: Iterable[TimelineEvent],
    flt: TimelineFilter,
    window: timedelta = DEFAULT_WINDOW,
    exclude: Iterable[str] = (),
) -> list[TimelineRow]:
    """Webes kérések, amelyek valamelyik pivot-IP-ről ±``window`` időn belül érkeztek.

    Az ``exclude`` a már közvetlenül illeszkedő események ``raw_ref`` értékei (pl. a
    felhasználó nevével naplózott kérések), ezek nem kerülnek be még egyszer.
    """
    by_ip: dict[str, list[PivotSeed]] = defaultdict(list)
    for seed in seeds:
        by_ip[seed.ip].append(seed)
    for ip_seeds in by_ip.values():
        ip_seeds.sort(key=lambda s: s.timestamp_utc)
    times_by_ip = {ip: [s.timestamp_utc for s in items] for ip, items in by_ip.items()}

    skip = set(exclude)
    rows: list[TimelineRow] = []
    for event in pool:
        if event.source != WEB_SOURCE or event.raw_ref in skip or event.src_ip not in by_ip:
            continue
        nearest = _nearest(by_ip[event.src_ip], times_by_ip[event.src_ip], event.timestamp_utc)
        if abs(event.timestamp_utc - nearest.timestamp_utc) > window:
            continue
        if not passes_filters(event, flt):
            continue
        rows.append(TimelineRow(event, Role.CORRELATED, correlated_with=nearest.raw_ref))
        skip.add(event.raw_ref)
    return rows


def _nearest(seeds: list[PivotSeed], times: list[datetime], moment: datetime) -> PivotSeed:
    index = bisect_left(times, moment)
    candidates = [seeds[i] for i in (index - 1, index) if 0 <= i < len(seeds)]
    return min(candidates, key=lambda s: abs(s.timestamp_utc - moment))


# Az összevonható (jellemzően nagy tömegben előforduló) műveletek.
COLLAPSIBLE_ACTIONS = frozenset(
    {
        "logon_success",
        "logon_failure",
        "logoff",
        "special_privileges",
        "kerberos_tgt",
        "kerberos_tgt_failure",
        "kerberos_service_ticket",
        "kerberos_service_ticket_failure",
        "kerberos_preauth_failed",
        "ntlm_validation",
        "ntlm_validation_failure",
        "web_request",
    }
)
DEFAULT_COLLAPSE_GAP = timedelta(minutes=15)
MIN_COLLAPSE_COUNT = 3


def _collapse_key(row: TimelineRow) -> tuple[object, ...] | None:
    event = row.event
    if event.action not in COLLAPSIBLE_ACTIONS or event.severity.rank > 1:
        return None
    account = event.target or event.actor
    return (
        event.source,
        event.host,
        event.action,
        row.role,
        event.src_ip,
        account.display() if account else None,
        event.details.get("LogonType"),
        event.details.get("cs-method"),
        event.details.get("sc-status"),
    )


def collapse_rows(
    rows: Sequence[TimelineRow],
    gap: timedelta = DEFAULT_COLLAPSE_GAP,
    min_count: int = MIN_COLLAPSE_COUNT,
) -> list[TimelineRow]:
    """Azonos jellegű, egymást legfeljebb ``gap`` időn belül követő sorok összevonása.

    Két sor akkor azonos jellegű, ha a forrás, a gép, a művelet, a szerep, a forrás-IP, a
    fiók és (ahol van) a bejelentkezési típus, illetve a HTTP-metódus és -státusz egyezik.
    A közbeékelődő más események nem szakítják meg a csoportot. Legalább ``min_count``
    eseményből lesz összevont sor; a kevesebb elemű csoportok sorai változatlanok.
    """
    ordered = sorted(rows, key=lambda r: r.event.sort_key)
    groups: list[list[TimelineRow]] = []
    open_groups: dict[tuple[object, ...], list[TimelineRow]] = {}
    for row in ordered:
        key = _collapse_key(row)
        if key is None:
            groups.append([row])
            continue
        current = open_groups.get(key)
        if current is not None and row.event.timestamp_utc - current[-1].event.timestamp_utc <= gap:
            current.append(row)
            continue
        current = [row]
        open_groups[key] = current
        groups.append(current)

    result: list[TimelineRow] = []
    for group in groups:
        if len(group) < min_count:
            result.extend(group)
            continue
        first = group[0]
        result.append(
            TimelineRow(
                first.event,
                first.role,
                correlated_with=first.correlated_with,
                members=tuple(r.event for r in group),
            )
        )
    result.sort(key=lambda r: r.event.sort_key)
    return result
