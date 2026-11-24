"""A keresett identitáshoz tartozó események kiválasztása és rendezése."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from usertrail.identity import IdentityQuery, is_machine_account
from usertrail.models import Category, Role, Severity, TimelineEvent


@dataclass(frozen=True, slots=True)
class TimelineFilter:
    """Keresési feltételek.

    Az ``identity`` (a --user/--sid kapcsolókból) és az ``ip`` ÉS kapcsolatban áll. Ha
    csak IP van megadva, az erről a forráscímről érkező összes esemény ``related``
    szereppel kerül a találatok közé.
    """

    identity: IdentityQuery | None = None
    ip: str | None = None
    start: datetime | None = None  # zárt (beleértve), UTC
    end: datetime | None = None  # nyílt (kizárva), UTC
    categories: frozenset[Category] | None = None
    min_severity: Severity = Severity.INFO
    include_machine_accounts: bool = False


@dataclass(frozen=True, slots=True)
class TimelineRow:
    event: TimelineEvent
    role: Role
    # Korrelált soroknál annak a bejelentkezésnek a raw_ref-je, amelyhez kötöttük.
    correlated_with: str | None = None


def role_of(event: TimelineEvent, flt: TimelineFilter) -> Role | None:
    if flt.ip is not None and event.src_ip != flt.ip:
        return None
    if flt.identity is not None and not flt.identity.is_empty:
        as_actor = flt.identity.matches(event.actor)
        as_target = flt.identity.matches(event.target) or any(
            flt.identity.matches(alias) for alias in event.aliases
        )
        if as_actor and as_target:
            return Role.BOTH
        if as_actor:
            return Role.ACTOR
        if as_target:
            return Role.TARGET
        return None
    if flt.ip is not None:
        return Role.RELATED
    return None


def _is_machine_event(event: TimelineEvent) -> bool:
    subject = event.target or event.actor
    return is_machine_account(subject)


def passes_filters(event: TimelineEvent, flt: TimelineFilter) -> bool:
    """Az identitástól független feltételek: időszak, kategória, súlyosság."""
    if flt.start is not None and event.timestamp_utc < flt.start:
        return False
    if flt.end is not None and event.timestamp_utc >= flt.end:
        return False
    if flt.categories is not None and event.category not in flt.categories:
        return False
    return event.severity.rank >= flt.min_severity.rank


def select(events: Iterable[TimelineEvent], flt: TimelineFilter) -> list[TimelineRow]:
    """Események szűrése, stabil idővonal-sorrendben visszaadva."""
    skip_machines = not flt.include_machine_accounts and not (
        flt.identity is not None and flt.identity.targets_machine_account
    )
    rows: list[TimelineRow] = []
    for event in events:
        if not passes_filters(event, flt):
            continue
        if skip_machines and _is_machine_event(event):
            continue
        role = role_of(event, flt)
        if role is not None:
            rows.append(TimelineRow(event, role))
    rows.sort(key=lambda row: row.event.sort_key)
    return rows
