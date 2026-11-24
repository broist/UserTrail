"""Selecting and ordering the events that belong to the searched identity."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from usertrail.identity import IdentityQuery, is_machine_account
from usertrail.models import Category, Role, Severity, TimelineEvent


@dataclass(frozen=True, slots=True)
class TimelineFilter:
    """Search criteria.

    ``identity`` (built from --user/--sid) and ``ip`` combine with AND. With only an IP,
    every event from that source address is returned with the ``related`` role.
    """

    identity: IdentityQuery | None = None
    ip: str | None = None
    start: datetime | None = None  # inclusive, UTC
    end: datetime | None = None  # exclusive, UTC
    categories: frozenset[Category] | None = None
    min_severity: Severity = Severity.INFO
    include_machine_accounts: bool = False


@dataclass(frozen=True, slots=True)
class TimelineRow:
    event: TimelineEvent
    role: Role


def role_of(event: TimelineEvent, flt: TimelineFilter) -> Role | None:
    if flt.ip is not None and event.src_ip != flt.ip:
        return None
    if flt.identity is not None and not flt.identity.is_empty:
        as_actor = flt.identity.matches(event.actor)
        as_target = flt.identity.matches(event.target)
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


def select(events: Iterable[TimelineEvent], flt: TimelineFilter) -> list[TimelineRow]:
    """Filter events and return them in stable timeline order."""
    skip_machines = not flt.include_machine_accounts and not (
        flt.identity is not None and flt.identity.targets_machine_account
    )
    rows: list[TimelineRow] = []
    for event in events:
        if flt.start is not None and event.timestamp_utc < flt.start:
            continue
        if flt.end is not None and event.timestamp_utc >= flt.end:
            continue
        if flt.categories is not None and event.category not in flt.categories:
            continue
        if event.severity.rank < flt.min_severity.rank:
            continue
        if skip_machines and _is_machine_event(event):
            continue
        role = role_of(event, flt)
        if role is not None:
            rows.append(TimelineRow(event, role))
    rows.sort(key=lambda row: row.event.sort_key)
    return rows
