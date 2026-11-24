"""A System csatorna parsere (7045 szolgáltatástelepítés, 104 naplótörlés)."""

from __future__ import annotations

from usertrail.identity import make_identity
from usertrail.mappings.event_map import SOURCE_LABELS, SYSTEM
from usertrail.models import TimelineEvent
from usertrail.parsers.base import Handler, MappedParser, set_actor
from usertrail.parsers.evtx_reader import RawRecord


def _actor_from_user_sid(record: RawRecord, event: TimelineEvent) -> None:
    """7045: a telepítő fiókot csak a System.Security UserID SID-je azonosítja."""
    if record.user_sid:
        set_actor(event, make_identity(sid=record.user_sid))


def _log_cleared(record: RawRecord, event: TimelineEvent) -> None:
    """104: a név a UserData-ból jön; ha van, a System.Security UserID SID-jét is hozzáadjuk."""
    if record.user_sid:
        name = event.actor.name if event.actor else None
        domain = event.actor.domain if event.actor else None
        set_actor(event, make_identity(name, domain, record.user_sid))


HANDLERS: dict[int, Handler] = {
    7045: _actor_from_user_sid,
    104: _log_cleared,
}


class SystemParser(MappedParser):
    def __init__(self) -> None:
        super().__init__(SYSTEM, SOURCE_LABELS[SYSTEM], HANDLERS)
