"""Security channel parser."""

from __future__ import annotations

from collections.abc import Iterator

from usertrail.i18n import normalize_status
from usertrail.identity import clean
from usertrail.mappings.event_map import spec_for
from usertrail.models import TimelineEvent
from usertrail.parsers.base import Handler, build_event
from usertrail.parsers.evtx_reader import RawRecord

CHANNEL = "Security"
SOURCE = "Security"


def _logon(record: RawRecord, event: TimelineEvent) -> None:
    """4624/4625: normalise codes, fall back to the workstation name as the source."""
    for key in ("Status", "SubStatus"):
        if key in event.details:
            event.details[key] = normalize_status(event.details[key])
            event.message_params[key] = event.details[key]
    if "LogonType" in event.details:
        try:
            event.details["LogonType"] = int(event.details["LogonType"])
            event.message_params["LogonType"] = event.details["LogonType"]
        except (TypeError, ValueError):
            pass
    if event.src_ip is None:
        event.message_params["src"] = clean(record.data.get("WorkstationName"))


HANDLERS: dict[int, Handler] = {
    4624: _logon,
    4625: _logon,
    4634: _logon,
}


class SecurityParser:
    channels = frozenset({CHANNEL})

    def parse(self, record: RawRecord) -> Iterator[TimelineEvent]:
        spec = spec_for(CHANNEL, record.event_id)
        if spec is None:
            return
        event = build_event(record, spec, SOURCE)
        handler = HANDLERS.get(record.event_id)
        if handler is not None:
            handler(record, event)
        yield event
