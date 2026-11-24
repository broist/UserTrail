"""Source parsers and channel dispatch."""

from __future__ import annotations

from collections.abc import Iterator

from usertrail.models import TimelineEvent
from usertrail.parsers.base import RecordParser
from usertrail.parsers.evtx_reader import RawRecord
from usertrail.parsers.security import SecurityParser

PARSERS: tuple[RecordParser, ...] = (SecurityParser(),)

_BY_CHANNEL: dict[str, RecordParser] = {
    channel: parser for parser in PARSERS for channel in parser.channels
}


def parse_record(record: RawRecord) -> Iterator[TimelineEvent]:
    """Dispatch on ``Event.System.Channel`` (never on the file name)."""
    parser = _BY_CHANNEL.get(record.channel)
    if parser is None:
        return iter(())
    return parser.parse(record)
