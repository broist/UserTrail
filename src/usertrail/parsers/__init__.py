"""Forrásparserek és csatorna szerinti szétosztás."""

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
    """Szétosztás az ``Event.System.Channel`` alapján (sosem a fájlnév alapján)."""
    parser = _BY_CHANNEL.get(record.channel)
    if parser is None:
        return iter(())
    return parser.parse(record)
