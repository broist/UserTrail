"""Forrásparserek és csatorna szerinti szétosztás."""

from __future__ import annotations

from collections.abc import Iterator

from usertrail.models import TimelineEvent
from usertrail.parsers.base import RecordParser
from usertrail.parsers.evtx_reader import RawRecord
from usertrail.parsers.powershell import PowerShellParser
from usertrail.parsers.rdp import LocalSessionManagerParser, RemoteConnectionManagerParser
from usertrail.parsers.security import SecurityParser
from usertrail.parsers.system import SystemParser


def new_parsers() -> tuple[RecordParser, ...]:
    """Friss parserpéldányok (az állapotot tartó parserek miatt futásonként újak)."""
    return (
        SecurityParser(),
        SystemParser(),
        LocalSessionManagerParser(),
        RemoteConnectionManagerParser(),
        PowerShellParser(),
    )


class Dispatcher:
    """A rekordokat az ``Event.System.Channel`` alapján (sosem a fájlnév alapján) a
    megfelelő parserhez irányítja. Fájlonként egy példány; a fájl végén ``finish``."""

    def __init__(self) -> None:
        self.parsers = new_parsers()
        self._by_channel: dict[str, RecordParser] = {
            channel: parser for parser in self.parsers for channel in parser.channels
        }

    def parse(self, record: RawRecord) -> Iterator[TimelineEvent]:
        parser = self._by_channel.get(record.channel)
        if parser is None:
            return iter(())
        return parser.parse(record)

    def finish(self) -> Iterator[TimelineEvent]:
        for parser in self.parsers:
            yield from parser.finish()
