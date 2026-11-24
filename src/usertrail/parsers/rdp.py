"""RDP-naplók parserei (TerminalServices LocalSessionManager és RemoteConnectionManager).

A mezők itt az ``Event.UserData.EventXML`` alatt vannak; az olvasó ezt is a ``data``
szótárba lapítja. A LocalSessionManager ``Address`` mezője helyi munkamenetnél
``LOCAL``; ilyenkor nincs forrás-IP (a ``normalize_ip`` None-t ad), de az eredeti érték
a details-ben megmarad.
"""

from __future__ import annotations

from usertrail.mappings.event_map import RDP_LSM, RDP_RCM, SOURCE_LABELS
from usertrail.parsers.base import MappedParser


class LocalSessionManagerParser(MappedParser):
    def __init__(self) -> None:
        super().__init__(RDP_LSM, SOURCE_LABELS[RDP_LSM], {})


class RemoteConnectionManagerParser(MappedParser):
    def __init__(self) -> None:
        super().__init__(RDP_RCM, SOURCE_LABELS[RDP_RCM], {})
