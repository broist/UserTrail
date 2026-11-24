"""Az alap adatmodell, amelyet minden parser, a tároló és a kimenetek is használnak."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Category(enum.StrEnum):
    """Az idővonal-események fő csoportjai."""

    ACCOUNT_LIFECYCLE = "ACCOUNT_LIFECYCLE"
    AUTHENTICATION = "AUTHENTICATION"
    PASSWORD = "PASSWORD"
    LOCKOUT = "LOCKOUT"
    GROUP_MEMBERSHIP = "GROUP_MEMBERSHIP"
    PRIVILEGE = "PRIVILEGE"
    REMOTE_ACCESS = "REMOTE_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    WEB = "WEB"
    LOG_TAMPERING = "LOG_TAMPERING"


class Severity(enum.StrEnum):
    """Az esemény súlyossága. Sorrend szerinti összehasonlításhoz a :attr:`rank` való."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


class Role(enum.StrEnum):
    """Milyen szerepben vesz részt a keresett identitás az eseményben."""

    ACTOR = "actor"  # a keresett fiók végezte a műveletet
    TARGET = "target"  # a műveletet a keresett fiókon végezték
    BOTH = "both"  # pl. a felhasználó a saját jelszavát cseréli
    RELATED = "related"  # csak a forrás-IP alapján kapcsolódik


# Jól ismert helyi rendszerfiókok (az identitás-normalizálás külön jelöli őket).
WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-7": "ANONYMOUS LOGON",
}


@dataclass(frozen=True, slots=True)
class Identity:
    """Egy fiók úgy, ahogy egyetlen eseményben megjelenik.

    Példányt a :func:`usertrail.identity.make_identity` függvénnyel érdemes létrehozni:
    az kiszűri a helyőrző értékeket, és szétbontja a ``DOMAIN\\felhasználó`` / UPN / SID
    alakú bemeneteket.
    """

    name: str | None = None
    domain: str | None = None
    sid: str | None = None

    @property
    def name_key(self) -> str | None:
        """A fióknév kis- és nagybetűtől független összehasonlító kulcsa."""
        return self.name.casefold() if self.name else None

    @property
    def sid_key(self) -> str | None:
        return self.sid.upper() if self.sid else None

    def display(self) -> str:
        if self.name and self.domain:
            return f"{self.domain}\\{self.name}"
        if self.name:
            return self.name
        if self.sid:
            label = WELL_KNOWN_SIDS.get(self.sid.upper())
            return f"{label} ({self.sid})" if label else self.sid
        return "-"


@dataclass(slots=True)
class TimelineEvent:
    """Egy normalizált esemény az idővonalon.

    Az emberi leírást nem kész szövegként tároljuk: a ``message_key`` és a
    ``message_params`` mezőkből a :meth:`description` állítja elő igény szerint, így
    ugyanaz a vizsgálat bármelyik támogatott nyelven megjeleníthető.
    """

    timestamp_utc: datetime
    source: str
    host: str
    event_id: str
    category: Category
    action: str
    actor: Identity | None
    target: Identity | None
    src_ip: str | None
    message_key: str
    message_params: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.INFO
    raw_ref: str = ""

    def __post_init__(self) -> None:
        if self.timestamp_utc.tzinfo is None:
            raise ValueError("a TimelineEvent.timestamp_utc mezőnek időzónát is tartalmaznia kell")

    def description(self, lang: str = "hu") -> str:
        from usertrail.i18n import render

        return render(self.message_key, self.message_params, lang)

    @property
    def sort_key(self) -> tuple[datetime, str, str, int]:
        """Stabil sorrend: idő, majd forrás, majd az eredeti fájl és a rekordszám."""
        path, _, record = self.raw_ref.rpartition("#")
        try:
            record_no = int(record)
        except ValueError:
            record_no = 0
            path = self.raw_ref
        return (self.timestamp_utc, self.source, path, record_no)
