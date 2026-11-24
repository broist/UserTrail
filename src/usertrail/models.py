"""Core data model shared by every parser, the store and the report writers."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Category(enum.StrEnum):
    """High-level grouping of timeline events."""

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
    """Event severity. Use :attr:`rank` for ordering comparisons."""

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
    """How the searched identity takes part in an event."""

    ACTOR = "actor"  # the searched account performed the action
    TARGET = "target"  # the action was performed on the searched account
    BOTH = "both"  # e.g. a user changing their own password
    RELATED = "related"  # matched through the source IP only


# Well-known local system principals (identity normalisation marks these separately).
WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-7": "ANONYMOUS LOGON",
}


@dataclass(frozen=True, slots=True)
class Identity:
    """An account as it appears in a single event.

    Construct instances through :func:`usertrail.identity.make_identity`, which cleans
    placeholder values and splits ``DOMAIN\\user`` / UPN / SID inputs.
    """

    name: str | None = None
    domain: str | None = None
    sid: str | None = None

    @property
    def name_key(self) -> str | None:
        """Case-insensitive comparison key for the account name."""
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
    """One normalised event on the timeline.

    The human readable description is not stored as text: ``message_key`` and
    ``message_params`` are rendered on demand by :meth:`description`, so the same case
    can be shown in any supported language.
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
            raise ValueError("TimelineEvent.timestamp_utc must be timezone-aware")

    def description(self, lang: str = "en") -> str:
        from usertrail.i18n import render

        return render(self.message_key, self.message_params, lang)

    @property
    def sort_key(self) -> tuple[datetime, str, str, int]:
        """Stable ordering: time, then source, then original file and record number."""
        path, _, record = self.raw_ref.rpartition("#")
        try:
            record_no = int(record)
        except ValueError:
            record_no = 0
            path = self.raw_ref
        return (self.timestamp_utc, self.source, path, record_no)
