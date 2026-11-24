"""UTC normalisation and display time zone handling."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, time, timedelta, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Fractional seconds longer than microseconds (EVTX uses 100 ns resolution) are trimmed.
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


def parse_system_time(value: str) -> datetime:
    """Parse an EVTX ``SystemTime`` / ISO 8601 string into an aware UTC datetime.

    Strings without an offset are treated as UTC, which is what Windows writes.
    """
    text = value.strip()
    if not text:
        raise ValueError("empty timestamp")
    if text.upper().endswith(" UTC"):  # evtx iterator format: "2026-11-20 08:59:58.123 UTC"
        text = text[:-4]
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION_RE.sub(r"\1", text)
    parsed = datetime.fromisoformat(text)
    return ensure_utc(parsed)


def ensure_utc(dt: datetime) -> datetime:
    """Attach UTC to naive datetimes and convert aware ones to UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def resolve_tz(name: str | None) -> tzinfo | None:
    """Resolve an IANA zone name. ``None`` or ``"local"`` means the machine's local zone.

    The local zone is represented as ``None`` because ``datetime.astimezone(None)``
    applies the correct DST offset for each instant, while a fixed offset would not.
    """
    if name is None or name.strip().lower() == "local":
        return None
    if name.strip().upper() == "UTC":
        return UTC
    try:
        return ZoneInfo(name.strip())
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown time zone: {name}") from exc


def to_display(dt: datetime, tz: tzinfo | None) -> datetime:
    return ensure_utc(dt).astimezone(tz)


def tz_label(tz: tzinfo | None) -> str:
    """Human readable name of the display zone, for report headers."""
    if tz is None:
        offset = datetime.now().astimezone().strftime("%z")
        return f"local time (UTC{offset[:3]}:{offset[3:]} now)"
    if tz is UTC:
        return "UTC"
    key = getattr(tz, "key", None)
    return str(key) if key else str(tz)


def format_display(dt: datetime, tz: tzinfo | None) -> str:
    local = to_display(dt, tz)
    return local.strftime("%Y-%m-%d %H:%M:%S")


def parse_bound(text: str, tz: tzinfo | None, *, end: bool = False) -> datetime:
    """Parse a ``--from`` / ``--to`` value given in the display time zone.

    A date without a time covers the whole day: as an end bound it means the start of
    the following day (exclusive). Values with an explicit offset keep that offset.
    """
    raw = text.strip()
    try:
        day = date.fromisoformat(raw)
    except ValueError:
        day = None
    if day is not None:
        if end:
            day = day + timedelta(days=1)
        naive = datetime.combine(day, time.min)
    else:
        naive = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if naive.tzinfo is not None:
        return naive.astimezone(UTC)
    if tz is None:
        # Interpret in the machine's local zone.
        return naive.astimezone().astimezone(UTC)
    return naive.replace(tzinfo=tz).astimezone(UTC)
