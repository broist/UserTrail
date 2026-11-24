"""UTC-normalizálás és a megjelenítési időzóna kezelése."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, time, timedelta, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# A mikroszekundumnál hosszabb törtmásodpercet levágjuk (az EVTX 100 ns felbontású).
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


def parse_system_time(value: str) -> datetime:
    """EVTX ``SystemTime`` / ISO 8601 szöveg átalakítása időzónás UTC datetime-má.

    Az eltolás nélküli szöveget UTC-nek tekinti, mert a Windows így írja.
    """
    text = value.strip()
    if not text:
        raise ValueError("üres időbélyeg")
    if text.upper().endswith(" UTC"):  # az evtx iterátor formátuma: "2026-11-20 08:59:58.123 UTC"
        text = text[:-4]
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION_RE.sub(r"\1", text)
    parsed = datetime.fromisoformat(text)
    return ensure_utc(parsed)


def ensure_utc(dt: datetime) -> datetime:
    """Időzóna nélküli datetime-hoz UTC-t rendel, az időzónást UTC-re váltja."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def resolve_tz(name: str | None) -> tzinfo | None:
    """IANA-időzónanév feloldása. ``None`` vagy ``"local"``: a gép helyi időzónája.

    A helyi időzónát ``None`` jelöli, mert a ``datetime.astimezone(None)`` minden
    időpontra a helyes nyári/téli eltolást alkalmazza, egy rögzített eltolás viszont nem.
    """
    if name is None or name.strip().lower() == "local":
        return None
    if name.strip().upper() == "UTC":
        return UTC
    try:
        return ZoneInfo(name.strip())
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"ismeretlen időzóna: {name}") from exc


def to_display(dt: datetime, tz: tzinfo | None) -> datetime:
    return ensure_utc(dt).astimezone(tz)


def tz_label(tz: tzinfo | None, lang: str = "hu") -> str:
    """A megjelenítési időzóna olvasható neve a riportfejlécekhez."""
    if tz is None:
        offset = datetime.now().astimezone().strftime("%z")
        utc = f"UTC{offset[:3]}:{offset[3:]}"
        return f"helyi idő (most {utc})" if lang == "hu" else f"local time ({utc} now)"
    if tz is UTC:
        return "UTC"
    key = getattr(tz, "key", None)
    return str(key) if key else str(tz)


def format_display(dt: datetime, tz: tzinfo | None) -> str:
    local = to_display(dt, tz)
    return local.strftime("%Y-%m-%d %H:%M:%S")


def parse_bound(text: str, tz: tzinfo | None, *, end: bool = False) -> datetime:
    """A megjelenítési időzónában megadott ``--from`` / ``--to`` érték feldolgozása.

    Az idő nélküli dátum az egész napot jelenti: záró határként a következő nap kezdetét
    (kizárólagosan). A kifejezett eltolással megadott érték megtartja az eltolását.
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
        # A gép helyi időzónájában értelmezzük.
        return naive.astimezone().astimezone(UTC)
    return naive.replace(tzinfo=tz).astimezone(UTC)
