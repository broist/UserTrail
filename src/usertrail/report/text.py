"""Kimenettől független szöveges megjelenítés (konzol, CSV, HTML közösen használja)."""

from __future__ import annotations

from datetime import tzinfo

from usertrail.i18n import collapse_label, logon_type_text, render
from usertrail.query import TimelineRow
from usertrail.timeutil import format_display, to_display


def _span(row: TimelineRow, tz: tzinfo | None) -> tuple[str, str]:
    first = row.members[0].timestamp_utc
    last = row.members[-1].timestamp_utc
    first_text = format_display(first, tz)
    if to_display(first, tz).date() == to_display(last, tz).date():
        return first_text, to_display(last, tz).strftime("%H:%M:%S")
    return first_text, format_display(last, tz)


def row_description(row: TimelineRow, tz: tzinfo | None, lang: str) -> str:
    """Egy sor emberi leírása; összevont sornál a darabszámmal és az időtartammal."""
    if not row.is_collapsed:
        return row.event.description(lang)
    event = row.event
    extra = ""
    if "LogonType" in event.details:
        extra = f" ({logon_type_text(event.details['LogonType'], lang)})"
    elif "cs-method" in event.details or "sc-status" in event.details:
        method = event.details.get("cs-method", "-")
        status = event.details.get("sc-status", "-")
        extra = f" ({method} {status})"
    account = event.target or event.actor
    first, last = _span(row, tz)
    return render(
        "collapsed",
        {
            "count": len(row.members),
            "label": collapse_label(event.action, lang),
            "extra": extra,
            "account": account.display() if account else None,
            "src": event.src_ip,
            "first": first,
            "last": last,
        },
        lang,
    )
