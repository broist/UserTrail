from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from usertrail.timeutil import (
    ensure_utc,
    format_display,
    parse_bound,
    parse_system_time,
    resolve_tz,
    tz_label,
)

BUDAPEST = ZoneInfo("Europe/Budapest")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-11-20T08:59:58.1234567Z", datetime(2026, 11, 20, 8, 59, 58, 123456, tzinfo=UTC)),
        ("2026-11-20T08:59:58Z", datetime(2026, 11, 20, 8, 59, 58, tzinfo=UTC)),
        ("2026-11-20 08:59:58", datetime(2026, 11, 20, 8, 59, 58, tzinfo=UTC)),
        ("2026-11-20T09:59:58+01:00", datetime(2026, 11, 20, 8, 59, 58, tzinfo=UTC)),
    ],
)
def test_parse_system_time(raw: str, expected: datetime) -> None:
    parsed = parse_system_time(raw)
    assert parsed == expected
    assert parsed.tzinfo is UTC


def test_parse_system_time_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        parse_system_time("  ")


def test_ensure_utc_converts_aware_values() -> None:
    local = datetime(2026, 7, 1, 12, 0, tzinfo=BUDAPEST)  # CEST, UTC+2
    assert ensure_utc(local) == datetime(2026, 7, 1, 10, 0, tzinfo=UTC)


def test_display_respects_dst() -> None:
    winter = datetime(2026, 11, 20, 8, 0, tzinfo=UTC)
    summer = datetime(2026, 7, 20, 8, 0, tzinfo=UTC)
    assert format_display(winter, BUDAPEST) == "2026-11-20 09:00:00"
    assert format_display(summer, BUDAPEST) == "2026-07-20 10:00:00"


def test_resolve_tz() -> None:
    assert resolve_tz(None) is None
    assert resolve_tz("local") is None
    assert resolve_tz("utc") is UTC
    assert resolve_tz("Europe/Budapest") == BUDAPEST
    with pytest.raises(ValueError, match="unknown time zone"):
        resolve_tz("Mars/Olympus_Mons")


def test_tz_label() -> None:
    assert tz_label(UTC) == "UTC"
    assert tz_label(BUDAPEST) == "Europe/Budapest"
    assert tz_label(None).startswith("local time")


def test_parse_bound_dates_cover_whole_day_in_display_zone() -> None:
    start = parse_bound("2026-11-20", BUDAPEST)
    end = parse_bound("2026-11-20", BUDAPEST, end=True)
    assert start == datetime(2026, 11, 19, 23, 0, tzinfo=UTC)
    assert end == datetime(2026, 11, 20, 23, 0, tzinfo=UTC)


def test_parse_bound_datetime_and_explicit_offset() -> None:
    assert parse_bound("2026-11-20T10:30", UTC) == datetime(2026, 11, 20, 10, 30, tzinfo=UTC)
    assert parse_bound("2026-11-20T10:30+01:00", UTC) == datetime(2026, 11, 20, 9, 30, tzinfo=UTC)
