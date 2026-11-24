from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from usertrail.identity import IdentityQuery, SidMap
from usertrail.models import Category, Role, Severity, TimelineEvent
from usertrail.query import TimelineFilter, TimelineRow, select


def _query(events: list[TimelineEvent], user: str) -> IdentityQuery:
    sid_map = SidMap()
    for ev in events:
        sid_map.learn(ev.actor)
        sid_map.learn(ev.target)
    return IdentityQuery.build(user, sid_map=sid_map)


def _ids(rows: Sequence[TimelineRow]) -> list[str]:
    return [row.event.raw_ref.rsplit("#", 1)[1] for row in rows]


def test_user_timeline_order_and_roles(auth_events: list[TimelineEvent]) -> None:
    rows = select(auth_events, TimelineFilter(identity=_query(auth_events, "CEG\\kovacs.janos")))
    # 4624 and 4672 share a timestamp: ordered by record number. Logoffs follow in time order.
    assert _ids(rows) == ["101", "102", "103", "104", "107", "106"]
    roles = {r.event.raw_ref.rsplit("#", 1)[1]: r.role for r in rows}
    assert roles["101"] is Role.TARGET
    assert roles["103"] is Role.ACTOR
    assert roles["104"] is Role.ACTOR


def test_sid_query_matches_name_only_events(auth_events: list[TimelineEvent]) -> None:
    query = _query(auth_events, "S-1-5-21-1111111111-2222222222-3333333333-1105")
    rows = select(auth_events, TimelineFilter(identity=query))
    # 4625 (record 101) carries only the name; the SID map links it.
    assert "101" in _ids(rows)


def test_time_category_and_severity_filters(auth_events: list[TimelineEvent]) -> None:
    query = _query(auth_events, "kovacs.janos")
    flt = TimelineFilter(
        identity=query,
        start=datetime(2026, 11, 20, 9, 0, tzinfo=UTC),
        end=datetime(2026, 11, 20, 9, 6, tzinfo=UTC),
    )
    assert _ids(select(auth_events, flt)) == ["102", "103", "104"]

    priv = TimelineFilter(identity=query, categories=frozenset({Category.PRIVILEGE}))
    assert _ids(select(auth_events, priv)) == ["103"]

    low = TimelineFilter(identity=query, min_severity=Severity.LOW)
    assert _ids(select(auth_events, low)) == ["101", "104"]


def test_ip_only_search_skips_machine_accounts_by_default(
    auth_events: list[TimelineEvent],
) -> None:
    rows = select(auth_events, TimelineFilter(ip="10.0.0.5"))
    assert _ids(rows) == ["101", "102"]
    assert all(r.role is Role.RELATED for r in rows)

    with_machines = select(
        auth_events, TimelineFilter(ip="10.0.0.5", include_machine_accounts=True)
    )
    assert _ids(with_machines) == ["101", "102", "105"]


def test_machine_account_query_is_not_filtered(auth_events: list[TimelineEvent]) -> None:
    rows = select(auth_events, TimelineFilter(identity=IdentityQuery.build("WS-042$")))
    assert _ids(rows) == ["105"]


def test_user_and_ip_combine_with_and(auth_events: list[TimelineEvent]) -> None:
    flt = TimelineFilter(identity=_query(auth_events, "kovacs.janos"), ip="10.0.0.5")
    assert _ids(select(auth_events, flt)) == ["101", "102"]
