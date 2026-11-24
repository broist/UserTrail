from __future__ import annotations

from tests.helpers import by_record
from usertrail.models import Category, Identity, Severity, TimelineEvent
from usertrail.parsers.evtx_reader import RawRecord
from usertrail.parsers.security import SecurityParser
from usertrail.timeutil import parse_system_time

SID = "S-1-5-21-1111111111-2222222222-3333333333-1105"


def test_unknown_event_ids_are_ignored(auth_events: list[TimelineEvent]) -> None:
    assert all(event.event_id != "4999" for event in auth_events)
    assert len(auth_events) == 7


def test_4625_failure(auth_events: list[TimelineEvent]) -> None:
    ev = by_record(auth_events, 101)
    assert ev.action == "logon_failure"
    assert ev.category is Category.AUTHENTICATION
    assert ev.severity is Severity.LOW
    assert ev.actor is None
    # A NULL SID kimarad, a ::ffff: előtag levágódik.
    assert ev.target == Identity("kovacs.janos", "CEG", None)
    assert ev.src_ip == "10.0.0.5"
    assert ev.details["SubStatus"] == "0xC000006A"
    assert ev.details["Status"] == "0xC000006D"
    assert ev.details["LogonType"] == 3
    assert ev.description("en") == (
        "Failed logon of CEG\\kovacs.janos (3 network) from 10.0.0.5: wrong password (0xC000006A)"
    )
    assert ev.description("hu") == (
        "Sikertelen bejelentkezés: CEG\\kovacs.janos (3 hálózati), forrás: 10.0.0.5 – "
        "hibás jelszó (0xC000006A)"
    )


def test_4624_success(auth_events: list[TimelineEvent]) -> None:
    ev = by_record(auth_events, 102)
    assert ev.action == "logon_success"
    assert ev.host == "DC01.ceg.local"
    assert ev.target == Identity("kovacs.janos", "CEG", SID)
    assert ev.actor is None
    assert ev.details["LogonType"] == 10
    assert ev.details["AuthenticationPackageName"] == "Negotiate"
    assert ev.raw_ref == "Security.evtx#102"
    assert "(10 RDP)" in ev.description("en")


def test_4672_actor_is_subject(auth_events: list[TimelineEvent]) -> None:
    ev = by_record(auth_events, 103)
    assert ev.category is Category.PRIVILEGE
    assert ev.actor == Identity("kovacs.janos", "CEG", SID)
    assert ev.target is None
    assert "SeDebugPrivilege" in ev.details["PrivilegeList"]


def test_4648_explicit_credentials(auth_events: list[TimelineEvent]) -> None:
    ev = by_record(auth_events, 104)
    assert ev.actor is not None
    assert ev.actor.name == "kovacs.janos"
    assert ev.target == Identity("admin.backup", "CEG", None)
    assert ev.src_ip is None
    assert ev.description("en") == (
        "CEG\\kovacs.janos used the explicit credentials of CEG\\admin.backup "
        "to access FS01.ceg.local"
    )


def test_logoffs(auth_events: list[TimelineEvent]) -> None:
    assert by_record(auth_events, 106).description("en") == "Logoff of CEG\\kovacs.janos (10 RDP)"
    user_logoff = by_record(auth_events, 107)
    assert user_logoff.action == "logoff"
    assert user_logoff.description("en") == "User-initiated logoff of CEG\\kovacs.janos"


def test_src_falls_back_to_workstation_when_no_ip() -> None:
    record = RawRecord(
        source_path="s.evtx",
        record_id=1,
        timestamp_utc=parse_system_time("2026-11-20T09:00:00Z"),
        channel="Security",
        provider=None,
        event_id=4624,
        computer="WS-042",
        user_sid=None,
        data={"TargetUserName": "kovacs.janos", "LogonType": "2", "WorkstationName": "WS-042"},
    )
    (event,) = SecurityParser().parse(record)
    assert event.src_ip is None
    assert event.details["LogonType"] == 2
    assert event.description("en").endswith("from WS-042")
