"""Figyelmeztetési szabályok és aggregálás (7. mérföldkő)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from typer.testing import CliRunner

from tests.helpers import load_records, parse_all
from usertrail.alerts import Alert, AlertConfig, alert_refs, detect_alerts
from usertrail.cli import app
from usertrail.correlate import collapse_rows
from usertrail.identity import IdentityQuery, SidMap
from usertrail.models import Category, Identity, Role, Severity, TimelineEvent
from usertrail.parsers.evtx_reader import RawRecord, ReadStats
from usertrail.query import TimelineFilter, TimelineRow, select
from usertrail.report.text import row_description

BUDAPEST = ZoneInfo("Europe/Budapest")
KOVACS = Identity("kovacs.janos", "CEG", "S-1-5-21-1-2-3-1105")
T0 = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)  # péntek, 10:00 budapesti idő
_counter = iter(range(1, 100_000))


def ev(
    action: str,
    at: datetime,
    *,
    ip: str | None = "10.0.0.66",
    details: dict[str, Any] | None = None,
    severity: Severity = Severity.INFO,
    target: Identity | None = KOVACS,
    actor: Identity | None = None,
    source: str = "Security",
    event_id: str = "4625",
) -> TimelineEvent:
    return TimelineEvent(
        timestamp_utc=at,
        source=source,
        host="DC01",
        event_id=event_id,
        category=Category.AUTHENTICATION,
        action=action,
        actor=actor,
        target=target,
        src_ip=ip,
        message_key=action,
        message_params={"target": target.display() if target else None, "src": ip},
        details=details or {},
        severity=severity,
        raw_ref=f"t.evtx#{next(_counter)}",
    )


def rows_of(*events: TimelineEvent, role: Role = Role.TARGET) -> list[TimelineRow]:
    return [TimelineRow(e, role) for e in events]


def failures(count: int, start: datetime, step: timedelta) -> list[TimelineEvent]:
    return [ev("logon_failure", start + i * step) for i in range(count)]


def rules(alerts: list[Alert]) -> list[str]:
    return [a.rule for a in alerts]


# --- sikertelen bejelentkezések -------------------------------------------------------


def test_failed_logon_burst_one_alert_per_burst() -> None:
    burst = failures(12, T0, timedelta(seconds=20))
    alerts = detect_alerts(rows_of(*burst))
    assert rules(alerts) == ["failed_logon_burst"]
    alert = alerts[0]
    assert alert.severity is Severity.MEDIUM
    assert alert.params["count"] == 12
    assert alert.refs == {e.raw_ref for e in burst}


def test_below_threshold_no_alert() -> None:
    assert detect_alerts(rows_of(*failures(9, T0, timedelta(seconds=20)))) == []


def test_spread_out_failures_are_not_a_burst() -> None:
    # 30 hiba percenként: egy 5 perces ablakban legfeljebb 6 van.
    assert detect_alerts(rows_of(*failures(30, T0, timedelta(minutes=1)))) == []


def test_two_separate_bursts() -> None:
    first = failures(10, T0, timedelta(seconds=10))
    second = failures(10, T0 + timedelta(hours=1), timedelta(seconds=10))
    alerts = detect_alerts(rows_of(*first, *second))
    assert rules(alerts) == ["failed_logon_burst", "failed_logon_burst"]


def test_threshold_is_configurable() -> None:
    cfg = AlertConfig(fail_threshold=3, fail_window=timedelta(minutes=1))
    assert rules(detect_alerts(rows_of(*failures(3, T0, timedelta(seconds=10))), cfg)) == [
        "failed_logon_burst"
    ]


def test_failure_kinds_are_combined_per_account() -> None:
    mixed = [
        ev(action, T0 + timedelta(seconds=i))
        for i, action in enumerate(
            ["logon_failure", "kerberos_preauth_failed", "ntlm_validation_failure"] * 4
        )
    ]
    other = Identity("nagy.peter", "CEG", "S-1-5-21-1-2-3-1300")
    noise = [ev("logon_failure", T0 + timedelta(seconds=i), target=other) for i in range(9)]
    assert rules(detect_alerts(rows_of(*mixed, *noise))) == ["failed_logon_burst"]


def test_success_after_failures() -> None:
    failed = failures(6, T0, timedelta(seconds=30))
    success = ev("logon_success", T0 + timedelta(minutes=3, seconds=10), ip="10.0.0.66")
    alerts = detect_alerts(rows_of(*failed, success))
    (alert,) = [a for a in alerts if a.rule == "success_after_failures"]
    assert alert.severity is Severity.HIGH
    assert alert.raw_ref == success.raw_ref
    assert set(alert.related) == {e.raw_ref for e in failed}
    assert alert.description() == (
        "Sikeres bejelentkezés 6 sikertelen után (5 percen belül): CEG\\kovacs.janos, "
        "forrás: 10.0.0.66 – lehetséges jelszótalálgatás"
    )


def test_success_after_few_failures_is_fine() -> None:
    failed = failures(4, T0, timedelta(seconds=30))
    success = ev("logon_success", T0 + timedelta(minutes=3))
    assert detect_alerts(rows_of(*failed, success)) == []


# --- zárolás, naplótörlés, kiemelt csoport, perzisztencia -------------------------------


def test_lockout_links_preceding_failures() -> None:
    old = ev("logon_failure", T0 - timedelta(hours=2), ip="10.0.0.1")
    recent = failures(3, T0 - timedelta(minutes=10), timedelta(minutes=1))
    locked = ev(
        "account_locked",
        T0,
        ip=None,
        details={"CallerComputerName": "WS-042"},
        severity=Severity.MEDIUM,
    )
    (alert,) = detect_alerts(rows_of(old, *recent, locked))
    assert alert.rule == "account_locked"
    assert set(alert.related) == {e.raw_ref for e in recent}
    assert alert.description() == (
        "A(z) CEG\\kovacs.janos fiók zárolva (hívó gép: WS-042); az előző 30 percben "
        "3 sikertelen próbálkozás, forrás: 10.0.0.66"
    )


def _fixture_rows(name: str, user: str) -> list[TimelineRow]:
    events = parse_all(load_records(name))
    sid_map = SidMap()
    for event in events:
        sid_map.learn_event(event)
    return select(events, TimelineFilter(identity=IdentityQuery.build(user, sid_map=sid_map)))


def test_fixture_alerts_for_channels() -> None:
    alerts = detect_alerts(_fixture_rows("channels.json", "kovacs.janos"), AlertConfig(tz=BUDAPEST))
    by_rule: dict[str, list[Alert]] = {}
    for alert in alerts:
        by_rule.setdefault(alert.rule, []).append(alert)
    assert len(by_rule["log_cleared"]) == 2
    assert {a.severity for a in by_rule["log_cleared"]} == {Severity.HIGH}
    persistence = by_rule["persistence_by_user"]
    assert [a.params["kind"] for a in persistence] == [
        "scheduled_task_created",
        "service_installed",
    ]
    # A 7045 telepítőjét csak SID azonosítja (a CLI a SID-térképből oldja fel a nevet).
    assert (
        persistence[1]
        .description()
        .endswith("új szolgáltatást telepített: UpdaterSvc (DC01.ceg.local)")
    )


def test_fixture_privileged_group_alert() -> None:
    alerts = detect_alerts(_fixture_rows("security_account.json", "kovacs.janos"))
    privileged = [a for a in alerts if a.rule == "privileged_group_added"]
    assert len(privileged) == 1
    assert privileged[0].description() == (
        "Kovács János kiemelt csoportba került: CEG\\Domain Admins "
        "(végrehajtotta: CEG\\rendszergazda)"
    )


def test_persistence_requires_actor_role() -> None:
    task = ev(
        "scheduled_task_created",
        T0,
        ip=None,
        actor=KOVACS,
        target=None,
        details={"TaskName": "\\X"},
    )
    assert rules(detect_alerts(rows_of(task, role=Role.ACTOR))) == ["persistence_by_user"]
    assert detect_alerts(rows_of(task, role=Role.RELATED)) == []


# --- munkaidő --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("at", "logon_type", "expected"),
    [
        (datetime(2026, 11, 20, 9, 0, tzinfo=UTC), 10, False),  # péntek 10:00 Budapest
        (datetime(2026, 11, 20, 21, 0, tzinfo=UTC), 10, True),  # péntek 22:00
        (datetime(2026, 11, 21, 9, 0, tzinfo=UTC), 2, True),  # szombat 10:00
        (datetime(2026, 11, 20, 5, 59, tzinfo=UTC), 2, True),  # péntek 06:59
        (datetime(2026, 11, 20, 22, 0, tzinfo=UTC), 3, False),  # hálózati: nem interaktív
    ],
)
def test_off_hours(at: datetime, logon_type: int, expected: bool) -> None:
    logon = ev("logon_success", at, details={"LogonType": logon_type})
    alerts = detect_alerts(rows_of(logon), AlertConfig(tz=BUDAPEST))
    assert ("off_hours_logon" in rules(alerts)) is expected


def test_off_hours_custom_hours() -> None:
    logon = ev("rdp_logon", datetime(2026, 11, 20, 18, 30, tzinfo=UTC), source="RDP-LSM")
    cfg = AlertConfig(tz=BUDAPEST, work_start=time(8, 0), work_end=time(20, 0))
    assert detect_alerts(rows_of(logon), cfg) == []  # 19:30 Budapest


# --- jelszó-visszaállítás + új IP --------------------------------------------------------


def test_password_reset_then_new_ip() -> None:
    before = ev("logon_success", T0 - timedelta(days=1), ip="10.0.0.5")
    reset = ev(
        "password_reset",
        T0,
        ip=None,
        actor=Identity("rendszergazda", "CEG", None),
        details={"Result": "success"},
        severity=Severity.MEDIUM,
    )
    reset.message_params["actor"] = "CEG\\rendszergazda"
    known_ip = ev("logon_success", T0 + timedelta(minutes=5), ip="10.0.0.5")
    new_ip = ev("logon_success", T0 + timedelta(minutes=20), ip="10.0.0.99")
    alerts = [
        a
        for a in detect_alerts(rows_of(before, reset, known_ip, new_ip))
        if a.rule == "password_reset_new_ip"
    ]
    assert len(alerts) == 1
    assert alerts[0].raw_ref == new_ip.raw_ref
    assert alerts[0].related == (reset.raw_ref,)
    assert alerts[0].description() == (
        "Bejelentkezés új IP-ről (10.0.0.99) 20 perccel a jelszó-visszaállítás után: "
        "CEG\\kovacs.janos (visszaállította: CEG\\rendszergazda)"
    )


def test_password_reset_followup_window() -> None:
    reset = ev("password_reset", T0, ip=None, details={"Result": "success"})
    late = ev("logon_success", T0 + timedelta(hours=2), ip="10.0.0.99")
    assert detect_alerts(rows_of(reset, late)) == []


def test_alert_refs() -> None:
    burst = failures(10, T0, timedelta(seconds=5))
    assert alert_refs(detect_alerts(rows_of(*burst))) == {e.raw_ref for e in burst}


# --- aggregálás ---------------------------------------------------------------------------


def _logons(count: int, start: datetime, ip: str = "10.0.0.5") -> list[TimelineEvent]:
    return [
        ev("logon_success", start + timedelta(minutes=i), ip=ip, details={"LogonType": 3})
        for i in range(count)
    ]


def test_collapse_groups_same_kind() -> None:
    group = _logons(5, T0)
    other_ip = _logons(1, T0 + timedelta(seconds=30), ip="10.0.0.7")
    result = collapse_rows(rows_of(*group, *other_ip))
    assert len(result) == 2
    collapsed = next(r for r in result if r.is_collapsed)
    assert collapsed.members == tuple(group)
    assert collapsed.raw_refs == tuple(e.raw_ref for e in group)
    assert row_description(collapsed, BUDAPEST, "hu") == (
        "5× sikeres bejelentkezés (3 hálózati): CEG\\kovacs.janos, forrás: 10.0.0.5 "
        "(2026-11-20 10:00:00 – 10:04:00)"
    )
    assert row_description(collapsed, BUDAPEST, "en").startswith("5× successful logon (3 network)")


def test_collapse_gap_splits_groups() -> None:
    first = _logons(3, T0)
    second = _logons(3, T0 + timedelta(hours=1))
    result = collapse_rows(rows_of(*first, *second), gap=timedelta(minutes=15))
    assert [len(r.members) for r in result] == [3, 3]


def test_collapse_keeps_small_groups_and_important_events() -> None:
    pair = _logons(2, T0)
    lockouts = [
        ev("account_locked", T0 + timedelta(minutes=i), severity=Severity.MEDIUM) for i in range(4)
    ]
    result = collapse_rows(rows_of(*pair, *lockouts))
    assert len(result) == 6
    assert not any(r.is_collapsed for r in result)


# --- CLI ------------------------------------------------------------------------------------


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"")

    def fake_read(p: Path, stats: ReadStats) -> Iterator[RawRecord]:
        for name in ("channels.json", "security_account.json"):
            for record in load_records(name, str(p)):
                stats.records += 1
                yield record

    monkeypatch.setattr("usertrail.pipeline.read_evtx", fake_read)
    return path


def _run(*args: str) -> str:
    result = CliRunner().invoke(app, list(args), env={"COLUMNS": "250"})
    assert result.exit_code == 0, result.output
    return result.output


def test_cli_shows_alerts(evidence: Path) -> None:
    out = _run("timeline", "-s", str(evidence), "--user", "kovacs.janos", "--tz", "Europe/Budapest")
    assert "Figyelmeztetések" in out
    assert "Naplótörlés" in out
    assert "Kiemelt csoport" in out
    assert "Perzisztencia" in out
    assert "figyelmeztetés (lásd a Figyelmeztetések táblát)" in out


def test_cli_alerts_ignore_category_filter(evidence: Path) -> None:
    out = _run(
        "timeline", "-s", str(evidence), "--user", "kovacs.janos", "--category", "REMOTE_ACCESS"
    )
    # A megjelenítés csak RDP, de a naplótörlés figyelmeztetése megmarad.
    assert "Naplótörlés" in out


def test_cli_no_alerts(evidence: Path) -> None:
    out = _run("timeline", "-s", str(evidence), "--user", "kovacs.janos", "--no-alerts")
    assert "Figyelmeztetések" not in out


def test_cli_invalid_work_hours(evidence: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["timeline", "-s", str(evidence), "--user", "x", "--work-hours", "19:00-07:00"],
    )
    assert result.exit_code != 0
    assert "munkaidő" in result.output
