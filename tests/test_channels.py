"""Kerberos/NTLM, RDP, PowerShell, System és naplótörlési események (6. mérföldkő)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.helpers import by_record, load_records, parse_all
from usertrail.cli import app
from usertrail.correlate import pivot_seeds
from usertrail.i18n import normalize_kerberos_status
from usertrail.identity import IdentityQuery, SidMap
from usertrail.models import Category, Identity, Role, Severity, TimelineEvent
from usertrail.netutil import normalize_ip
from usertrail.parsers.evtx_reader import RawRecord, ReadStats
from usertrail.parsers.powershell import PowerShellParser
from usertrail.query import TimelineFilter, select

DOM = "S-1-5-21-1111111111-2222222222-3333333333"
KOVACS = f"{DOM}-1105"


@pytest.fixture
def records() -> list[RawRecord]:
    return load_records("channels.json")


@pytest.fixture
def events(records: list[RawRecord]) -> list[TimelineEvent]:
    return parse_all(records)


def test_unmapped_powershell_event_is_ignored(events: list[TimelineEvent]) -> None:
    assert all(e.event_id != "4100" for e in events)
    # 25 rekord: a 3 részes és a 2 részes (hiányos) PowerShell-blokk 1-1 esemény,
    # a 4100 kimarad -> 25 - 2 - 1 - 1 = 21 esemény.
    assert len(events) == 21


# --- Kerberos / NTLM -------------------------------------------------------------------


def test_kerberos_tgt_success(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 301)
    assert (ev.action, ev.severity, ev.category) == (
        "kerberos_tgt",
        Severity.INFO,
        Category.AUTHENTICATION,
    )
    assert ev.target == Identity("kovacs.janos", "CEG.LOCAL", KOVACS)
    assert ev.src_ip == "10.0.0.5"
    assert ev.details["Status"] == "0x0"


def test_kerberos_tgt_failure(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 302)
    assert (ev.action, ev.severity) == ("kerberos_tgt_failure", Severity.LOW)
    assert ev.details["Status"] == "0x12"
    assert ev.description().endswith("– a fiók letiltva, zárolva vagy lejárt (0x12)")
    assert ev.description("en").endswith(": account disabled, locked out or expired (0x12)")


def test_kerberos_service_ticket_upn_target(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 303)
    assert ev.action == "kerberos_service_ticket"
    assert ev.target == Identity("kovacs.janos", "CEG.LOCAL", None)
    assert ev.details["ServiceName"] == "FS01$"
    assert ev.details["TicketEncryptionType"] == "0x17"


def test_kerberos_preauth_failed(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 304)
    assert (ev.action, ev.severity) == ("kerberos_preauth_failed", Severity.LOW)
    assert ev.description() == (
        "Sikertelen Kerberos előhitelesítés: kovacs.janos, forrás: 10.0.0.66 – hibás jelszó (0x18)"
    )


def test_ntlm_validation(events: list[TimelineEvent]) -> None:
    ok = by_record(events, 305)
    assert (ok.action, ok.severity) == ("ntlm_validation", Severity.INFO)
    assert ok.src_ip is None
    failed = by_record(events, 306)
    assert (failed.action, failed.severity) == ("ntlm_validation_failure", Severity.LOW)
    assert failed.details["Status"] == "0xC000006A"
    assert failed.description().endswith("munkaállomás: KALI – hibás jelszó (0xC000006A)")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("0x0", "0x0"), ("0x18", "0x18"), ("0X12", "0x12"), (24, "0x18"), ("-", None), (None, None)],
)
def test_normalize_kerberos_status(raw: object, expected: str | None) -> None:
    assert normalize_kerberos_status(raw) == expected


# --- Security egyéb / System ----------------------------------------------------------


def test_audit_log_cleared_from_user_data(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 307)
    assert (ev.action, ev.severity, ev.category) == (
        "audit_log_cleared",
        Severity.HIGH,
        Category.LOG_TAMPERING,
    )
    assert ev.actor == Identity("kovacs.janos", "CEG", KOVACS)
    assert ev.description() == "CEG\\kovacs.janos törölte a Security naplót"


def test_process_created_truncates_command(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 308)
    assert ev.category is Category.EXECUTION
    assert ev.actor is not None
    assert ev.actor.name == "kovacs.janos"
    assert ev.target is None  # a "-" célfiók nem identitás
    assert len(ev.details["CommandLine"]) > 200
    assert ev.message_params["command"].endswith("…")
    assert len(ev.message_params["command"]) == 160


def test_scheduled_task(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 309)
    assert (ev.action, ev.severity, ev.category) == (
        "scheduled_task_created",
        Severity.MEDIUM,
        Category.PERSISTENCE,
    )
    assert ev.details["TaskName"] == "\\Frissites"


def test_service_installed_actor_from_user_sid(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 310)
    assert (ev.source, ev.event_id, ev.action) == ("System", "7045", "service_installed")
    assert ev.actor == Identity(None, None, KOVACS)
    assert ev.details["ImagePath"] == "C:\\Users\\Public\\upd.exe"


def test_system_log_cleared(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 311)
    assert ev.actor == Identity("kovacs.janos", "CEG", KOVACS)
    assert ev.description() == "CEG\\kovacs.janos törölte a(z) System naplót"


# --- RDP --------------------------------------------------------------------------------


def test_rdp_events(events: list[TimelineEvent]) -> None:
    auth = by_record(events, 312)
    assert (auth.source, auth.action) == ("RDP-RCM", "rdp_auth_success")
    assert auth.target == Identity("kovacs.janos", "CEG", None)
    assert auth.src_ip == "10.0.0.5"

    logon = by_record(events, 313)
    assert (logon.source, logon.action, logon.category) == (
        "RDP-LSM",
        "rdp_logon",
        Category.REMOTE_ACCESS,
    )
    assert logon.target == Identity("kovacs.janos", "CEG", None)
    assert logon.description() == (
        "RDP-bejelentkezés: CEG\\kovacs.janos, forrás: 10.0.0.5 (3. munkamenet)"
    )
    assert by_record(events, 315).src_ip == "10.0.0.9"
    assert by_record(events, 316).action == "rdp_logoff"


def test_rdp_local_address_is_not_an_ip(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 317)
    assert ev.src_ip is None
    assert ev.details["Address"] == "LOCAL"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10.0.0.5", "10.0.0.5"),
        ("::ffff:10.0.0.5", "10.0.0.5"),
        ("fe80::1", "fe80::1"),
        ("LOCAL", None),
        ("WS-042", None),
        ("-", None),
    ],
)
def test_normalize_ip_validates(raw: str, expected: str | None) -> None:
    assert normalize_ip(raw) == expected


# --- PowerShell ---------------------------------------------------------------------------


def test_single_script_block(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 318)
    assert (ev.source, ev.action, ev.category) == ("PowerShell", "script_block", Category.EXECUTION)
    assert ev.actor == Identity(None, None, KOVACS)
    assert ev.details["ScriptBlockText"] == "Get-Process | Select-Object -First 5"
    assert ev.details["Incomplete"] is False
    assert ev.severity is Severity.INFO


def test_multi_part_script_is_joined(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 319)
    assert ev.details["ScriptBlockText"] == (
        "function Invoke-Big {\n  # első rész második rész IEX(New-Object Net.WebClient)"
        " harmadik rész\n}"
    )
    assert ev.details["Parts"] == ["Security.evtx#319", "Security.evtx#321", "Security.evtx#322"]
    assert ev.details["MessageTotal"] == 3
    # A 2. rész figyelmeztetés szintű volt: a PowerShell gyanúsnak jelölte.
    assert ev.details["SuspiciousByPowerShell"] is True
    assert ev.severity is Severity.MEDIUM
    # A közbeékelt egyrészes blokk önálló esemény marad.
    assert by_record(events, 320).details["ScriptBlockText"] == "whoami"


def test_incomplete_script_is_flushed_at_end(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 323)
    assert ev.details["Incomplete"] is True
    assert ev.details["PartsReceived"] == 2
    assert ev.message_params["preview"].startswith("[2/3] ")


def test_parts_out_of_order(records: list[RawRecord]) -> None:
    parser = PowerShellParser()
    parts = {r.record_id: r for r in records}
    out = [e for rid in (322, 319, 321) for e in parser.parse(parts[rid])]
    assert len(out) == 1
    assert out[0].details["ScriptBlockText"].startswith("function Invoke-Big")
    assert list(parser.finish()) == []


# --- Identitás és IP-pivot ---------------------------------------------------------------


def _rows(events: list[TimelineEvent], user: str) -> dict[str, Role]:
    sid_map = SidMap()
    for event in events:
        sid_map.learn_event(event)
    rows = select(events, TimelineFilter(identity=IdentityQuery.build(user, sid_map=sid_map)))
    return {row.event.raw_ref.rsplit("#", 1)[1]: row.role for row in rows}


def test_user_timeline_covers_all_channels(events: list[TimelineEvent]) -> None:
    roles = _rows(events, "kovacs.janos")
    # A SID-del azonosított PowerShell- és 7045-ös események is a felhasználóhoz kerülnek.
    for rid in ("301", "303", "306", "307", "310", "312", "313", "318", "319", "323"):
        assert rid in roles
    assert roles["310"] is Role.ACTOR
    assert roles["313"] is Role.TARGET
    assert "317" not in roles  # nagy.peter


def test_pivot_seeds_include_kerberos_and_rdp(events: list[TimelineEvent]) -> None:
    sid_map = SidMap()
    for event in events:
        sid_map.learn_event(event)
    rows = select(
        events, TimelineFilter(identity=IdentityQuery.build("kovacs.janos", sid_map=sid_map))
    )
    seeds = {s.raw_ref.rsplit("#", 1)[1] for s in pivot_seeds(rows)}
    # 4768 siker, 1149, 21 – a sikertelen 4768 (302) és a 24/25 nem pivotpont.
    assert seeds == {"301", "312", "313"}


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "logs.evtx"
    path.write_bytes(b"")

    def fake_read(p: Path, stats: ReadStats) -> Iterator[RawRecord]:
        for record in load_records("channels.json", str(p)):
            stats.records += 1
            yield record

    monkeypatch.setattr("usertrail.pipeline.read_evtx", fake_read)
    return path


def test_cli_resolves_sid_only_actors(evidence: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["timeline", "-s", str(evidence), "--user", "kovacs.janos", "--category", "EXECUTION"],
        env={"COLUMNS": "250"},
    )
    assert result.exit_code == 0, result.output
    assert f"PowerShell-szkriptblokk (kovacs.janos ({KOVACS}))" in result.output
    assert "[2/3]" in result.output
