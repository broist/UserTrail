"""A fiókkezelési, jelszó-, zárolási és csoporttagsági események (3. mérföldkő)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.helpers import by_record, load_records, parse_all
from usertrail.cli import app
from usertrail.identity import IdentityQuery, SidMap, resolve_sid_only_names
from usertrail.models import Category, Identity, Role, Severity, TimelineEvent
from usertrail.parsers.evtx_reader import RawRecord, ReadStats
from usertrail.parsers.security import audit_result
from usertrail.query import TimelineFilter, select

DOM = "S-1-5-21-1111111111-2222222222-3333333333"
KOVACS = f"{DOM}-1105"
NAGY = f"{DOM}-1300"


@pytest.fixture
def events() -> list[TimelineEvent]:
    return parse_all(load_records("security_account.json"))


def _rows_for(events: list[TimelineEvent], user: str) -> dict[str, Role]:
    sid_map = SidMap()
    for event in events:
        sid_map.learn_event(event)
    rows = select(events, TimelineFilter(identity=IdentityQuery.build(user, sid_map=sid_map)))
    return {row.event.raw_ref.rsplit("#", 1)[1]: row.role for row in rows}


def test_all_records_are_mapped(events: list[TimelineEvent]) -> None:
    assert len(events) == 16


@pytest.mark.parametrize(
    ("record_id", "action", "category", "severity"),
    [
        (201, "account_created", Category.ACCOUNT_LIFECYCLE, Severity.LOW),
        (202, "account_enabled", Category.ACCOUNT_LIFECYCLE, Severity.INFO),
        (203, "account_changed", Category.ACCOUNT_LIFECYCLE, Severity.INFO),
        (204, "password_reset", Category.PASSWORD, Severity.MEDIUM),
        (205, "password_change_attempt", Category.PASSWORD, Severity.LOW),
        (206, "group_member_added", Category.GROUP_MEMBERSHIP, Severity.HIGH),
        (207, "group_member_added", Category.GROUP_MEMBERSHIP, Severity.LOW),
        (208, "group_member_removed", Category.GROUP_MEMBERSHIP, Severity.MEDIUM),
        (209, "account_locked", Category.LOCKOUT, Severity.MEDIUM),
        (210, "account_unlocked", Category.LOCKOUT, Severity.LOW),
        (211, "account_renamed", Category.ACCOUNT_LIFECYCLE, Severity.LOW),
        (213, "account_disabled", Category.ACCOUNT_LIFECYCLE, Severity.LOW),
        (214, "account_deleted", Category.ACCOUNT_LIFECYCLE, Severity.MEDIUM),
        (216, "group_member_removed", Category.GROUP_MEMBERSHIP, Severity.MEDIUM),
    ],
)
def test_mapping(
    events: list[TimelineEvent],
    record_id: int,
    action: str,
    category: Category,
    severity: Severity,
) -> None:
    ev = by_record(events, record_id)
    assert (ev.action, ev.category, ev.severity) == (action, category, severity)


def test_account_created_actor_and_target(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 201)
    assert ev.actor == Identity("rendszergazda", "CEG", f"{DOM}-1200")
    assert ev.target == Identity("kovacs.janos", "CEG", KOVACS)
    assert ev.description() == "CEG\\rendszergazda létrehozta a(z) CEG\\kovacs.janos fiókot"
    assert ev.description("en") == "CEG\\rendszergazda created account CEG\\kovacs.janos"


def test_account_changed_lists_only_changed_attributes(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 203)
    assert ev.details["ChangedAttributes"] == [
        "DisplayName",
        "UserPrincipalName",
        "UserAccountControl",
    ]
    assert ev.details["OldUacValue"] == "0x15"
    assert "PasswordLastSet" not in ev.details
    assert "(változott: DisplayName, UserPrincipalName" in ev.description()


def test_password_results_from_keywords(events: list[TimelineEvent]) -> None:
    reset = by_record(events, 204)
    assert reset.details["Result"] == "success"
    assert reset.description() == (
        "CEG\\rendszergazda visszaállította a(z) CEG\\kovacs.janos jelszavát (sikeres)"
    )
    own = by_record(events, 205)
    assert own.details["Result"] == "failure"
    assert own.description("en").endswith("(failed)")


@pytest.mark.parametrize(
    ("keywords", "expected"),
    [
        ("0x8020000000000000", "success"),
        ("0x8010000000000000", "failure"),
        ("0x8000000000000000", None),
        (None, None),
        ("garbage", None),
    ],
)
def test_audit_result(keywords: str | None, expected: str | None) -> None:
    assert audit_result(keywords) == expected


def test_group_membership_uses_member_sid(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 206)
    # A DN-ből származó CN nem kerül identitásnévként a célpontba, csak a SID.
    assert ev.target == Identity(None, None, KOVACS)
    assert ev.details["GroupSid"] == f"{DOM}-512"
    assert ev.details["GroupScope"] == "global"
    assert ev.details["PrivilegedGroup"] == "Domain Admins"
    assert ev.description() == (
        "CEG\\rendszergazda hozzáadta Kovács János tagot a(z) CEG\\Domain Admins globális "
        "csoporthoz – KIEMELT CSOPORT: Domain Admins"
    )
    assert ev.description("en") == (
        "CEG\\rendszergazda added Kovács János to global group CEG\\Domain Admins"
        " – PRIVILEGED GROUP: Domain Admins"
    )


def test_non_privileged_local_group(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 207)
    assert ev.details["PrivilegedGroup"] is None
    assert ev.details["GroupScope"] == "local"
    # MemberName "-": a tag megjelenítése a SID-re esik vissza.
    assert ev.description().startswith(f"CEG\\rendszergazda hozzáadta {KOVACS} tagot")
    assert "KIEMELT" not in ev.description()


def test_sid_only_member_is_resolved_for_display(events: list[TimelineEvent]) -> None:
    sid_map = SidMap()
    for event in events:
        sid_map.learn_event(event)
    ev = by_record(events, 207)
    resolve_sid_only_names(ev, sid_map)
    assert ev.description().startswith(
        f"CEG\\rendszergazda hozzáadta janos.kovacs / kovacs.janos ({KOVACS}) tagot"
    )
    # Maga az identitás (a bizonyíték) nem változik.
    assert ev.target == Identity(None, None, KOVACS)


def test_builtin_administrators_is_privileged(events: list[TimelineEvent]) -> None:
    assert by_record(events, 216).details["PrivilegedGroup"] == "Administrators"


def test_lockout_caller_computer(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 209)
    assert ev.actor is None
    # A TargetDomainName itt a hívó gép, nem tartomány.
    assert ev.target == Identity("kovacs.janos", None, KOVACS)
    assert ev.details["CallerComputerName"] == "WS-042"
    assert ev.description() == (
        "A(z) kovacs.janos fiók zárolva; a hibás próbálkozások forrása: WS-042"
    )


def test_rename_links_old_and_new_name(events: list[TimelineEvent]) -> None:
    ev = by_record(events, 211)
    assert ev.target == Identity("janos.kovacs", "CEG", KOVACS)
    assert ev.aliases == (Identity("kovacs.janos", "CEG", KOVACS),)
    assert ev.description() == (
        "CEG\\rendszergazda átnevezte a(z) kovacs.janos fiókot, új neve: janos.kovacs"
    )


@pytest.mark.parametrize("user", ["kovacs.janos", "CEG\\janos.kovacs", "janos.kovacs@ceg.hu"])
def test_old_and_new_name_find_the_same_history(events: list[TimelineEvent], user: str) -> None:
    roles = _rows_for(events, user)
    expected = [str(n) for n in range(201, 215)]
    assert sorted(roles) == expected
    assert roles["205"] is Role.BOTH  # saját jelszó módosítása
    assert roles["206"] is Role.TARGET
    # Nagy Péter csoporteseményei nem kerülnek be.
    assert "215" not in roles
    assert "216" not in roles


def test_admin_appears_as_actor(events: list[TimelineEvent]) -> None:
    roles = _rows_for(events, "rendszergazda")
    assert roles["201"] is Role.ACTOR
    assert roles["215"] is Role.ACTOR
    assert "209" not in roles


def test_keywords_read_from_record() -> None:
    record = load_records("security_account.json")[4]
    assert record.keywords == "0x8010000000000000"


@pytest.fixture
def account_evtx(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"")

    def fake_read(p: Path, stats: ReadStats) -> Iterator[RawRecord]:
        for record in load_records("security_account.json", str(p)):
            stats.records += 1
            yield record

    monkeypatch.setattr("usertrail.pipeline.read_evtx", fake_read)
    return path


def test_cli_timeline_by_old_name(account_evtx: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "timeline",
            "-s",
            str(account_evtx),
            "--user",
            "kovacs.janos",
            "--tz",
            "UTC",
            "--category",
            "GROUP_MEMBERSHIP,LOCKOUT",
        ],
        env={"COLUMNS": "250"},
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "KIEMELT CSOPORT" in out
    assert "zárolva" in out
    assert "létrehozta" not in out
    assert "Nagy" not in out
    assert out.index("4728") < out.index("4729") < out.index("4740") < out.index("4767")
