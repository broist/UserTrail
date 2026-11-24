from __future__ import annotations

import pytest

from usertrail.identity import (
    IdentityQuery,
    SidMap,
    is_machine_account,
    make_identity,
    parse_account,
    well_known_label,
)
from usertrail.models import Identity

SID = "S-1-5-21-1111111111-2222222222-3333333333-1105"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CEG\\kovacs.janos", ("kovacs.janos", "CEG", None)),
        ("kovacs.janos@ceg.hu", ("kovacs.janos", "ceg.hu", None)),
        ("kovacs.janos", ("kovacs.janos", None, None)),
        (SID.lower(), (None, None, SID)),
        (
            "CN=Kovács János,OU=Users,DC=ceg,DC=local",
            ("Kovács János", "ceg.local", None),
        ),
        ("CN=Doe\\, John,OU=Users,DC=ceg,DC=hu", ("Doe, John", "ceg.hu", None)),
        ("-", (None, None, None)),
        ("", (None, None, None)),
    ],
)
def test_parse_account(raw: str, expected: tuple[str | None, str | None, str | None]) -> None:
    assert parse_account(raw) == expected


def test_make_identity_cleans_placeholders_and_null_sid() -> None:
    assert make_identity("-", "-", "S-1-0-0") is None
    ident = make_identity("kovacs.janos", "CEG", "S-1-0-0")
    assert ident == Identity("kovacs.janos", "CEG", None)


def test_make_identity_splits_domain_from_name() -> None:
    ident = make_identity("CEG\\kovacs.janos")
    assert ident == Identity("kovacs.janos", "CEG", None)
    assert ident.display() == "CEG\\kovacs.janos"


def test_identity_keys_are_case_insensitive() -> None:
    a = make_identity("Kovacs.Janos", "CEG", SID.lower())
    assert a is not None
    assert a.name_key == "kovacs.janos"
    assert a.sid_key == SID


def test_machine_and_well_known_accounts() -> None:
    assert is_machine_account(make_identity("WS-042$"))
    assert not is_machine_account(make_identity("kovacs.janos"))
    assert well_known_label(make_identity(sid="S-1-5-18")) == "SYSTEM"
    assert well_known_label(make_identity("NETWORK SERVICE")) == "NETWORK SERVICE"
    assert well_known_label(make_identity("kovacs.janos")) is None
    assert make_identity(sid="S-1-5-18").display() == "SYSTEM (S-1-5-18)"  # type: ignore[union-attr]


def test_query_matches_name_upn_and_sid_via_sid_map() -> None:
    sid_map = SidMap()
    sid_map.learn(make_identity("kovacs.janos", "CEG", SID))

    by_upn = IdentityQuery.build("KOVACS.JANOS@ceg.hu", sid_map=sid_map)
    assert SID in by_upn.sids
    # A csak SID-et hordozó esemény (pl. PowerShell) is illeszkedik.
    assert by_upn.matches(make_identity(sid=SID))
    assert by_upn.matches(make_identity("ceg\\Kovacs.Janos"))
    assert not by_upn.matches(make_identity("nagy.peter"))
    assert not by_upn.matches(None)

    by_sid = IdentityQuery.build(sid=SID.lower(), sid_map=sid_map)
    assert "kovacs.janos" in by_sid.names
    assert by_sid.matches(make_identity("kovacs.janos"))


def test_query_flags() -> None:
    assert IdentityQuery.build().is_empty
    assert IdentityQuery.build("WS-042$").targets_machine_account
