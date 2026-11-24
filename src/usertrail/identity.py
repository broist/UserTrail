"""Account name normalisation, SID <-> name mapping and identity matching."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from usertrail.models import WELL_KNOWN_SIDS, Identity

SID_RE = re.compile(r"^S-1-\d+(-\d+)+$", re.IGNORECASE)

_PLACEHOLDERS = {"", "-"}
# SIDs that mean "no account" in Windows events (e.g. 4625 for unknown users).
_EMPTY_SIDS = {"S-1-0-0"}
_WELL_KNOWN_NAMES = {
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "localsystem",
}


def clean(value: Any) -> str | None:
    """Turn a raw field value into a stripped string, or None for placeholders."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in _PLACEHOLDERS else text


def is_sid(text: str) -> bool:
    return bool(SID_RE.match(text))


def parse_account(raw: str) -> tuple[str | None, str | None, str | None]:
    """Split a free-form account reference into ``(name, domain, sid)``.

    Accepted forms: ``DOMAIN\\user``, ``user@domain.tld`` (UPN), ``user``, a SID, or an
    LDAP distinguished name (``CN=...,OU=...,DC=...``). For a DN the returned name is the
    CN, which is usually the display name and not the sAMAccountName, so DN matches
    should prefer the accompanying SID when one is available.
    """
    text = raw.strip()
    if not text or text in _PLACEHOLDERS:
        return (None, None, None)
    if is_sid(text):
        return (None, None, text.upper())
    if text[:3].upper() == "CN=":
        return _parse_dn(text)
    if "\\" in text:
        domain, _, name = text.partition("\\")
        return (name or None, domain or None, None)
    if "@" in text:
        name, _, domain = text.partition("@")
        return (name or None, domain or None, None)
    return (text, None, None)


def _parse_dn(dn: str) -> tuple[str | None, str | None, str | None]:
    # Split on commas that are not escaped with a backslash.
    parts = [p.replace("\\,", ",").strip() for p in re.split(r"(?<!\\),", dn)]
    cn: str | None = None
    dcs: list[str] = []
    for part in parts:
        key, _, value = part.partition("=")
        key = key.strip().upper()
        if key == "CN" and cn is None:
            cn = value.strip() or None
        elif key == "DC" and value.strip():
            dcs.append(value.strip())
    return (cn, ".".join(dcs) or None, None)


def make_identity(name: Any = None, domain: Any = None, sid: Any = None) -> Identity | None:
    """Build a normalised :class:`Identity` from raw event fields.

    Returns None when none of the inputs carries information.
    """
    name_s = clean(name)
    domain_s = clean(domain)
    sid_s = clean(sid)

    if name_s is not None:
        parsed_name, parsed_domain, parsed_sid = parse_account(name_s)
        name_s = parsed_name
        domain_s = domain_s or parsed_domain
        sid_s = sid_s or parsed_sid

    if sid_s is not None:
        sid_s = sid_s.upper()
        if sid_s in _EMPTY_SIDS or not is_sid(sid_s):
            sid_s = None

    if name_s is None and sid_s is None:
        return None
    return Identity(name=name_s, domain=domain_s, sid=sid_s)


def is_machine_account(identity: Identity | None) -> bool:
    if identity is None or identity.name is None:
        return False
    return identity.name.endswith("$")


def well_known_label(identity: Identity | None) -> str | None:
    """Return a label such as ``SYSTEM`` for built-in system principals."""
    if identity is None:
        return None
    if identity.sid_key and identity.sid_key in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[identity.sid_key]
    if identity.name_key in _WELL_KNOWN_NAMES:
        return (identity.name or "").upper()
    return None


class SidMap:
    """Bidirectional SID <-> account name map learnt from processed events."""

    def __init__(self) -> None:
        self._names_by_sid: dict[str, set[str]] = defaultdict(set)
        self._sids_by_name: dict[str, set[str]] = defaultdict(set)

    def learn(self, identity: Identity | None) -> None:
        if identity is None or identity.sid_key is None or identity.name_key is None:
            return
        self._names_by_sid[identity.sid_key].add(identity.name_key)
        self._sids_by_name[identity.name_key].add(identity.sid_key)

    def learn_all(self, identities: Iterable[Identity | None]) -> None:
        for identity in identities:
            self.learn(identity)

    def names_for_sid(self, sid: str) -> set[str]:
        return set(self._names_by_sid.get(sid.upper(), set()))

    def sids_for_name(self, name: str) -> set[str]:
        return set(self._sids_by_name.get(name.casefold(), set()))


@dataclass(frozen=True, slots=True)
class IdentityQuery:
    """The set of names and SIDs that all refer to the searched account."""

    names: frozenset[str]
    sids: frozenset[str]

    @classmethod
    def build(
        cls, user: str | None = None, sid: str | None = None, sid_map: SidMap | None = None
    ) -> IdentityQuery:
        names: set[str] = set()
        sids: set[str] = set()
        if user:
            p_name, _p_domain, p_sid = parse_account(user)
            if p_name:
                names.add(p_name.casefold())
            if p_sid:
                sids.add(p_sid)
        if sid:
            sids.add(sid.strip().upper())
        if sid_map is not None:
            # Expand both ways so SID-only events and name-only events both match.
            for n in list(names):
                sids |= sid_map.sids_for_name(n)
            for s in list(sids):
                names |= sid_map.names_for_sid(s)
        return cls(names=frozenset(names), sids=frozenset(sids))

    @property
    def is_empty(self) -> bool:
        return not self.names and not self.sids

    @property
    def targets_machine_account(self) -> bool:
        return any(n.endswith("$") for n in self.names)

    def matches(self, identity: Identity | None) -> bool:
        if identity is None:
            return False
        if identity.sid_key is not None and identity.sid_key in self.sids:
            return True
        return identity.name_key is not None and identity.name_key in self.names
