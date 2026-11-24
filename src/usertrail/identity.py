"""Fióknév-normalizálás, SID ↔ név térkép és identitás-illesztés."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from usertrail.models import WELL_KNOWN_SIDS, Identity, TimelineEvent

SID_RE = re.compile(r"^S-1-\d+(-\d+)+$", re.IGNORECASE)

_PLACEHOLDERS = {"", "-"}
# SID-ek, amelyek a Windows-eseményekben „nincs fiók” jelentésűek
# (pl. 4625 nem létező felhasználónál).
_EMPTY_SIDS = {"S-1-0-0"}
# Kiemelt jogosultságú csoportok a SID végén lévő RID alapján (tartományi csoportok).
PRIVILEGED_DOMAIN_RIDS: dict[str, str] = {
    "512": "Domain Admins",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
}
# Beépített helyi csoportok teljes SID-del.
PRIVILEGED_BUILTIN_SIDS: dict[str, str] = {
    "S-1-5-32-544": "Administrators",
}

_WELL_KNOWN_NAMES = {
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "localsystem",
}


def clean(value: Any) -> str | None:
    """Nyers mezőérték szóközmentes szöveggé alakítása; helyőrzőnél None."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in _PLACEHOLDERS else text


def is_sid(text: str) -> bool:
    return bool(SID_RE.match(text))


def parse_account(raw: str) -> tuple[str | None, str | None, str | None]:
    """Szabad formájú fiókhivatkozás szétbontása ``(név, tartomány, sid)`` hármasra.

    Elfogadott alakok: ``DOMAIN\\felhasználó``, ``felhasználó@domain.tld`` (UPN), puszta
    felhasználónév, SID, illetve LDAP DN (``CN=...,OU=...,DC=...``). DN esetén a visszaadott
    név a CN, ami általában a megjelenítendő név és nem a sAMAccountName, ezért DN-nél ha
    van mellette SID, az illesztésnél azt érdemes előnyben részesíteni.
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
    # Bontás a vesszőknél, kivéve a visszaperjellel escape-elt vesszőket.
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
    """Normalizált :class:`Identity` létrehozása nyers eseménymezőkből.

    None-t ad vissza, ha egyik bemenet sem hordoz információt.
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
    """Beépített rendszerfióknál címkét ad vissza, pl. ``SYSTEM``."""
    if identity is None:
        return None
    if identity.sid_key and identity.sid_key in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[identity.sid_key]
    if identity.name_key in _WELL_KNOWN_NAMES:
        return (identity.name or "").upper()
    return None


def privileged_group(sid: str | None) -> str | None:
    """A kiemelt csoport angol neve, ha a SID ilyen csoporté (pl. ``Domain Admins``)."""
    if not sid:
        return None
    sid = sid.strip().upper()
    if sid in PRIVILEGED_BUILTIN_SIDS:
        return PRIVILEGED_BUILTIN_SIDS[sid]
    if sid.startswith("S-1-5-21-"):
        return PRIVILEGED_DOMAIN_RIDS.get(sid.rsplit("-", 1)[1])
    return None


class SidMap:
    """Kétirányú SID ↔ fióknév térkép, amelyet a feldolgozott eseményekből tanul."""

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

    def learn_event(self, event: TimelineEvent) -> None:
        """Egy esemény összes identitásának megtanulása, az aliasokat is beleértve.

        A 4781-es átnevezésnél a régi név aliasként érkezik ugyanazzal a SID-del, így a
        régi és az új név ugyanahhoz az identitáshoz kötődik.
        """
        self.learn(event.actor)
        self.learn(event.target)
        self.learn_all(event.aliases)

    def display_name(self, sid: str) -> str | None:
        """A SID-hez tanult név (átnevezés után több név ``/`` jellel elválasztva)."""
        names = self.names_for_sid(sid)
        return " / ".join(sorted(names)) if names else None

    def names_for_sid(self, sid: str) -> set[str]:
        return set(self._names_by_sid.get(sid.upper(), set()))

    def sids_for_name(self, name: str) -> set[str]:
        return set(self._sids_by_name.get(name.casefold(), set()))


def resolve_sid_only_names(event: TimelineEvent, sid_map: SidMap) -> None:
    """Csak SID-del szereplő fiókok nevének kitöltése a leírásban a SID-térképből.

    Csak a megjelenítést (``message_params``) módosítja; az esemény identitásai, azaz a
    naplóban ténylegesen szereplő adatok változatlanok maradnak.
    """
    params = event.message_params
    for key, identity in (("actor", event.actor), ("target", event.target)):
        if identity is None or identity.name is not None or identity.sid is None:
            continue
        name = sid_map.display_name(identity.sid)
        if name is None:
            continue
        shown = f"{name} ({identity.sid})"
        if params.get(key) == identity.display():
            params[key] = shown
        # A csoporteseményeknél a tag külön paraméterben szerepel.
        if key == "target" and params.get("member") == identity.display():
            params["member"] = shown


@dataclass(frozen=True, slots=True)
class IdentityQuery:
    """Azoknak a neveknek és SID-eknek a halmaza, amelyek a keresett fiókra utalnak."""

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
            # Bővítés mindkét irányban, amíg már nem változik (átnevezésnél a régi név
            # -> SID -> új név lánc is bejárható), így a csak SID-es és a csak neves
            # események is illeszkednek.
            while True:
                before = (len(names), len(sids))
                for n in list(names):
                    sids |= sid_map.sids_for_name(n)
                for s in list(sids):
                    names |= sid_map.names_for_sid(s)
                if (len(names), len(sids)) == before:
                    break
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
