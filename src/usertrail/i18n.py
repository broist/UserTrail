"""Emberi olvasásra szánt üzenetsablonok magyarul és angolul.

A sablonok ``str.format`` helyőrzőket használnak, amelyeket az esemény
``message_params`` mezője tölt ki. A hiányzó paraméter helyén ``-`` jelenik meg. Néhány
származtatott értéket itt számolunk ki, hogy a tárolt paraméterek nyelvfüggetlenek
maradjanak:

* ``{logon_type_text}`` a ``LogonType`` mezőből
* ``{status_text}`` a ``SubStatus`` mezőből (vagy a ``Status`` mezőből, ha a SubStatus üres)
"""

from __future__ import annotations

import string
from collections.abc import Mapping
from typing import Any

SUPPORTED_LANGS = ("en", "hu")
DEFAULT_LANG = "hu"

MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        "logon_success": "Successful logon of {target} ({logon_type_text}) from {src}",
        "logon_failure": "Failed logon of {target} ({logon_type_text}) from {src}: {status_text}",
        "logoff": "Logoff of {target} ({logon_type_text})",
        "logoff_user": "User-initiated logoff of {target}",
        "explicit_credentials": (
            "{actor} used the explicit credentials of {target} to access {TargetServerName}"
        ),
        "special_privileges": "Special privileges assigned to the new logon of {actor}",
    },
    "hu": {
        "logon_success": "Sikeres bejelentkezés: {target} ({logon_type_text}), forrás: {src}",
        "logon_failure": (
            "Sikertelen bejelentkezés: {target} ({logon_type_text}), forrás: {src} – {status_text}"
        ),
        "logoff": "Kijelentkezés: {target} ({logon_type_text})",
        "logoff_user": "Felhasználó által kezdeményezett kijelentkezés: {target}",
        "explicit_credentials": (
            "{actor} explicit hitelesítő adatokat használt ({target}) a(z) "
            "{TargetServerName} eléréséhez"
        ),
        "special_privileges": "Kiemelt jogosultságok az új bejelentkezéshez: {actor}",
    },
}

LOGON_TYPES: dict[str, dict[int, str]] = {
    "en": {
        0: "system",
        2: "interactive",
        3: "network",
        4: "batch",
        5: "service",
        7: "unlock",
        8: "network cleartext",
        9: "new credentials (runas /netonly)",
        10: "RDP",
        11: "cached interactive",
        12: "cached RDP",
        13: "cached unlock",
    },
    "hu": {
        0: "rendszer",
        2: "interaktív",
        3: "hálózati",
        4: "batch",
        5: "szolgáltatás",
        7: "feloldás",
        8: "hálózati tiszta szöveges",
        9: "új hitelesítő adatok (runas /netonly)",
        10: "RDP",
        11: "gyorsítótárazott interaktív",
        12: "gyorsítótárazott RDP",
        13: "gyorsítótárazott feloldás",
    },
}

# A 4625 Status / SubStatus mezőiben előforduló NTSTATUS-kódok,
# normalizált "0xXXXXXXXX" kulccsal.
STATUS_CODES: dict[str, dict[str, str]] = {
    "en": {
        "0xC0000064": "user does not exist",
        "0xC000006A": "wrong password",
        "0xC000006D": "bad user name or authentication information",
        "0xC000006F": "logon outside allowed hours",
        "0xC0000070": "workstation not allowed",
        "0xC0000071": "password expired",
        "0xC0000072": "account disabled",
        "0xC000015B": "logon type not granted",
        "0xC0000193": "account expired",
        "0xC0000224": "password change required",
        "0xC0000234": "account locked out",
    },
    "hu": {
        "0xC0000064": "nem létező felhasználó",
        "0xC000006A": "hibás jelszó",
        "0xC000006D": "hibás felhasználónév vagy hitelesítési adat",
        "0xC000006F": "engedélyezett időn kívül",
        "0xC0000070": "nem engedélyezett munkaállomás",
        "0xC0000071": "lejárt jelszó",
        "0xC0000072": "letiltott fiók",
        "0xC000015B": "a bejelentkezési típus nem engedélyezett",
        "0xC0000193": "lejárt fiók",
        "0xC0000224": "jelszócsere szükséges",
        "0xC0000234": "zárolt fiók",
    },
}

UI_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "role.actor": "actor",
        "role.target": "target",
        "role.both": "actor+target",
        "role.related": "related (IP)",
        "col.time": "Time",
        "col.source": "Source",
        "col.host": "Host",
        "col.event": "Event",
        "col.role": "Role",
        "col.ip": "IP",
        "col.description": "Description",
        "header.tz": "Times shown in",
        "no_events": "No matching events.",
    },
    "hu": {
        "role.actor": "szereplő",
        "role.target": "célpont",
        "role.both": "szereplő+célpont",
        "role.related": "kapcsolódó (IP)",
        "col.time": "Idő",
        "col.source": "Forrás",
        "col.host": "Gép",
        "col.event": "Esemény",
        "col.role": "Szerep",
        "col.ip": "IP",
        "col.description": "Leírás",
        "header.tz": "Időzóna",
        "no_events": "Nincs találat.",
    },
}


def _lang(lang: str) -> str:
    return lang if lang in SUPPORTED_LANGS else DEFAULT_LANG


def ui(key: str, lang: str) -> str:
    return UI_TEXT[_lang(lang)].get(key) or UI_TEXT[DEFAULT_LANG].get(key, key)


def logon_type_text(value: Any, lang: str) -> str:
    try:
        code = int(value)
    except (TypeError, ValueError):
        return "-"
    text = LOGON_TYPES[_lang(lang)].get(code)
    return f"{code} {text}" if text else str(code)


def normalize_status(value: Any) -> str | None:
    """NTSTATUS-érték (egész szám vagy hexa szöveg) normalizálása ``0xXXXXXXXX`` alakra."""
    if value is None:
        return None
    if isinstance(value, int):
        return f"0x{value & 0xFFFFFFFF:08X}"
    text = str(value).strip()
    if not text or text == "-":
        return None
    try:
        number = int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return text
    return f"0x{number & 0xFFFFFFFF:08X}"


def status_text(status: Any, sub_status: Any, lang: str) -> str:
    sub = normalize_status(sub_status)
    code = sub if sub and sub != "0x00000000" else normalize_status(status)
    if code is None:
        return "-"
    text = STATUS_CODES[_lang(lang)].get(code)
    return f"{text} ({code})" if text else code


class _Params(dict[str, str]):
    def __missing__(self, key: str) -> str:
        return "-"


def render(key: str, params: Mapping[str, Any], lang: str = DEFAULT_LANG) -> str:
    lang = _lang(lang)
    template = MESSAGES[lang].get(key) or MESSAGES[DEFAULT_LANG].get(key)
    values = _Params({k: "-" if v is None else str(v) for k, v in params.items()})
    if "LogonType" in params:
        values["logon_type_text"] = logon_type_text(params["LogonType"], lang)
    if "Status" in params or "SubStatus" in params:
        values["status_text"] = status_text(params.get("Status"), params.get("SubStatus"), lang)
    if template is None:
        shown = ", ".join(f"{k}={v}" for k, v in values.items())
        return f"{key} ({shown})" if shown else key
    return string.Formatter().vformat(template, (), values)
