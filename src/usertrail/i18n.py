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
        "account_created": "{actor} created account {target}",
        "account_enabled": "{actor} enabled account {target}",
        "account_disabled": "{actor} disabled account {target}",
        "account_deleted": "{actor} deleted account {target}",
        "account_changed": "{actor} changed account {target} (changed: {changed})",
        "account_renamed": ("{actor} renamed account {OldTargetUserName} to {NewTargetUserName}"),
        "password_change_attempt": (
            "{actor} attempted to change the password of {target} ({result_text})"
        ),
        "password_reset": "{actor} reset the password of {target} ({result_text})",
        "account_locked": (
            "Account {target} was locked out; failed attempts came from {CallerComputerName}"
        ),
        "account_unlocked": "{actor} unlocked account {target}",
        "group_member_added": (
            "{actor} added {member} to {scope_text} group {group}{privileged_text}"
        ),
        "group_member_removed": (
            "{actor} removed {member} from {scope_text} group {group}{privileged_text}"
        ),
        "web_request": "Web request: {method} {uri} → {status}, client: {src}",
        "kerberos_tgt": "Kerberos TGT issued for {target}, from {src}",
        "kerberos_tgt_failure": (
            "Kerberos TGT request failed for {target}, from {src}: {kerb_status_text}"
        ),
        "kerberos_service_ticket": (
            "Kerberos service ticket for {target} to {ServiceName}, from {src}"
        ),
        "kerberos_service_ticket_failure": (
            "Kerberos service ticket request failed for {target} to {ServiceName}, "
            "from {src}: {kerb_status_text}"
        ),
        "kerberos_preauth_failed": (
            "Kerberos pre-authentication failed for {target}, from {src}: {kerb_status_text}"
        ),
        "ntlm_validation": "NTLM credential validation for {target}, workstation: {Workstation}",
        "ntlm_validation_failure": (
            "NTLM credential validation failed for {target}, workstation: {Workstation}: "
            "{status_text}"
        ),
        "audit_log_cleared": "{actor} cleared the Security audit log",
        "log_cleared": "{actor} cleared the {Channel} log",
        "process_created": "{actor} started process {NewProcessName}: {command}",
        "scheduled_task_created": "{actor} created scheduled task {TaskName}",
        "service_installed": (
            "Service installed: {ServiceName} – {ImagePath} "
            "(account: {AccountName}, installed by: {actor})"
        ),
        "rdp_logon": "RDP logon of {target} from {src} (session {SessionID})",
        "rdp_logoff": "RDP logoff of {target} (session {SessionID})",
        "rdp_disconnect": "RDP session of {target} disconnected (session {SessionID}, from {src})",
        "rdp_reconnect": "RDP session of {target} reconnected from {src} (session {SessionID})",
        "rdp_auth_success": "RDP network authentication succeeded for {target} from {src}",
        "script_block": "PowerShell script block run by {actor}: {preview}",
        # --- figyelmeztetések
        "alert.log_cleared": "Log cleared ({channel}) on {host} by {actor}",
        "alert.privileged_group_added": (
            "{member} was added to privileged group {group} (by {actor})"
        ),
        "alert.account_locked": (
            "Account {account} locked out (caller: {caller}); {count} failed attempts in the "
            "previous {minutes} minutes from: {sources}"
        ),
        "alert.failed_logon_burst": (
            "{count} failed logons for {account}, {first} – {last}, from: {sources}"
        ),
        "alert.success_after_failures": (
            "Successful logon of {account} after {count} failures within {minutes} minutes, "
            "from {src} – possible password guessing"
        ),
        "alert.off_hours_logon": (
            "Logon outside working hours: {account} at {local_time} "
            "(working hours: {work_start}–{work_end}, weekdays), from {src}"
        ),
        "alert.password_reset_new_ip": (
            "Logon of {account} from a new IP ({src}) {minutes} minutes after a password "
            "reset by {actor}"
        ),
        "alert.persistence_by_user": "{actor} {kind_text}: {name} on {host}",
        # --- összevont sorok
        "collapsed": "{count}× {label}{extra}: {account}, from {src} ({first} – {last})",
        "web_request_user": "Web request by {actor}: {method} {uri} → {status}, client: {src}",
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
        "account_created": "{actor} létrehozta a(z) {target} fiókot",
        "account_enabled": "{actor} engedélyezte a(z) {target} fiókot",
        "account_disabled": "{actor} letiltotta a(z) {target} fiókot",
        "account_deleted": "{actor} törölte a(z) {target} fiókot",
        "account_changed": "{actor} módosította a(z) {target} fiókot (változott: {changed})",
        "account_renamed": (
            "{actor} átnevezte a(z) {OldTargetUserName} fiókot, új neve: {NewTargetUserName}"
        ),
        "password_change_attempt": (
            "{actor} megkísérelte módosítani a(z) {target} jelszavát ({result_text})"
        ),
        "password_reset": "{actor} visszaállította a(z) {target} jelszavát ({result_text})",
        "account_locked": (
            "A(z) {target} fiók zárolva; a hibás próbálkozások forrása: {CallerComputerName}"
        ),
        "account_unlocked": "{actor} feloldotta a(z) {target} fiók zárolását",
        "group_member_added": (
            "{actor} hozzáadta {member} tagot a(z) {group} {scope_text} csoporthoz{privileged_text}"
        ),
        "group_member_removed": (
            "{actor} eltávolította {member} tagot a(z) {group} {scope_text} csoportból"
            "{privileged_text}"
        ),
        "web_request": "Webes kérés: {method} {uri} → {status}, kliens: {src}",
        "kerberos_tgt": "Kerberos TGT kiadva: {target}, forrás: {src}",
        "kerberos_tgt_failure": (
            "Sikertelen Kerberos TGT-kérés: {target}, forrás: {src} – {kerb_status_text}"
        ),
        "kerberos_service_ticket": (
            "Kerberos szolgáltatásjegy: {target} → {ServiceName}, forrás: {src}"
        ),
        "kerberos_service_ticket_failure": (
            "Sikertelen Kerberos szolgáltatásjegy-kérés: {target} → {ServiceName}, "
            "forrás: {src} – {kerb_status_text}"
        ),
        "kerberos_preauth_failed": (
            "Sikertelen Kerberos előhitelesítés: {target}, forrás: {src} – {kerb_status_text}"
        ),
        "ntlm_validation": "NTLM-hitelesítés ellenőrzése: {target}, munkaállomás: {Workstation}",
        "ntlm_validation_failure": (
            "Sikertelen NTLM-hitelesítés: {target}, munkaállomás: {Workstation} – {status_text}"
        ),
        "audit_log_cleared": "{actor} törölte a Security naplót",
        "log_cleared": "{actor} törölte a(z) {Channel} naplót",
        "process_created": "{actor} folyamatot indított: {NewProcessName} – {command}",
        "scheduled_task_created": "{actor} ütemezett feladatot hozott létre: {TaskName}",
        "service_installed": (
            "Új szolgáltatás telepítve: {ServiceName} – {ImagePath} "
            "(fiók: {AccountName}, telepítő: {actor})"
        ),
        "rdp_logon": "RDP-bejelentkezés: {target}, forrás: {src} ({SessionID}. munkamenet)",
        "rdp_logoff": "RDP-kijelentkezés: {target} ({SessionID}. munkamenet)",
        "rdp_disconnect": (
            "RDP-munkamenet bontva: {target} ({SessionID}. munkamenet, forrás: {src})"
        ),
        "rdp_reconnect": (
            "RDP-munkamenet újracsatlakozva: {target}, forrás: {src} ({SessionID}. munkamenet)"
        ),
        "rdp_auth_success": "Sikeres RDP hálózati hitelesítés: {target}, forrás: {src}",
        "script_block": "PowerShell-szkriptblokk ({actor}): {preview}",
        # --- figyelmeztetések
        "alert.log_cleared": "Napló törölve ({channel}) a(z) {host} gépen; végrehajtotta: {actor}",
        "alert.privileged_group_added": (
            "{member} kiemelt csoportba került: {group} (végrehajtotta: {actor})"
        ),
        "alert.account_locked": (
            "A(z) {account} fiók zárolva (hívó gép: {caller}); az előző {minutes} percben "
            "{count} sikertelen próbálkozás, forrás: {sources}"
        ),
        "alert.failed_logon_burst": (
            "{count} sikertelen bejelentkezés: {account}, {first} – {last}, forrás: {sources}"
        ),
        "alert.success_after_failures": (
            "Sikeres bejelentkezés {count} sikertelen után ({minutes} percen belül): {account}, "
            "forrás: {src} – lehetséges jelszótalálgatás"
        ),
        "alert.off_hours_logon": (
            "Munkaidőn kívüli bejelentkezés: {account}, {local_time} "
            "(munkaidő: {work_start}–{work_end}, hétköznap), forrás: {src}"
        ),
        "alert.password_reset_new_ip": (
            "Bejelentkezés új IP-ről ({src}) {minutes} perccel a jelszó-visszaállítás után: "
            "{account} (visszaállította: {actor})"
        ),
        "alert.persistence_by_user": "{actor} {kind_text}: {name} ({host})",
        # --- összevont sorok
        "collapsed": "{count}× {label}{extra}: {account}, forrás: {src} ({first} – {last})",
        "web_request_user": "Webes kérés ({actor}): {method} {uri} → {status}, kliens: {src}",
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

# Az eredmény, a csoport-hatókör és a kiemelt csoport szövegei.
# Kerberos-hibakódok (4768/4769 Status, 4771 Status/FailureCode), normalizált "0x.." kulccsal.
KERBEROS_CODES: dict[str, dict[str, str]] = {
    "en": {
        "0x6": "unknown principal (account does not exist)",
        "0x7": "service principal not found",
        "0xc": "policy restriction (e.g. workstation or logon hours)",
        "0x12": "account disabled, locked out or expired",
        "0x17": "password expired",
        "0x18": "wrong password",
        "0x1f": "integrity check failed",
        "0x20": "ticket expired",
        "0x25": "clock skew too great",
    },
    "hu": {
        "0x6": "nem létező fiók",
        "0x7": "a szolgáltatás nem található",
        "0xc": "házirend-korlátozás (pl. munkaállomás vagy bejelentkezési idő)",
        "0x12": "a fiók letiltva, zárolva vagy lejárt",
        "0x17": "lejárt jelszó",
        "0x18": "hibás jelszó",
        "0x1f": "integritás-ellenőrzési hiba",
        "0x20": "lejárt jegy",
        "0x25": "túl nagy óraeltérés",
    },
}

DERIVED_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "result.success": "succeeded",
        "result.failure": "failed",
        "result.unknown": "result unknown",
        "scope.global": "global",
        "scope.local": "local",
        "scope.universal": "universal",
        "privileged": " – PRIVILEGED GROUP: {name}",
        "kind.service_installed": "installed a new service",
        "kind.scheduled_task_created": "created a scheduled task",
    },
    "hu": {
        "result.success": "sikeres",
        "result.failure": "sikertelen",
        "result.unknown": "eredmény ismeretlen",
        "scope.global": "globális",
        "scope.local": "helyi",
        "scope.universal": "univerzális",
        "privileged": " – KIEMELT CSOPORT: {name}",
        "kind.service_installed": "új szolgáltatást telepített",
        "kind.scheduled_task_created": "ütemezett feladatot hozott létre",
    },
}

UI_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "role.actor": "actor",
        "role.target": "target",
        "role.both": "actor+target",
        "role.related": "related (IP)",
        "role.correlated": "correlated (IP)",
        "col.time": "Time",
        "col.source": "Source",
        "col.host": "Host",
        "col.event": "Event",
        "col.role": "Role",
        "col.ip": "IP",
        "col.description": "Description",
        "header.tz": "Times shown in",
        "no_events": "No matching events.",
        "col.alert": "!",
        "col.rule": "Rule",
        "col.severity": "Severity",
        "alerts.title": "Alerts",
        "rule.log_cleared": "Log cleared",
        "rule.privileged_group_added": "Privileged group",
        "rule.account_locked": "Account lockout",
        "rule.failed_logon_burst": "Failed logons",
        "rule.success_after_failures": "Possible password guessing",
        "rule.off_hours_logon": "Off-hours logon",
        "rule.password_reset_new_ip": "Password reset + new IP",
        "rule.persistence_by_user": "Persistence",
        "severity.info": "info",
        "severity.low": "low",
        "severity.medium": "medium",
        "severity.high": "high",
    },
    "hu": {
        "role.actor": "szereplő",
        "role.target": "célpont",
        "role.both": "szereplő+célpont",
        "role.related": "kapcsolódó (IP)",
        "role.correlated": "korrelált (IP)",
        "col.time": "Idő",
        "col.source": "Forrás",
        "col.host": "Gép",
        "col.event": "Esemény",
        "col.role": "Szerep",
        "col.ip": "IP",
        "col.description": "Leírás",
        "header.tz": "Időzóna",
        "no_events": "Nincs találat.",
        "col.alert": "!",
        "col.rule": "Szabály",
        "col.severity": "Súlyosság",
        "alerts.title": "Figyelmeztetések",
        "rule.log_cleared": "Naplótörlés",
        "rule.privileged_group_added": "Kiemelt csoport",
        "rule.account_locked": "Fiókzárolás",
        "rule.failed_logon_burst": "Sikertelen bejelentkezések",
        "rule.success_after_failures": "Lehetséges jelszótalálgatás",
        "rule.off_hours_logon": "Munkaidőn kívül",
        "rule.password_reset_new_ip": "Jelszó-visszaállítás + új IP",
        "rule.persistence_by_user": "Perzisztencia",
        "severity.info": "információ",
        "severity.low": "alacsony",
        "severity.medium": "közepes",
        "severity.high": "magas",
    },
}


# Az összevont (--collapse) sorok rövid eseménynevei.
COLLAPSE_LABELS: dict[str, dict[str, str]] = {
    "en": {
        "logon_success": "successful logon",
        "logon_failure": "failed logon",
        "logoff": "logoff",
        "special_privileges": "privileged logon",
        "kerberos_tgt": "Kerberos TGT",
        "kerberos_tgt_failure": "failed Kerberos TGT request",
        "kerberos_service_ticket": "Kerberos service ticket",
        "kerberos_service_ticket_failure": "failed Kerberos service ticket request",
        "kerberos_preauth_failed": "failed Kerberos pre-authentication",
        "ntlm_validation": "NTLM validation",
        "ntlm_validation_failure": "failed NTLM validation",
        "web_request": "web request",
    },
    "hu": {
        "logon_success": "sikeres bejelentkezés",
        "logon_failure": "sikertelen bejelentkezés",
        "logoff": "kijelentkezés",
        "special_privileges": "kiemelt jogosultságú bejelentkezés",
        "kerberos_tgt": "Kerberos TGT",
        "kerberos_tgt_failure": "sikertelen Kerberos TGT-kérés",
        "kerberos_service_ticket": "Kerberos szolgáltatásjegy",
        "kerberos_service_ticket_failure": "sikertelen Kerberos szolgáltatásjegy-kérés",
        "kerberos_preauth_failed": "sikertelen Kerberos előhitelesítés",
        "ntlm_validation": "NTLM-ellenőrzés",
        "ntlm_validation_failure": "sikertelen NTLM-ellenőrzés",
        "web_request": "webes kérés",
    },
}


def collapse_label(action: str, lang: str) -> str:
    return COLLAPSE_LABELS[_lang(lang)].get(action, action)


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


def normalize_kerberos_status(value: Any) -> str | None:
    """Kerberos-hibakód normalizálása rövid, kisbetűs hexa alakra (pl. ``0x18``)."""
    if value is None:
        return None
    if isinstance(value, int):
        return hex(value)
    text = str(value).strip()
    if not text or text == "-":
        return None
    try:
        number = int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return text
    return hex(number)


def kerberos_status_text(code: str | None, lang: str) -> str:
    if code is None:
        return "-"
    text = KERBEROS_CODES[_lang(lang)].get(code)
    return f"{text} ({code})" if text else code


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
    if "KerberosStatus" in params:
        values["kerb_status_text"] = kerberos_status_text(params["KerberosStatus"], lang)
    derived = DERIVED_TEXT[lang]
    if "kind" in params:
        values["kind_text"] = derived.get(f"kind.{params['kind']}", str(params["kind"]))
    if "Result" in params:
        values["result_text"] = derived[f"result.{params['Result'] or 'unknown'}"]
    if "GroupScope" in params:
        scope = params["GroupScope"]
        values["scope_text"] = derived.get(f"scope.{scope}", str(scope or "-"))
        privileged = params.get("PrivilegedGroup")
        values["privileged_text"] = (
            derived["privileged"].format(name=privileged) if privileged else ""
        )
    if template is None:
        shown = ", ".join(f"{k}={v}" for k, v in values.items())
        return f"{key} ({shown})" if shown else key
    return string.Formatter().vformat(template, (), values)
