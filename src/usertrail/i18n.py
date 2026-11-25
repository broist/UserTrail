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
        "health.no_sources": "The case contains no processed source files.",
        "health.incomplete_sources": (
            "{count} source file(s) were not fully ingested; run ingest again for them."
        ),
        "health.record_errors": (
            "{count} record(s) could not be processed; see the ingest output for samples."
        ),
        "health.missing.Security": (
            "No Security log: it is the main source of logon, account and group events."
        ),
        "health.missing.System": "No System log: service installations (7045) are not visible.",
        "health.missing.RDP-LSM": (
            "No TerminalServices-LocalSessionManager log: RDP sessions (21/23/24/25) "
            "are not visible."
        ),
        "health.missing.RDP-RCM": (
            "No TerminalServices-RemoteConnectionManager log: RDP authentication (1149) "
            "is not visible."
        ),
        "health.missing.PowerShell": (
            "No PowerShell/Operational log: PowerShell script blocks (4104) are not visible."
        ),
        "health.missing.IIS": "No IIS log: web requests and the IP pivot are not available.",
        "health.no_logon": (
            "No 4624 event: logon auditing (Logon/Logoff > Audit Logon) is probably disabled."
        ),
        "health.no_logon_failure": (
            "No 4625 event: either there were no failed logons, or failure auditing "
            "(Logon/Logoff > Audit Logon, Failure) is disabled."
        ),
        "health.no_process_creation": (
            "No 4688 event: process creation auditing "
            "(Detailed Tracking > Audit Process Creation) is probably disabled."
        ),
        "health.no_command_line": (
            "The 4688 events contain no command line: the policy 'Include command line in "
            "process creation events' is disabled."
        ),
        "health.no_kerberos": (
            "No Kerberos event (4768/4769/4771): the Security log is probably not from a domain "
            "controller, or Kerberos auditing (Account Logon) is disabled."
        ),
        "health.no_account_management": (
            "No account management event (4720–4781, group changes): the log is probably not "
            "from a domain controller, or Account Management auditing is disabled."
        ),
        "health.no_scheduled_task": (
            "No 4698 event: scheduled task auditing "
            "(Object Access > Audit Other Object Access Events) is probably disabled."
        ),
        "health.short_coverage": (
            "The Security log covers only {days} days ({first} – {last}), less than "
            "{min_days}; older events were probably overwritten. Consider a larger maximum "
            "log size."
        ),
        "health.no_script_block": (
            "The PowerShell log has no 4104 event: Script Block Logging is disabled."
        ),
        "health.log_cleared": (
            "The {source} log was cleared {count} time(s) ({source} {event_id}, first at "
            "{first}); events before that are missing."
        ),
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
        "health.no_sources": "A vizsgálatban nincs feldolgozott forrásfájl.",
        "health.incomplete_sources": (
            "{count} forrásfájl betöltése nem fejeződött be; futtasd újra rájuk az ingestet."
        ),
        "health.record_errors": (
            "{count} rekordot nem sikerült feldolgozni; a mintákat az ingest kimenete mutatja."
        ),
        "health.missing.Security": (
            "Nincs Security-napló: a bejelentkezési, fiókkezelési és csoportesemények fő forrása."
        ),
        "health.missing.System": (
            "Nincs System-napló: a szolgáltatástelepítések (7045) nem látszanak."
        ),
        "health.missing.RDP-LSM": (
            "Nincs TerminalServices-LocalSessionManager napló: az RDP-munkamenetek "
            "(21/23/24/25) nem látszanak."
        ),
        "health.missing.RDP-RCM": (
            "Nincs TerminalServices-RemoteConnectionManager napló: az RDP-hitelesítés (1149) "
            "nem látszik."
        ),
        "health.missing.PowerShell": (
            "Nincs PowerShell/Operational napló: a PowerShell-szkriptblokkok (4104) nem látszanak."
        ),
        "health.missing.IIS": "Nincs IIS-napló: a webes kérések és az IP-pivot nem érhetők el.",
        "health.no_logon": (
            "Nincs 4624-es esemény: a bejelentkezések auditálása "
            "(Logon/Logoff > Audit Logon) valószínűleg nincs bekapcsolva."
        ),
        "health.no_logon_failure": (
            "Nincs 4625-ös esemény: vagy nem volt sikertelen bejelentkezés, vagy a hibák "
            "auditálása (Logon/Logoff > Audit Logon, Failure) nincs bekapcsolva."
        ),
        "health.no_process_creation": (
            "Nincs 4688-as esemény: a folyamatindítás auditálása "
            "(Detailed Tracking > Audit Process Creation) valószínűleg nincs bekapcsolva."
        ),
        "health.no_command_line": (
            "A 4688-as eseményekben nincs parancssor: az 'Include command line in process "
            "creation events' házirend nincs bekapcsolva."
        ),
        "health.no_kerberos": (
            "Nincs Kerberos-esemény (4768/4769/4771): a Security-napló valószínűleg nem "
            "tartományvezérlőről származik, vagy a Kerberos-auditálás (Account Logon) nincs "
            "bekapcsolva."
        ),
        "health.no_account_management": (
            "Nincs fiókkezelési esemény (4720–4781, csoportváltozások): a napló valószínűleg "
            "nem tartományvezérlőről származik, vagy az Account Management auditálás nincs "
            "bekapcsolva."
        ),
        "health.no_scheduled_task": (
            "Nincs 4698-as esemény: az ütemezett feladatok auditálása "
            "(Object Access > Audit Other Object Access Events) valószínűleg nincs bekapcsolva."
        ),
        "health.short_coverage": (
            "A Security-napló csak {days} napot fed le ({first} – {last}), kevesebbet, mint "
            "{min_days}; a régebbi események valószínűleg felülíródtak. Érdemes nagyobb "
            "maximális naplóméretet beállítani."
        ),
        "health.no_script_block": (
            "A PowerShell-naplóban nincs 4104-es esemény: a szkriptblokk-naplózás "
            "(Script Block Logging) nincs bekapcsolva."
        ),
        "health.log_cleared": (
            "A(z) {source} naplót {count} alkalommal törölték ({source} {event_id}, először: "
            "{first}); az azelőtti események hiányoznak."
        ),
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
        "sources.title": "Log sources",
        "sources.files_title": "Processed source files",
        "sources.findings": "Findings",
        "sources.none": "No gaps found.",
        "col.channel": "Source",
        "col.files": "Files",
        "col.records": "Records",
        "col.events": "Timeline events",
        "col.first": "Earliest",
        "col.last": "Latest",
        "col.days": "Days",
        "col.path": "Path",
        "col.kind": "Type",
        "col.errors": "Errors",
        "level.warning": "warning",
        "level.info": "info",
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
        "sources.title": "Naplóforrások",
        "sources.files_title": "Feldolgozott forrásfájlok",
        "sources.findings": "Megállapítások",
        "sources.none": "Nem találtam hiányosságot.",
        "col.channel": "Forrás",
        "col.files": "Fájl",
        "col.records": "Rekord",
        "col.events": "Idővonal-esemény",
        "col.first": "Legkorábbi",
        "col.last": "Legkésőbbi",
        "col.days": "Nap",
        "col.path": "Útvonal",
        "col.kind": "Típus",
        "col.errors": "Hiba",
        "level.warning": "figyelmeztetés",
        "level.info": "információ",
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


# A HTML-riport feliratai.
REPORT_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "title": "UserTrail timeline",
        "generated": "Generated",
        "version": "Tool version",
        "parameters": "Run parameters",
        "time_zone": "Times shown in",
        "summary": "Summary",
        "period": "Period",
        "events": "Events",
        "rows": "Rows",
        "alerts": "Alerts",
        "no_alerts": "No alerts.",
        "by_category": "Events by category",
        "by_severity": "Events by severity",
        "timeline": "Timeline",
        "sources": "Processed source files",
        "search": "Search…",
        "all_categories": "All categories",
        "all_roles": "All roles",
        "min_severity": "Minimum severity",
        "only_alerts": "Only alerted rows",
        "theme": "Light / dark",
        "details": "Details",
        "raw_ref": "Original record",
        "members": "Collapsed events",
        "correlated_with": "Correlated with logon",
        "fields": "Raw fields",
        "path": "Path",
        "kind": "Type",
        "size": "Size (bytes)",
        "sha256": "SHA-256",
        "records": "Records",
        "errors": "Errors",
        "ingested": "Ingested",
        "options": "Options",
        "correlated_note": (
            "Rows marked “correlated (IP)” only share a source IP and time window with a "
            "logon of the account; they do not prove that the same person sent the request."
        ),
        "record_errors": "Records that could not be processed",
        "shown": "shown",
        "no_rows": "No matching events.",
    },
    "hu": {
        "title": "UserTrail idővonal",
        "generated": "Készült",
        "version": "Eszközverzió",
        "parameters": "Futtatási paraméterek",
        "time_zone": "Időzóna",
        "summary": "Összefoglaló",
        "period": "Időszak",
        "events": "Események",
        "rows": "Sorok",
        "alerts": "Figyelmeztetések",
        "no_alerts": "Nincs figyelmeztetés.",
        "by_category": "Események kategóriánként",
        "by_severity": "Események súlyosság szerint",
        "timeline": "Idővonal",
        "sources": "Feldolgozott forrásfájlok",
        "search": "Keresés…",
        "all_categories": "Minden kategória",
        "all_roles": "Minden szerep",
        "min_severity": "Legalacsonyabb súlyosság",
        "only_alerts": "Csak a figyelmeztetéses sorok",
        "theme": "Világos / sötét",
        "details": "Részletek",
        "raw_ref": "Eredeti rekord",
        "members": "Összevont események",
        "correlated_with": "Korrelált bejelentkezés",
        "fields": "Nyers mezők",
        "path": "Útvonal",
        "kind": "Típus",
        "size": "Méret (bájt)",
        "sha256": "SHA-256",
        "records": "Rekord",
        "errors": "Hiba",
        "ingested": "Betöltve",
        "options": "Beállítások",
        "correlated_note": (
            "A „korrelált (IP)” jelölésű sorokat csak a forrás-IP és az időablak köti a fiók "
            "egy bejelentkezéséhez; nem bizonyítják, hogy a kérést ugyanaz a személy küldte."
        ),
        "record_errors": "Fel nem dolgozható rekordok",
        "shown": "látható",
        "no_rows": "Nincs találat.",
    },
}

CATEGORY_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "ACCOUNT_LIFECYCLE": "Account lifecycle",
        "AUTHENTICATION": "Authentication",
        "PASSWORD": "Password",
        "LOCKOUT": "Lockout",
        "GROUP_MEMBERSHIP": "Group membership",
        "PRIVILEGE": "Privilege",
        "REMOTE_ACCESS": "Remote access",
        "EXECUTION": "Execution",
        "PERSISTENCE": "Persistence",
        "WEB": "Web",
        "LOG_TAMPERING": "Log tampering",
    },
    "hu": {
        "ACCOUNT_LIFECYCLE": "Fiók életciklusa",
        "AUTHENTICATION": "Hitelesítés",
        "PASSWORD": "Jelszó",
        "LOCKOUT": "Zárolás",
        "GROUP_MEMBERSHIP": "Csoporttagság",
        "PRIVILEGE": "Jogosultság",
        "REMOTE_ACCESS": "Távoli hozzáférés",
        "EXECUTION": "Futtatás",
        "PERSISTENCE": "Perzisztencia",
        "WEB": "Web",
        "LOG_TAMPERING": "Naplómanipuláció",
    },
}


def report_text(lang: str) -> dict[str, str]:
    return dict(REPORT_TEXT[_lang(lang)])


def category_text(category: str, lang: str) -> str:
    return CATEGORY_TEXT[_lang(lang)].get(category, category)


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
