"""Deklaratív leképezés: Event ID -> idővonal-esemény.

Egy új esemény támogatása általában egyetlen :class:`EventSpec` bejegyzés az alábbi
listában. Ha az eseményhez egyedi logika kell (átnevezett mezők, származtatott
súlyosság ...), a megfelelő parsermodulban egy kis kezelőfüggvényt is regisztrálni kell
(lásd ``parsers/security.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from usertrail.models import Category, Severity

# Csatornanevek, ahogy az ``Event.System.Channel`` mezőben szerepelnek.
SECURITY = "Security"
SYSTEM = "System"
RDP_LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RDP_RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"

# A ``TimelineEvent.source`` mezőbe kerülő rövid forrásnevek.
SOURCE_LABELS: dict[str, str] = {
    SECURITY: "Security",
    SYSTEM: "System",
    RDP_LSM: "RDP-LSM",
    RDP_RCM: "RDP-RCM",
    POWERSHELL: "PowerShell",
}

# (névmező, tartománymező, SID-mező); bármelyik elem lehet None.
IdentityFields: TypeAlias = tuple[str | None, str | None, str | None]
SUBJECT: IdentityFields = ("SubjectUserName", "SubjectDomainName", "SubjectUserSid")
TARGET: IdentityFields = ("TargetUserName", "TargetDomainName", "TargetUserSid")
# A fiókkezelési eseményekben (4720–4781) a célfiók SID-mezője TargetSid.
ACCOUNT: IdentityFields = ("TargetUserName", "TargetDomainName", "TargetSid")


@dataclass(frozen=True, slots=True)
class EventSpec:
    channel: str
    event_id: int
    action: str
    category: Category
    severity: Severity = Severity.INFO
    message_key: str | None = None  # alapértelmezés: az ``action`` értéke
    actor: IdentityFields | None = SUBJECT
    target: IdentityFields | None = TARGET
    ip_field: str | None = None
    # A ``details`` szótárba másolt mezők (az üzenetsablonokban is használhatók).
    detail_fields: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return self.message_key or self.action


_LOGON_FIELDS = (
    "LogonType",
    "IpAddress",
    "IpPort",
    "WorkstationName",
    "AuthenticationPackageName",
    "LogonProcessName",
    "TargetLogonId",
)

EVENT_SPECS: tuple[EventSpec, ...] = (
    # --- Security: hitelesítés ------------------------------------------------------
    EventSpec(
        "Security",
        4624,
        "logon_success",
        Category.AUTHENTICATION,
        actor=None,  # a Subject a bejelentkezést lebonyolító gép/SYSTEM
        ip_field="IpAddress",
        detail_fields=(*_LOGON_FIELDS, "ElevatedToken"),
    ),
    EventSpec(
        "Security",
        4625,
        "logon_failure",
        Category.AUTHENTICATION,
        Severity.LOW,
        actor=None,
        ip_field="IpAddress",
        detail_fields=(*_LOGON_FIELDS, "Status", "SubStatus", "FailureReason"),
    ),
    EventSpec(
        "Security",
        4634,
        "logoff",
        Category.AUTHENTICATION,
        actor=None,
        detail_fields=("LogonType", "TargetLogonId"),
    ),
    EventSpec(
        "Security",
        4647,
        "logoff",
        Category.AUTHENTICATION,
        message_key="logoff_user",
        actor=None,
        detail_fields=("TargetLogonId",),
    ),
    EventSpec(
        "Security",
        4648,
        "explicit_credentials",
        Category.AUTHENTICATION,
        Severity.LOW,
        target=("TargetUserName", "TargetDomainName", None),
        ip_field="IpAddress",
        detail_fields=("TargetServerName", "TargetInfo", "ProcessName", "IpAddress", "IpPort"),
    ),
    EventSpec(
        "Security",
        4672,
        "special_privileges",
        Category.PRIVILEGE,
        target=None,
        detail_fields=("PrivilegeList", "SubjectLogonId"),
    ),
    # --- Security: fiókok életciklusa ---------------------------------------------
    EventSpec(
        "Security",
        4720,
        "account_created",
        Category.ACCOUNT_LIFECYCLE,
        Severity.LOW,
        target=ACCOUNT,
        detail_fields=("SamAccountName", "DisplayName", "UserPrincipalName", "UserAccountControl"),
    ),
    EventSpec("Security", 4722, "account_enabled", Category.ACCOUNT_LIFECYCLE, target=ACCOUNT),
    EventSpec(
        "Security",
        4725,
        "account_disabled",
        Category.ACCOUNT_LIFECYCLE,
        Severity.LOW,
        target=ACCOUNT,
    ),
    EventSpec(
        "Security",
        4726,
        "account_deleted",
        Category.ACCOUNT_LIFECYCLE,
        Severity.MEDIUM,
        target=ACCOUNT,
    ),
    # A változott attribútumokat a 4738-as kezelőfüggvény gyűjti össze.
    EventSpec("Security", 4738, "account_changed", Category.ACCOUNT_LIFECYCLE, target=ACCOUNT),
    EventSpec(
        "Security",
        4781,
        "account_renamed",
        Category.ACCOUNT_LIFECYCLE,
        Severity.LOW,
        target=("NewTargetUserName", "TargetDomainName", "TargetSid"),
        detail_fields=("OldTargetUserName", "NewTargetUserName"),
    ),
    # --- Security: jelszó ------------------------------------------------------------
    EventSpec("Security", 4723, "password_change_attempt", Category.PASSWORD, target=ACCOUNT),
    EventSpec(
        "Security", 4724, "password_reset", Category.PASSWORD, Severity.MEDIUM, target=ACCOUNT
    ),
    # --- Security: zárolás -----------------------------------------------------------
    EventSpec(
        "Security",
        4740,
        "account_locked",
        Category.LOCKOUT,
        Severity.MEDIUM,
        actor=None,  # a Subject a zárolást végrehajtó tartományvezérlő gépfiókja
        # A 4740 TargetDomainName mezője valójában a hívó gép neve (Caller Computer Name).
        target=("TargetUserName", None, "TargetSid"),
    ),
    EventSpec("Security", 4767, "account_unlocked", Category.LOCKOUT, Severity.LOW, target=ACCOUNT),
    # --- Security: csoporttagság -----------------------------------------------------
    # A TargetUserName itt a csoport neve; a tagot a kezelőfüggvény állítja be a
    # MemberSid (és ha nincs, a MemberName DN) alapján.
    *(
        EventSpec(
            "Security",
            event_id,
            action,
            Category.GROUP_MEMBERSHIP,
            Severity.LOW,
            target=None,
            detail_fields=("MemberName", "MemberSid"),
        )
        for event_id, action in (
            (4728, "group_member_added"),
            (4729, "group_member_removed"),
            (4732, "group_member_added"),
            (4733, "group_member_removed"),
            (4756, "group_member_added"),
            (4757, "group_member_removed"),
        )
    ),
    # --- Security: Kerberos és NTLM ---------------------------------------------------
    # A sikertelen kéréseknél a kezelőfüggvény ``*_failure`` műveletre vált.
    EventSpec(
        "Security",
        4768,
        "kerberos_tgt",
        Category.AUTHENTICATION,
        actor=None,
        target=ACCOUNT,
        ip_field="IpAddress",
        detail_fields=(
            "Status",
            "ServiceName",
            "TicketOptions",
            "TicketEncryptionType",
            "PreAuthType",
            "IpAddress",
            "IpPort",
        ),
    ),
    EventSpec(
        "Security",
        4769,
        "kerberos_service_ticket",
        Category.AUTHENTICATION,
        actor=None,
        # A TargetUserName itt felhasznalo@REALM alakú.
        target=("TargetUserName", "TargetDomainName", None),
        ip_field="IpAddress",
        detail_fields=(
            "Status",
            "ServiceName",
            "ServiceSid",
            "TicketOptions",
            "TicketEncryptionType",
            "IpAddress",
            "IpPort",
        ),
    ),
    EventSpec(
        "Security",
        4771,
        "kerberos_preauth_failed",
        Category.AUTHENTICATION,
        Severity.LOW,
        actor=None,
        target=("TargetUserName", None, "TargetSid"),
        ip_field="IpAddress",
        detail_fields=(
            "Status",
            "FailureCode",
            "ServiceName",
            "PreAuthType",
            "IpAddress",
            "IpPort",
        ),
    ),
    EventSpec(
        "Security",
        4776,
        "ntlm_validation",
        Category.AUTHENTICATION,
        actor=None,
        target=("TargetUserName", None, None),
        detail_fields=("Workstation", "Status", "PackageName"),
    ),
    # --- Security: egyéb -------------------------------------------------------------
    EventSpec(
        "Security",
        1102,
        "audit_log_cleared",
        Category.LOG_TAMPERING,
        Severity.HIGH,
        target=None,
        detail_fields=("SubjectLogonId",),
    ),
    EventSpec(
        "Security",
        4688,
        "process_created",
        Category.EXECUTION,
        detail_fields=(
            "NewProcessName",
            "CommandLine",
            "ParentProcessName",
            "NewProcessId",
            "ProcessId",
            "TokenElevationType",
            "MandatoryLabel",
        ),
    ),
    EventSpec(
        "Security",
        4698,
        "scheduled_task_created",
        Category.PERSISTENCE,
        Severity.MEDIUM,
        target=None,
        detail_fields=("TaskName", "TaskContent"),
    ),
    # --- System ------------------------------------------------------------------------
    # A 7045 szereplője a System.Security UserID SID-je (a kezelőfüggvény állítja be).
    EventSpec(
        SYSTEM,
        7045,
        "service_installed",
        Category.PERSISTENCE,
        Severity.MEDIUM,
        actor=None,
        target=None,
        detail_fields=("ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"),
    ),
    EventSpec(
        SYSTEM,
        104,
        "log_cleared",
        Category.LOG_TAMPERING,
        Severity.HIGH,
        actor=("SubjectUserName", "SubjectDomainName", None),
        target=None,
        detail_fields=("Channel", "BackupPath"),
    ),
    # --- RDP: Local Session Manager ----------------------------------------------------
    *(
        EventSpec(
            RDP_LSM,
            event_id,
            action,
            Category.REMOTE_ACCESS,
            actor=None,
            target=("User", None, None),
            ip_field="Address",
            detail_fields=("SessionID", "Address"),
        )
        for event_id, action in (
            (21, "rdp_logon"),
            (23, "rdp_logoff"),
            (24, "rdp_disconnect"),
            (25, "rdp_reconnect"),
        )
    ),
    # --- RDP: Remote Connection Manager ------------------------------------------------
    EventSpec(
        RDP_RCM,
        1149,
        "rdp_auth_success",
        Category.REMOTE_ACCESS,
        actor=None,
        target=("Param1", "Param2", None),
        ip_field="Param3",
    ),
    # --- PowerShell ------------------------------------------------------------------
    # A szereplő a System.Security UserID SID-je; a darabokat a PowerShellParser fűzi össze.
    EventSpec(
        POWERSHELL,
        4104,
        "script_block",
        Category.EXECUTION,
        actor=None,
        target=None,
        detail_fields=("ScriptBlockId", "Path"),
    ),
)

EVENT_MAP: dict[tuple[str, int], EventSpec] = {(s.channel, s.event_id): s for s in EVENT_SPECS}


def spec_for(channel: str, event_id: int) -> EventSpec | None:
    return EVENT_MAP.get((channel, event_id))
