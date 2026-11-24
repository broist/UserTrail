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
)

EVENT_MAP: dict[tuple[str, int], EventSpec] = {(s.channel, s.event_id): s for s in EVENT_SPECS}


def spec_for(channel: str, event_id: int) -> EventSpec | None:
    return EVENT_MAP.get((channel, event_id))
