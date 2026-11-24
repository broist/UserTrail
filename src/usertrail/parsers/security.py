"""A Security csatorna parsere."""

from __future__ import annotations

from collections.abc import Iterator

from usertrail.i18n import normalize_status
from usertrail.identity import clean, make_identity, parse_account, privileged_group
from usertrail.mappings.event_map import spec_for
from usertrail.models import Severity, TimelineEvent
from usertrail.parsers.base import Handler, build_event
from usertrail.parsers.evtx_reader import RawRecord

CHANNEL = "Security"
SOURCE = "Security"

# A Keywords mező auditbitjei.
_AUDIT_FAILURE = 0x0010000000000000
_AUDIT_SUCCESS = 0x0020000000000000

# A 4738-ban szereplő attribútummezők; a "-" érték (None) azt jelenti, hogy nem változott.
CHANGED_ATTRIBUTE_FIELDS = (
    "SamAccountName",
    "DisplayName",
    "UserPrincipalName",
    "HomeDirectory",
    "HomePath",
    "ScriptPath",
    "ProfilePath",
    "UserWorkstations",
    "PasswordLastSet",
    "AccountExpires",
    "PrimaryGroupId",
    "AllowedToDelegateTo",
    "UserAccountControl",
    "UserParameters",
    "SidHistory",
    "LogonHours",
)

# Csoportesemények hatóköre az Event ID alapján.
GROUP_SCOPES: dict[int, str] = {
    4728: "global",
    4729: "global",
    4732: "local",
    4733: "local",
    4756: "universal",
    4757: "universal",
}


def audit_result(keywords: str | None) -> str | None:
    """A Keywords mezőből ``success`` / ``failure``, vagy None, ha nem állapítható meg."""
    if not keywords:
        return None
    try:
        value = int(keywords, 16) if keywords.lower().startswith("0x") else int(keywords)
    except ValueError:
        return None
    if value & _AUDIT_FAILURE:
        return "failure"
    if value & _AUDIT_SUCCESS:
        return "success"
    return None


def _logon(record: RawRecord, event: TimelineEvent) -> None:
    """4624/4625: kódok normalizálása; IP hiányában a munkaállomás neve a forrás."""
    for key in ("Status", "SubStatus"):
        if key in event.details:
            event.details[key] = normalize_status(event.details[key])
            event.message_params[key] = event.details[key]
    if "LogonType" in event.details:
        try:
            event.details["LogonType"] = int(event.details["LogonType"])
            event.message_params["LogonType"] = event.details["LogonType"]
        except (TypeError, ValueError):
            pass
    if event.src_ip is None:
        event.message_params["src"] = clean(record.data.get("WorkstationName"))


def _account_changed(record: RawRecord, event: TimelineEvent) -> None:
    """4738: a ténylegesen változott attribútumok összegyűjtése."""
    data = record.data
    changed: list[str] = []
    for field_name in CHANGED_ATTRIBUTE_FIELDS:
        value = data.get(field_name)
        if value is not None:
            event.details[field_name] = value
            changed.append(field_name)
    old_uac, new_uac = data.get("OldUacValue"), data.get("NewUacValue")
    if old_uac is not None and new_uac is not None and old_uac != new_uac:
        event.details["OldUacValue"] = old_uac
        event.details["NewUacValue"] = new_uac
        if "UserAccountControl" not in changed:
            changed.append("UserAccountControl")
    event.details["ChangedAttributes"] = changed
    event.message_params["changed"] = ", ".join(changed) if changed else None


def _account_renamed(record: RawRecord, event: TimelineEvent) -> None:
    """4781: a régi név aliasként ugyanahhoz a SID-hez kötődik."""
    data = record.data
    old = make_identity(data.get("OldTargetUserName"), data.get("TargetDomainName"))
    if old is not None and event.target is not None:
        event.aliases = (make_identity(old.name, old.domain, event.target.sid) or old,)


def _password(record: RawRecord, event: TimelineEvent) -> None:
    """4723/4724: a sikeresség a Keywords auditbitjeiből derül ki."""
    result = audit_result(record.keywords)
    event.details["Result"] = result
    event.message_params["Result"] = result
    if result == "failure" and event.severity.rank < Severity.LOW.rank:
        event.severity = Severity.LOW


def _account_locked(record: RawRecord, event: TimelineEvent) -> None:
    """4740: a hibás próbálkozások forrásgépe a TargetDomainName mezőben érkezik."""
    caller = clean(record.data.get("CallerComputerName")) or clean(
        record.data.get("TargetDomainName")
    )
    event.details["CallerComputerName"] = caller
    event.message_params["CallerComputerName"] = caller


def _group_membership(record: RawRecord, event: TimelineEvent) -> None:
    """Csoporttagság: a tag a MemberSid, a csoport a Target* mezők, kiemelt csoport jelölése."""
    data = record.data
    member_sid = clean(data.get("MemberSid"))
    member_dn = clean(data.get("MemberName"))
    # A DN-ből kinyert CN megjelenítendő név, nem sAMAccountName, ezért csak akkor
    # használjuk identitásként, ha nincs SID.
    event.target = make_identity(sid=member_sid) if member_sid else make_identity(member_dn)
    member_cn = parse_account(member_dn)[0] if member_dn else None

    group_name = clean(data.get("TargetUserName"))
    group_domain = clean(data.get("TargetDomainName"))
    group_sid = clean(data.get("TargetSid"))
    privileged = privileged_group(group_sid)
    added = event.action == "group_member_added"

    event.details.update(
        {
            "GroupName": group_name,
            "GroupDomain": group_domain,
            "GroupSid": group_sid,
            "GroupScope": GROUP_SCOPES.get(record.event_id),
            "PrivilegedGroup": privileged,
        }
    )
    if privileged:
        event.severity = Severity.HIGH if added else Severity.MEDIUM
    event.message_params.update(
        {
            "member": member_cn or (event.target.display() if event.target else None),
            "group": f"{group_domain}\\{group_name}" if group_domain else group_name,
            "GroupScope": event.details["GroupScope"],
            "PrivilegedGroup": privileged,
        }
    )


HANDLERS: dict[int, Handler] = {
    4624: _logon,
    4625: _logon,
    4634: _logon,
    4723: _password,
    4724: _password,
    4738: _account_changed,
    4740: _account_locked,
    4781: _account_renamed,
    **dict.fromkeys(GROUP_SCOPES, _group_membership),
}


class SecurityParser:
    channels = frozenset({CHANNEL})

    def parse(self, record: RawRecord) -> Iterator[TimelineEvent]:
        spec = spec_for(CHANNEL, record.event_id)
        if spec is None:
            return
        event = build_event(record, spec, SOURCE)
        handler = HANDLERS.get(record.event_id)
        if handler is not None:
            handler(record, event)
        yield event
