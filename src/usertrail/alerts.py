"""Figyelmeztetési szabályok az idővonal soraira.

A szabályok a keresett identitás (vagy IP) sorain futnak, a kategória- és
súlyosságszűrőtől függetlenül, hogy pl. egy jelszótalálgatás akkor is kiderüljön, ha a
megjelenítés csak egy kategóriára szűr. Minden figyelmeztetés hivatkozik az érintett
események ``raw_ref`` értékeire, így visszakereshető az eredeti rekordokig.

Szabályok:

* ``log_cleared`` – napló törlése (Security 1102, System 104)
* ``privileged_group_added`` – kiemelt csoportba vétel
* ``account_locked`` – fiókzárolás, az azt megelőző sikertelen próbálkozásokkal
* ``failed_logon_burst`` – sok sikertelen bejelentkezés rövid időn belül
* ``success_after_failures`` – sikeres bejelentkezés közvetlenül sok sikertelen után
* ``off_hours_logon`` – munkaidőn kívüli interaktív/RDP-bejelentkezés
* ``password_reset_new_ip`` – jelszó-visszaállítás után rövidesen bejelentkezés új IP-ről
* ``persistence_by_user`` – új szolgáltatás vagy ütemezett feladat a felhasználó nevében
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, tzinfo
from typing import Any

from usertrail.i18n import render
from usertrail.models import Identity, Role, Severity, TimelineEvent
from usertrail.netutil import is_external_ip
from usertrail.query import TimelineRow
from usertrail.timeutil import format_display, to_display

FAILURE_ACTIONS = frozenset(
    {
        "logon_failure",
        "kerberos_preauth_failed",
        "kerberos_tgt_failure",
        "ntlm_validation_failure",
    }
)
SUCCESS_ACTIONS = frozenset(
    {"logon_success", "kerberos_tgt", "ntlm_validation", "rdp_logon", "rdp_auth_success"}
)
# Interaktív jellegű bejelentkezések (munkaidőn kívüli figyelmeztetéshez): 4624 LogonType
# 2 interaktív, 7 feloldás, 10 RDP, 11–13 gyorsítótárazott; valamint az RDP-bejelentkezés.
INTERACTIVE_LOGON_TYPES = frozenset({2, 7, 10, 11, 12, 13})
PERSISTENCE_ACTIONS = frozenset({"service_installed", "scheduled_task_created"})
LOG_CLEAR_ACTIONS = frozenset({"audit_log_cleared", "log_cleared"})


@dataclass(frozen=True, slots=True)
class AlertConfig:
    fail_threshold: int = 10
    fail_window: timedelta = timedelta(minutes=5)
    # Ennyi, a sikeres bejelentkezést megelőző ``fail_window``-on belüli hiba után gyanús.
    success_after_failures: int = 5
    lockout_lookback: timedelta = timedelta(minutes=30)
    work_start: time = time(7, 0)
    work_end: time = time(19, 0)
    workdays: frozenset[int] = frozenset({0, 1, 2, 3, 4})  # hétfő–péntek
    reset_followup: timedelta = timedelta(hours=1)
    # A munkaidő ebben az időzónában értendő (None: a gép helyi ideje).
    tz: tzinfo | None = None


@dataclass(frozen=True, slots=True)
class Alert:
    rule: str
    severity: Severity
    timestamp_utc: datetime
    raw_ref: str  # az elsődleges esemény
    related: tuple[str, ...] = ()  # további érintett események
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def refs(self) -> frozenset[str]:
        return frozenset((self.raw_ref, *self.related))

    def description(self, lang: str = "hu") -> str:
        return render(f"alert.{self.rule}", self.params, lang)


def _account(identity: Identity | None) -> str | None:
    if identity is None:
        return None
    return identity.sid_key or identity.name_key


def _account_key(event: TimelineEvent) -> str | None:
    """Annak a fióknak a kulcsa, akire a hitelesítési esemény vonatkozik."""
    return _account(event.target) or _account(event.actor)


def _display(event: TimelineEvent) -> str:
    identity = event.target or event.actor
    return identity.display() if identity else "-"


def _by_account(events: Iterable[TimelineEvent]) -> dict[str, list[TimelineEvent]]:
    grouped: dict[str, list[TimelineEvent]] = defaultdict(list)
    for event in events:
        key = _account_key(event)
        if key is not None:
            grouped[key].append(event)
    for items in grouped.values():
        items.sort(key=lambda e: e.sort_key)
    return grouped


def _count_in_window(
    failures: Sequence[TimelineEvent], end: datetime, window: timedelta
) -> list[TimelineEvent]:
    return [f for f in failures if end - window <= f.timestamp_utc < end]


def _log_cleared(rows: Sequence[TimelineRow], _cfg: AlertConfig) -> list[Alert]:
    return [
        Alert(
            "log_cleared",
            Severity.HIGH,
            r.event.timestamp_utc,
            r.event.raw_ref,
            params={
                "actor": r.event.message_params.get("actor"),
                "channel": r.event.details.get("Channel", "Security"),
                "host": r.event.host,
            },
        )
        for r in rows
        if r.event.action in LOG_CLEAR_ACTIONS
    ]


def _privileged_group(rows: Sequence[TimelineRow], _cfg: AlertConfig) -> list[Alert]:
    return [
        Alert(
            "privileged_group_added",
            Severity.HIGH,
            r.event.timestamp_utc,
            r.event.raw_ref,
            params={
                "member": r.event.message_params.get("member"),
                "group": r.event.message_params.get("group"),
                "actor": r.event.message_params.get("actor"),
            },
        )
        for r in rows
        if r.event.action == "group_member_added" and r.event.details.get("PrivilegedGroup")
    ]


def _lockouts(rows: Sequence[TimelineRow], cfg: AlertConfig) -> list[Alert]:
    failures = _by_account(r.event for r in rows if r.event.action in FAILURE_ACTIONS)
    alerts = []
    for row in rows:
        event = row.event
        if event.action != "account_locked":
            continue
        before = _count_in_window(
            failures.get(_account_key(event) or "", []),
            event.timestamp_utc,
            cfg.lockout_lookback,
        )
        sources = sorted({f.src_ip or f.details.get("Workstation") or "-" for f in before})
        alerts.append(
            Alert(
                "account_locked",
                Severity.MEDIUM,
                event.timestamp_utc,
                event.raw_ref,
                related=tuple(f.raw_ref for f in before),
                params={
                    "account": _display(event),
                    "caller": event.details.get("CallerComputerName"),
                    "count": len(before),
                    "minutes": int(cfg.lockout_lookback.total_seconds() // 60),
                    "sources": ", ".join(sources) or "-",
                },
            )
        )
    return alerts


def _failure_bursts(rows: Sequence[TimelineRow], cfg: AlertConfig) -> list[Alert]:
    """Egy sorozat = egymást ``fail_window``-on belül követő hibák; a küszöb felett egy
    figyelmeztetés a teljes sorozatra."""
    alerts = []
    failures = _by_account(r.event for r in rows if r.event.action in FAILURE_ACTIONS)
    for items in failures.values():
        burst: list[TimelineEvent] = []
        for event in [*items, None]:
            if event is not None and (
                not burst or event.timestamp_utc - burst[-1].timestamp_utc <= cfg.fail_window
            ):
                burst.append(event)
                continue
            if _is_dense(burst, cfg):
                first, last = burst[0], burst[-1]
                sources = sorted({f.src_ip or f.details.get("Workstation") or "-" for f in burst})
                alerts.append(
                    Alert(
                        "failed_logon_burst",
                        Severity.MEDIUM,
                        first.timestamp_utc,
                        first.raw_ref,
                        related=tuple(f.raw_ref for f in burst[1:]),
                        params={
                            "account": _display(first),
                            "count": len(burst),
                            "first": format_display(first.timestamp_utc, cfg.tz),
                            "last": format_display(last.timestamp_utc, cfg.tz),
                            "sources": ", ".join(sources),
                        },
                    )
                )
            burst = [event] if event is not None else []
    return alerts


def _is_dense(burst: Sequence[TimelineEvent], cfg: AlertConfig) -> bool:
    """Van-e a sorozatban legalább ``fail_threshold`` hiba egy ``fail_window`` hosszú ablakban."""
    if len(burst) < cfg.fail_threshold:
        return False
    times = [e.timestamp_utc for e in burst]
    start = 0
    for end, moment in enumerate(times):
        while moment - times[start] > cfg.fail_window:
            start += 1
        if end - start + 1 >= cfg.fail_threshold:
            return True
    return False


def _success_after_failures(rows: Sequence[TimelineRow], cfg: AlertConfig) -> list[Alert]:
    failures = _by_account(r.event for r in rows if r.event.action in FAILURE_ACTIONS)
    alerts = []
    flagged: set[str] = set()
    for row in sorted(rows, key=lambda r: r.event.sort_key):
        event = row.event
        if event.action not in SUCCESS_ACTIONS:
            continue
        key = _account_key(event) or ""
        before = [
            f
            for f in _count_in_window(failures.get(key, []), event.timestamp_utc, cfg.fail_window)
            if f.raw_ref not in flagged
        ]
        if len(before) < cfg.success_after_failures:
            continue
        # Ugyanazokat a hibákat csak egy sikeres bejelentkezéshez kötjük.
        flagged.update(f.raw_ref for f in before)
        alerts.append(
            Alert(
                "success_after_failures",
                Severity.HIGH,
                event.timestamp_utc,
                event.raw_ref,
                related=tuple(f.raw_ref for f in before),
                params={
                    "account": _display(event),
                    "count": len(before),
                    "minutes": int(cfg.fail_window.total_seconds() // 60),
                    "src": event.src_ip or "-",
                },
            )
        )
    return alerts


def _is_interactive_logon(event: TimelineEvent) -> bool:
    if event.action == "rdp_logon":
        return True
    if event.action != "logon_success":
        return False
    try:
        return int(event.details.get("LogonType", -1)) in INTERACTIVE_LOGON_TYPES
    except (TypeError, ValueError):
        return False


def _off_hours(rows: Sequence[TimelineRow], cfg: AlertConfig) -> list[Alert]:
    alerts = []
    for row in rows:
        event = row.event
        if not _is_interactive_logon(event):
            continue
        local = to_display(event.timestamp_utc, cfg.tz)
        in_hours = local.weekday() in cfg.workdays and cfg.work_start <= local.time() < cfg.work_end
        if in_hours:
            continue
        alerts.append(
            Alert(
                "off_hours_logon",
                Severity.LOW,
                event.timestamp_utc,
                event.raw_ref,
                params={
                    "account": _display(event),
                    "local_time": format_display(event.timestamp_utc, cfg.tz),
                    "src": event.src_ip or "-",
                    "work_start": cfg.work_start.strftime("%H:%M"),
                    "work_end": cfg.work_end.strftime("%H:%M"),
                },
            )
        )
    return alerts


def _reset_then_new_ip(rows: Sequence[TimelineRow], cfg: AlertConfig) -> list[Alert]:
    ordered = sorted(rows, key=lambda r: r.event.sort_key)
    successes = _by_account(
        r.event
        for r in ordered
        if r.event.action in SUCCESS_ACTIONS and is_external_ip(r.event.src_ip)
    )
    alerts = []
    for row in ordered:
        reset = row.event
        if reset.action != "password_reset" or reset.details.get("Result") == "failure":
            continue
        logons = successes.get(_account_key(reset) or "", [])
        known = {e.src_ip for e in logons if e.timestamp_utc < reset.timestamp_utc}
        for logon in logons:
            delta = logon.timestamp_utc - reset.timestamp_utc
            if delta < timedelta(0) or delta > cfg.reset_followup:
                continue
            if logon.src_ip in known:
                continue
            alerts.append(
                Alert(
                    "password_reset_new_ip",
                    Severity.MEDIUM,
                    logon.timestamp_utc,
                    logon.raw_ref,
                    related=(reset.raw_ref,),
                    params={
                        "account": _display(reset),
                        "actor": reset.message_params.get("actor"),
                        "src": logon.src_ip,
                        "minutes": max(int(delta.total_seconds() // 60), 0),
                    },
                )
            )
            break
    return alerts


def _persistence(rows: Sequence[TimelineRow], _cfg: AlertConfig) -> list[Alert]:
    alerts = []
    for row in rows:
        event = row.event
        if event.action not in PERSISTENCE_ACTIONS or row.role not in (Role.ACTOR, Role.BOTH):
            continue
        alerts.append(
            Alert(
                "persistence_by_user",
                Severity.MEDIUM,
                event.timestamp_utc,
                event.raw_ref,
                params={
                    "actor": event.message_params.get("actor"),
                    "kind": event.action,
                    "name": event.details.get("ServiceName") or event.details.get("TaskName"),
                    "host": event.host,
                },
            )
        )
    return alerts


RULES = (
    _log_cleared,
    _privileged_group,
    _lockouts,
    _failure_bursts,
    _success_after_failures,
    _off_hours,
    _reset_then_new_ip,
    _persistence,
)


def detect_alerts(rows: Sequence[TimelineRow], cfg: AlertConfig | None = None) -> list[Alert]:
    """Az összes szabály lefuttatása; az eredmény idő szerint rendezve."""
    cfg = cfg or AlertConfig()
    alerts = [alert for rule in RULES for alert in rule(rows, cfg)]
    alerts.sort(key=lambda a: (a.timestamp_utc, a.rule, a.raw_ref))
    return alerts


def alert_refs(alerts: Iterable[Alert]) -> frozenset[str]:
    """Az összes figyelmeztetésben érintett esemény ``raw_ref`` értéke."""
    refs: set[str] = set()
    for alert in alerts:
        refs |= alert.refs
    return frozenset(refs)
