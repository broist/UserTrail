"""Az idővonal összeállítása: a ``timeline`` és az ``export`` parancs közös motorja.

Bemenete egy :class:`TimelineRequest` (forrás, keresett identitás/IP, szűrők,
kapcsolók), kimenete egy :class:`TimelineResult`: a megjelenítendő sorok, a
figyelmeztetések, a feldolgozott forrásfájlok dokumentációja (hash-ekkel) és a
futtatás paraméterei, amelyek minden riportba bekerülnek.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any

from usertrail import __version__
from usertrail.alerts import Alert, AlertConfig, detect_alerts
from usertrail.correlate import (
    DEFAULT_COLLAPSE_GAP,
    DEFAULT_WINDOW,
    collapse_rows,
    correlate_web,
    pivot_seeds,
    seed_time_range,
)
from usertrail.identity import IdentityQuery, SidMap, resolve_sid_only_names
from usertrail.models import Category, Severity, TimelineEvent
from usertrail.parsers.evtx_reader import ReadStats
from usertrail.pipeline import discover_sources, iter_events
from usertrail.query import TimelineFilter, TimelineRow, select
from usertrail.store import CaseStore, sha256_file
from usertrail.timeutil import tz_label


class EngineError(Exception):
    """Az idővonal nem állítható össze (pl. nincs feldolgozható forrásfájl)."""


@dataclass(frozen=True, slots=True)
class TimelineRequest:
    user: str | None = None
    sid: str | None = None
    ip: str | None = None
    case: Path | None = None
    sources: tuple[Path, ...] = ()
    start: datetime | None = None
    end: datetime | None = None
    display_tz: tzinfo | None = None
    categories: frozenset[Category] | None = None
    min_severity: Severity = Severity.INFO
    include_machine_accounts: bool = False
    pivot_ip: bool = False
    pivot_window: timedelta = DEFAULT_WINDOW
    iis_tz: tzinfo | None = None
    collapse: bool = False
    collapse_gap: timedelta = DEFAULT_COLLAPSE_GAP
    alerts: bool = True
    alert_config: AlertConfig = field(default_factory=AlertConfig)

    @property
    def title(self) -> str:
        return " / ".join(x for x in (self.user, self.sid, self.ip) if x)

    def parameters(self) -> dict[str, Any]:
        """A futtatás paraméterei olvasható formában (a riportok fejlécébe)."""
        cfg = self.alert_config
        params: dict[str, Any] = {
            "user": self.user,
            "sid": self.sid,
            "ip": self.ip,
            "case": str(self.case) if self.case else None,
            "source": [str(p) for p in self.sources] or None,
            "from": self.start.isoformat() if self.start else None,
            "to": self.end.isoformat() if self.end else None,
            "tz": tz_label(self.display_tz, "en"),
            "category": sorted(c.value for c in self.categories) if self.categories else None,
            "min_severity": self.min_severity.value,
            "include_machine_accounts": self.include_machine_accounts,
            "pivot_ip": self.pivot_ip,
            "pivot_window_minutes": int(self.pivot_window.total_seconds() // 60),
            "collapse": self.collapse,
            "collapse_gap_minutes": int(self.collapse_gap.total_seconds() // 60),
            "alerts": self.alerts,
            "fail_threshold": cfg.fail_threshold,
            "fail_window_minutes": int(cfg.fail_window.total_seconds() // 60),
            "work_hours": f"{cfg.work_start:%H:%M}-{cfg.work_end:%H:%M}",
        }
        if self.iis_tz is not None:
            params["iis_tz"] = tz_label(self.iis_tz, "en")
        return {k: v for k, v in params.items() if v is not None}


@dataclass(frozen=True, slots=True)
class SourceSummary:
    """Egy feldolgozott forrásfájl dokumentációja (forensic nyilvántartás)."""

    path: str
    kind: str
    size: int
    sha256: str
    records: int
    errors: int
    ingested_at: str | None = None
    tool_version: str | None = None
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TimelineResult:
    request: TimelineRequest
    rows: list[TimelineRow]
    alerts: list[Alert]
    sources: list[SourceSummary]
    generated_at: datetime
    candidate_count: int = 0
    records_read: int | None = None
    correlated_count: int = 0
    error_count: int = 0
    error_samples: list[str] = field(default_factory=list)
    pivot_without_identity: bool = False
    tool_version: str = __version__

    @property
    def alerted_refs(self) -> frozenset[str]:
        return frozenset(ref for alert in self.alerts for ref in alert.refs)


def _seed_rows(
    events: list[TimelineEvent], req: TimelineRequest, identity: IdentityQuery
) -> list[TimelineRow]:
    """A pivotpontokhoz a felhasználó összes sikeres bejelentkezése kell, a kategória- és
    súlyosságszűrőtől függetlenül (az időszakszűrő viszont érvényes)."""
    return select(
        events,
        TimelineFilter(
            identity=identity, start=req.start, end=req.end, include_machine_accounts=True
        ),
    )


def _web_pool_from_store(
    store: CaseStore, events: list[TimelineEvent], req: TimelineRequest, identity: IdentityQuery
) -> list[TimelineEvent]:
    seeds = pivot_seeds(_seed_rows(events, req, identity))
    bounds = seed_time_range(seeds, req.pivot_window)
    if bounds is None:
        return []
    return store.events_from_ips(
        {s.ip for s in seeds}, start=bounds[0], end=bounds[1], source="IIS"
    )


def build_timeline(
    req: TimelineRequest, on_status: Callable[[str], None] | None = None
) -> TimelineResult:
    """Az idővonal összeállítása vizsgálati adatbázisból (``case``) vagy közvetlenül a
    forrásfájlokból (``sources``)."""
    if (req.case is None) == (not req.sources):
        raise EngineError("adj meg --case adatbázist vagy --source útvonalat (csak az egyiket)")
    if not (req.user or req.sid or req.ip):
        raise EngineError("adj meg --user, --sid vagy --ip kapcsolót")

    generated_at = datetime.now(UTC)
    web_pool: list[TimelineEvent] = []
    records_read: int | None = None
    error_count = 0
    error_samples: list[str] = []

    if req.case is not None:
        with CaseStore.open(req.case) as store:
            sid_map = store.sid_map()
            identity = (
                IdentityQuery.build(req.user, req.sid, sid_map) if (req.user or req.sid) else None
            )
            events = store.candidate_events(
                names=identity.names if identity else (),
                sids=identity.sids if identity else (),
                ip=req.ip,
                start=req.start,
                end=req.end,
            )
            if req.pivot_ip and identity is not None:
                web_pool = _web_pool_from_store(store, events, req, identity)
            sources = [
                SourceSummary(
                    path=s.path,
                    kind=s.kind,
                    size=s.size,
                    sha256=s.sha256,
                    records=s.records,
                    errors=s.errors,
                    ingested_at=s.ingested_at,
                    tool_version=s.tool_version,
                    options=s.options,
                )
                for s in store.sources()
            ]
    else:
        files = discover_sources(req.sources)
        if not files:
            raise EngineError("nem található támogatott naplófájl (.evtx vagy IIS .log)")
        events = []
        sources = []
        records_read = 0
        for source_file in files:
            if on_status:
                on_status(f"Beolvasás: {source_file.path.name}")
            digest = sha256_file(source_file.path)
            stats = ReadStats()
            events.extend(iter_events([source_file], stats, req.iis_tz))
            records_read += stats.records
            error_count += stats.errors
            error_samples.extend(stats.error_samples)
            options = (
                {"iis_tz": tz_label(req.iis_tz, "en")}
                if source_file.kind == "iis" and req.iis_tz
                else {}
            )
            sources.append(
                SourceSummary(
                    path=str(source_file.path),
                    kind=source_file.kind,
                    size=source_file.path.stat().st_size,
                    sha256=digest,
                    records=stats.records,
                    errors=stats.errors,
                    options=options,
                )
            )
        web_pool = events
        sid_map = SidMap()
        for event in events:
            sid_map.learn_event(event)
        identity = (
            IdentityQuery.build(req.user, req.sid, sid_map) if (req.user or req.sid) else None
        )

    for event in events:
        resolve_sid_only_names(event, sid_map)

    flt = TimelineFilter(
        identity=identity,
        ip=req.ip,
        start=req.start,
        end=req.end,
        categories=req.categories,
        min_severity=req.min_severity,
        include_machine_accounts=req.include_machine_accounts,
    )
    rows = select(events, flt)

    correlated: list[TimelineRow] = []
    pivot_without_identity = req.pivot_ip and identity is None
    if req.pivot_ip and identity is not None:
        seeds = pivot_seeds(_seed_rows(events, req, identity))
        web_filter = TimelineFilter(
            start=req.start, end=req.end, categories=req.categories, min_severity=req.min_severity
        )
        correlated = correlate_web(
            seeds, web_pool, web_filter, req.pivot_window, exclude=(r.event.raw_ref for r in rows)
        )
        rows = sorted(rows + correlated, key=lambda row: row.event.sort_key)

    alerts: list[Alert] = []
    if req.alerts:
        # A szabályok a keresett identitás (vagy IP) összes során futnak, a kategória- és
        # súlyosságszűrőtől függetlenül; csak az időszakszűrő érvényes.
        alert_filter = TimelineFilter(
            identity=identity,
            ip=req.ip,
            start=req.start,
            end=req.end,
            include_machine_accounts=req.include_machine_accounts,
        )
        alerts = detect_alerts(select(events, alert_filter), req.alert_config)

    if req.collapse:
        rows = collapse_rows(rows, req.collapse_gap)

    return TimelineResult(
        request=req,
        rows=rows,
        alerts=alerts,
        sources=sources,
        generated_at=generated_at,
        candidate_count=len(events),
        records_read=records_read,
        correlated_count=len(correlated),
        error_count=error_count,
        error_samples=error_samples,
        pivot_without_identity=pivot_without_identity,
    )
