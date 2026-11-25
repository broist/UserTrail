"""Forrásállapot-ellenőrzés: milyen naplók és események állnak rendelkezésre, és mi hiányzik.

Az eszköz csak abból tud dolgozni, ami a naplókban benne van. Ha egy auditálási beállítás
nincs bekapcsolva, vagy egy napló túl rövid időszakot fed le (felülíródott), akkor a
hiányzó események nem „nem történtek meg”, hanem „nem látszanak”. Ez a modul ezeket a
hiányokat jelzi, hogy a vizsgáló ne vonjon le téves következtetést.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo
from typing import Any

from usertrail.i18n import render
from usertrail.mappings.event_map import SOURCE_LABELS
from usertrail.store import CaseStore
from usertrail.timeutil import format_display

SECURITY = "Security"
IIS = "IIS"
DEFAULT_MIN_DAYS = 7

# A várt források és a hiányukkor jelzett szint. A Security a fő forrás.
EXPECTED_SOURCES: tuple[str, ...] = (
    "Security",
    "System",
    "RDP-LSM",
    "RDP-RCM",
    "PowerShell",
    "IIS",
)

ACCOUNT_MANAGEMENT_IDS = (
    "4720", "4722", "4723", "4724", "4725", "4726", "4738", "4740", "4767", "4781",
    "4728", "4729", "4732", "4733", "4756", "4757",
)  # fmt: skip
KERBEROS_IDS = ("4768", "4769", "4771")
LOG_CLEAR = (("Security", "1102"), ("System", "104"))


class Level(enum.StrEnum):
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class Finding:
    level: Level
    code: str
    params: dict[str, Any] = field(default_factory=dict)

    def text(self, lang: str = "hu") -> str:
        return render(f"health.{self.code}", self.params, lang)


@dataclass(frozen=True, slots=True)
class ChannelSummary:
    """Egy csatorna (forrás) összesítése a vizsgálatban."""

    source: str  # a forrás rövid neve, pl. "Security", "RDP-LSM", "IIS"
    channel: str  # az eredeti csatornanév (IIS-nél "IIS")
    files: int
    records: int | None  # az összes beolvasott rekord (régi adatbázisnál ismeretlen)
    events: int  # ebből leképezett idővonal-esemény
    first: datetime | None
    last: datetime | None

    @property
    def span(self) -> timedelta | None:
        if self.first is None or self.last is None:
            return None
        return self.last - self.first


def _label(channel: str) -> str:
    return SOURCE_LABELS.get(channel, channel)


def summarize(store: CaseStore) -> list[ChannelSummary]:
    """Csatornánkénti összesítés a betöltéskor rögzített lefedettségből; régebbi
    adatbázisnál (lefedettség nélkül) a leképezett események időtartományából."""
    sources = [s for s in store.sources() if s.completed]
    counts = store.event_counts()
    events_by_source: dict[str, int] = {}
    for (source, _event_id), n in counts.items():
        events_by_source[source] = events_by_source.get(source, 0) + n

    per_channel: dict[str, dict[str, Any]] = {}
    for info in sources:
        for channel, cov in info.coverage.items():
            item = per_channel.setdefault(
                channel, {"files": 0, "records": 0, "first": None, "last": None}
            )
            item["files"] += 1
            item["records"] += int(cov.get("records", 0))
            first = datetime.fromisoformat(cov["first"])
            last = datetime.fromisoformat(cov["last"])
            item["first"] = first if item["first"] is None else min(item["first"], first)
            item["last"] = last if item["last"] is None else max(item["last"], last)

    summaries: dict[str, ChannelSummary] = {}
    for channel, item in per_channel.items():
        label = _label(channel)
        summaries[label] = ChannelSummary(
            source=label,
            channel=channel,
            files=item["files"],
            records=item["records"],
            events=events_by_source.get(label, 0),
            first=item["first"],
            last=item["last"],
        )
    # Régebbi (lefedettség nélküli) betöltések: becslés az eseményekből.
    for label, (first, last) in store.event_time_ranges().items():
        if label not in summaries:
            summaries[label] = ChannelSummary(
                source=label,
                channel=label,
                files=0,
                records=None,
                events=events_by_source.get(label, 0),
                first=first,
                last=last,
            )
    order = {name: i for i, name in enumerate(EXPECTED_SOURCES)}
    return sorted(summaries.values(), key=lambda s: (order.get(s.source, 99), s.source))


def _has(counts: dict[tuple[str, str], int], source: str, ids: Iterable[str]) -> int:
    return sum(counts.get((source, event_id), 0) for event_id in ids)


def check(
    store: CaseStore,
    summaries: list[ChannelSummary] | None = None,
    min_days: int = DEFAULT_MIN_DAYS,
    tz: tzinfo | None = None,
) -> list[Finding]:
    """A hiányosságok és figyelmeztető jelek listája; először a figyelmeztetések."""
    summaries = summaries if summaries is not None else summarize(store)
    sources = store.sources()
    counts = store.event_counts()
    present = {s.source for s in summaries}
    findings: list[Finding] = []

    if not sources:
        return [Finding(Level.WARNING, "no_sources")]

    incomplete = [s for s in sources if not s.completed]
    if incomplete:
        findings.append(Finding(Level.WARNING, "incomplete_sources", {"count": len(incomplete)}))
    errors = sum(s.errors for s in sources)
    if errors:
        findings.append(Finding(Level.WARNING, "record_errors", {"count": errors}))

    for source in EXPECTED_SOURCES:
        if source not in present:
            level = Level.WARNING if source == SECURITY else Level.INFO
            findings.append(Finding(level, f"missing.{source}"))

    if SECURITY in present:
        if not _has(counts, SECURITY, ("4624",)):
            findings.append(Finding(Level.WARNING, "no_logon"))
        if not _has(counts, SECURITY, ("4625",)):
            findings.append(Finding(Level.INFO, "no_logon_failure"))
        if not _has(counts, SECURITY, ("4688",)):
            findings.append(Finding(Level.INFO, "no_process_creation"))
        elif store.count_without_detail(SECURITY, "4688", "CommandLine") == _has(
            counts, SECURITY, ("4688",)
        ):
            findings.append(Finding(Level.INFO, "no_command_line"))
        if not _has(counts, SECURITY, KERBEROS_IDS):
            findings.append(Finding(Level.INFO, "no_kerberos"))
        if not _has(counts, SECURITY, ACCOUNT_MANAGEMENT_IDS):
            findings.append(Finding(Level.INFO, "no_account_management"))
        if not _has(counts, SECURITY, ("4698",)):
            findings.append(Finding(Level.INFO, "no_scheduled_task"))

        security = next(s for s in summaries if s.source == SECURITY)
        span = security.span
        if span is not None and span < timedelta(days=min_days):
            findings.append(
                Finding(
                    Level.WARNING,
                    "short_coverage",
                    {
                        "days": f"{span.total_seconds() / 86400:.1f}",
                        "min_days": min_days,
                        "first": _fmt(security.first, tz),
                        "last": _fmt(security.last, tz),
                    },
                )
            )

    if "PowerShell" in present and not _has(counts, "PowerShell", ("4104",)):
        findings.append(Finding(Level.WARNING, "no_script_block"))

    for source, event_id in LOG_CLEAR:
        n = counts.get((source, event_id), 0)
        if n:
            findings.append(
                Finding(
                    Level.WARNING,
                    "log_cleared",
                    {
                        "count": n,
                        "source": source,
                        "event_id": event_id,
                        "first": _fmt(store.first_event_time(source, [event_id]), tz),
                    },
                )
            )

    findings.sort(key=lambda f: 0 if f.level is Level.WARNING else 1)
    return findings


def _fmt(value: datetime | None, tz: tzinfo | None) -> str | None:
    return format_display(value, tz) if value is not None else None
