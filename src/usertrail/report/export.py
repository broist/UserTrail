"""Fájlkimenetek: CSV (UTF-8 BOM), JSON Lines és önálló HTML-riport.

Mindhárom formátum ugyanabból a sorleírásból (:func:`row_record`) dolgozik, és mindegyik
tartalmazza az eszköz verzióját, a futtatás paramétereit, a megjelenítési időzónát és a
feldolgozott forrásfájlok SHA-256 hash-ét (a CSV-nél egy mellé írt ``.meta.json``
fájlban, hogy maga a CSV Timeline Explorerrel és Excellel is tisztán nyitható legyen).
"""

from __future__ import annotations

import csv
import enum
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from usertrail.alerts import Alert
from usertrail.engine import TimelineResult
from usertrail.i18n import ui
from usertrail.models import Identity, TimelineEvent
from usertrail.query import TimelineRow
from usertrail.report.text import row_description
from usertrail.timeutil import format_display, tz_label

TOOL_NAME = "UserTrail"

# A CSV oszlopnevei angolok maradnak: ezeket gépi eszközök (pl. Timeline Explorer)
# dolgozzák fel; az emberi szövegek (leírás, szerep, figyelmeztetés) a --lang szerintiek.
CSV_COLUMNS = (
    "Timestamp",
    "TimestampUTC",
    "TimeZone",
    "Source",
    "Host",
    "EventID",
    "Category",
    "Action",
    "Severity",
    "Role",
    "Actor",
    "ActorSID",
    "Target",
    "TargetSID",
    "SourceIP",
    "Description",
    "Alerts",
    "Count",
    "CorrelatedWith",
    "RawRef",
    "Details",
)


class ExportFormat(enum.StrEnum):
    csv = "csv"
    json = "json"
    html = "html"


def _identity_name(event: TimelineEvent, key: str, identity: Identity | None) -> str | None:
    """A megjelenített név; csak SID-del azonosított fióknál a SID-térképből feloldott név
    (a ``resolve_sid_only_names`` a leírás paramétereibe teszi), a tárolt identitás változatlan."""
    if identity is None:
        return None
    if identity.name is None:
        resolved = event.message_params.get(key)
        if not resolved and key == "target":
            # Csoporteseményeknél a tag neve a "member" paraméterben van.
            resolved = event.message_params.get("member")
        if isinstance(resolved, str) and resolved:
            return resolved
    return identity.display()


def _alerts_by_ref(alerts: list[Alert]) -> dict[str, list[Alert]]:
    index: dict[str, list[Alert]] = {}
    for alert in alerts:
        for ref in alert.refs:
            index.setdefault(ref, []).append(alert)
    return index


def row_record(
    row: TimelineRow,
    result: TimelineResult,
    lang: str,
    alert_index: dict[str, list[Alert]],
) -> dict[str, Any]:
    """Egy idővonal-sor formátumfüggetlen leírása."""
    tz = result.request.display_tz
    ev = row.event
    row_alerts: dict[str, Alert] = {}
    for ref in row.raw_refs:
        for alert in alert_index.get(ref, ()):
            row_alerts.setdefault(f"{alert.rule}|{alert.raw_ref}", alert)
    record: dict[str, Any] = {
        "timestamp": format_display(ev.timestamp_utc, tz),
        "timestamp_utc": ev.timestamp_utc.isoformat(),
        "source": ev.source,
        "host": ev.host,
        "event_id": ev.event_id,
        "category": ev.category.value,
        "action": ev.action,
        "severity": ev.severity.value,
        "severity_rank": ev.severity.rank,
        "role": row.role.value,
        "role_text": ui(f"role.{row.role.value}", lang),
        "actor": _identity_name(ev, "actor", ev.actor),
        "actor_sid": ev.actor.sid if ev.actor else None,
        "target": _identity_name(ev, "target", ev.target),
        "target_sid": ev.target.sid if ev.target else None,
        "src_ip": ev.src_ip,
        "description": row_description(row, tz, lang),
        "alerts": [ui(f"rule.{a.rule}", lang) for a in row_alerts.values()],
        "count": len(row.members) if row.is_collapsed else 1,
        "correlated_with": row.correlated_with,
        "raw_refs": list(row.raw_refs),
        "details": ev.details,
    }
    if row.is_collapsed:
        record["last_timestamp"] = format_display(row.members[-1].timestamp_utc, tz)
        record["last_timestamp_utc"] = row.members[-1].timestamp_utc.isoformat()
    return record


def alert_record(alert: Alert, result: TimelineResult, lang: str) -> dict[str, Any]:
    return {
        "timestamp": format_display(alert.timestamp_utc, result.request.display_tz),
        "timestamp_utc": alert.timestamp_utc.isoformat(),
        "rule": alert.rule,
        "rule_text": ui(f"rule.{alert.rule}", lang),
        "severity": alert.severity.value,
        "severity_text": ui(f"severity.{alert.severity.value}", lang),
        "description": alert.description(lang),
        "raw_refs": sorted(alert.refs),
    }


def metadata(result: TimelineResult, lang: str) -> dict[str, Any]:
    """Az eszköz és a futtatás adatai, valamint a forrásfájlok nyilvántartása."""
    rows = result.rows
    return {
        "tool": TOOL_NAME,
        "version": result.tool_version,
        "generated_at_utc": result.generated_at.isoformat(),
        "time_zone": tz_label(result.request.display_tz, lang),
        "title": result.request.title,
        "parameters": result.request.parameters(),
        "counts": {
            "rows": len(rows),
            "events": sum(len(r.members) if r.is_collapsed else 1 for r in rows),
            "alerts": len(result.alerts),
            "correlated": result.correlated_count,
            "record_errors": result.error_count,
        },
        "sources": [asdict(s) for s in result.sources],
    }


def write_csv(result: TimelineResult, output: Path, lang: str) -> list[Path]:
    index = _alerts_by_ref(result.alerts)
    tz_text = tz_label(result.request.display_tz, lang)
    # utf-8-sig: BOM az elején, hogy az Excel UTF-8-ként nyissa (ékezetek).
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for row in result.rows:
            rec = row_record(row, result, lang, index)
            writer.writerow(
                [
                    rec["timestamp"],
                    rec["timestamp_utc"],
                    tz_text,
                    rec["source"],
                    rec["host"],
                    rec["event_id"],
                    rec["category"],
                    rec["action"],
                    rec["severity"],
                    rec["role_text"],
                    rec["actor"] or "",
                    rec["actor_sid"] or "",
                    rec["target"] or "",
                    rec["target_sid"] or "",
                    rec["src_ip"] or "",
                    rec["description"],
                    "; ".join(rec["alerts"]),
                    rec["count"],
                    rec["correlated_with"] or "",
                    "; ".join(rec["raw_refs"]),
                    json.dumps(rec["details"], ensure_ascii=False, default=str, sort_keys=True),
                ]
            )
    meta_path = output.with_name(output.stem + ".meta.json")
    meta = metadata(result, lang)
    meta["alerts"] = [alert_record(a, result, lang) for a in result.alerts]
    meta_path.write_text(
        json.dumps(meta, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8"
    )
    return [output, meta_path]


def write_jsonl(result: TimelineResult, output: Path, lang: str) -> list[Path]:
    """JSON Lines: az első sor a metaadat, majd a figyelmeztetések, végül az események."""
    index = _alerts_by_ref(result.alerts)
    with output.open("w", encoding="utf-8", newline="\n") as handle:

        def emit(kind: str, payload: dict[str, Any]) -> None:
            line = json.dumps({"type": kind, **payload}, ensure_ascii=False, default=str)
            handle.write(line + "\n")

        emit("meta", metadata(result, lang))
        for alert in result.alerts:
            emit("alert", alert_record(alert, result, lang))
        for row in result.rows:
            emit("event", row_record(row, result, lang, index))
    return [output]


def write_html(result: TimelineResult, output: Path, lang: str) -> list[Path]:
    from usertrail.report.html_report import render_html

    output.write_text(render_html(result, lang), encoding="utf-8")
    return [output]


def write_export(result: TimelineResult, fmt: ExportFormat, output: Path, lang: str) -> list[Path]:
    """A kért formátum megírása; a létrehozott fájlok listáját adja vissza."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt is ExportFormat.csv:
        return write_csv(result, output, lang)
    if fmt is ExportFormat.json:
        return write_jsonl(result, output, lang)
    return write_html(result, output, lang)


def category_counts(result: TimelineResult) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in result.rows:
        counts[row.event.category.value] += len(row.members) if row.is_collapsed else 1
    return counts
