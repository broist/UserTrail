"""Önálló (self-contained) HTML-riport jinja2-sablonból.

A riport egyetlen fájl: a CSS és a JavaScript a sablonba ágyazott, külső hivatkozás
nincs, így hálózat nélkül, bizonyítékként átadva is ugyanúgy jelenik meg.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from usertrail.engine import TimelineResult
from usertrail.i18n import category_text, report_text, ui
from usertrail.models import Category, Severity
from usertrail.report.export import _alerts_by_ref, alert_record, metadata, row_record

TEMPLATE_NAME = "report.html.j2"

_environment: Environment | None = None


def _env() -> Environment:
    global _environment
    if _environment is None:
        _environment = Environment(
            loader=PackageLoader("usertrail", "report/templates"),
            autoescape=select_autoescape(["html", "j2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
    return _environment


def _period(records: list[dict[str, Any]]) -> tuple[str, str] | None:
    if not records:
        return None
    first = min(records, key=lambda r: r["timestamp_utc"])
    last = max(records, key=lambda r: r.get("last_timestamp_utc") or r["timestamp_utc"])
    return first["timestamp"], last.get("last_timestamp") or last["timestamp"]


def render_html(result: TimelineResult, lang: str) -> str:
    index = _alerts_by_ref(result.alerts)
    records = [row_record(row, result, lang, index) for row in result.rows]
    for record in records:
        record["category_text"] = category_text(record["category"], lang)
        record["severity_text"] = ui(f"severity.{record['severity']}", lang)
        record["details_json"] = json.dumps(
            record["details"], ensure_ascii=False, indent=2, default=str, sort_keys=True
        )

    by_category: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    for record in records:
        by_category[record["category"]] += record["count"]
        by_severity[record["severity"]] += record["count"]
    total = sum(by_category.values())

    meta = metadata(result, lang)
    context = {
        "lang": lang,
        "t": report_text(lang),
        "meta": meta,
        "parameters_json": json.dumps(meta["parameters"], ensure_ascii=False, indent=2),
        "records": records,
        "alerts": [alert_record(a, result, lang) for a in result.alerts],
        "sources": meta["sources"],
        "period": _period(records),
        "total_events": total,
        "categories": [
            {
                "key": c.value,
                "text": category_text(c.value, lang),
                "count": by_category.get(c.value, 0),
                "percent": round(100 * by_category.get(c.value, 0) / total) if total else 0,
            }
            for c in Category
            if by_category.get(c.value)
        ],
        "severities": [
            {
                "key": s.value,
                "rank": s.rank,
                "text": ui(f"severity.{s.value}", lang),
                "count": by_severity.get(s.value, 0),
            }
            for s in Severity
        ],
        "all_categories": [
            {"key": c.value, "text": category_text(c.value, lang)} for c in Category
        ],
        "roles": [
            {"key": key, "text": ui(f"role.{key}", lang)}
            for key in ("actor", "target", "both", "related", "correlated")
        ],
        "has_correlated": any(r["role"] == "correlated" for r in records),
        "error_count": result.error_count,
        "error_samples": result.error_samples,
        "col": {
            key: ui(f"col.{key}", lang)
            for key in (
                "time",
                "source",
                "host",
                "event",
                "role",
                "ip",
                "description",
                "severity",
                "rule",
            )
        },
    }
    return _env().get_template(TEMPLATE_NAME).render(**context)
