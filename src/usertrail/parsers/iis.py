"""IIS W3C-naplók streamelt feldolgozása.

A mezősorrendet mindig a ``#Fields:`` direktíva adja meg; egy fájlon belül több ilyen sor
is lehet (pl. a szolgáltatás újraindítása után), ilyenkor onnantól az új sorrend érvényes.
A ``-`` érték üres mezőt jelent. Az időbélyeg alapértelmezésben UTC; ha a szerveren helyi
időre állították a naplózást, a ``tz`` paraméterrel adható meg a zóna.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any

from usertrail.identity import make_identity
from usertrail.models import Category, Severity, TimelineEvent
from usertrail.netutil import normalize_ip
from usertrail.parsers.evtx_reader import ReadStats

SOURCE = "IIS"
EVENT_ID = "IIS"
LOG_SUFFIX = ".log"
_SNIFF_BYTES = 4096
_IIS_MARKERS = ("#Fields:", "#Software: Microsoft Internet Information Services")
# A leírásba kerülő URI legfeljebb ilyen hosszú; a teljes érték a details-ben marad.
MAX_URI_IN_MESSAGE = 200
# Ezeknél a státuszkódoknál a kérés hitelesítési/jogosultsági hibát jelez.
_AUTH_FAILURE_STATUSES = {"401", "403"}


def is_iis_log(path: Path) -> bool:
    """Igaz, ha a fájl ``.log`` kiterjesztésű és az eleje W3C/IIS-fejlécet tartalmaz."""
    if path.suffix.lower() != LOG_SUFFIX:
        return False
    try:
        with path.open("rb") as handle:
            head = handle.read(_SNIFF_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return False
    return any(marker in head for marker in _IIS_MARKERS)


def parse_timestamp(date: str | None, time: str | None, tz: tzinfo | None) -> datetime:
    """A ``date`` és ``time`` mezőből UTC-időpont; ``tz`` megadásakor helyi időként értelmezi."""
    if not date or not time:
        raise ValueError("hiányzó date vagy time mező")
    try:
        naive = datetime.fromisoformat(f"{date}T{time}")
    except ValueError:
        raise ValueError(f"érvénytelen dátum/idő: {date} {time}") from None
    if tz is None:
        return naive.replace(tzinfo=UTC)
    return naive.replace(tzinfo=tz).astimezone(UTC)


def _event(
    row: dict[str, str | None], source_path: str, line_no: int, tz: tzinfo | None
) -> TimelineEvent:
    timestamp = parse_timestamp(row.get("date"), row.get("time"), tz)
    user = make_identity(row.get("cs-username"))
    src_ip = normalize_ip(row.get("c-ip"))
    status = row.get("sc-status")

    details: dict[str, Any] = {
        k: v for k, v in row.items() if v is not None and k not in ("date", "time")
    }
    agent = row.get("cs(User-Agent)")
    if agent is not None:
        # A W3C-formátum a szóközöket „+” jellel írja.
        details["cs(User-Agent)"] = agent.replace("+", " ")

    uri = row.get("cs-uri-stem") or "-"
    query = row.get("cs-uri-query")
    full_uri = f"{uri}?{query}" if query else uri
    if len(full_uri) > MAX_URI_IN_MESSAGE:
        full_uri = full_uri[: MAX_URI_IN_MESSAGE - 1] + "…"

    return TimelineEvent(
        timestamp_utc=timestamp,
        source=SOURCE,
        host=row.get("s-computername") or row.get("s-ip") or "-",
        event_id=EVENT_ID,
        category=Category.WEB,
        action="web_request",
        actor=user,
        target=None,
        src_ip=src_ip,
        message_key="web_request_user" if user else "web_request",
        message_params={
            "actor": user.display() if user else None,
            "method": row.get("cs-method"),
            "uri": full_uri,
            "status": status,
            "src": src_ip,
        },
        details=details,
        severity=Severity.LOW if status in _AUTH_FAILURE_STATUSES else Severity.INFO,
        raw_ref=f"{source_path}#{line_no}",
    )


def read_iis(path: Path, stats: ReadStats, tz: tzinfo | None = None) -> Iterator[TimelineEvent]:
    """Egy IIS W3C-napló soronkénti, streamelt feldolgozása (csak olvasásra nyitva).

    A ``raw_ref`` a fájl útvonala és a sor száma. A hibás sorokat a ``stats`` számolja.
    """
    source = str(path)
    fields: list[str] | None = None
    # utf-8-sig: az esetleges BOM ne kerüljön az első sor elejére.
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.startswith("#Fields:"):
                    fields = line[len("#Fields:") :].split()
                continue
            if fields is None:
                stats.add_error(f"{source}#{line_no}: adatsor a #Fields: direktíva előtt")
                continue
            values = line.split(" ")
            if len(values) != len(fields):
                stats.add_error(
                    f"{source}#{line_no}: a mezők száma ({len(values)}) eltér a "
                    f"#Fields: sorétól ({len(fields)})"
                )
                continue
            row = {
                name: (None if value == "-" else value)
                for name, value in zip(fields, values, strict=True)
            }
            try:
                event = _event(row, source, line_no, tz)
            except ValueError as exc:
                stats.add_error(f"{source}#{line_no}: {exc}")
                continue
            stats.records += 1
            stats.observe(SOURCE, event.timestamp_utc)
            yield event
