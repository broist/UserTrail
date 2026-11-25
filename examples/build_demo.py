"""A szintetikus demo-vizsgálat (``examples/demo/demo-case.db``) újraépítése.

A demo egy kitalált fiók (CEG\\kovacs.janos) életútját mutatja be: létrehozás, jelszó-
visszaállítás, kiemelt csoportba vétel, zárolás, RDP- és webes munka, PowerShell,
szolgáltatástelepítés, naplótörlés, átnevezés és törlés, valamint egy jelszótalálgatási
kísérlet. Minden adat kitalált; valódi napló nem kerül a repóba.

Az adatok a tesztek JSON-fixture-jeiből (``tests/fixtures``) és az itt generált
kiegészítő rekordokból állnak, és ugyanazon a parser- és tárolási úton haladnak át, mint
egy valódi ``ingest``. A forrásfájl-táblában a fixture-ök SHA-256 hash-e szerepel
``synthetic`` jelöléssel.

Futtatás a projekt gyökeréből::

    python examples/build_demo.py
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from usertrail.models import TimelineEvent
from usertrail.parsers import Dispatcher
from usertrail.parsers.evtx_reader import RawRecord, ReadStats, record_from_json
from usertrail.parsers.iis import read_iis
from usertrail.store import CaseStore

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
OUT_DIR = ROOT / "examples" / "demo"
CASE = OUT_DIR / "demo-case.db"

DOM = "S-1-5-21-1111111111-2222222222-3333333333"
KOVACS = f"{DOM}-1105"


def _security(rid: int, eid: int, at: datetime, data: dict[str, Any], ok: bool) -> dict[str, Any]:
    return {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                "EventID": eid,
                "TimeCreated": {"#attributes": {"SystemTime": at.isoformat()}},
                "EventRecordID": rid,
                "Keywords": "0x8020000000000000" if ok else "0x8010000000000000",
                "Channel": "Security",
                "Computer": "DC01.ceg.local",
            },
            "EventData": data,
        }
    }


def _logon_data(ip: str, logon_type: int, status: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "DC01$",
        "SubjectDomainName": "CEG",
        "TargetUserSid": KOVACS if status is None else "S-1-0-0",
        "TargetUserName": "kovacs.janos",
        "TargetDomainName": "CEG",
        "LogonType": logon_type,
        "AuthenticationPackageName": "NTLM",
        "WorkstationName": "-",
        "IpAddress": ip,
        "IpPort": "0",
    }
    if status is not None:
        data.update({"Status": "0xc000006d", "SubStatus": status})
    return data


def extra_records() -> list[dict[str, Any]]:
    """Kiegészítő forgatókönyvek: jelszótalálgatás, zajos hálózati bejelentkezések,
    munkaidőn kívüli RDP-bejelentkezés."""
    docs = []
    rid = 900
    start = datetime(2026, 11, 20, 7, 40, tzinfo=UTC)
    # 12 hibás jelszó 10.0.0.66-ról két percen belül, majd sikeres bejelentkezés.
    for i in range(12):
        rid += 1
        at = start + timedelta(seconds=10 * i)
        docs.append(_security(rid, 4625, at, _logon_data("10.0.0.66", 3, "0xc000006a"), False))
    rid += 1
    docs.append(
        _security(
            rid, 4624, start + timedelta(minutes=2, seconds=30), _logon_data("10.0.0.66", 3), True
        )
    )
    # Ismétlődő hálózati bejelentkezések egy fájlszerverről (a --collapse ezeket vonja össze).
    for i in range(8):
        rid += 1
        at = datetime(2026, 11, 20, 12, 0, tzinfo=UTC) + timedelta(minutes=i)
        docs.append(_security(rid, 4624, at, _logon_data("10.0.0.40", 3), True))
    # Szombat esti RDP-bejelentkezés (munkaidőn kívül).
    rid += 1
    docs.append(
        _security(
            rid, 4624, datetime(2026, 11, 21, 21, 30, tzinfo=UTC), _logon_data("10.0.0.5", 10), True
        )
    )
    return docs


def _ingest_docs(store: CaseStore, name: str, docs: list[dict[str, Any]], digest: str) -> None:
    stats = ReadStats()
    dispatcher = Dispatcher()

    def events() -> Iterator[TimelineEvent]:
        for index, doc in enumerate(docs, start=1):
            record: RawRecord = record_from_json(doc, name, index)
            stats.records += 1
            stats.observe(record.channel, record.timestamp_utc)
            yield from dispatcher.parse(record)
        yield from dispatcher.finish()

    source_id = store.add_source(
        Path(name), len(json.dumps(docs)), digest, "evtx", {"synthetic": True}
    )
    inserted = store.insert_events(source_id, events())
    store.finish_source(
        source_id, stats.records, inserted, stats.errors, stats.error_samples, stats.coverage_json()
    )


def build() -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        Path(f"{CASE}{suffix}").unlink(missing_ok=True)
    with CaseStore.open(CASE, create=True) as store:
        for fixture, name in (
            ("security_auth.json", "DC01/Security.evtx"),
            ("security_account.json", "DC01/Security-archiv.evtx"),
            ("channels.json", "WS-042/egyeb-csatornak.evtx"),
        ):
            path = FIXTURES / fixture
            docs = json.loads(path.read_text(encoding="utf-8"))
            _ingest_docs(store, name, docs, hashlib.sha256(path.read_bytes()).hexdigest())

        extra = extra_records()
        payload = json.dumps(extra, sort_keys=True).encode()
        _ingest_docs(
            store, "DC01/Security-kiegeszites.evtx", extra, hashlib.sha256(payload).hexdigest()
        )

        iis = FIXTURES / "iis" / "W3SVC1" / "u_ex261120.log"
        stats = ReadStats()
        source_id = store.add_source(
            Path("WEB01/W3SVC1/u_ex261120.log"),
            iis.stat().st_size,
            hashlib.sha256(iis.read_bytes()).hexdigest(),
            "iis",
            {"synthetic": True, "iis_tz": "UTC"},
        )
        inserted = store.insert_events(source_id, read_iis(iis, stats))
        store.finish_source(
            source_id,
            stats.records,
            inserted,
            stats.errors,
            stats.error_samples,
            stats.coverage_json(),
        )
        # A WAL-fájlok visszaírása, hogy a repóba egyetlen .db fájl kerüljön.
        store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        store.conn.execute("PRAGMA journal_mode=DELETE")
    return CASE


if __name__ == "__main__":
    print(f"Elkészült: {build()}")
