"""SQLite-alapú vizsgálati adatbázis: egy vizsgálat = egy adatbázisfájl.

A ``sources`` tábla a forensic dokumentációhoz rögzíti a feldolgozott fájlokat (útvonal,
méret, SHA-256, időpont, rekord- és hibaszám, eszközverzió). Ugyanazt a fájlt a hash
alapján csak egyszer dolgozzuk fel. Az ``events`` tábla az idővonal-eseményeket, az
``aliases`` tábla az átnevezésből származó további neveket tartalmazza.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path
from typing import Any

from usertrail import __version__
from usertrail.identity import SidMap, is_machine_account, well_known_label
from usertrail.models import Category, Identity, Severity, TimelineEvent

SCHEMA_VERSION = 2
BATCH_SIZE = 5000
_HASH_CHUNK = 1024 * 1024

# A sources.options a feldolgozási beállításokat tárolja JSON-ként, pl.
# {"iis_tz": "Europe/Budapest"}. (Az SQL-ben nincs komment, mert az SQLite
# ALTER TABLE a tárolt CREATE TABLE szöveget írja át.)
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    records INTEGER NOT NULL DEFAULT 0,
    events INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    error_samples TEXT NOT NULL DEFAULT '[]',
    completed INTEGER NOT NULL DEFAULT 0,
    options TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    timestamp_utc TEXT NOT NULL,
    source TEXT NOT NULL,
    host TEXT NOT NULL,
    event_id TEXT NOT NULL,
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_rank INTEGER NOT NULL,
    actor_name TEXT,
    actor_domain TEXT,
    actor_sid TEXT,
    actor_key TEXT,
    target_name TEXT,
    target_domain TEXT,
    target_sid TEXT,
    target_key TEXT,
    src_ip TEXT,
    message_key TEXT NOT NULL,
    message_params TEXT NOT NULL,
    details TEXT NOT NULL,
    raw_ref TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS aliases (
    event_rowid INTEGER NOT NULL REFERENCES events(id),
    name TEXT,
    domain TEXT,
    sid TEXT,
    name_key TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_time ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS ix_events_actor_key ON events(actor_key);
CREATE INDEX IF NOT EXISTS ix_events_target_key ON events(target_key);
CREATE INDEX IF NOT EXISTS ix_events_actor_sid ON events(actor_sid);
CREATE INDEX IF NOT EXISTS ix_events_target_sid ON events(target_sid);
CREATE INDEX IF NOT EXISTS ix_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS ix_events_event_id ON events(event_id);
CREATE INDEX IF NOT EXISTS ix_aliases_event ON aliases(event_rowid);
CREATE INDEX IF NOT EXISTS ix_aliases_name_key ON aliases(name_key);
CREATE INDEX IF NOT EXISTS ix_aliases_sid ON aliases(sid);
"""

_EVENT_COLUMNS = (
    "source_id, timestamp_utc, source, host, event_id, category, action, severity, "
    "severity_rank, actor_name, actor_domain, actor_sid, actor_key, target_name, "
    "target_domain, target_sid, target_key, src_ip, message_key, message_params, details, "
    "raw_ref"
)


class StoreError(Exception):
    """A vizsgálati adatbázis nem nyitható meg vagy nem kompatibilis."""


@dataclass(frozen=True, slots=True)
class SourceInfo:
    id: int
    path: str
    size: int
    sha256: str
    kind: str
    ingested_at: str
    tool_version: str
    records: int
    events: int
    errors: int
    error_samples: list[str]
    completed: bool
    options: dict[str, Any]


@dataclass(slots=True)
class IdentitySummary:
    """Egy ismert identitás összesítése a ``users`` parancshoz."""

    names: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    sid: str | None = None
    as_actor: int = 0
    as_target: int = 0
    first_seen: str | None = None
    last_seen: str | None = None

    @property
    def is_machine(self) -> bool:
        return any(n.endswith("$") for n in self.names)

    @property
    def label(self) -> str | None:
        sample = Identity(name=min(self.names) if self.names else None, sid=self.sid)
        return well_known_label(sample)


def sha256_file(path: Path) -> str:
    """A fájl SHA-256 hash-e streamelve, csak olvasásra megnyitva."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _ts(value: datetime) -> str:
    # Rögzített formátum, hogy a szöveges rendezés megegyezzen az időrenddel.
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)


def _identity_cols(identity: Identity | None) -> tuple[Any, ...]:
    if identity is None:
        return (None, None, None, None)
    return (identity.name, identity.domain, identity.sid_key, identity.name_key)


def _identity(name: Any, domain: Any, sid: Any) -> Identity | None:
    if name is None and sid is None:
        return None
    return Identity(name=name, domain=domain, sid=sid)


def _chunks(items: Iterable[TimelineEvent], size: int) -> Iterator[list[TimelineEvent]]:
    iterator = iter(items)
    while batch := list(islice(iterator, size)):
        yield batch


class CaseStore:
    """Egy vizsgálati adatbázis megnyitott kapcsolata."""

    def __init__(self, conn: sqlite3.Connection, path: Path) -> None:
        self.conn = conn
        self.path = path

    @classmethod
    def open(cls, path: Path, *, create: bool = False) -> CaseStore:
        if not path.exists() and not create:
            raise StoreError(f"a vizsgálati adatbázis nem létezik: {path}")
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        store = cls(conn, path)
        store._init_schema()
        return store

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.executescript(_SCHEMA)
            row = self.conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                now = _ts(datetime.now(UTC))
                self.conn.executemany(
                    "INSERT INTO meta(key, value) VALUES (?, ?)",
                    [
                        ("schema_version", str(SCHEMA_VERSION)),
                        ("created_at", now),
                        ("created_by", f"usertrail {__version__}"),
                    ],
                )
            else:
                version = int(row["value"])
                if version == 1:
                    self._migrate_v1_to_v2()
                elif version != SCHEMA_VERSION:
                    raise StoreError(
                        f"nem támogatott adatbázis-sémaverzió: {version} (várt: {SCHEMA_VERSION})"
                    )

    def _migrate_v1_to_v2(self) -> None:
        """1 -> 2: a sources tábla ``options`` oszlopot kap (pl. az IIS-időzónához)."""
        self.conn.execute("ALTER TABLE sources ADD COLUMN options TEXT NOT NULL DEFAULT '{}'")
        self.conn.execute("UPDATE meta SET value = '2' WHERE key = 'schema_version'")

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> CaseStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # --- források -------------------------------------------------------------------

    def find_source(self, sha256: str) -> SourceInfo | None:
        row = self.conn.execute("SELECT * FROM sources WHERE sha256 = ?", (sha256,)).fetchone()
        return self._source(row) if row else None

    def add_source(
        self,
        path: Path,
        size: int,
        sha256: str,
        kind: str,
        options: dict[str, Any] | None = None,
    ) -> int:
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO sources(path, size, sha256, kind, ingested_at, tool_version, "
                "options) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(path),
                    size,
                    sha256,
                    kind,
                    _ts(datetime.now(UTC)),
                    __version__,
                    _json(options or {}),
                ),
            )
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    def finish_source(
        self, source_id: int, records: int, events: int, errors: int, error_samples: list[str]
    ) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE sources SET records = ?, events = ?, errors = ?, error_samples = ?, "
                "completed = 1 WHERE id = ?",
                (records, events, errors, _json(error_samples), source_id),
            )

    def discard_source(self, source_id: int) -> None:
        """Egy félbeszakadt feldolgozás nyomainak törlése, hogy újra lehessen futtatni."""
        with self.conn:
            self.conn.execute(
                "DELETE FROM aliases WHERE event_rowid IN "
                "(SELECT id FROM events WHERE source_id = ?)",
                (source_id,),
            )
            self.conn.execute("DELETE FROM events WHERE source_id = ?", (source_id,))
            self.conn.execute("DELETE FROM sources WHERE id = ?", (source_id,))

    def sources(self) -> list[SourceInfo]:
        rows = self.conn.execute("SELECT * FROM sources ORDER BY id").fetchall()
        return [self._source(row) for row in rows]

    @staticmethod
    def _source(row: sqlite3.Row) -> SourceInfo:
        return SourceInfo(
            id=row["id"],
            path=row["path"],
            size=row["size"],
            sha256=row["sha256"],
            kind=row["kind"],
            ingested_at=row["ingested_at"],
            tool_version=row["tool_version"],
            records=row["records"],
            events=row["events"],
            errors=row["errors"],
            error_samples=json.loads(row["error_samples"]),
            completed=bool(row["completed"]),
            options=json.loads(row["options"]),
        )

    # --- események -------------------------------------------------------------------

    def insert_events(
        self, source_id: int, events: Iterable[TimelineEvent], batch_size: int = BATCH_SIZE
    ) -> int:
        """Események kötegelt beírása, kötegenként egy tranzakcióban."""
        total = 0
        for batch in _chunks(events, batch_size):
            with self.conn:
                for event in batch:
                    cursor = self.conn.execute(
                        f"INSERT INTO events({_EVENT_COLUMNS}) VALUES ({', '.join('?' * 22)})",
                        self._event_row(source_id, event),
                    )
                    if event.aliases:
                        rowid = cursor.lastrowid
                        self.conn.executemany(
                            "INSERT INTO aliases(event_rowid, name, domain, sid, name_key) "
                            "VALUES (?, ?, ?, ?, ?)",
                            [
                                (rowid, a.name, a.domain, a.sid_key, a.name_key)
                                for a in event.aliases
                            ],
                        )
            total += len(batch)
        return total

    @staticmethod
    def _event_row(source_id: int, event: TimelineEvent) -> tuple[Any, ...]:
        return (
            source_id,
            _ts(event.timestamp_utc),
            event.source,
            event.host,
            event.event_id,
            event.category.value,
            event.action,
            event.severity.value,
            event.severity.rank,
            *_identity_cols(event.actor),
            *_identity_cols(event.target),
            event.src_ip,
            event.message_key,
            _json(event.message_params),
            _json(event.details),
            event.raw_ref,
        )

    def _events_from_rows(self, rows: Sequence[sqlite3.Row]) -> list[TimelineEvent]:
        ids = [row["id"] for row in rows]
        aliases: dict[int, list[Identity]] = {}
        for start in range(0, len(ids), 900):
            chunk = ids[start : start + 900]
            for alias in self.conn.execute(
                f"SELECT * FROM aliases WHERE event_rowid IN ({','.join('?' * len(chunk))})",
                chunk,
            ):
                identity = _identity(alias["name"], alias["domain"], alias["sid"])
                if identity is not None:
                    aliases.setdefault(alias["event_rowid"], []).append(identity)
        return [
            TimelineEvent(
                timestamp_utc=datetime.fromisoformat(row["timestamp_utc"]),
                source=row["source"],
                host=row["host"],
                event_id=row["event_id"],
                category=Category(row["category"]),
                action=row["action"],
                actor=_identity(row["actor_name"], row["actor_domain"], row["actor_sid"]),
                target=_identity(row["target_name"], row["target_domain"], row["target_sid"]),
                src_ip=row["src_ip"],
                message_key=row["message_key"],
                message_params=json.loads(row["message_params"]),
                details=json.loads(row["details"]),
                severity=Severity(row["severity"]),
                raw_ref=row["raw_ref"],
                aliases=tuple(aliases.get(row["id"], ())),
            )
            for row in rows
        ]

    def candidate_events(
        self,
        names: Iterable[str] = (),
        sids: Iterable[str] = (),
        ip: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[TimelineEvent]:
        """Az identitásra vagy IP-re illeszkedő események előszűrése SQL-ben.

        A pontos szerep-meghatározást és a további szűrést a ``query.select`` végzi.
        """
        name_list = sorted({n.casefold() for n in names})
        sid_list = sorted({s.upper() for s in sids})
        where: list[str] = []
        params: list[Any] = []
        if name_list or sid_list:
            n_marks = ",".join("?" * len(name_list)) or "NULL"
            s_marks = ",".join("?" * len(sid_list)) or "NULL"
            where.append(
                f"(actor_key IN ({n_marks}) OR target_key IN ({n_marks}) "
                f"OR actor_sid IN ({s_marks}) OR target_sid IN ({s_marks}) "
                f"OR id IN (SELECT event_rowid FROM aliases "
                f"WHERE name_key IN ({n_marks}) OR sid IN ({s_marks})))"
            )
            params += name_list * 2 + sid_list * 2 + name_list + sid_list
        if ip is not None:
            where.append("src_ip = ?")
            params.append(ip)
        if not where:
            return []
        if start is not None:
            where.append("timestamp_utc >= ?")
            params.append(_ts(start))
        if end is not None:
            where.append("timestamp_utc < ?")
            params.append(_ts(end))
        rows = self.conn.execute(
            f"SELECT * FROM events WHERE {' AND '.join(where)} ORDER BY timestamp_utc, id",
            params,
        ).fetchall()
        return self._events_from_rows(rows)

    def events_from_ips(
        self,
        ips: Iterable[str],
        start: datetime | None = None,
        end: datetime | None = None,
        source: str | None = None,
    ) -> list[TimelineEvent]:
        """Az adott IP-címekről érkező események (pl. az IP-pivothoz az IIS-kérések)."""
        ip_list = sorted(set(ips))
        if not ip_list:
            return []
        where = [f"src_ip IN ({','.join('?' * len(ip_list))})"]
        params: list[Any] = list(ip_list)
        if source is not None:
            where.append("source = ?")
            params.append(source)
        if start is not None:
            where.append("timestamp_utc >= ?")
            params.append(_ts(start))
        if end is not None:
            where.append("timestamp_utc <= ?")
            params.append(_ts(end))
        rows = self.conn.execute(
            f"SELECT * FROM events WHERE {' AND '.join(where)} ORDER BY timestamp_utc, id",
            params,
        ).fetchall()
        return self._events_from_rows(rows)

    def event_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    # --- identitások -----------------------------------------------------------------

    def sid_map(self) -> SidMap:
        """SID ↔ név térkép az összes tárolt eseményből (aliasokkal együtt)."""
        sid_map = SidMap()
        rows = self.conn.execute(
            "SELECT actor_name AS name, actor_sid AS sid FROM events "
            "WHERE actor_key IS NOT NULL AND actor_sid IS NOT NULL "
            "UNION SELECT target_name, target_sid FROM events "
            "WHERE target_key IS NOT NULL AND target_sid IS NOT NULL "
            "UNION SELECT name, sid FROM aliases WHERE name_key IS NOT NULL AND sid IS NOT NULL"
        )
        for row in rows:
            sid_map.learn(Identity(name=row["name"], sid=row["sid"]))
        return sid_map

    def identities(self, *, include_machine_accounts: bool = False) -> list[IdentitySummary]:
        """Az összes ismert identitás összesítve; a SID-térkép alapján összevonva."""
        sid_map = self.sid_map()
        rows = self.conn.execute(
            """
            SELECT name_key, MAX(name) AS name, MAX(domain) AS domain, sid,
                   SUM(as_actor) AS as_actor, SUM(as_target) AS as_target,
                   MIN(ts) AS first_seen, MAX(ts) AS last_seen
            FROM (
                SELECT actor_key AS name_key, actor_name AS name, actor_domain AS domain,
                       actor_sid AS sid, 1 AS as_actor, 0 AS as_target, timestamp_utc AS ts
                FROM events WHERE actor_key IS NOT NULL OR actor_sid IS NOT NULL
                UNION ALL
                SELECT target_key, target_name, target_domain, target_sid, 0, 1, timestamp_utc
                FROM events WHERE target_key IS NOT NULL OR target_sid IS NOT NULL
            )
            GROUP BY name_key, sid
            """
        ).fetchall()
        merged: dict[str, IdentitySummary] = {}
        for row in rows:
            sid = row["sid"]
            name_key = row["name_key"]
            if sid is None and name_key is not None:
                known = sid_map.sids_for_name(name_key)
                if len(known) == 1:
                    sid = next(iter(known))
            key = f"sid:{sid}" if sid else f"name:{name_key}"
            summary = merged.setdefault(key, IdentitySummary(sid=sid))
            if row["name"]:
                summary.names.add(row["name"])
            if row["domain"]:
                summary.domains.add(row["domain"])
            summary.as_actor += row["as_actor"]
            summary.as_target += row["as_target"]
            first, last = row["first_seen"], row["last_seen"]
            if summary.first_seen is None or first < summary.first_seen:
                summary.first_seen = first
            if summary.last_seen is None or last > summary.last_seen:
                summary.last_seen = last
        # A SID-hez tanult, de az eseményekben csak aliasként szereplő nevek is látszódjanak.
        for summary in merged.values():
            if summary.sid:
                known_names = sid_map.names_for_sid(summary.sid)
                lower = {n.casefold() for n in summary.names}
                summary.names |= {n for n in known_names if n not in lower}
        result = [
            s
            for s in merged.values()
            if include_machine_accounts
            or not any(is_machine_account(Identity(name=n)) for n in s.names)
        ]
        result.sort(key=lambda s: (min((n.casefold() for n in s.names), default="~"), s.sid or ""))
        return result
