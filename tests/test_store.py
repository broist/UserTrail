"""A SQLite-tároló és az ingest → timeline / users folyamat (4. mérföldkő)."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.helpers import load_records, parse_all
from usertrail.cli import app
from usertrail.models import TimelineEvent
from usertrail.parsers.evtx_reader import RawRecord, ReadStats
from usertrail.store import SCHEMA_VERSION, CaseStore, StoreError, sha256_file

DOM = "S-1-5-21-1111111111-2222222222-3333333333"
KOVACS = f"{DOM}-1105"
runner = CliRunner()


@pytest.fixture
def all_events() -> list[TimelineEvent]:
    return parse_all(load_records("security_auth.json")) + parse_all(
        load_records("security_account.json")
    )


@pytest.fixture
def store(tmp_path: Path, all_events: list[TimelineEvent]) -> Iterator[CaseStore]:
    with CaseStore.open(tmp_path / "case.db", create=True) as case:
        source_id = case.add_source(Path("Security.evtx"), 123, "ab" * 32, "evtx")
        case.insert_events(source_id, all_events, batch_size=5)
        case.finish_source(source_id, len(all_events) + 1, len(all_events), 1, ["hiba"])
        yield case


def test_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "x.bin"
    path.write_bytes(b"usertrail" * 100_000)
    assert sha256_file(path) == hashlib.sha256(b"usertrail" * 100_000).hexdigest()


def test_open_missing_case_without_create(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="nem létezik"):
        CaseStore.open(tmp_path / "nincs.db")


def test_schema_version_is_checked(tmp_path: Path) -> None:
    path = tmp_path / "case.db"
    CaseStore.open(path, create=True).close()
    conn = sqlite3.connect(path)
    with conn:
        conn.execute("UPDATE meta SET value = '999' WHERE key = 'schema_version'")
    conn.close()
    with pytest.raises(StoreError, match="sémaverzió"):
        CaseStore.open(path)


def test_migration_from_schema_v1(tmp_path: Path) -> None:
    path = tmp_path / "case.db"
    CaseStore.open(path, create=True).close()
    # Egy 1-es sémájú adatbázis szimulálása: nincs options oszlop.
    conn = sqlite3.connect(path)
    with conn:
        conn.execute("ALTER TABLE sources DROP COLUMN options")
        conn.execute("ALTER TABLE sources DROP COLUMN coverage")
        conn.execute("UPDATE meta SET value = '1' WHERE key = 'schema_version'")
        conn.execute(
            "INSERT INTO sources(path, size, sha256, kind, ingested_at, tool_version) "
            "VALUES ('régi.evtx', 1, 'ff', 'evtx', '2026-01-01', '0.0.1')"
        )
    conn.close()
    with CaseStore.open(path) as case:
        (source,) = case.sources()
        assert source.options == {}
        assert source.coverage == {}
        version = case.conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()[0]
        assert int(version) == SCHEMA_VERSION == 3


def test_events_round_trip(store: CaseStore, all_events: list[TimelineEvent]) -> None:
    assert store.event_count() == len(all_events)
    loaded = store.candidate_events(names=["kovacs.janos", "janos.kovacs"], sids=[KOVACS])
    originals = {e.raw_ref: e for e in all_events}
    assert loaded
    for event in loaded:
        assert event == originals[event.raw_ref]


def test_source_bookkeeping(store: CaseStore) -> None:
    (source,) = store.sources()
    assert source.sha256 == "ab" * 32
    assert source.completed
    assert source.errors == 1
    assert source.error_samples == ["hiba"]
    assert store.find_source("ab" * 32) == source
    assert store.find_source("cd" * 32) is None


def test_candidate_filters(store: CaseStore) -> None:
    by_ip = store.candidate_events(ip="10.0.0.5")
    assert {e.event_id for e in by_ip} == {"4624", "4625"}
    windowed = store.candidate_events(
        sids=[KOVACS],
        start=datetime(2026, 11, 3, tzinfo=UTC),
        end=datetime(2026, 11, 4, tzinfo=UTC),
    )
    assert sorted(e.event_id for e in windowed) == ["4728", "4729", "4732"]
    assert store.candidate_events() == []


def test_alias_is_searchable(store: CaseStore) -> None:
    # A 4781 célpontja az új név; a régi névvel az alias-táblán keresztül is megtalálható.
    renamed = [e for e in store.candidate_events(names=["kovacs.janos"]) if e.event_id == "4781"]
    assert len(renamed) == 1
    assert renamed[0].aliases[0].name == "kovacs.janos"


def test_sid_map_from_store(store: CaseStore) -> None:
    sid_map = store.sid_map()
    assert sid_map.names_for_sid(KOVACS) == {"kovacs.janos", "janos.kovacs"}


def test_identities_are_merged_by_sid(store: CaseStore) -> None:
    identities = store.identities()
    kovacs = [i for i in identities if i.sid == KOVACS]
    assert len(kovacs) == 1
    assert {n.casefold() for n in kovacs[0].names} == {"kovacs.janos", "janos.kovacs"}
    assert kovacs[0].as_actor > 0
    assert kovacs[0].as_target > 0
    assert kovacs[0].first_seen is not None
    assert kovacs[0].first_seen.startswith("2026-11-01")
    # A gépfiókok alapértelmezésben kimaradnak.
    assert not any(i.is_machine for i in identities)
    assert any(i.is_machine for i in store.identities(include_machine_accounts=True))


def test_discard_source(store: CaseStore) -> None:
    (source,) = store.sources()
    store.discard_source(source.id)
    assert store.event_count() == 0
    assert store.sources() == []


# --- CLI: ingest → timeline / users ---------------------------------------------------


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Két „EVTX” fájl eltérő tartalommal; az olvasójuk a JSON-fixture-öket adja."""
    folder = tmp_path / "evidence"
    (folder / "dc01").mkdir(parents=True)
    (folder / "dc01" / "Security.evtx").write_bytes(b"auth")
    (folder / "Security-2.EVTX").write_bytes(b"account")
    fixtures = {"Security.evtx": "security_auth.json", "Security-2.EVTX": "security_account.json"}

    def fake_read(path: Path, stats: ReadStats) -> Iterator[RawRecord]:
        for record in load_records(fixtures[path.name], str(path)):
            stats.records += 1
            yield record

    monkeypatch.setattr("usertrail.pipeline.read_evtx", fake_read)
    return folder


def _invoke(*args: str) -> str:
    result = runner.invoke(app, list(args), env={"COLUMNS": "250"})
    assert result.exit_code == 0, result.output
    return result.output


def test_ingest_then_timeline(evidence: Path, tmp_path: Path) -> None:
    case = str(tmp_path / "case.db")
    out = _invoke("ingest", str(evidence), "--case", case)
    assert out.count("betöltve") == 2
    assert "összesen 23 esemény" in out

    again = _invoke("ingest", str(evidence), "--case", case)
    assert again.count("már betöltve") == 2
    assert "összesen 23 esemény" in again

    timeline = _invoke("timeline", "--case", case, "--user", "janos.kovacs", "--tz", "UTC")
    # A régi névvel rögzített 4625-ös (auth fixture) és a fiók teljes élete is látszik.
    for event_id in ("4625", "4720", "4728", "4781", "4726"):
        assert event_id in timeline
    assert timeline.index("4720") < timeline.index("4781") < timeline.index("4726")
    assert "Nagy" not in timeline

    users = _invoke("users", "--case", case, "--tz", "UTC")
    assert "janos.kovacs / kovacs.janos" in users
    assert "rendszergazda" in users
    assert "WS-042$" not in users


def test_case_and_source_are_exclusive(evidence: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["timeline", "--case", str(tmp_path / "c.db"), "-s", str(evidence), "--user", "x"],
    )
    assert result.exit_code != 0


def test_timeline_on_missing_case(tmp_path: Path) -> None:
    result = runner.invoke(app, ["timeline", "--case", str(tmp_path / "nincs.db"), "--user", "x"])
    assert result.exit_code == 1
    assert "nem létezik" in result.output


def test_interrupted_ingest_is_redone(evidence: Path, tmp_path: Path) -> None:
    case_path = tmp_path / "case.db"
    file_path = evidence / "dc01" / "Security.evtx"
    with CaseStore.open(case_path, create=True) as case:
        # Félbeszakadt betöltés szimulálása: forrássor van, de nincs lezárva.
        case.add_source(file_path, 4, sha256_file(file_path), "evtx")
    out = _invoke("ingest", str(file_path), "--case", str(case_path))
    assert "betöltve" in out
    assert "már betöltve" not in out
    with CaseStore.open(case_path) as case:
        (source,) = case.sources()
        assert source.completed
        assert case.event_count() == 7
