"""IIS W3C-parser, forrásfelismerés és IP-pivot (5. mérföldkő)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from typer.testing import CliRunner

from tests.helpers import FIXTURES, load_records, parse_all
from usertrail.cli import app
from usertrail.correlate import PivotSeed, correlate_web, pivot_seeds, seed_time_range
from usertrail.identity import IdentityQuery, SidMap
from usertrail.models import Category, Identity, Role, Severity, TimelineEvent
from usertrail.parsers.evtx_reader import RawRecord, ReadStats
from usertrail.parsers.iis import is_iis_log, parse_timestamp, read_iis
from usertrail.pipeline import KIND_EVTX, KIND_IIS, SourceFile, discover_sources
from usertrail.query import TimelineFilter, TimelineRow, select
from usertrail.store import CaseStore

IIS_LOG = FIXTURES / "iis" / "W3SVC1" / "u_ex261120.log"
runner = CliRunner()


def _read(
    path: Path = IIS_LOG, tz: ZoneInfo | None = None
) -> tuple[list[TimelineEvent], ReadStats]:
    stats = ReadStats()
    return list(read_iis(path, stats, tz)), stats


def _line(events: list[TimelineEvent], line_no: int) -> TimelineEvent:
    for event in events:
        if event.raw_ref.endswith(f"#{line_no}"):
            return event
    raise AssertionError(f"nincs esemény a(z) {line_no}. sorhoz")


def test_lines_and_errors_are_counted() -> None:
    events, stats = _read()
    assert [e.raw_ref.rsplit("#", 1)[1] for e in events] == ["5", "6", "8", "13", "14", "15"]
    assert stats.records == 6
    assert stats.errors == 2
    assert "#7" in stats.error_samples[0]
    assert "#16" in stats.error_samples[1]
    assert "érvénytelen dátum/idő: 2026-11-20 xx:yy:zz" in stats.error_samples[1]


def test_first_fields_block() -> None:
    events, _ = _read()
    ev = _line(events, 6)
    assert ev.timestamp_utc == datetime(2026, 11, 20, 9, 10, tzinfo=UTC)
    assert ev.source == "IIS"
    assert ev.event_id == "IIS"
    assert ev.category is Category.WEB
    assert ev.action == "web_request"
    assert ev.actor is None
    assert ev.src_ip == "10.0.0.5"
    assert ev.host == "10.0.0.20"
    assert ev.details["cs-method"] == "POST"
    assert ev.details["cs(User-Agent)"] == "Mozilla/5.0 (Windows NT 10.0)"
    assert ev.details["cs(Referer)"] == "https://mail.ceg.local/owa/"
    assert "cs-uri-query" not in ev.details  # a "-" üres mezőt jelent
    assert ev.description() == "Webes kérés: POST /owa/auth.owa → 200, kliens: 10.0.0.5"


def test_second_fields_block_uses_new_order() -> None:
    events, _ = _read()
    ev = _line(events, 13)
    assert ev.actor == Identity("kovacs.janos", "CEG", None)
    assert ev.src_ip == "10.0.0.7"  # ::ffff: levágva
    assert ev.details["cs-uri-query"] == "id=42"
    assert ev.description() == (
        "Webes kérés (CEG\\kovacs.janos): GET /intranet/doc.aspx?id=42 → 200, kliens: 10.0.0.7"
    )
    upn = _line(events, 14)
    assert upn.actor == Identity("nagy.peter", "ceg.hu", None)


def test_auth_failure_status_is_low_severity() -> None:
    events, _ = _read()
    assert _line(events, 8).severity is Severity.LOW
    assert _line(events, 6).severity is Severity.INFO


def test_iis_local_time_zone() -> None:
    events, _ = _read(tz=ZoneInfo("Europe/Budapest"))
    # 09:10 budapesti idő (CET, UTC+1) = 08:10 UTC
    assert _line(events, 6).timestamp_utc == datetime(2026, 11, 20, 8, 10, tzinfo=UTC)


def test_parse_timestamp_requires_date_and_time() -> None:
    with pytest.raises(ValueError, match="hiányzó"):
        parse_timestamp(None, "10:00:00", None)


def test_crlf_bom_and_data_before_fields(tmp_path: Path) -> None:
    path = tmp_path / "u_ex261121.log"
    path.write_bytes(
        "﻿#Software: Microsoft Internet Information Services 10.0\r\n"
        "2026-11-21 10:00:00 x\r\n"
        "#Fields: date time c-ip\r\n"
        "2026-11-21 10:00:01 10.0.0.1\r\n".encode()
    )
    events, stats = _read(path)
    assert len(events) == 1
    assert events[0].src_ip == "10.0.0.1"
    assert stats.errors == 1
    assert "#Fields:" in stats.error_samples[0]


def test_source_detection(tmp_path: Path) -> None:
    (tmp_path / "notes.log").write_text("ez nem IIS-napló\n", encoding="utf-8")
    (tmp_path / "Security.evtx").write_bytes(b"")
    (tmp_path / "sub").mkdir()
    iis_copy = tmp_path / "sub" / "u_ex261120.log"
    iis_copy.write_bytes(IIS_LOG.read_bytes())
    assert is_iis_log(iis_copy)
    assert not is_iis_log(tmp_path / "notes.log")
    assert discover_sources([tmp_path]) == [
        SourceFile(tmp_path / "Security.evtx", KIND_EVTX),
        SourceFile(iis_copy, KIND_IIS),
    ]


# --- IP-pivot ---------------------------------------------------------------------------


@pytest.fixture
def mixed_events() -> list[TimelineEvent]:
    iis, _ = _read()
    return parse_all(load_records("security_auth.json")) + iis


def _kovacs_rows(events: list[TimelineEvent]) -> tuple[TimelineFilter, list[TimelineRow]]:
    sid_map = SidMap()
    for event in events:
        sid_map.learn_event(event)
    flt = TimelineFilter(identity=IdentityQuery.build("kovacs.janos", sid_map=sid_map))
    return flt, select(events, flt)


def test_direct_iis_match_by_username(mixed_events: list[TimelineEvent]) -> None:
    _, rows = _kovacs_rows(mixed_events)
    iis_rows = [r for r in rows if r.event.source == "IIS"]
    assert [(r.event.raw_ref.rsplit("#", 1)[1], r.role) for r in iis_rows] == [("13", Role.ACTOR)]


def test_pivot_seeds_only_successful_external_logons(mixed_events: list[TimelineEvent]) -> None:
    _, rows = _kovacs_rows(mixed_events)
    seeds = pivot_seeds(rows)
    # Csak a 4624 (10.0.0.5); a 4625 sikertelen, az IIS-kérés nem bejelentkezés.
    assert [(s.ip, s.raw_ref) for s in seeds] == [("10.0.0.5", "Security.evtx#102")]


def test_correlate_web_window(mixed_events: list[TimelineEvent]) -> None:
    _, rows = _kovacs_rows(mixed_events)
    seeds = pivot_seeds(rows)
    correlated = correlate_web(
        seeds, mixed_events, TimelineFilter(), exclude=[r.event.raw_ref for r in rows]
    )
    assert [r.event.raw_ref.rsplit("#", 1)[1] for r in correlated] == ["5", "6"]
    assert all(r.role is Role.CORRELATED for r in correlated)
    assert all(r.correlated_with == "Security.evtx#102" for r in correlated)

    wide = correlate_web(seeds, mixed_events, TimelineFilter(), window=timedelta(hours=3))
    assert "15" in [r.event.raw_ref.rsplit("#", 1)[1] for r in wide]


def test_correlate_respects_filters(mixed_events: list[TimelineEvent]) -> None:
    _, rows = _kovacs_rows(mixed_events)
    seeds = pivot_seeds(rows)
    only_auth = TimelineFilter(categories=frozenset({Category.AUTHENTICATION}))
    assert correlate_web(seeds, mixed_events, only_auth) == []
    later = TimelineFilter(start=datetime(2026, 11, 20, 9, 0, tzinfo=UTC))
    assert [
        r.event.raw_ref.rsplit("#", 1)[1] for r in correlate_web(seeds, mixed_events, later)
    ] == ["6"]


def test_seed_time_range() -> None:
    t = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
    seeds = [PivotSeed("10.0.0.5", t, "a#1"), PivotSeed("10.0.0.6", t + timedelta(hours=2), "a#2")]
    assert seed_time_range(seeds) == (t - timedelta(hours=1), t + timedelta(hours=3))
    assert seed_time_range([]) is None


# --- CLI ----------------------------------------------------------------------------------


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    folder = tmp_path / "evidence"
    (folder / "W3SVC1").mkdir(parents=True)
    (folder / "Security.evtx").write_bytes(b"auth")
    (folder / "W3SVC1" / "u_ex261120.log").write_bytes(IIS_LOG.read_bytes())

    def fake_read(path: Path, stats: ReadStats) -> Iterator[RawRecord]:
        for record in load_records("security_auth.json", str(path)):
            stats.records += 1
            yield record

    monkeypatch.setattr("usertrail.pipeline.read_evtx", fake_read)
    return folder


def _invoke(*args: str) -> str:
    result = runner.invoke(app, list(args), env={"COLUMNS": "250"})
    assert result.exit_code == 0, result.output
    return result.output


def test_cli_direct_mode_with_pivot(evidence: Path) -> None:
    base = ["timeline", "-s", str(evidence), "--user", "kovacs.janos", "--tz", "UTC"]
    without = _invoke(*base)
    assert "/intranet/doc.aspx" in without  # közvetlen találat a felhasználónévvel
    assert "/owa/auth.owa" not in without
    assert "2 rekordot nem sikerült feldolgozni" in without

    with_pivot = _invoke(*base, "--pivot-ip")
    assert "/owa/auth.owa" in with_pivot
    assert "korrelált (IP)" in with_pivot
    assert "/owa/late" not in with_pivot
    assert "2 korrelált webes kérés" in with_pivot
    assert "nem bizonyítják" in with_pivot

    wide = _invoke(*base, "--pivot-ip", "--pivot-window", "180")
    assert "/owa/late" in wide


def test_cli_ingest_and_pivot_from_case(evidence: Path, tmp_path: Path) -> None:
    case = tmp_path / "case.db"
    out = _invoke("ingest", str(evidence), "--case", str(case), "--iis-tz", "Europe/Budapest")
    assert out.count("betöltve") == 2
    with CaseStore.open(case) as store:
        kinds = {s.kind: s.options for s in store.sources()}
        assert kinds == {"evtx": {}, "iis": {"iis_tz": "Europe/Budapest"}}

    # Budapesti időként betöltve a 09:10-es kérés 08:10 UTC, a 08:55-ös 07:55 UTC lesz:
    # ±1 órán belül a 09:00:01-es bejelentkezéstől csak a 08:10-es marad.
    pivot = _invoke(
        "timeline", "--case", str(case), "--user", "kovacs.janos", "--tz", "UTC", "--pivot-ip"
    )
    assert "1 korrelált webes kérés" in pivot
    assert "2026-11-20 08:10:00" in pivot


def test_pivot_requires_identity(evidence: Path) -> None:
    out = _invoke("timeline", "-s", str(evidence), "--ip", "10.0.0.5", "--pivot-ip")
    assert "csak --user vagy --sid" in out


def test_invalid_iis_tz(evidence: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["ingest", str(evidence), "--case", str(tmp_path / "c.db"), "--iis-tz", "local"]
    )
    assert result.exit_code != 0
    assert "IANA" in result.output
