"""Forrásállapot-ellenőrzés és a sources parancs (9. mérföldkő)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.helpers import FIXTURES, load_records
from usertrail import health
from usertrail.cli import app
from usertrail.health import Finding, Level
from usertrail.parsers.evtx_reader import RawRecord, ReadStats
from usertrail.store import CaseStore

runner = CliRunner()
IIS_LOG = FIXTURES / "iis" / "W3SVC1" / "u_ex261120.log"

RecordFilter = Callable[[RawRecord], bool]


def _keep_all(_record: RawRecord) -> bool:
    return True


def _make_case(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    files: dict[str, tuple[str, RecordFilter]],
    with_iis: bool = False,
) -> Path:
    """Vizsgálati adatbázis a JSON-fixture-ökből, a valódi ingest parancson keresztül."""
    folder = tmp_path / "evidence"
    folder.mkdir()
    for name in files:
        (folder / name).write_bytes(name.encode())
    if with_iis:
        (folder / "W3SVC1").mkdir()
        (folder / "W3SVC1" / "u_ex261120.log").write_bytes(IIS_LOG.read_bytes())

    def fake_read(path: Path, stats: ReadStats) -> Iterator[RawRecord]:
        fixture, keep = files[path.name]
        for record in load_records(fixture, str(path)):
            if keep(record):
                stats.records += 1
                yield record

    monkeypatch.setattr("usertrail.pipeline.read_evtx", fake_read)
    case = tmp_path / "case.db"
    result = runner.invoke(app, ["ingest", str(folder), "--case", str(case)])
    assert result.exit_code == 0, result.output
    return case


def _codes(findings: list[Finding]) -> dict[str, Level]:
    return {f.code: f.level for f in findings}


@pytest.fixture
def full_case(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return _make_case(
        monkeypatch,
        tmp_path,
        {
            "Security.evtx": ("security_auth.json", _keep_all),
            "Account.evtx": ("security_account.json", _keep_all),
            "Channels.evtx": ("channels.json", _keep_all),
        },
        with_iis=True,
    )


def test_summary_per_channel(full_case: Path) -> None:
    with CaseStore.open(full_case) as store:
        summaries = {s.source: s for s in health.summarize(store)}
    assert list(summaries)[:6] == ["Security", "System", "RDP-LSM", "RDP-RCM", "PowerShell", "IIS"]
    security = summaries["Security"]
    assert security.files == 3  # a Channels.evtx-ben is vannak Security-rekordok
    assert security.records == 8 + 16 + 9
    assert security.first == datetime(2026, 11, 1, 8, 0, tzinfo=UTC)
    assert security.last == datetime(2026, 11, 20, 17, 30, tzinfo=UTC)
    # Minden beolvasott rekord számít, a leképezetlen 4100-as PowerShell-esemény is.
    assert summaries["PowerShell"].records == 8
    assert summaries["PowerShell"].events == 4
    assert summaries["IIS"].records == 6


def test_findings_for_full_case(full_case: Path) -> None:
    with CaseStore.open(full_case) as store:
        codes = _codes(health.check(store, min_days=30))
        relaxed = _codes(health.check(store, min_days=7))
    assert codes["log_cleared"] is Level.WARNING
    assert codes["short_coverage"] is Level.WARNING
    assert codes["record_errors"] is Level.WARNING  # az IIS-fixture 2 hibás sora
    assert "short_coverage" not in relaxed
    for absent in (
        "missing.Security",
        "no_logon",
        "no_process_creation",
        "no_command_line",
        "no_kerberos",
        "no_account_management",
        "no_script_block",
        "missing.IIS",
    ):
        assert absent not in codes


def test_log_cleared_texts(full_case: Path) -> None:
    with CaseStore.open(full_case) as store:
        cleared = [f for f in health.check(store) if f.code == "log_cleared"]
    texts = sorted(f.text() for f in cleared)
    assert texts[0].startswith("A(z) Security naplót 1 alkalommal törölték (Security 1102")
    assert "System 104" in texts[1]


def test_workstation_security_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = _make_case(monkeypatch, tmp_path, {"Security.evtx": ("security_auth.json", _keep_all)})
    with CaseStore.open(case) as store:
        findings = health.check(store)
    codes = _codes(findings)
    assert codes["no_process_creation"] is Level.INFO
    assert codes["no_kerberos"] is Level.INFO
    assert codes["no_account_management"] is Level.INFO
    assert codes["no_scheduled_task"] is Level.INFO
    assert codes["short_coverage"] is Level.WARNING
    assert codes["missing.PowerShell"] is Level.INFO
    assert codes["missing.IIS"] is Level.INFO
    # A figyelmeztetések elöl állnak.
    levels = [f.level for f in findings]
    assert levels == sorted(levels, key=lambda lvl: 0 if lvl is Level.WARNING else 1)
    text = next(f for f in findings if f.code == "no_process_creation").text()
    assert "Audit Process Creation" in text


def test_command_line_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def strip_command_line(record: RawRecord) -> bool:
        record.data.pop("CommandLine", None)
        return record.channel == "Security"

    case = _make_case(monkeypatch, tmp_path, {"Ch.evtx": ("channels.json", strip_command_line)})
    with CaseStore.open(case) as store:
        codes = _codes(health.check(store))
    assert codes["no_command_line"] is Level.INFO
    assert "no_process_creation" not in codes


def test_script_block_logging_disabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    case = _make_case(
        monkeypatch,
        tmp_path,
        {"PS.evtx": ("channels.json", lambda r: r.event_id == 4100)},
    )
    with CaseStore.open(case) as store:
        codes = _codes(health.check(store))
    assert codes["no_script_block"] is Level.WARNING
    assert codes["missing.Security"] is Level.WARNING


def test_empty_case(tmp_path: Path) -> None:
    with CaseStore.open(tmp_path / "ures.db", create=True) as store:
        assert [f.code for f in health.check(store)] == ["no_sources"]


def test_old_case_without_coverage_uses_event_range(full_case: Path) -> None:
    with CaseStore.open(full_case) as store:
        with store.conn:
            store.conn.execute("UPDATE sources SET coverage = '{}'")
        summaries = {s.source: s for s in health.summarize(store)}
    security = summaries["Security"]
    assert security.records is None
    assert security.files == 0
    assert security.first == datetime(2026, 11, 1, 8, 0, tzinfo=UTC)


def test_incomplete_source_is_reported(full_case: Path) -> None:
    with CaseStore.open(full_case) as store:
        store.add_source(Path("felbe.evtx"), 1, "ab" * 32, "evtx")
        assert _codes(health.check(store))["incomplete_sources"] is Level.WARNING


def test_cli_sources(full_case: Path) -> None:
    result = runner.invoke(
        app,
        ["sources", "--case", str(full_case), "--tz", "UTC", "--min-days", "30"],
        env={"COLUMNS": "250"},
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Naplóforrások" in out
    assert "Feldolgozott forrásfájlok" in out
    assert "Megállapítások" in out
    assert "2026-11-01 08:00:00" in out
    assert "felülíródtak" in out
    assert "törölték" in out


def test_cli_sources_english(full_case: Path) -> None:
    result = runner.invoke(
        app, ["sources", "--case", str(full_case), "--lang", "en"], env={"COLUMNS": "250"}
    )
    assert result.exit_code == 0, result.output
    assert "Log sources" in result.output
    assert "was cleared" in result.output
