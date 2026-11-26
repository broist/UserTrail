"""Élő gyűjtés: wevtutil-hívások, IIS-mappák felderítése és a CLI élő módja (szimulálva)."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from usertrail import live
from usertrail.cli import app

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner(env={"COLUMNS": "250"})


class FakeWevtutil:
    """A wevtutil helyettesítője: rögzíti a hívásokat, és csatornánként adott kóddal tér vissza."""

    def __init__(self, codes: dict[str, int] | None = None) -> None:
        self.codes = codes or {}
        self.calls: list[list[str]] = []

    def __call__(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        channel, target = args[1], Path(args[2])
        code = self.codes.get(channel, 0)
        if code == 0:
            target.write_bytes(b"ElfFile\x00")
        return subprocess.CompletedProcess(list(args), code, "", "hiba" if code else "")


def test_channel_file_name_matches_windows_naming() -> None:
    assert live.channel_file_name("Security") == "Security.evtx"
    assert (
        live.channel_file_name("Microsoft-Windows-PowerShell/Operational")
        == "Microsoft-Windows-PowerShell%4Operational.evtx"
    )


def test_time_query_uses_utc() -> None:
    assert live.time_query(None) is None
    since = datetime(2026, 11, 20, 1, 30, tzinfo=UTC)
    assert (
        live.time_query(since) == "*[System[TimeCreated[@SystemTime>='2026-11-20T01:30:00.000Z']]]"
    )


def test_export_channel_passes_query_and_overwrite(tmp_path: Path) -> None:
    fake = FakeWevtutil()
    since = datetime(2026, 11, 20, tzinfo=UTC)
    result = live.export_channel("System", tmp_path, since, fake)
    assert result.path == tmp_path / "System.evtx"
    assert fake.calls[0][:4] == ["epl", "System", str(tmp_path / "System.evtx"), "/ow:true"]
    assert fake.calls[0][4].startswith("/q:*[System[TimeCreated")


def test_export_channel_reports_access_denied_and_missing(tmp_path: Path) -> None:
    fake = FakeWevtutil({"Security": 5, "Nincs/Ilyen": 15007, "Egyeb": 1})
    denied = live.export_channel("Security", tmp_path, runner=fake)
    assert denied.path is None
    assert denied.access_denied
    assert "rendszergazdai" in (denied.error or "")
    missing = live.export_channel("Nincs/Ilyen", tmp_path, runner=fake)
    assert missing.path is None
    assert not missing.access_denied
    assert "nincs ilyen napló" in (missing.error or "")
    other = live.export_channel("Egyeb", tmp_path, runner=fake)
    assert "kód: 1" in (other.error or "")


def test_collect_continues_after_failed_channel(tmp_path: Path) -> None:
    fake = FakeWevtutil({"Security": 5})
    snapshot = live.collect(tmp_path / "snap", runner=fake, include_iis=False)
    assert [c.channel for c in snapshot.channels] == list(live.LIVE_CHANNELS)
    assert snapshot.access_denied
    assert len(snapshot.paths) == len(live.LIVE_CHANNELS) - 1
    described = snapshot.describe()
    assert described["channels"]["System"] == "ok"  # type: ignore[index]


def _write_config(path: Path, body: str) -> Path:
    path.write_text(
        f"<configuration><system.applicationHost><sites>{body}</sites>"
        "</system.applicationHost></configuration>",
        encoding="utf-8",
    )
    return path


def test_iis_log_dirs_from_site_defaults_and_site_override(tmp_path: Path) -> None:
    default_base = tmp_path / "alap"
    own_base = tmp_path / "sajat"
    (default_base / "W3SVC1").mkdir(parents=True)
    (own_base / "W3SVC2").mkdir(parents=True)
    config = _write_config(
        tmp_path / "applicationHost.config",
        f'<site name="A" id="1"/>'
        f'<site name="B" id="2"><logFile directory="{own_base}"/></site>'
        f'<site name="C" id="3"/>'
        f'<siteDefaults><logFile directory="{default_base}"/></siteDefaults>',
    )
    assert live.iis_log_dirs(config) == [default_base / "W3SVC1", own_base / "W3SVC2"]


def test_iis_log_dirs_falls_back_to_default_dir(tmp_path: Path) -> None:
    logs = tmp_path / "LogFiles"
    logs.mkdir()
    assert live.iis_log_dirs(tmp_path / "nincs.config", str(logs)) == [logs]
    assert live.iis_log_dirs(tmp_path / "nincs.config", str(tmp_path / "sehol")) == []


@pytest.fixture
def fake_collect(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Az élő gyűjtés helyett a tesztfixture IIS-naplóit adja vissza."""
    folders: list[Path] = []

    def collect(folder: Path, **_: object) -> live.LiveSnapshot:
        folders.append(folder)
        snapshot = live.LiveSnapshot("TESZTGEP", datetime.now(UTC), folder)
        snapshot.channels.append(
            live.ChannelExport("Security", None, "hozzáférés megtagadva", access_denied=True)
        )
        snapshot.iis_dirs = [FIXTURES / "iis"]
        return snapshot

    monkeypatch.setattr(live, "collect", collect)
    monkeypatch.setattr(live, "is_admin", lambda: False)
    return folders


def test_timeline_without_case_or_source_uses_live_logs(fake_collect: list[Path]) -> None:
    result = runner.invoke(app, ["timeline", "--user", "kovacs.janos", "--tz", "UTC"])
    assert result.exit_code == 0, result.output
    assert "Élő gyűjtés" in result.output
    assert "TESZTGEP" in result.output
    assert "rendszergazdai jog" in result.output
    assert "/intranet/doc.aspx" in result.output
    # Az ideiglenes munkamappa a futás végén törlődik.
    assert fake_collect
    assert not fake_collect[0].exists()


def test_export_records_live_collection_in_parameters(
    fake_collect: list[Path], tmp_path: Path
) -> None:
    out = tmp_path / "ki.jsonl"
    result = runner.invoke(app, ["export", "--user", "kovacs.janos", "-f", "json", "-o", str(out)])
    assert result.exit_code == 0, result.output
    first = out.read_text(encoding="utf-8").splitlines()[0]
    assert '"live"' in first
    assert "TESZTGEP" in first


def test_save_logs_keeps_snapshot_folder(fake_collect: list[Path], tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["timeline", "--user", "kovacs.janos", "--save-logs", str(tmp_path / "mentes")]
    )
    assert result.exit_code == 0, result.output
    assert fake_collect[0].parent == tmp_path / "mentes"


def test_users_and_sources_without_case_use_live_logs(fake_collect: list[Path]) -> None:
    users = runner.invoke(app, ["users"])
    assert users.exit_code == 0, users.output
    assert "élő gép (TESZTGEP)" in users.output
    assert "kovacs.janos" in users.output
    sources = runner.invoke(app, ["sources"])
    assert sources.exit_code == 0, sources.output
    assert "IIS" in sources.output


def test_live_mode_fails_cleanly_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "is_windows", lambda: False)
    result = runner.invoke(app, ["timeline", "--user", "kovacs.janos"])
    assert result.exit_code == 1
    assert "csak Windowson" in result.output
