from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from usertrail import __version__
from usertrail.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("timeline", "ingest", "sources", "users", "export"):
        assert command in result.output


def test_timeline_requires_a_search_key(fake_evtx: Path) -> None:
    result = runner.invoke(app, ["timeline", "-s", str(fake_evtx)])
    assert result.exit_code != 0


def test_timeline_for_user_from_folder(fake_evtx: Path) -> None:
    result = runner.invoke(
        app,
        [
            "timeline",
            "-s",
            str(fake_evtx.parent),
            "--user",
            "kovacs.janos@ceg.hu",
            "--tz",
            "Europe/Budapest",
            "--lang",
            "hu",
        ],
        env={"COLUMNS": "250"},
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Europe/Budapest" in out
    # 08:59:58 UTC Budapesten 09:59:58 (CET).
    assert "2026-11-20 09:59:58" in out
    assert "hibás jelszó" in out
    assert "célpont" in out
    assert "szereplő" in out
    assert "WS-042$" not in out
    assert out.index("4625") < out.index("4624") < out.index("4647") < out.index("4634")


def test_timeline_filters_by_date(fake_evtx: Path) -> None:
    result = runner.invoke(
        app,
        [
            "timeline",
            "-s",
            str(fake_evtx),
            "--user",
            "kovacs.janos",
            "--tz",
            "UTC",
            "--from",
            "2026-11-20T17:00",
        ],
        env={"COLUMNS": "250"},
    )
    assert result.exit_code == 0, result.output
    assert "4625" not in result.output
    assert "4634" in result.output


def test_invalid_category_is_rejected(fake_evtx: Path) -> None:
    result = runner.invoke(
        app, ["timeline", "-s", str(fake_evtx), "--user", "x", "--category", "NOPE"]
    )
    assert result.exit_code != 0


def test_not_yet_implemented_commands_exit_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["sources", "--case", str(tmp_path / "case.db")])
    assert result.exit_code == 2


def test_default_language_is_hungarian(fake_evtx: Path) -> None:
    result = runner.invoke(
        app,
        ["timeline", "-s", str(fake_evtx), "--user", "kovacs.janos", "--tz", "UTC"],
        env={"COLUMNS": "250"},
    )
    assert result.exit_code == 0, result.output
    assert "Sikertelen bejelentkezés" in result.output
    assert "Időzóna: UTC" in result.output


def test_unknown_time_zone_message_is_hungarian(fake_evtx: Path) -> None:
    result = runner.invoke(
        app, ["timeline", "-s", str(fake_evtx), "--user", "x", "--tz", "Mars/Base"]
    )
    assert result.exit_code != 0
    assert "ismeretlen időzóna" in result.output
