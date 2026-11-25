"""Kimenetek: CSV, JSON Lines, HTML-riport és az ingest → export integráció (8. mérföldkő)."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tests.helpers import FIXTURES, load_records
from usertrail.cli import app
from usertrail.engine import EngineError, TimelineRequest, build_timeline
from usertrail.parsers.evtx_reader import RawRecord, ReadStats
from usertrail.report.export import CSV_COLUMNS

runner = CliRunner()
IIS_LOG = FIXTURES / "iis" / "W3SVC1" / "u_ex261120.log"
FIXTURE_FILES = {
    "Security.evtx": "security_auth.json",
    "Security-account.evtx": "security_account.json",
    "Channels.evtx": "channels.json",
}


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    folder = tmp_path / "evidence"
    (folder / "W3SVC1").mkdir(parents=True)
    for name in FIXTURE_FILES:
        (folder / name).write_bytes(name.encode())
    (folder / "W3SVC1" / "u_ex261120.log").write_bytes(IIS_LOG.read_bytes())

    def fake_read(path: Path, stats: ReadStats) -> Iterator[RawRecord]:
        for record in load_records(FIXTURE_FILES[path.name], str(path)):
            stats.records += 1
            yield record

    monkeypatch.setattr("usertrail.pipeline.read_evtx", fake_read)
    return folder


def _invoke(*args: str) -> str:
    result = runner.invoke(app, list(args), env={"COLUMNS": "250"})
    assert result.exit_code == 0, result.output
    return result.output


@pytest.fixture
def case(evidence: Path, tmp_path: Path) -> Path:
    path = tmp_path / "case.db"
    _invoke("ingest", str(evidence), "--case", str(path))
    return path


def _export(case: Path, fmt: str, out: Path, *extra: str) -> str:
    return _invoke(
        "export",
        "--case",
        str(case),
        "--user",
        "kovacs.janos",
        "--tz",
        "Europe/Budapest",
        "--pivot-ip",
        "-f",
        fmt,
        "-o",
        str(out),
        *extra,
    )


# --- CSV ------------------------------------------------------------------------------------


def test_csv_has_bom_header_and_rows(case: Path, tmp_path: Path) -> None:
    out = tmp_path / "out" / "idovonal.csv"
    printed = _export(case, "csv", out)
    assert "Elkészült" in printed
    raw = out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM az Excelnek
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    assert tuple(rows[0].keys()) == CSV_COLUMNS
    assert {r["TimeZone"] for r in rows} == {"Europe/Budapest"}
    # Időrend és magyar ékezetek
    assert [r["TimestampUTC"] for r in rows] == sorted(r["TimestampUTC"] for r in rows)
    created = next(r for r in rows if r["EventID"] == "4720")
    assert created["Description"] == "CEG\\rendszergazda létrehozta a(z) CEG\\kovacs.janos fiókot"
    assert created["Role"] == "célpont"
    assert created["Timestamp"] == "2026-11-01 09:00:00"
    assert created["RawRef"].endswith("Security-account.evtx#201")
    privileged = next(r for r in rows if r["EventID"] == "4728")
    assert privileged["Alerts"] == "Kiemelt csoport"
    assert json.loads(privileged["Details"])["PrivilegedGroup"] == "Domain Admins"
    correlated = [r for r in rows if r["Role"] == "korrelált (IP)"]
    assert correlated
    assert all(r["CorrelatedWith"] for r in correlated)


def test_csv_meta_sidecar(case: Path, evidence: Path, tmp_path: Path) -> None:
    out = tmp_path / "idovonal.csv"
    _export(case, "csv", out)
    meta = json.loads((tmp_path / "idovonal.meta.json").read_text(encoding="utf-8"))
    assert meta["tool"] == "UserTrail"
    assert meta["version"]
    assert meta["parameters"]["user"] == "kovacs.janos"
    assert meta["parameters"]["pivot_ip"] is True
    hashes = {Path(s["path"]).name: s["sha256"] for s in meta["sources"]}
    expected = hashlib.sha256((evidence / "Security.evtx").read_bytes()).hexdigest()
    assert hashes["Security.evtx"] == expected
    assert len(hashes) == 4
    assert any(a["rule"] == "log_cleared" for a in meta["alerts"])


# --- JSON Lines -------------------------------------------------------------------------------


def test_jsonl_structure(case: Path, tmp_path: Path) -> None:
    out = tmp_path / "idovonal.jsonl"
    _export(case, "json", out, "--lang", "en")
    lines = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["type"] == "meta"
    assert lines[0]["counts"]["rows"] == sum(1 for x in lines if x["type"] == "event")
    kinds = [x["type"] for x in lines]
    # meta, majd a figyelmeztetések, végül az események
    assert kinds == sorted(kinds, key=["meta", "alert", "event"].index)
    events = [x for x in lines if x["type"] == "event"]
    renamed = next(e for e in events if e["event_id"] == "4781")
    assert renamed["description"] == (
        "CEG\\rendszergazda renamed account kovacs.janos to janos.kovacs"
    )
    assert renamed["role_text"] == "target"
    assert renamed["raw_refs"][0].endswith("#211")


# --- HTML ----------------------------------------------------------------------------------------


@pytest.fixture
def html(case: Path, tmp_path: Path) -> str:
    out = tmp_path / "riport.html"
    _export(case, "html", out)
    return out.read_text(encoding="utf-8")


def test_html_is_self_contained(html: str) -> None:
    assert "<script src" not in html
    assert "<link" not in html
    assert not re.search(r"""(src|href)=["']https?://""", html)
    assert "@import" not in html


def test_html_contains_required_sections(html: str) -> None:
    for text in (
        "UserTrail idővonal: kovacs.janos",
        "Időzóna",
        "Europe/Budapest",
        "Összefoglaló",
        "Események kategóriánként",
        "Figyelmeztetések",
        "Feldolgozott forrásfájlok",
        "Futtatási paraméterek",
        "Eszközverzió",
        "prefers-color-scheme: dark",
    ):
        assert text in html
    assert "korrelált (IP)" in html
    assert "nem bizonyítják" in html


def test_html_timeline_order(html: str) -> None:
    # Az idővonal sorai a várt időrendben: létrehozás → csoport → zárolás → átnevezés → törlés
    body = html[html.index('id="timeline"') :]
    positions = [
        body.index("létrehozta a(z) CEG\\kovacs.janos fiókot"),
        body.index("hozzáadta Kovács János tagot"),
        body.index("fiók zárolva"),
        body.index("átnevezte a(z) kovacs.janos fiókot"),
        body.index("törölte a(z) CEG\\janos.kovacs fiókot"),
    ]
    assert positions == sorted(positions)


def test_html_escapes_untrusted_values(evidence: Path, tmp_path: Path) -> None:
    # Naplóból származó szöveg nem futhat le a riportban.
    log = evidence / "W3SVC1" / "u_ex261120.log"
    log.write_text(
        log.read_text(encoding="utf-8")
        + "2026-11-20 10:07:00 10.0.0.7 CEG\\kovacs.janos 10.0.0.20 443 GET "
        "/<script>alert(1)</script> - 200 5 x\n",
        encoding="utf-8",
    )
    out = tmp_path / "x.html"
    _invoke("export", "-s", str(evidence), "--user", "kovacs.janos", "-o", str(out))
    content = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content


def test_html_english(case: Path, tmp_path: Path) -> None:
    out = tmp_path / "en.html"
    _export(case, "html", out, "--lang", "en")
    content = out.read_text(encoding="utf-8")
    assert '<html lang="en">' in content
    assert "Processed source files" in content
    assert "created account CEG\\kovacs.janos" in content


def test_html_collapsed_rows(evidence: Path, tmp_path: Path) -> None:
    log = evidence / "W3SVC1" / "u_ex261120.log"
    repeated = "".join(
        f"2026-11-20 12:0{i}:00 10.0.0.5 - 10.0.0.20 443 GET /owa/ping - 200 3 Mozilla/5.0\n"
        for i in range(4)
    )
    log.write_text(log.read_text(encoding="utf-8") + repeated, encoding="utf-8")
    out = tmp_path / "c.html"
    _invoke(
        "export",
        "-s",
        str(evidence),
        "--ip",
        "10.0.0.5",
        "--collapse",
        "--tz",
        "UTC",
        "-o",
        str(out),
    )
    content = out.read_text(encoding="utf-8")
    assert "4× webes kérés (GET 200)" in content
    assert "Összevont események" in content
    assert "IIS web_request ×4" in content


# --- motor és hibakezelés ------------------------------------------------------------------------


def test_engine_requires_exactly_one_source() -> None:
    with pytest.raises(EngineError):
        build_timeline(TimelineRequest(user="x"))
    with pytest.raises(EngineError):
        build_timeline(TimelineRequest(user="x", case=Path("a.db"), sources=(Path("b"),)))


def test_engine_parameters_are_recorded(evidence: Path) -> None:
    result = build_timeline(TimelineRequest(user="kovacs.janos", sources=(evidence,)))
    params: dict[str, Any] = result.request.parameters()
    assert params["user"] == "kovacs.janos"
    assert params["alerts"] is True
    assert {s.kind for s in result.sources} == {"evtx", "iis"}
    assert result.error_count == 2  # az IIS-fixture két hibás sora


def test_export_unwritable_output(case: Path, tmp_path: Path) -> None:
    target = tmp_path / "foglalt"
    target.mkdir()
    result = runner.invoke(
        app, ["export", "--case", str(case), "--user", "kovacs.janos", "-o", str(target)]
    )
    assert result.exit_code == 1
    assert "nem írható" in result.output
