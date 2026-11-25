from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.helpers import load_records, parse_all
from usertrail.models import TimelineEvent
from usertrail.parsers.evtx_reader import RawRecord, ReadStats


def pytest_configure(config: pytest.Config) -> None:
    """Egyszerű szöveges CLI-kimenet a CI-ban is.

    A typer GitHub Actions alatt (GITHUB_ACTIONS, FORCE_COLOR, PY_COLORS) terminálnak
    tekinti a kimenetet, és ANSI-színkódokat tesz a hibaüzenetekbe; a rich a FORCE_COLOR
    hatására szintén. Ez szétszabdalja a tesztekben keresett szövegeket. A hook a
    tesztmodulok (és így a typer és a CLI) betöltése előtt fut.
    """
    os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"
    for variable in ("FORCE_COLOR", "PY_COLORS", "TTY_COMPATIBLE"):
        os.environ.pop(variable, None)


@pytest.fixture(autouse=True)
def _plain_typer_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Biztosíték arra az esetre, ha a typer már a fenti beállítás előtt betöltődött."""
    from typer import rich_utils

    monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", False)


@pytest.fixture
def auth_records() -> list[RawRecord]:
    return load_records("security_auth.json")


@pytest.fixture
def auth_events(auth_records: list[RawRecord]) -> list[TimelineEvent]:
    return parse_all(auth_records)


@pytest.fixture
def fake_evtx(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Üres ``Security.evtx``, amelynek olvasója a JSON-fixture rekordjait adja vissza.

    Így a CLI-tesztek bináris EVTX-fixture nélkül is végig tudnak futni.
    """
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"")

    def fake_read(p: Path, stats: ReadStats) -> Iterator[RawRecord]:
        for record in load_records("security_auth.json", str(p)):
            stats.records += 1
            yield record

    monkeypatch.setattr("usertrail.pipeline.read_evtx", fake_read)
    return path
