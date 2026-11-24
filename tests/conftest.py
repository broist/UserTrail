from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.helpers import load_records, parse_all
from usertrail.models import TimelineEvent
from usertrail.parsers.evtx_reader import RawRecord, ReadStats


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
