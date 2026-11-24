"""Közös teszt-segédfüggvények (``tests.helpers`` néven importálhatók)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from usertrail.models import TimelineEvent
from usertrail.parsers import parse_record
from usertrail.parsers.evtx_reader import RawRecord, record_from_json

FIXTURES = Path(__file__).parent / "fixtures"


def load_docs(name: str) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return docs


def load_records(name: str, source_path: str = "Security.evtx") -> list[RawRecord]:
    return [
        record_from_json(doc, source_path, index + 1) for index, doc in enumerate(load_docs(name))
    ]


def parse_all(records: list[RawRecord]) -> list[TimelineEvent]:
    return [event for record in records for event in parse_record(record)]


def by_record(events: list[TimelineEvent], record_id: int) -> TimelineEvent:
    for event in events:
        if event.raw_ref.endswith(f"#{record_id}"):
            return event
    raise AssertionError(f"no event for record {record_id}")
