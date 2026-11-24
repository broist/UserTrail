"""Read EVTX files into source-independent :class:`RawRecord` objects.

The heavy lifting is done by the Rust based ``evtx`` package. This module only turns
its JSON output into a flat, predictable structure and makes sure that a corrupt
record never stops processing of the rest of the file.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from usertrail.timeutil import parse_system_time

# Stop reading a file after this many consecutive iterator errors, so a badly damaged
# file cannot trap us in an endless loop.
MAX_CONSECUTIVE_ERRORS = 1000
MAX_ERROR_SAMPLES = 20


@dataclass(frozen=True, slots=True)
class RawRecord:
    """One EVTX record with its EventData / UserData flattened into ``data``."""

    source_path: str
    record_id: int
    timestamp_utc: datetime
    channel: str
    provider: str | None
    event_id: int
    computer: str | None
    user_sid: str | None
    data: dict[str, Any]

    @property
    def raw_ref(self) -> str:
        return f"{self.source_path}#{self.record_id}"


@dataclass(slots=True)
class ReadStats:
    """Per-run counters; errors are kept so they can be reported, never silently lost."""

    records: int = 0
    errors: int = 0
    error_samples: list[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors += 1
        if len(self.error_samples) < MAX_ERROR_SAMPLES:
            self.error_samples.append(message)


def _scalar(value: Any) -> Any:
    """Unwrap ``{"#text": ...}`` nodes and turn placeholders into None."""
    if isinstance(value, Mapping):
        if "#text" in value:
            value = value["#text"]
        else:
            return {k: _scalar(v) for k, v in value.items() if k != "#attributes"}
    if isinstance(value, str):
        stripped = value.strip()
        return None if stripped in ("", "-") else stripped
    return value


def flatten_event_data(node: Any) -> dict[str, Any]:
    """Flatten ``Event.EventData`` into ``{field_name: value}``.

    Unnamed ``<Data>`` elements (seen in some providers) become ``Data_0``, ``Data_1`` ...
    """
    if not isinstance(node, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key, value in node.items():
        if key == "#attributes":
            continue
        if key == "Data":
            items = value.get("#text") if isinstance(value, Mapping) else value
            if not isinstance(items, list):
                items = [items]
            for index, item in enumerate(items):
                out[f"Data_{index}"] = _scalar(item)
            continue
        out[key] = _scalar(value)
    return out


def flatten_user_data(node: Any) -> dict[str, Any]:
    """Flatten ``Event.UserData``; its single child (e.g. ``EventXML``) holds the fields."""
    if not isinstance(node, Mapping):
        return {}
    for key, child in node.items():
        if key != "#attributes" and isinstance(child, Mapping):
            return {k: _scalar(v) for k, v in child.items() if k != "#attributes"}
    return {}


def _event_id(value: Any) -> int:
    if isinstance(value, Mapping):
        value = value.get("#text")
    if value is None:
        raise ValueError("record has no EventID")
    return int(value)


def _attr(node: Any, name: str) -> Any:
    if isinstance(node, Mapping):
        attributes = node.get("#attributes")
        if isinstance(attributes, Mapping):
            return attributes.get(name)
    return None


def record_from_json(
    doc: Mapping[str, Any],
    source_path: str,
    record_id: int,
    fallback_timestamp: str | None = None,
) -> RawRecord:
    """Convert one record from ``PyEvtxParser.records_json()`` into a RawRecord.

    Raises ``ValueError`` (or ``KeyError``/``TypeError``) on structurally broken input;
    callers count those as record errors.
    """
    event = doc["Event"]
    system = event["System"]
    channel = system.get("Channel")
    if not channel:
        raise ValueError("record has no Channel")

    time_raw = _attr(system.get("TimeCreated"), "SystemTime") or fallback_timestamp
    if not time_raw:
        raise ValueError("record has no TimeCreated/SystemTime")

    data = flatten_event_data(event.get("EventData"))
    if "UserData" in event:
        data.update(flatten_user_data(event.get("UserData")))

    computer = system.get("Computer")
    user_sid = _attr(system.get("Security"), "UserID")
    return RawRecord(
        source_path=source_path,
        record_id=int(system.get("EventRecordID") or record_id),
        timestamp_utc=parse_system_time(str(time_raw)),
        channel=str(channel),
        provider=_attr(system.get("Provider"), "Name"),
        event_id=_event_id(system.get("EventID")),
        computer=str(computer) if computer else None,
        user_sid=str(user_sid).upper() if user_sid else None,
        data=data,
    )


def read_evtx(path: Path, stats: ReadStats) -> Iterator[RawRecord]:
    """Stream the records of one EVTX file. The file is opened read-only."""
    from evtx import PyEvtxParser

    source = str(path)
    with path.open("rb") as handle:
        records = PyEvtxParser(handle).records_json()
        consecutive = 0
        while True:
            try:
                item = next(records)
            except StopIteration:
                break
            except Exception as exc:  # the Rust parser surfaces corrupt chunks this way
                stats.add_error(f"{source}: {exc}")
                consecutive += 1
                if consecutive >= MAX_CONSECUTIVE_ERRORS:
                    stats.add_error(f"{source}: túl sok egymást követő hiba, az olvasás leállt")
                    break
                continue
            consecutive = 0
            if not isinstance(item, Mapping):
                stats.add_error(f"{source}: váratlan rekordobjektum: {type(item).__name__}")
                continue
            record_id = int(item.get("event_record_id", 0))
            try:
                doc = json.loads(item["data"])
                record = record_from_json(doc, source, record_id, item.get("timestamp"))
            except (ValueError, KeyError, TypeError) as exc:
                stats.add_error(f"{source}#{record_id}: {exc}")
                continue
            stats.records += 1
            yield record
