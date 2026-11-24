from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from usertrail.parsers.evtx_reader import (
    flatten_event_data,
    flatten_user_data,
    record_from_json,
)


def _doc(**system: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "EventID": 4624,
        "TimeCreated": {"#attributes": {"SystemTime": "2026-11-20T09:00:00Z"}},
        "EventRecordID": 7,
        "Channel": "Security",
        "Computer": "DC01",
    }
    base.update(system)
    return {"Event": {"System": base, "EventData": {"TargetUserName": "x"}}}


def test_event_id_as_int_or_object() -> None:
    assert record_from_json(_doc(), "f.evtx", 1).event_id == 4624
    wrapped = _doc(EventID={"#attributes": {"Qualifiers": 16384}, "#text": 7045})
    assert record_from_json(wrapped, "f.evtx", 1).event_id == 7045


def test_basic_fields_and_raw_ref() -> None:
    rec = record_from_json(_doc(), "C:/cases/Security.evtx", 99)
    assert rec.timestamp_utc == datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
    assert rec.channel == "Security"
    assert rec.computer == "DC01"
    # EventRecordID from the record wins over the iterator's id.
    assert rec.record_id == 7
    assert rec.raw_ref == "C:/cases/Security.evtx#7"


def test_user_sid_from_system_security() -> None:
    doc = _doc(Security={"#attributes": {"UserID": "s-1-5-21-1-2-3-1105"}})
    assert record_from_json(doc, "f", 1).user_sid == "S-1-5-21-1-2-3-1105"


def test_fallback_timestamp_used_when_timecreated_missing() -> None:
    doc = _doc(TimeCreated=None)
    rec = record_from_json(doc, "f", 1, fallback_timestamp="2026-11-21 10:00:00.000000 UTC")
    assert rec.timestamp_utc == datetime(2026, 11, 21, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize("missing", ["Channel", "EventID"])
def test_broken_records_raise(missing: str) -> None:
    doc = _doc()
    del doc["Event"]["System"][missing]
    with pytest.raises((ValueError, KeyError)):
        record_from_json(doc, "f", 1)


def test_flatten_event_data_named_and_placeholders() -> None:
    data = flatten_event_data(
        {
            "#attributes": {"Name": "ignored"},
            "TargetUserName": "kovacs.janos",
            "IpAddress": "-",
            "WorkstationName": "",
            "LogonType": 3,
            "Wrapped": {"#text": "value"},
        }
    )
    assert data == {
        "TargetUserName": "kovacs.janos",
        "IpAddress": None,
        "WorkstationName": None,
        "LogonType": 3,
        "Wrapped": "value",
    }


def test_flatten_event_data_unnamed_data_list() -> None:
    assert flatten_event_data({"Data": ["a", "-", 5]}) == {
        "Data_0": "a",
        "Data_1": None,
        "Data_2": 5,
    }
    assert flatten_event_data({"Data": {"#text": ["x", "y"]}}) == {"Data_0": "x", "Data_1": "y"}
    assert flatten_event_data(None) == {}


def test_flatten_user_data_eventxml() -> None:
    node = {
        "EventXML": {
            "#attributes": {"xmlns": "Event_NS"},
            "User": "CEG\\kovacs.janos",
            "SessionID": 3,
            "Address": "10.0.0.5",
        }
    }
    assert flatten_user_data(node) == {
        "User": "CEG\\kovacs.janos",
        "SessionID": 3,
        "Address": "10.0.0.5",
    }


def test_user_data_merged_into_record() -> None:
    doc = _doc(Channel="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
    doc["Event"].pop("EventData")
    doc["Event"]["UserData"] = {"EventXML": {"User": "CEG\\kovacs.janos"}}
    assert record_from_json(doc, "f", 1).data == {"User": "CEG\\kovacs.janos"}
