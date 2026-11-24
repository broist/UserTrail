"""Közös parser-interfész és az általános EventSpec -> TimelineEvent építő."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from typing import Any, Protocol

from usertrail.identity import make_identity
from usertrail.mappings.event_map import EventSpec, IdentityFields
from usertrail.models import Identity, TimelineEvent
from usertrail.netutil import normalize_ip
from usertrail.parsers.evtx_reader import RawRecord

# A kezelőfüggvény módosíthatja a specifikációból épített eseményt
# (súlyosság, részletek, paraméterek ...).
Handler = Callable[[RawRecord, TimelineEvent], None]


class RecordParser(Protocol):
    """A parser a kezelt csatornák nyers rekordjait idővonal-eseményekké alakítja."""

    channels: frozenset[str]

    def parse(self, record: RawRecord) -> Iterator[TimelineEvent]: ...


def identity_from(data: Mapping[str, Any], fields: IdentityFields | None) -> Identity | None:
    if fields is None:
        return None
    name_f, domain_f, sid_f = fields
    return make_identity(
        data.get(name_f) if name_f else None,
        data.get(domain_f) if domain_f else None,
        data.get(sid_f) if sid_f else None,
    )


def build_event(record: RawRecord, spec: EventSpec, source: str) -> TimelineEvent:
    """TimelineEvent építése egy rekordból, kizárólag a deklaratív specifikáció alapján."""
    data = record.data
    actor = identity_from(data, spec.actor)
    target = identity_from(data, spec.target)
    src_ip = normalize_ip(data.get(spec.ip_field)) if spec.ip_field else None
    details = {f: data[f] for f in spec.detail_fields if data.get(f) is not None}
    params: dict[str, Any] = dict(details)
    params["actor"] = actor.display() if actor else None
    params["target"] = target.display() if target else None
    params["src"] = src_ip
    return TimelineEvent(
        timestamp_utc=record.timestamp_utc,
        source=source,
        host=record.computer or "-",
        event_id=str(record.event_id),
        category=spec.category,
        action=spec.action,
        actor=actor,
        target=target,
        src_ip=src_ip,
        message_key=spec.key,
        message_params=params,
        details=details,
        severity=spec.severity,
        raw_ref=record.raw_ref,
    )
