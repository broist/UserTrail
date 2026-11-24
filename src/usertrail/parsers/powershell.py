"""PowerShell/Operational parser: 4104 szkriptblokk-naplózás.

A nagy szkripteket a PowerShell több 4104-es rekordra bontja (``MessageNumber`` /
``MessageTotal``, közös ``ScriptBlockId``). A parser a részeket összegyűjti, és csak a
teljes szkriptből készít egy idővonal-eseményt. Ha a fájl végén egy blokk hiányos
marad (pl. a napló felülírta a régi részeket), a ``finish`` a meglévő részekből adja
ki, ``Incomplete`` jelöléssel.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from usertrail.identity import make_identity
from usertrail.mappings.event_map import POWERSHELL, SOURCE_LABELS, spec_for
from usertrail.models import Severity, TimelineEvent
from usertrail.parsers.base import build_event, set_actor
from usertrail.parsers.evtx_reader import RawRecord

SCRIPT_BLOCK_EVENT = 4104
# A leírásba kerülő előnézet hossza (a teljes szöveg a details-ben marad).
PREVIEW_LENGTH = 120
# A PowerShell a gyanúsnak ítélt szkriptblokkokat figyelmeztetés szinttel naplózza.
_LEVEL_WARNING = 3


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class PowerShellParser:
    channels = frozenset({POWERSHELL})

    def __init__(self) -> None:
        self.source = SOURCE_LABELS[POWERSHELL]
        # ScriptBlockId -> {MessageNumber: rekord, ...}
        self._pending: dict[str, dict[int, RawRecord]] = {}
        self._totals: dict[str, int] = {}

    def parse(self, record: RawRecord) -> Iterator[TimelineEvent]:
        if record.event_id != SCRIPT_BLOCK_EVENT:
            return
        total = _as_int(record.data.get("MessageTotal"), 1)
        number = _as_int(record.data.get("MessageNumber"), 1)
        block_id = record.data.get("ScriptBlockId")
        if total <= 1 or not block_id:
            yield self._build([record], total=1)
            return
        parts = self._pending.setdefault(str(block_id), {})
        parts[number] = record
        self._totals[str(block_id)] = total
        if len(parts) >= total:
            del self._pending[str(block_id)]
            del self._totals[str(block_id)]
            yield self._build([parts[n] for n in sorted(parts)], total=total)

    def finish(self) -> Iterator[TimelineEvent]:
        for block_id, parts in list(self._pending.items()):
            yield self._build([parts[n] for n in sorted(parts)], total=self._totals[block_id])
        self._pending.clear()
        self._totals.clear()

    def _build(self, parts: list[RawRecord], total: int) -> TimelineEvent:
        first = parts[0]
        spec = spec_for(POWERSHELL, SCRIPT_BLOCK_EVENT)
        assert spec is not None
        event = build_event(first, spec, self.source)
        text = "".join(str(p.data.get("ScriptBlockText") or "") for p in parts)
        set_actor(event, make_identity(sid=first.user_sid))
        event.details["ScriptBlockText"] = text
        event.details["MessageTotal"] = total
        event.details["PartsReceived"] = len(parts)
        event.details["Incomplete"] = len(parts) < total
        if total > 1:
            event.details["Parts"] = [p.raw_ref for p in parts]
        if any(p.level == _LEVEL_WARNING for p in parts):
            event.details["SuspiciousByPowerShell"] = True
            event.severity = Severity.MEDIUM
        preview = " ".join(text.split())
        if len(preview) > PREVIEW_LENGTH:
            preview = preview[: PREVIEW_LENGTH - 1] + "…"
        if event.details["Incomplete"]:
            preview = f"[{len(parts)}/{total}] {preview}"
        event.message_params["preview"] = preview or "-"
        return event
