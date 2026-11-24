"""Forrásfájlok felderítése és rekord -> esemény streamelés a CLI-parancsokhoz."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import tzinfo
from pathlib import Path

from usertrail.models import TimelineEvent
from usertrail.parsers import parse_record
from usertrail.parsers.evtx_reader import ReadStats, read_evtx
from usertrail.parsers.iis import is_iis_log, read_iis

EVTX_SUFFIX = ".evtx"
KIND_EVTX = "evtx"
KIND_IIS = "iis"


@dataclass(frozen=True, slots=True, order=True)
class SourceFile:
    path: Path
    kind: str  # KIND_EVTX vagy KIND_IIS


def classify(path: Path) -> str | None:
    """A fájl típusa: ``evtx``, ``iis`` vagy None, ha nem támogatott."""
    if path.suffix.lower() == EVTX_SUFFIX:
        return KIND_EVTX
    if is_iis_log(path):
        return KIND_IIS
    return None


def discover_sources(paths: Iterable[Path]) -> list[SourceFile]:
    """Fájlok és mappák (rekurzív) kibontása támogatott forrásfájlok rendezett listájává.

    Az EVTX-et a kiterjesztés, az IIS-naplót a ``.log`` kiterjesztés és a W3C-fejléc
    alapján ismeri fel.
    """
    candidates: set[Path] = set()
    for path in paths:
        if path.is_dir():
            candidates.update(p for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            candidates.add(path)
    found = []
    for candidate in candidates:
        kind = classify(candidate)
        if kind is not None:
            found.append(SourceFile(candidate, kind))
    return sorted(found)


def iter_events(
    files: Iterable[SourceFile], stats: ReadStats, iis_tz: tzinfo | None = None
) -> Iterator[TimelineEvent]:
    """Idővonal-események a forrásfájlokból; a parserhibákat számolja, nem dobja tovább."""
    for source in files:
        try:
            if source.kind == KIND_IIS:
                yield from read_iis(source.path, stats, iis_tz)
                continue
            for record in read_evtx(source.path, stats):
                try:
                    yield from parse_record(record)
                except Exception as exc:  # egy hibás rekord sosem állíthatja le a futást
                    stats.add_error(f"{record.raw_ref}: feldolgozási hiba: {exc}")
        except OSError as exc:
            stats.add_error(f"{source.path}: nem nyitható meg: {exc}")
