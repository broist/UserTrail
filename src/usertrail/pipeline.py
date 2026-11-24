"""Forrásfájlok felderítése és rekord -> esemény streamelés a CLI-parancsokhoz."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from usertrail.models import TimelineEvent
from usertrail.parsers import parse_record
from usertrail.parsers.evtx_reader import ReadStats, read_evtx

EVTX_SUFFIX = ".evtx"


def discover_evtx(paths: Iterable[Path]) -> list[Path]:
    """Fájlok és mappák (rekurzív) kibontása EVTX-fájlok rendezett listájává."""
    found: set[Path] = set()
    for path in paths:
        if path.is_dir():
            found.update(
                p for p in path.rglob("*") if p.is_file() and p.suffix.lower() == EVTX_SUFFIX
            )
        elif path.is_file() and path.suffix.lower() == EVTX_SUFFIX:
            found.add(path)
    return sorted(found)


def iter_events(files: Iterable[Path], stats: ReadStats) -> Iterator[TimelineEvent]:
    """Idővonal-események EVTX-fájlokból; a parserhibákat számolja, nem dobja tovább."""
    for path in files:
        try:
            for record in read_evtx(path, stats):
                try:
                    yield from parse_record(record)
                except Exception as exc:  # egy hibás rekord sosem állíthatja le a futást
                    stats.add_error(f"{record.raw_ref}: feldolgozási hiba: {exc}")
        except OSError as exc:
            stats.add_error(f"{path}: nem nyitható meg: {exc}")
