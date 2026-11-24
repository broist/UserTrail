"""Source discovery and record -> event streaming shared by the CLI commands."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from usertrail.models import TimelineEvent
from usertrail.parsers import parse_record
from usertrail.parsers.evtx_reader import ReadStats, read_evtx

EVTX_SUFFIX = ".evtx"


def discover_evtx(paths: Iterable[Path]) -> list[Path]:
    """Expand files and directories (recursively) into a sorted list of EVTX files."""
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
    """Yield timeline events from EVTX files; parser failures are counted, not raised."""
    for path in files:
        try:
            for record in read_evtx(path, stats):
                try:
                    yield from parse_record(record)
                except Exception as exc:  # one bad record must never stop the run
                    stats.add_error(f"{record.raw_ref}: parser error: {exc}")
        except OSError as exc:
            stats.add_error(f"{path}: cannot open: {exc}")
