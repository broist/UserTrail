"""Élő gyűjtés: az aktuális gép naplóinak pillanatképe a feldolgozáshoz.

Az eseménynaplókat a Windows saját ``wevtutil epl`` parancsa menti egy munkamappába, így a
feldolgozás egy konzisztens, rögzített hash-ű másolatból dolgozik, az élő naplófájlokat pedig
semmi nem módosítja. Az IIS-naplók helyét az ``applicationHost.config`` adja meg; ezeket a
program a helyükön, csak olvasásra nyitja meg (több GB-osak is lehetnek, másolásuk lassú
volna).
"""

from __future__ import annotations

import os
import platform
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# Az élő gyűjtés csatornái (a támogatott parserek szerint).
LIVE_CHANNELS: tuple[str, ...] = (
    "Security",
    "System",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-PowerShell/Operational",
)

DEFAULT_IIS_DIR = r"%SystemDrive%\inetpub\logs\LogFiles"
APPHOST_CONFIG = r"%windir%\System32\inetsrv\config\applicationHost.config"

# A wevtutil ismert hibakódjai (Win32-hibakódok).
_ERROR_ACCESS_DENIED = 5
_ERROR_CHANNEL_NOT_FOUND = 15007

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class LiveError(Exception):
    """Az élő gyűjtés nem végezhető el (pl. nem Windows a futtató rendszer)."""


@dataclass(frozen=True, slots=True)
class ChannelExport:
    """Egy csatorna mentésének eredménye."""

    channel: str
    path: Path | None
    error: str | None = None
    access_denied: bool = False


@dataclass(slots=True)
class LiveSnapshot:
    """Az élő gépről gyűjtött források."""

    host: str
    collected_at: datetime
    folder: Path
    channels: list[ChannelExport] = field(default_factory=list)
    iis_dirs: list[Path] = field(default_factory=list)

    @property
    def paths(self) -> list[Path]:
        """A feldolgozandó fájlok és mappák."""
        return [c.path for c in self.channels if c.path is not None] + self.iis_dirs

    @property
    def access_denied(self) -> bool:
        return any(c.access_denied for c in self.channels)

    def describe(self) -> dict[str, object]:
        """A gyűjtés leírása a riportok futtatási paramétereihez."""
        return {
            "host": self.host,
            "collected_at": self.collected_at.isoformat(),
            "snapshot": str(self.folder),
            "channels": {
                c.channel: ("ok" if c.path is not None else (c.error or "hiba"))
                for c in self.channels
            },
            "iis_dirs": [str(p) for p in self.iis_dirs],
        }


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_admin() -> bool:
    """Rendszergazdai (emelt szintű) jogosultsággal fut-e a folyamat (csak Windowson)."""
    if not is_windows():
        return False
    try:
        import ctypes

        windll = getattr(ctypes, "windll")  # noqa: B009 - csak Windowson létezik
        return bool(windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def channel_file_name(channel: str) -> str:
    """A csatorna fájlneve, ahogy a Windows is tárolja (``/`` helyett ``%4``)."""
    return channel.replace("/", "%4") + ".evtx"


def time_query(since: datetime | None) -> str | None:
    """XPath-szűrő a wevtutilnak: csak a ``since`` utáni rekordok."""
    if since is None:
        return None
    stamp = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return f"*[System[TimeCreated[@SystemTime>='{stamp}']]]"


def _run_wevtutil(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # rögzített program, a paramétereket mi állítjuk elő
        ["wevtutil", *args],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def export_channel(
    channel: str, folder: Path, since: datetime | None = None, runner: Runner = _run_wevtutil
) -> ChannelExport:
    """Egy csatorna mentése ``wevtutil epl``-lel a munkamappába."""
    target = folder / channel_file_name(channel)
    args = ["epl", channel, str(target), "/ow:true"]
    query = time_query(since)
    if query is not None:
        args.append(f"/q:{query}")
    try:
        result = runner(args)
    except OSError as exc:
        return ChannelExport(channel, None, f"a wevtutil nem indítható: {exc}")
    if result.returncode == 0 and target.is_file():
        return ChannelExport(channel, target)
    message = (result.stderr or result.stdout or "").strip()
    # A wevtutil üzenetei a Windows nyelvén jönnek, ezért a kilépési kód a mérvadó.
    if result.returncode == _ERROR_ACCESS_DENIED:
        return ChannelExport(
            channel, None, "hozzáférés megtagadva (rendszergazdai jog kell)", access_denied=True
        )
    if result.returncode == _ERROR_CHANNEL_NOT_FOUND:
        return ChannelExport(channel, None, "ezen a gépen nincs ilyen napló")
    return ChannelExport(
        channel, None, f"a mentés nem sikerült (kód: {result.returncode}) {message}".strip()
    )


def _expand(value: str) -> Path:
    return Path(os.path.expandvars(value))


def iis_log_dirs(config: Path | None = None, default_dir: str = DEFAULT_IIS_DIR) -> list[Path]:
    """Az IIS-webhelyek naplómappái.

    Az ``applicationHost.config`` alapértelmezett (``siteDefaults``) és webhelyenkénti
    ``logFile`` beállításait olvassa; a webhely naplói a ``<mappa>\\W3SVC<azonosító>``
    alatt vannak. Ha a konfiguráció nem olvasható, az alapértelmezett mappát nézi meg.
    Csak a létező mappákat adja vissza.
    """
    config = config if config is not None else _expand(APPHOST_CONFIG)
    base_default = default_dir
    site_dirs: list[Path] = []
    try:
        root = ET.parse(config).getroot()  # helyi, rendszergazdai konfiguráció
    except (OSError, ET.ParseError):
        root = None
    if root is not None:
        sites = root.find("system.applicationHost/sites")
        if sites is not None:
            defaults = sites.find("siteDefaults/logFile")
            if defaults is not None and defaults.get("directory"):
                base_default = defaults.get("directory", default_dir)
            for site in sites.findall("site"):
                site_id = site.get("id")
                if not site_id:
                    continue
                own = site.find("logFile")
                base = own.get("directory") if own is not None else None
                site_dirs.append(_expand(base or base_default) / f"W3SVC{site_id}")
    candidates = site_dirs or [_expand(base_default)]
    found: list[Path] = []
    for candidate in candidates:
        if candidate.is_dir() and candidate not in found:
            found.append(candidate)
    return found


def collect(
    folder: Path,
    *,
    since: datetime | None = None,
    include_iis: bool = True,
    channels: Sequence[str] = LIVE_CHANNELS,
    runner: Runner = _run_wevtutil,
    iis_config: Path | None = None,
    on_status: Callable[[str], None] | None = None,
) -> LiveSnapshot:
    """Az élő gép naplóinak pillanatképe a ``folder`` munkamappába."""
    if not is_windows() and runner is _run_wevtutil:
        raise LiveError(
            "élő gyűjtés csak Windowson lehetséges; más rendszeren adj meg --source "
            "útvonalat vagy --case adatbázist"
        )
    folder.mkdir(parents=True, exist_ok=True)
    snapshot = LiveSnapshot(
        host=platform.node() or "-", collected_at=datetime.now(UTC), folder=folder
    )
    for channel in channels:
        if on_status:
            on_status(f"Napló mentése: {channel}")
        snapshot.channels.append(export_channel(channel, folder, since, runner))
    if include_iis:
        snapshot.iis_dirs = iis_log_dirs(iis_config)
    return snapshot
