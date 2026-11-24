"""UserTrail: felhasználóközpontú Windows forensic idővonal-építő."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("usertrail")
except PackageNotFoundError:  # pragma: no cover - telepítés nélkül, forrásfából futtatva
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
