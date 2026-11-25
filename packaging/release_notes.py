"""Kiírja a CHANGELOG.md adott verzióhoz tartozó szakaszát (a release leírásához).

Használat: python packaging/release_notes.py 0.1.1 > notes.md
"""

import re
import sys
from pathlib import Path


def section(changelog: str, version: str) -> str:
    """Visszaadja a ``## [version]`` fejléc és a következő ``## [`` fejléc közötti szöveget."""
    lines: list[str] = []
    inside = False
    for line in changelog.splitlines():
        if line.startswith("## ["):
            if inside:
                break
            inside = line.startswith(f"## [{version}]")
            continue
        if inside and not re.match(r"^\[[^\]]+\]: ", line):
            lines.append(line)
    return "\n".join(lines).strip() + "\n"


if __name__ == "__main__":
    text = section(Path("CHANGELOG.md").read_text(encoding="utf-8"), sys.argv[1])
    if not text.strip():
        sys.exit(f"Nincs ilyen verzió a CHANGELOG.md-ben: {sys.argv[1]}")
    sys.stdout.buffer.write(text.encode("utf-8"))
