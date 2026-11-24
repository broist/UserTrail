"""A typer (és a beépített click-másolata) angol feliratainak magyarítása.

A typer ezeket a szövegeket nem teszi fordíthatóvá, ezért induláskor felülírjuk a
modulszintű konstansokat, és a hibaüzeneteket egy reguláris kifejezésekből álló
fordítótáblán vezetjük át. Minden lépés „legjobb igyekezet” elven működik: ha egy
későbbi typer-verzióban megváltozik egy belső név, az adott felirat angol marad, de a
program ettől nem áll le.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

# A rich_utils modul konstansai (panelcímek, alapérték- és kötelező-jelölés stb.).
RICH_CONSTANTS: dict[str, str] = {
    "DEPRECATED_STRING": "(elavult) ",
    "DEFAULT_STRING": "[alapértelmezés: {}]",
    "ENVVAR_STRING": "[környezeti változó: {}]",
    "REQUIRED_LONG_STRING": "[kötelező]",
    "ARGUMENTS_PANEL_TITLE": "Argumentumok",
    "OPTIONS_PANEL_TITLE": "Kapcsolók",
    "COMMANDS_PANEL_TITLE": "Parancsok",
    "ERRORS_PANEL_TITLE": "Hiba",
    "ABORTED_TEXT": "Megszakítva.",
    "RICH_HELP": "Súgó: [blue]'{command_path} {help_option}'[/]",
}

USAGE_PREFIX = "Használat: "
HELP_OPTION_TEXT = "Megjeleníti ezt a súgót, majd kilép."
USAGE_PIECES: dict[str, str] = {
    "[OPTIONS]": "[KAPCSOLÓK]",
    "COMMAND [ARGS]...": "PARANCS [ARGUMENTUMOK]...",
}

# Hibaüzenet-fordítások, a megadott sorrendben alkalmazva.
ERROR_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), replacement)
    for pattern, replacement in (
        (r"Value error, ", ""),
        (r"Invalid value for (.+?): ", r"Érvénytelen érték (\1): "),
        (r"^Invalid value: ", "Érvénytelen érték: "),
        (r"^Missing option (.+?)\.", r"Hiányzó kapcsoló: \1."),
        (r"^Missing argument (.+?)\.", r"Hiányzó argumentum: \1."),
        (r"^Missing parameter:? ?(.*?)\.?$", r"Hiányzó paraméter: \1."),
        (r"^Missing command\.", "Hiányzó parancs."),
        (r"^No such option: (\S+)", r"Nincs ilyen kapcsoló: \1"),
        (r"^No such command (.+?)\.", r"Nincs ilyen parancs: \1."),
        (r"Did you mean (.+?)\?", r"Erre gondoltál: \1?"),
        (r"\(Possible options: (.+?)\)", r"(Lehetséges kapcsolók: \1)"),
        (r"^Got unexpected extra arguments? \((.*)\)", r"Váratlan további argumentum: (\1)"),
        (r"^Option (.+?) requires an argument\.", r"A(z) \1 kapcsolónak értéket kell adni."),
        (r"(.+?) is not one of (.+?)\.$", r"\1 nem a lehetséges értékek egyike: \2."),
        (r"^Value (.+?) is not a valid (.+?)\.$", r"A(z) \1 érték nem érvényes \2."),
        (r"(.+?) does not exist\.$", r"\1 nem létezik."),
    )
)


def translate_error(message: str) -> str:
    """Egy typer/click hibaüzenet magyar változata (ismeretlen szöveg változatlan marad)."""
    for pattern, replacement in ERROR_PATTERNS:
        message = pattern.sub(replacement, message)
    return message


def _patch_rich_utils() -> None:
    try:
        from typer import rich_utils
    except ImportError:  # pragma: no cover - a rich nélküli typer nem használja ezeket
        return
    for name, value in RICH_CONSTANTS.items():
        if hasattr(rich_utils, name):
            setattr(rich_utils, name, value)

    original: Callable[[Any], None] | None = getattr(rich_utils, "rich_format_error", None)
    if original is None or getattr(original, "_usertrail_hu", False):
        return

    def rich_format_error(error: Any) -> None:
        format_message = error.format_message
        error.format_message = lambda: translate_error(format_message())
        original(error)

    rich_format_error._usertrail_hu = True  # type: ignore[attr-defined]
    # setattr: a typer típusjelzése szűkebb, mint amit a burkoló elfogad.
    setattr(rich_utils, "rich_format_error", rich_format_error)  # noqa: B010


def _patch_usage_prefix() -> None:
    try:
        from typer._click import formatting
    except ImportError:  # pragma: no cover
        return
    formatter_cls = getattr(formatting, "HelpFormatter", None)
    original = getattr(formatter_cls, "write_usage", None)
    if formatter_cls is None or original is None or getattr(original, "_usertrail_hu", False):
        return

    def write_usage(self: Any, prog: str, args: str = "", prefix: str | None = None) -> None:
        original(self, prog, args, USAGE_PREFIX if prefix is None else prefix)

    write_usage._usertrail_hu = True  # type: ignore[attr-defined]
    formatter_cls.write_usage = write_usage
    # A rich kiemelő a „Usage: ” előtagot keresi; a magyar előtagot is emelje ki.
    try:
        from typer import rich_utils

        highlights = rich_utils.highlighter.highlights
        translated = [
            h.replace("(?P<usage>Usage: )", f"(?P<usage>{USAGE_PREFIX})") for h in highlights
        ]
        # Példányszintű felülírás, a typer osztályszintű listáját nem módosítjuk.
        setattr(rich_utils.highlighter, "highlights", translated)  # noqa: B010
    except (ImportError, AttributeError):  # pragma: no cover
        pass


def _patch_help_option() -> None:
    try:
        from typer._click import core
    except ImportError:  # pragma: no cover
        return
    command_cls = getattr(core, "Command", None)
    original = getattr(command_cls, "get_help_option", None)
    if command_cls is None or original is None or getattr(original, "_usertrail_hu", False):
        return

    def get_help_option(self: Any, ctx: Any) -> Any:
        option = original(self, ctx)
        if option is not None and getattr(option, "help", None) == "Show this message and exit.":
            option.help = HELP_OPTION_TEXT
        return option

    get_help_option._usertrail_hu = True  # type: ignore[attr-defined]
    command_cls.get_help_option = get_help_option


def _patch_usage_pieces() -> None:
    """A használati sor helyőrzőinek ([OPTIONS], COMMAND [ARGS]...) fordítása."""
    try:
        from typer import core as typer_core
        from typer._click import core as click_core
    except ImportError:  # pragma: no cover
        return
    for cls in (getattr(click_core, "Command", None), getattr(typer_core, "TyperGroup", None)):
        original = getattr(cls, "collect_usage_pieces", None)
        if cls is None or original is None or getattr(original, "_usertrail_hu", False):
            continue

        def collect_usage_pieces(
            self: Any, ctx: Any, _original: Callable[[Any, Any], list[str]] = original
        ) -> list[str]:
            return [USAGE_PIECES.get(piece, piece) for piece in _original(self, ctx)]

        collect_usage_pieces._usertrail_hu = True  # type: ignore[attr-defined]
        cls.collect_usage_pieces = collect_usage_pieces


def apply() -> None:
    """Az összes magyarítás alkalmazása; többszöri hívása sem okoz gondot."""
    _patch_rich_utils()
    _patch_usage_prefix()
    _patch_usage_pieces()
    _patch_help_option()
