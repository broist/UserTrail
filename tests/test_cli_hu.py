from __future__ import annotations

import pytest
from typer.testing import CliRunner

from usertrail.cli import app
from usertrail.cli_hu import translate_error

runner = CliRunner()


def test_help_labels_are_hungarian() -> None:
    result = runner.invoke(app, ["timeline", "--help"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    out = result.output
    assert "Használat:" in out
    assert "[KAPCSOLÓK]" in out
    assert "Kapcsolók" in out
    assert "[alapértelmezés: hu]" in out
    assert "Megjeleníti ezt a súgót" in out
    for english in ("Usage:", "[OPTIONS]", "Options", "[default:", "Show this message"):
        assert english not in out


def test_group_usage_is_hungarian() -> None:
    result = runner.invoke(app, ["--help"], env={"COLUMNS": "200"})
    assert "PARANCS [ARGUMENTUMOK]..." in result.output
    assert "Parancsok" in result.output


def test_click_errors_are_hungarian() -> None:
    result = runner.invoke(app, ["timeline", "--usr", "x"], env={"COLUMNS": "200"})
    assert result.exit_code != 0
    assert "Nincs ilyen kapcsoló: --usr" in result.output
    assert "Hiba" in result.output
    missing = runner.invoke(app, ["ingest"], env={"COLUMNS": "200"})
    assert "Hiányzó argumentum" in missing.output


@pytest.mark.parametrize(
    ("english", "hungarian"),
    [
        (
            "Invalid value for '--lang': 'de' is not one of 'en', 'hu'.",
            "Érvénytelen érték ('--lang'): 'de' nem a lehetséges értékek egyike: 'en', 'hu'.",
        ),
        ("Missing option '--case'.", "Hiányzó kapcsoló: '--case'."),
        ("Got unexpected extra argument (x)", "Váratlan további argumentum: (x)"),
        ("No such command 'foo'.", "Nincs ilyen parancs: 'foo'."),
        ("Something unknown", "Something unknown"),
    ],
)
def test_translate_error(english: str, hungarian: str) -> None:
    assert translate_error(english) == hungarian
