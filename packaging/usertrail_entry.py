"""A PyInstaller-rel készülő önálló futtatható fájl belépési pontja."""

from usertrail.cli import app

if __name__ == "__main__":
    app(prog_name="usertrail")
