# PyInstaller-leírás az önálló, egyfájlos usertrail futtatható fájlhoz.
# Építés a projekt gyökeréből: pyinstaller packaging/usertrail.spec
# ruff: noqa
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

datas = []
# A HTML-riport jinja2-sablonja.
datas += collect_data_files("usertrail", includes=["report/templates/*"])
# A verziószám az importlib.metadata-ból jön, ezért a csomag metaadata is kell.
datas += copy_metadata("usertrail")
# Az időzóna-adatbázis (Windowson nincs rendszerszintű IANA-adatbázis).
datas += collect_data_files("tzdata")

hiddenimports = []
hiddenimports += collect_submodules("rich")
hiddenimports += collect_submodules("tzdata")
hiddenimports += ["evtx"]

a = Analysis(
    ["usertrail_entry.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "mypy", "ruff"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="usertrail",
    debug=False,
    strip=False,
    upx=False,
    console=True,
)
