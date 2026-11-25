# Hozzájárulás a UserTrailhez

Köszönjük, hogy segítesz! A projekt nyelve a magyar: a kommentek, a docstringek, a
commit-üzenetek, a dokumentáció és a CLI szövegei is magyarul készülnek. Csak az azonosítók
(változó-, függvény- és osztálynevek) angolok. Az idővonal leírásai magyarul és angolul is
elérhetők (`--lang hu|en`).

## Fejlesztői környezet

```bash
python -m venv .venv
. .venv/bin/activate            # Windowson: .venv\Scripts\activate
pip install -e ".[dev]"
```

Pull request előtt ezeknek mind át kell menniük. A CI Linuxon, Windowson és macOS-en is
lefuttatja őket:

```bash
ruff check .
ruff format --check .
mypy            # strict mód
pytest
```

## Új eseménytípus hozzáadása

1. **Vegyél fel egy `EventSpec` bejegyzést** a `src/usertrail/mappings/event_map.py` fájl
   `EVENT_SPECS` listájába:

   ```python
   EventSpec(
       "Security", 4740, "account_locked", Category.LOCKOUT, Severity.MEDIUM,
       actor=None,                                     # nincs értelmes Subject
       target=("TargetUserName", "TargetDomainName", "TargetSid"),
       detail_fields=("CallerComputerName",),
   ),
   ```

   Az `actor` és a `target` megadja a műveletet végző és az elszenvedő fiók
   (felhasználónév, tartomány, SID) mezőinek nevét. A `detail_fields` mezői bekerülnek az
   esemény `details` szótárába, és a leírássablonban is használhatók.

2. **Írj leírássablont** az `action` (vagy a `message_key`) kulcshoz a
   `src/usertrail/i18n.py` fájlban, a `MESSAGES["hu"]` és a `MESSAGES["en"]` szótárba is.
   Használható helyőrzők: `{actor}`, `{target}`, `{src}`, valamint bármelyik részletmező neve,
   pl. `{CallerComputerName}`.

3. **Csak ha szükséges**, regisztrálj egy kis kezelőfüggvényt a csatorna parsermoduljában
   (pl. a `src/usertrail/parsers/security.py` fájl `HANDLERS` szótárában), amely utólag
   módosítja az eseményt: kódokat normalizál, súlyosságot emel, származtatott részleteket ad
   hozzá.

4. **Írj tesztet** egy kis JSON-fixture rekorddal a `tests/fixtures/` mappában. A rekord
   szerkezete ugyanaz legyen, mint amit az `evtx` csomag `records_json()` függvénye ad.

Új csatornához saját parserosztály kell, `channels` halmazzal és `parse()` metódussal, amelyet a
`src/usertrail/parsers/__init__.py` fájlban kell regisztrálni. A csatornát mindig a rekord
`Event.System.Channel` mezője határozza meg, sosem a fájlnév.

## Forensic alapszabályok

- A forrásfájlokba soha nem írunk, csak olvasásra nyitjuk meg őket.
- Minden idővonal-eseménynek legyen `raw_ref` hivatkozása (fájl + rekordszám).
- Egy hibás rekord soha nem állíthatja le a feldolgozást: számold meg és jelentsd.
- Amit nem bizonyít közvetlenül a napló, csak következtetünk rá (pl. IP-alapú korreláció),
  azt egyértelműen jelölni kell.

## A demo-vizsgálat újraépítése

Az `examples/demo/demo-case.db` a tesztek szintetikus fixture-jeiből készül. Ha a parserek vagy
a séma változnak, építsd újra, és frissítsd a mintariportot is:

```bash
python examples/build_demo.py
usertrail export --case examples/demo/demo-case.db --user kovacs.janos \
    --tz Europe/Budapest --pivot-ip --collapse -f html -o examples/demo/riport.html
```

Valódi naplót soha ne tegyél a repóba: a `.gitignore` az `.evtx`, `.log` és `.db` fájlokat
kizárja (a tesztfixture-ök és a demo-adatbázis kivételével).

## Kiadás

1. A `pyproject.toml` verziószámának emelése, a `CHANGELOG.md` kiegészítése.
2. Zöld ellenőrzések helyben és a CI-ban.
3. Csomag építése és próbatelepítése tiszta környezetbe: `python -m build` (vagy
   `pip wheel . --no-deps -w dist`), majd `pip install dist/usertrail-*.whl`.
4. Címke: `git tag -a vX.Y.Z -m "..."` és `git push origin vX.Y.Z`. A címke elindítja a
   `Kiadás` munkafolyamatot (`.github/workflows/release.yml`): ez Windowsra, Linuxra és
   macOS-re önálló futtatható fájlt épít, kipróbálja őket a demo-vizsgálaton, és a wheellel, a
   forráscsomaggal és a `SHA256SUMS.txt` fájllal együtt létrehozza a release-t (a leírás a
   CHANGELOG megfelelő része). Ha a release már létezik, csak a fájlokat tölti fel hozzá.

## Futtatható fájl építése helyben

```bash
pip install -e ".[exe]"
pyinstaller --noconfirm --clean --distpath build/exe --workpath build/pyi packaging/usertrail.spec
```

Az eredmény a `build/exe/usertrail(.exe)`. A `packaging/usertrail.spec` gyűjti be a
HTML-sablont, a csomag metaadatát (verziószám) és a `tzdata` időzóna-adatbázist; ha új
adatfájl kerül a csomagba, azt ott is fel kell venni.
