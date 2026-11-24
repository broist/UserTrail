# Hozzájárulás a UserTrailhez

Köszönjük, hogy segítesz! A kód, a változónevek és a kommentek angolul készülnek, hogy külföldi
hozzájárulók is dolgozhassanak rajta. A commit-üzenetek és a dokumentáció magyarul íródnak. A
felhasználónak szóló leírások magyarul és angolul is elérhetők.

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
       actor=None,                                     # no meaningful Subject
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
