# UserTrail

**Felhasználóközpontú Windows forensic idővonal-építő.**

Adj meg a UserTrailnek egy Active Directory fióknevet és a begyűjtött Windows-eseménynaplókat
(EVTX) és IIS-logokat: egyetlen, időrendi idővonalat kapsz arról, mi történt a fiókkal és mit
csinált a fiók. Benne vannak a bejelentkezések, a sikertelen próbálkozások, a jelszócserék, a
zárolások, a csoporttagság-változások, az RDP-munkamenetek, a PowerShell-futtatások és az
ugyanarról az IP-ről érkező webes kérések.

A Hayabusa, a Chainsaw és a plaso eseményközpontú eszközök: szabályok alapján keresnek gyanús
eseményeket. A UserTrail identitásközpontú: egy fiók teljes történetét rakja össze több
forrásból, és minden eseménynél jelzi, hogy a fiók **szereplő** volt (ő csinálta) vagy
**célpont** (vele csinálták).

> **Állapot:** korai fejlesztés (pre-alpha). Kész az 1–8. mérföldkő: EVTX- és IIS-naplók
> betöltése SQLite vizsgálati adatbázisba (SHA-256 hash-sel, duplikáció-szűréssel), illetve
> közvetlen olvasása, IP-pivot a webes kérésekre, figyelmeztetések, a zajos események
> összevonása, CSV-, JSON Lines- és önálló HTML-riport, és az alábbi események:
>
> - bejelentkezés: 4624, 4625, 4634, 4647, 4648, 4672
> - fiókok életciklusa: 4720, 4722, 4725, 4726, 4738, 4781 (átnevezés után a régi és az új
>   névvel is megtalálható a teljes előzmény)
> - jelszó: 4723, 4724; zárolás: 4740, 4767
> - csoporttagság: 4728/4729, 4732/4733, 4756/4757; a kiemelt csoportba vétel (Domain Admins,
>   Schema Admins, Enterprise Admins, Administrators) magas súlyosságú
> - Kerberos és NTLM: 4768, 4769, 4771, 4776 (sikertelen kéréseknél a hibakód szövegesen)
> - egyéb Security: 1102 (naplótörlés), 4688 (folyamatindítás), 4698 (ütemezett feladat)
> - System: 7045 (szolgáltatástelepítés), 104 (naplótörlés)
> - RDP: LocalSessionManager 21/23/24/25, RemoteConnectionManager 1149
> - PowerShell 4104: a több részre bontott szkriptblokkok összefűzve; a hiányos blokkok
>   jelölve
> - IIS W3C-naplók: a mezősorrend mindig a `#Fields:` sorból, akár fájlon belül változva

## Gyors kezdés (fejlesztői telepítés)

```bash
python -m venv .venv
. .venv/bin/activate            # Windowson: .venv\Scripts\activate
pip install -e ".[dev]"

usertrail timeline --source ./bizonyitekok/ --user "CEG\kovacs.janos" --tz Europe/Budapest
usertrail timeline --source Security.evtx --ip 10.0.0.5 --lang en
```

A `--user` elfogadja a `DOMAIN\felhasználó`, az UPN (`felhasználó@domain`) és a puszta név
alakot, a `--sid` pedig SID-et vár. A nevek összehasonlítása kis- és nagybetűtől független, és
az eszköz a naplókból tanult SID-ekhez köti őket, így a csak SID-et tartalmazó események is
megtalálhatók.

### Vizsgálati adatbázissal

```bash
usertrail ingest ./bizonyitekok/ --case ugy-2026-11.db     # betöltés, hash-ek rögzítése
usertrail users --case ugy-2026-11.db                      # ismert fiókok listája
usertrail timeline --case ugy-2026-11.db --user kovacs.janos --tz Europe/Budapest
```

Az `ingest` minden fájl SHA-256 hash-ét rögzíti feldolgozás előtt, és a már betöltött fájlokat
(azonos hash) kihagyja, így többször is lefuttatható ugyanarra a mappára.

### Kipróbálás a saját gépeden

A saját Windows-gépeden is ki tudod próbálni. A naplók kimentéséhez rendszergazdai
PowerShell kell:

```powershell
mkdir C:\usertrail-proba
wevtutil epl Security C:\usertrail-proba\Security.evtx
wevtutil epl System C:\usertrail-proba\System.evtx
wevtutil epl Microsoft-Windows-PowerShell/Operational C:\usertrail-proba\PowerShell.evtx
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational C:\usertrail-proba\RDP-LSM.evtx
```

Ezután (nem kell rendszergazdai jog):

```powershell
usertrail ingest C:\usertrail-proba --case C:\usertrail-proba\proba.db
usertrail users --case C:\usertrail-proba\proba.db
usertrail timeline --case C:\usertrail-proba\proba.db --user $env:USERNAME --tz Europe/Budapest
```

Egy munkaállomáson főleg bejelentkezési események (4624, 4634, 4672) lesznek; a fiókkezelési és
csoporttagsági események a tartományvezérlő Security-naplójában vannak. A kimentett napló
érzékeny adatokat tartalmaz: ne tedd a repóba (a `.gitignore` az `.evtx` fájlokat kizárja), és
próba után töröld.

### IIS-naplók és IP-pivot

Az IIS-naplókat (`C:\inetpub\logs\LogFiles\W3SVC<n>\u_exYYMMDD.log`) a `.log` kiterjesztés és a
W3C-fejléc alapján ismeri fel, így elég a mappát megadni. Az IIS alapból UTC-ben naplóz; ha a
szerveren helyi időre állították, add meg az `--iis-tz Europe/Budapest` kapcsolót (az
adatbázisban fájlonként rögzül, milyen időzónával lett betöltve).

```bash
usertrail ingest ./dc01/ ./web01/W3SVC1/ --case ugy.db
usertrail timeline --case ugy.db --user kovacs.janos --pivot-ip --pivot-window 60
```

A felhasználó nevével naplózott webes kérések (`cs-username`) közvetlen találatok. A
`--pivot-ip` ezen felül behúzza azokat a kéréseket is, amelyek a felhasználó **sikeres
bejelentkezéseinek** IP-címeiről érkeztek a bejelentkezés előtt/után ±`--pivot-window` percen
belül. Ezek **„korrelált (IP)”** jelölést kapnak, mert nem bizonyítják, hogy a kérést ugyanaz a
felhasználó küldte (ugyanarról az IP-ről mások is dolgozhattak, pl. NAT vagy terminálszerver
mögül).

### Exportálás: CSV, JSON Lines, HTML-riport

Az `export` ugyanazokat a szűrőket és kapcsolókat fogadja, mint a `timeline`:

```bash
usertrail export --case ugy.db --user kovacs.janos --tz Europe/Budapest -f html -o riport.html
usertrail export --case ugy.db --user kovacs.janos -f csv -o idovonal.csv
usertrail export --case ugy.db --user kovacs.janos -f json -o idovonal.jsonl
```

- **HTML:** egyetlen önálló fájl, külső hivatkozás nélkül (hálózat nélkül is megnyitható,
  bizonyítékként átadható). Tartalma: összefoglaló (időszak, eseményszám kategóriánként és
  súlyosság szerint), figyelmeztetések, kereshető és szűrhető idővonal (kategória, szerep,
  súlyosság, csak figyelmeztetéses sorok), kategóriaszínek, szereplő/célpont jelölés,
  kinyitható részletek a nyers mezőkkel és az eredeti rekord hivatkozásával, a feldolgozott
  forrásfájlok listája SHA-256 hash-sel, a megjelenítési időzóna, az eszközverzió és a futtatás
  paraméterei. Világos és sötét módban is működik.
- **CSV:** UTF-8 BOM-mal, hogy az Excel jól nyissa az ékezeteket. Az oszlopnevek angolok
  (`Timestamp`, `Source`, `EventID`, `Description` …), mert ezeket gépi eszközök, pl. a Timeline
  Explorer dolgozzák fel. Mellé egy `<név>.meta.json` kerül a futtatás paramétereivel, a
  forrásfájlok hash-eivel és a figyelmeztetésekkel.
- **JSON Lines:** az első sor a metaadat (`"type": "meta"`), utána a figyelmeztetések
  (`"alert"`), majd az események (`"event"`).

### Figyelmeztetések

Az idővonal alatt egy „Figyelmeztetések” tábla jelenik meg, az érintett sorokat pedig „!” jelöli.
A szabályok a keresett fiók összes eseményén futnak, a `--category` és a `--min-severity`
szűrőtől függetlenül (csak az időszakszűrő érvényes):

| Szabály | Mikor jelez | Súlyosság |
|---|---|---|
| Naplótörlés | Security 1102, System 104 | magas |
| Kiemelt csoport | Domain/Schema/Enterprise Admins vagy Administrators csoportba vétel | magas |
| Lehetséges jelszótalálgatás | sikeres bejelentkezés legalább 5 sikertelen után, 5 percen belül | magas |
| Fiókzárolás | 4740, az előző 30 perc sikertelen próbálkozásaival összekötve | közepes |
| Sikertelen bejelentkezések | legalább 10 hiba 5 percen belül (`--fail-threshold`, `--fail-window`) | közepes |
| Jelszó-visszaállítás + új IP | 4724 után 1 órán belül bejelentkezés korábban nem látott IP-ről | közepes |
| Perzisztencia | új szolgáltatás (7045) vagy ütemezett feladat (4698) a felhasználó nevében | közepes |
| Munkaidőn kívül | interaktív/RDP-bejelentkezés munkaidőn kívül (`--work-hours`, hétköznap, `--tz` szerint) | alacsony |

Sikertelen bejelentkezésnek számít a 4625, a 4771, a sikertelen 4768 és a sikertelen 4776.

### Zajos események összevonása

A `--collapse` az ismétlődő eseményeket (pl. sok hálózati bejelentkezés vagy Kerberos-jegy
ugyanarról az IP-ről) egy sorba vonja: „42× sikeres bejelentkezés (3 hálózati): CEG\kovacs.janos,
forrás: 10.0.0.5 (09:00:00 – 09:15:00)”. Csak az információ és alacsony súlyosságú eseményeket
vonja össze, legalább 3-at, ha egymást legfeljebb `--collapse-gap` percen belül követik.

Hasznos kapcsolók:

| Kapcsoló | Jelentés |
|---|---|
| `--from` / `--to` | Időszak a megjelenítési időzónában; egy dátum az egész napot jelenti |
| `--tz` | Megjelenítési időzóna, pl. `Europe/Budapest` (alapértelmezés: a gép helyi ideje) |
| `--category` | Kategóriák vesszővel elválasztva, pl. `AUTHENTICATION,PRIVILEGE` |
| `--min-severity` | Legalacsonyabb súlyosság: `info`, `low`, `medium`, `high` |
| `--include-machine-accounts` | A `$` végű gépfiókok eseményei is látszanak |
| `--pivot-ip` | Webes kérések bevonása a bejelentkezési IP-címekről (korrelált jelöléssel) |
| `--pivot-window` | Az IP-pivot időablaka percben (alapértelmezés: 60) |
| `--iis-tz` | Az IIS-naplók időzónája, ha nem UTC-ben naplóznak |
| `--collapse`, `--collapse-gap` | Zajos események összevonása (alapértelmezett szünet: 15 perc) |
| `--fail-threshold`, `--fail-window` | Sikertelen bejelentkezések küszöbe (10) és időablaka (5 perc) |
| `--work-hours` | Munkaidő, pl. `07:00-19:00` (hétköznap) |
| `--no-alerts` | Figyelmeztetések kikapcsolása |
| `--lang` | A leírások nyelve: `hu` (alapértelmezés) vagy `en` |

Az eszköz a forrásfájlokat mindig csak olvasásra nyitja meg.

## Fejlesztés

```bash
ruff check . && ruff format --check .
mypy
pytest
```

Új Event ID támogatásának hozzáadásáról a [CONTRIBUTING.md](CONTRIBUTING.md) ír.

## Licenc

MIT, lásd: [LICENSE](LICENSE).
