# UserTrail – felhasználóközpontú Windows forensic idővonal-építő

> Ez a fájl a projekt specifikációja és fejlesztési útmutatója Claude Code számára.
> Mielőtt bármilyen kódot írsz, olvasd végig. A fejlesztést a „Mérföldkövek” szakasz sorrendjében végezd.
> (A projektnév munkanév, később módosítható.)

## 1. Cél

Nyílt forráskódú parancssori eszköz, amely Windows-naplókból (EVTX) és IIS-logokból **egyetlen, időrendi idővonalat** készít **egy adott Active Directory felhasználóra** fókuszálva.

Tipikus használat: a vizsgáló beírja egy AD-fiók nevét, és látja, mi történt a fiókkal és a fiók által, időrendben:
bejelentkezések, sikertelen próbálkozások, jelszócserék, zárolások, csoporttagság-változások, RDP-munkamenetek, PowerShell-futtatások, és az ugyanarról az IP-ről érkező IIS-kérések.

**Ami megkülönbözteti a meglévő eszközöktől:** a Hayabusa, a Chainsaw és a plaso eseményközpontú (szabályok alapján keres gyanús eseményeket). Ez az eszköz **identitásközpontú**: egy fiók teljes életútját rakja össze több forrásból, szereplő/célpont szerepekkel és IP-alapú korrelációval.

A projektet nyilvánosan, GitHubon publikáljuk, ezért a dokumentáció, a tesztek és a kódminőség kiemelten fontos.

## 2. Hatókör

### Benne van (MVP)
- Offline elemzés: kimásolt `.evtx` fájlok és IIS W3C-logmappák feldolgozása.
- Security, System, RDP (TerminalServices), PowerShell/Operational naplók.
- IIS W3C logok.
- Felhasználónév-normalizálás (DOMAIN\user, UPN, SID, puszta név).
- Keresés felhasználóra, SID-re vagy IP-re, időszűréssel.
- IP-pivot: a felhasználó bejelentkezési IP-címeiről érkező IIS-kérések behúzása.
- Kimenet: konzol, CSV, önálló (self-contained) HTML-riport.
- Figyelmeztetések (pl. naplótörlés, kiemelt csoportba vétel).

### Később
- Sysmon-támogatás.
- Élő gyűjtés PowerShell-szkripttel (külön, opcionális komponens).
- További források: Task Scheduler Operational, Windows Defender, Prefetch, registry (UserAssist), MFT-időbélyegek.
- Sigma-szabályok illesztése.

### Nincs benne (non-goals)
- Az élő rendszer módosítása bármilyen módon.
- Valós idejű monitorozás vagy SIEM-funkciók.
- Grafikus asztali alkalmazás.

## 3. Technológia

- **Python 3.11+**
- `evtx` (PyPI, Rust-alapú, gyors EVTX-parser; `PyEvtxParser`, `records_json()`)
- `sqlite3` (standard könyvtár) tárolásra
- `typer` a CLI-hez
- `rich` a konzolos táblázatokhoz
- `jinja2` a HTML-riporthoz (a riport egyetlen fájl legyen, inline CSS/JS, külső függőség nélkül)
- `pytest` a tesztekhez, `ruff` a lintinghez és formázáshoz, `mypy` a típusellenőrzéshez
- Csomagkezelés: `pyproject.toml`

A programnak Windowson, Linuxon és macOS-en is futnia kell (offline elemzés miatt).

## 4. Könyvtárszerkezet

```
usertrail/
├── pyproject.toml
├── README.md
├── LICENSE                      # MIT vagy Apache-2.0
├── CONTRIBUTING.md
├── CLAUDE.md                    # ez a fájl
├── src/usertrail/
│   ├── __init__.py
│   ├── cli.py                   # typer parancsok
│   ├── models.py                # TimelineEvent dataclass, enumok
│   ├── identity.py              # névnormalizálás, SID-térkép
│   ├── timeutil.py              # UTC-normalizálás
│   ├── store.py                 # SQLite séma, beírás, lekérdezés
│   ├── correlate.py             # IP-pivot, aggregálás
│   ├── alerts.py                # figyelmeztetési szabályok
│   ├── health.py                # hiányzó források / audit policy jelzése
│   ├── parsers/
│   │   ├── base.py              # közös interfész
│   │   ├── evtx_reader.py       # EVTX → nyers dict (EventID, idő, EventData)
│   │   ├── security.py          # Security.evtx eseményleképezések
│   │   ├── system.py
│   │   ├── rdp.py
│   │   ├── powershell.py
│   │   └── iis.py
│   ├── mappings/
│   │   └── event_map.py         # Event ID → kategória, szerepek, leírássablon
│   └── report/
│       ├── console.py
│       ├── csv_export.py
│       ├── html_report.py
│       └── templates/report.html.j2
└── tests/
    ├── fixtures/                # minta EVTX és IIS log
    └── test_*.py
```

## 5. Egységes eseménymodell

Minden parser ilyen objektumokat ad vissza:

```python
@dataclass
class TimelineEvent:
    timestamp_utc: datetime        # mindig timezone-aware UTC
    source: str                    # "Security", "System", "RDP-LSM", "RDP-RCM", "PowerShell", "IIS"
    host: str                      # Computer mező vagy IIS szervernév
    event_id: str                  # EVTX Event ID, IIS esetén "IIS"
    category: Category             # enum, lásd lent
    action: str                    # rövid gépi kód, pl. "logon_success", "password_reset"
    actor: Identity | None         # aki a műveletet végezte (Subject)
    target: Identity | None        # akin a műveletet végezték (Target)
    src_ip: str | None
    description: str               # magyar nyelvű, emberi olvasásra szánt leírás
    details: dict                  # forrásspecifikus mezők (LogonType, Status, URI stb.)
    severity: Severity             # info / low / medium / high
    raw_ref: str                   # forrásfájl + rekordazonosító a visszakereséshez
```

`Category` értékei: `ACCOUNT_LIFECYCLE`, `AUTHENTICATION`, `PASSWORD`, `LOCKOUT`, `GROUP_MEMBERSHIP`, `PRIVILEGE`, `REMOTE_ACCESS`, `EXECUTION`, `PERSISTENCE`, `WEB`, `LOG_TAMPERING`.

A HTML-riportban és a konzolon is jól látszódjon, hogy a keresett felhasználó az eseményben **szereplő** (ő csinálta) vagy **célpont** (vele csinálták).

## 6. Adatforrások és eseményleképezés

### Csatornák és fájlnevek
| Csatorna | Tipikus fájlnév |
|---|---|
| Security | `Security.evtx` |
| System | `System.evtx` |
| RDP Local Session Manager | `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` |
| RDP Remote Connection Manager | `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx` |
| PowerShell | `Microsoft-Windows-PowerShell%4Operational.evtx` |
| IIS | `C:\inetpub\logs\LogFiles\W3SVC<n>\u_exYYMMDD.log` |

A csatornát **ne a fájlnévből**, hanem a rekord `Event.System.Channel` mezőjéből határozd meg (a fájlt átnevezhették).

### EVTX JSON-szerkezet buktatói (`evtx` csomag)
- `Event.System.EventID` lehet szám **vagy** `{"#attributes": {"Qualifiers": ...}, "#text": 7045}` alakú objektum. Mindkettőt kezeld.
- Idő: `Event.System.TimeCreated["#attributes"]["SystemTime"]` (UTC, ISO 8601).
- Gép: `Event.System.Computer`.
- A felhasználó SID-je egyes csatornákon: `Event.System.Security["#attributes"]["UserID"]`.
- Az adatmezők általában `Event.EventData` alatt névvel vannak, de az RDP-naplóknál `Event.UserData.EventXML` alatt.
- Hiányzó vagy `-` értékű mezőket `None`-ként kezeld.

### Security – fiók életciklusa és módosítások
| ID | action | Szereplő | Célpont | Megjegyzés |
|---|---|---|---|---|
| 4720 | account_created | SubjectUserName | TargetUserName | |
| 4722 | account_enabled | Subject | Target | |
| 4725 | account_disabled | Subject | Target | |
| 4726 | account_deleted | Subject | Target | severity: medium |
| 4738 | account_changed | Subject | Target | a változott attribútumok a details-be |
| 4781 | account_renamed | Subject | OldTargetUserName → NewTargetUserName | mindkét nevet kösd ugyanahhoz az identitáshoz |
| 4723 | password_change_attempt | Subject | Target | saját jelszó módosítása |
| 4724 | password_reset | Subject | Target | más általi visszaállítás, severity: medium |
| 4740 | account_locked | (rendszer) | TargetUserName | `CallerComputerName` = honnan jöttek a hibás próbálkozások |
| 4767 | account_unlocked | Subject | Target | |

### Security – csoporttagság
| ID | action |
|---|---|
| 4728 / 4729 | group_member_added / removed (globális) |
| 4732 / 4733 | group_member_added / removed (helyi) |
| 4756 / 4757 | group_member_added / removed (univerzális) |

**Fontos buktató:** ezekben az eseményekben a `TargetUserName` a **csoport neve**, a tag pedig a `MemberSid` és a `MemberName` (DN formátum, pl. `CN=Kovács János,OU=...`). A felhasználó azonosításához a `MemberSid`-et használd.

Kiemelt csoportba vétel legyen `high` severity. Az ismert RID-ek: 512 Domain Admins, 518 Schema Admins, 519 Enterprise Admins, 544 Administrators (BUILTIN). Ezeket a csoport SID-jének végéből lehet felismerni.

### Security – hitelesítés
| ID | action | Fontos mezők |
|---|---|---|
| 4624 | logon_success | TargetUserName, TargetDomainName, TargetUserSid, LogonType, IpAddress, WorkstationName, AuthenticationPackageName |
| 4625 | logon_failure | ugyanezek + Status, SubStatus |
| 4634 / 4647 | logoff | TargetUserName, TargetLogonId |
| 4648 | explicit_credentials | SubjectUserName (szereplő), TargetUserName, TargetServerName |
| 4672 | special_privileges | SubjectUserName, PrivilegeList |
| 4768 | kerberos_tgt | TargetUserName, IpAddress, Status |
| 4769 | kerberos_service_ticket | TargetUserName, ServiceName, IpAddress |
| 4771 | kerberos_preauth_failed | TargetUserName, IpAddress, FailureCode (0x18 = hibás jelszó) |
| 4776 | ntlm_validation | TargetUserName, Workstation, Status |

Logon Type leképezés (magyar leírással a riportban):
2 interaktív, 3 hálózati, 4 batch, 5 szolgáltatás, 7 feloldás, 8 hálózati tiszta szöveges, 9 új hitelesítő adatok (runas /netonly), 10 RDP, 11 gyorsítótárazott interaktív.

4625 SubStatus kódok (a details-ben és a leírásban is jelenjenek meg):
`0xC0000064` nem létező felhasználó, `0xC000006A` hibás jelszó, `0xC0000234` zárolt fiók, `0xC0000072` letiltott fiók, `0xC000006F` engedélyezett időn kívül, `0xC0000070` nem engedélyezett munkaállomás, `0xC0000071` lejárt jelszó, `0xC0000193` lejárt fiók, `0xC0000224` jelszócsere szükséges.

IP-címek: az `::ffff:` előtagot vágd le, a `-`, `::1`, `127.0.0.1` értékeket ne tekintsd külső IP-nek.

### Security – egyéb
| ID | action | Megjegyzés |
|---|---|---|
| 1102 | audit_log_cleared | mindig severity: high, külön figyelmeztetés |
| 4688 | process_created | NewProcessName, CommandLine, SubjectUserName (csak ha be van kapcsolva) |
| 4698 | scheduled_task_created | TaskName, TaskContent, SubjectUserName |

### System
| ID | action | Megjegyzés |
|---|---|---|
| 7045 | service_installed | ServiceName, ImagePath, AccountName; a felhasználó a System.Security UserID SID-jéből |
| 104 | log_cleared | severity: high |

### RDP
| Forrás | ID | action | Mezők |
|---|---|---|---|
| LocalSessionManager | 21 | rdp_logon | User (DOMAIN\user), Address |
| LocalSessionManager | 23 | rdp_logoff | User |
| LocalSessionManager | 24 | rdp_disconnect | User, Address |
| LocalSessionManager | 25 | rdp_reconnect | User, Address |
| RemoteConnectionManager | 1149 | rdp_auth_success | Param1 = user, Param2 = domain, Param3 = IP |

### PowerShell
| ID | action | Megjegyzés |
|---|---|---|
| 4104 | script_block | ScriptBlockText (a details-be, a leírásba csak rövidítve); a felhasználó a System.Security UserID SID-jéből. A több részre bontott szkripteket (MessageNumber/MessageTotal, ScriptBlockId) fűzd össze. |

### IIS (W3C)
- A mezősorrendet **mindig** a `#Fields:` direktívából olvasd. Egy fájlon belül több `#Fields:` sor is lehet (pl. újraindítás után), ilyenkor onnantól az új sorrend érvényes.
- Fontos mezők: `date`, `time`, `s-ip`, `cs-method`, `cs-uri-stem`, `cs-uri-query`, `s-port`, `cs-username`, `c-ip`, `cs(User-Agent)`, `sc-status`, `time-taken`.
- Az időbélyeg alapértelmezésben UTC. Legyen egy `--iis-tz` kapcsoló arra az esetre, ha a szerveren helyi időre állították.
- A `cs-username` lehet `DOMAIN\user` vagy UPN formátumú, ezt is normalizáld.
- A `-` érték üres mezőt jelent.
- A feldolgozás soronként, streamelve történjen (a logok több GB-osak lehetnek).

## 7. Identitás-normalizálás (`identity.py`)

- Bemenet lehet: `CEG\kovacs.janos`, `kovacs.janos@ceg.hu`, `kovacs.janos`, `S-1-5-21-...-1105`, illetve DN (`CN=...`).
- Összehasonlítás kis- és nagybetűtől függetlenül.
- Építs **SID ↔ név térképet** a feldolgozott eseményekből (pl. 4624 TargetUserSid + TargetUserName, 4720). Erre szükség van, mert egyes források (PowerShell, System) csak SID-et tartalmaznak.
- 4781 átnevezésnél a régi és az új név ugyanahhoz az identitáshoz kerüljön.
- A gépfiókokat (`$` végű név) alapértelmezésben szűrd ki a keresési találatokból, de legyen `--include-machine-accounts` kapcsoló.
- A jól ismert rendszerfiókokat (SYSTEM `S-1-5-18`, LOCAL SERVICE `S-1-5-19`, NETWORK SERVICE `S-1-5-20`, ANONYMOUS LOGON) jelöld külön.

## 8. Időkezelés

- Tárolás és rendezés kizárólag UTC-ben.
- Megjelenítéskor `--tz` kapcsolóval választható időzóna (alapértelmezés: a futtató gép helyi ideje, pl. `Europe/Budapest`). A riport fejlécében mindig szerepeljen, milyen időzónában vannak az időpontok.
- Azonos időbélyegű eseményeknél stabil rendezés: idő, majd forrás, majd rekordazonosító.

## 9. Tárolás (`store.py`)

- SQLite, egy vizsgálat = egy adatbázisfájl (pl. `case.db`).
- Indexek: `timestamp_utc`, `actor_key`, `target_key`, `src_ip`, `event_id`.
- Kötegelt beírás (pl. 5000 rekordonként), tranzakcióban.
- Külön táblában tárold a feldolgozott forrásfájlokat: elérési út, méret, **SHA-256 hash**, feldolgozás ideje, rekordszám, hibák száma. Ez a forensic dokumentáláshoz szükséges.
- Ugyanazt a fájlt kétszer ne dolgozd fel (hash alapján ellenőrizd).

## 10. Korreláció (`correlate.py`)

- **IP-pivot:** a felhasználó sikeres bejelentkezéseiből (4624, 4768, RDP 1149/21) gyűjtsd ki a forrás-IP-ket, és a `--pivot-ip` kapcsolóval vond be az ugyanerről az IP-ről érkező IIS-kéréseket egy állítható időablakon belül (alapértelmezés: ±1 óra a bejelentkezéstől). Ezeket a riportban jelöld „korrelált” eseményként, mert nem bizonyos, hogy ugyanaz a felhasználó volt.
- **Aggregálás:** az ismétlődő, zajos eseményeket (pl. sok 4624 Type 3 vagy 4769 ugyanarról az IP-ről) a `--collapse` kapcsolóval egy sorba lehessen vonni („42× hálózati bejelentkezés 10.0.0.5-ről, 09:00–09:15”).

## 11. Figyelmeztetések (`alerts.py`)

Az idővonalon kiemelten jelenjenek meg:
- napló törlése (Security 1102, System 104);
- kiemelt csoportba vétel (lásd RID-lista);
- fiók zárolása (4740), és az azt megelőző sikertelen próbálkozások összekötése;
- sok sikertelen bejelentkezés rövid időn belül (küszöb és időablak állítható, alapértelmezés: 10 db / 5 perc);
- sikeres bejelentkezés közvetlenül sok sikertelen után (lehetséges jelszótalálgatás);
- munkaidőn kívüli bejelentkezés (állítható, alapértelmezés: 07:00–19:00, hétköznap);
- jelszó-visszaállítás, amit után rövidesen bejelentkezés követ új IP-ről;
- új szolgáltatás vagy ütemezett feladat a felhasználó nevében.

## 12. Forrásállapot-ellenőrzés (`health.py`)

A `sources` parancs mutassa meg, milyen csatornák és mennyi esemény áll rendelkezésre, és jelezze, ha valami hiányzik. Például: „Nincs 4688-as esemény: a folyamatindítás auditálása valószínűleg nincs bekapcsolva.” Jelezze azt is, ha a Security napló túl rövid időszakot fed le (a legrégebbi és a legújabb esemény ideje), mert ez napló-felülírásra utalhat.

## 13. CLI

```
usertrail ingest <útvonal>... --case case.db [--iis-tz Europe/Budapest]
usertrail sources --case case.db
usertrail timeline --case case.db --user "kovacs.janos"
        [--sid S-1-5-21-...] [--ip 10.0.0.5]
        [--from 2026-11-01] [--to 2026-11-20] [--tz Europe/Budapest]
        [--category AUTHENTICATION,PASSWORD] [--min-severity medium]
        [--pivot-ip] [--collapse] [--include-machine-accounts]
usertrail export --case case.db --user ... --format csv|html|json -o kimenet.html
usertrail users --case case.db          # az összes ismert identitás listája
```

Az `ingest` mappát is kapjon, és rekurzívan ismerje fel a `.evtx` és az IIS `.log` fájlokat. A hibás vagy sérült rekordokat ne dobja el csendben: naplózza őket, és a végén összesítse.

## 14. Kimenetek

- **Konzol:** `rich` táblázat, oszlopok: idő, forrás, gép, esemény, szerep (szereplő/célpont), IP, leírás. Severity szerinti színezés.
- **CSV:** UTF-8 BOM-mal (hogy az Excel jól nyissa a magyar ékezeteket), Timeline Explorerrel kompatibilis oszlopnevekkel.
- **JSON:** JSON Lines formátum, gépi feldolgozáshoz.
- **HTML:** egyetlen önálló fájl, külső hivatkozás nélkül. Tartalmazza: összefoglaló (időszak, eseményszám kategóriánként, figyelmeztetések), szűrhető és kereshető idővonal, kategóriaszínek, szereplő/célpont jelölés, kinyitható részletek (nyers mezők), a feldolgozott forrásfájlok listája hash-ekkel, és a megjelenítési időzóna. Működjön világos és sötét módban is.

## 15. Forensic alapelvek

- A forrásfájlokat **csak olvasásra** nyisd meg, soha ne módosítsd őket.
- Minden forrásfájl SHA-256 hash-ét rögzítsd feldolgozás előtt.
- Minden idővonal-esemény legyen visszakereshető az eredeti fájlig és rekordig (`raw_ref`).
- A korrelált (nem közvetlenül bizonyított) kapcsolatokat egyértelműen jelöld.
- Az eszköz verziószáma és a futtatás paraméterei kerüljenek bele minden riportba.

## 16. Teljesítmény

- Streamelt feldolgozás, a teljes fájlt ne töltsd memóriába.
- Cél: egy 1 GB-os Security.evtx feldolgozása néhány perc alatt egy átlagos laptopon.
- Folyamatjelző (`rich.progress`) az `ingest` alatt.

## 17. Tesztelés

- Minden parserhez legyenek unit tesztek, kis minta-fixture-ökkel.
- Nyilvános minta EVTX-gyűjtemények (pl. a GitHubon elérhető „EVTX-ATTACK-SAMPLES”) használhatók tesztelésre; a licencüket ellenőrizd, mielőtt a repóba másolsz belőlük.
- Készíts szintetikus IIS-logot is, több `#Fields:` sorral és hibás sorokkal.
- Tesztek a névnormalizálásra (DOMAIN\user, UPN, SID, DN, átnevezés).
- Tesztek az időzóna-kezelésre.
- Integrációs teszt: ingest → timeline → HTML, ellenőrizve, hogy a várt események a várt sorrendben megjelennek.
- Ajánlott labor a valós teszteléshez: egy domain controller és egy IIS-szerver virtuális gépen, bekapcsolt Advanced Audit Policyval. A README-ben legyen leírva, milyen audit-beállításokat érdemes bekapcsolni.

## 18. Kódolási szabályok

- **Minden magyarul legyen** (a projekt gazdájának döntése, 2026-11-24; felülírja a korábbi, angol nyelvre vonatkozó szabályt): kommentek, docstringek, commit-üzenetek, README, CONTRIBUTING.md, a CLI súgó- és hibaüzenetei (a typer beépített feliratai is, lásd `cli_hu.py`), a kivételek szövegei, a CI lépésnevei és a Claude-dal folytatott kommunikáció.
- Kivételek: az azonosítók (változó-, függvény-, osztály- és modulnevek) angolok maradnak, mert a Python-ökoszisztémában ez a szokás; a LICENSE az MIT-licenc eredeti angol szövege (jogi okból); az `i18n.py` angol sablonjai a `--lang en` kimenethez kellenek.
- Commitokban és PR-leírásokban Claude ne szerepeljen szerzőként vagy társszerzőként (nincs `Co-Authored-By` sor).
- A riportban megjelenő emberi leírások **magyarul és angolul** is legyenek elérhetők: a leírássablonokat egy nyelvi fájlban tárold, `--lang hu|en` kapcsolóval (alapértelmezés: `hu`; az angol változat a nemzetközi közönségnek továbbra is elérhető).
- Típusannotációk mindenhol, `mypy --strict`-kel ellenőrizve.
- `ruff` formázás és linting.
- Az új eseménytípusok hozzáadása legyen egyszerű: egy bejegyzés az `event_map.py`-ban, és ha kell, egy kis kezelőfüggvény. Ezt a CONTRIBUTING.md-ben dokumentáld.
- Hibakezelés: egy hibás rekord soha ne állítsa le a teljes feldolgozást.

## 19. Mérföldkövek

Mindegyik végén legyenek zöld tesztek, és a funkció legyen kipróbálható a CLI-ből.

1. **Váz:** projektstruktúra, `pyproject.toml`, `models.py`, CLI-váz, CI (GitHub Actions: ruff, mypy, pytest).
2. **Security-parser, alapok:** EVTX-olvasó, 4624/4625/4634/4647/4648/4672, időnormalizálás, konzolos kimenet egy felhasználóra.
3. **Fiókkezelés:** 4720–4781, csoportesemények (MemberSid-kezeléssel), 4740/4767, identitás-normalizálás és SID-térkép.
4. **SQLite tárolás:** `ingest` és `timeline` szétválasztása, forrásfájl-hash-ek, duplikáció-ellenőrzés.
5. **IIS-parser:** `#Fields:`-kezelés, időzóna-kapcsoló, IP-pivot.
6. **További források:** Kerberos/NTLM, RDP, PowerShell 4104, System 7045, 1102/104.
7. **Figyelmeztetések és aggregálás.**
8. **Kimenetek:** CSV, JSON, HTML-riport.
9. **`sources` parancs és forrásállapot-ellenőrzés.**
10. **Kiadás:** README képernyőképekkel és példákkal, LICENSE, CONTRIBUTING.md, minta-adatkészlet, első release (v0.1.0) a GitHubon.

## 20. README tartalma (a 10. mérföldkőnél)

- Mire jó, egy képernyőképpel a HTML-riportról.
- Telepítés (`pip install`) és gyors kezdés három paranccsal.
- Hogyan gyűjtsük össze a naplókat egy Windows-szerverről (melyik fájlok, honnan).
- Ajánlott audit policy beállítások.
- A támogatott Event ID-k listája.
- Korlátok (pl. a korrelált IIS-találatok nem bizonyítékok).
- Hozzájárulási útmutató és licenc.

## 21. Megvalósítási jegyzetek (fejlesztés közben frissítendő)

- **Állapot:** 1–9. mérföldkő kész (váz, CI, EVTX-olvasó, Security hitelesítési, fiókkezelési, jelszó-, zárolási és csoporttagsági események, SID-térkép átnevezéssel, konzolos kimenet).
- **4740 buktató:** a `TargetDomainName` mező itt a hívó gép neve (Caller Computer Name), nem tartomány; a parser `CallerComputerName` néven teszi a details-be, a célfiók tartománya üres marad.
- **Csoportesemények:** a tag identitása csak a `MemberSid` (a DN-ből kinyert CN megjelenítendő név, nem sAMAccountName, ezért nem kerül a SID-térképbe). A leírásban a tag neve a DN CN-je; ha nincs DN, a SID-térképből feloldott név (`resolve_sid_only_names`), amely csak a megjelenítést módosítja, a tárolt identitást nem.
- **Átnevezés (4781):** a régi név a `TimelineEvent.aliases` mezőbe kerül ugyanazzal a SID-del; a `SidMap.learn_event` ezt is megtanulja, az `IdentityQuery.build` pedig fixpontig bővít, így a régi és az új névvel is a teljes előzmény megtalálható.
- **Sikeresség (4723/4724):** a `System.Keywords` auditbitjeiből (`RawRecord.keywords`), a details `Result` mezőjében `success`/`failure`.
- **Leírás nyelve:** a `TimelineEvent` nem kész szöveget tárol, hanem `message_key` + `message_params` mezőket; a szöveget a `description(lang)` metódus állítja elő a `usertrail/i18n.py` sablonjaiból. Így ugyanaz az adatbázis `--lang hu` és `--lang en` alatt is megjeleníthető.
- **Közvetlen mód:** a `timeline --source <fájl/mappa>` közvetlenül az EVTX-fájlokból dolgozik, adatbázis nélkül, gyors vizsgálatra. A `--case` és a `--source` kizárja egymást.
- **Tárolás (`store.py`):** `sources` (útvonal, méret, SHA-256, időpont, eszközverzió, rekord-/esemény-/hibaszám, hibaminták, `completed`), `events`, `aliases` (4781 régi nevek), `meta` (sémaverzió). Félbeszakadt betöltésnél (`completed = 0`) a következő `ingest` eldobja a részleges adatot és újra feldolgozza a fájlt. A `timeline --case` SQL-lel előszűr (név-, SID-, alias-, IP- és időfeltétel), a szerepeket és a további szűrést a `query.select` végzi. A `users` a SID-térkép alapján vonja össze ugyanannak a fióknak a SID nélküli és SID-es előfordulásait.
- **Szerep 4624/4625-nél:** a bejelentkező fiók `target`, mert a Subject általában a gépfiók/SYSTEM, amely a bejelentkezést lebonyolította.
- **Keresési logika:** `--user` és `--sid` ugyanarra az identitásra illeszkednek (VAGY kapcsolat), az `--ip` szűkít (ÉS). Csak `--ip` esetén minden olyan esemény megjelenik, amelynek forrás-IP-je egyezik.
- **IIS (`parsers/iis.py`):** nem a RawRecord/EVTX-úton megy, közvetlenül TimelineEvent-et ad. Felismerés: `.log` kiterjesztés + `#Fields:`/IIS `#Software:` az első 4 KB-ban. `raw_ref` = fájl#sorszám. Hibás sor: eltérő mezőszám, `#Fields:` előtti adatsor, rossz dátum/idő; ezeket a ReadStats számolja. 401/403 = low súlyosság. A `cs-username` a szereplő (actor). Az `--iis-tz` a `sources.options` mezőben (`{"iis_tz": ...}`) rögzül; ehhez a séma 2-es verzióra lépett, az 1-es adatbázisokat a `CaseStore` automatikusan migrálja. Az SQL-sémában ne legyen `--` komment (az SQLite ALTER TABLE a tárolt CREATE TABLE szöveget írja át).
- **IP-pivot (`correlate.py`):** pivotpontok = a felhasználó sikeres bejelentkezései (`SEED_ACTIONS`: logon_success, kerberos_tgt, rdp_auth_success, rdp_logon) külső IP-vel, a kategória-/súlyosságszűrőtől függetlenül. A ±ablakon belüli IIS-kérések `Role.CORRELATED` szerepet kapnak, a `TimelineRow.correlated_with` a bejelentkezés raw_ref-je. A közvetlenül (felhasználónévvel) illeszkedő kérések nem duplikálódnak.
- **Parser-architektúra:** a `parsers.Dispatcher` fájlonként új parserpéldányokat hoz létre (`new_parsers()`), a fájl végén `finish()`. A legtöbb csatorna `MappedParser` (event_map + kezelőfüggvények); a `PowerShellParser` állapotot tart (ScriptBlockId szerint gyűjti a részeket; a fájl végén a hiányos blokkokat `Incomplete` jelöléssel adja ki). Csatornanevek és forráscímkék: `event_map.SOURCE_LABELS`.
- **Mezőértékek:** az EVTX-olvasó a szöveges értékeket nem vágja (strip), mert az a bizonyíték módosítása lenne; csak az üres és a `-` értékből lesz None. Ahol összehasonlításhoz tisztítani kell, az `identity.clean` vágja le a szóközöket.
- **Kerberos/NTLM:** sikertelen 4768/4769-nél az action `*_failure` (low), 4776-nál `ntlm_validation_failure`; így a pivotpontok (`SEED_ACTIONS`) csak a sikeres kérések. A Kerberos-kódok rövid hexa alakban (`0x18`), szövegük `i18n.KERBEROS_CODES`.
- **IP-validálás:** a `normalize_ip` csak érvényes IP-címet ad vissza (az RDP `LOCAL` értéke None lesz, az eredeti a details-ben marad).
- **Figyelmeztetések (`alerts.py`):** a szabályok a keresett identitás (vagy IP) összes során futnak, a kategória-/súlyosságszűrőtől függetlenül (csak időszakszűrő). Minden `Alert` hivatkozik az érintett `raw_ref`-ekre (`raw_ref` + `related`); a konzol ezek alapján jelöli a sorokat „!”-lel. A fiók kulcsa a target (ennek hiányában az actor) SID-je vagy neve. A munkaidő a `--tz` (megjelenítési) időzónában értendő. A szövegek az `i18n` `alert.*` és `rule.*` kulcsai alatt.
- **Összevonás (`correlate.collapse_rows`):** csak `COLLAPSIBLE_ACTIONS` és legfeljebb low súlyosság; kulcs: forrás, gép, művelet, szerep, IP, fiók, LogonType, HTTP-metódus és -státusz; a közbeékelt más események nem szakítják meg. Az összevont `TimelineRow.members` az összes eseményt megőrzi; a leírást a `report/text.row_description` adja (a CSV/HTML is ezt használja majd).
- **Motor (`engine.py`):** a `timeline` és az `export` közös része: `TimelineRequest` → `build_timeline` → `TimelineResult` (sorok, figyelmeztetések, forrásfájlok hash-ekkel, futtatási paraméterek). Közvetlen (`--source`) módban is minden fájl SHA-256 hash-e kiszámolódik a riporthoz. A CLI közös kapcsolói típusaliasok (`SourceOpt`, `UserOpt` …), a `_make_request` ellenőrzi és gyűjti össze őket.
- **Kimenetek (`report/export.py`, `report/html_report.py`):** mindhárom formátum a `row_record` sorleírásból dolgozik. A CSV oszlopnevei szándékosan angolok (Timeline Explorer-kompatibilitás), a metaadat a `<név>.meta.json` fájlba kerül. A HTML-sablon (`report/templates/report.html.j2`) jinja2 autoescape-pel készül (a naplóból származó szöveg nem futhat le), külső hivatkozás nélkül; a wheelbe a hatchling automatikusan belecsomagolja. Csak SID-del azonosított fióknál a riport a SID-térképből feloldott nevet mutatja (csoporteseménynél a `member` paramétert).
- **Lefedettség és forrásállapot (`health.py`):** a `ReadStats.observe` csatornánként gyűjti a rekordszámot és a legkorábbi/legkésőbbi időpontot az összes beolvasott rekordból (a pipeline EVTX-rekordonként, az IIS-olvasó soronként hívja); az ingest a `sources.coverage` oszlopba írja (séma 3, a `_add_column_if_missing` miatt a migrációk idempotensek). Régebbi adatbázisnál a `summarize` az események időtartományából becsül (`records = None`). A `check` megállapításai `health.*` i18n-kulcsok; a figyelmeztetések állnak elöl.
- **Licenc:** MIT.
- **Nyelv:** a `--lang` alapértéke `hu` (`i18n.DEFAULT_LANG`). A typer/click beépített feliratait (Usage, Options, [default: …], --help, hibaüzenetek) a `usertrail/cli_hu.py` magyarítja induláskor, „legjobb igyekezet” elven: ha egy typer-frissítés megváltoztatja a belső neveket, a felirat angolra esik vissza; ezt a `tests/test_cli_hu.py` jelzi.
- **Fejlesztői környezet (Windows):** Python 3.12 felhasználói telepítés, projekt-venv a `.venv` mappában (`pip install -e ".[dev]"`). Ellenőrzés: `.venv\Scripts\ruff check .`, `ruff format --check .`, `mypy`, `pytest`. A `ruff` a `*.md` fájlokat nem formázza (különben a specifikáció kódrészleteit átírná).
- **Az `evtx` csomag** saját típusjelzéseket hoz; a `records_json()` iterátor `__next__`-je `Any | None`, ezt az olvasó kezeli.
