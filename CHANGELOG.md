# Változások

A formátum a [Keep a Changelog](https://keepachangelog.com/hu/1.1.0/) ajánlását követi, a
verziószámozás pedig a [Semantic Versioning](https://semver.org/lang/hu/) szabályait.

## [0.1.1] – 2026-11-25

### Új

- **Önálló futtatható fájlok** Windowsra (x64), Linuxra (x64) és macOS-re (Apple Silicon):
  Python telepítése nélkül futtathatók, a release-hez `SHA256SUMS.txt` hash-listával csatolva.
- Automatikus kiadási munkafolyamat (GitHub Actions): verziócímkére megépíti és a
  demo-vizsgálaton kipróbálja a futtatható fájlokat, majd létrehozza a release-t.

### Javítva

- Nem magyar nyelvű Windowson (pl. cp1252 kódlappal) a fájlba vagy csőbe irányított kimenet
  `UnicodeEncodeError`-ral leállt az „ő” és „ű” betűknél. Az átirányított kimenet mostantól
  UTF-8.

## [0.1.0] – 2026-11-25

Az első nyilvános kiadás.

### Új

- **Források:** Security, System, TerminalServices-LocalSessionManager és
  -RemoteConnectionManager, PowerShell/Operational EVTX-naplók és IIS W3C-naplók. A csatornát
  a rekordokból állapítja meg, nem a fájlnévből.
- **Események:** 4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4771, 4776, 4720, 4722, 4723,
  4724, 4725, 4726, 4738, 4740, 4767, 4781, 4728/4729, 4732/4733, 4756/4757, 1102, 4688, 4698;
  System 7045 és 104; RDP 21, 23, 24, 25, 1149; PowerShell 4104 (a több részre bontott
  szkriptblokkok összefűzve).
- **Identitás:** `DOMAIN\felhasználó`, UPN, név, SID és DN normalizálása; SID ↔ név térkép;
  átnevezés (4781) után a régi és az új névvel is a teljes előzmény; szereplő/célpont szerepek.
- **Vizsgálati adatbázis (SQLite):** `ingest` SHA-256 hash-sel, duplikáció-szűréssel,
  félbeszakadt betöltés újrafeldolgozásával és csatornánkénti lefedettséggel; `users`.
- **Idővonal:** `timeline` szűrőkkel (időszak, kategória, súlyosság, IP, gépfiókok),
  megjelenítési időzónával, magyar és angol leírásokkal.
- **IP-pivot:** a sikeres bejelentkezések IP-címeiről érkező webes kérések „korrelált” jelöléssel.
- **Figyelmeztetések:** naplótörlés, kiemelt csoportba vétel, jelszótalálgatás, fiókzárolás az
  előzményeivel, sok sikertelen bejelentkezés, munkaidőn kívüli bejelentkezés,
  jelszó-visszaállítás után új IP, perzisztencia.
- **Összevonás:** `--collapse` a zajos, ismétlődő eseményekre.
- **Kimenetek:** konzol, CSV (UTF-8 BOM, `.meta.json`), JSON Lines és önálló HTML-riport világos
  és sötét móddal.
- **Forrásállapot:** `sources` parancs a hiányzó naplók, a kikapcsoltnak tűnő auditálás, a
  felülírásra utaló rövid lefedettség és a naplótörlések jelzésére.
- **Demo:** szintetikus demo-vizsgálat és mintariport az `examples/demo` mappában.
- Magyar nyelvű CLI (a typer beépített feliratai is), dokumentáció és kód-kommentek.

[0.1.1]: https://github.com/broist/UserTrail/releases/tag/v0.1.1
[0.1.0]: https://github.com/broist/UserTrail/releases/tag/v0.1.0
