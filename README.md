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

> **Állapot:** korai fejlesztés (pre-alpha). Kész az 1–2. mérföldkő: az EVTX-fájlok közvetlen
> olvasása és a Security bejelentkezési események (4624, 4625, 4634, 4647, 4648, 4672)
> megjelenítése a konzolon.

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

Hasznos kapcsolók:

| Kapcsoló | Jelentés |
|---|---|
| `--from` / `--to` | Időszak a megjelenítési időzónában; egy dátum az egész napot jelenti |
| `--tz` | Megjelenítési időzóna, pl. `Europe/Budapest` (alapértelmezés: a gép helyi ideje) |
| `--category` | Kategóriák vesszővel elválasztva, pl. `AUTHENTICATION,PRIVILEGE` |
| `--min-severity` | Legalacsonyabb súlyosság: `info`, `low`, `medium`, `high` |
| `--include-machine-accounts` | A `$` végű gépfiókok eseményei is látszanak |
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
