# UserTrail

**Identity-centric Windows forensic timeline builder.**

Give UserTrail an Active Directory account name and a pile of collected Windows event
logs (EVTX) and IIS logs, and it builds one chronological timeline of what happened *to*
and *by* that account: logons, failed attempts, password changes, lockouts, group
membership changes, RDP sessions, PowerShell activity, and web requests from the same IP.

Tools like Hayabusa, Chainsaw and plaso are event-centric: they hunt for suspicious
events with rules. UserTrail is identity-centric: it reconstructs the full story of one
account across sources, marking whether the account was the **actor** or the **target**.

> **Status:** early development (pre-alpha). Milestones 1–2 are done: direct EVTX reading
> and Security logon events (4624, 4625, 4634, 4647, 4648, 4672) on the console.

## Quick start (development)

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

usertrail timeline --source ./evidence/ --user "CEG\kovacs.janos" --tz Europe/Budapest
usertrail timeline --source Security.evtx --ip 10.0.0.5 --lang hu
```

`--user` accepts `DOMAIN\user`, a UPN (`user@domain`) or a bare name; `--sid` takes a
SID. Names are matched case-insensitively and linked to SIDs learnt from the logs.

Useful options: `--from` / `--to` (dates in the display time zone; a date covers the
whole day), `--category AUTHENTICATION,PRIVILEGE`, `--min-severity low`,
`--include-machine-accounts`, `--lang en|hu`.

Source files are always opened read-only.

## Development

```bash
ruff check . && ruff format --check .
mypy
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add support for a new event ID.

## License

MIT, see [LICENSE](LICENSE).
