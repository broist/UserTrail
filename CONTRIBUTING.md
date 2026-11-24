# Contributing to UserTrail

Thanks for helping! Code, comments and commit messages are in English. User-facing
descriptions exist in English and Hungarian.

## Setup

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Before opening a pull request, all of these must pass (CI runs them on Linux, Windows and
macOS):

```bash
ruff check .
ruff format --check .
mypy            # strict mode
pytest
```

## Adding a new event type

1. **Add an `EventSpec`** to `EVENT_SPECS` in `src/usertrail/mappings/event_map.py`:

   ```python
   EventSpec(
       "Security", 4740, "account_locked", Category.LOCKOUT, Severity.MEDIUM,
       actor=None,                                     # no meaningful Subject
       target=("TargetUserName", "TargetDomainName", "TargetSid"),
       detail_fields=("CallerComputerName",),
   ),
   ```

   `actor` / `target` name the (user name, domain, SID) fields of the account that did the
   action and the account it was done to. `detail_fields` are copied into the event's
   `details` and are available to the description template.

2. **Add description templates** for the `action` (or `message_key`) in
   `src/usertrail/i18n.py`, in both `MESSAGES["en"]` and `MESSAGES["hu"]`. Placeholders:
   `{actor}`, `{target}`, `{src}` and any detail field name, e.g. `{CallerComputerName}`.

3. **Only if needed**, register a small handler in the channel's parser module (for
   example `HANDLERS` in `src/usertrail/parsers/security.py`) to adjust the built event:
   normalise codes, raise severity, add derived details.

4. **Add a test** with a small JSON fixture record under `tests/fixtures/` (the same shape
   that `evtx`'s `records_json()` produces).

A new channel needs its own parser class with a `channels` set and a `parse()` method,
registered in `src/usertrail/parsers/__init__.py`. Dispatch is always on the record's
`Event.System.Channel`, never on the file name.

## Forensic ground rules

- Never write to source files; open them read-only.
- Every timeline event must keep a `raw_ref` (file + record number).
- A broken record must never abort processing: count and report it.
- Anything inferred rather than proven (e.g. IP-based correlation) must be marked so.
