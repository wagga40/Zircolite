# Contributing to Zircolite

## Setting up

Zircolite uses [PDM](https://pdm-project.org/) for dependency management.

```bash
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite
pdm install --dev
```

A plain virtualenv works too:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-timeout
```

## Running the tests

```bash
pdm run pytest                                            # everything
pdm run pytest tests/test_zircore.py                      # one file
pdm run pytest tests/test_zircore.py::TestZircoliteCoreInit::test_init_creates_in_memory_db
pdm run pytest -k "event_filter"                          # by name
pdm run pytest -m "not slow"                              # skip slow tests
pdm run pytest --cov=zircolite --cov-report=term-missing   # with coverage
```

Markers: `slow`, `integration`, `requires_lxml`, `requires_sigma`,
`requires_py7zr`.

The suite must be green before you open a pull request; CI runs it on every
push and pull request across Linux, macOS and Windows.

`.forgejo/workflows/` mirrors those workflows for a self-hosted Forgejo
instance, so CI can be rehearsed before pushing. It covers Linux x86_64 only —
see `.forgejo/README.md` for what it does and does not reach, and note that
Forgejo ignores `.github/workflows/` entirely whenever `.forgejo/` is present.

### Test fixtures are tracked

`tests/fixtures/` holds real sample logs (EVTX, auditd, Sysmon for Linux,
EVTXtract, XML, JSON) and they are committed. The end-to-end tests that read
them assert the fixture exists rather than skipping, because a skipped test is
not a passing one — and tests that quietly skipped are how several silent
ingestion bugs survived in the past. The blanket `*.evtx` / `*.log` rules in
`.gitignore` are for user data and are negated for this directory.

## Linting and types

```bash
pdm run ruff check .          # must be clean; CI fails on any finding
pdm run ruff check --fix .    # most findings fix themselves
pdm run python -m mypy zircolite   # must be clean too
```

Both are clean and both block in CI. The type check names the package, not the
tree, and that is not a gap: `zircolite.py` is a shim over `zircolite/cli.py`,
so every line that ships is inside the package. Naming `zircolite.py` there as
well would abort the run rather than widen it — the script shares its name with
the package. Keep logic out of it; `tests/test_entry_point.py` enforces that.

The rule set and its exemptions live in
`[tool.ruff.lint]` in `pyproject.toml`, and `ruff` is pinned as a dev
dependency — left undeclared it ran from `PATH` against whatever rule set that
build shipped, so a regression looked exactly like an upgrade.

If a rule is wrong for a specific line, silence that line with a reason
(`# noqa: S608 - values are bound parameters`) rather than widening the global
ignore list. `ruff format` is deliberately *not* enforced: running it over this
codebase would rewrite most of it and bury every behavioural diff.

## What matters most in this codebase

Zircolite is a detection tool, so **a rule that silently matches nothing is the
worst possible failure**: it is indistinguishable from a clean estate. When you
touch detection or ingestion, prefer failing loudly over failing quietly.

Concretely:

- Never swallow an exception into an empty result. If a rule cannot run, record
  it (`ZircoliteCore._note_broken_rule`) so it reaches the run summary.
- If a reader cannot finish a file, mark the run degraded. `--remove-events`
  deletes source files, and it spares only those reported as failed.
- The early event filter (`EventFilter` in `zircolite/rules.py`) may only narrow
  what it can prove. Every uncertainty must fail open — a wrong bound drops
  events at ingest, and the rule then reports nothing while looking healthy.
- Parse rule SQL with `zircolite/sqlscan.py`, never with a regex. Field names
  are backtick-quoted whenever they are not `^[a-zA-Z0-9_]*$` (every ECS name),
  and a regex also reads column names out of string literals.

## Adding things

`CLAUDE.md` documents the exact steps for adding an input format, a CLI option
or a field mapping, along with the architecture and code style. Read it before
adding to those surfaces — a CLI flag without its `SETTINGS` row is accepted by
argparse and silently ignored by the YAML config.

Also, when changing behaviour:

1. **Update the tests.** A regression test should fail before your fix and pass
   after it; if it passes both ways it is not testing the bug.
2. **Update the docs.** `docs/Usage.md`, `docs/Advanced.md` and
   `docs/Internals.md` are user-facing and are expected to match the code.

## Rules and licensing

Code is LGPL-3.0-or-later; the SIGMA rules under `rules/` are covered by the
Detection Rule License. Rulesets are generated from
[Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) — send rule
changes there, not here.
