# Contributing to Zircolite

## Setting up

Zircolite uses [PDM](https://pdm-project.org/) for dependency management.

```bash
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite
pdm install --dev
```

Dependencies live in `pyproject.toml` and `pdm.lock` only; `uv sync` and
`poetry install` read the same file.

Installing also compiles `zircolite/flatten_kernel.py` into
`zircolite._flatten_native` (see `setup.py`) when a C compiler is available.
Rerun `pdm install` after editing `flatten_kernel.py`: a kernel built from an
older copy is detected and ignored, so the suite would quietly run the Python
kernel instead. CI sets `ZIRCOLITE_REQUIRE_NATIVE=1`, which turns a failed
compile into a failed install; set it locally to get the same guarantee.

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

## Building the standalone binary

The release binaries are PyInstaller builds from `Zircolite.spec`. The spec bundles
the flattening kernel compiled beside `flatten_kernel.py`, so build from an in-place
install: run `pdm install` first, and again after editing the kernel.

```bash
pdm run pyinstaller --noconfirm Zircolite.spec
ZIRCOLITE_BINARY=dist/Zircolite/Zircolite pdm run python -m pytest tests/test_frozen_binary.py tests/test_e2e_regression.py
```

The build lands in `dist/Zircolite/`: the executable (`Zircolite.exe` on Windows)
and the `_internal/` directory it cannot run without. With
`ZIRCOLITE_REQUIRE_NATIVE=1` the spec refuses a missing or stale kernel instead of
warning and building a binary that flattens in Python. `task binary-build` runs
both commands with it set.

Without `ZIRCOLITE_BINARY`, `tests/test_frozen_binary.py` skips and
`tests/test_e2e_regression.py` runs in process as usual. With it, the first
compares the binary against `python -m zircolite` from the same environment and
the second runs its cases through the binary. The tests use the raw
`dist/Zircolite/`, so a file missing from `_internal/` fails them even though the
release package would have hidden it. Some cases need more:

| Variable | Enables |
|----------|---------|
| `ZIRCOLITE_TEST_NETWORK=1` | The `-U` test, which downloads the rulesets |
| `ZIRCOLITE_GLIBC_FLOOR=2.28` | On Linux, the check that no file in the build needs a newer glibc (needs `objdump` and `readelf`) |
| `ZIRCOLITE_MACOS_FLOOR=15.0` | On macOS, the check of every Mach-O file's minimum OS version (needs `otool`) |

Leave the floor variables unset for a local build on Homebrew Python: it targets
the running macOS, so the check would fail by design. CI builds on interpreters
made for the floors and sets them.

To package a build the way a release does:

```bash
ZIRCOLITE_TARGET=<target> pdm run python tools/package-release.py
```

`<target>` is one of `linux-x64`, `linux-arm64`, `macos-arm64`, `windows-x64` and
`windows-arm64`. The script reads `dist/Zircolite/` and writes
`dist/Zircolite-<version>-<target>.zip`. Extract it with `unzip` somewhere outside the
repository and run it from there, so that nothing resolves against the checkout by
accident.

Windows ARM64 cannot install `pdm.lock` as it stands; `tools/install-win-arm64.py`
assembles the environment there instead. See
[Internals → Packaging](docs/Internals.md#packaging) for why, and for what each CI
gate checks.

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

## Releasing

A release is cut by pushing a version tag; the `build_pyinstaller` workflow does
the rest, up to a draft that is published by hand.

1. Bump the version in **both** `zircolite/__init__.py` (`__version__`) and
   `pyproject.toml` (`version` under `[project]`). Nothing else may carry the
   number — `tests/test_docs_sync.py` fails on a copy in the docs. On a minor or
   major bump, also move the supported line in `SECURITY.md`, which the same
   tests check. A number that already has a tag cannot be released again.
2. Run the suite, commit, and merge the bump into `master`.
3. Tag that commit `vX.Y.Z`, with the same number, and push the tag.
4. The workflow builds all five targets and runs the binary tests on each. It
   checks that the tag, `__version__`, the `pyproject.toml` version and each
   binary's `--version` agree, then smoke-tests every archive on a clean runner
   and the Linux ones on older distributions. Finally it writes `SHA256SUMS`,
   attests the archives and creates a **draft** GitHub release carrying them.
5. Review the draft — assets, checksums, notes — and publish it.

If the tag already has a release, the workflow replaces its assets instead of
creating another. To rehearse the whole matrix without releasing anything, run
the workflow by hand: `dry_run` is on by default and stops after `SHA256SUMS`.

## Rules and licensing

Code is LGPL-3.0-or-later; the SIGMA rules under `rules/` are covered by the
Detection Rule License. Rulesets are generated from
[Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) — send rule
changes there, not here.
