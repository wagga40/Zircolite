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
Rerun `pdm install` after editing `flatten_kernel.py`: stale builds fall back
to Python. Set `ZIRCOLITE_REQUIRE_NATIVE=1` to fail installation if compilation
fails, as CI does.

### Tasks

[Task](https://taskfile.dev/) (go-task) runs the production tasks in `Taskfile.yml`
from the project root. Development tasks live in a separate, uncommitted
Taskfile; the commands below run without it.

| Task | Does |
|------|------|
| `task --list` | List the tasks |
| `task clean` | Remove default artifacts (`detected_events.json`, `flattened_events_*.json`, `tmp-*`, `zircolite.log`, …) |
| `task update-rules` | Refresh `rules/` from [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) with `-U` |
| `task docker-build`, `task docker-build-multi-arch` | Build the Docker image, for one or both of linux/amd64 and linux/arm64 |
| `task docker-push`, `task save` | Push the multi-arch image, or save it to an archive |
| `task binary-build` | Build the standalone binary into `dist/Zircolite/` and run the binary tests |
| `task gui-build` | Check, test and build the Zircolite Viewer into `gui/viewer/`; commit the result |
| `task get-version` | Print the version from `zircolite/__init__.py` |

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

The suite must pass before you open a pull request; CI runs it on every
push and pull request across Linux, macOS and Windows.

`.forgejo/workflows/` mirrors those workflows for a self-hosted Forgejo
instance, so CI can be rehearsed before pushing. It covers Linux x86_64 only —
see `.forgejo/README.md` for what it does and does not reach, and note that
Forgejo ignores `.github/workflows/` entirely whenever `.forgejo/` is present.

### Test fixtures are tracked

`tests/fixtures/` contains tracked sample logs (EVTX, auditd, Sysmon for Linux,
EVTXtract, XML, JSON). Tests must fail if a required fixture is missing.
The directory is exempt from the `*.evtx` and `*.log` ignore rules for user data.

## Linting and types

```bash
pdm run ruff check .          # must be clean; CI fails on any finding
pdm run ruff check --fix .    # apply available automatic fixes
pdm run python -m mypy zircolite   # must be clean too
```

Lint and type checks block CI. Type-check the `zircolite` package; the
same-named `zircolite.py` entry point must remain a shim over `zircolite/cli.py`.
Including both in the mypy command causes a duplicate-module error.
`tests/test_entry_point.py` enforces the shim's scope.

Ruff's rules and exemptions are configured in `[tool.ruff.lint]` in
`pyproject.toml`; its version is resolved through the tracked development lock.

If a rule is wrong for a specific line, silence that line with a reason
(`# noqa: S608 - values are bound parameters`) rather than widening the global
ignore list. `ruff format` is not enforced; keep bulk formatting separate from
behavior changes.

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
assembles the environment there instead
([Internals → Windows ARM64](docs/Internals.md#windows-arm64)). Why the build is
onedir PyInstaller, and its platform floors, are in
[Internals → Packaging](docs/Internals.md#packaging).

### What the spec has to name

PyInstaller only bundles what static import analysis finds, so `Zircolite.spec`
names what is loaded dynamically. A missing entry fails silently in the binary.

- **pySigma pipelines and backends**, discovered at run time by walking the
  `sigma.pipelines` and `sigma.backends` namespace packages; the spec collects
  their submodules, without tests.
- **The flattening kernel**, which `streaming.py` loads through `importlib`. A
  binary ships no `flatten_kernel.py` to check `SOURCE_SHA256` against, so the
  spec runs that check at build time and, under `ZIRCOLITE_REQUIRE_NATIVE=1`,
  refuses a missing or stale kernel.
- **`evtx` and `ijson`**, collected whole, and **`py7zr`**, named so `.7z`
  support never depends on the scan.

UPX is off. `pytest`, `Cython`, `tkinter`, `IPython` and `setuptools` are
excluded; the last because PyInstaller's `backports` alias would follow
py7zr's and urllib3's `backports.zstd` import into `setuptools._vendor`.

### CI gates

`.github/workflows/build_pyinstaller.yml` builds, tests, verifies and releases:

| Trigger | What runs |
|---------|-----------|
| A `v*` tag | All five targets, then the release |
| A push to `master` or a pull request touching the spec, the package, the lock, `setup.py`, the shipped assets, fixtures, the binary tests, `tools/`, the packaged docs or the workflow | The `linux-x64` leg only, as a canary |
| `workflow_dispatch` (`dry_run` by default) and a weekly schedule | All five targets |

- **Build.** Each leg builds with the spec and runs `tests/test_frozen_binary.py`
  and `tests/test_e2e_regression.py` against the raw `dist/Zircolite/`. On a
  tag, `tools/package-release.py --check-tag` confirms that the tag,
  `__version__`, `pyproject.toml` and the binary's `--version` agree.
- **Verify.** A fresh runner with no Python setup extracts each archive and runs
  `--version`, a detection over `tests/fixtures/sample_bitsadmin.evtx` that must
  match the golden result, and `--package`. The Linux archives repeat the first
  two in `rockylinux:8`, `debian:11` and `ubuntu:20.04`.
- **Release.** Once every verify job passes, one job writes `SHA256SUMS`; on a
  tag it attests the archives and creates a draft release, published by hand.
- **Forgejo.** `.forgejo/workflows/build_pyinstaller.yml` mirrors the `linux-x64`
  leg and its verify smoke; the distro containers and the release stay on
  GitHub.

## What matters most in this codebase

Detection and ingestion errors must be distinguishable from a completed run
with no matches:

- Never swallow an exception into an empty result. If a rule cannot run, record
  it (`ZircoliteCore._note_broken_rule`) so it reaches the run summary.
- If a reader cannot finish a file, mark the run degraded, so the file is
  reported as partial rather than as a clean run with fewer events.
- The early event filter (`EventFilter` in `zircolite/rules.py`) must retain
  events when a bound is uncertain, so it cannot discard potential detections.
- Parse rule SQL with `zircolite/sqlscan.py`, never with a regex. Field names
  are backtick-quoted whenever they are not `^[a-zA-Z0-9_]*$` (every ECS name),
  and a regex also reads column names out of string literals.

## Adding things

[Internals](docs/Internals.md) describes the architecture and has a map of every
module. Three surfaces have more than one place to touch:

**A CLI option**

1. Add the argument in `zircolite/cli.py::parse_arguments()`. Declare
   `default=None` when the default is ambiguous, so "the user passed the default"
   stays distinguishable from "the user passed nothing"; `run_config.resolve`
   applies the real default.
2. Add a `Setting(...)` row to `SETTINGS` in `zircolite/run_config.py`, naming
   the YAML section and key, the default and the merge rule. Without it argparse
   accepts the flag and the YAML config silently ignores the key.
3. Add the field to the section dataclass in `zircolite/config_loader.py`, and
   to its `parse_config` branch, so `validate_config` accepts the key. Document
   the key in the template `create_default_config_file()` writes, then
   regenerate `config/zircolite_example.yaml` from it rather than editing it by
   hand: `tests/test_config_loader.py` checks it covers every key.
4. Update the dataclass in `zircolite/config.py` if the value reaches the
   engine.
5. Add tests in `tests/test_cli.py` and a resolution test in
   `tests/test_yaml_merge.py`, and document the flag in `docs/Usage.md`. An
   option with no YAML equivalent skips steps 2 and 3, but `docs/Usage.md` must
   list it as CLI-only.

**An input format**

1. Add a row to `INPUT_FORMATS` in `zircolite/formats.py`. It is the single
   source for the CLI flag, the YAML `input.format` value, the default
   extension and encoding, the streaming reader and whether the extractor is
   needed.
2. Add the flag to the format group in `zircolite/cli.py::parse_arguments()`.
3. Add the reader to `StreamingEventProcessor` in `zircolite/streaming.py`.
4. If detection needs an extension fallback, add it to `EXTENSION_FALLBACKS`
   in `formats.py` (and to `ALIAS_EXTENSIONS` if no format claims it).
5. Add the format to the parity table in `tests/test_formats.py` and reader
   tests in `tests/test_streaming_processor.py`.

**A field mapping** goes in `config/config.yaml`, with tests in
`tests/test_field_mappings_loader.py`. If the structure of the file changes,
update `load_field_mappings()` in `zircolite/utils.py` too.

Also, when changing behaviour:

1. **Update the tests.** A regression test should fail before your fix and pass
   after it; if it passes both ways it is not testing the bug.
2. **Update the docs.** `docs/Usage.md`, `docs/Advanced.md`, `docs/Viewer.md`
   and `docs/Internals.md` are user-facing and are expected to match the code.
   Give each fact one home and link to it from elsewhere;
   `tests/test_docs_links.py` checks every link and anchor.

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

Code is LGPL-3.0-or-later; the Sigma rules under `rules/` keep the licence of
their source (DRL 1.1, GPL 3.0 or CC0 1.0), named with its text in
`rules/licenses/` and for every file in `rules/release-manifest.json`. Refresh
them with `-U` rather than by hand: a release refuses files that manifest does
not list. Rulesets are generated from
[Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) — send rule
changes there, not here.
