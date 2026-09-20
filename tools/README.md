# Zircolite tools

This directory holds scripts intended for regular use with Zircolite (tracked in git).

The benchmark and the regression runner reach into the package internals, so
`tests/test_tools.py` drives them end-to-end over the tracked fixtures: a rename in
`StreamingEventProcessor` or `ZircoliteCore` fails the suite rather than waiting for
somebody to run a script by hand. The two release scripts need a real PyInstaller build
or a Windows ARM64 host, so the suite does not run them end-to-end; the same test
module pins what they decide against fake checkouts.

## package-release.py

Turns the PyInstaller onedir build in `dist/Zircolite/` into a release archive. It needs
the standard library, plus `packaging` to evaluate environment markers while it gathers
the licences. PyInstaller depends on `packaging`, so any environment that can build the
binary has it.

```sh
pdm run pyinstaller --noconfirm Zircolite.spec
ZIRCOLITE_TARGET=macos-arm64 pdm run python tools/package-release.py
```

`ZIRCOLITE_TARGET` is required and must be one of `linux-x64`, `linux-arm64`,
`macos-arm64`, `windows-x64` or `windows-arm64`. The script stages
`dist/Zircolite-<version>-<target>/`, which holds:

- the onedir build: the executable (`Zircolite`, or `Zircolite.exe` on Windows) and
  `_internal/`;
- editable copies of `config/`, `rules/`, `templates/` and `gui/`, which the binary uses
  in preference to its bundled copies;
- `docs/`, `pics/`, `README.md` and `LICENSE`;
- a generated `THIRD_PARTY_LICENSES`.

It then writes `dist/Zircolite-<version>-<target>.zip` and prints the archive's path,
which is all it writes to stdout. For the Linux and macOS targets every entry is recorded
as made on Unix, with its mode, so `unzip` and Archive Utility restore it; the executable
is always marked executable, and symlinks in the build are stored as symlinks. Entries
are sorted, and `SOURCE_DATE_EPOCH` caps the timestamps when it is set.
The version comes from `zircolite/__init__.py`, read as text rather than imported.

`THIRD_PARTY_LICENSES` is built from the environment the binary was built in. It covers:

- the interpreter's licence (`LICENSE.txt` beside the standard library);
- on Linux and macOS targets, the native libraries the interpreter is built with
  (OpenSSL, libffi, mpdecimal, liblzma, bzip2, zstd, Expat, zlib, SQLite, libedit,
  ncurses, libuuid), from `tools/licenses/python-runtime-libraries.txt`, since only
  the Windows `LICENSE.txt` carries their notices;
- PyInstaller, whose licence carries the bootloader exception, and
  pyinstaller-hooks-contrib, whose runtime hooks are in the executable;
- every distribution in the runtime dependency closure of the installed `Zircolite`
  project. It follows `Requires-Dist`, evaluates environment markers for the running
  interpreter with `packaging` and ignores extras nobody requested;
- the Detection Rule License for `rules/`.

A distribution's licence files are the ones in its own `.dist-info`: those listed in
`License-File`, anything under `licenses/`, and files named `LICENSE*`, `LICENCE*`,
`COPYING*`, `NOTICE*` or `AUTHORS*`. A distribution that ships none falls back to
`tools/licenses/<name>.txt`. evtx is the only one today.

The script fails, and writes nothing, when:

- `dist/Zircolite/` or its executable is missing, or the build is not a onedir build
  (no `_internal/`);
- anything it copies from the checkout (`config/`, `rules/`, `templates/`, `gui/`,
  `docs/`, `pics/`, `README.md`, `LICENSE`) is or contains a symlink. Only a Windows
  archive cannot hold one, but the check runs for every target so that the linux-x64
  canary build catches it. Symlinks inside the onedir build are kept in the Linux and
  macOS archives, and fail a Windows target;
- a required distribution is not installed. The only exception is jq on
  `windows-arm64`; see below;
- a distribution has no licence text and nothing is vendored for it;
- the interpreter's licence, the PyInstaller licence, the rules licence or, for a Linux
  or macOS target, `python-runtime-libraries.txt` cannot be found.

To take in a new dependency that ships no licence file, add its published text to
`tools/licenses/` under its normalised name (lower case, runs of `-_.` replaced by `-`).

```sh
pdm run python tools/package-release.py --check-tag v1.2.3
```

`--check-tag` only checks a release tag. The tag must be `v` followed by the version,
and that version must match `__version__` in `zircolite/__init__.py`, the `[project]`
version in `pyproject.toml`, and what the built executable prints for `--version`. On
a mismatch, the script lists every source that disagrees and exits 1.

`--root DIR` points either mode at another checkout, which must contain `dist/Zircolite`
and the assets. The tests use it; releases do not.

`tools/licenses/` holds the vendored texts:

- `evtx.txt`: the evtx wheel has no licence file. pyevtx-rs declares MIT/Apache-2.0;
  the text is the evtx crate's `LICENSE-MIT` plus the Apache-2.0 notice.
- `DRL-1.1.txt`: the [Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License)
  that SigmaHQ publishes its rules under, copied verbatim.
- `python-runtime-libraries.txt`: the licence texts of the native libraries in the
  Linux and macOS interpreters, each copied from its upstream source, which heads its
  section. The list follows python-build-standalone's `pythonbuild/downloads.json` and
  the python.org macOS installer's `Mac/BuildScript/build-installer.py`; check both
  when the interpreter version changes.

## install-win-arm64.py

Installs the development environment on Windows on ARM64. `pdm install` cannot do it
there: evtx has neither a `win_arm64` wheel nor an sdist, and jq does not build on that
platform.

```sh
uvx maturin build --release   # in a pyevtx-rs checkout at the tag the lock pins
python tools/install-win-arm64.py --wheels <directory holding the evtx wheel>
```

Run it from the Python that should host the environment, with `pdm` and `uv` on `PATH`.
It runs, and prints, these steps:

1. `pdm export -G dev -o dist/reqs.txt`, then removes the `evtx` and `jq` requirements
   and their hash lines. It stops if either is missing from the export, since that
   means the recipe is out of date.
2. `uv venv --clear .venv --python <this interpreter>`. An existing `.venv` is replaced.
3. `uv pip install --no-config --no-deps --python .venv -r dist/reqs.txt`.
4. `uv pip install --no-config --no-deps --python .venv <evtx wheel>`.
5. `uv pip install --no-config --no-deps --python .venv -e .`. The editable install
   compiles the flattening kernel in place, where `Zircolite.spec` finds it. Set
   `ZIRCOLITE_REQUIRE_NATIVE=1` to make a failed compile fail the step.
6. `pdm use -f .venv`, so later `pdm run` commands use this environment.

`--no-deps` stops uv from resolving jq back in. `--no-config` stops the project's
`[tool.uv] exclude-newer` from rejecting versions the lock already pins. Leaving jq out
is safe: pySigma imports it only in its jq transformation, which Zircolite never uses.
The same reason lets `package-release.py` accept its absence on `windows-arm64`.

## throughput-benchmark.py

Compares complete CLI runs -- process startup, ingestion, indexing, rule execution,
output and cleanup -- and rejects any pass whose detection multiset (rule identity,
event contents, duplicate counts) differs from the first variant. Runs are
interleaved; input generation and verification happen outside the timed region.
Each run's `--performance-json` report is embedded, so stage timings, the selected
flattening backend, literal-filter counters and the resolved executor come with it.

```sh
# Real captures, several executors
pdm run python tools/throughput-benchmark.py --events /path/to/logs --ruleset rules/rules_windows_merged.json --passes 3 --modes sequential thread process --workers 4

# Generated workload, Python reference path against the defaults
pdm run python tools/throughput-benchmark.py --scenario sparse --event-count 500000 --files 4 --rule-count 32 --passes 3 --variants reference current

# Before/after: a preserved checkout against the working tree
pdm run python tools/throughput-benchmark.py --events /path/to/logs --ruleset rules/rules_windows_merged.json --variants baseline current --baseline-root /path/to/old-checkout
```

- `--variants`: `reference` (Python flattening, literal filter off), `current` (defaults),
  `disk` (defaults with `--working-db disk`), `baseline` (the `--baseline-root`
  checkout), and `python-auto`, `python-literal`, `cython-off`, `cython-auto`,
  `cython-literal` to isolate one accelerator at a time.
- `--scenario`: `many-small`, `large`, `mixed`, `sparse`, `gzip`, `array`,
  `array-gzip`, `csv`, `noisy`, `transforms`, `evtx-derived`, `linux` (use
  `rules/rules_linux.json` with the last one). Generated inputs reproduce a change;
  draw conclusions from real captures. Use `--rule-count 32` or more, or automatic
  literal filtering never engages.
- A `.db` file exported with `--dbfile` can be passed as `--events` to measure the
  rule phase alone.

The report lands in a new file in the system temporary directory unless `--report`
names one. RSS is sampled every 20 ms; where child processes cannot be inspected the
report says `parent-only`, and those figures exclude worker memory. Keep benchmarks
apart from builds and test runs.

## tool-benchmark.py

Times Zircolite against [Hayabusa](https://github.com/Yamato-Security/hayabusa) and
[Chainsaw](https://github.com/WithSecureLabs/chainsaw) on the same logs, each at its own
defaults with its own rules. It measures what a user gets out of the box, not
rule-for-rule engine speed. The results and their caveats are in
[docs/Benchmark.md](../docs/Benchmark.md).

```sh
pdm run python tools/tool-benchmark.py --events /path/to/evtx \
    --hayabusa /opt/hayabusa/hayabusa \
    --chainsaw /opt/chainsaw/chainsaw \
    --chainsaw-sigma /opt/sigma/rules \
    --chainsaw-sigma /opt/sigma/rules-emerging-threats \
    --chainsaw-sigma /opt/sigma/rules-threat-hunting \
    --chainsaw-rules /opt/chainsaw/rules \
    --chainsaw-mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml
```

- Zircolite runs from this checkout under the current interpreter, with
  `rules/rules_windows_merged.json`. `--zircolite` names an executable instead (a
  standalone build), and `--zircolite-ruleset` another ruleset.
- Hayabusa runs `dfir-timeline -w` from its own directory, so the `rules/` and `config/`
  beside the binary are the ones it loads. Update them yourself beforehand if you want
  current rules; the script never does.
- Chainsaw needs a mapping file and at least one of `--chainsaw-sigma` (repeatable) and
  `--chainsaw-rules`.
- Either other tool can be left out. `--runs` (default 3) timed passes follow `--warmup`
  (default 1) unrecorded ones. The tools are interleaved and their order rotates every
  pass.

Each pass records wall time and the peak RSS of the process tree, sampled every 20 ms by
the same code as `throughput-benchmark.py`. Detections and distinct rules matched are
counted after each run, outside the timed region; a tool whose count changes between
passes stops the benchmark. The JSON report also names each tool's version, the rules it
says it loaded, and the commit of every rule checkout. It lands in the system temporary
directory unless `--report` names a path, and a markdown table is printed at the end.

## sigma-regression.py

Runs detection tests using the [Sigma repository’s regression_data](https://github.com/SigmaHQ/sigma/tree/master/regression_data). Each test case directory there contains:

- **info.yml** – rule metadata (`rule_metadata`, with `id` and `title`) and test definitions (`regression_tests_info`: path to EVTX/JSON, optional `match_count`, etc.).
- **.evtx / .json** – sample logs that should trigger the referenced rule.

The script:

1. Loads rules from the path given by `--rules` / `-r`. The type is **auto-detected**: a `.json` file (or a file whose content starts with `[`) is treated as a Zircolite JSON ruleset and used as-is; a directory is treated as Sigma YAML rules and converted with pySigma (pipelines such as `sysmon`, `windows-logsources`; rules loaded recursively from that path).
2. Discovers all test cases under the path given by `--regression-data` (recursively: every directory containing an `info.yml` is a test case).
3. For each test, resolves the data file from `info.yml`, ingests it once, runs every rule the case refers to against it, and checks the outcome against `match_count`.

### How a test is matched and judged

**Rules are looked up by Sigma `id` first, and by `title` only as a fallback.** A merged
Zircolite ruleset carries one rule per pipeline, all sharing the Sigma id but suffixing
the title — `Anydesk Temporary Artefact` ships as `… - Generic` and `… - Sysmon`.
Matching on the title alone therefore misses most of a merged ruleset: against
`rules/rules_windows_merged.json`, 112 of 136 Windows cases resolve by id and by id
only. Titles still matter because a converted ruleset need not carry ids.

**Every variant a case resolves to is executed**, against a single ingest of the data
file. A positive test passes when *any* variant fires, since the sample only carries one
provider; a negative test requires all of them to stay silent. The report lists the
count each variant saw.

**`match_count` states that the rule fired, not how many records it fired on.** Every
entry in the current regression_data is a positive test declaring `1`, while several
samples hold more than one matching record — the `IE Change Domain Zone` capture holds
three, all of which legitimately match. Zircolite counts matching *events*, so a
positive test passes on **at least** the declared count. Only `match_count: 0` demands
silence. When `match_count` is absent it is inferred from the test name: a name
containing "negative" expects 0, anything else expects a detection.

### Requirements

- A local clone of the [Sigma repository](https://github.com/SigmaHQ/sigma).
- Zircolite and its dependencies (including `pysigma`, `pysigma-backend-sqlite`, and pipelines such as `pysigma-pipeline-sysmon`).

### Arguments

- **`--regression-data`** (required): Path to the directory under which test cases are discovered (recursively; each directory containing an `info.yml` is a test case). Data file paths from `info.yml` are resolved relative to this path or the test case directory.
- **`--rules`** / **`-r`** (required): Path to rules; type is auto-detected. A **file** with extension `.json` or content starting with `[` is used as a Zircolite JSON ruleset. A **directory** is used as Sigma YAML rules (converted recursively).
- **`--fail-on-skip`**: Exit non-zero when any test was skipped. A skipped test asserts nothing, so without this a run whose ruleset covers almost none of the cases still reports success.
- **`--zircolite-config`**, **`--pipeline`**, **`--verbose`**, **`--report`**, **`--report-all-event-fields`**: Optional (see `--help`).

### Usage

From the Zircolite project root:

```bash
# Sigma YAML rules (directory): auto-detected, converted with pySigma
pdm run python tools/sigma-regression.py \
  --regression-data /path/to/sigma/regression_data/rules/windows \
  -r /path/to/sigma/rules/windows

# Zircolite JSON ruleset (file): auto-detected, used as-is
pdm run python tools/sigma-regression.py \
  --regression-data /path/to/sigma/regression_data/rules/windows \
  -r rules/rules_windows_merged.json

# Optional: Zircolite config, pipelines (for Sigma YAML conversion)
pdm run python tools/sigma-regression.py \
  --regression-data /path/to/sigma/regression_data/rules/windows \
  -r /path/to/sigma/rules/windows \
  --zircolite-config config/config.yaml \
  --pipeline sysmon --pipeline windows-logsources

# Verbose output
pdm run python tools/sigma-regression.py \
  --regression-data /path/to/sigma/regression_data/rules/windows \
  -r /path/to/sigma/rules/windows --verbose

# Write a Markdown and JSON report (includes full failed-test data: SQL, YAML, events)
pdm run python tools/sigma-regression.py \
  --regression-data /path/to/sigma/regression_data/rules/windows \
  -r /path/to/sigma/rules/windows --report regression_report

# Include all event fields in the report (default: only fields referenced in the rule SQL)
pdm run python tools/sigma-regression.py \
  --regression-data /path/to/sigma/regression_data/rules/windows \
  -r /path/to/sigma/rules/windows --report regression_report --report-all-event-fields

# Treat a case the ruleset does not cover as a failure
pdm run python tools/sigma-regression.py \
  --regression-data /path/to/sigma/regression_data/rules/windows \
  -r rules/rules_windows_merged.json --fail-on-skip
```

### Output files

- **`--report PATH`**: Writes two files with **full failed-test data**:
  - **PATH.md** – Markdown: summary table, failed-tests table, then for each failed test: Rule (SQL, beautified), Rule (Sigma YAML), Events (from DB), and the count each rule variant saw. By default, events include only fields referenced in the rule SQL.
  - **PATH.json** – JSON: same summary and `failed_tests[]` with `rule_sql`, `sigma_yaml`, `events` and `variants` for each entry.
- **`--report-all-event-fields`**: Include all event fields in the report; by default only fields used in the rule SQL are included.

The fields kept in the report come from `zircolite.sqlscan.column_refs`, the same
quote-aware SQL reader the engine uses to widen the events table.

### Exit code

- `0` if all run tests passed.
- `1` if any test failed, if `--fail-on-skip` was given and any test was skipped, or if the script could not load the ruleset / find regression data.

A test is skipped when its data file is missing or no rule in the ruleset matches the
case. Skips are shown in the summary with their share of the total; pass
`--fail-on-skip` to make them fail the run.
