# Zircolite tools

Scripts for packaging, benchmarking, Sigma regression tests and the docs pictures and tour.

`tests/test_tools.py` runs the benchmark and regression tools over tracked fixtures, and
`tests/test_compact_storage_benchmark.py` the storage experiment. Release-script unit tests
use temporary checkouts; end-to-end validation requires a PyInstaller build or a Windows
ARM64 host. `process_tree.py` is a shared helper, not a script: it enumerates a process's
descendants for `throughput-benchmark.py` and `tests/test_frozen_binary.py`.

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
- editable copies of `config/`, `rules/`, `templates/` and `gui/viewer/`, which the binary uses
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
- one section per rules source, from `rules/release-manifest.json`: the source's
  repository and revision, the files in `rules/` holding its rules and the licence
  text `-U` installed in `rules/licenses/`, then the Detection Rule License when a
  source uses it. A file the manifest does not list, a missing manifest or a missing
  licence text fails packaging, since nothing would say which licence covers it.

A distribution's licence files are the ones in its own `.dist-info`: those listed in
`License-File`, anything under `licenses/`, and files named `LICENSE*`, `LICENCE*`,
`COPYING*`, `NOTICE*` or `AUTHORS*`. A distribution that ships none falls back to
`tools/licenses/<name>.txt`. evtx is the only one today.

The script fails, and writes nothing, when:

- `dist/Zircolite/` or its executable is missing, or the build is not a onedir build
  (no `_internal/`);
- anything it copies from the checkout (`config/`, `rules/`, `templates/`, `gui/viewer/`,
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
  that SigmaHQ publishes its rules under, copied verbatim. SigmaHQ's own licence file,
  which `-U` installs, only links to it.
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

## compact_storage_benchmark.py

This opt-in storage experiment compares a complete in-memory SQLite working table with a projected table and a compressed evidence file. Run it from the repository root with the installed project environment.

```sh
python tools/compact_storage_benchmark.py \
  --events tests/fixtures/sample_bitsadmin.evtx \
  --ruleset rules/rules_windows_merged.json --rows-per-file 0
```

Pass one or more real EVTX paths after `--events`. By default the tool reads the first 10,000 committed events per file. Use `--rows-per-file 0` for complete files, `--repeat 2` to alternate worker order and `--scratch-dir DIR` to select an existing volume. The temporary canonical database and evidence file share a 2,048 MiB SQLite page budget, configurable with `--disk-mib`. Allocation checks reserve 64 MiB of free space. The harness removes its private temporary directory on exit.

The standard EVTX parser uses one reader thread and the normal field mappings and 250-row insertion batches to produce a common canonical SQLite stage. The reference worker copies it into memory. The compact worker keeps values used by eligible predicates for each channel and EventID. SQLite resolves the fields and functions during preparation and evaluates the normalized predicates against the original column affinities and collations. Every projected block and its evidence commit together. The block carries at most 512 rows and 1 MiB of serialized evidence before compression. A hit retrieves its full event by part and committed row ID, including its stored types and original field spellings. A sequential reader also supplies every event in package input order.

The JSON report lists separate staging, working-table build/index, query/hydration and full-replay measurements. The optional `--detector sql` includes ANALYZE in the build interval and checks individual normalized statements with literal prefiltering disabled. Query time includes a multiset digest of their complete matches. Full replay and its digest run separately. Each worker records its OS peak resident memory. The harness verifies both digests and counts, including duplicates, sparse row IDs and unmatched evidence. Fresh workers share only the stage on disk. The stage and detection workers run sequentially. The supervising benchmark process stays alive during both measurements and is outside their reported RSS.

The experiment accepts freshly ingested EVTX files and supported converted event rules. An ambiguous statement, correlation, keyword query, unusable schema or oversized evidence row ends the experiment. The normal detector handles those workloads. The default `--detector auto` compares the production rule executor on both layouts. Its build interval covers the wide copy or compact projection, compressed evidence and standard indexes. The subsequent interval covers ruleset preparation, ANALYZE, source census, automatic literal prefiltering, final SQLite checks, rule-result assembly, projected-row hydration and the result digest. This mode compares the complete public metadata and typed evidence for each matched rule, including statement overlap removal. Both workers must also agree on rule errors, regex timeouts, correlation diagnostics and the number of pruned rules. CLI output files and package export are measured separately by the complete CLI throughput benchmark.

An isolated macOS arm64 `--detector sql` probe combined the first 5,000 rows each from a T001 forwarded-events archive, T001 Sysmon and HANCITOR PC1. All 4,538 default statements agreed on 14,400 matches and all 15,000 complete events. The initial prototype narrowed EventID for native integers. Its build plus query, hydration and digest took 10.28 s with 189.75 MiB sampled peak worker RSS. The reference took 11.02 s with 183.72 MiB. The shared stage took 1.03 s. The probe sampled RSS every 10 ms. Current workers report the OS high-water mark and can also narrow ASCII decimal text EventIDs.

A complete-file comparison used all 142,737 events in T001 `ForwardedEvents.evtx` and all 4,538 shipped Windows merged statements. Each mode ran once on a shared macOS arm64 host with Python 3.14.10 and SQLite 3.54.1. Other CLI benchmarks and project checks ran concurrently. The times below start from the committed stage and end after matching, hydration and digesting. Peak RSS is for each fresh worker through full replay.

| Detector | Wide build and matching | Compact build and matching | Wide peak RSS | Compact peak RSS |
| --- | ---: | ---: | ---: | ---: |
| `--detector auto` | 7.28 s | 17.94 s | 762.23 MiB | 486.95 MiB |
| `--detector sql` | 1,061.40 s | 1,108.84 s | 843.34 MiB | 501.08 MiB |

Both layouts reproduced every event and the same 6,268 matches. The automatic executor reported 11 matching rules, 2,812 pruned rules and zero rule errors or regex timeouts on both. The shared stage took 8.76 s in the automatic comparison. The wide copy and standard indexes took 0.30 s. Building and indexing the compact table and writing 30.90 MiB of compressed evidence took 10.23 s, exceeding the wide worker's complete 7.28 s build-and-match interval. The compact layout remains an experimental tool.

To reproduce the complete input, pass `--events /path/to/T001-04062021/ForwardedEvents.evtx --rows-per-file 0 --ruleset rules/rules_windows_merged.json`. Add `--detector sql` for the unaccelerated comparison.

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

# Compare exports with one warmup and five measured, interleaved passes
pdm run python tools/throughput-benchmark.py --events /path/to/logs --ruleset rules/rules_windows_merged.json --variants baseline current --baseline-root /path/to/old-checkout --modes sequential --exports json csv ndjson timesketch navigator summary timeline-jsonl timeline-csv package --cache warm --warmup 1 --passes 5
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
- `--exports` selects output modes (default: `json`). Reports include export bytes,
  record counts and normalized content fingerprints, checked across variants and
  repeats for each executor. CSV detections are compared separately from JSON;
  template and timeline runs also check their underlying JSON detections. Packages
  verify ZIP and embedded payload checksums, then compare every decoded Parquet schema
  and row, including event IDs, links and full-text values, plus manifest metadata.
  Tables compare independently of row order. Creation time and physical
  Parquet encoding are excluded. Validation runs
  outside the timed region, alongside JSON detection parity.
- `--warmup` excludes initial passes from reported measurements (default: `0`).
  Use `--baseline-python /path/to/old-checkout/.venv/bin/python` when the two
  checkouts use different dependencies. Launch the harness with the candidate interpreter.
  `--cache warm` reuses isolated rule-analysis and viewer-asset caches per variant; use a warmup to
  populate it before measurement. `--cache cold` clears it before every run;
  `--cache off` disables it. These settings do not clear operating-system file caches.

The report lands in a new file in the system temporary directory unless `--report`
names one. RSS is sampled every 20 ms; where child processes cannot be inspected the
report says `parent-only`, and those figures exclude worker memory. The temporary
disk sample includes the working databases, visible temporary files and package
staging directory. Keep benchmarks
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

**Rules are matched by Sigma `id`, falling back to `title`.** Merged rulesets can contain
pipeline variants with the same ID and different title suffixes, such as `… - Generic`
and `… - Sysmon`. Title matching supports rulesets without IDs.

**Every variant a case resolves to is executed**, against a single ingest of the data
file. A positive test passes when *any* variant fires, since the sample only carries one
provider; a negative test requires all of them to stay silent. The report lists the
count each variant saw.

**A positive `match_count` is a minimum event count.** A test declaring `1` can pass with
several matching records. `match_count: 0` requires no matches. When absent, a test name
containing "negative" expects zero matches; other names expect a detection.

### Requirements

- A local clone of the [Sigma repository](https://github.com/SigmaHQ/sigma).
- Zircolite and its dependencies (including `pysigma`, `pysigma-backend-sqlite`, and pipelines such as `pysigma-pipeline-sysmon`).

### Arguments

- **`--regression-data`** (required): Path to the directory under which test cases are discovered (recursively; each directory containing an `info.yml` is a test case). Data file paths from `info.yml` are resolved relative to this path or the test case directory.
- **`--rules`** / **`-r`** (required): Path to rules; type is auto-detected. A **file** with extension `.json` or content starting with `[` is used as a Zircolite JSON ruleset. A **directory** is used as Sigma YAML rules (converted recursively).
- **`--fail-on-skip`**: Exit non-zero when any test was skipped. Without it, a run with only passing or skipped tests exits `0`.
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

## svg-theme-variants.py

The explainer SVGs in `docs/pics/` pick their palette with `prefers-color-scheme` inside
the file. Safari evaluates that against the system appearance rather than the page, so on
GitHub, whose theme can differ from the system's, an explainer in the README drew the wrong
palette. The README therefore shows fixed copies, `<name>-light.svg` and `<name>-dark.svg`,
through a `<picture>` with one source per theme, and GitHub picks the copy for its theme.
The docs site follows the system appearance and keeps the original.

Edit the original only, then regenerate its copies:

```sh
pdm run python tools/svg-theme-variants.py docs/pics/how-it-works.svg
```

`tests/test_tools.py` fails while a copy differs from what the script writes.

## viewer-tour/

Records the README's tour of the Zircolite Viewer, `docs/pics/viewer-tour.webp`: a
looping animated WebP of every view, played in headless Chromium with a drawn cursor.

```sh
tools/viewer-tour/make-tour.sh <unpacked package or its .zip> gui/viewer [output.webp]
```

It needs [uv](https://docs.astral.sh/uv/), which fetches Playwright 1.62.0 (with its
Chromium) and Pillow outside the project's environment, and `img2webp` and `webpmux`
(`brew install webp`). A run takes about four minutes:

1. `record.py` copies the package to the work directory, puts the viewer build's
   `app.js`, `app.css` and `index.html` over the copy, and refuses a manifest that holds a
   local path. It then visits every view and the Run details dialog looking for the home
   directory or the user name, and plays the storyboard at 1280×800 in the light theme,
   capturing frames with the DevTools screencast plus a screenshot at the start of every
   hold. Each hold checks the page for local paths again. To check its targets quickly,
   run it directly with `--dry`, which saves one screenshot per beat instead of capturing,
   and `--only <beat,…>` for the beats after the overview:
   `uv run --no-project --with playwright==1.62.0 python -I tools/viewer-tour/record.py --package <dir> --viewer gui/viewer --out <work> --dry`.
2. `encode.py` shortens the waits for data to 0.2 s, keeps at most 15 frames a second
   (5 while the drawer scrolls), merges identical frames and encodes them losslessly. It
   writes the frame shown late in each beat, decoded back from the WebP, to `review/` in
   the work directory. It warns above 2,500,000 bytes and fails above 3,000,000.

The work directory is a new temporary one unless `TOUR_WORK` names it; neither it nor the
output path may contain a space. `TOUR_FPS`, `TOUR_MODE` (`lossless`, `lossy` or `mixed`),
`TOUR_Q` and `TOUR_METHOD` change the encoding. On the current tour, lossless at 15 frames a
second gave 1.8 MB for 70 s, smaller than lossy at quality 70 and 12 frames a second
(2.0 MB), because most frames change little and lossy blurs the text.

The storyboard is tied to the public
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) corpus: a rule
title, two event times, plink.exe PID 2312 and the Logons view's 87 sessions. Another
corpus needs those targets changed in `record.py`. Make the package from relative paths,
so no local path reaches its manifest:

```sh
mkdir tour && cd tour
ln -s /path/to/EVTX-ATTACK-SAMPLES EVTX-ATTACK-SAMPLES
ln -s /path/to/Zircolite/rules rules
mkdir pkg
python /path/to/Zircolite/zircolite.py --events EVTX-ATTACK-SAMPLES/ \
    -r rules/rules_windows_merged.json --package --package-dir pkg -o out.json
```
