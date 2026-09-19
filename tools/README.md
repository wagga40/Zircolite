# Zircolite tools

This directory holds scripts intended for regular use with Zircolite (tracked in git).

Each of these reaches into the package internals, so `tests/test_tools.py` drives them
end-to-end over the tracked fixtures: a rename in `StreamingEventProcessor` or
`ZircoliteCore` fails the suite rather than waiting for somebody to run a script by hand.

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
