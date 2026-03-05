# Zircolite tools

This directory holds scripts intended for regular use with Zircolite (tracked in git).

## sigma-regression.py

Runs detection tests using the [Sigma repository’s regression_data](https://github.com/SigmaHQ/sigma/tree/master/regression_data). Each test case directory there contains:

- **info.yml** – rule metadata (`rule_metadata`, with `title`) and test definitions (`regression_tests_info`: path to EVTX/JSON, optional `match_count`, etc.). If `match_count` is omitted, it is inferred from the test name: "Positive Detection Test" → expect 1 match, "Negative Detection Test" → expect 0.
- **.evtx / .json** – sample logs that should trigger the referenced rule with the expected match count.

The script:

1. Loads rules from the path given by `--rules` / `-r`. The type is **auto-detected**: a `.json` file (or a file whose content starts with `[`) is treated as a Zircolite JSON ruleset and used as-is; a directory is treated as Sigma YAML rules and converted with pySigma (pipelines such as `sysmon`, `windows-logsources`; rules loaded recursively from that path).
2. Discovers all test cases under the path given by `--regression-data` (recursively: every directory containing an `info.yml` is a test case).
3. For each test, resolves the data file from `info.yml`, runs Zircolite on that file with only the related rule(s), and checks that the rule fires with the expected `match_count`.

### Requirements

- A local clone of the [Sigma repository](https://github.com/SigmaHQ/sigma).
- Zircolite and its dependencies (including `pysigma`, `pysigma-backend-sqlite`, and pipelines such as `pysigma-pipeline-sysmon`).

### Arguments

- **`--regression-data`** (required): Path to the directory under which test cases are discovered (recursively; each directory containing an `info.yml` is a test case). Data file paths from `info.yml` are resolved relative to this path or the test case directory.
- **`--rules`** / **`-r`** (required): Path to rules; type is auto-detected. A **file** with extension `.json` or content starting with `[` is used as a Zircolite JSON ruleset. A **directory** is used as Sigma YAML rules (converted recursively).
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
```

### Output files

- **`--report PATH`**: Writes two files with **full failed-test data**:
  - **PATH.md** – Markdown: summary table, failed-tests table, then for each failed test: Rule (SQL, beautified), Rule (Sigma YAML), Events (from DB). By default, events include only fields referenced in the rule SQL.
  - **PATH.json** – JSON: same summary and `failed_tests[]` with `rule_sql`, `sigma_yaml`, `events` for each entry.
- **`--report-all-event-fields`**: Include all event fields in the report; by default only fields used in the rule SQL are included.

### Exit code

- `0` if all run tests passed.
- `1` if any test failed or the script could not load the ruleset / find regression data.

Skipped tests (missing data file or no matching rule in the ruleset) are reported in the summary but do not change the exit code unless you treat "skipped" as failure in your workflow.
