# Docker-based external tests

External tests run Zircolite inside a Docker image built from the **current directory**, so they always test the version under development. The image is built from `tests/external/Dockerfile.external-tests`, which is **not** committed (see `.gitignore`). Tests are invoked via Taskfile.dev.yml (or by running the runner script directly).

## Requirements

- Docker
- Python 3.10+ with project dependencies (e.g. `pdm install`), for the runner script

## Running the tests

From the repository root:

```bash
# Build the image and run all scenarios
pdm run python tests/external/run_external_tests.py --build

# Run without rebuilding (faster if image already exists)
pdm run python tests/external/run_external_tests.py

# Run specific scenarios
pdm run python tests/external/run_external_tests.py --build version help json_basic

# Run by tag (union match — any matching tag is included)
pdm run python tests/external/run_external_tests.py --tag smoke
pdm run python tests/external/run_external_tests.py --tag json --tag csv

# Run scenarios in parallel (4 concurrent containers)
pdm run python tests/external/run_external_tests.py --parallel 4

# Save output reports
pdm run python tests/external/run_external_tests.py --results-file results/external.json
pdm run python tests/external/run_external_tests.py --markdown-file results/external.md
pdm run python tests/external/run_external_tests.py --junit-file results/external.xml

# Save all three report formats
pdm run python tests/external/run_external_tests.py \
  --results-file results/external.json \
  --markdown-file results/external.md \
  --junit-file results/external.xml
```

## Scenarios

| Scenario            | CLI options covered | Tags |
|---------------------|---------------------|------|
| `version`           | `--version` | smoke, cli |
| `help`              | `--help` | smoke, cli |
| `pipeline_list`     | `--pipeline-list` | cli |
| `generate_config`   | `--generate-config` | cli |
| `transform_list`    | `--transform-list` | cli |
| `json_basic`        | `-e`, `-r`, `-o`, `-j` (JSONL input) | smoke, json |
| `json_array`        | `--json-array-input` | json |
| `csv_input`         | `--csv-input`, `-c` (config) | csv |
| `csv_output`        | `--csv` (CSV output) | csv, output |
| `keepflat`          | `--keepflat` | json, output |
| `quiet`             | `-q` (quiet mode — banner suppressed) | json, cli |
| `custom_outfile`    | `-o` (custom output path) | json, output |
| `rulefilter`        | `-R` (exclude rules by title, verifies exact count and title) | json |
| `unified_db`        | `--unified-db`, `-e` (directory), `-f` (fileext) | json |
| `no_auto_mode`      | `--no-auto-mode` | json |
| `sysmon_linux`      | `--sysmon-linux-input` (real fixture data) | format |
| `xml_input`         | `--xml-input` (real fixture data) | format |
| `evtxtract`         | `--evtxtract-input` (real fixture data) | format |
| `winlogbeat`        | `--json-input` with Winlogbeat/ECS format (real fixture data) | format |
| `db_input`          | `-D` (load from pre-built SQLite database) | format |
| `navigator_output`  | `--navigator-output` (ATT&CK Navigator layer) | json, output |
| `template_output`   | `-t`, `-T` (Jinja2 template rendering) | output |
| `dbfile`            | `-d` (save SQLite database file) | json, output |
| `hashes`            | `--hashes` (xxhash field in every detection) | json |
| `time_filter`       | `-A` (after-timestamp filter, expects 0 detections) | json |
| `before_timestamp`  | `-B` (before-timestamp filter, expects 0 detections) | json |
| `nolog`             | `-n` (no log/result files beyond the output JSON) | json, cli |
| `debug_mode`        | `--debug` (debug logging, same detections as normal) | json, cli |
| `limit_results`     | `-L` (limit output to N detections) | json, output |
| `yaml_config`       | `-Y` (YAML configuration file) | json, cli |
| `evtx_single`       | EVTX auto-detection, single file (bitsadmin regression sample) | evtx |
| `evtx_no_parallel`  | `--no-parallel` with two EVTX files in a directory | evtx |
| `evtx_unified_db`   | `--unified-db` with two EVTX files in a directory | evtx |
| `evtx_perfile`      | `--no-auto-mode` (per-file mode) with two EVTX files | evtx |
| `error_invalid_flag` | Unknown CLI flag (expects exit 2) | error, smoke |
| `error_missing_events` | Non-existent events file (expects exit 1) | error |
| `error_bad_ruleset` | Broken JSON ruleset (expects exit 1) | error |
| `error_no_ruleset`  | Events file without a ruleset (expects exit 1) | error |

## Tags

Scenarios are tagged for selective execution via `--tag`:

| Tag | Description |
|-----|-------------|
| `smoke` | Fast sanity checks: version, help, json_basic, error_invalid_flag |
| `json` | All JSONL input scenarios |
| `csv` | CSV input/output scenarios |
| `evtx` | EVTX format scenarios (may require fixtures) |
| `format` | Non-EVTX format scenarios (XML, Winlogbeat, Sysmon, DB input) |
| `output` | Output format and path scenarios |
| `cli` | CLI flag and mode scenarios |
| `error` | Negative/failure scenarios |

## Taskfile.dev.yml

The repo's `Taskfile.dev.yml` (if present) includes `external-tests` and `external-tests:build`. Otherwise add to your **local** `Taskfile.dev.yml`:

```yaml
external-tests:
  desc: Run Docker-based external tests (current tree)
  cmds:
    - pdm run python tests/external/run_external_tests.py --build
  preconditions:
    - sh: command -v docker
      msg: Docker is required for external tests

external-tests:build:
  desc: Build external test Docker image only
  cmds:
    - docker build -f tests/external/Dockerfile.external-tests -t zircolite:external-test .
```

Then run:

```bash
task -t Taskfile.dev.yml external-tests
```

## Scenario format

Each scenario lives under `tests/external/scenarios/<name>/`:

- **`scenario.yaml`** – Defines the test (required):
  - `command`: list of arguments to `python3 zircolite.py` (paths use `/data/input` and `/data/output` inside the container).
  - `expected_exit_code`: default `0`.
  - `tags`: list of string tags for filtering (e.g. `[smoke, json]`).
  - `timeout`: per-scenario timeout in seconds (overrides `default_timeout` from `runner.yaml`).
  - `allow_stderr_errors`: set `true` to suppress the default traceback/error check on stderr (needed for error scenarios).
  - `skip_if`:
    - `missing_input: true` — skip (not fail) when input files referenced in the command don't exist on disk.
  - `stdout_contains`: list of strings that must appear in stdout+stderr.
  - `stdout_not_contains`: list of strings that must NOT appear in stdout+stderr.
  - `stderr_contains`: list of strings that must appear in stderr.
  - `compare_files`: list of `{ actual, expected?, compare?, ... }`:
    - `actual`: path inside the container (e.g. `/data/output/detected_events.json`).
    - `expected`: filename under the scenario's `expected/` dir (optional for non-content modes).
    - `compare`: one of:
      - `content` (default) — byte-for-byte comparison with `expected` file.
      - `json_keys` — compare JSON arrays by key/value, tolerating extra keys in actual.
      - `json_count_min` — actual JSON array must have at least `min_count` items.
      - `json_exact_count` — actual JSON array must have exactly `count` items.
      - `json_all_have_field` — every item in the JSON array must contain `field`.
      - `json_matches_all_have_field` — every item in each rule's `matches` list must contain `field`.
      - `json_schema` — every item must have `required_keys`; if `matches_min` > 0, each item's `matches` list must have at least that many entries.
      - `json_contains_titles` — the output must contain detections with each title in `titles`.
      - `exists` — file must exist (no content check).
      - `lines_min` — file must have at least `min_count` non-empty lines.
- **`input/`** – (optional) Directory mounted at `/data/input` in the container.
- **`expected/`** – (optional) Directory with expected output files.

The runner mounts each scenario's `input/` at `/data/input` and a temporary directory at `/data/output`, runs the container with the given `command`, then validates the output.

### Default stderr assertion

By default, the runner fails any scenario whose stderr contains Python tracebacks (`Traceback (most recent call last)`) or common exception patterns (`SyntaxError:`, `ModuleNotFoundError:`, `ImportError:`). This catches unhandled exceptions without explicit `stderr_contains` assertions.

Set `allow_stderr_errors: true` in the scenario to suppress this check (e.g. for error scenarios that intentionally trigger errors).

## Runner configuration

`tests/external/runner.yaml` is auto-loaded if it exists. All keys are optional and are overridden by the equivalent CLI argument.

```yaml
# tests/external/runner.yaml
image_tag: zircolite:external-test
dockerfile: tests/external/Dockerfile.external-tests
results_file: results/external-tests.json
markdown_file: results/external-tests.md
junit_file: results/external-tests.xml
default_timeout: 120
parallel: 1
```

To use a different config file:
```bash
pdm run python tests/external/run_external_tests.py --config path/to/my-runner.yaml
```

## Parallel execution

Pass `--parallel N` (or set `parallel: N` in `runner.yaml`) to run up to N scenarios concurrently. Each scenario runs in its own Docker container with its own temp directory, so there are no filesystem conflicts.

```bash
pdm run python tests/external/run_external_tests.py --parallel 4
```

Default is `1` (sequential). Use `--parallel 1` for debugging to get deterministic output ordering.

## Results log

Pass `--results-file PATH` (or set `results_file` in `runner.yaml`) to write a detailed, machine-readable JSON log after the run. Each scenario entry captures the full docker command, exit code, wall-clock duration, and the complete stdout/stderr from the container — enough to reproduce or diagnose any failure without re-running:

```json
{
  "timestamp": "2024-01-15T10:30:00+00:00",
  "image": "zircolite:external-test",
  "total": 35,
  "passed": 30,
  "failed": 1,
  "skipped": 4,
  "total_duration_seconds": 183.4,
  "scenarios": [
    {
      "name": "version",
      "result": "pass",
      "message": "",
      "exit_code": 0,
      "expected_exit_code": 0,
      "duration_seconds": 1.2,
      "docker_command": ["docker", "run", "--rm", "-e", "PYTHONUNBUFFERED=1", "..."],
      "zircolite_args": ["--version"],
      "stdout": "Zircolite - v3.5.0\n",
      "stderr": ""
    }
  ]
}
```

Pass `--junit-file PATH` to write a JUnit XML report for CI systems (GitHub Actions, GitLab CI, Jenkins).

## Creating the Dockerfile

`tests/external/Dockerfile.external-tests` is listed in `.gitignore` and is not shipped. Create it in `tests/external/` by copying the main `Dockerfile` and:

1. Removing the step that runs `python3 zircolite.py -U` (so the build does not require network).
2. Keeping the same layout (WORKDIR, COPY of `zircolite/`, `config/`, `rules/`, etc.).

Build from the repo root with:

```bash
docker build -f tests/external/Dockerfile.external-tests -t zircolite:external-test .
```

The runner script builds this image when you pass `--build` or when the image does not exist.
