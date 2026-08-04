# Zircolite tools

This directory holds scripts intended for regular use with Zircolite (tracked in git).

Each of these reaches into the package internals, so `tests/test_tools.py` drives them
end-to-end over the tracked fixtures: a rename in `StreamingEventProcessor` or
`ZircoliteCore` fails the suite rather than waiting for somebody to run a script by hand.

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

## flatten-benchmark.py

Measures Zircolite's event-**flattening** throughput, isolated from EVTX parsing, SQLite insertion, and rule execution. Flattening is the dominant cost of log ingestion, so this harness is useful when changing the `_flatten_event` / `process_leaf` hot path.

The script reads raw events once, then repeatedly calls `StreamingEventProcessor._flatten_event` over them. The first pass warms schema discovery and the seen-key cache, so the reported numbers reflect steady-state flattening.

**An external EVTX corpus is required.** Every EVTX file tracked in this repository holds a
single event, so pointing the benchmark at `tests/fixtures/` runs but measures noise. Use a
real capture set such as [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
and enough events for the median to settle.

### Arguments

- **`--evtx`** (required): Path to an EVTX file or a directory of EVTX files (searched recursively).
- **`--config`**: Field mappings config file (default: `config/config.yaml`).
- **`--max-events`**: Maximum number of events to load and flatten (default: `20000`).
- **`--passes`**: Number of timed passes over the loaded events (default: `11`); the median and best are reported.

### Usage

From the Zircolite project root:

```bash
# Single file
pdm run python tools/flatten-benchmark.py --evtx sample.evtx

# Directory of EVTX files, custom event count and pass count
pdm run python tools/flatten-benchmark.py \
  --evtx /path/to/EVTX-ATTACK-SAMPLES \
  --max-events 20000 --passes 11
```

### Output

Prints the event count and, for the timed passes, the median and best wall time plus the corresponding events/second.

### Exit code

- `0` on success.
- `1` if no events could be collected (for example, a bad `--evtx` path or a capture with no standard records).

## db-benchmark.py

Measures everything that happens **after** flattening: the SQLite insert, the indexes, the widening a ruleset forces on the table, and the rule queries themselves. Use it when changing the schema, the indexes, `execute_select_query`'s repairs, or anything that touches how rule SQL reaches SQLite.

It ingests the corpus once, then runs the whole ruleset twice — before and after `ANALYZE` — and reports the wall time of each alongside how many rule queries the planner put on the narrowest index available to them. That last number is the point: widening adds an all-NULL column for every field a rule names and the dataset never produced, and with no statistics SQLite prices a row by its column count, so a wide table quietly moves every query off its selective index. Same rules, same detections, several times the wall clock. Wall time alone blames the machine; the plan count names the cause.

**"Selective" is never a hardcoded index name.** Each query is judged against its own options: whichever of the indexes it was ever planned on returns the fewest rows per key, as `ANALYZE` measured it. A query that can only ever be a full scan — `CommandLine LIKE '%x%'` — is counted apart rather than held against the planner.

**An external EVTX corpus is required.** Every EVTX file tracked in this repository holds a
single event, so pointing the benchmark at `tests/fixtures/` runs but measures noise. Use a
real capture set such as [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).

Two deliberate properties worth knowing before reading the numbers:

- It does **not** call `execute_ruleset`, which analyses the table itself and would leave the harness structurally unable to measure a run without statistics. It drives `ZircoliteCore.execute_rule` directly, which also skips output files and the detection table.
- The two rule passes are compared by `{title: count}`, not by row order — driving a query from a different index returns the same rows in a different order. A mismatch exits `1`, so the harness is a correctness check as well as a timer.

Measurement caveats: the first rule pass runs on a colder cache than the second, so `--rule-passes N` (best of N) is worth using before trusting a small delta; and `--index-delta` runs last, on a warm cache, which biases it in favour of the no-index configuration and therefore under-reports what the indexes are worth.

### Arguments

- **`--evtx`** (required): Path to an EVTX file or a directory of EVTX files (searched recursively).
- **`--ruleset`** (required): Zircolite JSON ruleset to execute.
- **`--config`**: Field mappings config file (default: `config/config.yaml`).
- **`--max-files`**: Ingest at most this many files (default: `0`, meaning all).
- **`--rule-passes`**: Ruleset runs per pass; the fastest is reported (default: `1`).
- **`--auto-index`**: Index the top-N columns the ruleset references, as `--auto-index` does (default: `0`).
- **`--index-delta`**: Add a third rule pass with the `idx_%` indexes dropped.
- **`--index-sets`**: Time the ruleset under each candidate index set instead of either side of `ANALYZE`.

### Comparing index sets

`--index-sets` answers a different question from the default mode: not "do the statistics
help?" but "which indexes are worth building?". It drops every index, builds one candidate
set, runs `ANALYZE`, times the ruleset, and repeats — reporting build cost and rule time
side by side, plus the selective-plan count for each.

The sets are `none`, `eventid only`, `eventid + channel` (what Zircolite built before) and
`eventid + composite` (what it builds now). A set naming a column the corpus does not carry
is skipped rather than faked, so an auditd or sysmon-for-linux capture simply reports fewer
rows.

**Detections are compared across every set and a difference exits `1`.** An index set that
is faster because it found less is a regression, and wall time alone cannot tell the two
apart.

**The corpus decides whether this measures anything.** The composite `(Channel, eventid)`
exists to stop SQLite fetching every row of a channel to re-check the eventID, so a corpus
carrying a single `Channel` value — which is common, and includes some large public
captures — cannot show a difference between it and a channel-only index. Read this mode on
a multi-channel corpus, or it will report a tie and mean nothing by it.

### Usage

From the Zircolite project root:

```bash
# Whole corpus, one ruleset
pdm run python tools/db-benchmark.py \
  --evtx /path/to/EVTX-ATTACK-SAMPLES \
  --ruleset rules/rules_windows_generic.json

# Best of three passes, plus the cost of running with no indexes at all
pdm run python tools/db-benchmark.py \
  --evtx /path/to/captures \
  --ruleset rules/rules_windows_merged.json --rule-passes 3 --index-delta
```

### Output

Prints the file and event counts, ingest throughput, the column count before and after widening, how many rule queries could be planned, the wall time of each rule pass and of `ANALYZE`, the selective-plan count either side of it, and the detection totals — followed by a per-pass tally of which index each plan drove from.

### Exit code

- `0` on success.
- `1` if no events could be ingested, if `--ruleset` is not a Zircolite JSON ruleset, if no rule query could be planned, or if the two rule passes disagree about what matched.
