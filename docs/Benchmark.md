# Benchmark

Recorded results for Zircolite, [Hayabusa](https://github.com/Yamato-Security/hayabusa)
and [Chainsaw](https://github.com/WithSecureLabs/chainsaw) on the same Windows logs and
machine, recorded in October 2026. Each tool used its defaults and its own rules, so the
results compare those configurations. Tool and rule revisions are listed under
[Setup](#setup).

The November comparison covers package generation, viewer startup, chronological
queries and detection memory. [Offline viewer and package writer](#offline-viewer-and-package-writer).

## Results

One corpus contains a single channel; the other contains eleven. Both used the same
machine, tool versions and rule checkouts. Times are medians of three timed passes after
one warm-up pass, with the range in brackets; peak memory is the median of the three.

### Single-channel corpus

4 Sysmon EVTX files, 478 MB, 452,554 events.

| Tool | Rules loaded | Wall time | Peak memory | Detections | Rules matched |
|------|-------------:|----------:|------------:|-----------:|--------------:|
| Zircolite 4.6.0 | 4,527 | **7.7 s** (7.6–7.7) | 1,200 MiB | 162,362 | 108 |
| Hayabusa 4.2.0 | 4,674 (2,301 after its channel filter) | 23.3 s (23.3–25.0) | 749 MiB | 589,555 | 134 |
| Chainsaw 2.17.1 | 3,630 (296 could not be loaded) | 48.3 s (48.3–48.4) | 378 MiB | 41,499 | 99 |

### Multi-channel corpus

8 EVTX files — seven forwarded-event logs and one Sysmon log — 13.3 GB, 1,720,383 events
once Zircolite's event filter has run, spread over eleven channels. Security carries 74% of
them, then Windows PowerShell (184,183), PowerShell/Operational (172,759), Sysmon (67,371),
WMI-Activity (13,228), TaskScheduler (7,017) and five more.

| Tool | Rules loaded | Wall time | Peak memory | Detections | Rules matched |
|------|-------------:|----------:|------------:|-----------:|--------------:|
| Zircolite 4.6.0 | 4,527 | **30.2 s** (30.0–30.3) | 9,158 MiB | 264,200 | 124 |
| Hayabusa 4.2.0 | 4,674 (4,425 after its channel filter) | 500.3 s (498.2–503.2) | 1,390 MiB | 703,920 | 182 |
| Chainsaw 2.17.1 | 3,630 | 183.0 s (181.2–185.0) | 1,176 MiB | 122,997 | 83 |

## Reading the numbers

- **Channel mix affects rule pruning and runtime.** Hayabusa's channel filter keeps 2,301
  of its 4,674 rules on the single-channel corpus and 4,425 on the multi-channel one, and
  its time per event goes from 51 µs to 291 µs between the two. Zircolite stays near 17 µs
  and Chainsaw near 106 µs on both. The multi-channel rates use the event count after
  Zircolite's event filter.
- **The rule sets differ.** Each tool loads its own conversion of SigmaHQ, and Hayabusa
  adds rules of its own. Its informational and "Sysmon Alert" rules
  (`Net Conn (Sysmon Alert)`, `DLL Loaded (Sysmon Alert)`, …) match most Sysmon events and
  account for most of its lead in detections: of its 589,555 hits on the single-channel
  corpus, 46,783 are informational, 92,205 low and 439,291 medium. Chainsaw loads only the
  rules its mapping file can express. Detection totals therefore do not measure detection
  quality.
- **Rules matched are counted by Sigma rule id.** Zircolite's merged ruleset carries some
  rules once per log source, under one id.
- **Memory covers the whole process tree.** Zircolite picks its worker count from the
  files and the free RAM — four on the single-channel corpus, eight on the multi-channel
  one — and the figure is their sum, the most of the three tools. Hayabusa and Chainsaw run
  as one process with several threads. `--no-parallel` runs one file at a time.
- **Zircolite's time includes Python start-up and loading its 9.4 MB ruleset.** On a 68 KiB
  EVTX file a run takes 0.58 s, under a tenth of the single-channel figure and 2% of the
  multi-channel one.

## Setup

Apple M1 Max (10 cores, 64 GB), macOS, Python 3.14.8 and SQLite 3.54.1 for Zircolite
(commit `e21ed93`), with the compiled flattening kernel. Logs and outputs on the same
internal SSD. Nothing else running.

| Tool | Rules |
|------|-------|
| Zircolite 4.6.0 | `rules/rules_windows_merged.json`, the default ruleset, as shipped in `rules/` (SigmaHQ `b7920ed`, 2026-10-18) |
| Hayabusa 4.2.0 | hayabusa-rules `3264c6f` (2026-10-16), pulled into the `rules/` directory of its release package |
| Chainsaw 2.17.1 | SigmaHQ `b7920ed` (2026-10-18): `rules`, `rules-emerging-threats` and `rules-threat-hunting`, plus Chainsaw's own `rules/`, through `mappings/sigma-event-logs-all.yml` |

The commands, as `tools/tool-benchmark.py` runs them:

```shell
# Zircolite
python3 zircolite.py -e TEST_CORPUS/ -r rules/rules_windows_merged.json -o zircolite.json -l zircolite.log

# Hayabusa, from its own directory
./hayabusa dfir-timeline -d TEST_CORPUS/ -w -q -Q -K -C -t jsonl -o hayabusa.jsonl

# Chainsaw, from its own directory
./chainsaw --no-banner hunt TEST_CORPUS/ -s sigma/rules -s sigma/rules-emerging-threats \
    -s sigma/rules-threat-hunting -r rules/ --mapping mappings/sigma-event-logs-all.yml \
    --jsonl -o chainsaw.jsonl
```

`-w` only stops Hayabusa asking which rules to load and keeps its defaults (every level,
the `standard` output profile). `-C` overwrites its output file, `-t jsonl` selects JSONL
output, and `-q`, `-Q` and `-K` drop the banner, the error-log files and colour.

## Method

The three tools run in turn, and the order rotates on every pass so none of them always
follows the same neighbour. The warm-up pass fills the page cache and is not recorded.
Each run is timed from launch to exit, and the resident memory of its whole process tree
is sampled every 20 ms. Detections are counted from each tool's output after it exits,
outside the timed region. A tool whose count changed between passes would have stopped
the benchmark; none did.

## Reproducing

`tools/tool-benchmark.py` runs the whole comparison on any logs and writes a JSON report
with every pass, each tool's version and loaded rule count, and the commit of every rule
checkout:

```shell
pdm run python tools/tool-benchmark.py --events /path/to/evtx \
    --hayabusa /opt/hayabusa/hayabusa \
    --chainsaw /opt/chainsaw/chainsaw \
    --chainsaw-sigma /opt/sigma/rules \
    --chainsaw-sigma /opt/sigma/rules-emerging-threats \
    --chainsaw-sigma /opt/sigma/rules-threat-hunting \
    --chainsaw-rules /opt/chainsaw/rules \
    --chainsaw-mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml
```

See [`tools/README.md`](https://github.com/wagga40/Zircolite/tree/master/tools) for every
option.

To compare Zircolite's own settings or two checkouts, use `tools/throughput-benchmark.py`;
time the rule phase alone with `-D` and `--performance-json`.

## Offline viewer and package writer

The investigation benchmark uses the same eight-file capture with all 1,868,682
events retained for the offline package and 264,200 detection hits. The baseline
is 4.7.1 (`ff8da3c`). Python DuckDB builds the Parquet files. The viewer reads
them with the separately bundled DuckDB-WASM 1.4.3.

| Operation on this capture | 4.7.1 | Updated viewer |
|---|---:|---:|
| Engine and data ready | 1.864 s | 1.899 s |
| Startup work finished, including any eager index load | 2.260 s | 1.899 s |
| Peak RSS through idle, Node process hosting the bundled engine | 1,696 MiB | 1,177 MiB |
| Wrapped script bytes read through idle | 258,206,615 | 151,963,611 |

These are medians of three fresh processes per version on an Apple M1 Max.
The first bare-word search pays about 0.35 s to load and register the text
index before its scan. Field searches and ordinary navigation leave it on disk.

The optional `--package-explore-index` was measured against the same events and
the same viewer with the chronological index disabled. Each measurement builds
the result IDs, counts the rows and fetches the first 200 with three displayed
fields. The table gives medians of five warmed paired runs in the bundled engine
under Node. All ordered event IDs, positions and first-page values matched.

| Explore operation | Read events | Read chronological index |
|---|---:|---:|
| All events, oldest first | 421 ms | 122 ms |
| All events, newest first | 447 ms | 121 ms |
| Most common host | 273 ms | 150 ms |
| Most common channel | 366 ms | 187 ms |
| EventID 4624 | 215 ms | 123 ms |
| Time range covering 15% of the capture | 139 ms | 93 ms |

The index occupied 8,503,544 Parquet bytes. With the same viewer and evidence,
adding it grew the ZIP from 186,419,137 to 194,938,396 bytes (+4.6%).
Reading it at startup added 44 ms
to median engine-ready time in a separate three-pair test. These measurements
cover query execution and registration. Browser layout and rendering are outside
the timings. The index is opt-in because creating and opening the extra table
has a cost, and the common filtered pivots improved by less than 2×.

The wide Python writer test used a 142,737-row, 184-column spool, a 4 GB DuckDB
buffer limit and four threads. Writing the events and full-text Parquet files
took 1.023 s and 1,981 MiB peak RSS on 1.5.6, and 1.107 s and 1,458 MiB on
2.0.0. The thread sweep and narrow-input measurements are in
[Parquet writer measurements](Internals.md#parquet-writer-measurements).

### Complete CLI runs

Both checkouts use Python 3.14.10, the native flattening kernel and the same
4,538-rule Windows ruleset. One warm-up per checkout fills separate rule and
viewer-asset caches. The execution order alternates over five measured passes.
Wall time covers launch through exit. The harness samples resident memory across
the parent and its descendants, and samples visible temporary files including
package staging. The macOS sampler uses `proc_listchildpids` to enumerate the
measured process tree. Detection and decoded package comparisons run after the CLI exits.

| Capture and output | 4.7.1 wall | Updated wall | 4.7.1 peak RSS | Updated peak RSS | 4.7.1 / updated visible temp | 4.7.1 / updated ZIP |
|---|---:|---:|---:|---:|---:|---:|
| HANCITOR, package | 12.06 s | 12.03 s | 1,867 MiB | 1,292 MiB | 149.4 / 149.5 MiB | 32.48 / 32.39 MiB |
| T001, package | 66.42 s | 68.63 s | 10,688 MiB | 10,698 MiB | 486.3 / 496.0 MiB | 177.81 / 181.99 MiB |
| HANCITOR, detections | 7.90 s | 8.10 s | 976 MiB | 976 MiB | 132.2 / 134.1 MiB | — |
| T001, detections | 34.26 s | 35.96 s | 7,458 MiB | 7,459 MiB | 500.2 / 501.0 MiB | — |

The package comparison uses macOS on a 64 GiB M1 Max. The four HANCITOR files
produce 454,806 packaged events and 162,362 detection matches. Native DuckDB
is 1.5.6 in the baseline environment and 2.0.0 in the candidate. The viewer
index is off for the default package comparison.

All T001 runs matched on the normalized detection output, every packaged event,
rule, hit and alert, full-text contents and stable manifest metadata. The native
package took 66.09–85.42 s on 4.7.1 and 66.03–88.09 s on the candidate. Four
passes used eight workers and one used seven for each checkout. A separate
single-worker storage experiment ran during part of the comparison. On this
capture median wall time rose 3.3% and peak RSS changed by 0.1%.

One additional full CLI run with `--package-explore-index` finished in 65.12 s
and produced a 199,654,352-byte ZIP. Its detection fingerprint and the decoded
contents of all six original tables matched the default package. All 1,868,682
index positions, timestamps, event identifiers and pivot values matched the
original events in chronological order.

Detection-only runs used an offline ARM64 Linux container with a 16 GiB memory
limit, swap disabled and SQLite 3.46.1. The cached image's Python source matched
the 4.7.1 checkout. Both environments used the image's Python dependencies.
The detection command uses SQLite and the shipped converted rules. Python
DuckDB 2.0 package generation was measured on macOS, where the wheel was
available locally.

The six-worker T001 runs retained 1,720,383 events after detection filtering
and agreed on all 264,200 matches. The complete CLI comparisons did not reach
the targets of 20% lower wall time and 30% lower peak RSS together. HANCITOR
package generation reached the memory target on its own.

Run the comparison from the candidate checkout with two local environments.

```sh
.venv/bin/python tools/throughput-benchmark.py \
  --events /path/to/evtx --ruleset rules/rules_windows_merged.json \
  --baseline-root /path/to/baseline --baseline-python /path/to/baseline/.venv/bin/python \
  --variants baseline current --modes auto --exports package --warmup 1 --passes 5
```

### Detection field projection

The prototype builds a narrower SQLite row for each event family. A Security
4624 row keeps the values that eligible rules can test for that channel and
EventID. A Sysmon process-creation row can keep a different set. The full
canonical event stays in compressed evidence storage, keyed by its original
row ID. Matching rules and exports can recover every original field.

On one 142,737-event forwarded log, the production rule executor, pruning and
prefilter ran against both layouts. The pair matched on 6,268 detections across
11 rules, complete evidence, diagnostics and the replay of every event.

| Single worker, same committed input | Wide SQLite | Projected SQLite + evidence |
|---|---:|---:|
| Build and index | 0.30 s | 10.23 s |
| Execute rules, hydrate and hash matched evidence | 6.98 s | 7.71 s |
| Both stages | 7.28 s | 17.94 s |
| Peak worker RSS | 762 MiB | 487 MiB |

This was one shared-host pair. The common 8.76 s staging step and separate
full-evidence replay are outside the two stage timings. Projection reduced peak
worker memory by 36%, but its build alone took longer than both wide-table
stages together. It remains a developer experiment. The normal detector uses
the existing SQLite layout. [Reproduce the storage comparison](../tools/README.md#compact_storage_benchmarkpy).
