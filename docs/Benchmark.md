# Benchmark

Recorded results for Zircolite, [Hayabusa](https://github.com/Yamato-Security/hayabusa)
and [Chainsaw](https://github.com/WithSecureLabs/chainsaw) on the same Windows logs and
machine, recorded in September 2026. Each tool used its defaults and its own rules, so the
results compare those configurations. Tool and rule revisions are listed under
[Setup](#setup).

## Results

One corpus contains a single channel; the other contains eleven. Both used the same
machine, tool versions and rule checkouts. Times are medians of three timed passes after
one warm-up pass, with the range in brackets.

### Single-channel corpus

4 Sysmon EVTX files, 478 MB, 452,554 events.

| Tool | Rules loaded | Wall time | Peak memory | Detections | Rules matched |
|------|-------------:|----------:|------------:|-----------:|--------------:|
| Zircolite | 4,319 | **11.6 s** (11.6–14.4) | 1,207 MiB | 149,069 | 88 |
| Hayabusa 4.1.0 | 4,658 (2,293 after its channel filter) | 24.7 s (23.3–25.1) | 900 MiB | 589,409 | 132 |
| Chainsaw 2.16.0 | 3,524 (388 could not be loaded) | 113.5 s (92.8–125.5) | 346 MiB | 40,843 | 86 |

Chainsaw's times varied the most between passes; an earlier series on the same machine gave it 100.0 s
(97.3–102.9).

### Multi-channel corpus

8 EVTX files — seven forwarded-event logs and one Sysmon log — 13.3 GB, 1,720,377 events
once Zircolite's event filter has run, spread over eleven channels. Security carries 74% of
them, then Windows PowerShell (184,183), PowerShell/Operational (172,759), Sysmon (67,371),
WMI-Activity (13,228), TaskScheduler (7,017) and five more.

| Tool | Rules loaded | Wall time | Peak memory | Detections | Rules matched |
|------|-------------:|----------:|------------:|-----------:|--------------:|
| Zircolite | 4,319 | **104.8 s** (102.8–106.3) | 8,103 MiB | 257,678 | 104 |
| Hayabusa 4.1.0 | 4,658 (4,409 after its channel filter) | 518.8 s (515.6–520.0) | 1,599 MiB | 704,533 | 181 |
| Chainsaw 2.16.0 | 3,524 | 206.3 s (197.4–215.3) | 338 MiB | 6,871 | 67 |

## Reading the numbers

- **Channel mix affects rule pruning and runtime.**
  Hayabusa reports it directly: its channel filter keeps 2,293 of its 4,658 rules on the
  single-channel corpus and 4,409 on the multi-channel one. Per event it goes from 55 µs to
  302 µs between the two, while Zircolite goes from 26 µs to 61 µs and Chainsaw drops from
  251 µs to 120 µs. These rates use the reported corpus counts; the multi-channel count
  is after Zircolite's event filter, not a measurement of each tool's parsed event count.
- **The rule sets differ.** Each tool loads its own conversion of SigmaHQ, and Hayabusa
  adds 181 rules of its own. Hayabusa's own informational and "Sysmon Alert" rules
  (`Net Conn (Sysmon Alert)`, `DLL Loaded (Sysmon Alert)`, …) match most Sysmon events,
  and account for most of its lead in detections. Of its 589,409 hits on the single-channel
  corpus, 46,783 are informational, 92,205 low and 439,194 medium. Chainsaw loads only the
  rules its mapping file can express, and it reports far fewer hits on the multi-channel
  corpus than on the Sysmon-only one — 6,871 against 40,843 — despite the larger input.
  Detection totals therefore do not measure relative detection quality.
- **Rules matched are counted by Sigma rule id.** Zircolite's merged ruleset carries some
  rules once per log source, under one id.
- **Memory covers the whole process tree.** Zircolite picks its
  worker count from the files and the free RAM — four on the small corpus, five on the
  large one — and the figure is their sum. Hayabusa and Chainsaw run as one process with
  several threads. Zircolite used the most memory in these runs. `--no-parallel` disables
  its file workers, reducing concurrent databases at the cost of parallelism.
- **Zircolite's time includes Python start-up and loading 7.6 MB of rule SQL.** On very
  small inputs that fixed cost dominates; it is about a second, so roughly a tenth of the
  small-corpus figure and about 1% of the large one.

## Setup

Apple M1 Max (10 cores, 64 GB), macOS, Python 3.14 and SQLite 3.53 for Zircolite, with the
compiled flattening kernel. Logs and outputs on the same internal SSD. Nothing else
running.

| Tool | Rules |
|------|-------|
| Zircolite | `rules/rules_windows_merged.json`, the default ruleset, as shipped in `rules/` (SigmaHQ, 2026-09-13) |
| Hayabusa 4.1.0 | The `rules/` directory of its release package, hayabusa-rules `fffbdd1` (2026-09-03) |
| Chainsaw 2.16.0 | SigmaHQ `2e8fd89` (2026-09-15): `rules`, `rules-emerging-threats` and `rules-threat-hunting`, plus Chainsaw's own `rules/`, through `mappings/sigma-event-logs-all.yml` |

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

## Zircolite configurations

How Zircolite's own settings compare, with `rules/rules_windows_merged.json` (4,319 rules)
on the same machine, Python 3.14 and SQLite 3.53, with the compiled kernel. These came from
a separate session from the comparison above, hence 11.0 s here against 11.6 s there. Every
configuration reported the same detections as `--rule-prefilter off`.

| Workload | Baseline (`c972b28`) | Measured |
|---|---:|---:|
| Single-channel corpus, auto (processes) | 42.0 s | 11.0 s |
| Single-channel corpus, `--unified-db` | — | 22.8 s |
| Single-channel corpus as database input (`-D`) | — | 11.7 s (51.8 s with the prefilter off) |
| EVTX-ATTACK-SAMPLES, 278 files, auto (unified) | 7.0 s | 5.8 s |
| EVTX-ATTACK-SAMPLES, 278 files, per-file | 473 s | 55.7 s |

The single-channel corpus gains from the literal prefilter and process workers; the 278
small multi-channel files show the per-rule costs of per-file runs, which census pruning
and lazy result spools remove. Compare configurations or checkouts with
`tools/throughput-benchmark.py`, and time the rule phase alone with `-D` and
`--performance-json`.

## Text equality bounds and schema preflight (October 2026)

This compares the [candidate filter](Internals.md#rule-execution) before and after it learned
to bound text equality and to add missing rule fields before planning: commit `037144a`
against the next one, with the 4,515-rule `rules_windows_merged.json` (SHA-256
`8ea9b07f5fd35f37f6bf5e2430010ff8bb9160c2d072039a66a95ff29aabc9eb`). Both ran in the same
environment: Python 3.14.8, SQLite 3.53.4, compiled flattening kernel, macOS on Apple
Silicon (10 cores, 64 GiB). Times are medians of three interleaved passes, ranges in
brackets; memory is the peak of the whole process tree. Multi-file runs use four process
workers with automatic mode selection off. Every pass reported the same detections, down to
each event's fields.

| Corpus | Before | After | Peak RSS before / after | Matches |
|---|---:|---:|---:|---:|
| T001, 8 files (13.3 GiB) | 118.59 s (117.47–127.37) | 67.96 s (66.00–68.52) | 7,071 / 7,065 MiB | 264,200 |
| T001 Sysmon file (142 MiB), sequential | 27.58 s (27.57–27.65) | 8.83 s (8.77–8.95) | 251 / 254 MiB | 13,905 |
| HANCITOR, 4 files (478 MiB) | 11.90 s (11.78–11.94) | 11.17 s (11.04–11.27) | 1,252 / 1,275 MiB | 162,362 |
| EVTX-ATTACK-SAMPLES, 278 files, per file | 12.10 s (11.95–12.46) | 12.10 s (12.04–12.14) | 730 / 735 MiB | 1,562 |

Most of the gain is in rules such as `Image LIKE '%\cmd.exe' OR OriginalFileName='Cmd.Exe'`:
the equality used to leave the whole condition unbounded. On the Sysmon file, 1,943 queries
get candidates instead of 1,284, and the detection stage falls from 22.40 to 3.79 seconds.
Over T001 the four workers spend 48.0 seconds in detection instead of 208.6, and 50.0 in
building candidates instead of 41.5, since more columns are indexed. Ingestion, at 108
seconds, is now the larger cost. The attack samples are below the filter's 1,000-event
threshold, so nothing changes for them; HANCITOR has a single channel and few such rules.

Reproduce a row against a checkout of the earlier commit (copy the compiled kernel into it):

```shell
pdm run python tools/throughput-benchmark.py \
  --events samples/T001-04062021 --ruleset rules/rules_windows_merged.json \
  --variants baseline current --baseline-root /path/to/037144a \
  --modes process --workers 4 --passes 3
```

The Sysmon row uses `--events 'samples/T001-04062021/Microsoft-Windows-Sysmon%4Operational.evtx'`
and `--modes sequential`.

## Startup, regex bounds, page size and batch size (October 2026)

The same method as above, for the changes that followed: commit `1ec809a` against
`d1dd080`, each with its own compiled kernel, a warm rule-analysis cache, and the 4,515-rule
`rules_windows_merged.json`. Times are medians of three interleaved passes, ranges in
brackets; every pass reported the same detections.

| Corpus | Before | After | Peak RSS before / after | Matches |
|---|---:|---:|---:|---:|
| T001, 8 files (13.3 GiB) | 66.02 s (65.80–70.05) | 53.71 s (51.67–54.69) | 7,075 / 5,574 MiB | 264,200 |
| T001 Sysmon file (142 MiB), sequential | 9.09 s (9.07–9.13) | 4.55 s (4.53–4.58) | 255 / 273 MiB | 13,905 |
| HANCITOR, 4 files (478 MiB) | 11.35 s (11.16–11.40) | 8.10 s (8.00–8.11) | 1,276 / 1,196 MiB | 162,362 |
| SOC subset, 7 files (108 MiB) | 6.19 s (6.15–6.27) | 3.29 s (3.20–3.31) | 876 / 862 MiB | 1,201 |
| EVTX-ATTACK-SAMPLES, 278 files, per file | 13.48 s (12.83–14.18) | 11.38 s (11.26–11.53) | 729 / 758 MiB | 1,562 |

Where the time went, per stage (CPU seconds summed over workers):

- **Setup.** About 2.4 s became 0.1 s in every worker, now that the rule analysis comes from
  disk and workers no longer import pySigma.
- **Detection.** T001 went from 47.7 to 18.9 s, mostly because regular expressions now bound
  their own candidates.
- **Ingestion.** T001 went from 105.1 to 91.2 s, from smaller insert batches and C-side
  folding of field-name case.
- **Memory.** On T001, 64 KiB pages and the smaller batches take 1.5 GiB off the peak. The
  small rises on the Sysmon log and the attack samples are the loaded rule analysis.

The per-change measurements are in the commit messages of that range.
