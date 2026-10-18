# Benchmark

Recorded results for Zircolite, [Hayabusa](https://github.com/Yamato-Security/hayabusa)
and [Chainsaw](https://github.com/WithSecureLabs/chainsaw) on the same Windows logs and
machine, recorded in October 2026. Each tool used its defaults and its own rules, so the
results compare those configurations. Tool and rule revisions are listed under
[Setup](#setup).

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
