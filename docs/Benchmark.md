# Benchmark

How Zircolite compares with [Hayabusa](https://github.com/Yamato-Security/hayabusa) and
[Chainsaw](https://github.com/WithSecureLabs/chainsaw), two Rust tools that also run Sigma
rules over Windows event logs, on the same logs and the same machine. Each tool runs at its
own defaults with its own rules: this is what a user gets out of the box, not a
rule-for-rule comparison of the engines.

## Results

HANCITOR corpus: 4 Sysmon EVTX files, 478 MB, 452,554 events. Median of three timed passes
after one warm-up pass, with the range in brackets.

| Tool | Rules loaded | Wall time | Peak memory | Detections | Rules matched |
|------|-------------:|----------:|------------:|-----------:|--------------:|
| Zircolite | 4,319 | **11.7 s** (11.2–11.8) | 1,200 MiB | 73,246 | 86 |
| Hayabusa 4.1.0 | 4,658 (2,293 after its channel filter) | 26.9 s (24.0–28.3) | 905 MiB | 589,409 | 132 |
| Chainsaw 2.16.0 | 3,524 (388 could not be loaded) | 100.0 s (97.3–102.9) | 346 MiB | 40,843 | 86 |

Zircolite was measured at commit `49a309b`, the code this release ships.

## Reading the numbers

- **The rule sets differ.** Each tool loads its own conversion of SigmaHQ, and Hayabusa
  adds 181 rules of its own. Hayabusa's own informational and "Sysmon Alert" rules
  (`Net Conn (Sysmon Alert)`, `DLL Loaded (Sysmon Alert)`, …) match most Sysmon events,
  and account for most of its eightfold lead in detections. Of its 589,409 hits, 46,783 are
  informational, 92,205 low and 439,194 medium. Chainsaw loads only the rules its mapping
  file can express. Detections and rules matched are shown for context. They are not a
  score.
- **Rules matched are counted by Sigma rule id.** Zircolite's merged ruleset carries some
  rules once per log source, under one id.
- **Memory is the whole process tree.** Zircolite picks four worker processes for four
  large files, and its figure is their sum. Hayabusa and Chainsaw run as one process with
  several threads. `--no-parallel` trades Zircolite's speed for a single process.
- **HANCITOR holds a single channel, Sysmon.** Zircolite and Hayabusa skip the rules
  written for channels the logs do not contain, about half of each ruleset. A corpus
  that mixes Security, System and Sysmon logs runs more of them.
- **Zircolite's time includes Python start-up and loading 7.6 MB of rule SQL.** On very
  small inputs that fixed cost dominates; on this corpus it is about a second.

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
python3 zircolite.py -e HANCITOR/ -r rules/rules_windows_merged.json -o zircolite.json -l zircolite.log

# Hayabusa, from its own directory
./hayabusa dfir-timeline -d HANCITOR/ -w -q -Q -K -C -t jsonl -o hayabusa.jsonl

# Chainsaw, from its own directory
./chainsaw --no-banner hunt HANCITOR/ -s sigma/rules -s sigma/rules-emerging-threats \
    -s sigma/rules-threat-hunting -r rules/ --mapping mappings/sigma-event-logs-all.yml \
    --jsonl -o chainsaw.jsonl
```

`-w` only stops Hayabusa asking which rules to load and keeps its defaults (every level,
the `standard` output profile). `-q`, `-Q` and `-K` drop the banner, the error-log files
and colour.

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
option. Zircolite's own before/after measurements, and how to measure its rule phase
alone, are under [Internals → Measured results](Internals.md#measured-results).
