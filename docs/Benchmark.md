# Benchmark

Zircolite, [Hayabusa](https://github.com/Yamato-Security/hayabusa) and
[Chainsaw](https://github.com/WithSecureLabs/chainsaw) on the same Windows logs and machine,
each at its defaults with its own rules, in November 2026.

![Median wall time per tool. One channel: Zircolite 5.0 s, Hayabusa 23.2 s, Chainsaw 47.0 s. Eleven channels: Zircolite 19.2 s, Hayabusa 498.9 s, Chainsaw 176.5 s](pics/benchmark.svg)

## Results

Medians of three timed passes after one warm-up, with the range in brackets. Peak memory is
the median peak of the whole process tree.

### One channel

4 Sysmon EVTX files, 478 MB, 452,554 events.

| Tool | Rules loaded | Wall time | Peak memory | Detections | Rules matched |
|------|-------------:|----------:|------------:|-----------:|--------------:|
| Zircolite | 4,538 | **5.0 s** (5.0–5.0) | 1,626 MiB | 162,362 | 108 |
| Hayabusa 4.4.0 | 4,689 (2,307 after its channel filter) | 23.2 s (23.0–23.3) | 767 MiB | 589,555 | 134 |
| Chainsaw 2.18.0 | 3,638 | 47.0 s (46.9–51.6) | 375 MiB | 41,548 | 100 |

### Eleven channels

8 EVTX files, seven forwarded-event logs and one Sysmon log: 13.3 GB, 1,868,682 events, of
which Zircolite's event filter keeps 1,720,383. Security holds 74% of them, then the two
PowerShell channels, Sysmon, WMI-Activity, TaskScheduler and five more.

| Tool | Rules loaded | Wall time | Peak memory | Detections | Rules matched |
|------|-------------:|----------:|------------:|-----------:|--------------:|
| Zircolite | 4,538 | **19.2 s** (18.9–19.3) | 6,082 MiB | 264,200 | 124 |
| Hayabusa 4.4.0 | 4,689 (4,440 after its channel filter) | 498.9 s (497.6–499.2) | 1,410 MiB | 703,920 | 182 |
| Chainsaw 2.18.0 | 3,638 | 176.5 s (176.1–177.6) | 1,173 MiB | 122,997 | 83 |

## Reading the numbers

- **The channel mix reorders the Rust tools.** Hayabusa's channel filter keeps 2,307 of its
  rules on one channel and 4,440 on eleven, and its time per event goes from 51 µs to 290 µs.
  Zircolite stays near 11 µs and Chainsaw near 103 µs on both (counting the events
  Zircolite's filter keeps).
- **Detection totals do not compare.** Each tool loads its own conversion of SigmaHQ.
  Hayabusa adds informational rules such as `Net Conn (Sysmon Alert)` that match most Sysmon
  events, and Chainsaw loads only what its mapping file can express. Rules matched are
  counted by Sigma id.
- **Zircolite's memory is a sum over its workers**, 8 and 10 here, chosen from the files,
  their [slices](Internals.md#slices-of-large-evtx-files) and the free RAM. The two others run
  as one process. `--no-parallel` runs one file at a time.
- **Start-up is included.** Python and the 9.4 MB default ruleset take most of the 0.40 s
  Zircolite needs for a 68 KiB EVTX file.

## Packages and the viewer

`--package` keeps every event for the [Zircolite Viewer](Viewer.md), so the event filter is
off and the run also writes Parquet.

| Median of three, same harness | One channel | Eleven channels |
|---|---:|---:|
| Events packaged | 454,806 | 1,868,682 |
| Detections only | 4.9 s, 1.6 GiB | 19.2 s, 5.9 GiB |
| With `--package` | 8.1 s, 1.7 GiB | 45.5 s, 7.4 GiB |
| Package zip | 32 MiB | 181 MiB |
| Viewer ready in Chromium | 1.9 s | 1.9 s |

The viewer loads its tables incrementally, so it is ready as fast on either package.

## Setup and method

Apple M1 Max (10 cores, 64 GB), macOS, Python 3.14.10 and SQLite 3.54.1 for Zircolite
(commit `a790666`), with the compiled flattening kernel. Logs and outputs on the internal SSD,
nothing else running.

| Tool | Rules |
|------|-------|
| Zircolite | `rules/rules_windows_merged.json`, the default ruleset as shipped (SigmaHQ `05d1031`, 2026-10-21) |
| Hayabusa 4.4.0 | hayabusa-rules `97b3fd9` (2026-10-28) in its `rules/` directory |
| Chainsaw 2.18.0 | SigmaHQ `05d1031`: `rules`, `rules-emerging-threats` and `rules-threat-hunting`, plus Chainsaw's own `rules/`, through `mappings/sigma-event-logs-all.yml` |

The tools run in turn, in an order that rotates every pass, after a warm-up pass that fills
the page cache. Each run is timed from launch to exit while the memory of its process tree
is sampled every 20 ms. Detections are counted afterwards; a count that changed between
passes would stop the benchmark.

<details>
<summary>Commands, and how to reproduce</summary>

As `tools/tool-benchmark.py` runs them:

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

Hayabusa's `-w` only skips its rule-selection prompt, keeping every level and the `standard`
profile; `-q`, `-Q` and `-K` drop the banner, error logs and colour.

The script runs the whole comparison on any logs and writes a JSON report with every pass,
each tool's version and rule count, and every rule checkout's commit:

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

To compare Zircolite's own settings or two checkouts, use `tools/throughput-benchmark.py`.
[`tools/README.md`](https://github.com/wagga40/Zircolite/tree/master/tools) documents both.

</details>
