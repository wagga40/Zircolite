# Throughput implementation measurements

Measured on 2026-09-12 using Python 3.14.7, SQLite 3.53.4 and a 10-CPU macOS arm64 host.
The baseline is commit `93d483c09ece603416e57decda5977371ec91fc7`; the candidate is the
working tree implementing the throughput review. Both used the same installed
packages, generated events and rules. No benchmark ran concurrently with tests.

These are synthetic workloads with one detection rule. They establish behavior on
these inputs, rather than predicting throughput for a production ruleset.

Each value is the median of three interleaved complete CLI runs, including process
startup, ingestion, indexing, detection and output. All runs used per-file databases.
Thread and process runs requested four workers. Generation and detection comparison
ran outside the timed region. Every pass produced the same detection multiset as
the baseline, including duplicate counts.

| Workload | Baseline sequential | Current sequential | Current threads | Current processes |
|---|---:|---:|---:|---:|
| 40,000 events / 100 files | 7.69 s | 1.18 s | 1.15 s | 1.15 s |
| 400,000 events / 4 mixed-schema files | 5.30 s | 3.92 s | 4.97 s | 1.82 s |
| 300,000 matches / 4 files | 4.88 s | 3.61 s | 6.01 s | 1.80 s |

For the 300,000-match workload, median sequential peak RSS fell from
385.7 MiB to 98.0 MiB. The row
spool removes the need to retain every detection in memory. Templates and library
callers requesting complete results still retain matches.

Process workers helped on the larger workloads; threads were slower than sequential
processing on those same inputs. Threads remain the default, with process mode
available through `--executor process`. Small inputs can be dominated by startup.

The host restricts child-process inspection. Process-mode RSS in the raw report is
**parent-only**, and cannot be compared with sequential RSS as total memory usage.
The 20 ms sampler estimates peaks; it is not an allocation profiler.

[Raw measurements](benchmarks/implementation-2026-09-12.json) include every run,
fingerprint, time and RSS sample maximum.

## Reproducing the candidate workloads

```sh
python tools/throughput-benchmark.py --scenario many-small --event-count 40000 --files 100 --passes 3 --workers 4 --report small.json
python tools/throughput-benchmark.py --scenario mixed --event-count 400000 --files 4 --passes 3 --workers 4 --report mixed.json
python tools/throughput-benchmark.py --scenario noisy --event-count 300000 --files 4 --passes 3 --workers 4 --report noisy.json
```

The baseline comparison used `make_corpus` and `measure` from the same harness,
invoking the baseline's `zircolite.py` with `--no-parallel --no-auto-mode` on the
same temporary corpus and rules as each candidate. The baseline source was extracted
with `git archive`; its dependencies and field-mapping config matched the candidate.

Additional smoke runs compared sequential, thread and process detection output on
real EVTX fixtures (two matches) and compressed JSON arrays (30,000 events, 300
matches). Both agreed across all modes. The initial array smoke test used the
validating standard-library fallback. `ijson` 3.5.1 with its `yajl2_c` backend became
available after the executor benchmarks, and the full suite then passed with that
backend: 1,803 passed, one skipped. The suite also explicitly exercises the fallback.
Ruff and mypy passed. Native Rust ingestion, Vectorscan and DuckDB remain separate
experiments described in the tools README.

## JSON-array backend comparison

After `ijson` became available, three interleaved sequential runs compared its C
backend with the fallback on 400,000 events in four gzip-compressed JSON arrays.
Both paths produced the same 4,000 detections on every pass. Complete CLI median
time fell from **6.64 s** with the fallback to **4.83 s** with `ijson` 3.5.1
(`yajl2_c`), a 27% reduction in elapsed time.

[Raw parser measurements](benchmarks/array-backends-2026-09-12.json) contain all runs.
The fallback was selected in a fresh interpreter by setting
`zircolite.jsonstream.ijson = None` before calling `zircolite.cli.main()`; all CLI
arguments, installed packages, input files and rules were otherwise identical.
A subsequent compressed-array smoke run also agreed across sequential, thread and
process modes with the C parser enabled.
