# Zircolite

**Zircolite** runs Sigma detection rules over logs. It flattens events into an SQLite
database, turns each rule into an SQL query, and reports the events that match.

![How Zircolite works: logs are flattened into rows of an SQLite table, Sigma rules become SQL queries, and matching rows become detections](pics/how-it-works.svg)

It reads Windows EVTX (binary, XML and JSON), Auditd, Sysmon for Linux, EVTXtract, CSV, XML
and JSON, plain or compressed, and detects the format on its own.

## Quick start

Download the [standalone binary](Usage.md#standalone-binaries) for your platform from the
[releases](https://github.com/wagga40/Zircolite/releases), unzip it, and point it at your
logs:

```shell
./Zircolite --events <logs>
```

Or run it from source:

```shell
git clone https://github.com/wagga40/Zircolite.git && cd Zircolite
pdm install                                        # or: uv sync
pdm run python3 zircolite.py --events <logs>
```

Detections go to `detected_events.json`, with a detection table and a summary on the
terminal. Add `--package` to explore every event in the [Zircolite Viewer](Viewer.md).
[Docker](Usage.md#docker) works too.

## Which ruleset?

Windows logs, with or without Sysmon, need nothing more: `rules/rules_windows_merged.json`
is the default. For Linux logs pass `--ruleset rules/rules_linux.json`, and for your own
Sigma rules the YAML file or directory. [Rulesets and rules](Usage.md#rulesets--rules)
covers the others and updates.

## Contents

| Page | Covers |
|------|--------|
| [Usage](Usage.md) | Installing, running, rulesets, input formats, output, configuration, troubleshooting, every option |
| [Advanced](Advanced.md) | Field transforms, large datasets, filtering, templates |
| [Zircolite Viewer](Viewer.md) | Packages and the offline browser viewer |
| [Internals](Internals.md) | Architecture, rule execution, the package pipeline, SQLite behaviour, packaging |
| [Benchmark](Benchmark.md) | Zircolite, Hayabusa and Chainsaw on the same logs |

Contributing, building and releasing are covered in
[CONTRIBUTING.md](https://github.com/wagga40/Zircolite/blob/master/CONTRIBUTING.md).
