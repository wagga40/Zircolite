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
pdm install                                        # or: uv sync / poetry install
pdm run python3 zircolite.py --events <logs>
```

Detections go to `detected_events.json`, with a detection table and a summary on the
terminal. Add `--package` to explore every event in the [Zircolite Viewer](Viewer.md).
[Docker](Usage.md#docker) works too.

## Which ruleset?

| Your logs | Ruleset |
|-----------|---------|
| Windows, with or without Sysmon | `rules/rules_windows_merged.json`, the default |
| Windows, Sysmon only | `rules/rules_windows_sysmon.json` |
| Linux: Auditd, Sysmon for Linux | `rules/rules_linux.json` |
| Your own Sigma rules | The YAML file or directory |

Pass it with `--ruleset`. See [Rulesets](Usage.md#rulesets--rules) for the others and for
updates.

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
