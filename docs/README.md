# Zircolite Documentation

**Zircolite** is a standalone Python 3 tool that applies SIGMA detection rules to log
files. Rules are converted to SQLite SQL, events are flattened into an in-memory SQLite
database, and each rule runs as a query against it.

It reads MS Windows EVTX (binary, XML and JSONL), Auditd, Sysmon for Linux, EVTXtract,
CSV, XML and JSON — plain, compressed or archived — and in most cases works out which is
which on its own.

## Quick start

```shell
pip3 install -r requirements.txt
python3 zircolite.py --events <logs> --ruleset rules/rules_windows_merged.json
```

Results are written to `detected_events.json`, with a detection table and summary panel on
the terminal. `python3 -m zircolite …` is equivalent from the project root — though
`python -m` searches the working directory rather than the script's own, so the
`zircolite.py` form is the one that works from anywhere.

Start with [Usage → Requirements and Installation](Usage.md#requirements-and-installation)
and [Usage → Basic Usage](Usage.md#basic-usage).

## Contents

| Page | Covers |
|------|--------|
| [Usage](Usage.md) | Installation, running, every command-line option, input formats, rulesets, rule testing, configuration, Docker |
| [Advanced](Advanced.md) | Field transforms, large datasets, parallel processing, event filtering, templating, the Mini-GUI |
| [Internals](Internals.md) | Architecture, module map, SQLite behaviour, automatic SQL repairs |

## Task and Taskfile

The project uses [Task](https://taskfile.dev/) (go-task) for automation. Install it from
[taskfile.dev](https://taskfile.dev/installation/) or your package manager, then run from
the project root:

| Task | Description |
|------|-------------|
| `task --list` | List all available tasks |
| `task clean` | Remove default artifacts (`detected_events.json`, `flattened_events_*.json`, `tmp-*`, `zircolite.log`, …) |
| `task update-rules` | Update the default rulesets from [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2), overwriting `rules/` |
| `task docker-build` | Build the Docker image |
| `task docker-build-multi-arch` | Build for linux/amd64 and linux/arm64 |
| `task docker-push` | Push to Docker Hub, after a multi-arch build |
| `task save` | Save the Docker image to an archive |
| `task get-version` | Print the version from `zircolite/__init__.py` |

`Taskfile.yml` holds these production tasks. Development tasks — lint, format, tests —
live in a separate Taskfile that is not committed; see
[CONTRIBUTING.md](https://github.com/wagga40/Zircolite/blob/master/CONTRIBUTING.md) for
running them directly.
