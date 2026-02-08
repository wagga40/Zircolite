# Zircolite Documentation

Documentation for **Zircolite 3.x**. Zircolite is a standalone SIGMA-based detection tool for EVTX, Auditd, Sysmon for Linux, XML, CSV, and JSONL/NDJSON logs. It uses SQLite as a backend for SIGMA rule execution.

**Zircolite** supports the following log sources:

- MS Windows EVTX (EVTX, XML, and JSONL formats)
- Auditd logs
- Sysmon for Linux
- EVTXtract
- CSV and XML logs
- JSON Array logs

### Key Features


- **Multiple Input Formats**: Supports EVTX, JSON Lines, JSON Arrays, CSV, XML, Auditd, and Sysmon for Linux logs.
- **Automatic Log Type Detection**: Automatically identifies log formats (EVTX, Windows JSON/XML, Sysmon, Auditd, ECS, CSV, etc.) and timestamp fields using magic bytes, content analysis, and regex-based fallback -- reducing the need for explicit CLI flags.
- **Parallel Processing**: Automatic parallel file processing. Worker count is calculated based on available RAM, CPU cores, and file sizes.
- **Streaming Mode**: Single-pass event processing (enabled by default) that combines extraction, flattening, and database insertion.
- **YAML Configuration**: Support for YAML configuration files for complex analysis workflows.
- **SIGMA Backend**: Based on a SQLite backend for SIGMA rules.
- **Native Sigma Support**: Directly use native Sigma rules (YAML) via pySigma conversion.
- **Field Transforms**: Apply Python transformations to fields during processing (e.g., Base64 decoding, IOC extraction) using RestrictedPython.
- **Field Splitting**: Extract key-value pairs from fields (e.g., split Sysmon `Hashes` field into `MD5`, `SHA256` fields).
- **Flexible Export**: Export results to JSON, CSV, Splunk, Elastic, Zinc, Timesketch, and more using Jinja templates.

**You can use Zircolite directly with Python.**

### Quick start

1. Install dependencies: `pip3 install -r requirements.txt`
2. Run: `python3 zircolite.py --events <logs> --ruleset <ruleset>`
3. For EVTX with default Sysmon rules: `python3 zircolite.py --evtx sample.evtx --ruleset rules/rules_windows_sysmon.json`

See [Usage → First run](Usage.md#first-run), [Usage → Basic usage](Usage.md#basic-usage), and [Usage → Automatic Log Type Detection](Usage.md#automatic-log-type-detection) for details.

### Task and Taskfile

The project uses [Task](https://taskfile.dev/) (go-task) for automation. Install Task from [taskfile.dev](https://taskfile.dev/installation/) or your package manager, then run tasks from the project root:

| Task | Description |
|------|-------------|
| `task --list` | List all available tasks |
| `task clean` | Remove default artifacts (detected_events.json, tmp-*, zircolite.log, etc.) |
| `task update-rules` | Update default rulesets from [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) (overwrites existing rules in `rules/`) |
| `task docker-build` | Build the Docker image (requires Docker) |
| `task docker-build-multi-arch` | Build multi-architecture image (linux/amd64, linux/arm64) |
| `task docker-push` | Push the image to Docker Hub (after multi-arch build) |
| `task get-version` | Print version from zircolite.py |
| `task save` | Save the Docker image to an archive (set `DOCKER_TAG` as needed) |

The `Taskfile.yml` in the repository defines these production tasks. Development tasks (lint, format, tests) may use a separate Taskfile that is not committed to the repository.

### Documentation Contents

- [Usage](Usage.md) - Installation, first run, basic usage, and input formats
- [Advanced](Advanced.md) - Working with large datasets, streaming mode, parallel processing, filtering, templating, and the Mini-GUI
- [Internals](Internals.md) - Architecture and project structure
