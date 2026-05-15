# Usage

## Requirements and Installation

- Zircolite works with **Python 3.10** and above.
- It runs on Linux, macOS, and Windows.
- Zircolite uses the `evtx` Python library (pyevtx-rs) for EVTX parsing. If it is not available, you must use an alternative input format.

### Dependencies

**Required packages** (installed via `requirements.txt`):
- `orjson` - Fast JSON parsing
- `xxhash` - Fast hashing for log line identification
- `rich` - Styled terminal output with colors, progress bars, tables, and formatted text
- `RestrictedPython` - Safe execution of field transforms
- `requests` - For rule updates (`-U` option)
- `pySigma` and related packages - For native Sigma rule conversion
- `evtx` (pyevtx-rs) - For EVTX file parsing
- `jinja2` - For templating
- `lxml` - For XML input support
- `psutil` - For memory usage tracking and parallel processing
- `py7zr` - For reading 7-Zip (`.7z`) archives; optional (ZIP and gzip/bzip2 use the standard library)
- `pyyaml` - For YAML configuration file parsing

### Installation from Repository

#### Using [venv](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/) on Linux/macOS

```shell
# INSTALL
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite 
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt

# EXAMPLE RUN
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
python3 zircolite.py -e EVTX-ATTACK-SAMPLES/ -r rules/rules_windows_merged.json
deactivate # Exit the Python virtual environment
```

#### Using [PDM](https://pdm-project.org/latest/)

```shell
# INSTALL (uses pyproject.toml)
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite 
pdm install

# EXAMPLE RUN
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
pdm run python3 zircolite.py -e EVTX-ATTACK-SAMPLES/ -r rules/rules_windows_merged.json
```

#### Using [Poetry](https://python-poetry.org)

```shell
# INSTALL
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite 
poetry install
pip install -r requirements.txt  # if pyproject.toml doesn't cover all deps

# EXAMPLE RUN
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
poetry run python3 zircolite.py -e EVTX-ATTACK-SAMPLES/ -r rules/rules_windows_merged.json
```

#### Using [UV](https://docs.astral.sh/uv/)

```shell
# INSTALL
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite 
uv sync

# EXAMPLE RUN
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
uv run python zircolite.py -e EVTX-ATTACK-SAMPLES/ -r rules/rules_windows_merged.json
```

UV reads `pyproject.toml` and handles the venv automatically. You can also use `uv pip install -r requirements.txt` if you prefer an explicit install.

After installation, you can use [Task](https://taskfile.dev/) for automation (update rules, Docker build, clean): see [Task and Taskfile](README.md#task-and-taskfile) in the [documentation index](README.md).

## First Run

A minimal first run from clone to results:

1. **Clone and install**
   ```shell
   git clone https://github.com/wagga40/Zircolite.git
   cd Zircolite
   pip3 install -r requirements.txt
   ```

2. **Optional: update rulesets**  
   The repository includes rules in `rules/` (e.g. `rules_windows_merged.json`). To fetch the latest pre-built rules from [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2), run:
   ```shell
   python3 zircolite.py -U
   ```
   After `-U`, rules may be named e.g. `rules_windows_merged.json`. See [Rulesets / Rules](Usage.md#rulesets--rules) for naming details.

3. **Run on one EVTX**
   ```shell
   python3 zircolite.py --evtx path/to/sample.evtx --ruleset rules/rules_windows_merged.json
   ```

4. **Output**  
   Results are written to `detected_events.json` in the current working directory (override with `-o`). The summary panel and detection table are printed to the terminal.

For more options, see [Basic usage](Usage.md#basic-usage) and the [Command-Line Options Summary](Usage.md#command-line-options-summary).

## Basic Usage 

Help is available with `zircolite.py -h`.

The simplest way to use Zircolite is:

```shell
python3 zircolite.py --events <LOGS> --ruleset <RULESET>
```

Where: 

- `--events` is a filename or a directory containing the logs you want to analyze (`--evtx` and `-e` can be used instead of `--events`). Zircolite supports the following formats: EVTX, XML, JSON (one event per line), JSON Array (one large array), EVTXTRACT, CSV, Auditd, and Sysmon for Linux. Logs can also be compressed or archived (gzip, bzip2, ZIP, 7-Zip); see [Compressed and archived logs](Usage.md#compressed-and-archived-logs).
- `--ruleset` is a file or directory containing the Sigma rules to use for detection. Zircolite has its own format called "Zircolite ruleset" where all the rules are in one JSON file. Zircolite can also use Sigma rules in YAML format directly (YAML file or directory containing YAML files).

Multiple rulesets can be specified:

```shell
# Example with a Zircolite ruleset and a Sigma rule
python3 zircolite.py --events sample.evtx --ruleset rules/rules_windows_merged.json \
    --ruleset schtasks.yml 
```

By default: 

- `--ruleset` is not mandatory; the default ruleset is `rules/rules_windows_generic.json`.
- Results are written to `detected_events.json` in the same directory as Zircolite. You can choose a CSV-formatted output with `--csv` (see [CSV detection output](Usage.md#csv-detection-output)).
- A `zircolite.log` file will be created in the current working directory; it can be disabled with `--nolog`.
- When providing a directory for event logs, Zircolite will automatically filter by file extension. You can change this with `--fileext`. You can also use `--file-pattern` for custom glob patterns.
- Use `--no-recursion` to disable recursive directory search.

### Interrupting a Run

Pressing `Ctrl+C` triggers a graceful shutdown: in-flight workers finish their current event batch or rule, temporary files are cleaned up, the SQLite database is closed, and Zircolite exits with status code `130` — no Python traceback.

If shutdown takes longer than you want to wait (for example, a worker is mid-way through a large file), press `Ctrl+C` a second time to force an immediate exit. The first message confirms the request:

```
[!] Interrupt received - finishing current work and shutting down. Press Ctrl+C again to force quit.
```

### Command-Line Options Summary

For the full list of options and up-to-date help, run: `python3 zircolite.py -h`. The tables below summarize the main options.

#### Input Files and Filtering

| Option | Description |
|--------|-------------|
| `-e`, `--evtx`, `--events` | Path to log file or directory |
| `-s`, `--select` | Process only files containing the specified string |
| `-a`, `--avoid` | Skip files containing the specified string |
| `-f`, `--fileext` | File extension of logs to process |
| `-fp`, `--file-pattern` | Python glob pattern for file selection |
| `--no-recursion` | Disable recursive directory search |
| `--archive-password` | Password for encrypted ZIP or 7-Zip archives (used for auto-detect and streaming) |

#### Event Filtering

| Option | Description |
|--------|-------------|
| `-A`, `--after` | Process only events after this timestamp |
| `-B`, `--before` | Process only events before this timestamp |
| `--no-event-filter` | Disable early event filtering based on channel/eventID |

#### Input Formats

| Option | Description |
|--------|-------------|
| `-j`, `--json-input` | Input logs are in JSON lines format |
| `--json-array-input` | Input logs are in JSON array format |
| `--db-input` | Use a previously saved database file |
| `-S`, `--sysmon-linux-input` | Process Sysmon for Linux logs |
| `-AU`, `--auditd-input` | Process Auditd logs |
| `-x`, `--xml-input` | Process XML-formatted logs |
| `--evtxtract-input` | Process EVTXtract output |
| `--csv-input` | Process CSV logs |
| `-LE`, `--logs-encoding` | Specify encoding for log files |
| `--no-auto-detect` | Disable automatic log type detection (use explicit format flags instead) |

#### Rules and Rulesets

| Option | Description |
|--------|-------------|
| `-r`, `--ruleset` | Sigma ruleset (JSON or YAML) |
| `-sr`, `--save-ruleset` | Save converted ruleset to disk |
| `-p`, `--pipeline` | Use specified pySigma pipeline |
| `-pl`, `--pipeline-list` | List installed pipelines |
| `-R`, `--rulefilter` | Remove rules by title |
| `--test-rules` | JSON file with rule test cases (true-positive / true-negative); validate rules and exit |

#### Output Options

| Option | Description |
|--------|-------------|
| `-o`, `--outfile` | Output file for results |
| `--csv` | Output results in CSV format |
| `--csv-delimiter` | Delimiter for CSV output (default: `;`) |
| `--keepflat` | Save flattened events as JSON (only processed events; filtered events are excluded) |
| `-d`, `--dbfile` | Save logs to SQLite database |
| `-l`, `--logfile` | Log file name |
| `--hashes` | Add xxhash64 to each event |
| `-L`, `--limit` | Discard results exceeding limit |
| `--profile-rules` | Time each rule execution and print a performance report at the end (Rule Performance table) |

#### CSV detection output

When you use `--csv`, detections are written as one flat table. The header row is built from the **first** match row that is written (plus `rule_title`, `rule_description`, `rule_level`, and `rule_count`). If another rule later returns rows with **additional** columns—for example one rule uses a narrow `SELECT` and another uses `SELECT *`—those extra fields are not added as new CSV columns; values for those keys are omitted from the CSV for that row.

JSON output does not have this limitation: each rule’s result object includes full `matches` with whatever columns the rule’s SQL returns. Use JSON (or post-process) when you need every field from every rule in the export file.

#### Advanced Configuration

| Option | Description |
|--------|-------------|
| `-c`, `--config` | YAML config file (JSON also accepted) |
| `-q`, `--quiet` | Quiet mode: suppress banner, progress bars, and info messages — only the summary panel and errors are shown |
| `--debug` | Enable debug logging (includes full tracebacks on errors) |
| `-n`, `--nolog` | Don't create log files |
| `-RE`, `--remove-events` | Remove log files after analysis |
| `-U`, `--update-rules` | Update rulesets |
| `-v`, `--version` | Display version |
| `--timefield` | Specify timestamp field name (default: 'SystemTime', auto-detects if not found) |
| `--unified-db` | Force unified database mode (all files in one DB, enables cross-file correlation) |
| `--no-auto-mode` | Disable automatic processing mode selection |
| `--no-auto-detect` | Disable automatic log type and timestamp detection |
| `--add-index` | Create an index on the given column(s); repeat or list multiple (e.g. `--add-index Channel EventID`) |
| `--remove-index` | Drop the given index name(s) after creation; repeat or list multiple (e.g. `--remove-index idx_channel`) |
| `--auto-index [N]` | Inspect the loaded ruleset and auto-create indices on the top-N most-referenced columns (defaults to N=5 when used without a value, 0 = off). Combines with `--add-index`. |
| `--all-transforms` | Enable all defined transforms (overrides enabled_transforms list) |
| `--transform-category` | Enable transforms by category name (repeatable) |
| `--transform-list` | List available transform categories and exit |

> [!TIP]
> The field mappings configuration file (`-c` option) also contains **field transforms** that can automatically decode Base64, extract IOCs, detect obfuscation patterns, and more. See the [Field Transforms](Advanced.md#field-transforms) section in Advanced.md for details.

#### YAML Configuration

| Option | Description |
|--------|-------------|
| `-Y`, `--yaml-config` | YAML configuration file (CLI arguments override file settings) |
| `--generate-config` | Generate a default YAML configuration file and exit |

#### Parallel Processing

| Option | Description |
|--------|-------------|
| `--no-parallel` | Disable automatic parallel processing |
| `--parallel-workers` | Maximum number of parallel workers (default: auto-detect) |
| `--parallel-memory-limit` | Memory usage threshold percentage before throttling (default: 85) |

Parallel processing includes several automatic optimizations:

- **LPT scheduling** — files are sorted largest-first so that big files start early and small files fill gaps at the end, minimizing total wall-clock time.
- **Real throttling** — when memory pressure exceeds the configured limit, new task submissions are deferred (not just delayed) until in-flight tasks finish and memory drops back down.
- **Adaptive memory estimation** — after the first file completes, the actual memory-per-file ratio is measured and blended with the heuristic estimate, producing more accurate worker counts for the remaining files.
- **Config pre-loading** — the field-mappings configuration file is read once and shared across all workers, eliminating redundant disk I/O.
- **Schema-preserving table reuse** — workers reuse the SQLite table schema between files (`DELETE FROM` instead of `DROP TABLE`), avoiding repeated `ALTER TABLE` for files with the same structure.
- **Incremental result writing** — detection results are written to the output file as each file completes rather than buffered in memory until the end.

#### Templating and Mini-GUI

| Option | Description |
|--------|-------------|
| `--template` | Jinja2 template for output |
| `--templateOutput` | Output file for template |
| `--timesketch` | Shortcut: Timesketch template → `timesketch-<RAND>.json` |
| `--navigator-output` | Shortcut: ATT&CK Navigator layer → `navigator-<RAND>.json` (or optional custom filename) |
| `--package` | Create ZircoGui package |
| `--package-dir` | Directory for ZircoGui package |

## Output Verbosity

Zircolite has three output verbosity levels:

| Mode | Flag | What's Shown |
|------|------|-------------|
| **Default** | *(none)* | Banner, workload analysis, progress bars with live detection counters, per-file tree view, detection results table, summary panel, ATT&CK coverage panel, output file path, and contextual suggestions |
| **Quiet** | `-q` / `--quiet` | Summary panel only (plus errors and warnings). Ideal for CI pipelines or when piping results to other tools |
| **Debug** | `--debug` | Everything from default mode plus debug-level log messages and detailed tracebacks on errors |

### Quiet Mode

In quiet mode, Zircolite suppresses all non-essential output. Only the final summary panel and error/warning messages are displayed:

```shell
python3 zircolite.py --quiet -e logs/ -r rules/rules_windows_merged.json
```

The log file (if not disabled with `-n`) still captures full details regardless of quiet mode.

### Summary Panel

At the end of every run, Zircolite displays a summary panel with:

- **Duration** and **throughput** (events/second)
- **Phase timing breakdown** — a visual bar showing how time was split between setup and processing phases (shown when phases exceed 0.5 s)
- **File count** and **event count** (with filtered events noted)
- **Event filter efficiency** — match rate percentage showing how many events passed the early channel/eventID filter vs. total scanned
- **Peak memory** usage
- **Workers** — number of parallel workers used (shown when parallel processing is active)
- **Detection summary** by severity (CRIT / HIGH / MED / LOW / INFO)
- **Rule coverage bar** — a visual bar showing how many rules matched at least once out of the total rules loaded
- **Top 5 detections** by severity and event count

After the summary panel, Zircolite also displays:

- **MITRE ATT&CK tactics summary** — a heatmap panel grouping detected techniques by tactic (Execution, Persistence, Defense Evasion, etc.), sorted by hit count
- **Output file path** — shown prominently with a terminal hyperlink (`file://` link) that is clickable in supported terminals (iTerm2, Windows Terminal, modern GNOME/KDE terminals)
- **Contextual suggestions** — tips based on the results, such as suggesting `--package` when critical detections are found

When processing multiple files in per-file mode, a **file tree** is also displayed showing per-file event counts, detection counts, and filtered event counts.

### Detection Results Table

When rules produce matches, Zircolite displays detection results in a Rich table with four columns:

| Column | Description |
|--------|-------------|
| **Severity** | Rule severity level (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL) |
| **Rule** | The rule title |
| **Events** | Number of matching events |
| **ATT&CK** | MITRE ATT&CK technique IDs extracted from rule tags (e.g., T1059, T1053.005) |

Results are sorted by severity (critical first) and then by event count (descending).

In **per-file mode**, each file's detection table includes the filename as its title. In **parallel mode**, results are aggregated across all files into a single combined table.

> **Note:** Severity levels are color-coded in terminal output: **CRITICAL** (bold red), **HIGH** (bold magenta), **MEDIUM** (bold yellow), **LOW** (green), **INFORMATIONAL** (dim).

### Rule performance profiling

Use `--profile-rules` to measure how long each rule takes to execute. After the run, Zircolite prints a **Rule Performance** section with a table of rules sorted by elapsed time (slowest first), plus total rule execution time. This helps you identify rules that are slow on your dataset so you can tune or exclude them (e.g. with `--rulefilter`).

```shell
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --profile-rules
```

The report shows the top rules by execution time (milliseconds). Rules taking ≥500 ms are highlighted in red, ≥100 ms in yellow.

### Sigma Rule Conversion Summary

When converting native Sigma rules (YAML) to Zircolite format, a mini-summary is displayed showing:

- Number of rules **successfully converted**
- Number of **invalid rules skipped** (files that are not valid Sigma detection or correlation YAML)
- Number of rules that **failed** conversion

For example: `[✓] Converted 245 rules (3 invalid skipped, 2 failed)`

### Sigma correlation rules

Zircolite converts **Sigma correlation rules** (e.g. `event_count`, `value_count`, `temporal`) using the same SQLite backend as standalone SIGMA rules. Put the **base rule(s)** and the **correlation rule** in the **same YAML file** (multi-document stream, separated by `---`) or in the **same directory** passed to `--ruleset`, so rule `name` references between documents can resolve. Passing two separate `--ruleset` paths loads separate collections and cannot resolve cross-file references.

Rules that exist only as **references** for a correlation (not emitted as standalone detections) are still compiled internally so the correlation SQL can embed their conditions. The emitted Zircolite ruleset therefore typically contains **one row per correlation rule**, not the referenced base rules.

**Timestamp alignment:** Correlation rules that use `timespan` need a timestamp column in the SQLite database. Zircolite automatically aligns the timestamp field used by the SQLite backend with the timestamp field detected from your logs (or set via `--timefield`). For example, if auto-detection finds `@timestamp` (sanitized to `timestamp`), the correlation SQL will reference `timestamp` instead of the default `SystemTime`. If you use `--timefield UtcTime`, correlation queries will use `UtcTime`. This is handled transparently — no extra configuration is needed.

**Limitations:**

- **`timespan` on `event_count`:** The SQLite backend may not apply the time window in the generated query; counts can reflect all matching rows in the database, not a rolling window. For large time ranges this can differ from engines that enforce `timespan` strictly.
- **Event filter:** Correlation-only entries do not list Windows `Channel` / `EventID` metadata; they are omitted from early event filtering so referenced base rules still drive channel/event filtering.

## Automatic Log Type Detection

As of version 3.0, Zircolite can **automatically detect** the log format and timestamp field of input files, reducing the need for explicit format flags like `--json-input`, `--auditd-input`, `--sysmon-linux-input`, etc.

### How It Works

When you point Zircolite at a file or directory without specifying a format flag, the `LogTypeDetector` analyzes a sample of the input to determine:

1. **File format** (EVTX binary, JSON/JSONL, XML, CSV, plain text)
2. **Log source** (Windows EVTX, Sysmon Windows/Linux, Auditd, ECS/Elastic, EVTXtract, etc.)
3. **Timestamp field** (SystemTime, UtcTime, @timestamp, etc.)

For **compressed or archived files** (`.gz`, `.bz2`, `.zip`, `.7z`), detection first resolves the inner file (decompressing or opening the archive, using `--archive-password` when needed), then applies the phases below to the inner content.

Detection is performed in three phases:

| Phase | Method | Example |
|-------|--------|---------|
| **1. Magic bytes** | Checks the file header for binary signatures | EVTX files start with `ElfFile\x00` |
| **2. Content analysis** | Parses a 64 KB sample for structural patterns | Windows JSON events have `Event.System.Channel` |
| **3. Extension fallback + regex** | Falls back to the file extension, enriched with regex-based timestamp scanning | `.log` files with ISO 8601 timestamps |

Each detection result includes a **confidence level** (`high`, `medium`, `low`):

- **High**: Strong structural match (e.g., EVTX magic bytes, Sysmon channel in JSON)
- **Medium**: Reasonable match (e.g., generic JSON with a detected timestamp field)
- **Low**: Extension-based fallback only

### Supported Auto-Detections

| Log Source | Detection Signals | Timestamp Field |
|------------|-------------------|-----------------|
| Windows EVTX (binary) | Magic bytes (`ElfFile\x00`) | `SystemTime` |
| Windows EVTX JSON | Nested `Event.System` structure with `Channel`/`EventID` | `SystemTime` |
| Windows EVTX XML | XML with Microsoft Event namespace | `SystemTime` |
| Sysmon Windows JSON | `Channel` = `Microsoft-Windows-Sysmon/Operational` | `UtcTime` |
| Sysmon for Linux | Syslog header + embedded `<Event>` XML | `UtcTime` |
| Auditd (raw) | `type=XXXX msg=audit(...)` pattern | `timestamp` |
| Auditd (JSON) | `type` field with auditd values (SYSCALL, EXECVE, etc.) | `timestamp` |
| ECS / Elastic | `@timestamp` field or `winlog` structure | `@timestamp` |
| EVTXtract output | Marker strings ("Found at offset", "Record number") | `SystemTime` |
| CSV logs | CSV headers with `Channel`/`EventID` or known timestamp columns | Auto-detected |
| Generic JSON/JSONL | Heuristic field scanning + regex fallback | Auto-detected |

### Usage

Auto-detection is enabled by default. Simply run Zircolite without a format flag:

```shell
# Auto-detection identifies the format and timestamp field automatically
python3 zircolite.py --events logs/ --ruleset rules/rules_windows_merged.json

# Example output:
# [+] Auto-detected log type: sysmon_windows (json), confidence=high, timestamp=UtcTime
```

When a format is auto-detected, Zircolite will also re-discover files in the input directory using the appropriate extension if needed.

### Disabling Auto-Detection

If you prefer to specify the format explicitly (or if auto-detection produces incorrect results), disable it with `--no-auto-detect`:

```shell
python3 zircolite.py --events logs/ --ruleset rules.json --no-auto-detect --json-input
```

Explicit format flags (`--json-input`, `--auditd-input`, etc.) always take precedence over auto-detection, even when auto-detection is enabled.

### Timestamp Auto-Detection

The detector tries to find the correct timestamp field in three ways:

1. **Known field names** - Checks a priority-ordered list (configurable in `config/config.yaml`): `SystemTime`, `UtcTime`, `TimeCreated`, `@timestamp`, `timestamp`, `EventTime`, `_time`, `ts`, etc.
2. **Heuristic scoring** - Scans all event fields, scoring them by name relevance (fields containing "time", "date", "created") and value format.
3. **Regex fallback** - Scans raw file content for timestamp patterns (ISO 8601, syslog, epoch seconds/millis, US date-time, Windows FileTime) and ties the match back to a JSON key when possible.

You can always override the timestamp field explicitly:

```shell
python3 zircolite.py --events logs/ --ruleset rules.json --timefield "my_custom_timestamp"
```

### EVTX Files

If your EVTX files have the extension ".evtx":

```shell
python3 zircolite.py --evtx <EVTX_FOLDER/EVTX_FILE> \
    --ruleset <Converted Sigma ruleset (JSON)/Directory with Sigma rules (YAML)/>
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_merged.json
```

### XML Logs

`evtx_dump` or services like **VirusTotal** sometimes output logs in text format with XML logs inside. 

To do this with `evtx_dump`, use the following command line: 
```shell
./evtx_dump -o xml <EVTX_FILE> -f <OUTPUT_XML_FILE> --no-indent --dont-show-record-number
```

This produces something like the following (one event per line): 

```xml
<?xml version="1.0" encoding="utf-8"?><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="XXXXXX"></Provider><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>XXXX</Keywords><TimeCreated SystemTime="XXXX-XX-XXTXX:XX:XX.XXXXXXZ"></TimeCreated><EventRecordID>XXXX</EventRecordID><Correlation></Correlation><Execution ProcessID="XXXXX" ThreadID="XXXXX"></Execution><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>XXXXXXX</Computer><Security UserID="XXXXX"></Security></System><EventData><Data Name="RuleName">XXXX</Data><Data Name="UtcTime">XXXX-XX-XX XX:XX:XX.XXX</Data><Data Name="ProcessGuid">XXXX</Data><Data Name="ProcessId">XXX</Data><Data Name="Image">XXXXXX</Data><Data Name="FileVersion">XXXX</Data><Data Name="Description">XXXXXXXX</Data><Data Name="Product">Microsoft® Windows® Operating System</Data><Data Name="Company">Microsoft Corporation</Data><Data Name="OriginalFileName">XXXX</Data><Data Name="CommandLine">XXXX</Data><Data Name="CurrentDirectory">XXXXXX</Data><Data Name="User">XXXXX</Data><Data Name="LogonGuid">XXXX</Data><Data Name="LogonId">XXXXX</Data><Data Name="TerminalSessionId">0</Data><Data Name="IntegrityLevel">High</Data><Data Name="Hashes">XXXX</Data><Data Name="ParentProcessGuid">XXXXXX</Data><Data Name="ParentProcessId">XXXXXXX</Data><Data Name="ParentImage">XXXXXX</Data><Data Name="ParentCommandLine">XXXXXX</Data><Data Name="ParentUser">XXXXXX</Data></EventData></Event>

```

**VirusTotal**: If you have an enterprise account, it allows you to get logs in a similar format: 

```xml
<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Guid="XXXXXXX" Name="Microsoft-Windows-Sysmon"/><EventID>13</EventID><Version>2</Version><Level>4</Level><Task>13</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="XXXX-XX-XXTXX:XX:XX.XXXXXXZ"/><EventRecordID>749827</EventRecordID><Correlation/><Execution ProcessID="2248" ThreadID="2748"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>XXXXXX</Computer><Security UserID="S-1-5-18"/></System><EventData><Data Name="RuleName">-</Data><Data Name="EventType">SetValue</Data><Data Name="UtcTime">XXXX-XX-XX XX:XX:XX.XXX</Data><Data Name="ProcessGuid">XXXXXXX</Data><Data Name="ProcessId">XXXXX</Data><Data Name="Image">C:\Windows\Explorer.EXE</Data><Data Name="TargetObject">XXXXXXXX</Data><Data Name="Details">Binary Data</Data></EventData></Event>
</Events>
```

**Zircolite** will handle both formats with the following command line:

```shell
python3 zircolite.py --events <LOGS_FOLDER_OR_LOG_FILE>  --ruleset <RULESET> --xml
python3 zircolite.py --events  Microsoft-Windows-SysmonOperational.xml \
    --ruleset rules/rules_windows_merged.json --xml
```

### EVTXtract Logs

Willi Ballenthin has built a tool called [EVTXtract](https://github.com/williballenthin/EVTXtract) that recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images.

**Zircolite** can work with the output of EVTXtract using the following command line:

```shell
python3 zircolite.py --events <EVTXTRACT_EXTRACTED_LOGS>  --ruleset <RULESET> --evtxtract
```

### Auditd Logs

```shell
# Auto-detected (no flag needed if auto-detection is enabled)
python3 zircolite.py --events auditd.log --ruleset rules/rules_linux.json

# Or explicit format flag
python3 zircolite.py --events auditd.log --ruleset rules/rules_linux.json --auditd
```

> [!NOTE]  
> `--events` and `--evtx` are strictly equivalent, but `--events` makes more sense with non-EVTX logs.

### Sysmon for Linux Logs

Sysmon for Linux outputs XML in text format with one event per line. Zircolite supports Sysmon for Linux log files. With auto-detection enabled, Zircolite will identify Sysmon for Linux logs automatically. You can also specify the format explicitly with `-S`, `--sysmon4linux`, `--sysmon-linux`, or `--sysmon-linux-input`:

```shell
# Auto-detected
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json

# Or explicit
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json --sysmon-linux
```

> [!NOTE]  
> Since the logs come from Linux, the default file extension when using `-S` is `.log`. Use `-LE` or `--logs-encoding` to specify a custom encoding if needed (default is ISO-8859-1 for Sysmon for Linux).

### JSONL/NDJSON Logs

JSONL/NDJSON logs have one event log per line. They look like this: 

```json
{"EventID": "4688", "EventRecordID": "1", ...}
{"EventID": "4688", "EventRecordID": "2", ...}
...
```

You can use Zircolite directly on JSONL/NDJSON files (e.g., NXLog files) with the `-j`, `--jsonl`, `--jsononly`, or `--json-input` options: 

```shell
python3 zircolite.py --events <LOGS_FOLDER> --ruleset <RULESET> --jsonl
```

If you have already converted EVTX to JSON (e.g. in another run) and kept the files, you can re-run Zircolite using that directory as the event source with `--evtx <JSON_DIRECTORY>` and `--json-input` to avoid converting again.

### JSON Array / Full JSON Object

Some logs will be provided in JSON format as an array: 

```json
[ 
    {"EventID": "4688", "EventRecordID": "1", ...}, 
    {"EventID": "4688", "EventRecordID": "2", ...}, 
... ]
```

To handle these logs, use the `--jsonarray`, `--json-array`, or `--json-array-input` options:

```shell
python3 zircolite.py --events <LOGS_FOLDER> --ruleset <RULESET> --json-array-input
```

### CSV

You can use Zircolite directly on CSV logs **if they are correctly formatted**. The field names must appear on the first line: 

```csv
EventID,EventRecordID,Computer,SubjectUserSid,...
4624,32421,xxxx.DOMAIN.local,S-1-5-18,xxxx,DOMAIN,...
...
```

To handle these logs, use the `--csv-input` option (**do not use `--csv`**!):

```shell
python3 zircolite.py --events <LOGS_FOLDER> --ruleset <RULESET> --csv-input
```

### Compressed and archived logs

Zircolite can read logs that are compressed or stored in a single-file archive. The **inner** format (EVTX, JSON, XML, etc.) is auto-detected when possible.

| Suffix   | Format   | Notes |
|----------|----------|--------|
| `.gz`    | gzip     | Standard library; inner format from filename (e.g. `logs.json.gz` → JSON). |
| `.bz2`   | bzip2    | Standard library; inner format from filename. |
| `.zip`   | ZIP      | Single-file ZIP only; inner format from the member name. Encrypted ZIP supported with `--archive-password`. |
| `.7z`    | 7-Zip    | Requires `py7zr`. Single-file 7z only; inner format from the member name. Encrypted 7z supported with `--archive-password`. |

- **Single-file only**: Archives must contain exactly one file (e.g. one JSONL file inside the ZIP). Multi-file archives are not supported.
- **Auto-detection**: For `.gz` and `.bz2`, the inner format is inferred from the filename (e.g. `events.json.gz`). For `.zip` and `.7z`, Zircolite opens the archive when possible to read the member name and a sample; if the archive is password-protected and no password is given, it falls back to the filename (e.g. `data.json.7z` → JSON).
- **Encrypted archives**: Use `--archive-password` with the correct password. The same password is used for auto-detection (so the log type can be determined) and for streaming. If the password is wrong or missing, Zircolite reports: *Wrong or missing archive password. Use --archive-password with the correct password.*

Examples:

```shell
# Gzip-compressed JSONL (no password)
python3 zircolite.py --events logs.json.gz --ruleset rules/rules_windows_merged.json

# Password-protected 7-Zip archive containing JSON
python3 zircolite.py --events export.json.7z --ruleset rules/rules_windows_merged.json --archive-password "yourpassword"
```

### SQLite Database Files

Since everything in Zircolite is stored in an in-memory SQLite database, you can choose to save the database on disk for later use with the `--dbfile <db_filename>` option. When processing multiple files, each file's database is saved with a file-specific name.

```shell
python3 zircolite.py --evtx <EVTX_FOLDER> --ruleset <CONVERTED_SIGMA_RULES> \
    --dbfile output.db
```

If you need to re-execute Zircolite, you can do so directly using the SQLite database as the EVTX source (with `--evtx <SAVED_SQLITE_DB_PATH>` and `--dbonly`) to avoid converting the EVTX files, post-processing them, and inserting data into the database. **Using this technique can save a lot of time.**

#### Database indexes

Zircolite creates an index on the `eventid` column by default. When the logs table has a `Channel` column (Windows EVTX/XML logs), an index on `Channel` is created automatically to speed up rule matching. You can add indexes on other columns with `--add-index` and remove indexes by name with `--remove-index`:

```shell
# Add indexes on Channel and EventID (if not already present)
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --add-index Channel EventID

# Remove the automatic Channel index (e.g. to reduce write time)
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --remove-index idx_channel
```

Index names for `--remove-index` are the SQLite index names (e.g. `idx_eventid`, `idx_channel`, or names from `--add-index` such as `idx_SystemTime`).

If you don't want to pick columns by hand, use `--auto-index [N]` to let Zircolite inspect the loaded ruleset and create indices on the N columns that the rules' WHERE clauses reference most often (N defaults to 5 when the flag is used without a value, and 0 when it is omitted). Columns already covered by the built-in `eventid`/`Channel` indices or by `--add-index` are skipped, and only columns that exist in the loaded data are indexed. You can combine `--auto-index` with `--add-index` to force a specific column on top of the auto-picked ones:

```shell
# Auto-index the top 8 columns referenced by the ruleset
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --auto-index 8

# Auto-index (top 5 by default), plus always index Computer
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --auto-index --add-index Computer
```

## Rulesets / Rules

Zircolite has its own ruleset format (JSON). Default rulesets are available in the [rules](https://github.com/wagga40/Zircolite/tree/master/rules/) directory or in the [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) repository.

**Ruleset naming:** The repository ships with rules such as `rules_windows_merged.json` (Sysmon + generic Windows), `rules_windows_sysmon.json`, and `rules_windows_generic.json`. If you run `python3 zircolite.py -U` (or `task update-rules`), rules are updated from Zircolite-Rules-v2. When you omit `--ruleset`, Zircolite defaults to `rules/rules_windows_generic.json` if that file exists; otherwise use a ruleset from `rules/` or run `-U` first. Examples in this doc use `rules_windows_merged.json` for Windows EVTX.

Zircolite can use native Sigma rules (YAML) by converting them with [pySigma](https://github.com/SigmaHQ/pySigma). Zircolite detects whether the provided rules are in JSON or YAML format and converts YAML rules automatically: 

```bash
# Simple rule
python3 zircolite.py -e sample.evtx -r schtasks.yml

# Directory
python3 zircolite.py -e sample.evtx -r ./sigma/rules/windows/process_creation

```
### Using Multiple Rules/Rulesets

You can use multiple rulesets by chaining or repeating the `-r` or `--ruleset` arguments: 

```bash
# Multiple rules/rulesets
python3 zircolite.py -e sample.evtx -r schtasks.yml -r ./sigma/rules/windows/process_creation

```

## Rule testing

You can validate a ruleset against a set of test cases without processing real log files. This is useful for regression testing when you change rules or field mappings, or for CI/CD.

Use `--test-rules` with a JSON file that defines, per rule, which events must trigger the rule (true positives) and which must not (true negatives). Zircolite runs the rules against these events and exits after printing a results table. No `--evtx` or `--events` input is required.

```bash
python3 zircolite.py --ruleset rules/rules_windows_merged.json --test-rules rule_tests.json
```

### Test file format

The test file must be a JSON array. Each element describes tests for one rule and is matched to a rule by **title** or **id** (at least one of `title` or `id` is required).

| Field | Description |
|-------|-------------|
| `title` | Rule title (matched against the ruleset) |
| `id` | Rule ID (matched against the ruleset) |
| `true_positive` | Array of event objects that **must** trigger the rule (at least one match expected) |
| `true_negative` | Array of event objects that **must not** trigger the rule (zero matches expected) |

Each event in `true_positive` and `true_negative` is a flat key-value object. Keys are column names as they appear in the SQLite `logs` table (e.g. after field mappings). Use the same field names your rules expect (e.g. `CommandLine`, `Image`, `EventID`).

Example:

```json
[
  {
    "title": "Detect PowerShell",
    "id": "ps-001",
    "true_positive": [
      { "CommandLine": "powershell.exe -c Get-Process", "EventID": "4688" }
    ],
    "true_negative": [
      { "CommandLine": "notepad.exe document.txt", "EventID": "4688" }
    ]
  },
  {
    "id": "cmd-001",
    "true_positive": [
      { "CommandLine": "cmd.exe /c whoami", "EventID": "4688" }
    ],
    "true_negative": []
  }
]
```

### Results

- **True-positive test**: Passes if the rule matches at least one of the given events; fails otherwise (false negative).
- **True-negative test**: Passes if the rule matches none of the given events; fails if it matches any (false positive).

Rules that have no corresponding entry in the test file are reported as “no test case” (skipped). The summary shows counts for passed, failed, and skipped rules. Exit code is `0`; check the table for any failed tests.

## Pipelines 

By default, Zircolite does not use any pySigma pipelines, which can be somewhat limiting. However, you can use the default pySigma pipelines. 

### Install and List Pipelines

Pipelines must be installed before use. Check the [pySigma docs](https://github.com/SigmaHQ) for details, but it is generally as simple as: 

- `pip3 install pysigma-pipeline-nameofpipeline`
- `poetry add pysigma-pipeline-nameofpipeline`

Installed pipelines can be listed with: 

- `python3 zircolite.py -pl`
- `python3 zircolite.py --pipeline-list`

### Use Pipelines

To use pipelines, use the `-p` or `--pipeline` option (repeat for multiple pipelines). The usage is similar to **sigma-cli**.

Example: 

```bash
python3 zircolite.py -e sample.evtx -r schtasks.yml -p sysmon -p windows-logsources
```

The converted rules/rulesets can be saved using the `-sr` or `--save-ruleset` arguments.

> [!NOTE]  
> When using multiple native Sigma rules/rulesets, you cannot differentiate pipelines. All the pipelines will be used in the conversion process.

## Field Mappings, Exclusions, Aliases, and Splitting

If your logs need to be reshaped before rules can match them, Zircolite offers several config-driven mechanisms. The canonical configuration lives in [`config/config.yaml`](https://github.com/wagga40/Zircolite/tree/master/config/). Use your own with `-c` / `--config`.

> [!NOTE]
> Configuration is **YAML** (`.yaml` / `.yml`). JSON (`.json`) is still accepted for backward compatibility — the format is detected from the file extension.

### Configuration overview

A configuration file can define five top-level sections. All are optional:

```yaml
exclusions:               # fields to drop entirely
  - xmlns

useless:                  # values that should remove their field
  - null
  - ""

mappings:                 # rename a (possibly nested) field
  Event.System.EventID: EventID
  Event.EventData.CommandLine: CommandLine

alias:                    # duplicate a field under a new name
  CommandLine: cmd

split:                    # parse key=value strings into separate fields
  Hashes:
    separator: ","
    equal: "="

transforms_enabled: true  # see "Field Transforms" below
```

### Field Mappings

Rename a field (the original name is **not** kept). Zircolite uses this internally to flatten nested JSON paths into simple names. See defaults in [`config/config.yaml`](https://github.com/wagga40/Zircolite/blob/master/config/config.yaml).

```yaml
mappings:
  CommandLine: cmdline
```

### Field Exclusions

Drop a field from every event. Used internally to remove `xmlns`. See defaults in [`config/config.yaml`](https://github.com/wagga40/Zircolite/blob/master/config/config.yaml).

### Value Exclusions

Drop a field if its value matches one of the listed values. Used internally to remove `null` and empty strings. See defaults in [`config/config.yaml`](https://github.com/wagga40/Zircolite/blob/master/config/config.yaml).

### Field Aliases

Duplicate a field under a new name, keeping the original. Works on raw, mapped, and split fields.

```yaml
alias:
  CommandLine: cmdline
```

Applied to this event:

```json
{
    "EventID": 1,
    "CommandLine": "powershell.exe",
    "Image": "C:\\Windows\\...\\powershell.exe"
}
```

…rules will see the alias added alongside the original:

```json
{
    "EventID": 1,
    "CommandLine": "powershell.exe",
    "cmdline": "powershell.exe",
    "Image": "C:\\Windows\\...\\powershell.exe"
}
```

Aliases duplicate data — use them sparingly.

### Field Splitting

Parse a key=value string into separate fields. Used internally for Sysmon's `Hashes` field. Aliases can be applied to the resulting fields.

```yaml
split:
  Hashes:
    separator: ","
    equal: "="
```

Given this event:

```json
{ "Hashes": "SHA1=XX,MD5=X,SHA256=XXX,IMPHASH=XXXX", "EventID": 1 }
```

…rules will see:

```json
{
    "SHA1": "XX",
    "MD5": "X",
    "SHA256": "XXX",
    "IMPHASH": "XXXX",
    "Hashes": "SHA1=XX,MD5=X,SHA256=XXX,IMPHASH=XXXX",
    "EventID": 1
}
```

## Field Transforms

Transforms run small Python snippets against field values during event flattening, in a **RestrictedPython** sandbox. They can decode data (Base64, hex), extract IOCs (URLs, IPs), categorize values, or flag obfuscation patterns.

### Enabling Transforms

Transforms live in `config/config.yaml`. Only transforms listed in `enabled_transforms` will run:

```yaml
transforms_enabled: true

enabled_transforms:
  - proctitle                # Auditd
  - cmd
  # - CommandLine_b64decoded
  # - Image_LOLBinMatch
```

You can also enable transforms by category from the CLI:

```bash
python3 zircolite.py -e logs/ --transform-category commandline --transform-category process
python3 zircolite.py -e logs/ --all-transforms      # enable everything
python3 zircolite.py --transform-list               # show available categories
```

Categories are defined in the `transform_categories` section of `config.yaml`.

### Defining a Transform

Each transform is attached to a field and has either inline code (`type: python`) or an external file (`type: python_file`):

```yaml
transforms:
  CommandLine:
    - info: "Base64 decoded CommandLine"
      type: python
      code: |
        def transform(param):
            import base64
            return base64.b64decode(param).decode("utf-8")
      alias: true
      alias_name: CommandLine_b64decoded
      source_condition: [evtx_input, json_input]
      enabled: true
```

| Key | Purpose |
|-----|---------|
| `info` | Short description |
| `type` | `python` (inline) or `python_file` (load from disk) |
| `code` | Inline code (with `type: python`) |
| `file` | Path to a `.py` file relative to `transforms_dir` (with `type: python_file`) |
| `alias` | `true` → write to a new field; `false` → replace the original value |
| `alias_name` | Name of the new field when `alias: true` |
| `source_condition` | Input types this transform applies to (see below) |
| `enabled` | Whether the transform is active |

**Source conditions:** `evtx_input`, `json_input`, `json_array_input`, `xml_input`, `csv_input`, `db_input`, `sysmon_linux_input`, `auditd_input`, `evtxtract_input`.

### External File Transforms

For longer code, keep the function in its own file under `transforms_dir` (default: `config/transforms/`):

```yaml
transforms:
  CommandLine:
    - info: "Base64 decoded CommandLine"
      type: python_file
      file: commandline_b64decoded.py
      alias: true
      alias_name: CommandLine_b64decoded
      source_condition: [evtx_input, json_input]
      enabled: true
```

```python
# config/transforms/commandline_b64decoded.py
def transform(param):
    import base64
    return base64.b64decode(param).decode("utf-8")
```

Change the directory with `transforms_dir:` in `config.yaml` if needed.

> [!TIP]
> Use `config/transform_tester.py` to develop and debug transforms locally — it uses the same sandbox as Zircolite.
> ```bash
> python config/transform_tester.py config/transforms/image_exename.py "C:\Windows\cmd.exe"
> python config/transform_tester.py my_transform.py --interactive
> python config/transform_tester.py --list-builtins
> ```

### Writing Transform Functions

The function must be named `transform` and take a single `param` (the field value, always a string).

**Available in the sandbox:**

- A subset of Python built-ins (`len`, `int`, `str`, etc.)
- Modules: `re`, `base64`, `chardet`, `math`
- `dict[k] = v` / `list[i] = v` writes; augmented assignments (`+=`, `-=`, …)

**Blocked:** file I/O, network, system calls, writes to arbitrary object attributes.

### Built-in Transforms

The default `config.yaml` ships with a large catalogue of security-oriented transforms (Base64 decoding, LOLBin detection, AMSI bypass, typosquat detection, DGA scoring, registry persistence, etc.). For the full list and the values each transform produces, see [Advanced.md — Available Transforms](Advanced.md#available-transforms).

### Best Practices

- **Test first**: validate your code on sample values with `config/transform_tester.py`.
- **Prefer aliases**: set `alias: true` with an `alias_name` so the original field stays intact.
- **Watch performance**: transforms run on every event — keep them tight and only enable what you need.
- **Scope correctly**: use `source_condition` so a transform only runs on the input types it makes sense for.

## Event Filter and Timestamp Configuration

Zircolite includes an early event filtering mechanism and automatic timestamp detection. Both are configured in the `event_filter` and `timestamp_detection` sections of the field mappings file (`config/config.yaml`).

### Early Event Filtering

Zircolite can skip events before processing based on **Channel** and **EventID**, so only events that could match at least one rule’s log source are loaded. This reduces memory and CPU when rules use a subset of channels/eventIDs. **Event filtering applies only to Windows logs** (EVTX, Windows JSON/XML, etc.); other log types (Linux, Auditd, generic JSON, etc.) are not filtered by channel/eventID.

**How it works:**

- When rules are loaded, Zircolite collects all unique `Channel` and `EventID` values from the ruleset (from each rule’s `channel` and `eventid` metadata).
- Filtering is **enabled** only when the ruleset has at least one channel and one eventID **and** every rule has at least one channel and one eventID. If any rule has empty or missing channel/eventid (“any” log source), filtering is **disabled** so that rule still sees all events and alert counts stay consistent whether you run one rule or the full ruleset.
- When enabled, an event is **kept** only if both its Channel is in the ruleset’s channel set and its EventID is in the ruleset’s eventID set; otherwise it is skipped before flattening and database insertion.

The filter supports multiple log formats through configurable field paths:

```yaml
event_filter:
  enabled: true
  channel_fields:
    - Event.System.Channel      # Standard EVTX
    - Channel                   # Pre-flattened
    - winlog.channel            # Elastic Winlogbeat
  eventid_fields:
    - Event.System.EventID      # Standard EVTX
    - EventID                   # Pre-flattened
    - winlog.event_id           # Elastic Winlogbeat
```

Disable with the `--no-event-filter` CLI option or set `enabled: false` in config.

### Timestamp Auto-Detection

Zircolite automatically detects the timestamp field when the default (`SystemTime`) is not found:

```yaml
timestamp_detection:
  auto_detect: true
  detection_fields:
    - SystemTime                # Windows EVTX default
    - UtcTime                   # Sysmon logs
    - "@timestamp"              # Elasticsearch/ECS format
    - timestamp                 # Common generic name
    - _time                     # Splunk format
```

Explicitly specify a timestamp field:

```shell
python3 zircolite.py --events logs/ --ruleset rules.json --timefield "@timestamp"
```

## Generating Your Own Rulesets

Default rulesets are already provided in the `rules` directory. These rulesets are only the conversion of the rules located in the [rules/windows](https://github.com/SigmaHQ/sigma/tree/master/rules/windows) directory of the Sigma repository. These rulesets are provided to use Zircolite out of the box, but [you should generate your own rulesets](#why-you-should-build-your-own-rulesets).

Zircolite can auto-update its default rulesets using the `-U` or `--update-rules` option (or `task update-rules`). The auto-updated rulesets are available from [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2).

### Generate Rulesets Using pySigma

Install [sigma-cli](https://github.com/SigmaHQ/pySigma) and the required pipelines, then use `sigma convert` to generate rulesets in Zircolite format. Below are examples for pip/venv, PDM/Poetry, and UV.

#### Using pip / venv

```shell
pip install sigma-cli pysigma-pipeline-sysmon pysigma-pipeline-windows pysigma-backend-sqlite

# Clone Sigma rules (optional; you can use a local Sigma repo)
git clone https://github.com/SigmaHQ/sigma.git
cd sigma

# GENERATE RULESET (SYSMON)
sigma convert -t sqlite -f zircolite -p sysmon -p windows-logsources sigma/rules/windows/ -s -o rules.json

# GENERATE RULESET (GENERIC / NO SYSMON)
sigma convert -t sqlite -f zircolite -p windows-audit -p windows-logsources sigma/rules/windows/ -s -o rules.json
```

#### Using [PDM](https://pdm-project.org/latest/) or [Poetry](https://python-poetry.org)

```shell
git clone https://github.com/SigmaHQ/sigma.git
cd sigma
pdm init -n
pdm add pysigma sigma-cli pysigma-pipeline-sysmon pysigma-pipeline-windows pysigma-backend-sqlite

# GENERATE RULESET (SYSMON)
pdm run sigma convert -t sqlite -f zircolite -p sysmon -p windows-logsources sigma/rules/windows/ -s -o rules.json

# GENERATE RULESET (GENERIC / NO SYSMON)
pdm run sigma convert -t sqlite -f zircolite -p windows-audit -p windows-logsources sigma/rules/windows/ -s -o rules.json
```

With Poetry, use `poetry add ...` and `poetry run sigma convert ...` instead of `pdm add` and `pdm run sigma convert`.

#### Using [UV](https://docs.astral.sh/uv/)

```shell
git clone https://github.com/SigmaHQ/sigma.git
cd sigma
uv venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
uv pip install pysigma sigma-cli pysigma-pipeline-sysmon pysigma-pipeline-windows pysigma-backend-sqlite

# GENERATE RULESET (SYSMON)
uv run sigma convert -t sqlite -f zircolite -p sysmon -p windows-logsources sigma/rules/windows/ -s -o rules.json

# GENERATE RULESET (GENERIC / NO SYSMON)
uv run sigma convert -t sqlite -f zircolite -p windows-audit -p windows-logsources sigma/rules/windows/ -s -o rules.json
```

**Options:**

- `-t` is the backend type (SQLite).
- `-f` is the format. Here, "zircolite" means the ruleset will be generated in the format used by Zircolite.
- `-p` is the pipeline used. In the given example, we use two pipelines.
- `-s` continues on error (e.g., when there are unsupported rules).
- `-o` allows you to specify the output file.

### Why You Should Build Your Own Rulesets

The default rulesets provided are the conversion of the rules located in the `rules/windows` directory of the Sigma repository. You should take into account that: 

- **Some rules are very noisy or produce a lot of false positives** depending on your environment or the pipelines you use when generating rulesets.
- **Some rules can be very slow** depending on your logs.

For example: 

- "Suspicious Eventlog Clear or Configuration Using Wevtutil": **Very noisy** on fresh environments (labs, etc.) and commonly generates a lot of useless detections.
- Notepad Making Network Connection: **Can significantly slow down** the execution of Zircolite.

## Docker

Zircolite is also packaged as a Docker image (see [wagga40/zircolite](https://hub.docker.com/r/wagga40/zircolite) on Docker Hub), which embeds all dependencies (e.g., `evtx_dump`) and provides a platform-independent way of using the tool. Please note that this image is not updated with the latest rulesets!

You can pull the latest image with: `docker pull wagga40/zircolite:latest`

### Build and Run Your Own Image

```shell
docker build . -t <Image name>
docker container run --tty \
    --volume <Logs folder>:/case
    wagga40/zircolite:latest \
    --ruleset rules/rules_windows_merged.json \
    --events /case \
    --outfile /case/detected_events.json
```

This will recursively find log files in the `/case` directory of the container (which is bound to the `/path/to/evtx` of the host filesystem) and write the detection events to `/case/detected_events.json` (which finally corresponds to `/path/to/evtx/detected_events.json`). The given example uses the internal rulesets. If you want to use your own, place them in the same directory as the logs: 

```shell
docker container run --tty \
    --volume <Logs folder>:/case
    wagga40/zircolite:latest \
    --ruleset /case/my_ruleset.json \
    --events /case/my_logs.evtx \
    --outfile /case/detected_events.json
```

Even though Zircolite does not alter the original log files, sometimes you want to make sure that nothing will write to the original files. For these cases, you can use a read-only bind mount with the following command:

```shell
docker run --rm --tty \
    -v <EVTX folder>:/case/input:ro \
    -v <Results folder>:/case/output \
    wagga40/zircolite:latest \
    --ruleset rules/rules_windows_merged.json \
    --events /case/input \
    -o /case/output/detected_events.json
```

### Docker Hub

You can use the Docker image available on [Docker Hub](https://hub.docker.com/r/wagga40/zircolite). Please note that in this case, the configuration files and rules are the default ones.

```shell
docker container run --tty \
    --volume <EVTX folder>:/case docker.io/wagga40/zircolite:latest \
    --ruleset rules/rules_windows_merged.json \
    --events /case --outfile /case/detected_events.json
```

## Troubleshooting

### Common issues

| Issue | What to try |
|-------|-------------|
| **Wrong log format detected** | Use `--no-auto-detect` and an explicit format flag (e.g. `--json-input`, `--auditd-input`). |
| **Missing or wrong timestamp field** | Set the timestamp field explicitly with `--timefield "FieldName"`. |
| **Out of memory on large datasets** | Use `--no-parallel`, `--no-auto-mode`; reduce `--parallel-workers`. |
| **EVTX library (pyevtx-rs) fails to install** | On some systems (Mac, ARM), install Rust and Cargo first; see [Requirements and Installation](Usage.md#requirements-and-installation). |
| **No detections / rules not matching** | Ensure ruleset matches your log source (e.g. Sysmon vs generic Windows); check that field names in your logs align with what the rules expect. |
| **Ruleset file not found** | Default rulesets are in `rules/` (e.g. `rules_windows_merged.json`). If missing, run `python3 zircolite.py -U` to download them from Zircolite-Rules-v2. |

### Getting help

- Use `python3 zircolite.py -h` for all CLI options.
- Use `--debug` for full tracebacks and debug logging.
- Check [Advanced](Advanced.md) for large datasets, filtering, and templating.
- Check [Internals](Internals.md) for architecture and processing flow.

## FAQ

**Why do I get no detections?**  
Rules only match if your log fields align with what the rule expects. Ensure the ruleset matches your log source (e.g. Sysmon rules for Sysmon EVTX; generic Windows rules for Security/System EVTX). Check that the timestamp field is correct (`--timefield` if auto-detection is wrong).

**What is the difference between EVTX rules and JSON/generic rules?**  
`rules_windows_merged.json` covers both Sysmon and generic Windows channels. `rules_windows_sysmon.json` targets Sysmon EVTX only (process creation, network, etc.). `rules_windows_generic.json` targets Windows event logs without Sysmon (Security, System, etc.). Use the ruleset that matches your log source; for mixed or unknown Windows logs, prefer `rules_windows_merged.json`.

**When should I use unified mode vs per-file mode?**  
Use **unified mode** (`--unified-db`) when you need cross-file correlation (e.g. one rule matching events from multiple logs). Use **per-file mode** (default, or `--no-auto-mode`) when you have many or large files and want lower memory use and parallel processing. Zircolite auto-selects based on file count and size unless you override with `--no-auto-mode` or `--unified-db`.

**Which ruleset should I use: Sysmon, generic, or merged?**  
Prefer `rules_windows_merged.json` for most Windows EVTX (Sysmon and/or other channels). Use `rules_windows_sysmon.json` for Sysmon-only logs, or `rules_windows_generic.json` for standard Windows logs (Security, System, etc.) without Sysmon. Each variant also has `_high` (high severity and above) and `_medium` (medium and above) versions. Run `python3 zircolite.py -U` (or `task update-rules`) to fetch the latest rulesets from Zircolite-Rules-v2.

**Where is the full CLI reference?**  
Run `python3 zircolite.py -h` for the complete, up-to-date list of options. The [Command-Line Options Summary](Usage.md#command-line-options-summary) in this doc is a condensed reference.
