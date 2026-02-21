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
python3 zircolite.py -e EVTX-ATTACK-SAMPLES/ -r rules/rules_windows_sysmon.json
deactivate # Exit the Python virtual environment
```

#### Using [PDM](https://pdm-project.org/latest/) or [Poetry](https://python-poetry.org)

```shell
# INSTALL
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite 
pdm init -n
cat requirements.txt | xargs pdm add

# EXAMPLE RUN
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
pdm run python3 zircolite.py -e EVTX-ATTACK-SAMPLES/ -r rules/rules_windows_sysmon.json
```

If you use Poetry, replace `pdm` with `poetry` in the commands above.

#### Using [UV](https://docs.astral.sh/uv/)

```shell
# INSTALL (UV creates venv and installs from requirements.txt)
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite 
uv venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt

# EXAMPLE RUN
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
uv run python zircolite.py -e EVTX-ATTACK-SAMPLES/ -r rules/rules_windows_sysmon.json
```

Alternatively, run Zircolite without activating the venv: `uv run python zircolite.py ...` (UV will use the project venv automatically).

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
   The repository includes rules in `rules/` (e.g. `rules_windows_sysmon.json`). To fetch the latest pre-built rules from [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2), run:
   ```shell
   python3 zircolite.py -U
   ```
   After `-U`, rules may be named e.g. `rules_windows_sysmon.json`. See [Rulesets / Rules](Usage.md#rulesets--rules) for naming details.

3. **Run on one EVTX**
   ```shell
   python3 zircolite.py --evtx path/to/sample.evtx --ruleset rules/rules_windows_sysmon.json
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

- `--events` is a filename or a directory containing the logs you want to analyze (`--evtx` and `-e` can be used instead of `--events`). Zircolite supports the following formats: EVTX, XML, JSON (one event per line), JSON Array (one large array), EVTXTRACT, CSV, Auditd, and Sysmon for Linux.
- `--ruleset` is a file or directory containing the Sigma rules to use for detection. Zircolite has its own format called "Zircolite ruleset" where all the rules are in one JSON file. Zircolite can also use Sigma rules in YAML format directly (YAML file or directory containing YAML files).

Multiple rulesets can be specified, and results can be per-ruleset or combined (with `--combine-rulesets` or `-cr`): 

```shell
# Example with a Zircolite ruleset and a Sigma rule. Results will be displayed per-ruleset
python3 zircolite.py --events sample.evtx --ruleset rules/rules_windows_sysmon.json \
    --ruleset schtasks.yml 
# Example with a Zircolite ruleset and a Sigma rule. Results will be displayed combined 
python3 zircolite.py --events sample.evtx --ruleset rules/rules_windows_sysmon.json \
    --ruleset schtasks.yml --combine-rulesets 
```

By default: 

- `--ruleset` is not mandatory; the default ruleset is `rules/rules_windows_generic.json`.
- Results are written to `detected_events.json` in the same directory as Zircolite. You can choose a CSV-formatted output with `--csv`.
- A `zircolite.log` file will be created in the current working directory; it can be disabled with `--nolog`.
- When providing a directory for event logs, Zircolite will automatically filter by file extension. You can change this with `--fileext`. You can also use `--file-pattern` for custom glob patterns.
- Use `--no-recursion` to disable recursive directory search.

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
| `-cr`, `--combine-rulesets` | Merge all rulesets into one |
| `-sr`, `--save-ruleset` | Save converted ruleset to disk |
| `-p`, `--pipeline` | Use specified pySigma pipeline |
| `-pl`, `--pipeline-list` | List installed pipelines |
| `-R`, `--rulefilter` | Remove rules by title |

#### Output Options

| Option | Description |
|--------|-------------|
| `-o`, `--outfile` | Output file for results |
| `--csv` | Output results in CSV format |
| `--csv-delimiter` | Delimiter for CSV output (default: `;`) |
| `--keepflat` | Save flattened events as JSON |
| `-d`, `--dbfile` | Save logs to SQLite database |
| `-l`, `--logfile` | Log file name |
| `--hashes` | Add xxhash64 to each event |
| `-L`, `--limit` | Discard results exceeding limit |

#### Advanced Configuration

| Option | Description |
|--------|-------------|
| `-c`, `--config` | YAML/JSON config file for field mappings and transforms |
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
| `--parallel-memory-limit` | Memory usage threshold percentage before throttling (default: 75) |

#### Templating and Mini-GUI

| Option | Description |
|--------|-------------|
| `--template` | Jinja2 template for output |
| `--templateOutput` | Output file for template |
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
python3 zircolite.py --quiet -e logs/ -r rules/rules_windows_sysmon.json
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

### Sigma Rule Conversion Summary

When converting native Sigma rules (YAML) to Zircolite format, a mini-summary is displayed showing:

- Number of rules **successfully converted**
- Number of **invalid rules skipped** (files that don't have required Sigma fields)
- Number of rules that **failed** conversion

For example: `[✓] Converted 245 rules (3 invalid skipped, 2 failed)`

## Automatic Log Type Detection

As of version 3.0, Zircolite can **automatically detect** the log format and timestamp field of input files, reducing the need for explicit format flags like `--json-input`, `--auditd-input`, `--sysmon-linux-input`, etc.

### How It Works

When you point Zircolite at a file or directory without specifying a format flag, the `LogTypeDetector` analyzes a sample of the input to determine:

1. **File format** (EVTX binary, JSON/JSONL, XML, CSV, plain text)
2. **Log source** (Windows EVTX, Sysmon Windows/Linux, Auditd, ECS/Elastic, EVTXtract, etc.)
3. **Timestamp field** (SystemTime, UtcTime, @timestamp, etc.)

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
python3 zircolite.py --events logs/ --ruleset rules/rules_windows_sysmon.json

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
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json
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
    --ruleset rules/rules_windows_sysmon.json --xml
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

### SQLite Database Files

Since everything in Zircolite is stored in an in-memory SQLite database, you can choose to save the database on disk for later use with the `--dbfile <db_filename>` option. When processing multiple files, each file's database is saved with a file-specific name.

```shell
python3 zircolite.py --evtx <EVTX_FOLDER> --ruleset <CONVERTED_SIGMA_RULES> \
    --dbfile output.db
```

If you need to re-execute Zircolite, you can do so directly using the SQLite database as the EVTX source (with `--evtx <SAVED_SQLITE_DB_PATH>` and `--dbonly`) to avoid converting the EVTX files, post-processing them, and inserting data into the database. **Using this technique can save a lot of time.** 

## Rulesets / Rules

Zircolite has its own ruleset format (JSON). Default rulesets are available in the [rules](https://github.com/wagga40/Zircolite/tree/master/rules/) directory or in the [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) repository.

**Ruleset naming:** The repository ships with rules such as `rules_windows_sysmon.json` and `rules_windows_generic.json`. If you run `python3 zircolite.py -U` (or `task update-rules`), rules are updated from Zircolite-Rules-v2 and may be named e.g. `rules_windows_sysmon.json` and `rules_windows_generic.json`. When you omit `--ruleset`, Zircolite defaults to `rules/rules_windows_generic.json` if that file exists; otherwise use a ruleset from `rules/` or run `-U` first.

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

By default, detection results are displayed by ruleset. You can group the results with `-cr` or `--combine-rulesets`. In this case, only one list will be displayed.

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

## Field Mappings, Field Exclusions, Value Exclusions, Field Aliases, and Field Splitting

If your logs require transformations to align with your rules, Zircolite offers several mechanisms for this purpose. You can configure these mechanisms using a file located in the [config](https://github.com/wagga40/Zircolite/tree/master/config/) directory of the repository. Additionally, you have the option to use your own configuration by utilizing the `--config` or `-c` options.

### Configuration File Formats

Zircolite supports both **YAML** and **JSON** formats for the field mappings configuration file:

- **YAML format**: `config/config.yaml` (default, with comments for documentation)
- **JSON format**: Also supported for backward compatibility

The file format is automatically detected based on the file extension (`.json`, `.yaml`, or `.yml`). If no extension is provided, Zircolite will attempt to parse as JSON first, then YAML.

> [!TIP]
> The YAML format is recommended for custom configurations as it supports comments, making it easier to document your mappings and transforms.

**JSON format example:**

```json 
{
    "exclusions" : [],
    "useless" : [],
    "mappings" : 
    {
        "field_name_1": "new_field_name_1", 
        "field_name_2": "new_field_name_2"
    },
    "alias":
    {
        "field_alias_1": "alias_1"
    },
    "split":
    {
        "field_name_split": {"separator":",", "equal":"="}
    },
    "transforms_enabled": true,
    "transforms": {}
}
```

**YAML format example:**

```yaml
# Field mappings configuration
exclusions:
  - xmlns  # Exclude XML namespace attributes

useless:
  - null
  - ""

mappings:
  # Rename nested fields to simpler names
  Event.System.EventID: EventID
  Event.EventData.CommandLine: CommandLine

alias:
  CommandLine: cmd  # Create alias 'cmd' for CommandLine

split:
  Hashes:
    separator: ","
    equal: "="

transforms_enabled: true
transforms: {}
```

### Field Mappings

**Field mappings** enable you to rename a field from your logs. Zircolite uses this mechanism to rename nested JSON fields. You can view all the built-in field mappings in [`config/config.yaml`](https://github.com/wagga40/Zircolite/blob/master/config/config.yaml).

For instance, to rename the "CommandLine" field in **your raw logs** to "cmdline", you can add the following entry to the configuration file:

```json 
{
    "exclusions" : [],
    "useless" : [],
    "mappings" : 
    {
        "CommandLine": "cmdline"
    },
    "alias":{},
    "split": {}
}
```

Please keep in mind that, unlike field aliases, the original field name is not preserved.

### Field Exclusions

**Field exclusions** allow you to exclude a field. Zircolite uses this mechanism to exclude the `xmlns` field. See the built-in field exclusions in [`config/config.yaml`](https://github.com/wagga40/Zircolite/blob/master/config/config.yaml).

### Value Exclusions

**Value exclusions** allow you to remove fields whose values should be excluded. Zircolite uses this mechanism to remove *null* and empty values. See the built-in value exclusions in [`config/config.yaml`](https://github.com/wagga40/Zircolite/blob/master/config/config.yaml).

### Field Aliases

**Field aliases** allow you to have multiple fields with different names but the same value. It is similar to field mapping, but you keep the original value. Field aliases can be used on original field names as well as on mapped field names and split fields.

Let's say you have this event log in JSON format (the event has been deliberately truncated): 

```json 
{
    "EventID": 1,
    "Provider_Name": "Microsoft-Windows-Sysmon",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "IntegrityLevel": "Medium"
}
```

Let's say you are not sure all your rules use the "CommandLine" field, but you remember that some of them use the "cmdline" field. To avoid any problems, you could use an alias for the "CommandLine" field like this: 

```json 
{
    "exclusions" : [],
    "useless" : [],
    "mappings" : {},
    "alias":{
        "CommandLine": "cmdline"
    },
    "split": {}
}
```

With this configuration, the event log used to apply Sigma rules will look like this: 

```json 
{
    "EventID": 1,
    "Provider_Name": "Microsoft-Windows-Sysmon",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
    "cmdline": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "IntegrityLevel": "Medium"
}
```

Be careful when using aliases because the data is stored multiple times.

### Field Splitting

**Field splitting** allows you to split fields that contain key-value pairs. Zircolite uses this mechanism to handle hash/hashes fields in Sysmon logs. See the built-in field splittings in [`config/config.yaml`](https://github.com/wagga40/Zircolite/blob/master/config/config.yaml). Field aliases can be applied to split fields.

For example, let's say we have this Sysmon event log: 

```json
{
    "Hashes": "SHA1=XX,MD5=X,SHA256=XXX,IMPHASH=XXXX",
    "EventID": 1
}
```

With the following configuration, Zircolite will split the `Hashes` field like this: 

```json 
{
    "exclusions" : [],
    "useless" : [],
    "mappings" : {},
    "alias":{},
    "split": {
        "Hashes": {"separator":",", "equal":"="}
    }
}
```

The final event log used to apply Sigma rules will look like this: 

```json
{
    "SHA1": "x",
    "MD5": "x",
    "SHA256": "x",
    "IMPHASH": "x",
    "Hashes": "SHA1=x,MD5=x,SHA256=x,IMPHASH=x",
    "EventID": 1
}
```

## Field Transforms 

### What Are Transforms?

Transforms in Zircolite are custom functions that manipulate the value of a specific field during the event flattening process. They allow you to:

- Format or normalize data
- Enrich events with additional computed fields
- Decode encoded data (e.g., Base64, hexadecimal)
- Extract information using regular expressions

By using transforms, you can preprocess event data to make it more suitable for detection rules and analysis. Transforms are executed using **RestrictedPython** for safe, sandboxed execution.

### Enabling Transforms

Transforms are configured in `config/config.yaml`. To enable transforms:

1. Set `transforms_enabled: true`
2. Add transform names to the `enabled_transforms` list

```yaml
transforms_enabled: true

enabled_transforms:
  # Auditd (Linux)
  - proctitle
  - cmd
  
  # Uncomment to enable:
  # - CommandLine_b64decoded
  # - Image_LOLBinMatch
  # - ScriptBlockText_ObfuscationIndicators
```

Only transforms listed in `enabled_transforms` will run. This provides a single location to control all transforms.

**Enabling transforms by category (CLI):**

```bash
# Enable all transforms in specific categories
python3 zircolite.py -e logs/ --transform-category commandline --transform-category process

# Enable ALL transforms
python3 zircolite.py -e logs/ --all-transforms

# List available categories
python3 zircolite.py --transform-list
```

Categories are defined in the `transform_categories` section of `config/config.yaml`. See [Advanced.md](Advanced.md#transform-categories) for the full list.

**JSON format (alternative):**

```json
{
  "transforms_enabled": true,
  "transforms": {
  }
}
```

**YAML format:**

```yaml
transforms_enabled: true
transforms: {}
```

### Configuring Transforms

Transforms are defined in the `"transforms"` section of the configuration file. Each transform is associated with a specific field and consists of several properties.

### Transform Structure

A transform definition has the following structure:

- **Field Name**: The name of the field to which the transform applies.
- **Transform List**: A list of transform objects for the field.

Each transform object contains:

- **info**: A description of what the transform does.
- **type**: `"python"` for inline code or `"python_file"` for external file.
- **code**: The Python code that performs the transformation (for `type: python`).
- **file**: Path to a `.py` file containing the transform function (for `type: python_file`). Resolved relative to `transforms_dir`.
- **alias**: A boolean indicating whether the result should be stored in a new field.
- **alias_name**: The name of the new field if `alias` is `true`.
- **source_condition**: A list specifying when the transform should be applied based on the input type (e.g., `["evtx_input", "json_input"]`).
- **enabled**: A boolean indicating whether the transform is active.

#### Source Condition Possible Values
    
| `source_condition` Value      |
|-------------------------------|
| `"json_input"`                |
| `"json_array_input"`          |
| `"db_input"`                  |
| `"sysmon_linux_input"`        |
| `"auditd_input"`              |
| `"xml_input"`                 |
| `"evtxtract_input"`           |
| `"csv_input"`                 |
| `"evtx_input"`                |

#### Example: Inline Transform (type: python)

**JSON format:**

```json
{
  "info": "Base64 decoded CommandLine",
  "type": "python",
  "code": "def transform(param):\n    # Transformation logic\n    return transformed_value",
  "alias": true,
  "alias_name": "CommandLine_b64decoded",
  "source_condition": ["evtx_input", "json_input"],
  "enabled": true
}
```

**YAML format:**

```yaml
- info: "Base64 decoded CommandLine"
  type: python
  code: |
    def transform(param):
        # Transformation logic
        return transformed_value
  alias: true
  alias_name: "CommandLine_b64decoded"
  source_condition:
    - evtx_input
    - json_input
```

> [!TIP]
> YAML's multi-line string syntax (`|`) makes writing transform code much cleaner than escaping newlines in JSON.

#### Example: External File Transform (type: python_file)

```yaml
- info: "Base64 decoded CommandLine"
  type: python_file
  file: commandline_b64decoded.py
  alias: true
  alias_name: "CommandLine_b64decoded"
  source_condition:
    - evtx_input
    - json_input
```

The `.py` file contains only the transform function:

```python
def transform(param):
    # param is the field value (always a string)
    # return the transformed value (string)
    return param.upper()
```

External files are resolved relative to `transforms_dir` (default: `transforms/`, relative to the config file directory). This is configured in `config.yaml`:

```yaml
transforms_dir: transforms/
```

> [!TIP]
> Use `config/transform_tester.py` to develop and test transforms locally with the same RestrictedPython sandbox.
> ```bash
> python config/transform_tester.py config/transforms/image_exename.py "C:\Windows\cmd.exe"
> python config/transform_tester.py my_transform.py --interactive
> python config/transform_tester.py --list-builtins
> ```

### Available Fields

You can define transforms for any field present in your event data. In the configuration, transforms are keyed by the field name:

**JSON format:**

```json
"transforms": {
  "CommandLine": [
    { }
  ],
  "Payload": [
    { }
  ]
}
```

**YAML format:**

```yaml
transforms:
  CommandLine:
    - info: "Transform description"
      # ... transform properties
  Payload:
    - info: "Another transform"
      # ... transform properties
```

---

### Writing Transform Functions

Zircolite uses `RestrictedPython` to safely execute transform functions. This means that certain built-in functions and modules are available, while others are restricted.
The function must be named `transform` and accept a single parameter `param`, which is the original value of the field.

**Available Modules and Functions:**

- **Built-in Functions**: A limited set of Python built-in functions, such as `len`, `int`, `str`, etc.
- **Modules**: You can use `re` for regular expressions, `base64` for encoding/decoding, `chardet` for character encoding detection, and `math` for mathematical functions.
- **Container writes**: `dict[key] = value` and `list[idx] = value` are supported.
- **Augmented assignments**: `+=`, `-=`, `*=`, etc. are supported.

**Unavailable Features:**

- Access to file I/O, network, or system calls is prohibited.
- Writing to arbitrary object attributes is blocked (only `dict`, `list`, and `set` writes are allowed).
- Use of certain built-in functions that can affect the system is restricted.

#### Example Transform Functions

##### Base64 Decoding

```python
def transform(param):
    import base64
    decoded = base64.b64decode(param)
    return decoded.decode('utf-8')
```

##### Hexadecimal to ASCII Conversion

```python
def transform(param):
    decoded = bytes.fromhex(param).decode('ascii')
    return decoded.replace('\x00', ' ')
```

### Applying Transforms

Transforms are automatically applied during the event flattening process if:

- They are **enabled** (`"enabled": true`).
- The current input type matches the **source condition** (`"source_condition": [...]`).

For each event, Zircolite checks if any transforms are defined for the fields present in the event. If so, it executes the transform function and replaces the field's value with the transformed value or stores it in a new field if `alias` is `true`.

### Built-in Transforms

The default configuration file (`config/config.yaml`) includes many pre-configured transforms for security analysis:

#### Auditd Transforms
- **proctitle**: Converts hexadecimal proctitle from Auditd to ASCII
- **cmd**: Converts hexadecimal cmd from Auditd to ASCII

#### CommandLine Transforms
- **CommandLine_b64decoded**: Base64 decoding
- **CommandLine_Extracted_Creds**: Credential extraction from net/wmic/psexec commands
- **CommandLine_URLs**: Extract HTTP/HTTPS/FTP URLs
- **CommandLine_XORIndicators**: Detect XOR operations and extract keys
- **CommandLine_AMSIBypass**: Detect AMSI bypass techniques
- **CommandLine_HexStrings**: Find and decode hex-encoded strings
- **CommandLine_EnvVarObfuscation**: Detect environment variable abuse
- **CommandLine_DownloadCradle**: Identify download cradle patterns (DownloadString, WebClient, certutil, bitsadmin)
- **CommandLine_EvasionTechniques**: Detect process hollowing, injection, syscalls, ETW bypass
- **CommandLine_RegistryPaths**: Extract registry key paths

#### PowerShell (ScriptBlockText) Transforms
- **ScriptBlockText_b64decoded**: Base64 decoding
- **ScriptBlockText_ObfuscationIndicators**: Detect char substitution, string concat, GzipStream, MemoryStream, etc.
- **ScriptBlockText_XORPatterns**: Detect XOR keys and patterns
- **ScriptBlockText_ReflectionAbuse**: Detect .NET reflection-based attacks
- **ScriptBlockText_ShellcodeIndicators**: Detect shellcode execution patterns
- **ScriptBlockText_NetworkIOCs**: Extract IPs, URLs, and domains

#### Process Transforms
- **Image_ExeName**: Extract executable name from path
- **Image_LOLBinMatch**: Detect Living Off The Land Binaries (certutil, mshta, regsvr32, etc.)
- **Image_TyposquatDetect**: Detect typosquatted process names (svchost→svch0st, lsass→1sass, etc.)
- **ParentImage_ExeName**: Extract parent executable name

#### Network Transforms
- **QueryName_TLD**: Extract TLD from DNS queries
- **QueryName_EntropyScore**: Entropy score for DGA detection
- **QueryName_TyposquatDetect**: Detect typosquatted official domains (gov sites, banks, tech companies)
- **DestinationIp_ObfuscationCheck**: Detect hex/octal/decimal IP obfuscation
- **DestinationPort_Category**: Categorize ports (HTTP, SMB, RDP, METASPLOIT_DEFAULT, etc.)

#### User Transforms
- **User_Name**: Extract username without domain
- **User_Domain**: Extract domain from user field

#### File and Registry Transforms
- **TargetFileName_URLDecoded**: URL decode file paths
- **TargetObject_SuspiciousRegistry**: Identify persistence registry keys (Run, Services, IFEO, COM)
- **Hash_MD5**: Extract MD5 from Sysmon Hashes field
- **Hash_SHA256**: Extract SHA256 from Sysmon Hashes field

> [!TIP]
> For a complete reference of transform output values and detailed examples, see the [Field Transforms](Advanced.md#field-transforms) section in Advanced.md.

### Example

**Use Case**: Convert hexadecimal-encoded command lines in Auditd logs to readable ASCII strings.

**JSON Configuration:**

```json
"proctitle": [
  {
    "info": "Proctitle HEX to ASCII",
    "type": "python",
    "code": "def transform(param):\n    return bytes.fromhex(param).decode('ascii').replace('\\x00', ' ')",
    "alias": false,
    "alias_name": "",
    "source_condition": ["auditd_input"],
    "enabled": true
  }
]
```

**YAML Configuration:**

```yaml
proctitle:
  - info: "Proctitle HEX to ASCII"
    type: python
    code: |
      def transform(param):
          return bytes.fromhex(param).decode('ascii').replace('\x00', ' ')
    alias: false
    alias_name: ""
    source_condition:
      - auditd_input
    enabled: true
```

**Explanation:**

- **Field**: `proctitle`
- **Function**: Converts hexadecimal strings to ASCII and replaces null bytes with spaces.
- **Alias**: `false` (the original `proctitle` field is replaced).

### Best Practices

- **Test Your Transforms**: Before enabling a transform, ensure that the code works correctly with sample data.
- **Use Aliases Wisely**: If you don't want to overwrite the original field, set `"alias": true` and provide an `"alias_name"`.
- **Manage Performance**: Complex transforms can impact performance. Optimize your code and only enable necessary transforms.
- **Keep Transforms Specific**: Tailor transforms to specific fields and input types using `"source_condition"` to avoid unexpected behavior.

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
    --ruleset rules/rules_windows_sysmon.json \
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
    --ruleset rules/rules_windows_sysmon.json \
    --events /case/input \
    -o /case/output/detected_events.json
```

### Docker Hub

You can use the Docker image available on [Docker Hub](https://hub.docker.com/r/wagga40/zircolite). Please note that in this case, the configuration files and rules are the default ones.

```shell
docker container run --tty \
    --volume <EVTX folder>:/case docker.io/wagga40/zircolite:latest \
    --ruleset rules/rules_windows_sysmon.json \
    --evtx /case --outfile /case/detected_events.json
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
| **Ruleset file not found** | Default rulesets may be named `rules_windows_sysmon.json` (in repo) or `rules_windows_sysmon.json` (after `-U`). Use `python3 zircolite.py -U` to update rules from Zircolite-Rules-v2. |

### Getting help

- Use `python3 zircolite.py -h` for all CLI options.
- Use `--debug` for full tracebacks and debug logging.
- Check [Advanced](Advanced.md) for large datasets, filtering, and templating.
- Check [Internals](Internals.md) for architecture and processing flow.

## FAQ

**Why do I get no detections?**  
Rules only match if your log fields align with what the rule expects. Ensure the ruleset matches your log source (e.g. Sysmon rules for Sysmon EVTX; generic Windows rules for Security/System EVTX). Check that the timestamp field is correct (`--timefield` if auto-detection is wrong).

**What is the difference between EVTX rules and JSON/generic rules?**  
Rulesets like `rules_windows_sysmon.json` target Sysmon EVTX (process creation, network, etc.). Rules like `rules_windows_generic.json` target Windows event logs without Sysmon rewriting (Security, System, etc.). Use the ruleset that matches your log source.

**When should I use unified mode vs per-file mode?**  
Use **unified mode** (`--unified-db`) when you need cross-file correlation (e.g. one rule matching events from multiple logs). Use **per-file mode** (default, or `--no-auto-mode`) when you have many or large files and want lower memory use and parallel processing. Zircolite auto-selects based on file count and size unless you override with `--no-auto-mode` or `--unified-db`.

**Which ruleset file should I use: `rules_windows_sysmon.json` or `rules_windows_sysmon.json`?**  
The repository ships with `rules_windows_sysmon.json` (and similar). Running `python3 zircolite.py -U` (or `task update-rules`) fetches rules from Zircolite-Rules-v2. Use whichever file exists in your `rules/` directory; both are valid Zircolite rulesets.

**Where is the full CLI reference?**  
Run `python3 zircolite.py -h` for the complete, up-to-date list of options. The [Command-Line Options Summary](Usage.md#command-line-options-summary) in this doc is a condensed reference.
