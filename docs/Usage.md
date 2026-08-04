# Usage

## Requirements and Installation

Zircolite needs **Python 3.10 or above** and runs on Linux, macOS and Windows.

### Dependencies

| Package | Purpose |
|---------|---------|
| `orjson` | Fast JSON parsing |
| `xxhash` | Log-line hashing for `--hashes` |
| `rich`, `rich-argparse` | Terminal output, progress bars, tables, coloured help |
| `RestrictedPython` | Sandbox for field transforms |
| `requests` | Ruleset updates (`-U`) |
| `pySigma` and backends | Native Sigma rule conversion |
| `evtx` (pyevtx-rs) | EVTX parsing |
| `jinja2` | Output templates |
| `lxml` | XML input |
| `chardet` | Encoding detection |
| `psutil` | Memory tracking and parallel-processing heuristics |
| `pyyaml` | YAML configuration |
| `py7zr` | 7-Zip archives. ZIP, gzip and bzip2 use the standard library. It is required like the rest, but imported only when a `.7z` is opened |

> [!NOTE]
> On some systems (macOS, ARM), the `evtx` library needs Rust and Cargo installed before
> it will build. Without it, use one of the other input formats.

### Installing

Clone the repository, then pick whichever tool you already use:

| Tool | Install | Run |
|------|---------|-----|
| pip + venv | `python3 -m venv .venv && source .venv/bin/activate && pip3 install -r requirements.txt` | `python3 zircolite.py …` |
| [PDM](https://pdm-project.org/latest/) | `pdm install` | `pdm run python3 zircolite.py …` |
| [Poetry](https://python-poetry.org) | `poetry install` | `poetry run python3 zircolite.py …` |
| [UV](https://docs.astral.sh/uv/) | `uv sync` | `uv run python zircolite.py …` |

PDM, Poetry and UV read `pyproject.toml` and manage the virtual environment themselves.
Add `--dev` (PDM) or the equivalent to get the test suite as well.

A complete first run, from nothing:

```shell
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite
pip3 install -r requirements.txt

# Optional: fetch the latest rulesets
python3 zircolite.py -U

# Some sample logs to try it on
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
python3 zircolite.py -e EVTX-ATTACK-SAMPLES/ -r rules/rules_windows_merged.json
```

Results land in `detected_events.json` in the working directory, and the detection table
and summary panel are printed to the terminal.

After installation you can use [Task](https://taskfile.dev/) for automation — updating
rules, building the Docker image, cleaning up. See
[Task and Taskfile](README.md#task-and-taskfile).

## Basic Usage

```shell
python3 zircolite.py --events <LOGS> --ruleset <RULESET>
```

- `--events` is a file or a directory of logs. `--evtx` and `-e` are the same option.
  EVTX, XML, JSON lines, JSON array, EVTXtract, CSV, Auditd and Sysmon for Linux are all
  supported, as are compressed and archived logs — see
  [Compressed and archived logs](Usage.md#compressed-and-archived-logs). The format is
  detected automatically in most cases.
- `--ruleset` is a Zircolite ruleset (one JSON file) or native Sigma rules (a YAML file or
  a directory of them). Repeat it to use several.

```shell
python3 zircolite.py --events sample.evtx \
    --ruleset rules/rules_windows_merged.json --ruleset schtasks.yml
```

Defaults worth knowing:

- `--ruleset` is optional; without it Zircolite uses `rules/rules_windows_generic.json`.
- Results go to `detected_events.json`, or a `.csv` with `--csv` (see
  [CSV detection output](Usage.md#csv-detection-output)).
- A `zircolite.log` is written alongside; `--nolog` disables it.
- Pointing at a directory filters by file extension, which `--fileext` overrides and
  `--file-pattern` replaces with a glob. `--no-recursion` stops the descent into
  subdirectories.

Full help is always available with `python3 zircolite.py -h`.

### Interrupting a run

`Ctrl+C` triggers a graceful shutdown: in-flight workers finish their current batch or
rule, temporary files are cleaned up, the database is closed, and Zircolite exits `130`
with no traceback.

```
[!] Interrupt received - finishing current work and shutting down. Press Ctrl+C again to force quit.
```

A second `Ctrl+C` is a **force quit**: the default signal handler is restored and Python
exits immediately, so work in flight is abandoned and the output file may be incomplete.

Because the files after the interrupt were never read, `--remove-events` deletes nothing
on an interrupted run.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | The run completed. Detections may or may not have been found — that is not an error. |
| `1` | The run did not produce the analysis it was asked for. |
| `2` | The command line or configuration file was rejected before anything was processed. |
| `130` | Interrupted with `Ctrl+C`. |

`2` is reserved for a specific set of conflicting or impossible invocations: no events
path given at all, `--csv` with more than one ruleset, a `--csv-delimiter` that is not
exactly one character, `--all-transforms` together with `--transform-category`, a
`--dbfile` whose path already exists, `--dbfile` with parallel processing over several
files, or a `--generate-config` that could not be written.

Everything else that stops a run is `1`, including some problems found just as early: a
path that matched no files, a ruleset that loaded no rules, a `--strict` parse error, a
`--timefield` value or `--after`/`--before` timestamp that could not be parsed, an
inverted time range, a `--limit` that is not positive, `--templateOutput` without a
matching `--template`, a template file that is not there, a per-file database name that
already exists, an unreadable or failing `--test-rules` file, or a configuration file
that could not be honoured. Treat `1` as "the run did not happen or did not finish" and
`2` as "these particular options cannot be combined".

A run that could only read part of its input still exits `0` when the rest was analysed.
The affected files are named on the console and are never deleted by `--remove-events`.

A run that loaded **no** rules exits `1`: it analysed nothing, and the empty output file
it would otherwise leave behind is indistinguishable from a clean run that found nothing.

## Command-Line Options

The tables below summarise the options; `python3 zircolite.py -h` is always current.

Several options carry alternative spellings kept for compatibility with older command
lines. They behave identically to the documented form:

| Documented form | Also accepted |
|-----------------|---------------|
| `-j`, `--json-input` | `--jsononly`, `--jsonline`, `--jsonl` |
| `--json-array-input` | `--jsonarray`, `--json-array` |
| `-D`, `--db-input` | `--dbonly` |
| `-S`, `--sysmon-linux-input` | `--sysmon4linux`, `--sysmon-linux` |
| `-AU`, `--auditd-input` | `--auditd` |
| `-x`, `--xml-input` | `--xml` |
| `--evtxtract-input` | `--evtxtract` |
| `--csv-input` | `--csvonly` |
| `--csv` | `--csv-output` |
| `--keepflat` | `--keep-flat` |
| `-d`, `--dbfile` | `--db-file` |
| `-l`, `--logfile` | `--log-file` |
| `-L`, `--limit` | `--limit-results` |
| `-n`, `--nolog` | `--no-log` |
| `--timefield` | `--time-field` |
| `--unified-db` | `--all-in-one` |
| `-T`, `--templateOutput` | `--template-output` |
| `-e`, `--evtx` | `--events` |

### Input files and filtering

| Option | Description |
|--------|-------------|
| `-e`, `--evtx`, `--events` | Path to a log file or directory |
| `-s`, `--select` | Keep only files whose *filename* contains this string (case-insensitive) |
| `-a`, `--avoid` | Skip files whose *filename* contains this string (case-insensitive); applied after `--select` |
| `-f`, `--fileext` | File extension to look for |
| `-fp`, `--file-pattern` | Python glob pattern; only applies when the input is a directory |
| `--no-recursion` | Do not descend into subdirectories |
| `--archive-password` | Password for encrypted ZIP or 7-Zip archives, used for both detection and reading |

### Event filtering

| Option | Description |
|--------|-------------|
| `-A`, `--after` | Process only events at or after this timestamp (inclusive). Ignored with `--db-input` |
| `-B`, `--before` | Process only events at or before this timestamp (inclusive). Ignored with `--db-input` |
| `--no-event-filter` | Disable early channel/eventID filtering |

### Input formats

When the events path is a directory, the format also decides which extension is globbed,
unless `--fileext` or `--file-pattern` says otherwise.

| Option | Description | Default extension |
|--------|-------------|-------------------|
| *(none)* | EVTX files | `.evtx` |
| `-j`, `--json-input` | JSON lines | `.json` |
| `--json-array-input` | JSON array | `.json` |
| `-D`, `--db-input` | A previously saved database | *(path given explicitly)* |
| `-S`, `--sysmon-linux-input` | Sysmon for Linux | `.log` |
| `-AU`, `--auditd-input` | Auditd | `.log` |
| `-x`, `--xml-input` | XML | `.xml` |
| `--evtxtract-input` | EVTXtract output | `.log` |
| `--csv-input` | CSV | `.csv` |

### Rules and rulesets

| Option | Description |
|--------|-------------|
| `-r`, `--ruleset` | Sigma ruleset, JSON or YAML; repeatable |
| `-sr`, `--save-ruleset` | Save the converted ruleset to disk |
| `-p`, `--pipeline` | Use a pySigma pipeline; repeatable |
| `-pl`, `--pipeline-list` | List installed pipelines and exit |
| `-R`, `--rulefilter` | Skip rules by title (case-sensitive); repeatable |
| `--test-rules` | JSON file of rule test cases; validate and exit |

### Output

| Option | Description |
|--------|-------------|
| `-o`, `--outfile` | Output file for results |
| `--csv`, `--csv-output` | Write results as CSV. Accepts only one ruleset |
| `--csv-delimiter` | CSV delimiter, exactly one character (default: `;`) |
| `--keepflat` | Save the flattened events — processed events only — to `flattened_events_<RAND>.json` in the working directory. The contents are JSONL despite the extension |
| `-d`, `--dbfile` | Save the logs to an SQLite database |
| `-l`, `--logfile` | Log file name |
| `--hashes` | Add an xxhash64 to each event. For CSV, EVTXtract and JSON-array input the reader hands over a parsed record rather than a source line, so the hash covers a canonical form of the event |
| `-L`, `--limit` | Discard results from any rule matching more than this many events (positive integer, or `-1` to disable). Counted per input database: per file by default, corpus-wide with `--unified-db` |
| `--profile-rules` | Time each rule and print a performance report. Forces sequential processing |

> [!NOTE]
> `--dbfile` cannot be combined with parallel processing of several files, because each
> worker would need to write the same database. Use `--unified-db` for a single database
> file, or `--no-parallel` to save one per input. Zircolite exits with an error rather
> than silently dropping databases.
>
> In per-file mode the name is derived from each input, so `--dbfile save.db` over
> `a.json` and `b.json` writes `save_a.json.db` and `save_b.json.db`; inputs sharing a
> basename get a numbered form. Those names are stable between runs, and every one of them
> is checked before any processing starts rather than half-way through.

### Advanced configuration

| Option | Description |
|--------|-------------|
| `-c`, `--config` | Field-mapping config file, YAML or JSON (default: `config/config.yaml`) |
| `-LE`, `--logs-encoding` | Encoding of the source files, for the formats read as text: Sysmon for Linux, Auditd, EVTXtract and CSV. XML uses the encoding declared in the document, and JSON is read as UTF-8 |
| `-q`, `--quiet` | Suppress banner, progress bars and info messages — only the summary panel and errors |
| `--debug` | Debug logging, with full tracebacks |
| `-n`, `--nolog` | Do not create the log file **or the detections output file**. Files asked for explicitly with `--template`, `--dbfile`, `--keepflat` or `--package` are still written |
| `-RE`, `--remove-events` | Delete input files that were read successfully. Files that failed to parse are kept, and an interrupted run keeps everything |
| `-U`, `--update-rules` | Update the default rulesets |
| `-v`, `--version` | Print the version |
| `--timefield` | Field holding the event timestamp. Left unset it is auto-detected, falling back to `SystemTime`; naming one pins it and turns detection off |
| `--unified-db` | One database for all files, which is what cross-file correlation needs |
| `--no-auto-mode` | Disable automatic processing-mode selection |
| `--no-auto-detect` | Disable automatic log type and timestamp detection |
| `--strict` | Abort on a corrupted or malformed EVTX chunk instead of skipping it (default: lenient) |
| `--add-index` | Create an index on the given column(s), e.g. `--add-index Channel EventID` |
| `--remove-index` | Drop the given index name(s) after creation, e.g. `--remove-index idx_channel` |
| `--auto-index` | Index the top-N columns that the most rules in the ruleset filter on. Takes an optional count: N defaults to 5 when the flag is used bare, and to 0 when it is omitted altogether. Combines with `--add-index` |

### Transforms

| Option | Description |
|--------|-------------|
| `--all-transforms` | Enable every transform, ignoring `source_condition`. Cannot be combined with `--transform-category` |
| `--transform-category` | Enable transforms by category name; repeatable |
| `--transform-list` | List the available categories and exit |

> [!TIP]
> Transforms can decode Base64, extract IOCs, detect obfuscation and more. See
> [Field Transforms](Advanced.md#field-transforms).

### Parallel processing

| Option | Description |
|--------|-------------|
| `-P`, `--no-parallel` | Disable automatic parallel processing |
| `-w`, `--parallel-workers` | Maximum worker count (default: auto) |
| `--parallel-memory-limit` | Memory-pressure threshold before throttling, as a percentage (default: 85) |

`--parallel-workers` is also an explicit override: passing a value above 1 enables
parallel processing even where the built-in heuristic would not have recommended it. Two
further settings exist only in the YAML file — `parallel.min_workers` and
`parallel.adaptive`.

How the worker count and the database mode are chosen is described in
[Advanced → Automatic processing optimization](Advanced.md#automatic-processing-optimization).

### Templating and Mini-GUI

| Option | Description |
|--------|-------------|
| `-t`, `--template` | Jinja2 template for output; repeatable |
| `-T`, `--templateOutput` | Output file for the matching template |
| `--template-append` | Append to template output instead of overwriting |
| `--timesketch` | Shortcut: Timesketch template → `timesketch-<RAND>.json` |
| `--navigator-output` | Shortcut: ATT&CK Navigator layer → `navigator-<RAND>.json`, or a name you give |
| `-G`, `--package` | Create a Mini-GUI package |
| `--package-dir` | Directory for the Mini-GUI package; it must already exist |

Both shortcuts use the template of that name from `templates/` in the working directory
when there is one, and the shipped template otherwise. The same rule applies to `-c`
and `-r` defaults.

> [!WARNING]
> `--template-append` is only safe for templates whose output is a stream of independent
> records. See [Append mode](Advanced.md#append-mode).

### YAML configuration

| Option | Description |
|--------|-------------|
| `-Y`, `--yaml-config` | YAML run-configuration file |
| `--generate-config` | Write a default configuration file and exit |

This is a *run* configuration — which logs to read, which rules to apply, where to write.
It is unrelated to `-c`/`--config`, which points at the field-mappings and transforms
configuration.

`--generate-config` writes a fully commented template covering every supported key, and
that template is the reference for this file's schema. Passing a freshly generated file
straight back with `-Y` changes nothing about how Zircolite behaves: values whose default
is conditional — `output.file`, which follows `--csv`, and `processing.time_field`, which
is auto-detected — ship commented out, because writing them counts as choosing them.

`input.format` accepts `evtx`, `json`, `json_array`, `xml`, `csv`, `sysmon_linux`,
`auditd`, `evtxtract` and `sqlite` (the equivalent of `-D`/`--db-input`).

A configuration file that cannot be honoured stops the run: an unknown key, a ruleset
that is not there, an invalid `input.format`, an unparseable time filter. All the problems
are reported together, then Zircolite exits non-zero rather than continuing with something
other than what the file asked for.

Some options have no equivalent key and must be passed on the command line: `-c`/`--config`, `-q`/`--quiet`, `--profile-rules`, `--archive-password`, `--no-auto-detect`, `--test-rules`, `--timesketch`, `--navigator-output`, `--transform-list`, `--pipeline-list`, `-U`/`--update-rules`, `-v`/`--version`, `--generate-config` and `-Y`/`--yaml-config` itself.

CLI arguments override the file, with three deliberate exceptions:
`--transform-category`, `--add-index` and `--remove-index` are *added* to whatever the
file lists rather than replacing it, since they name things to include rather than which
things to use.

## Output

### Verbosity

| Mode | Flag | What you see |
|------|------|--------------|
| Default | *(none)* | Banner, workload analysis, progress bars with live detection counters, per-file tree, detection table, summary panel, ATT&CK coverage and the output path |
| Quiet | `-q` | The summary panel only, plus errors and warnings. Good for CI or when piping to other tools |
| Debug | `--debug` | Everything, plus debug-level messages and full tracebacks |

The log file still captures full detail regardless of the mode, unless disabled with `-n`.

### Summary panel

Every run ends with a summary panel showing duration and throughput, a phase-timing bar
(when phases exceed 0.5 s), file and event counts, peak memory, the worker count when
parallel processing was used, detections by severity, a rule-coverage bar, and the top 5
detections.

Two filter statistics appear there, counted separately because the filters act at
different stages: the **event filter** match rate, shown whenever the filter was active
even if it dropped nothing, and the **time range** drops from `--after`/`--before`.

After the panel come a MITRE ATT&CK tactics heatmap grouping detected techniques by
tactic, and the output file path as a clickable `file://` hyperlink in terminals that
support it. Processing several files per-file also prints a tree with per-file event,
detection and filtered counts.

### Detection results table

Matches are shown in a table with four columns — **Severity**, **Rule**, **Events** and
**ATT&CK** (technique IDs pulled from the rule tags). Rows are sorted by severity, then by
event count. Severity is a fixed-width coloured badge: `CRITICAL` on red, `HIGH` on
magenta, `MEDIUM` on yellow, `LOW` on green, and `INFO` on grey.

In per-file mode each file's table is titled with its filename; in parallel mode results
are aggregated into one combined table.

### Rule performance profiling

`--profile-rules` measures how long each rule takes. Files are processed sequentially
while profiling so the timings are comparable, which makes a run over many files slower
than usual.

```shell
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --profile-rules
```

The report lists the top 20 rules by execution time, slowest first, plus the total. Rules
taking 500 ms or more are highlighted red, 100 ms or more yellow. Use it to decide what to
exclude with `--rulefilter`.

### CSV detection output

With `--csv`, detections are written as one flat table. The header covers every column of
the events table plus `rule_title`, `rule_description`, `rule_level` and `rule_count`, so
a rule returning wider rows than the ones before it does not lose fields.

The same holds across inputs. A header has to be written before the rows it describes,
but one file can carry fields an earlier one never produced, so multi-file runs collect
the detections and write the table once at the end — the column set covers every file,
not just the first one to match. That is why a CSV run holds its results in memory where
a JSON run streams them out per file.

Two values are rewritten so the report stays readable and safe to open:

- Embedded newlines and carriage returns become spaces, so a multi-line `ScriptBlockText`
  or `CommandLine` stays on one row without gluing the ends of adjacent lines together.
- A value then starting with `=`, `+`, `-`, `@` or a tab is prefixed with a single quote,
  so a logged string cannot execute as a formula when the report is opened in a
  spreadsheet.

Use JSON when you need the values exactly as stored.

### Sigma conversion summary

Converting native Sigma rules prints a one-line summary — how many converted, how many
were skipped as invalid (files that are not valid Sigma detection or correlation YAML),
and how many failed:

```
[✓] Converted 245 rules (3 invalid skipped, 2 failed)
```

## Automatic Log Type Detection

Zircolite detects the log format and timestamp field of its input, so explicit format
flags are usually unnecessary.

### How it works

Detection runs in three phases against a sample of the file:

| Phase | Method | Example |
|-------|--------|---------|
| **1. Magic bytes** | Binary signature in the file header | EVTX files start with `ElfFile\x00` |
| **2. Content analysis** | Structural patterns in a 64 KB sample | Windows JSON events have `Event.System.Channel` |
| **3. Extension fallback** | The file extension, enriched by a regex scan for timestamps | `.log` files with ISO 8601 timestamps |

For **compressed or archived** files (`.gz`, `.bz2`, `.zip`, `.7z`) the inner file is
resolved first — decompressing or opening the archive, using `--archive-password` where
needed — and the phases then run against the inner content.

Each result carries a confidence level: **high** for a strong structural match (EVTX magic
bytes, a Sysmon channel in JSON), **medium** for a reasonable one (generic JSON with a
detected timestamp field), **low** for an extension-based guess.

| Log source | Detection signals | Timestamp field |
|------------|-------------------|-----------------|
| Windows EVTX (binary) | Magic bytes `ElfFile\x00` | `SystemTime` |
| Windows EVTX JSON | Nested `Event.System` with `Channel`/`EventID` | `SystemTime` |
| Windows EVTX XML | XML with the Microsoft Event namespace | `SystemTime` |
| Sysmon Windows | Channel is `Microsoft-Windows-Sysmon/Operational` | `UtcTime` |
| Sysmon for Linux | Syslog header plus embedded `<Event>` XML | `UtcTime` |
| Auditd (raw) | `type=XXXX msg=audit(...)` | `timestamp` |
| Auditd (JSON) | A `type` field with an auditd value | `timestamp` |
| ECS / Elastic | `@timestamp` or `event.module` present | `@timestamp` |
| EVTXtract output | Marker strings ("Found at offset", "Record number") | `SystemTime` |
| Saved database | SQLite magic bytes | — |
| CSV | Headers with `Channel`/`EventID` or a known timestamp column | Auto-detected |
| Generic JSON/JSONL | Heuristic field scanning plus regex fallback | Auto-detected |

Detection works on directories too. Zircolite first looks for `.evtx` files; finding none,
and with no `--fileext` or `--file-pattern` pinned, it samples the directory to detect the
format and re-scans with the matching extension. So a folder of `.json`, `.log` or `.csv`
logs needs no extra flag. An explicit `--fileext` always wins.

```shell
python3 zircolite.py --events logs/ --ruleset rules/rules_windows_merged.json
# [+] Auto-detected log type: sysmon_windows (json), confidence=high, timestamp=UtcTime
```

### Timestamp detection

The timestamp field is found in three ways, in order:

1. **Known field names** — a priority list configurable in `config/config.yaml`:
   `SystemTime`, `UtcTime`, `TimeCreated`, `@timestamp`, `timestamp`, `EventTime`,
   `_time`, `ts` and others.
2. **Heuristic scoring** — every field is scored by name relevance (containing "time",
   "date", "created") and by the shape of its value.
3. **Regex fallback** — the raw content is scanned for timestamp patterns (ISO 8601,
   syslog, epoch seconds or milliseconds, US date-time, Windows FileTime) and tied back to
   a key where possible.

On that last path a field is only accepted when its **whole value** is the timestamp, or
when its name reads like a time field. A free-text `message` that happens to mention a
date is not a timestamp field — treating it as one would leave `--after`/`--before`
filtering on prose.

Override it explicitly at any time:

```shell
python3 zircolite.py --events logs/ --ruleset rules.json --timefield "@timestamp"
```

### Disabling detection

```shell
python3 zircolite.py --events logs/ --ruleset rules.json --no-auto-detect --json-input
```

Explicit format flags always take precedence over detection, whether or not it is enabled.

## Input Formats

### EVTX

```shell
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_merged.json
```

EVTX parsing is **lenient** by default: when a chunk is corrupted or malformed, Zircolite
keeps every event recovered up to that point, logs a warning and moves on to the next
file. That is usually what you want with evidence from a damaged disk or an interrupted
export.

`--strict` aborts on the first parsing error instead, for when you need to know a file was
processed in full. The run stops and exits `1`, whether the bad file was given on its own
or found in a directory. Because aborting the whole run is the point, `--strict` forces
sequential processing.

Either way, a file that could not be read in full is named on the console and is never
removed by `--remove-events`.

### XML

`evtx_dump` and services such as VirusTotal produce text files with XML events inside,
either one `<Event>` per line or wrapped in an `<Events>` element. Zircolite handles both:

```shell
python3 zircolite.py --events Microsoft-Windows-SysmonOperational.xml \
    --ruleset rules/rules_windows_merged.json --xml
```

To produce that format with `evtx_dump`:

```shell
./evtx_dump -o xml <EVTX_FILE> -f <OUTPUT_XML_FILE> --no-indent --dont-show-record-number
```

Each line then looks like this (truncated):

```xml
<?xml version="1.0" encoding="utf-8"?><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="XXXXXX"></Provider><EventID>1</EventID><TimeCreated SystemTime="XXXX-XX-XXTXX:XX:XX.XXXXXXZ"></TimeCreated><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>XXXXXXX</Computer></System><EventData><Data Name="UtcTime">XXXX-XX-XX XX:XX:XX.XXX</Data><Data Name="Image">XXXXXX</Data><Data Name="CommandLine">XXXX</Data></EventData></Event>
```

### EVTXtract

[EVTXtract](https://github.com/williballenthin/EVTXtract) recovers EVTX fragments from raw
binary data, including unallocated space and memory images. Zircolite reads its output:

```shell
python3 zircolite.py --events <EVTXTRACT_OUTPUT> --ruleset <RULESET> --evtxtract
```

### Auditd

```shell
python3 zircolite.py --events auditd.log --ruleset rules/rules_linux.json
python3 zircolite.py --events auditd.log --ruleset rules/rules_linux.json --auditd
```

Auditd `timestamp` fields are rendered in UTC, since auditd epoch timestamps are UTC,
regardless of the timezone of the machine running the analysis.

### Sysmon for Linux

Sysmon for Linux writes XML in text form, one event per line.

```shell
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json --sysmon-linux
```

The default extension for `-S` is `.log` and the default encoding is ISO-8859-1; use
`-LE`/`--logs-encoding` for anything else.

### JSONL / NDJSON

One event per line, as produced by NXLog among others:

```json
{"EventID": "4688", "EventRecordID": "1", ...}
{"EventID": "4688", "EventRecordID": "2", ...}
```

```shell
python3 zircolite.py --events <LOGS_FOLDER> --ruleset <RULESET> --json-input
```

If you have already converted EVTX to JSON and kept the files, re-running over that
directory with `--json-input` avoids converting again.

### JSON array

One large array rather than one object per line:

```shell
python3 zircolite.py --events <LOGS_FOLDER> --ruleset <RULESET> --json-array-input
```

### CSV

Field names must be on the first line:

```csv
EventID,EventRecordID,Computer,SubjectUserSid,...
4624,32421,xxxx.DOMAIN.local,S-1-5-18,xxxx,DOMAIN,...
```

```shell
python3 zircolite.py --events <LOGS_FOLDER> --ruleset <RULESET> --csv-input
```

The delimiter is detected from the first lines: comma, semicolon, tab (`.tsv` exports) and
pipe are all supported, and quoted values containing the delimiter are preserved. Use
`-LE`/`--logs-encoding` when the file is not UTF-8.

Note the asymmetry: `--csv-input` reads CSV, `--csv` *writes* it.

### Compressed and archived logs

The **inner** format is auto-detected where possible.

| Suffix | Format | Notes |
|--------|--------|-------|
| `.gz` | gzip | Standard library; inner format from the filename, e.g. `logs.json.gz` |
| `.bz2` | bzip2 | Standard library; inner format from the filename |
| `.zip` | ZIP | Single-file only; inner format from the member name. Encrypted archives need `--archive-password` |
| `.7z` | 7-Zip | Requires `py7zr`. Single-file only; inner format from the member name. Encrypted archives need `--archive-password` |

Archives must contain **exactly one file**. For `.zip` and `.7z`, Zircolite opens the
archive to read the member name and a sample; when it is password-protected and no
password was given, it falls back to the outer filename (`data.json.7z` → JSON). A wrong
or missing password is reported rather than guessed at.

```shell
python3 zircolite.py --events logs.json.gz --ruleset rules/rules_windows_merged.json
python3 zircolite.py --events export.json.7z --ruleset rules/rules_windows_merged.json \
    --archive-password "yourpassword"
```

### SQLite database files

Everything lives in an in-memory SQLite database, and `--dbfile` saves it:

```shell
python3 zircolite.py --evtx <EVTX_FOLDER> --ruleset <RULESET> --dbfile output.db
```

Re-running against that database with `--db-input` skips parsing, flattening and insertion
entirely, which saves a great deal of time:

```shell
python3 zircolite.py --evtx output.db --ruleset <RULESET> --db-input
```

#### Database indexes

An index on `eventid` is created when the logs table has that column. When it has a
`Channel` column too, the second index is the composite `idx_channel_eventid` on
`(Channel, eventid)` rather than one on `Channel` alone — the Sigma shape is
`Channel = … AND EventID = …`, and a channel-only index leaves SQLite fetching and
re-checking every row of the channel. Its leading column still serves the rules that
name only a channel, so it replaces `idx_channel` rather than joining it; a dataset with
a `Channel` column but no `eventid` still gets a plain `idx_channel`. Adjust the set by
hand:

```shell
# Add indexes
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --add-index Channel EventID

# Drop one by name
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --remove-index idx_channel_eventid
```

Index names follow the `idx_<column>` form: `idx_eventid`, `idx_SystemTime`. The
composite is named for both of its columns, `idx_channel_eventid`.

To let Zircolite choose, `--auto-index` inspects the loaded ruleset and indexes the N
columns that the most *rules* filter on (N defaults to 5). It ranks by rule count, not
by how often a column appears — one rule listing three thousand hashes says no more about
which index earns its keep than a rule listing one. Columns already covered
by the built-in indexes or by `--add-index` are skipped, as are any named in
`--remove-index`, and only columns present in the data are indexed.

```shell
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --auto-index 8
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_merged.json --auto-index --add-index Computer
```

## Rulesets / Rules

Zircolite has its own ruleset format: a single JSON file. Default rulesets live in
[`rules/`](https://github.com/wagga40/Zircolite/tree/master/rules/), and the latest are
published in [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2).

| Ruleset | Covers |
|---------|--------|
| `rules_windows_merged.json` | Sysmon and generic Windows channels — the best default for Windows EVTX |
| `rules_windows_sysmon.json` | Sysmon only |
| `rules_windows_generic.json` | Windows event logs without Sysmon (Security, System, …). Used when `--ruleset` is omitted |
| `rules_linux.json` | Auditd and Sysmon for Linux |

Each also has `_high` and `_medium` variants (that severity and above). `-U` or
`task update-rules` fetches the current versions.

Native Sigma rules in YAML work directly — Zircolite detects the format and converts them
with [pySigma](https://github.com/SigmaHQ/pySigma):

```bash
python3 zircolite.py -e sample.evtx -r schtasks.yml
python3 zircolite.py -e sample.evtx -r ./sigma/rules/windows/process_creation
python3 zircolite.py -e sample.evtx -r schtasks.yml -r ./sigma/rules/windows/process_creation
```

### Sigma correlation rules

Correlation rules (`event_count`, `value_count`, `temporal`) use the same SQLite backend.
Put the base rule(s) and the correlation rule in the **same YAML file** (a multi-document
stream separated by `---`) or in the **same directory** passed to `--ruleset`, so that
`name` references resolve. Two separate `--ruleset` paths load separate collections and
cannot resolve references across them.

Rules that exist only as references for a correlation are compiled internally so the
correlation SQL can embed their conditions, but they are not emitted as standalone
detections — a converted ruleset therefore typically has one row per correlation rule.

Correlations using `timespan` need a timestamp column, and Zircolite aligns the backend's
timestamp field with the one detected in your logs or set with `--timefield`. If detection
finds `@timestamp` (sanitised to `timestamp`), the correlation SQL references `timestamp`
rather than the default `SystemTime`. No configuration is needed.

Two limitations are worth knowing:

- **`timespan` on `event_count`**: the backend may not apply the time window in the
  generated query, so counts can reflect every matching row rather than a rolling window.
- **Event filtering**: correlation-only entries carry no Channel/EventID metadata, so they
  are omitted from early filtering and the referenced base rules drive it instead.

### Rules with very large value lists

Some rules enumerate thousands of values — vulnerable driver hashes, malicious package
names. Converted straight from Sigma, their SQL nests one level per value and exceeds
SQLite's parser depth limit, so it cannot be prepared at all.

Zircolite detects this and rewrites the expression into an equivalent, shallower form
before retrying, so these rules run normally. Nothing is required of you. Two consequences:

- The `sigma` field in `detected_events.json` always reports the rule's declared SQL, even
  when the statement executed was the rewritten one.
- `--save-ruleset` writes the SQL exactly as pySigma produced it. The repair happens on
  load, so an exported ruleset stays faithful to the conversion.

A rule that genuinely cannot be evaluated is reported at the end of the run rather than
passing for a rule that simply matched nothing; use `--debug` for the SQL error.

### Generating your own rulesets

Install [sigma-cli](https://github.com/SigmaHQ/pySigma) with the SQLite backend and the
pipelines you need, then convert:

```shell
pip install sigma-cli pysigma-pipeline-sysmon pysigma-pipeline-windows pysigma-backend-sqlite

git clone https://github.com/SigmaHQ/sigma.git
cd sigma

# Sysmon
sigma convert -t sqlite -f zircolite -p sysmon -p windows-logsources rules/windows/ -s -o rules.json

# Generic (no Sysmon)
sigma convert -t sqlite -f zircolite -p windows-audit -p windows-logsources rules/windows/ -s -o rules.json
```

With PDM, Poetry or UV, add the same packages and prefix the command with `pdm run`,
`poetry run` or `uv run`.

- `-t` is the backend (SQLite); `-f zircolite` selects the Zircolite output format.
- `-p` names a pipeline; repeat for several.
- `-s` continues on error, for unsupported rules.
- `-o` is the output file.

### Why You Should Build Your Own Rulesets

The default rulesets are a straight conversion of the Sigma repository's `rules/windows`
and `rules/linux` directories, provided so Zircolite works out of the box. They are not
filtered, and two things follow:

- **Some rules are very noisy** or produce many false positives, depending on your
  environment and the pipelines used. "Suspicious Eventlog Clear or Configuration Using
  Wevtutil" is a classic on fresh lab environments.
- **Some rules are very slow** on particular datasets. "Notepad Making Network Connection"
  can significantly slow a run.

`--profile-rules` tells you which ones cost you time; `--rulefilter` removes them.

## Rule testing

`--test-rules` validates a ruleset against test cases without touching real logs — useful
for regression testing after changing rules or field mappings, and for CI.

```bash
python3 zircolite.py --ruleset rules/rules_windows_merged.json --test-rules rule_tests.json
```

Zircolite runs the rules against the given events, prints a results table and exits: `0`
when every case passes, `1` when any does not. No `--events` input is needed. Test events
are stored in typed columns, so numeric comparisons behave exactly as they do during a
real run.

### Test file format

A JSON array. Each element describes the tests for one rule and is matched by **title** or
**id** — at least one is required.

| Field | Description |
|-------|-------------|
| `title` | Rule title, matched against the ruleset |
| `id` | Rule ID, matched against the ruleset |
| `true_positive` | Events that **must** trigger the rule (at least one match expected) |
| `true_negative` | Events that **must not** trigger it (zero matches expected) |

Events are flat key-value objects whose keys are column names as they appear in the `logs`
table — that is, after field mappings.

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
  }
]
```

Rules with no entry in the test file are reported as "no test case" and **skipped** —
they do not fail the run. The reverse is a failure: a test case whose `title`/`id` matches
no rule never runs, so counting it as a pass would hide a typo. Those entries are reported
and the run exits `1`.

## Pipelines

Zircolite uses no pySigma pipeline by default. Install the ones you need
(`pip3 install pysigma-pipeline-<name>`), list what is available, and pass them with `-p`:

```bash
python3 zircolite.py -pl
python3 zircolite.py -e sample.evtx -r schtasks.yml -p sysmon -p windows-logsources
```

The converted result can be saved with `-sr`/`--save-ruleset`.

> [!NOTE]
> With multiple native Sigma rulesets you cannot vary the pipeline per ruleset — every
> pipeline is applied to the whole conversion.

## Field Mappings, Exclusions, Aliases, and Splitting

Logs often need reshaping before rules can match them. The canonical configuration is
[`config/config.yaml`](https://github.com/wagga40/Zircolite/tree/master/config/); point at
your own with `-c`/`--config`. YAML is the expected format; JSON is still accepted for
backward compatibility and is recognised from the extension.

`config/fieldMappings.yaml` is the former name of this file. It is still read, and still
warns that it is deprecated on every run; it may be dropped in a future version.

```yaml
exclusions:               # drop these fields entirely
  - xmlns

useless:                  # drop a field when its value is one of these
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
```

The same file also holds `transforms_enabled`, `enabled_transforms`,
`transform_categories`, `transforms_dir` and `transforms` (see
[Field Transforms](Advanced.md#field-transforms)), plus `event_filter` and
`timestamp_detection`, below.

**Mappings** rename a field; the original name is not kept. Zircolite uses this internally
to flatten nested JSON paths into simple names.

**Exclusions** drop a field from every event — `xmlns` by default. **Value exclusions**
(`useless`) drop a field when its value matches, which is how `null` and empty strings are
removed.

**Aliases** duplicate a field under a new name, keeping the original. They apply to raw
and mapped field names — given `alias: {CommandLine: cmdline}`, rules see both
`CommandLine` and `cmdline`. They do **not** apply to fields produced by splitting, which
are written directly. Aliases duplicate data, so use them sparingly; the shipped
`config/config.yaml` defines none.

### Field Splitting

Splitting parses a packed key=value string into separate, queryable fields. Sysmon's
`Hashes` is the built-in case:

```yaml
split:
  Hashes:
    separator: ","
    equal: "="
```

```json
{ "Hashes": "SHA1=XX,MD5=X,SHA256=XXX,IMPHASH=XXXX", "EventID": 1 }
```

…becomes, as far as rules are concerned:

```json
{
    "SHA1": "XX", "MD5": "X", "SHA256": "XXX", "IMPHASH": "XXXX",
    "Hashes": "SHA1=XX,MD5=X,SHA256=XXX,IMPHASH=XXXX",
    "EventID": 1
}
```

The shipped configuration splits three fields this way: `Hash`, `Hashes` and
`ConfigurationFileHash`.

Splitting runs *after* transforms, so a transform that replaces a value rather than
writing an alias changes what gets split.

### Event filter and timestamp configuration

Two more sections of `config/config.yaml` shape ingestion.

**`event_filter`** skips events before processing, based on Channel and EventID, so only
events that could match some rule's log source are loaded. The field paths are
configurable, which is what makes it work on pre-flattened and ECS logs as well as raw
EVTX:

```yaml
event_filter:
  enabled: true
  channel_fields:
    - Event.System.Channel      # Standard EVTX
    - Channel                   # Pre-flattened
    - winlog.channel            # Elastic Winlogbeat
  eventid_fields:
    - Event.System.EventID
    - EventID
    - winlog.event_id
  # Windows-only by default. Set true to filter every input format by
  # Channel/EventID, including Linux, auditd and generic JSON sources.
  filter_all_sources: false
```

Disable it with `--no-event-filter` or `enabled: false`. How the per-channel bounds are
derived, when they do not apply, and why a Linux ruleset disables the filter entirely are
covered in [Advanced → Early event filtering](Advanced.md#early-event-filtering).

**`timestamp_detection`** controls the search described under
[Timestamp detection](#timestamp-detection):

```yaml
timestamp_detection:
  auto_detect: true
  default_field: SystemTime     # used when none of the detection_fields is present
  detection_fields:
    - SystemTime                # Windows EVTX default
    - UtcTime                   # Sysmon
    - "@timestamp"              # Elasticsearch / ECS
    - timestamp
    - _time                     # Splunk
```

A field set with `--timefield`, or with `processing.time_field` in a run configuration, is
never overridden by auto-detection.

## Field Transforms

Transforms run small sandboxed Python snippets against field values during flattening.
They can decode Base64 and hex, extract IOCs, categorise values or flag obfuscation, and
they normally write to a **new** field so the original is preserved. Zircolite ships 55 of
them in 11 categories, all switched off by default apart from the two auditd ones.

Everything about them — enabling, the full catalogue, the values each one produces, and
how to write your own — is in [Advanced → Field Transforms](Advanced.md#field-transforms).

## Docker

Zircolite is published as [wagga40/zircolite](https://hub.docker.com/r/wagga40/zircolite),
with all dependencies included. Note that the image is not rebuilt for every ruleset
update.

```shell
docker pull wagga40/zircolite:latest
```

Mount your logs and point Zircolite at the mount. Read-only for the input, writable for
the results:

```shell
docker run --rm --tty \
    -v <Logs folder>:/case/input:ro \
    -v <Results folder>:/case/output \
    wagga40/zircolite:latest \
    --ruleset rules/rules_windows_merged.json \
    --events /case/input \
    -o /case/output/detected_events.json
```

That uses the rulesets baked into the image. To use your own, put them in a mounted
directory and give the container path: `--ruleset /case/input/my_ruleset.json`.

To build the image yourself: `docker build . -t <image name>`.

## Troubleshooting

| Issue | What to try |
|-------|-------------|
| **Wrong format detected** | `--no-auto-detect` plus an explicit format flag |
| **Missing or wrong timestamp field** | `--timefield "FieldName"` |
| **No detections** | Make sure the ruleset matches the log source — Sysmon rules for Sysmon EVTX, generic Windows rules for Security/System. For mixed or unknown Windows logs use `rules_windows_merged.json`. Then check that your field names match what the rules expect. |
| **Out of memory on large datasets** | `--no-parallel`, `--no-auto-mode`, or a lower `--parallel-workers` |
| **A run is slow** | `--profile-rules` to find the expensive rules, then `--rulefilter` to drop them |
| **Ruleset file not found** | Default rulesets are in `rules/`; run `python3 zircolite.py -U` to download them |
| **`evtx` (pyevtx-rs) fails to install** | On macOS and ARM, install Rust and Cargo first — see [Requirements and Installation](Usage.md#requirements-and-installation) |

`--debug` gives full tracebacks and debug logging. For large datasets, filtering and
templating see [Advanced](Advanced.md); for architecture see [Internals](Internals.md).
