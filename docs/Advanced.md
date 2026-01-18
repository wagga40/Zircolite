# Advanced Use

## Working with Large Datasets

Zircolite tries to be as fast as possible while managing memory efficiently. The tool now processes each log file separately in its own database by default, which significantly improves memory usage for large datasets.

### Automatic Processing Optimization

As of version 2.41.0, Zircolite automatically analyzes your workload and optimizes processing. When you run Zircolite with multiple files, it:

1. **Analyzes your files** - counts files, measures sizes, checks available RAM and CPU cores
2. **Selects optimal database mode** - unified (all files in one DB) vs. per-file (separate DB per file)
3. **Enables parallel processing** - when beneficial, automatically processes files in parallel with optimal worker count

```shell
# Auto-optimization happens by default
python3 zircolite.py --evtx ./logs/ --ruleset rules/rules_windows_sysmon.json

# Example output:
# [+] Analyzing workload...
#     [>] Files: 15 (250.3 MB total, avg 16.7 MB)
#     [>] System: 12.5 GB RAM available, 8 CPUs
#     [>] 📁 Database mode: PER-FILE
#         [i] Default mode - 15 files, 250.3 MB total
#     [>] ⚡ Parallel: ENABLED (4 workers)
```

#### Database Mode Selection Heuristics

The automatic mode selection uses the following rules:

| Condition | Mode Selected | Reason |
|-----------|---------------|--------|
| Single file | Per-file | No benefit from unified mode |
| Low RAM (<2 GB available) | Per-file | Safer for memory-constrained systems |
| Total data > Available RAM / 3 | Per-file | Avoid out-of-memory errors |
| Many small files (>10 files, avg <5 MB) | Unified | Less overhead, enables cross-file correlation |
| Few large files (<5 files, avg >50 MB) | Per-file | Memory efficient processing |
| High RAM (>8 GB) + multiple files | Unified | Faster overall processing |

#### Controlling Processing Mode

```shell
# Disable automatic mode selection (use default per-file mode)
python3 zircolite.py --evtx logs/ --ruleset rules.json --no-auto-mode

# Force unified database mode (enables cross-file rule correlation)
python3 zircolite.py --evtx logs/ --ruleset rules.json --unified-db

# Disable parallel processing
python3 zircolite.py --evtx logs/ --ruleset rules.json --no-parallel

# Set specific worker count
python3 zircolite.py --evtx logs/ --ruleset rules.json --parallel-workers 4
```

### Parallel Processing

Zircolite automatically enables parallel processing when it's beneficial. The parallel processor:

- **Calculates optimal workers** based on available memory, CPU cores, and file sizes
- **Monitors memory** during processing and can throttle if approaching limits
- **Uses threads** for I/O-bound EVTX parsing (process-based parallelism was deprecated due to compatibility issues)
- **Falls back to sequential** if parallel isn't beneficial (single file, low memory)

#### Parallel Processing Heuristics

| Condition | Parallel | Reason |
|-----------|----------|--------|
| Single file | Disabled | No benefit |
| Very low RAM (<1 GB) | Disabled | Safety |
| Memory per file > 60% usable RAM | Disabled | Prevent OOM |
| Multiple files + sufficient memory | Enabled | Faster processing |

#### Manual Parallel Configuration

```shell
# Set maximum workers
python3 zircolite.py --evtx logs/ --ruleset rules.json --parallel-workers 8

# Set memory threshold for throttling (default: 75%)
python3 zircolite.py --evtx logs/ --ruleset rules.json --parallel-memory-limit 80
```

### Streaming Mode

Zircolite includes a **streaming mode** (enabled by default) that provides significantly faster processing by combining extraction, flattening, and database insertion into a single pass.

#### How Streaming Mode Works

**Traditional Mode (multi-pass):**
1. Extract logs from EVTX → Write intermediate JSON files
2. Read JSON files → Flatten → Store in memory
3. Create database → Insert all events
4. Execute rules

**Streaming Mode (single-pass):**
1. Extract logs → Flatten immediately → Insert directly to database in batches
2. Execute rules

This eliminates intermediate file I/O, avoids double JSON parsing, and reduces memory usage (typically 40-60% faster).

#### When Streaming Mode is Used

Streaming mode is **enabled by default** for most input types:
- EVTX files
- JSON/JSONL files
- JSON Array files
- XML logs
- Sysmon for Linux logs
- Auditd logs

Streaming mode is **automatically disabled** for:
- CSV input (`--csv-input`)
- EVTXtract input (`--evtxtract-input`)
- When using `--keepflat` (to save intermediate JSON)
- When using `--fieldlist`

#### Controlling Streaming Mode

```shell
# Force traditional mode (disable streaming)
python3 zircolite.py --evtx logs/ --ruleset rules.json --no-streaming
```

### Memory Usage

- Zircolite displays memory statistics (peak and average usage) at the end of each run.
- Memory tracking uses `psutil` if available.
- In per-file mode, each log file is processed in its own in-memory database, and the database is released after processing.

### Performance Optimizations

There are several ways to speed up Zircolite:

- Let automatic optimization do its work (enabled by default).
- Use [Filtering](#filtering) to process only relevant files.
- Use the `--no-recursion` option if you don't need recursive directory search.
- For extreme cases with very large datasets, use GNU Parallel for external parallelization.

> [!NOTE]  
> There is an option to use an on-disk database instead of in-memory by using the `--ondiskdb <DB_NAME>` argument. This is only useful to avoid errors when dealing with very large datasets and if you have a lot of time... **This should be used with caution, and the alternatives below are far better choices.**

### Using GNU Parallel

> [!NOTE]  
> Zircolite now has built-in parallel processing that is enabled by default. The section below is only useful for advanced scenarios where you need external parallelization (e.g., processing across multiple machines or when you need separate output files per directory).

On Linux or macOS, you can use **GNU Parallel** to launch multiple Zircolite instances for advanced scenarios.

> [!NOTE]  
> On macOS, please use GNU find (`brew install findutils` will install `gfind`).

- **"DFIR Case Mode": One directory per computer/endpoint**

	This mode is very useful when you have a case where all your evidence is stored per computer (one directory per computer containing all EVTX files for that computer). It will create one result file per computer in the current directory.

	```shell
	find <CASE_DIRECTORY> -maxdepth 1 -mindepth 1 -type d | \
		parallel --bar python3 zircolite.py -e {} \
		-r rules/rules_windows_sysmon_pysigma.json --outfile {/.}.json
	```
	
	One downside of this mode is that if you have fewer computer evidence directories than CPU cores, they will not all be used.

- **"WEF/WEC Mode": One Zircolite instance per EVTX**

	You can use this mode when you have a lot of aggregated EVTX files coming from multiple computers. This is generally the case when you use WEF/WEC and you recover the EVTX files from the collector. This mode will create one result file per EVTX.

	```shell
	find <CASE_DIRECTORY> -type f -name "*.evtx" \
		parallel -j -1 --progress python3 zircolite.py -e {} \
		-r rules/rules_windows_sysmon_pysigma.json --outfile {/.}.json
	```
	
	In this example, `-j -1` uses all cores but one. You can adjust the number of cores used with this argument.

## Keeping Data Used by Zircolite

**Zircolite** has several arguments that can be used to keep data used to perform Sigma detections: 

- `--dbfile <FILE>` allows you to export all the logs to a SQLite 3 database file. You can query the logs with SQL statements to find more things than what the Sigma rules could have found. When processing multiple files, each file gets its own database file with a unique name.
- `--keeptmp` allows you to keep the source logs (EVTX/Auditd/EVTXtract/XML...) converted in JSON format.
- `--keepflat` allows you to keep the source logs (EVTX/Auditd/EVTXtract/XML...) converted in a flattened JSON format.
- `--hashes` adds an xxhash64 hash of the original log line to each event, useful for deduplication and tracking.

## Filtering

Zircolite has many filtering options to speed up the detection process. Don't overlook these options because they can save you a lot of time.

### File Filters

Some EVTX files are not used by SIGMA rules but can become quite large (a good example is `Microsoft-Windows-SystemDataArchiver%4Diagnostic.evtx`). If you use Zircolite with a directory as the input argument, all EVTX files will be converted, saved, and matched against the SIGMA rules. 

To speed up the detection process, you may want to use Zircolite on files matching or not matching a specific pattern. For that, you can use **filters** provided by the following command-line arguments:

- `-s` or `--select`: Select files partly matching the provided string (case insensitive).
- `-a` or `--avoid`: Exclude files partly matching the provided string (case insensitive).
- `-fp` or `--file-pattern`: Use a Python glob pattern for file selection.
- `--no-recursion`: Disable recursive directory search.

> [!NOTE]  
> When using both `--select` and `--avoid` arguments, the "select" argument is always applied first, and then the "avoid" argument is applied. So it is possible to exclude files from included files, but not the opposite.

- Only use EVTX files that contain "sysmon" in their names:

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
		--select sysmon
	```
- Exclude "Microsoft-Windows-SystemDataArchiver%4Diagnostic.evtx": 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
		--avoid systemdataarchiver
	```

- Only use EVTX files with "operational" in their names but exclude "defender"-related logs:
	
	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
	--select operational --avoid defender
	```

- Use a custom glob pattern to select specific files:

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
		--file-pattern "Security*.evtx"
	```

For example, the **Sysmon** ruleset available in the `rules` directory only uses the following channels (names have been shortened): *Sysmon, Security, System, Powershell, Defender, AppLocker, DriverFrameworks, Application, NTLM, DNS, MSExchange, WMI-Activity, TaskScheduler*. 

So if you use the Sysmon ruleset with the following rules, it should speed up Zircolite's execution: 

```shell
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
	--select sysmon --select security.evtx --select system.evtx \
	--select application.evtx --select Windows-NTLM --select DNS \
	--select powershell --select defender --select applocker \
	--select driverframeworks --select "msexchange management" \
	--select TaskScheduler --select WMI-activity
```

### Time Filters

Sometimes you only want to work on a specific time range to speed up analysis. With Zircolite, it is possible to filter on a specific time range using the `--after` and `--before` arguments and their respective shorter versions `-A` and `-B`. Please note that: 

- The filter will apply to the `SystemTime` field of each event.
- The `--after` and `--before` arguments can be used independently.
- The timestamps provided must have the following format: `YYYY-MM-DDTHH:MM:SS` (hours are in 24-hour format).

Examples: 

- Select all events between 2021-06-02 22:40:00 and 2021-06-02 23:00:00: 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
		-A 2021-06-02T22:40:00 -B 2021-06-02T23:00:00
	```

- Select all events after 2021-06-01 12:00:00: 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
		-A 2021-06-01T12:00:00
	```

### Rule Filters

Some rules can be noisy or slow on specific datasets (check [here](https://github.com/wagga40/Zircolite/tree/master/rules/README.md)), so it is possible to skip them by using the `-R` or `--rulefilter` argument. This argument can be used multiple times.

The filter will apply to the rule title. To avoid unexpected side effects, **comparison is case-sensitive**. For example, if you do not want to use all MSHTA-related rules: 

```shell
python3 zircolite.py --evtx logs/ \
	--ruleset rules/rules_windows_sysmon_pysigma.json \
	-R MSHTA
```

### Limit the Number of Detected Events

Sometimes SIGMA rules can be very noisy (and generate a lot of false positives), but you still want to keep them in your rulesets. It is possible to filter rules that return too many detected events with the option `--limit <MAX_NUMBER>`. **Please note that when using this option, the rules are not skipped—the results are just ignored.** However, this is useful when forwarding events to Splunk.

## Templating and Formatting

Zircolite provides a templating system based on Jinja2. It allows you to change the output format to suit your needs (Splunk or ELK integration, grep-able output, etc.). There are some templates available in the [Templates directory](https://github.com/wagga40/Zircolite/tree/master/templates) of the repository: Splunk, Timesketch, and more. To use the template system, use these arguments:

- `--template <template_filename>`
- `--templateOutput <output_filename>`

```shell
python3 zircolite.py --evtx sample.evtx  --ruleset rules/rules_windows_sysmon_pysigma.json \
--template templates/exportForSplunk.tmpl --templateOutput exportForSplunk.json
```

It is possible to use multiple templates if you provide a `--templateOutput` argument for each `--template` argument.

## Mini-GUI

![](pics/gui.jpg)


The Mini-GUI can be used completely offline. It allows the user to display and search results. It uses [DataTables](https://datatables.net/) and the [SB Admin 2 theme](https://github.com/StartBootstrap/startbootstrap-sb-admin-2). 

### Automatic Generation

As of Zircolite 2.1.0, the easiest way to use the Mini-GUI is to generate a package with the `--package` option. A ZIP file containing all the necessary data will be generated. Use `--package-dir` to specify the output directory:

```shell
python3 zircolite.py --evtx sample.evtx \
    --ruleset rules/rules_windows_sysmon_pysigma.json \
    --package --package-dir /path/to/output
```

### Manual Generation

You need to generate a `data.js` file with the `exportForZircoGui.tmpl` template, decompress the `zircogui.zip` file in the [gui](https://github.com/wagga40/Zircolite/tree/master/gui/) directory, and replace the `data.js` file in it with yours:

```shell
python3 zircolite.py --evtx sample.evtx 
	--ruleset rules/rules_windows_sysmon_pysigma.json \
	--template templates/exportForZircoGui.tmpl --templateOutput data.js
7z x gui/zircogui.zip
mv data.js zircogui/
```

Then simply open `index.html` in your favorite browser and click on a MITRE ATT&CK® category or an alert level.
  
> [!WARNING]  
> **The Mini-GUI was not built to handle large datasets.**

## Packaging Zircolite 

### PyInstaller

* Install Python 3.10+ on the same OS as the one you want to use Zircolite on.
* Install all dependencies: `pip3 install -r requirements.txt`
* Install PyInstaller: `pip3 install pyinstaller`
* In the root folder of Zircolite, type: `pyinstaller -c --onefile zircolite.py`
* The `dist` folder will contain the packaged app.

### Nuitka

* Install Python 3.10+ on the same OS as the one you want to use Zircolite on.
* Install all dependencies: `pip3 install -r requirements.txt`
* Install Nuitka: `pip3 install nuitka`
* In the root folder of Zircolite, type: `python3 -m nuitka --onefile zircolite.py`

> [!WARNING]  
> When packaging with PyInstaller or Nuitka, some antivirus programs may flag your package.

## Troubleshooting

### Debug Mode

Use `--debug` for detailed logging:

```shell
python3 zircolite.py --evtx sample.evtx --ruleset rules.json --debug
```

## Other Tools 

Some other tools (mostly untested) have included a way to run Zircolite: 

- [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) has a module for Zircolite: [here](https://github.com/EricZimmerman/KapeFiles/tree/master/Modules/Apps/GitHub)
- [Velociraptor](https://github.com/Velocidex/velociraptor) has an artifact for Zircolite: [here](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.zircolite/)
