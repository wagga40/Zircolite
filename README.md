# <p align="center">![](pics/zircolite_400.png)</p>

## Standalone SIGMA-Based Detection Tool for EVTX, Auditd, Sysmon for Linux, XML, CSV, or JSONL/NDJSON Logs 
![](pics/Zircolite_v2.9.gif)

[![python](https://img.shields.io/badge/python-3.10-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Architecture-64bit-red)

**Zircolite** is a standalone tool written in Python 3 that allows you to use SIGMA rules on:

- MS Windows EVTX (EVTX, XML, and JSONL formats)
- Auditd logs
- Sysmon for Linux
- EVTXtract
- CSV and XML logs
- JSON Array logs

### Key Features

- **Automatic Log Type Detection**: Automatically identifies log formats and timestamp fields using magic bytes, content analysis, and regex-based fallback -- no need to specify format flags in most cases.
- **Multiple Input Formats**: Supports various log formats including EVTX, JSON Lines, JSON Arrays, CSV, XML, and more.
- **Native Sigma Support**: Zircolite can directly use native Sigma rules (YAML) by converting them with pySigma.
- **SIGMA Backend**: It is based on a SIGMA backend (SQLite) and does not use internal SIGMA-to-something conversion.
- **Advanced Log Manipulation**: It can manipulate input logs by splitting fields and applying transformations, allowing for more flexible and powerful log analysis.
- **Field Transforms**: Apply custom Python transformations to fields during processing (e.g., Base64 decoding, hex-to-ASCII conversion).
- **Flexible Export**: Zircolite can export results to multiple formats using Jinja [templates](templates), including JSON, CSV, JSONL, Splunk, Elastic, Zinc, Timesketch, and more.
- **Rich Terminal Output**: Detection results displayed in severity-sorted tables with MITRE ATT&CK technique IDs, ATT&CK tactics heatmap, rule coverage metrics, clickable output file links, and contextual post-run suggestions.

**You can use Zircolite directly with Python.** 

**Documentation is available [here](https://wagga40.github.io/Zircolite/) (dedicated site) or [here](docs) (repository directory).**

## Requirements / Installation

The project has been tested with Python 3.10 and above. Install dependencies with: `pip3 install -r requirements.txt`.

### Dependencies

- **Required**: `orjson`, `xxhash`, `rich`, `RestrictedPython`, `requests`, `pySigma`, `evtx` (pyevtx-rs), `jinja2`, `lxml`, `psutil`, `pyyaml`

:warning: On some systems (Mac, ARM, etc.), the `evtx` Python library may require Rust and Cargo to be installed.

## Quick Start

Check out tutorials made by others (EN, ES, and FR) [here](#tutorials).

### EVTX Files

Help is available with:

```shell
python3 zircolite.py -h
```

If your EVTX files have the extension ".evtx":

```shell
# python3 zircolite.py --evtx <EVTX FOLDER or EVTX FILE> --ruleset <SIGMA RULESET> [--ruleset <OTHER RULESET>]
python3 zircolite.py --evtx sysmon.evtx --ruleset rules/rules_windows_sysmon.json
```

### Using Native Sigma Rules (YAML)

You can use native Sigma rules (YAML) directly:

```shell
# Single YAML rule
python3 zircolite.py --evtx sample.evtx --ruleset path/to/rule.yml

# Directory of Sigma rules
python3 zircolite.py --evtx sample.evtx --ruleset ./sigma/rules/windows/process_creation

# With pySigma pipelines
python3 zircolite.py --evtx sample.evtx --ruleset rule.yml --pipeline sysmon --pipeline windows-logsources
```

### Other Log Formats

Zircolite **auto-detects** the log format in most cases, so explicit format flags are optional:

```shell
# Auto-detection (recommended) - Zircolite identifies the format automatically
python3 zircolite.py --events auditd.log --ruleset rules/rules_linux.json
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json
python3 zircolite.py --events <JSON_FOLDER_OR_FILE> --ruleset rules/rules_windows_sysmon.json

# Explicit format flags (still supported, override auto-detection)
python3 zircolite.py --events auditd.log --ruleset rules/rules_linux.json --auditd
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json --sysmon4linux
python3 zircolite.py --events <JSON_FOLDER_OR_FILE> --ruleset rules/rules_windows_sysmon.json --jsononly
python3 zircolite.py --events <JSON_FOLDER_OR_FILE> --ruleset rules/rules_windows_sysmon.json --json-array
python3 zircolite.py --events <CSV_FOLDER_OR_FILE> --ruleset rules/rules_windows_sysmon.json --csv-input
python3 zircolite.py --events <XML_FOLDER_OR_FILE> --ruleset rules/rules_windows_sysmon.json --xml-input
```

- The `--events` argument can be a file or a folder. If it is a folder, all log files in the current folder and subfolders will be selected (use `--no-recursion` to disable).
- Use `--file-pattern` to specify a custom glob pattern for file selection.
- Use `--no-auto-detect` to disable automatic format detection.

> [!TIP]
> If you want to try the tool, you can test with [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (EVTX files).

### Running with Docker

```bash
# Pull the Docker image
docker pull wagga40/zircolite:latest
# If your logs and rules are in a specific directory
docker run --rm --tty \
    -v $PWD:/case/input:ro \
    -v $PWD:/case/output \
    wagga40/zircolite:latest \
    -e /case/input \
    -o /case/output/detected_events.json \
    -r /case/input/a_sigma_rule.yml
```

- Replace `$PWD` with the directory (absolute path only) where your logs and rules/rulesets are stored.

### Automatic Processing Optimization

Zircolite automatically optimizes processing based on your workload. When you run Zircolite with multiple files, it:

1. **Analyzes your files** - counts files, measures sizes, checks available RAM
2. **Selects optimal database mode** - unified (all files in one DB) vs. per-file (separate DB per file)
3. **Enables parallel processing** - when beneficial, automatically processes files in parallel

```shell
python3 zircolite.py --evtx ./logs/ --ruleset rules/rules_windows_sysmon.json
```

You can control this behavior:

```shell
# Disable automatic mode selection (force per-file mode)
python3 zircolite.py --evtx ./logs/ --ruleset rules/rules_windows_sysmon.json --no-auto-mode

# Force unified database mode (enables cross-file correlation)
python3 zircolite.py --evtx ./logs/ --ruleset rules/rules_windows_sysmon.json --unified-db

# Disable parallel processing
python3 zircolite.py --evtx ./logs/ --ruleset rules/rules_windows_sysmon.json --no-parallel

# Specify maximum workers manually
python3 zircolite.py --evtx ./logs/ --ruleset rules/rules_windows_sysmon.json --parallel-workers 4
```

The parallel processor automatically:
- Calculates optimal worker count based on available memory, CPU cores, and file sizes
- Monitors memory usage and throttles if approaching limits
- Falls back to sequential processing if parallel isn't beneficial

### Using YAML Configuration Files

For complex or repeated analysis workflows, use a YAML configuration file:

```shell
# Generate a default configuration file
python3 zircolite.py --generate-config my_config.yaml

# Run with a configuration file
python3 zircolite.py --yaml-config my_config.yaml

# CLI arguments override config file settings
python3 zircolite.py --yaml-config my_config.yaml --evtx ./other_logs/
```

Example configuration file (`config/zircolite_example.yaml`):

```yaml
input:
  path: ./logs/
  format: evtx
  recursive: true

rules:
  rulesets:
    - rules/rules_windows_sysmon.json
  pipelines:
    - sysmon

output:
  file: detected_events.json
  format: json

processing:
  streaming: true      # Single-pass processing (default: enabled)
  unified_db: false    # Per-file databases (default)
  auto_mode: true      # Automatic mode selection (default: enabled)

parallel:
  enabled: true        # Parallel processing (auto-enabled when beneficial)
  max_workers: null    # Auto-detect based on CPU/memory
  memory_limit_percent: 75.0
```

### Updating Default Rulesets

```shell
python3 zircolite.py -U
```

Alternatively, if you use [Task](https://taskfile.dev/) (go-task), run `task update-rules` from the project root to update rules from [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2). See [docs](docs/README.md) for other tasks (Docker build, clean, etc.).

> [!IMPORTANT]  
> Please note that these rulesets are provided to use Zircolite out of the box, but [you should generate your own rulesets](#why-you-should-build-your-own-rulesets) as they can be noisy or slow. These auto-updated rulesets are available in the dedicated repository: [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2).

### Field Splitting

Field splitting extracts key-value pairs from fields. For example, Sysmon logs contain a `Hashes` field like:

```
SHA1=abc123,MD5=def456,SHA256=789xyz
```

With field splitting configured in `config/fieldMappings.yaml`:

```yaml
split:
  Hashes:
    separator: ","
    equal: "="
```

The event becomes:

```json
{
  "SHA1": "abc123",
  "MD5": "def456",
  "SHA256": "789xyz",
  "Hashes": "SHA1=abc123,MD5=def456,SHA256=789xyz"
}
```

Now you can write rules that match on `SHA256` or `MD5` directly.

### Field Transforms

Transforms apply Python code to field values during processing. They can decode data, extract IOCs, or detect attack patterns.

**Example: Base64 Decoding**

When a command line contains `powershell -enc SGVsbG8gV29ybGQ=`, the transform:

```yaml
transforms:
  CommandLine:
    - info: "Base64 decode"
      type: python
      code: |
        def transform(param):
            import base64
            import re
            match = re.search(r'-[eE]nc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)', param)
            if match:
                try:
                    return base64.b64decode(match.group(1)).decode('utf-16-le')
                except:
                    return ""
            return ""
      alias: true
      alias_name: "CommandLine_b64decoded"
```

Creates a new field `CommandLine_b64decoded` containing `Hello World`.

**Example: LOLBin Detection**

```yaml
transforms:
  Image:
    - info: "Detect Living Off The Land Binaries"
      type: python
      code: |
        def transform(param):
            import re
            lolbins = ['certutil', 'mshta', 'regsvr32', 'rundll32', 'bitsadmin']
            exe_name = param.lower().split('\\')[-1].replace('.exe', '')
            for lolbin in lolbins:
                if exe_name == lolbin:
                    return f"LOLBIN:{lolbin}"
            return ""
      alias: true
      alias_name: "Image_LOLBinMatch"
```

When `Image` is `C:\Windows\System32\certutil.exe`, creates `Image_LOLBinMatch` = `LOLBIN:certutil`.

See [Advanced documentation](docs/Advanced.md#field-transforms) for all available transforms and detailed configuration.

## Documentation

Complete documentation is available [here](docs).

## Mini-GUI

The Mini-GUI can be used completely offline. It allows you to display and search results. You can automatically generate a Mini-GUI "package" with the `--package` option. Use `--package-dir` to specify the output directory. To learn how to use the Mini-GUI, check the documentation [here](docs/Advanced.md#mini-gui).

### Detected Events by MITRE ATT&CK® Techniques and Criticality Levels

![](pics/gui.webp)

### Detected Events Timeline

![](pics/gui-timeline.webp)

### Detected Events by MITRE ATT&CK® Techniques Displayed on the Matrix 

![](pics/gui-matrix.webp)

## Tutorials, References, and Related Projects

### Tutorials

- **English**: [Russ McRee](https://holisticinfosec.io) has published a detailed [tutorial](https://holisticinfosec.io/post/2021-09-28-zircolite/) on SIGMA and Zircolite on his blog.

- **Spanish**: **César Marín** has published a tutorial in Spanish [here](https://derechodelared.com/zircolite-ejecucion-de-reglas-sigma-en-ficheros-evtx/).

- **French**: [IT-connect.fr](https://www.it-connect.fr/) has published [an extensive tutorial](https://www.it-connect.fr/) on Zircolite in French.

- **French**: [IT-connect.fr](https://www.it-connect.fr/) has also published a [Hack the Box challenge write-up](https://www.it-connect.fr/hack-the-box-sherlocks-tracer-solution/) using Zircolite.

### References 

- [Florian Roth](https://github.com/Neo23x0/) cited Zircolite in his [**SIGMA Hall of Fame**](https://github.com/Neo23x0/Talks/blob/master/Sigma_Hall_of_Fame_20211022.pdf) during his talk at the October 2021 EU ATT&CK Workshop.
- Zircolite has been cited and presented during [JSAC 2023](https://jsac.jpcert.or.jp/archive/2023/pdf/JSAC2023_workshop_sigma_jp.pdf).
- Zircolite has been cited and used in multiple research papers:
  - **CIDRE Team**:
    - [PWNJUTSU - Website](https://pwnjutsu.irisa.fr)
    - [PWNJUTSU - Academic Paper](https://hal.inria.fr/hal-03694719/document)
    - [CERBERE: Cybersecurity Exercise for Red and Blue Team Entertainment, Reproducibility](https://centralesupelec.hal.science/hal-04285565/file/CERBERE_final.pdf)
  - **Universidad de la República**:
    - [A Process Mining-Based Method for Attacker Profiling Using the MITRE ATT&CK Taxonomy](https://journals-sol.sbc.org.br/index.php/jisa/article/view/3902/2840)

---

## License

- All the **code** of the project is licensed under the [GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html).
- `evtx_dump` is under the MIT license.
- The rules are released under the [Detection Rule License (DRL) 1.0](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md).

---
