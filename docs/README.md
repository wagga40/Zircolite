# Zircolite Documentation

**Zircolite** is a standalone tool written in Python 3 that allows you to use SIGMA rules on:

- MS Windows EVTX (EVTX, XML, and JSONL formats)
- Auditd logs
- Sysmon for Linux
- EVTXtract
- CSV and XML logs
- JSON Array logs

### Key Features

- **Fast Processing**: Zircolite is relatively fast and can parse large datasets in just seconds. Memory usage statistics (peak and average) are displayed after each run.
- **Automatic Parallel Processing**: Intelligent parallel file processing enabled by default. Automatically calculates optimal worker count based on available RAM, CPU cores, and file sizes.
- **Smart Processing Mode**: Automatically analyzes your workload and selects the optimal database mode (unified vs. per-file) based on file count, sizes, and available system resources.
- **Streaming Mode**: Single-pass event processing (enabled by default) that combines extraction, flattening, and database insertion for 40-60% faster processing.
- **YAML Configuration**: Support for YAML configuration files for easier management of complex analysis workflows.
- **SIGMA Backend**: It is based on a SIGMA backend (SQLite) and does not use internal SIGMA-to-something conversion.
- **Native Sigma Support**: As of version 2.20.0, Zircolite can directly use native Sigma rules (YAML) by converting them with pySigma.
- **Advanced Log Manipulation**: It can manipulate input logs by splitting fields and applying transformations, allowing for more flexible and powerful log analysis.
- **Field Transforms**: Apply custom Python transformations to fields during processing (e.g., Base64 decoding, hex-to-ASCII conversion) using RestrictedPython for safe execution.
- **Flexible Export**: Zircolite can export results to multiple formats using Jinja [templates](templates), including JSON, CSV, JSONL, Splunk, Elastic, Zinc, Timesketch, and more.
- **Memory Efficient**: Each log file is processed separately in its own database by default to optimize memory usage.

**You can use Zircolite directly in Python or use the binaries provided in the [releases](https://github.com/wagga40/Zircolite/releases).**

### Documentation Contents

- [Usage](Usage.md) - Installation, basic usage, and input formats
- [Advanced](Advanced.md) - Working with large datasets, streaming mode, parallel processing, filtering, templating, and the Mini-GUI
- [Internals](Internals.md) - Architecture and project structure
