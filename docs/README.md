# Zircolite Documentation

**Zircolite** is a standalone tool written in Python 3 that allows you to use SIGMA rules on:

- MS Windows EVTX (EVTX, XML, and JSONL formats)
- Auditd logs
- Sysmon for Linux
- EVTXtract
- CSV and XML logs
- JSON Array logs

### Key Features

- **Multiple Input Formats**: Supports EVTX, JSON Lines, JSON Arrays, CSV, XML, Auditd, and Sysmon for Linux logs.
- **Parallel Processing**: Automatic parallel file processing. Worker count is calculated based on available RAM, CPU cores, and file sizes.
- **Streaming Mode**: Single-pass event processing (enabled by default) that combines extraction, flattening, and database insertion.
- **YAML Configuration**: Support for YAML configuration files for complex analysis workflows.
- **SIGMA Backend**: Based on a SQLite backend for SIGMA rules.
- **Native Sigma Support**: Directly use native Sigma rules (YAML) via pySigma conversion.
- **Field Transforms**: Apply Python transformations to fields during processing (e.g., Base64 decoding, IOC extraction) using RestrictedPython.
- **Field Splitting**: Extract key-value pairs from fields (e.g., split Sysmon `Hashes` field into `MD5`, `SHA256` fields).
- **Flexible Export**: Export results to JSON, CSV, Splunk, Elastic, Zinc, Timesketch, and more using Jinja templates.

**You can use Zircolite directly in Python or use the binaries provided in the [releases](https://github.com/wagga40/Zircolite/releases).**

### Documentation Contents

- [Usage](Usage.md) - Installation, basic usage, and input formats
- [Advanced](Advanced.md) - Working with large datasets, streaming mode, parallel processing, filtering, templating, and the Mini-GUI
- [Internals](Internals.md) - Architecture and project structure
