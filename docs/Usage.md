# Usage

> [!NOTE]  
> If you use the packaged version of Zircolite don't forget to replace `python3 zircolite.py` in the examples by the packaged binary name.

## Requirements and Installation

- [Release versions](https://github.com/wagga40/Zircolite/releases) are standalone, they are easier to use and deploy. Be careful, **the packager (nuitka) does not like Zircolite being run in from another directory**.
- If you have an **ARM CPU, it is strongly recommended to use the release versions**
- The repository version of Zircolite works with **Python 3.8** and above
- The repository version can run on Linux, Mac OS and Windows
- The use of [evtx_dump](https://github.com/omerbenamram/evtx) is **optional but required by default (because it is for now much faster)**, I you do not want to use it you have to use the '--noexternal' option. The tool is provided if you clone the Zircolite repository (the official repository is [here](https://github.com/omerbenamram/evtx)).

### Installation from releases

- Get the appropriate version [here](https://github.com/wagga40/Zircolite/releases)

```bash
# DECOMPRESS
7z x zircolite_lin_amd64_glibc_2.20.0.zip
cd zircolite_lin_amd64_glibc/

# EXAMPLE RUN
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
./zircolite_lin_amd64_glibc.bin -e EVTX-ATTACK-SAMPLES/Execution/ \
                                -r rules/rules_windows_sysmon_pysigma.json

```

### Installation from repository

#### Using [venv](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/) on Linux/MacOS

```shell
# INSTALL
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite 
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt

# EXAMPLE RUN
git clone https://github.com/sbousseaden/EVTX-ATTA^C-SAMPLES.git
python3 zircolite.py -e EVTX-ATTACK-SAMPLES/ -r rules/rules_windows_sysmon_pysigma.json
deactivate # Quit Python3 venv
```

#### Using [Pdm](https://pdm-project.org/latest/) or [Poetry](https://python-poetry.org)

```shell
# INSTALL
git clone https://github.com/wagga40/Zircolite.git
cd Zircolite 
pdm init -n
cat requirements.txt | xargs pdm add

# EXAMPLE RUN
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
pdm run python3 zircolite.py -e EVTX-ATTACK-SAMPLES/ \
    -r rules/rules_windows_sysmon_pysigma.json
```

If you want to use *poetry*, just replace the "pdm" command in the above example by "poetry".

### Known issues

- Sometimes `evtx_dump` hangs under MS Windows, this is not related to Zircolite. If it happens to you, usually the use of `--noexternal` solves the problem. If you can share the EVTX files on whose the blocking happened, feel free to post an issue in the [evtx_dump](https://github.com/omerbenamram/evtx/issues) repository.
- If you use the packaged/release version, please note that the packager (nuitka) does not like Zircolite being run in from another directory (i.e : `c:\SOMEDIR\Zircolite\Zircolite.exe -e sample.evtx -r rules.json`).


## Basic usage 

Help is available with `zircolite.py -h`. 

Basically, the simplest way to use Zircolite is something like this:

```shell
python3 zircolite.py --events <LOGS> --ruleset <RULESET>
```

Where : 

- `--events` is a filename or a directory containing the logs you want to analyse (`--evtx` and `-e` can be used instade of `--events`) . Zircolite support the following format : EVTX, XML, JSON (one event per line), JSON Array (one big array), EVTXTRACT, CSV, Auditd, Sysmon for Linux
- `--ruleset` is a file or directory containing the Sigma rules to use for detection. Zircolite as its own format called "Zircolite ruleset" where all the rules are in one JSON file. However, as of version *2.20.0*, Zircolite can directly use Sigma rules in YAML format (YAML file or Directory containing the YAML files)

Multiple rulesets can be specified, results can be per-ruleset or combined (with `--combine-rulesets` or `-cr`) : 

```shell
# Example with a Zircolite ruleset and a Sigma rule. Results will be displayed per-ruleset
python3 zircolite.py --events sample.evtx --ruleset rules/rules_windows_sysmon_pysigma.json \
    --ruleset schtasks.yml 
# Example with a Zircolite ruleset and a Sigma rule. Results will be displayed combined 
python3 zircolite.py --events sample.evtx --ruleset rules/rules_windows_sysmon_pysigma.json \
    --ruleset schtasks.yml --combine-rulesets 
```

By default : 

- `--ruleset` is not mandatory but the default ruleset is `rules/rules_windows_generic_pysigma.json`
- Results are written in the `detected_events.json` in the same directory as Zircolite, you can choose a CSV formatted output with `--csv`
- There is a `zircolite.log` file that will be created in the current working directory, it can be disabled with `--nolog`
-  When providing a directory for then event logs, `Zircolite` will automatically use a file extension, you can change it with `--fileext`. This option can be used with wildcards or [Python Glob syntax](https://docs.python.org/3/library/glob.html) but `*.` will automatically be added before the given parameter value : `*.<FILEEXT PARAMETER VALUE>`. For example `--fileext log` will search for `*.log` files in the given path and `--fileext log.*` will search for `*.log.*` which can be useful when handling linux log files (auditd.log.1...)

### EVTX files

If your evtx files have the extension ".evtx" :

```shell
python3 zircolite.py --evtx <EVTX_FOLDER/EVTX_FILE> \
    --ruleset <Converted Sigma ruleset (JSON)/Directory with Sigma rules (YAML)/>
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon_pysigma.json
```

### XML logs

`evtx_dump` or services like **VirusTotal** sometimes output logs in text format with XML logs inside. 

To do that with `evtx_dump` you have to use the following command line : 
```shell
./evtx_dump -o xml <EVTX_FILE> -f <OUTPUT_XML_FILE> --no-indent --dont-show-record-number
```

And it produces something like this (1 event per line): 

```xml
<?xml version="1.0" encoding="utf-8"?><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="XXXXXX"></Provider><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>XXXX</Keywords><TimeCreated SystemTime="XXXX-XX-XXTXX:XX:XX.XXXXXXZ"></TimeCreated><EventRecordID>XXXX</EventRecordID><Correlation></Correlation><Execution ProcessID="XXXXX" ThreadID="XXXXX"></Execution><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>XXXXXXX</Computer><Security UserID="XXXXX"></Security></System><EventData><Data Name="RuleName">XXXX</Data><Data Name="UtcTime">XXXX-XX-XX XX:XX:XX.XXX</Data><Data Name="ProcessGuid">XXXX</Data><Data Name="ProcessId">XXX</Data><Data Name="Image">XXXXXX</Data><Data Name="FileVersion">XXXX</Data><Data Name="Description">XXXXXXXX</Data><Data Name="Product">Microsoft® Windows® Operating System</Data><Data Name="Company">Microsoft Corporation</Data><Data Name="OriginalFileName">XXXX</Data><Data Name="CommandLine">XXXX</Data><Data Name="CurrentDirectory">XXXXXX</Data><Data Name="User">XXXXX</Data><Data Name="LogonGuid">XXXX</Data><Data Name="LogonId">XXXXX</Data><Data Name="TerminalSessionId">0</Data><Data Name="IntegrityLevel">High</Data><Data Name="Hashes">XXXX</Data><Data Name="ParentProcessGuid">XXXXXX</Data><Data Name="ParentProcessId">XXXXXXX</Data><Data Name="ParentImage">XXXXXX</Data><Data Name="ParentCommandLine">XXXXXX</Data><Data Name="ParentUser">XXXXXX</Data></EventData></Event>

```

**VirusTotal** : if you have an enterprise account will allow you to get logs in a pretty similar format : 

```xml
<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Guid="XXXXXXX" Name="Microsoft-Windows-Sysmon"/><EventID>13</EventID><Version>2</Version><Level>4</Level><Task>13</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="XXXX-XX-XXTXX:XX:XX.XXXXXXZ"/><EventRecordID>749827</EventRecordID><Correlation/><Execution ProcessID="2248" ThreadID="2748"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>XXXXXX</Computer><Security UserID="S-1-5-18"/></System><EventData><Data Name="RuleName">-</Data><Data Name="EventType">SetValue</Data><Data Name="UtcTime">XXXX-XX-XX XX:XX:XX.XXX</Data><Data Name="ProcessGuid">XXXXXXX</Data><Data Name="ProcessId">XXXXX</Data><Data Name="Image">C:\Windows\Explorer.EXE</Data><Data Name="TargetObject">XXXXXXXX</Data><Data Name="Details">Binary Data</Data></EventData></Event>
</Events>
```

**Zircolite** will handle both format with the following command line :

```shell
python3 zircolite.py --events <LOGS_FOLDER_OR_LOG_FILE>  --ruleset <RULESET> --xml
python3 zircolite.py --events  Microsoft-Windows-SysmonOperational.xml \
    --ruleset rules/rules_windows_sysmon_pysigma.json --xml
```

### EVTXtract logs

Willi Ballenthin has built called [EVTXtract](https://github.com/williballenthin/EVTXtract) a tool to recovers and reconstructs fragments of EVTX log files from raw binary data, including unallocated space and memory images.

**Zircolite** can work with the output of EVTXtract with the following command line :

```shell
python3 zircolite.py --events <EVTXTRACT_EXTRACTED_LOGS>  --ruleset <RULESET> --evtxtract
```

### Auditd logs

```shell
python3 zircolite.py --events auditd.log --ruleset rules/rules_linux.json --auditd
```

> [!NOTE]  
> `--events` and `--evtx` are strictly equivalent but `--events` make more sense with non-EVTX logs.

### Sysmon for Linux logs

Sysmon for linux has been released in October 2021. It outputs XML in text format with one event per-line. As of version 2.6.0, **Zircolite** support of Sysmon for Linux log files. You just have to add `-S`, `--sysmon4linux`, `--sysmon-linux`, `--sysmon-linux-input` to your command line : 

```shell
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json --sysmon-linux
```

> [!NOTE]  
> Since the logs come from Linux, the default file extension when using `-S` case is `.log`

### JSONL/NDJSON logs

JSONL/NDJSON logs have one event log per line, they look like this : 

```json
{"EventID": "4688", "EventRecordID": "1", ...}
{"EventID": "4688", "EventRecordID": "2", ...}
...
```

It is possible to use Zircolite directly on JSONL/NDJSON files (NXLog files) with the `-j`, `--jsonl`, `--jsononly` or `--json-input` options : 

```shell
python3 zircolite.py --events <LOGS_FOLDER> --ruleset <RULESET> --jsonl
```

A simple use case is when you have already run Zircolite and use the `--keeptmp` option. Since it keeps all the converted EVTX in a temp directory, if you need to re-execute Zircolite, you can do it directly using this directory as the EVTX source (with `--evtx <EVTX_IN_JSON_DIRECTORY>` and `--jsononly`) and avoid to convert the EVTX again.

### JSON Array / Full JSON object

Some logs will be provided in JSON format as an array : 

```json
[ 
    {"EventID": "4688", "EventRecordID": "1", ...}, 
    {"EventID": "4688", "EventRecordID": "2", ...}, 
... ]
```

To handle these logs you will need to use the `--jsonarray`, `--json-array` or `--json-array-input` options :

```shell
python3 zircolite.py --events <LOGS_FOLDER> --ruleset <RULESET> --json-array-input
```

### CSV

It is possible to use Zircolite directly on CSV logs **if the CSV are correctly formatted**. The field names must appear on the first line : 

```csv
EventID,EventRecordID,Computer,SubjectUserSid,...
4624,32421,xxxx.DOMAIN.local,S-1-5-18,xxxx,DOMAIN,...
...
```

To handle these logs you will need to use the `--csv-input` options (**Do not use `--csv`** !):

```shell
python3 zircolite.py --events <LOGS_FOLDER> --ruleset <RULESET> --csv-input
```

### SQLite database files

Since everything in Zircolite is stored in a in-memory SQlite database, you can choose to save the database on disk for later use. It is possible with the option `--dbfile <db_filename>`.

```shell
python3 zircolite.py --evtx <EVTX_FOLDER> --ruleset <CONVERTED_SIGMA_RULES> \
    --dbfile output.db
```

If you need to re-execute Zircolite,  you can do it directly using the SQLite database as the EVTX source (with `--evtx <SAVED_SQLITE_DB_PATH>` and `--dbonly`) and avoid to convert the EVTX, post-process the EVTX and insert data to database. **Using this technique can save a lot of time... But you will be unable to use the `--forwardall`option** 

## Rulesets / Rules

Zircolite has his own rulesets format (JSON). Default rulesets are available in the [rules](https://github.com/wagga40/Zircolite/tree/master/rules/) directory or in the [Zircolite-Rules](https://github.com/wagga40/Zircolite-Rules) repository.

Since version 2.20.0, Zircolite can directly use native Sigma rules by converting them with [pySigma](https://github.com/SigmaHQ/pySigma). Zircolite will detect whether the provided rules are in JSON or YAML format and will automatically convert the rules in the latter case : 

```bash
# Simple rule
python3 zircolite.py -e sample.evtx -r schtasks.yml

# Directory
python3 zircolite.py -e sample.evtx -r ./sigma/rules/windows/process_creation

```
### Using multiple rules/rulesets

It is possible to use multiple rulesets by chaining or repeating with the `-r`or `--ruleset` arguments : 

```bash
# Simple rule
python3 zircolite.py -e sample.evtx -r schtasks.yml -r ./sigma/rules/windows/process_creation

```

By default, the detection results are displayed by ruleset, it is possible to group the results with `-cr` or `--combine-rulesets`. In this case only one list will be displayed.

## Pipelines 

By default, Zircolite does not use any pySigma pipelines, which can be somewhat limiting. However, it is possible to use the default pySigma pipelines. 

### Install and list pipelines

However, they must be installed before check [pySigma docs](https://github.com/SigmaHQ) for that, but it is generaly as simple as : 

- `pip3 install pysigma-pipeline-nameofpipeline`
- `poetry add pysigma-pipeline-nameofpipeline`

Installed pipelines can be listed with : 

- `python3 zircolite_dev.py -pl`
- `python3 zircolite_dev.py --pipeline-list`

### Use pipelines

To use pipelines, employ the -p or --pipelines arguments; multiple pipelines are supported. The usage closely mirrors that of **Sigma-cli**.

Example : 

```bash
python3 zircolite.py -e sample.evtx -r schtasks.yml -p sysmon -p windows-logsources
```

The converted rules/rulesets can be saved by using the `-sr` or the `--save-ruleset` arguments.

> [!NOTE]  
> When using multiple native Sigma rule/rulesets, you cannot differenciate pipelines. All the pipelines will be used in the conversion process.

## Field mappings, field exclusions, value exclusions, field aliases and field splitting

If your logs require transformations to align with your rules, Zircolite offers several mechanisms for this purpose. You can configure these mechanisms using a file located in the [config](https://github.com/wagga40/Zircolite/tree/master/config/) directory of the repository. Additionally, you have the option to use your own configuration by utilizing the `--config` or `-c` options.

The configuration file has the following structure : 

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
    }
}
```

### Field mappings

**Field mappings** enable you to rename a field from your logs. Zircolite leverages this mechanism extensively to rename nested JSON fields. You can view all the built-in field mappings [here](https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json).

For instance, to rename the "CommandLine" field in **your raw logs** to "cmdline", you can add the following entry to the [fieldMappings.json](https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json) file:

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

Please keep in mind that as opposed to field alias, the original field name is not kept.

### Field exclusions

**field exclusions** allow you to exclude a field. Zircolite already uses this mechanism to exclude the `xlmns` field. You can check all the builtin field exclusions [here](https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json).

### Value exclusions

**value exclusions** allow you to remove field which value is to be excluded. Zircolite already uses this mechanism to remove *null* and empty values. You can check all the builtin value exclusions [here](https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json).

### Field aliases

**field aliases** allow you to have multiple fields with different name but the same value. It is pretty similar to field mapping but you keep the original value. Field aliases can be used on original field names but also on mapped field names and splitted fields.

Let's say you have this event log in JSON format (the event has been deliberately truncated): 

```json 
{
    "EventID": 1,
    "Provider_Name": "Microsoft-Windows-Sysmon",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "IntegrityLevel": "Medium",
}
```

Let's say you are not sure all your rules use the "CommandLine" field but you remember that some of them use the "cmdline" field. To avoid any problems you could use an alias for the "CommandLine" field like this : 

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

With this configuration, the event log used to apply Sigma rules will look like this : 

```json 
{
    "EventID": 1,
    "Provider_Name": "Microsoft-Windows-Sysmon",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
    "cmdline": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "IntegrityLevel": "Medium",
}
```

Be careful when using aliases because the data is stored multiple times.

### Field splitting

**field aliases** allow you to split fields that contain key,value pairs.  Zircolite already uses this mechanism to handle hash/hashes fields in Sysmon logs. You can check all the builtin field splittings [here](https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json). Moreover, Field aliases can be applied to splitted fields.

For example, let's say we have this Sysmon event log : 

```json
{
    "Hashes": "SHA1=XX,MD5=X,SHA256=XXX,IMPHASH=XXXX",
    "EventID": 1
}
```

With the following configuration, Zircolite will split the `hashes` field like this : 

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

The final event log used to apply Sigma rules will look like this : 

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

By using transforms, you can preprocess event data to make it more suitable for detection rules and analysis.

### Enabling Transforms

Transforms are configured in the config file (the default one is in `config/fieldMappings.json`) under the `"transforms"` section. To enable transforms, set the `"transforms_enabled"` flag to `true` in your configuration file:

```json
{
  "transforms_enabled": true,
  "transforms": {
    // Transform definitions
  }
}
```

### Configuring Transforms

Transforms are defined in the `"transforms"` section of the configuration file. Each transform is associated with a specific field and consists of several properties.

### Transform Structure

A transform definition has the following structure:

- **Field Name**: The name of the field to which the transform applies.
- **Transform List**: A list of transform objects for the field.

Each transform object contains:

- **info**: A description of what the transform does.
- **type**: The type of the transform (currently only `"python"` is supported).
- **code**: The Python code that performs the transformation.
- **alias**: A boolean indicating whether the result should be stored in a new field.
- **alias_name**: The name of the new field if `alias` is `true`.
- **source_condition**: A list specifying when the transform should be applied based on the input type (e.g., `["evtx_input", "json_input"]`).
- **enabled**: A boolean indicating whether the transform is active.

#### Source conditions possible values
    
| Sets `source_condition` Value |
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

#### Example Transform Object

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

### Available Fields

You can define transforms for any field present in your event data. In the configuration, transforms are keyed by the field name:

```json
"transforms": {
  "CommandLine": [
    {
      // Transform object
    }
  ],
  "Payload": [
    {
      // Transform object
    }
  ]
}
```

---

### Writing Transform Functions

Zircolite uses `RestrictedPython` to safely execute transform functions. This means that certain built-in functions and modules are available, while others are restricted.
The function must be named `transform` and accept a single parameter `param`, which is the original value of the field.

**Available Modules and Functions:**

- **Built-in Functions**: A limited set of Python built-in functions, such as `len`, `int`, `str`, etc.
- **Modules**: You can import `re` for regular expressions, `base64` for encoding/decoding, and `chardet` for character encoding detection.

**Unavailable Features:**

- Access to file I/O, network, or system calls is prohibited.
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

### Example

**Use Case**: Convert hexadecimal-encoded command lines in Auditd logs to readable ASCII strings.

**Configuration:**

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

**Explanation:**

- **Field**: `proctitle`
- **Function**: Converts hexadecimal strings to ASCII and replaces null bytes with spaces.
- **Alias**: `false` (the original `proctitle` field is replaced).

### Best Practices

- **Test Your Transforms**: Before enabling a transform, ensure that the code works correctly with sample data.
- **Use Aliases Wisely**: If you don't want to overwrite the original field, set `"alias": true` and provide an `"alias_name"`.
- **Manage Performance**: Complex transforms can impact performance. Optimize your code and only enable necessary transforms.
- **Keep Transforms Specific**: Tailor transforms to specific fields and input types using `"source_condition"` to avoid unexpected behavior.

## Generate your own rulesets

Default rulesets are already provided in the `rules` directory. These rulesets only are the conversion of the rules located in [rules/windows](https://github.com/SigmaHQ/sigma/tree/master/rules/windows) directory of the Sigma repository. These rulesets are provided to use Zircolite out-of-the-box but [you should generate your own rulesets](#why-you-should-build-your-own-rulesets).

**As of v2.9.5, Zircolite can auto-update its default rulesets using the `-U` or `--update-rules`. There is an auto-updated rulesets repository available [here](https://github.com/wagga40/Zircolite-Rules).**

### Generate rulesets using PySigma

#### Using [Pdm](https://pdm-project.org/latest/) or [Poetry](https://python-poetry.org)

```shell
# INSTALL
git clone https://github.com/SigmaHQ/sigma.git
cd sigma
pdm init -n
pdm add pysigma pip sigma-cli pysigma-pipeline-sysmon pysigma-pipeline-windows pysigma-backend-sqlite

# GENERATE RULESET (SYSMON)
pdm run sigma convert -t sqlite -f zircolite -p sysmon -p windows-logsources sigma/rules/windows/ -s -o rules.json
# GENERATE RULESET (GENERIC / NO SYSMON)
pdm run sigma convert -t sqlite -f zircolite -p windows-audit -p windows-logsources sigma/rules/windows/ -s -o rules.json

```

In the last line : 

- `-t` is the backend type (SQlite) 
- `-f` is the format, here "zircolite" means the ruleset will be generated in the format used by Zircolite
- `-p` option is the pipeline used, in the given example we use two pipelines
- `-s` to continue on error (e.g when there are not supported rules)
- `-o` allow to specify the output file

If you want to use *poetry*, just replace the "pdm" command in the above example by "poetry".

### Generate rulesets using sigmatools [**DEPRECATED**]

[**DEPRECATED**] Zircolite use the SIGMA rules in JSON format. Since the SQLite backend is not yet available in pySigma, you need to generate your ruleset with the official [legacy-sigmatools](https://github.com/SigmaHQ/legacy-sigmatools) (**version 0.21 minimum**) : 

```shell 
pip3 install sigmatools
```

[**DEPRECATED**] since you need to access the configuration files directly it is easier to also clone the repository :  

```shell 
git clone https://github.com/SigmaHQ/legacy-sigmatools.git
cd legacy-sigmatools
```

#### [**DEPRECATED**] Sysmon rulesets (when investigated endpoints have Sysmon logs) 

```shell 
sigmac \
    -t sqlite \
    -c tools/config/generic/sysmon.yml \
    -c tools/config/generic/powershell.yml \
    -c tools/config/zircolite.yml \
    -d rules/windows/ \
   --output-fields title,id,description,author,tags,level,falsepositives,filename,status \
   --output-format json \
   -r \
   -o rules_sysmon.json \
   --backend-option table=logs
```

Where : 

- `-t` is the backend type (SQlite) 
- `-c` options are the backend configurations from the official repository
- `-r` option is used to convert an entire directory (don't forget to remove if it is a single rule conversion)
- `-o` option is used to provide the output filename 
-  `--backend-option` is used to specify the SQLite table name (leave as is)

#### [**DEPRECATED**] Generic rulesets (when investigated endpoints _don't_ have Sysmon logs) [**DEPRECATED**]

```shell 
sigmac \
    -t sqlite \
    -c tools/config/generic/windows-audit.yml \
    -c tools/config/generic/powershell.yml \
    -c tools/config/zircolite.yml \
    -d rules/windows/ \
   --output-fields title,id,description,author,tags,level,falsepositives,filename,status \
   --output-format json \
   -r \
   -o rules_generic.json \
   --backend-option table=logs
```

### Why you should build your own rulesets

The default rulesets provided are the conversion of the rules located in `rules/windows` directory of the Sigma repository. You should take into account that : 

- **Some rules are very noisy or produce a lot of false positives** depending on your environment or the config file you used with genRules
- **Some rules can be very slow** depending on your logs

For example : 

-  "Suspicious Eventlog Clear or Configuration Using Wevtutil" : **very noisy** on fresh environment (labs etc.), commonly generate a lot of useless detections
-  Notepad Making Network Connection : **can slow very significantly** the execution of Zircolite

## Generate embedded versions

***Removed***

- You can use DFIR Orc to package Zircolite, check [here](Advanced.md#using-with-dfir-orc)
- [Kape](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) also has a module for Zircolite : [here](https://github.com/EricZimmerman/KapeFiles/tree/master/Modules/Apps/GitHub)

## Docker

Zircolite is also packaged as a Docker image (cf. [wagga40/zircolite](https://hub.docker.com/r/wagga40/zircolite) on Docker Hub), which embeds all dependencies (e.g. `evtx_dump`) and provides a platform-independant way of using the tool. Please note this image is not updated with the last rulesets !

You can pull the last image with : `docker pull wagga40/zircolite:latest`

### Build and run your own image

```shell
docker build . -t <Image name>
docker container run --tty \
    --volume <Logs folder>:/case
    wagga40/zircolite:latest \
    --ruleset rules/rules_windows_sysmon_pysigma.json \
    --events /case \
    --outfile /case/detected_events.json
```

This will recursively find log files in the `/case` directory of the container (which is bound to the `/path/to/evtx` of the host filesystem) and write the detection events to the `/case/detected_events.json` (which finally corresponds to `/path/to/evtx/detected_events.json`). The given example uses the internal rulesets, if you want to use your own, place them in the same directory as the logs : 

```shell
docker container run --tty \
    --volume <Logs folder>:/case
    wagga40/zircolite:latest \
    --ruleset /case/my_ruleset.json \
    --events /case/my_logs.evtx \
    --outfile /case/detected_events.json
```

Event if Zircolite does not alter the original log files, sometimes you want to make sure that nothing will write to the original files. For these cases, you can use a read-only bind mount with the following command:

```shell
docker run --rm --tty \
    -v <EVTX folder>:/case/input:ro \
    -v <Results folder>:/case/output \
    wagga40/zircolite:latest \
    --ruleset rules/rules_windows_sysmon_pysigma.json \
    --events /case/input \
    -o /case/output/detected_events.json
```

### Docker Hub

You can use the Docker image available on [Docker Hub](https://hub.docker.com/r/wagga40/zircolite). Please note that in this case, the configuration files and rules are the default ones.

```shell
docker container run --tty \
    --volume <EVTX folder>:/case docker.io/wagga40/zircolite:lastest \
    --ruleset rules/rules_windows_sysmon_pysigma.json \
    --evtx /case --outfile /case/detected_events.json
```
