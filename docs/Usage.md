# Usage

:information_source: if you use the packaged version of Zircolite don't forget to replace `python3 zircolite.py` in the examples by the packaged binary name.

## Requirements and Installation

You can install dependencies with : `pip3 install -r requirements.txt`

The use of [evtx_dump](https://github.com/omerbenamram/evtx) is **optional but required by default (because it is for now much faster)**, I you do not want to use it you have to use the '--noexternal' option. The tool is provided if you clone the Zircolite repository (the official repository is [here](https://github.com/omerbenamram/evtx)).

#### Known issues

Sometimes `evtx_dump` hangs under MS Windows, this is not related to Zircolite. If it happens to you, usually the use of `--noexternal` solves the problem.

If you can share the EVTX files on whose the blocking happened, feel free to post an issue in the [evtx_dump](https://github.com/omerbenamram/evtx/issues) repository.

## Basic usage 

Help is available with `zircolite.py -h`. 

### For EVTX files

If your evtx files have the extension ".evtx" :

```shell
python3 zircolite.py --evtx <EVTX_FOLDER> --ruleset <Converted Sigma rules>
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json
```

It also works directly on an unique EVTX file.

:information_source: `--evtx`, `--events` and `-e` are equivalent

By default

- `--ruleset` is not mandatory but the default ruleset will be `rules/rules_windows_generic.json`
- Results are written in the `detected_events.json` in the same directory as Zircolite
- There is a `zircolite.log`file that will be created in the current working directory
- `Zircolite` will automatically choose a file extension, you can change it with `--fileext`. This option can be used with wildcards or [Python Glob syntax](https://docs.python.org/3/library/glob.html) but with `*.` added before the given parameter value : `*.<FILEEXT PARAMETER VALUE>`. For example `--fileext log` will search for `*.log` files in the given path and `--fileext log.*` will search for `*.log.*` which can be useful when handling linux log files (auditd.log.1...).

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
	--ruleset rules/rules_windows_sysmon_full.json --xml
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

:information_source: `--events` and `--evtx` are strictly equivalent but `--events` make more sense with non EVTX logs.

### Sysmon for Linux logs

Sysmon for linux has been released in October 2021. It outputs XML in text format with one event per-line. As of version 2.6.0, **Zircolite** support of Sysmon for Linux log files. You just have to add `-S`, `--sysmon4linux`, `--sysmon-linux`, `--sysmon-linux-input` to your command line : 

```shell
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json --sysmon-linux
```

:information_source: Since the logs come from Linux, the default file extension when using `-S` case is `.log`

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

## Field mappings, field exclusions, value exclusions, field aliases and field splitting

Sometimes your logs need some transformations to allow your rules to match against them. Zircolite has multiple mechanisms for this. The configuration of these mechanisms is provided by a file that can be found in the [config](../config/) directory of the repository. It is also possible to provide your own configuration woth the `--config` or `-c` options.

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

**field mappings** allow you to rename a field from your raw logs (the ones that you want to analyze with Zircolite). Zircolite already uses this mechanism to rename nested JSON fields. You can check all the builtin field mappings [here](https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json).

For example, if you want to rename the field "CommandLine" in **your raw logs** to "cmdline", you can add the following in the [here](https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json) file : 

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
	"SHA1": "F43D9BB316E30AE1A3494AC5B0624F6BEA1BF054",
	"MD5": "04029E121A0CFA5991749937DD22A1D9",
	"SHA256": "9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F",
	"IMPHASH": "7C955A0ABC747F57CCC4324480737EF7",
	"Hashes": "SHA1=F43D9BB316E30AE1A3494AC5B0624F6BEA1BF054,MD5=04029E121A0CFA5991749937DD22A1D9,SHA256=9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F,IMPHASH=7C955A0ABC747F57CCC4324480737EF7",
	"EventID": 1
}
```

## Generate your own rulesets

Default rulesets are already provided in the `rules` directory. These rulesets only are the conversion of the rules located in [rules/windows](https://github.com/SigmaHQ/sigma/tree/master/rules/windows) directory of the Sigma repository. These rulesets are provided to use Zircolite out-of-the-box but [you should generate your own rulesets](#why-you-should-build-your-own-rulesets).

**As of v2.9.5, Zircolite can auto-update its default rulesets using the `-U` or `--update-rules`. There is an auto-updated rulesets repository available [here](https://github.com/wagga40/Zircolite-Rules).**

### With sigmatools

Zircolite use the SIGMA rules in JSON format. Since the SQLite backend is not yet available in pySigma, you need to generate your ruleset with  the official [legacy-sigmatools](https://github.com/SigmaHQ/legacy-sigmatools) (**version 0.21 minimum**) : 

```shell 
pip3 install sigmatools
```

since you need to access the configuration files directly it is easier to also clone the repository :  
```shell 
git clone https://github.com/SigmaHQ/legacy-sigmatools.git
cd legacy-sigmools
```

#### Sysmon rulesets (when investigated endpoints have Sysmon logs)

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

#### Generic rulesets (when investigated endpoints _don't_ have Sysmon logs)

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

*Removed*.
You can use DFIR Orc to package Zircolite, check [here](Advanced.md#using-with-dfir-orc).

## Docker

Zircolite is also packaged as a Docker image (cf. [wagga40/zircolite](https://hub.docker.com/r/wagga40/zircolite) on Docker Hub), which embeds all dependencies (e.g. `evtx_dump`) and provides a platform-independant way of using the tool.

### Build and run your own image

```shell
docker build . -t <Image name>
docker container run --tty --volume <EVTX folder>:/case <Image name> \
	--ruleset rules/rules_windows_sysmon.json \
	--evtx /case \
	--outfile /case/detected_events.json
```

This will recursively find EVTX files in the `/case` directory of the container (which is bound to the `/path/to/evtx` of the host filesystem) and write the detection events to the `/case/detected_events.json` (which finally corresponds to `/path/to/evtx/detected_events.json`).

Event if Zircolite does not alter the original EVTX files, sometimes you want to make sure that nothing will write to the original files. For these cases, you can use a read-only bind mount with the following command:

```shell
docker run --rm --tty -v <EVTX folder>:/case/input:ro -v <Results folder>:/case/output \
	<Zircolite Image name> 
	--ruleset rules/rules_windows_sysmon.json \
	--evtx /case/input -o /case/output/detected_events.json
```

### Docker Hub

You can use the Docker image available on [Docker Hub](https://hub.docker.com/r/wagga40/zircolite). Please note that in this case, the configuration files and rules are the default ones.

```shell
docker container run --tty \
	--volume <EVTX folder>:/case docker.io/wagga40/zircolite:lastest \
	--ruleset rules/rules_windows_sysmon.json \
	--evtx /case --outfile /case/detected_events.json
```
