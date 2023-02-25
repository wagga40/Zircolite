# Zircolite documentation

## Usage

* [Requirements and Installation](#requirements-and-installation)
* [Basic usage](#basic-usage)
* [Generate your own rulesets](#generate-your-own-rulesets)
	* [Why you should make your own rulesets](#why-you-should-make-your-own-rulesets)
* [Generate embedded versions](#generate-embedded-versions)
* [Docker](#docker)
	* [Build and run your own image](#build-and-run-your-own-image)
	* [Docker Hub](#docker-Hub)

:information_source: if you use the packaged version of Zircolite don't forget to replace `python3 zircolite.py` in the examples by the packaged binary name.

---

### Requirements and Installation

You can install dependencies with : `pip3 install -r requirements.txt`

The use of [evtx_dump](https://github.com/omerbenamram/evtx) is **optional but required by default (because it is for now much faster)**, I you do not want to use it you have to use the '--noexternal' option. The tool is provided if you clone the Zircolite repository (the official repository is [here](https://github.com/omerbenamram/evtx)).

#### Known issues

Sometimes `evtx_dump` hangs under MS Windows, this is not related to Zircolite. If it happens to you, usually the use of `--noexternal` solves the problem.

If you can share the EVTX files on whose the blocking happened, feel free to post an issue in the [evtx_dump](https://github.com/omerbenamram/evtx/issues) repository.

---

### Basic usage 

Help is available with `zircolite.py -h`. 

#### For EVTX files : 

If your evtx files have the extension ".evtx" :

```shell
python3 zircolite.py --evtx <EVTX_FOLDER> --ruleset <Converted Sigma rules>
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json
```

It also works directly on an unique EVTX file.

By default : 

- `--ruleset` is not mandatory but the default ruleset will be `rules/rules_windows_generic.json`
- Results are written in the `detected_events.json` in the same directory as Zircolite
- There is a `zircolite.log`file that will be created in the current working directory

#### Auditd logs : 

```shell
python3 zircolite.py --events auditd.log --ruleset rules/rules_linux.json --auditd
```

:information_source: `--events` and `--evtx` are strictly equivalent but `--events` is more logical to use for non EVTX logs.

#### Sysmon for Linux logs : 

Sysmon for linux has been released in October 2021. It outputs XML in text format with one event per-line. As of version 2.6.0, **Zircolite** has an *initial* support of Sysmon for Linux log files. To test it, just add `-S` to you command line : 

```shell
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json --sysmon4linux
```

:information_source: Since the logs come from Linux, the default file extension when using `-S` case is `.log`

#### JSONL/NDJSON

It is possible to use Zircolite directly on JSONL/NDJSON files (NXLog files) with the `--jsononly` or `-j` arguments : 

```shell
python3 zircolite.py --events <EVTX_FOLDER> --ruleset <CONVERTED_SIGMA_RULES> --jsononly
```

A simple use case is when you have already run Zircolite and use the `--keeptmp` option. Since it keeps all the converted EVTX in a temp directory, if you need to re-execute Zircolite, you can do it directly using this directory as the EVTX source (with `--evtx <EVTX_IN_JSON_DIRECTORY>` and `--jsononly`) and avoid to convert the EVTX again.

:information_source: You can change the file extension with `--fileext`.

#### SQLite database files

Since everything in Zircolite is stored in a in-memory SQlite database, you can choose to save the database on disk for later use. It is possible with the option `--dbfile <db_filename>`.

```shell
python3 zircolite.py --evtx <EVTX_FOLDER> --ruleset <CONVERTED_SIGMA_RULES> --dbfile output.db
```

If you need to re-execute Zircolite,  you can do it directly using the SQLite database as the EVTX source (with `--evtx <SAVED_SQLITE_DB_PATH>` and `--dbonly`) and avoid to convert the EVTX, post-process the EVTX and insert data to database. **Using this technique can save a lot of time... But you will be unable to use the `--forwardall`option** 

---

### Generate your own rulesets

Default rulesets are already provided in the `rules` directory. These rulesets only are the conversion of the rules located in [rules/windows](https://github.com/SigmaHQ/sigma/tree/master/rules/windows) directory of the Sigma repository. These rulesets are provided to use Zircolite out-of-the-box but [you should generate your own rulesets](#why-you-should-build-your-own-rulesets).

**As of v2.9.5, Zircolite can auto-update its default rulesets using the `-U` or `--update-rules`. There is an auto-updated rulesets repository available [here](https://github.com/wagga40/Zircolite-Rules).**

#### With sigmatools

Zircolite use the SIGMA rules in JSON format. To generate your ruleset you need the official sigmatools (**version 0.21 minimum**) : 

```shell 
git clone https://github.com/SigmaHQ/sigma.git
cd sigma
```
**You must have the sigma dependencies installed, check [here](https://github.com/SigmaHQ/sigma#installation) :**

##### Sysmon rulesets (when investigated endpoints have Sysmon logs)

```shell 
tools/sigmac \
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

##### Generic rulesets (when investigated endpoints _don't_ have Sysmon logs)

```shell 
tools/sigmac \
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

#### Why you should build your own rulesets

The default rulesets provided are the conversion of the rules located in `rules/windows` directory of the Sigma repository. You should take into account that : 

- **Some rules are very noisy or produce a lot of false positives** depending on your environment or the config file you used with genRules
- **Some rules can be very slow** depending on your logs

For example : 

-  "Suspicious Eventlog Clear or Configuration Using Wevtutil" : **very noisy** on fresh environment (labs etc.), commonly generate a lot of useless detections
-  Notepad Making Network Connection : **can slow very significantly** the execution of Zircolite

---

### Generate embedded versions

*Removed*.
You can use DFIR Orc to package Zircolite, check [here](Advanced.md#using-with-dfir-orc).

---

### Docker

Zircolite is also packaged as a Docker image (cf. [wagga40/zircolite](https://hub.docker.com/r/wagga40/zircolite) on Docker Hub), which embeds all dependencies (e.g. `evtx_dump`) and provides a platform-independant way of using the tool.

#### Build and run your own image

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

#### Docker Hub

You can use the Docker image available on [Docker Hub](https://hub.docker.com/r/wagga40/zircolite). Please note that in this case, the configuration files and rules are the default ones.

```shell
docker container run --tty --volume <EVTX folder>:/case docker.io/wagga40/zircolite:1.4.0 \
	--ruleset rules/rules_windows_sysmon.json \
	--evtx /case --outfile /case/detected_events.json
```
