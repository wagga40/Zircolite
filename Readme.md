# Zircolite
## Battle-tested, standalone and fast SIGMA-based detection tool for EVTX or JSON

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)
![version](https://img.shields.io/badge/Architecture-64bit-red)

### CLI

![](pics/Zircolite.gif)

**Zircolite is a standalone tool written in Python 3 allowing to use SIGMA rules on Windows EVTX logs :**

- It can be used directly on an endpoint (pseudo live-forensics) or in your forensic/detection workstation
- Zircolite was designed to be light (less than 500 lines of code), simple and portable
- Zircolite is more a workflow than a real detection engine ([check here](#architecture))

If you use `zircolite.py` with evtx files as input **you can only execute it on a 64 bits OS** (`evtx_dump` is 64 bits only).
Zircolite can be used directly in Python or you can use the binaries provided in release (Microsoft Windows only).

:information_source: If you want to try the tool you can test with these EVTX files : [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).

## Requirements

### Mandatory

* [Evtx_dump](https://github.com/omerbenamram/evtx) : The tool is provided if you clone the repo. You can download also the tool directly on the official repository : [here](https://github.com/omerbenamram/evtx). In order to use it with Zircolite you must put it in the [bin](bin/) directory and name it accordingly to the following array :

    | Tool             | Windows             | MacOS          | Linux           |
    |------------------|---------------------|----------------|-----------------|
    | evtx_dump        | evtx\_dump\_win.exe | evtx\_dump\_mac| evtx\_dump\_lin |

### Optional

To enhance Zircolite experience, you can use the following third party Python libraries : **tqdm**, **colorama**, **jinja2**. You can install them with : `pip3 install -r requirements.txt`

## Quick start

Help is available with `zircolite.py -h`. If your evtx files have the extension ".evtx" :

```shell
python3 zircolite.py --evtx <EVTX folder> --ruleset <Converted Sigma rules>
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json
```

## Advanced use

### Templating

Zircolite provides a templating system based on Jinja 2. It allows you to change the output format to suits your needs (Splunk or ELK integration, Grep-able output...). To use the template system, use these arguments :

- `--template <template_filename>`
- `--templateOutput <output_filename>`

```shell
python3 zircolite.py --evtx sample.evtx  --ruleset rules/rules_windows_sysmon.json \
--template templates/exportCSV.tmpl --templateOutput test.csv
```

It is possible to use multiple templates if you provide as long as for each `--template` argument there is a `--templateOutput` argument associated.

### Mini-Gui

![](pics/gui.jpg)

The Mini-GUI can be used totaly offline, it allows the user to display and search results. It uses [datatables](https://datatables.net/) and the [SB Admin 2 theme](https://github.com/StartBootstrap/startbootstrap-sb-admin-2). To use it you just need to generate a `data.js` file with the `exportForZircoGui.tmpl` template and move it to the [gui](gui/) directory :

```shell
python3 zircolite.py --evtx sample.evtx 
	--ruleset rules/rules_windows_sysmon.json \ 
	--template templates/exportForZircoGui.tmpl --templateOutput data.js
mv data.js gui/
```

Then you just have to open `index.html` in your favorite browser and click on a Mitre Att&ck category or an alert level.
  
:warning: **The mini-GUI was not build to handle big datasets**.

### Forward SIGMA detected events

If you have multiple endpoints to scan, it is usefull to send the detected events to a central point. As of v1.2, Zircolite can forward detected events to an HTTP server :

```shell
python3 zircolite.py --evtx sample.evtx  --ruleset rules/rules_windows_sysmon.json \
	--remote http://address:port/uri
```

An **example** server called is available in the [tools](tools/) directory.

### Big EVTX files

Zircolite tries to be as fast as possible so a lot of data is stored in memory. So : 

- As of v1.0, there is no "slower" mode that use less memory. **Zircolite memory use oscillate between 2 or 3 times the size of the logs**
- It is not a good idea to use it on very big EVTX files or a large number of EVTX
- Except when `evtx_dump` is used, Zircolite only use one core. 

If you have a lot of EVTX files and their total size is big, it is recommanded that you use a script to launch multiple Zircolite instances. On Linux or macOS The easiest way is to use GNU Parallel : 

```shell
find ../Samples/EVTX-ATTACK-SAMPLES/  -type f -name "*.evtx" \
| parallel -j -1 --progress python3 zircolite.py --evtx {} \
--ruleset rules/rules_windows_sysmon.json --outfile {/.}.json
```

If you don't have find and/or GNU Parallel, you can use the **very basic** `Zircolite_mp.py` available in the [tools](tools/) directory of this repository.

### Benchmarks

On an Intel Core-i9 8c/16t - 64 GB RAM (**Updated 4th May 2021**):

|                            | Monocore | Multicore  |
|----------------------------|----------|------------|
| EVTX : 34 GB - 16 files    | -        | 9 Min      |
| EVTX : 7.8 GB - 4 files    | -        | 162 sec    |
| EVTX : 1.7 GB - One file   | 99 sec   |            |
| EVTX : 40 MB  - 263 files  | 3 sec    | 1 sec      |

### Rules

The SIGMA rules must be converted into JSON. This can be done with the `genRules.py` script located in the repository `tools` directory. Some rules are already provided in the rules directory.

## Architecture

**Zircolite is more a workflow than a real detection engine**. To put it simply, it leverages the ability of the sigma converter to output rules in SQLite format. Zircolite simply applies SQLite-converted rules to EVTX stored in an in-memory SQLite DB.

![](pics/Zircolite.png)

### Project structure

```text
├── Makefile                # Only make clean works
├── Readme.md               # The file you are reading
├── bin                     # Directory containing all external binaries used by Zircolite
├── config                  # Directory containing the config files
├── pics                    # Pictures directory - not really relevant
├── rules                   # Sample rules you can use
├── templates               # Jinja2 templates
├── tools                   # Directory containing all external tools
└── zircolite.py            # Zircolite !
```

## Installation

No installation needed. If you need to package it for standalone use on a computer use [PyInstaller](https://www.pyinstaller.org/) or [Nuitka](https://nuitka.net/).

### Zircolite with Docker

Zircolite is also packaged as a Docker image (cf. `wagga40/zircolite` on Docker Hub), which embeds all dependencies (e.g. `evtx_dump`) and provides a platform-independant way of using the tool.

Using Zircolite with Docker is as simple as:

```sh
docker container run --tty --volume /path/to/evtx:/case docker.io/wagga40/zircolite:1.1.4 \ 
	--ruleset rules/rules_windows_sysmon.json \
	--evtx /case --outfile /case/detected_events.json
```

This will recursively find EVTX files in the `/case` directory of the container (which is bound to the `/path/to/evtx` of the host filesystem) and write the detection events to the `/case/detected_events.json` (which finally corresponds to `/path/to/evtx/detected_events.json`).

Event if Zircolite does not alter the original EVTX files, sometimes you want to make sure that nothing will write to the original files. For these cases, you can use a read-only bind mount with the following command:

```sh
docker run --rm --tty -v /path/to/evtx:/case/input:ro -v /path/to/results:/case/output \
	docker.io/wagga40/zircolite:1.1.4 -r rules/rules_windows_sysmon.json \
	-e /case/input -o /case/output/detected_events.json
```

Since the Docker image mirrors Zircolite's repository, all options are also available in the image.

### Package Zircolite with PyInstaller

* Install Python 3.8 on the same OS as the one you want to use Zircolite on
* After Python 3.8 install, you will need PyInstaller : `pip3 install pyinstaller`
* In the root folder of Zircolite type : `pyinstaller -c --onefile zircolite.py`
* The `dist` folder will contain the packaged app

:warning: When packaging with PyInstaller some AV may not like your package.

## "Battle-tested" ?

Zircolite has been used to perform cold-analysis (in Lab) on EVTX in multiple "real-life" situations. 
However, even if Zircolite has been used many times to perform analysis directly on an Microsoft Windows endpoint there is not yet a pipeline to thoroughly test every release.

## License

- All the **code** of the project is licensed under the [GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html)
- `evtx_dump` is under the MIT license
- The rules are released under the [Detection Rule License (DRL) 1.0](https://github.com/Neo23x0/sigma/blob/master/LICENSE.Detection.Rules.md)
