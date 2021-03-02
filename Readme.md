# Zircolite

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)
![version](https://img.shields.io/badge/Architecture-64bit-red)

**Zircolite is a standalone tool written in Python 3 allowing to use SIGMA rules on Windows EVTX logs.**

## Requirements 

`Zircolite.py` do not need external Python libraries but it needs some external tools :

* [Evtx_dump](https://github.com/omerbenamram/evtx)

These tools must be placed in the `bin` directory and be named according to the following array : 

| Tool             | Windows             | MacOS          | Linux           |
|------------------|---------------------|----------------|-----------------|
| evtx_dump        | evtx\_dump\_win.exe | evtx\_dump\_mac| evtx\_dump\_lin | 

## Quick start

### Basic

If your evtx files have the extension ".evtx" : 

```
python3 zircolite.py --evtx <EVTX folder> --ruleset <Converted Sigma rules>
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_medium_sysmon.json
```

Other arguments are described when using : `zircolite.py -h`. Relevant **optional** arguments are : 

- `--config [configuration file]` : JSON File containing field mappings and exclusions
- `--fileext` : Allows to customize the evtx file extension (some tools like to change the extension)

:warning: Zircolite is putting a lot of data in memory, if you want to use it with a lot of logs please check the "Advanced" section.

### Advanced

`Zircolite_mp.py` is a tool that leverage multiples cores to launch multiples Zircolite instances to speed up the analysis. It is pretty much like `GNU Parallel`. All cores can be used, be it is better to leave one or two cores alone for other things.

```
# 1 core "--monore" or "--core 1"
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_medium_generic.json --monocore
# All cores "--core all" (default)
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_medium_generic.json --core all
# 4 cores
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_medium_generic.json --core 4

```

#### Benchmarks

On an Intel Core-i9 8c/16t - 64 Go RAM : 

|                            | Monocore | Multicore  |
|----------------------------|----------|------------|
| EVTX : 34 Go - 16 folders  | -        | 12 Min     |
| EVTX : 3,4 Go - 9 folders  | -        | 3 Min      |
| EVTX : 1,2 Go - 6 folders  | 11 Min   | 1 Min 30 s |
| EVTX : 40 Mo  - 2 folders  | 3 s      | 1 s        |

### Rules

The SIGMA rules must be converted into SQLite. This can be done with the `genRules.py` script located in the repository `tools` directory.

## Architecture

![](pics/Zircolite.png)

### Project structure

```text
├── Makefile                    # Only make clean works
├── Readme.md                   # The file you are reading  
├── bin                         # Directory containing all external binaries used in Zircolite
│   ├── evtx_dump_lin
│   ├── evtx_dump_mac
│   └── evtx_dump_win.exe
├── config                      # Directory containing the config files
│   └── fieldMappings.json      # File containing the field mappings and exclusions
├── pics                        # Pictures directory - not really relevant
│   └── Zircolite.png           
├── rules                       # Sample rules you can use
│   ├── rules_godmode.json      # The Florian Roth Godmode rule, fast and usefull
│   ├── rules_medium.json       # 551 rules from SIGMA/Rules official repository
│   └── rules_powershell.json   # Some powershell related rules
├── templates					# Jinja2 templates
│   ├── jsonl.tmpl		      	# JSONL template (Usefull for Splunk)
├── tools                       # Directory containing all external tools
│   ├── config
│   │   └── sysmon.yml          # Sysmon generic config file for Sigmac
│   └── genRules.py             # genRules allows to generate rules in JSON format
└── zircolite.py                # Zircolite !
```

## Installation

No installation needed. If you need to package it for standalone use on a computer use [PyInstaller](https://www.pyinstaller.org/)

### How to package Zircolite

* Install Python 3.8 on the same OS as the one you want to use zircolite on
* After Python 3.8 install, you will need PyInstaller : `pip3 install pyinstaller`
* In the root folder of Zircolite type : `pyinstaller -c --onefile zircolite.py`
* The `dist` folder will contain the packaged app 