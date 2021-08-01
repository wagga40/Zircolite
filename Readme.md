# <p align="center">![](pics/zircolite_400.png)</p>

## Battle-tested, standalone and fast SIGMA-based detection tool for EVTX or JSON

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)
![version](https://img.shields.io/badge/Architecture-64bit-red)
![](pics/Zircolite.gif)

**Zircolite is a standalone tool written in Python 3 allowing to use SIGMA rules on Windows event logs (in EVTX and JSON format)**

- **Zircolite** can be used directly on the investigated endpoint (use [releases](https://github.com/wagga40/Zircolite/releases)) or in your favorite forensic/detection lab
- **Zircolite** is fast and can parse large datasets in just seconds (check [benchmarks](docs/Internals.md#benchmarks))
- **Zircolite** can handle EVTX files and JSON files as long as they are in JSONL/NDJSON format (one JSON event per line)

**Zircolite can be used directly in Python or you can use the binaries provided in [releases](https://github.com/wagga40/Zircolite/releases) (Microsoft Windows and Linux  only).** 
**Documentation is [here](docs).**

:information_source: If you want to try the tool you can test with these samples : 

- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (EVTX Files)
- [MORDOR - APT29 Day 1](https://github.com/OTRF/mordor/blob/master/datasets/large/apt29/day1/apt29_evals_day1_manual.zip) (JSONL Files), [MORDOR - APT29 Day 2](https://github.com/OTRF/mordor/blob/master/datasets/large/apt29/day2/apt29_evals_day2_manual.zip) (JSONL Files)
- [MORDOR - APT3 Scenario 1](https://github.com/OTRF/mordor/blob/master/datasets/large/windows/apt3/caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz) (JSONL Files), [MORDOR - APT3 Scenario 2](https://github.com/OTRF/mordor/blob/master/datasets/large/windows/apt3/empire_apt3.tar.gz) (JSONL Files)

## Requirements

* **Mandatory** - [Evtx_dump](https://github.com/omerbenamram/evtx) : The tool is provided if you clone the repo. You can download also the tool directly on the official repository : [here](https://github.com/omerbenamram/evtx).
* **Optional** - To enhance Zircolite experience, you can use the following third party Python libraries : **tqdm**, **colorama**, **jinja2**. You can install them with : `pip3 install -r requirements.txt`

## Quick start

Help is available with `zircolite.py -h`. If your evtx files have the extension ".evtx" :

```shell
python3 zircolite.py --evtx <EVTX folder> --ruleset <Converted Sigma rules>
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json
```

For JSONL/NDJSON : 

```shell
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json --jsononly
```

## Docs

Everything is [here](docs).

## Mini-Gui

![](pics/gui.jpg)

The Mini-GUI can be used totaly offline, it allows the user to display and search results. To know how to use the Mini-GUI Check docs [here](docs).

## "Battle-tested" ?

Zircolite has been used to perform cold-analysis (in Lab) on EVTX in multiple "real-life" situations. 
However, even if Zircolite has been used many times to perform analysis directly on an Microsoft Windows endpoint, there is not yet a pipeline to thoroughly test every release.

## License

- All the **code** of the project is licensed under the [GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html)
- `evtx_dump` is under the MIT license
- The rules are released under the [Detection Rule License (DRL) 1.0](https://github.com/Neo23x0/sigma/blob/master/LICENSE.Detection.Rules.md)
