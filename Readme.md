# <p align="center">![](pics/zircolite_400.png)</p>

## Standalone and fast SIGMA-based detection tool for EVTX or JSON Logs 
![](pics/Zircolite.gif)

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)
![version](https://img.shields.io/badge/Architecture-64bit-red)

**Zircolite is a standalone tool written in Python 3. It allows to use SIGMA rules on MS Windows EVTX (EVTX and JSON format)**

- **Zircolite** can be used directly on the investigated endpoint (use [releases](https://github.com/wagga40/Zircolite/releases)) or in your forensic/detection lab
- **Zircolite** is fast and can parse large datasets in just seconds (check [benchmarks](docs/Internals.md#benchmarks))
- **Zircolite** can handle EVTX files and JSON files as long as they are in JSONL/NDJSON format

**Zircolite can be used directly in Python or you can use the binaries provided in [releases](https://github.com/wagga40/Zircolite/releases) (Microsoft Windows and Linux  only).** 
**Documentation is [here](docs).**

If you like it you can buy me a coffee : 
[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/wagga40)

## Requirements / Installation

You can install dependencies with : `pip3 install -r requirements.txt`

The use of [evtx_dump](https://github.com/omerbenamram/evtx) is **optional but required by default (because it is for now much faster)**, If you do not want to use it you have to use the `--noexternal` option. The tool is provided if you clone the Zircolite repository (the official repository is [here](https://github.com/omerbenamram/evtx)).

## Quick start

#### For EVTX files : 

Help is available with `zircolite.py -h`. If your EVTX files have the extension ".evtx" :

```shell
python3 zircolite.py --evtx <EVTX_FOLDER/EVTX_FILE> --ruleset <Converted Sigma rules>
python3 zircolite.py --evtx sysmon.evtx --ruleset rules/rules_windows_sysmon.json
```
The SYSMON ruleset used here is a default one and it is for logs coming from endpoints where SYSMON installed. A generic ruleset is available too.

#### For JSONL/NDJSON files : 

```shell
python3 zircolite.py --evtx <JSON_FOLDER/JSON_FILE> --ruleset rules/rules_windows_sysmon.json --jsononly
```

:information_source: If you want to try the tool you can test with these samples : 

- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (EVTX Files)
- [MORDOR - APT29](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29) (JSONL Files)
- [MORDOR - APT3](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/windows/apt3) (JSONL Files)

## Docs

Everything is [here](docs).

## Tutorials, references and related projects

### Tutorial

[Russ McRee](https://holisticinfosec.io) has published a pretty good [tutorial](https://holisticinfosec.io/post/2021-09-28-zircolite/) on SIGMA and **Zircolite** in his [blog](https://holisticinfosec.io/post/2021-09-28-zircolite/).

### EU ATT&CK Workshop October 2021

[Florian Roth](https://github.com/Neo23x0/) cited **Zircolite** in his [**SIGMA Hall of fame**](https://github.com/Neo23x0/Talks/blob/master/Sigma_Hall_of_Fame_20211022.pdf) in its talk dugin the October 2021 EU ATT&CK Workshop.

### Related projects

[Michel de CREVOISIER](https://github.com/mdecrevoisier) is doing an amazing work with SIGMA, MITRE Att&ck (c) and other projects. Check [his work on mapping EVTX on the MITRE Att&ck (c) framework](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack).

## Mini-Gui

![](pics/gui.jpg)

The Mini-GUI can be used totally offline, it allows the user to display and search results. To know how to use the Mini-GUI, check docs [here](docs).

## Battle-tested

Zircolite has been used to perform cold-analysis (in Lab) on EVTX in multiple "real-life" situations. 
However, even if Zircolite has been used many times to perform analysis directly on a Microsoft Windows endpoint, there is not yet a pipeline to thoroughly test every release.

## License

- All the **code** of the project is licensed under the [GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html)
- `evtx_dump` is under the MIT license
- The rules are released under the [Detection Rule License (DRL) 1.0](https://github.com/Neo23x0/sigma/blob/master/LICENSE.Detection.Rules.md)
