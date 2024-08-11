# <p align="center">![](pics/zircolite_400.png)</p>

## Standalone SIGMA-based detection tool for EVTX, Auditd, Sysmon for linux, XML or JSONL/NDJSON Logs
![](pics/Zircolite_v2.9.gif)

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Architecture-64bit-red)

> **Zircolite is a standalone tool written in Python 3. It allows to use SIGMA rules on : MS Windows EVTX (EVTX, XML and JSONL format), Auditd logs, Sysmon for Linux, EVTXtract, CSV and XML logs**

- **Zircolite** is relatively fast and can parse large datasets in just seconds
- **Zircolite** is based on a Sigma backend (SQLite) and do not use internal sigma to "something" conversion
- **Zircolite** can export results to multiple format with using Jinja [templates](templates) : JSON, CSV, JSONL, Splunk, Elastic, Zinc, Timesketch...

**Zircolite can be used directly in Python or you can use the binaries provided in [releases](https://github.com/wagga40/Zircolite/releases).**

**Documentation is [here](https://wagga40.github.io/Zircolite/) (dedicated site) or [here](docs) (repo directory).**

## Requirements / Installation

Python 3.8 minimum is required. If you only want to use base functionalities of Zircolite, you can install dependencies with : `pip3 install -r requirements.txt`. But `pip3 install -r requirements.full.txt` is strongly recommended.

The use of [evtx_dump](https://github.com/omerbenamram/evtx) is **optional but required by default (because it is -for now- much faster)**, If you do not want to use it you have to use the `--noexternal` option. The tool is provided if you clone the Zircolite repository (the official repository is [here](https://github.com/omerbenamram/evtx)).

:warning: On some systems (Mac, Arm, ...) the `evtx` library may need Rust and Cargo to be installed.

## Quick start

Check tutorials made by other (EN, SP and FR) [here](#tutorials).

### EVTX files

Help is available with `zircolite.py -h`. If your EVTX files have the extension ".evtx" :

```shell
# python3 zircolite.py --evtx <EVTX FOLDER or EVTX FILE> --ruleset <SIGMA RULESET> [--ruleset <OTHER RULESET>]
python3 zircolite.py --evtx sysmon.evtx --ruleset rules/rules_windows_sysmon_pysigma.json
```

The SYSMON ruleset employed is a default one, intended for analyzing logs from endpoints with SYSMON installed.

### Auditd / Sysmon for Linux / JSONL or NDJSON logs

```shell
python3 zircolite.py --events auditd.log --ruleset rules/rules_linux.json --auditd
python3 zircolite.py --events sysmon.log --ruleset rules/rules_linux.json --sysmon4linux
python3 zircolite.py --events <JSON_FOLDER or JSON_FILE> --ruleset rules/rules_windows_sysmon_pysigma.json --jsononly
```

:information_source: If you want to try the tool you can test with [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (EVTX Files).

### Run with Docker

```bash
# Pull docker image
docker pull wagga40/zircolite:latest
# If your logs and rules are in a specific directory
docker run --rm --tty \
    -v $PWD:/case/input:ro \
    -v $PWD:/case/output \
    wagga40/zircolite:latest \
    -e /case/input \
    -o /case/output/detected_events.json \
    -r /case/input/a_sigma_rule.yml
```

You can replace `$PWD` with the directory (absolute path only) where your logs and rules/rulesets are stored.

### Updating default rulesets

```shell
python3 zircolite.py -U
```

:information_source: Please note these rulesets are provided to use Zircolite out-of-the-box but [you should generate your own rulesets](#why-you-should-build-your-own-rulesets) but they can be very noisy or slow. These auto-updated rulesets are available on the dedicated repository : [Zircolite-Rules](https://github.com/wagga40/Zircolite-Rules).

## Docs

Everything is [here](docs).

## Mini-Gui

The Mini-GUI can be used totally offline, it allows the user to display and search results. You can automatically generate a Mini-Gui "package" with the `--package` option. To know how to use the Mini-GUI, check docs [here](docs/Advanced.md#mini-gui).

### Detected events by Mitre Att&ck (c) techniques and criticality levels

![](pics/gui.webp)

### Detected events Timeline

![](pics/gui-timeline.webp)

### Detected events by Mitre Att&ck (c) techniques displayed on the Matrix

![](pics/gui-matrix.webp)

## Tutorials, references and related projects

### Tutorials

- (EN) [Russ McRee](https://holisticinfosec.io) has published a pretty good [tutorial](https://holisticinfosec.io/post/2021-09-28-zircolite/) on SIGMA and **Zircolite** in his [blog](https://holisticinfosec.io/post/2021-09-28-zircolite/)

- (SP) **César Marín** has published a tutorial in **spanish** [here](https://derechodelared.com/zircolite-ejecucion-de-reglas-sigma-en-ficheros-evtx/)

- (FR) [IT-connect.fr](https://www.it-connect.fr/) has published [a very extensive tutorial](https://www.it-connect.fr/) in **French** on Zircolite

### References

- [Florian Roth](https://github.com/Neo23x0/) cited **Zircolite** in his [**SIGMA Hall of fame**](https://github.com/Neo23x0/Talks/blob/master/Sigma_Hall_of_Fame_20211022.pdf) in its talk during the October 2021 EU ATT&CK Workshop in October 2021
- Zircolite has been cited and used in the research work of the CIDRE team : [PWNJUSTSU - Website](https://pwnjutsu.irisa.fr) and [PWNJUSTSU - Academic paper](https://hal.inria.fr/hal-03694719/document)
- Zircolite has been cited and presented during [JSAC 2023](https://jsac.jpcert.or.jp/archive/2023/pdf/JSAC2023_workshop_sigma_jp.pdf)

## License

- All the **code** of the project is licensed under the [GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html)
- `evtx_dump` is under the MIT license
- The rules are released under the [Detection Rule License (DRL)](https://github.com/SigmaHQ/Detection-Rule-License)
