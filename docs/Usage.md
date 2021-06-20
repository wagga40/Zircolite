# Zircolite documentation

## Usage

* [Requirements](#requirements)
	* [Mandatory](#mandatory)
	* [Optional](#optional)
* [Basic usage](#basic-usage)
* [Generate your own rulesets](#generate-your-own-rulesets)
	* [Why you should make your own rulesets](#why-you-should-make-your-own-rulesets)
* [Docker](#docker)
	* [Build and run your own image](#build-and-run-your-own-image)
	* [Docker Hub](#docker-Hub)

:information_source: if you use the packaged version of Zircolite don't forget to replace `python3 zircolite.py` in the examples by the packaged binary name.

--

### Requirements

#### Mandatory

* [Evtx_dump](https://github.com/omerbenamram/evtx) : The tool is provided if you clone the repo. You can download also the tool directly on the official repository : [here](https://github.com/omerbenamram/evtx). In order to use it with Zircolite you must put it in the [bin](bin/) directory and name it accordingly to the following array :

    | OS               | Windows             | MacOS          | Linux           |
    |------------------|---------------------|----------------|-----------------|
    | Tool name        | evtx\_dump\_win.exe | evtx\_dump\_mac| evtx\_dump\_lin |

#### Optional

- To enhance Zircolite experience with progress bars and colors, you can use the following third party Python libraries : **tqdm**, **colorama**, **jinja2**. You can install them with : `pip3 install -r requirements.txt`

:warning: Since there are packaged releases, the ability to run Zircolite without third party Python libraries will be removed soon.

- Build tools : **Git** and **Make** can be useful.

--

### Basic usage 

Help is available with `zircolite.py -h`. If your evtx files have the extension ".evtx" :

```shell
python3 zircolite.py --evtx <EVTX folder> --ruleset <Converted Sigma rules>
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json
```

It is possible to use Zircolite directly on JSONL/NDJSON files (NXLog files) with the `--jsononly` or `-j` arguments : 

```shell
python3 zircolite.py --evtx <EVTX folder> --ruleset <Converted Sigma rules> --jsononly
```

By default : 

- Results are written in the `detected_events.json` in the same directory as Zircolite
- There is a `zircolite.log`file that will be created in the current working directory

--

### Generate your own rulesets

The SIGMA rules must be converted into JSON. This can be done with the `genRules.py` script located in the repository [tools](../tools/genRules) directory. Default rulesets are already provided in the `rules` directory. These rulesets only are the conversion of the rules located in [rules/windows](https://github.com/SigmaHQ/sigma/tree/master/rules/windows) directory of the Sigma repository.

#### Why you should make your own rulesets

The default rulesets provided are the conversion of the rules located in `rules/windows` directory of the Sigma repository. You should take into account that : 

- **Some rules are very noisy or produce a lot of false positives** depending on your environnement or the config file you used with genRules
- **Some rules can be very slow** depending on your logs

For example : 

-  "Suspicious Eventlog Clear or Configuration Using Wevtutil" : **very noisy** on fresh environnement (labs etc.), commonly generate a lot of useless detection
-  Notepad Making Network Connection : **can slow very significantly** the execution of Zircolite

--

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
