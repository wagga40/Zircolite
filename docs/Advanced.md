# Zircolite documentation

## Advanced use

* [Working with large datasets](#working-with-large-datasets)
	* [Using GNU Parallel](#file-filters)
	* [Time filters](#time-filters)
* [Filtering](#filtering)
	* [File filters](#file-filters)
	* [Time filters](#time-filters)
	* [Rule filters](#rule-filters)
* [Forwarding detected events](#forwarding-detected-events) 
* [Templating and Formatting](#templating-and-formatting)
* [Mini GUI](#mini-gui)

Zircolite has a lot of command line arguments, you can list them with the `-h` argument.

---

### Working with large datasets

Zircolite tries to be as fast as possible so a lot of data is stored in memory. So : 

- **Zircolite memory use oscillate between 2 or 3 times the size of the logs**
- It is not a good idea to use it on very big EVTX files or a large number of EVTX **as is**

The tool has been created to be used on very big datasets and there are a lot of ways to speed up Zircolite :

- Using as much CPU core as possible : see below "[Using GNU Parallel](using-gnu-parallel)"
- Using [Filtering](#filtering)

#### Using GNU Parallel 

Except when `evtx_dump` is used, Zircolite only use one core. So if you have a lot of EVTX files and their total size is big, it is recommanded that you use a script to launch multiple Zircolite instances. On Linux or MacOS The easiest way is to use **GNU Parallel**. 

:information_source: on MacOS, please use GNU find (`brew install find` will install `gfind`)

- **"DFIR Case mode" : One directory per computer/endpoint**

	This mode is very useful when you have a case where all your evidences is stored per computer (one directory per computer containing all EVTX for this computer). It will create one result file per computer in the current directory.

	```shell
	find <CASE_DIRECTORY> -maxdepth 1 -mindepth 1 -type d | \
		parallel --bar python3 zircolite.py --evtx {} 
		--ruleset rules/rules_windows_sysmon.json --outfile {/.}.json
	```
	
	One downside of this mode is that if you have less computer evidences than CPU Cores, they all will not be used.

- **"WEF/WEC mode" : One zircolite instance per EVTX**

	You can use this mode when you have a lot of aggregated EVTX coming from multiple computers. It is generaly the case when you use WEF/WEC and you recover the EVTX files from the collector. This mode will create one result file per EVTX.

	```shell
	find <CASE_DIRECTORY> -type f -name "*.| \
		parallel -j -1 --progress python3 zircolite.py --evtx {} \
		--ruleset rules/rules_windows_sysmon.json --outfile {/.}.json
	```
	
	In this example the `-j -1` is for using all cores but one. You can adjust the number of used cores with this arguments.

#### Using Zircolite MP (*deprecated*)

If you don't have find and/or GNU Parallel, you can use the **very basic** `Zircolite_mp.py` available in the [tools](tools/) directory of this repository.

---

### Filtering

Zircolite has a lot of filtering options to speed up the detection process. Don't overlook these options because they can save you a lot of time.

#### File filters

Some EVTX files are not used by SIGMA rules but can become quite large (a good example is `Microsoft-Windows-SystemDataArchiver%4Diagnostic.evtx`), if you use Zircolite with a directory as input argument, all EVTX files will be converted, saved and matched against the SIGMA Rules. 

To speed up the detection process, you may want to use Zircolite on files matching or not matching a specific pattern. For that you can use **filters** provided by the two command line arguments :

- `-s` or `--select` : select files partly matching the provided a string (case insensitive)
- `-a` or `--avoid` : exclude files partly matching the provided a string (case insensitive)

:information_source: When using te two arguments, the "select" argument is always applied first and then the "avoid" argument is applied. So, it is possible to exclude files from included files but not the opposite.

- Only use EVTX files that contains "sysmon" in their names

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json --select sysmon
	```
- Exclude "Microsoft-Windows-SystemDataArchiver%4Diagnostic.evtx" 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
		--avoid systemdataarchiver
	```

- Only use EVTX files with "operational" in their names but exclude "defender" related logs
	
	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
	--select operational --avoid defender
	```

For example, the **Sysmon** ruleset available in the `rules` directory only use the following channels (names have been shortened) : *Sysmon, Security, System, Powershell, Defender, AppLocker, DriverFrameworks, Application, NTLM, DNS, MSexchange, WMI-activity, TaskScheduler*. 

So if you use the sysmon ruleset with the following rules, it should speed up `Zircolite`execution : 

```shell
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \
	--select sysmon --select security.evtx --select system.evtx \
	--select application.evtx --select Windows-NTLM --select DNS \
	--select powershell --select defender --select applocker \
	--select driverframeworks --select "msexchange management" \
	--select TaskScheduler --select WMI-activity
```

#### Time filters

Sometimes you only want to work on a specific timerange to speed up analysis. With Zircolite, it is possible to filter on a specific timerange just by using the `--after` and `--before` and their respective shorter versions `-A` and `-B`. Please note that : 

-  The filter will apply on the `SystemTime` field of each event
-  The `--after` and `--before` arguments can be used independently
-  The timestamps provided must have the following format : YYYY-MM-DD**T**HH:MM:SS (hours are in 24h format)

Examples : 

- Select all events between the 2021-06-02 22:40:00 and 2021-06-02 23:00:00 : 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \ 
		-A 2021-06-02T22:40:00 -B 2021-06-02T23:00:00
	```

- Select all events after the 2021-06-01 12:00:00 : 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json \ 
		-A 2021-06-01T12:00:00
	```

#### Rule filters

Some rules can be noisy or slow on specific datasets (check [here](rules/Readme.md)) so it is possible to skip them by using the `-R` or `--rulefilter` argument. This argument can be used multiple times.

The filter will apply on the rule title. Since there is a CRC32 in the rule title it is easier to use it. For example, to skip execution of the rule "Suspicious Eventlog Clear or Configuration Using Wevtutil - BFFA7F72" : 

```shell
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json -R BFFA7F72
```

You can also specify a string, to avoid unexpected side-effect **comparison is case-sensitive**. For example, if you do not want to use all MSHTA related rules and skip the execution of the rule "Suspicious Eventlog Clear or Configuration Using Wevtutil - BFFA7F72": 

```shell
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon.json -R BFFA7F72 -R MSHTA
```
---

### Forwarding detected events 

Zircolite provide 2 ways to forward events to a collector : 

- the HTTP forwarder : this is a very simple forwarder and pretty much a "toy" example and should be used when you have nothing else. An **example** server called is available in the [tools](tools/) directory
- the Splunk HEC Forwarder : it allows to forward all detected events to a Splunk instance using **HTTP Event Collector**.

For now, the forwarders are not asynchronous so it can slow Zircolite execution. There are two modes to forward the events : 

- By default all events are forwarded after the detection process
- The argument `--stream` allow to forward events during the detection process

If you forward your events to a central collector you can disable local logging with the Zircolite `--nolog` argument.

#### Forward to a HTTP server

If you have multiple endpoints to scan, it is usefull to send the detected events to a central collector. As of v1.2, Zircolite can forward detected events to an HTTP server :

```shell
python3 zircolite.py --evtx sample.evtx  --ruleset rules/rules_windows_sysmon.json \
	--remote http://address:port/uri
```
An **example** server called is available in the [tools](tools/) directory.

#### Forward to a Splunk instance via HEC

As of v1.3.5, Zircolite can forward detections to a Splunk instance with Splunk **HTTP Event Collector**.

1. Configure HEC on you Splunk instance : [check here](https://docs.splunk.com/Documentation/Splunk/8.2.0/Data/UsetheHTTPEventCollector)
2. Get your token and you are ready to go : 

```shell
python3 zircolite.py --evtx /sample.evtx  --ruleset rules/rules_windows_sysmon.json \
	--remote https://x.x.x.x:8088 --token xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```
---

### Templating and Formatting

Zircolite provides a templating system based on Jinja 2. It allows you to change the output format to suits your needs (Splunk or ELK integration, Grep-able output...). There are some templates available in the [Templates directory](../templates) of the repository : CSV, Splunk, Mini-GUI. To use the template system, use these arguments :

- `--template <template_filename>`
- `--templateOutput <output_filename>`

```shell
python3 zircolite.py --evtx sample.evtx  --ruleset rules/rules_windows_sysmon.json \
--template templates/exportCSV.tmpl --templateOutput test.csv
```

It is possible to use multiple templates if you provide for each `--template` argument there is a `--templateOutput` argument associated.

---

### Mini-GUI

![](../pics/gui.jpg)

The Mini-GUI can be used totaly offline, it allows the user to display and search results. It uses [datatables](https://datatables.net/) and the [SB Admin 2 theme](https://github.com/StartBootstrap/startbootstrap-sb-admin-2). To use it you just need to generate a `data.js` file with the `exportForZircoGui.tmpl` template and move it to the [gui](gui/) directory :

```shell
python3 zircolite.py --evtx sample.evtx 
	--ruleset rules/rules_windows_sysmon.json \ 
	--template templates/exportForZircoGui.tmpl --templateOutput data.js
mv data.js gui/
```

Then you just have to open `index.html` in your favorite browser and click on a Mitre Att&ck category or an alert level.
  
:warning: **The mini-GUI was not built to handle big datasets**.

---

### Packaging Zircolite 

#### PyInstaller

* Install Python 3.8 on the same OS as the one you want to use Zircolite on
* Install all dependencies : `pip3 install -r requirements.txt`
* After Python 3.8 install, you will need PyInstaller : `pip3 install pyinstaller`
* In the root folder of Zircolite type : `pyinstaller -c --onefile zircolite.py`
* The `dist` folder will contain the packaged app

#### Nuitka

* Install Python 3.8 on the same OS as the one you want to use Zircolite on
* Install all dependencies : `pip3 install -r requirements.txt`
* 

:warning: When packaging with PyInstaller some AV may not like your package.