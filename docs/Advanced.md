# Advanced use

## Working with large datasets

Zircolite tries to be as fast as possible so a lot of data is stored in memory. So : 

- **Zircolite memory use oscillate between 2 or 3 times the size of the logs**
- It is not a good idea to use it on very big EVTX files or a large number of EVTX **as is**

There are a lot of ways to speed up Zircolite :

- Using as much CPU core as possible : see below "[Using GNU Parallel](using-gnu-parallel)"
- Using [Filtering](#filtering)

> [!NOTE]  
> There is an option to heavily limit the memory usage of Zircolite by using the `--ondiskdb <DB_NAME>` argument. This is only usefull to avoid errors when dealing with very large datasets and if you have have a lot of time... **This should be used with caution and the below alternatives are far better choices**.

### Using GNU Parallel 

Except when `evtx_dump` is used, Zircolite only use one core. So if you have a lot of EVTX files and their total size is big, it is recommended that you use a script to launch multiple Zircolite instances. On Linux or MacOS The easiest way is to use **GNU Parallel**. 

> [!NOTE]  
> On MacOS, please use GNU find (`brew install find` will install `gfind`)

- **"DFIR Case mode" : One directory per computer/endpoint**

	This mode is very useful when you have a case where all your evidences is stored per computer (one directory per computer containing all EVTX for this computer). It will create one result file per computer in the current directory.

	```shell
	find <CASE_DIRECTORY> -maxdepth 1 -mindepth 1 -type d | \
		parallel --bar python3 zircolite.py -e {} \
		-r rules/rules_windows_sysmon_pysigma.json --outfile {/.}.json
	```
	
	One downside of this mode is that if you have less computer evidences than CPU Cores, they all will not be used.

- **"WEF/WEC mode" : One zircolite instance per EVTX**

	You can use this mode when you have a lot of aggregated EVTX coming from multiple computers. It is generally the case when you use WEF/WEC and you recover the EVTX files from the collector. This mode will create one result file per EVTX.

	```shell
	find <CASE_DIRECTORY> -type f -name "*.evtx" \
		parallel -j -1 --progress python3 zircolite.py -e {} \
		-r rules/rules_windows_sysmon_pysigma.json --outfile {/.}.json
	```
	
	In this example the `-j -1` is for using all cores but one. You can adjust the number of used cores with this arguments.

## Keep data used by Zircolite

**Zircolite** has a lot of arguments that can be used to keep data used to perform Sigma detections : 

- `--dbfile <FILE>` allows you to export all the logs in a SQLite 3 database file. You can query the logs with SQL statements to find more things than what the Sigma rules could have found
- `--keeptmp` allows you to keep the source logs (EVTX/Auditd/Evtxtract/XML...) converted in JSON format
- `--keepflat` allow you to keep the source logs (EVTX/Auditd/Evtxtract/XML...) converted in a flattened JSON format

## Filtering

Zircolite has a lot of filtering options to speed up the detection process. Don't overlook these options because they can save you a lot of time.

### File filters

Some EVTX files are not used by SIGMA rules but can become quite large (a good example is `Microsoft-Windows-SystemDataArchiver%4Diagnostic.evtx`), if you use Zircolite with a directory as input argument, all EVTX files will be converted, saved and matched against the SIGMA Rules. 

To speed up the detection process, you may want to use Zircolite on files matching or not matching a specific pattern. For that you can use **filters** provided by the two command line arguments :

- `-s` or `--select` : select files partly matching the provided a string (case insensitive)
- `-a` or `--avoid` : exclude files partly matching the provided a string (case insensitive)

> [!NOTE]  
> When using the two arguments, the "select" argument is always applied first and then the "avoid" argument is applied. So, it is possible to exclude files from included files but not the opposite.

- Only use EVTX files that contains "sysmon" in their names

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
		--select sysmon
	```
- Exclude "Microsoft-Windows-SystemDataArchiver%4Diagnostic.evtx" 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
		--avoid systemdataarchiver
	```

- Only use EVTX files with "operational" in their names but exclude "defender" related logs
	
	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
	--select operational --avoid defender
	```

For example, the **Sysmon** ruleset available in the `rules` directory only use the following channels (names have been shortened) : *Sysmon, Security, System, Powershell, Defender, AppLocker, DriverFrameworks, Application, NTLM, DNS, MSexchange, WMI-activity, TaskScheduler*. 

So if you use the sysmon ruleset with the following rules, it should speed up `Zircolite`execution : 

```shell
python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
	--select sysmon --select security.evtx --select system.evtx \
	--select application.evtx --select Windows-NTLM --select DNS \
	--select powershell --select defender --select applocker \
	--select driverframeworks --select "msexchange management" \
	--select TaskScheduler --select WMI-activity
```

### Time filters

Sometimes you only want to work on a specific timerange to speed up analysis. With Zircolite, it is possible to filter on a specific timerange just by using the `--after` and `--before` and their respective shorter versions `-A` and `-B`. Please note that : 

-  The filter will apply on the `SystemTime` field of each event
-  The `--after` and `--before` arguments can be used independently
-  The timestamps provided must have the following format : YYYY-MM-DD**T**HH:MM:SS (hours are in 24h format)

Examples : 

- Select all events between the 2021-06-02 22:40:00 and 2021-06-02 23:00:00 : 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
		-A 2021-06-02T22:40:00 -B 2021-06-02T23:00:00
	```

- Select all events after the 2021-06-01 12:00:00 : 

	```shell
	python3 zircolite.py --evtx logs/ --ruleset rules/rules_windows_sysmon_pysigma.json \
		-A 2021-06-01T12:00:00
	```

### Rule filters

Some rules can be noisy or slow on specific datasets (check [here](https://github.com/wagga40/Zircolite/tree/master/rules/README.md)) so it is possible to skip them by using the `-R` or `--rulefilter` argument. This argument can be used multiple times.

The filter will apply on the rule title. To avoid unexpected side-effect **comparison is case-sensitive**. For example, if you do not want to use all MSHTA related rules : 

```shell
python3 zircolite.py --evtx logs/ \
	--ruleset rules/rules_windows_sysmon_pysigma.json \
	-R MSHTA
```

### Limit the number of detected events

Sometimes, SIGMA rules can be very noisy (and generate a lot of false positives) but you still want to keep them in your rulesets. It is possible to filter rules that returns too mich detected events with the option `--limit <MAX_NUMBER>`. **Please note that when using this option, the rules are not skipped the results are just ignored** but this is useful when forwarding events to Splunk.

## Templating and Formatting

Zircolite provides a templating system based on Jinja 2. It allows you to change the output format to suits your needs (Splunk or ELK integration, Grep-able output...). There are some templates available in the [Templates directory](https://github.com/wagga40/Zircolite/tree/master/templates) of the repository : Splunk, Timesketch, ... To use the template system, use these arguments :

- `--template <template_filename>`
- `--templateOutput <output_filename>`

```shell
python3 zircolite.py --evtx sample.evtx  --ruleset rules/rules_windows_sysmon_pysigma.json \
--template templates/exportForSplunk.tmpl --templateOutput exportForSplunk.json
```

It is possible to use multiple templates if you provide for each `--template` argument there is a `--templateOutput` argument associated.

## Mini-GUI

![](pics/gui.jpg)


The Mini-GUI can be used totally offline, it allows the user to display and search results. It uses [datatables](https://datatables.net/) and the [SB Admin 2 theme](https://github.com/StartBootstrap/startbootstrap-sb-admin-2). 

### Automatic generation

As of Zircolite 2.1.0, the easier way to use the Mini-GUI is to generate a package with the `--package` option. A zip file containing all the necessary data will be generated at the root of the repository.  

### Manual generation

You need to generate a `data.js` file with the `exportForZircoGui.tmpl` template, decompress the zircogui.zip file in the [gui](https://github.com/wagga40/Zircolite/tree/master/gui/) directory and replace the `data.js` file in it with yours :

```shell
python3 zircolite.py --evtx sample.evtx 
	--ruleset rules/rules_windows_sysmon_pysigma.json \
	--template templates/exportForZircoGui.tmpl --templateOutput data.js
7z x gui/zircogui.zip
mv data.js zircogui/
```

Then you just have to open `index.html` in your favorite browser and click on a Mitre Att&ck category or an alert level.
  
> [!WARNING]  
> **The mini-GUI was not built to handle big datasets**.

## Packaging Zircolite 

### PyInstaller

* Install Python 3.8 on the same OS as the one you want to use Zircolite on
* Install all dependencies : `pip3 install -r requirements.txt`
* After Python 3.8 install, you will need PyInstaller : `pip3 install pyinstaller`
* In the root folder of Zircolite type : `pyinstaller -c --onefile zircolite.py`
* The `dist` folder will contain the packaged app

### Nuitka

* Install Python 3.8 on the same OS as the one you want to use Zircolite on
* Install all dependencies : `pip3 install -r requirements.txt`
* After Python 3.8 install, you will need Nuitka : `pip3 install nuitka`
* In the root folder of Zircolite type : `python3 -m nuitka --onefile zircolite.py`

> [!WARNING]  
> When packaging with PyInstaller or Nuitka some AV may not like your package.

## Other tools 

Some other tools (mostly untested) have included a way to run Zircolite : 

- [Kape](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) has a module for Zircolite : [here](https://github.com/EricZimmerman/KapeFiles/tree/master/Modules/Apps/GitHub)
- [Velociraptor](https://github.com/Velocidex/velociraptor) has an artifact for Zircolite : [here](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.zircolite/)
