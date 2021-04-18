# Zircolite_MP

**Not really maintained, for use only if you cannot use GNU Parallel**

`zircolite_mp.py` is a **very basic** tool that leverages multiple cores to launch multiple Zircolite instances to speed up the analysis. It is pretty much like `GNU Parallel`. All cores can be used, but it is better to leave one or two cores unused. `zircolite_mp.py` needs data to be organised accordingly to the following directory tree :

```console
CASE
├── COMPUTER-DC-01
│   ├── *.evtx
├── COMPUTER-DC-02
│   ├── *.evtx
├── WORKSTATION_WIN10_01
│   ├── *.evtx
├── WORKSTATION_WIN10_02
│   ├── *.evtx
├── ...
```
To launch `zircolite_mp.py` :

```
# 1 core "--monore" or "--core 1"
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json --monocore
# All cores "--core all" (default)
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json --core all
# 4 cores
python3 zircolite.py --evtx ../Logs --ruleset rules/rules_windows_sysmon.json --core 4

```