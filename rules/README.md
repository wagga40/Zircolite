# Rulesets

## Default rulesets

These rulesets have been generated with `sigmac` wich is available in the [official sigma repository](https://github.com/SigmaHQ/sigma).

:warning: **These rulesets are given "as is" to help new analysts to discover SIGMA and Zircolite. They are not filtered for slow rules, rules with a lot of false positives etc. If you know what you do, you SHOULD generate your own rulesets.**

- `rules_windows_generic_full.json` : Full SIGMA ruleset from the "**Windows**" directory of the official repository (no SYSMON rewriting)
- `rules_windows_generic_high.json` : Only level high and above SIGMA rules from the "**Windows**" directory of the official repository (no SYSMON rewriting)
- `rules_windows_generic_medium.json` : Only level medium and above SIGMA rules from the "**Windows**" directory of the official repository (no SYSMON rewriting)
- `rules_windows_generic.json` : Same file as `rules_windows_generic_high.json`
- `rules_windows_sysmon_full.json` : Full SIGMA ruleset from the "**Windows**" directory of the official repository  (SYSMON)
- `rules_windows_sysmon_high.json` : Only level high and above SIGMA rules from the "**Windows**" directory of the official repository (SYSMON)
- `rules_windows_sysmon_medium.json` : Only level medium and above SIGMA rules from the "**Windows**" directory of the official repository (SYSMON)
- `rules_windows_sysmon.json` : Same file as `rules_windows_sysmon_high.json`
- `rules_linux.json`: Full SIGMA ruleset from the "**linux**" directory of the official repository. This ruleset can be used with Auditd and Sysmon for Linux logs.

**As of v2.9.5, Zircolite can auto-update its default rulesets using the `-U` or `--update-rules`. There is an auto-updated rulesets repository available [here](https://github.com/wagga40/Zircolite-Rules).**

## Why you should make your own rulesets

The default rulesets provided are the conversion of the rules located in `rules/windows` directory of the Sigma repository. You should take into account that : 

- **Some rules are very noisy or produce a lot of false positives** depending on your environment or the config file you used with genRules
- **Some rules can be very slow** depending on your logs

To generate you own ruleset please check the docs [here](https://github.com/wagga40/Zircolite/tree/master/docs).

For example : 

-  "Suspicious Eventlog Clear or Configuration Using Wevtutil" : **very noisy** on fresh environment (labs etc.), commonly generate a lot of useless detection
-  "Notepad Making Network Connection" : **can slow very significantly** the execution of Zircolite
-  "Rundll32 Internet Connection" : can be **very noisy** in some situations
-  "Wuauclt Network Connection" : **can slow very significantly** the execution of Zircolite
- "PowerShell Network Connections : **can slow very significantly** the execution of Zircolite