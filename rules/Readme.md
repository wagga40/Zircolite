# Rulesets

## Default rulesets

These rulesets have been generated with `genRules.py` wich is available in the folder `tools` of the Zircolite repository.

:warning: **These rulesets are given "as is" to help new analysts to discover SIGMA and Zircolite. They are not filtered for slow rules, rules with a lot of false positives etc. If you know what you do, you SHOULD generate your own rulesets.**

- `rules_windows_generic.json` : Full SIGMA "**Windows**" ruleset (no SYSMON rewriting)
- `rules_windows_sysmon.json` : Full SIGMA "**Windows**" ruleset (SYSMON)

## Why you should make your own rulesets

The default rulesets provided are the conversion of the rules located in `rules/windows` directory of the Sigma repository. You should take into account that : 

- **Some rules are very noisy or produce a lot of false positives** depending on your environnement or the config file you used with genRules
- **Some rules can be very slow** depending on your logs

For example : 

-  "Suspicious Eventlog Clear or Configuration Using Wevtutil" : **very noisy** on fresh environnement (labs etc.), commonly generate a lot of useless detection
-  "Notepad Making Network Connection" : **can slow very significantly** the execution of Zircolite
-  "Rundll32 Internet Connection" : can be **very noisy** in some situations
-  "Wuauclt Network Connection" : **can slow very significantly** the execution of Zircolite
- "PowerShell Network Connections : **can slow very significantly** the execution of Zircolite