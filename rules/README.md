# Rulesets

## Default rulesets

These rulesets are generated from SIGMA rules using **pySigma** from the [official Sigma repository](https://github.com/SigmaHQ/sigma).

:warning: **These rulesets are given "as is" to help new analysts discover SIGMA and Zircolite. They are not filtered for slow rules or high false-positive rules. If you know what you’re doing, you SHOULD generate your own rulesets.**

### Windows (generic – no Sysmon rewriting)

- `rules_windows_generic_high.json` : Level high and above from the **Windows** directory (no Sysmon rewriting)
- `rules_windows_generic_medium.json` : Level medium and above from the **Windows** directory (no Sysmon rewriting)
- `rules_windows_generic.json` : Same as `rules_windows_generic_high.json`

### Windows (Sysmon)

- `rules_windows_sysmon_high.json` : Level high and above from the **Windows** directory (Sysmon)
- `rules_windows_sysmon_medium.json` : Level medium and above from the **Windows** directory (Sysmon)
- `rules_windows_sysmon.json` : Same as `rules_windows_sysmon_high.json`

### Linux

- `rules_linux.json` : Full SIGMA ruleset from the **linux** directory (Auditd and Sysmon for Linux)
- `rules_linux_high.json` : Level high and above from the **linux** directory
- `rules_linux_medium.json` : Level medium and above from the **linux** directory

**Zircolite can auto-update these rulesets with `-U` or `--update-rules`. Pre-built rules are available in [Zircolite-Rules](https://github.com/wagga40/Zircolite-Rules-v2).**

## Why you should make your own rulesets

The default rulesets are converted from the **Windows** and **linux** rule directories of the Sigma repository. Keep in mind:

- **Some rules are very noisy or produce many false positives** depending on your environment and configuration.
- **Some rules can be very slow** depending on your log volume and schema.

To generate your own ruleset, see the [documentation](https://wagga40.github.io/Zircolite/) or the [docs](https://github.com/wagga40/Zircolite/tree/master/docs) in the repository.

Examples of rules that may be noisy or slow:

- **Suspicious Eventlog Clear or Configuration Using Wevtutil** : very noisy on fresh environments (e.g. labs), often generates useless detections
- **Notepad Making Network Connection** : can slow execution significantly
- **Rundll32 Internet Connection** : can be very noisy in some environments
- **Wuauclt Network Connection** : can slow execution significantly
- **PowerShell Network Connections** : can slow execution significantly