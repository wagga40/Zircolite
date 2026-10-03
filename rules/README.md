# Rulesets

## Default rulesets

These rulesets are generated from SIGMA rules using **pySigma** from the [official Sigma repository](https://github.com/SigmaHQ/sigma).

> [!NOTE]
> These rulesets are provided as-is, without filtering for runtime or false positives in
> your environment. Review detections and select rules for your log sources.

### Windows

- `rules_windows_sysmon.json` — the **Windows** rules, mapped to Sysmon events
- `rules_windows_generic.json` — the **Windows** rules, mapped to Windows audit events (no Sysmon rewriting)
- `rules_windows_merged.json` — both mappings, merged Windows log sources (default when `--ruleset` is omitted)

Rules with provably absent channels are skipped before execution. The merged ruleset
can therefore cover both Sysmon and generic Windows logs without running every query.

### Linux

- `rules_linux.json` — the **linux** rules (Auditd and Sysmon for Linux)

Each ruleset carries every level, from informational to critical. `--min-level medium` (or `high`, `critical`) keeps the rules at that level and above; it replaces the `_medium` and `_high` variants, which are no longer published.

## Updating with `-U`

`-U`/`--update-rules` installs everything [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) publishes, into the `rules/` directory the next run reads:

- the SigmaHQ rulesets above;
- `rules_windows_all.json` — the Windows detections of SigmaHQ and every community source, combined and deduplicated;
- community rulesets kept apart from them, one file per source and profile: Hayabusa (`rules_hayabusa_*`, DRL 1.1), Joe Security (`rules_joesecurity_*`, GPL 3.0), Micah Babinski (`rules_mbabinski_*`, GPL 3.0), mdecrevoisier (`rules_mdecrevoisier_*`, CC0 1.0) and tsale (`rules_tsale_*`, GPL 3.0);
- `experimental/` — Sigma correlation rulesets, run with `-r rules/experimental/<file>.json`;
- `licenses/` — the licence text of every source;
- `release-manifest.json` — the source, licence, revision and SHA-256 of every file above.

Each file is checked against the SHA-256 the repository's `release-manifest.json` lists for it, and a file that does not match leaves `rules/` untouched. A source whose last update failed keeps its previous rulesets and is reported as stale. Files `-U` no longer finds upstream are never deleted.

The Zircolite repository, its release archives and its Docker image carry all of these. Each ruleset stays under its source's licence, not under one covering `rules/` as a whole: `rules_windows_all.json` holds rules under DRL 1.1, GPL 3.0 and CC0 1.0 alike, each keeping its own. A release's `THIRD_PARTY_LICENSES` lists every source with its files, revision and licence text.

## Why you should make your own rulesets

The default SigmaHQ rulesets convert the Windows and Linux rule directories of the Sigma
repository. False positives and runtime depend on your environment, log volume and schema.
Use `--profile-rules` to measure runtime and `--rulefilter` to exclude rules by title.

To generate your own ruleset, see the [Usage documentation](../docs/Usage.md#rulesets--rules) in the repository or the [online docs](https://wagga40.github.io/Zircolite/).

A handful of rules enumerate thousands of values — *Vulnerable Driver Load*, *Shai-Hulud
2.0 Malicious NPM Package Installation*, the emoji-evasion rules. Converted straight from
Sigma, their SQL nests one level per value and exceeds SQLite's parser depth limit.
Zircolite retries those expressions in an equivalent, shallower form during execution.

Examples to review for false positives or runtime on your own data:

- **Suspicious Eventlog Clear or Configuration Using Wevtutil**
- **Notepad Making Network Connection**
- **Rundll32 Internet Connection**
- **Wuauclt Network Connection**
- **PowerShell Network Connections**
