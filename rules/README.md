# Rulesets

These files are what `-U` installs from
[Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2), which converts the
SigmaHQ and community rules with pySigma. They are provided as-is: review the detections
and keep the rules that fit your log sources.

- `rules_windows_merged.json` is the default when `--ruleset` is omitted.
- `experimental/` holds Sigma correlation rules, run with `-r rules/experimental/<file>.json`.
- `release-manifest.json` gives the source, licence, revision and SHA-256 of every file;
  `-U` checks each download against it before writing anything.

Each file keeps its source's licence; there is no single licence for `rules/` as a whole.
The texts are in `licenses/`, and a release's `THIRD_PARTY_LICENSES` lists every source with
its files and revision. The rules repository documents
[the sources and their licences](https://github.com/wagga40/Zircolite-Rules-v2/blob/main/docs/sources.md)
and [how each ruleset is built](https://github.com/wagga40/Zircolite-Rules-v2/blob/main/docs/rulesets.md).

Which ruleset to use, how to choose rules and how to build your own:
[Rulesets and rules](../docs/Usage.md#rulesets--rules) and
[Rule selection](../docs/Advanced.md#rule-selection).
