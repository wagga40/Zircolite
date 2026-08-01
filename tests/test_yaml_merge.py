"""Tests for resolving a YAML config file onto the CLI args namespace."""
import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite import cli as zircolite_script
from zircolite import run_config
from zircolite.run_config import EARLY_DESTS, flatten_groups, resolve

WORKSPACE_ROOT = Path(__file__).parent.parent


def _args(**overrides):
    """Namespace shaped like a freshly parsed one: unset scalars are None."""
    defaults = dict(
        ruleset=None,
        pipeline=None,
        rulefilter=None,
        save_ruleset=False,
        no_parallel=False,
        parallel_workers=None,
        no_event_filter=False,
        auto_index=None,
        add_index=None,
        remove_index=None,
        strict=False,
        after=None,
        before=None,
        evtx=None,
        json_input=False,
        json_array_input=False,
        xml_input=False,
        csv_input=False,
        sysmon_linux_input=False,
        auditd_input=False,
        evtxtract_input=False,
        no_recursion=False,
        file_pattern=None,
        fileext=None,
        logs_encoding=None,
        select=None,
        avoid=None,
        csv=False,
        template=None,
        templateOutput=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestRulesResolution:
    """rules.* -> args."""

    def test_yaml_rulesets_keep_argparse_nested_shape(self):
        """YAML rulesets must be wrapped per-element so main()'s flatten works."""
        args = _args()

        resolve(args, {"rules": {"rulesets": ["rules/a.json", "rules/b.json"]}})

        assert args.ruleset == [["rules/a.json"], ["rules/b.json"]]
        assert flatten_groups(args.ruleset) == ["rules/a.json", "rules/b.json"]

    def test_cli_ruleset_takes_precedence_over_yaml(self):
        args = _args(ruleset=[["cli/rules.json"]])

        resolve(args, {"rules": {"rulesets": ["rules/a.json"]}})

        assert args.ruleset == [["cli/rules.json"]]

    def test_yaml_pipelines_and_filters_are_nested(self):
        args = _args()

        resolve(
            args,
            {"rules": {"rulesets": ["rules/a.json"], "pipelines": ["pipeline_x"],
                       "filters": ["Noisy"]}},
        )

        assert args.pipeline == [["pipeline_x"]]
        assert args.rulefilter == [["Noisy"]]

    def test_absent_rules_section_leaves_ruleset_unset(self):
        """main() falls back to the bundled ruleset only when this stays unset."""
        args = _args()

        resolve(args, {"input": {"path": "logs/"}})

        assert args.ruleset is None

    def test_bare_rulefilter_does_not_discard_yaml_filters(self):
        """`-R` with nargs='*' and no operand yields [[]]; it names nothing."""
        args = _args(rulefilter=[[]])

        resolve(args, {"rules": {"filters": ["Noisy"]}})

        assert args.rulefilter == [["Noisy"]]


class TestParallelResolution:
    """parallel.* -> args."""

    def test_yaml_without_parallel_section_keeps_parallel_enabled(self):
        """A YAML file with no parallel section must not set --no-parallel."""
        args = _args()

        resolve(args, {})

        assert args.no_parallel is False

    def test_yaml_parallel_enabled_false_disables_parallel(self):
        args = _args()

        resolve(args, {"parallel": {"enabled": False}})

        assert args.no_parallel is True

    def test_yaml_parallel_enabled_true_keeps_parallel(self):
        args = _args()

        resolve(args, {"parallel": {"enabled": True}})

        assert args.no_parallel is False

    def test_cli_no_parallel_survives_yaml_enabled_true(self):
        """YAML must never clear a flag the user set on the CLI."""
        args = _args(no_parallel=True)

        resolve(args, {"parallel": {"enabled": True}})

        assert args.no_parallel is True

    def test_yaml_min_workers_applied(self):
        args = _args()

        resolve(args, {"parallel": {"min_workers": 3}})

        assert args.parallel_min_workers == 3

    def test_yaml_adaptive_false_applied(self):
        args = _args()

        resolve(args, {"parallel": {"adaptive": False}})

        assert args.parallel_adaptive is False

    def test_yaml_parallel_defaults_are_filled_in(self):
        """Every destination carries a usable value after resolution."""
        args = _args()

        resolve(args, {})

        assert args.parallel_min_workers == 1
        assert args.parallel_adaptive is True
        assert args.parallel_memory_limit == 85.0


class TestInputAndProcessingResolution:
    """Options that were once parsed but never applied."""

    def test_yaml_select_and_avoid_applied(self):
        args = _args()

        resolve(args, {"input": {"select": ["sysmon", "security"],
                                 "avoid": ["backup"]}})

        assert args.select == [["sysmon"], ["security"]]
        assert args.avoid == [["backup"]]

    def test_cli_select_takes_precedence_over_yaml(self):
        args = _args(select=[["clipick"]])

        resolve(args, {"input": {"select": ["yamlpick"]}})

        assert args.select == [["clipick"]]

    def test_yaml_event_filter_disabled(self):
        args = _args()

        resolve(args, {"processing": {"event_filter_enabled": False}})

        assert args.no_event_filter is True

    def test_yaml_event_filter_enabled_by_default(self):
        args = _args()

        resolve(args, {})

        assert args.no_event_filter is False

    def test_yaml_auto_index_applied(self):
        args = _args()

        resolve(args, {"processing": {"auto_index": 5}})

        assert args.auto_index == 5

    def test_cli_auto_index_takes_precedence_over_yaml(self):
        args = _args(auto_index=10)

        resolve(args, {"processing": {"auto_index": 5}})

        assert args.auto_index == 10


class TestAdditiveKeysMerge:
    """add_index / remove_index / transform_categories union YAML and CLI."""

    def test_transform_categories_union(self):
        args = _args(transform_categories=["process"])

        resolve(args, {"processing": {"transform_categories": ["commandline"]}})

        assert args.transform_categories == ["commandline", "process"]

    def test_add_index_union(self):
        args = _args(add_index=[["Channel"]])

        resolve(args, {"processing": {"add_index": ["Computer"]}})

        assert flatten_groups(args.add_index) == ["Computer", "Channel"]

    def test_remove_index_union(self):
        args = _args(remove_index=[["idx_cli"]])

        resolve(args, {"processing": {"remove_index": ["idx_yaml"]}})

        assert flatten_groups(args.remove_index) == ["idx_yaml", "idx_cli"]

    def test_union_is_deduplicated(self):
        args = _args(add_index=[["Channel"]])

        resolve(args, {"processing": {"add_index": ["Channel"]}})

        assert flatten_groups(args.add_index) == ["Channel"]

    def test_yaml_only_still_applies(self):
        args = _args()

        resolve(args, {"processing": {"transform_categories": ["commandline"]}})

        assert args.transform_categories == ["commandline"]


class TestExplicitDefaultsWin:
    """A value the user typed must beat the config file, even at the default."""

    def test_cli_delimiter_equal_to_default_beats_yaml(self):
        args = _args(csv_delimiter=";")

        resolve(args, {"output": {"csv_delimiter": ","}})

        assert args.csv_delimiter == ";"

    def test_cli_limit_equal_to_default_beats_yaml(self):
        args = _args(limit=-1)

        resolve(args, {"processing": {"limit": 10}})

        assert args.limit == -1

    def test_yaml_applies_when_cli_is_silent(self):
        args = _args(csv_delimiter=None, limit=None)

        resolve(args, {"output": {"csv_delimiter": ","},
                       "processing": {"limit": 10}})

        assert args.csv_delimiter == ","
        assert args.limit == 10

    def test_defaults_apply_with_no_yaml_at_all(self):
        args = _args(csv_delimiter=None, limit=None, outfile=None, logfile=None,
                     timefield=None)

        resolve(args, {})

        assert args.csv_delimiter == ";"
        assert args.limit == -1
        assert args.outfile == "detected_events.json"
        assert args.logfile == "zircolite.log"
        assert args.timefield == "SystemTime"


class TestCsvOutputNaming:
    """--csv picks the .csv default name without clobbering an explicit one."""

    def test_csv_flag_changes_default_outfile(self):
        args = _args(csv=True, outfile=None)

        resolve(args, {})

        assert args.outfile == "detected_events.csv"

    def test_yaml_csv_format_changes_default_outfile(self):
        args = _args(outfile=None)

        resolve(args, {"output": {"format": "csv"}})

        assert args.csv is True
        assert args._csv_from_yaml is True
        assert args.outfile == "detected_events.csv"

    def test_explicit_outfile_survives_csv(self):
        args = _args(csv=True, outfile="detected_events.json")

        resolve(args, {})

        assert args.outfile == "detected_events.json"


class TestYamlLoggingOverrides:
    """debug/log_file/no_output must reach the logger, which is built early."""

    def test_debug_true_sets_args_debug(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("processing:\n  debug: true\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False, logfile=None)

        zircolite_script.resolve_logging_args(args)

        assert args.debug is True

    def test_log_file_overrides_default(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("output:\n  log_file: custom.log\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False, logfile=None)

        zircolite_script.resolve_logging_args(args)

        assert args.logfile == "custom.log"

    def test_cli_log_file_wins_over_yaml(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("output:\n  log_file: from_yaml.log\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False,
                     logfile="from_cli.log")

        zircolite_script.resolve_logging_args(args)

        assert args.logfile == "from_cli.log"

    def test_no_output_sets_nolog(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("output:\n  no_output: true\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False, logfile=None)

        zircolite_script.resolve_logging_args(args)

        assert args.nolog is True

    def test_missing_or_broken_file_is_left_to_the_real_merge(self, tmp_path):
        """A parse error here must not crash: resolve_run_config reports it."""
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("output: [this is not a mapping\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False, logfile=None)

        zircolite_script.resolve_logging_args(args)

        assert args.debug is False
        assert args.logfile == "zircolite.log"

    def test_no_yaml_config_still_applies_the_default_log_file(self):
        """Without this, argparse's None default would disable file logging."""
        args = _args(yaml_config=None, debug=False, nolog=False, logfile=None)

        zircolite_script.resolve_logging_args(args)

        assert args.debug is False
        assert args.logfile == "zircolite.log"

    def test_early_phase_touches_only_the_logging_settings(self, tmp_path):
        """The rest must wait for validation, so it stays unresolved here."""
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("processing:\n  limit: 10\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False, logfile=None,
                     limit=None)

        zircolite_script.resolve_logging_args(args)

        assert args.limit is None
        assert set(EARLY_DESTS) == {"debug", "nolog", "logfile"}


class TestSettingsTable:
    """Structural invariants of the settings table itself."""

    def test_every_setting_has_a_unique_dest(self):
        dests = [s.dest for s in run_config.SETTINGS]
        assert len(dests) == len(set(dests))

    def test_every_setting_names_a_known_section(self):
        from zircolite.config_loader import SECTIONS

        for setting in run_config.SETTINGS:
            assert setting.section in SECTIONS, setting.dest

    def test_every_setting_key_is_a_real_config_field(self):
        from dataclasses import fields as dc_fields

        from zircolite.config_loader import SECTIONS

        for setting in run_config.SETTINGS:
            known = {f.name for f in dc_fields(SECTIONS[setting.section])}
            assert setting.key in known, f"{setting.section}.{setting.key}"

    def test_early_dests_are_all_settings(self):
        dests = {s.dest for s in run_config.SETTINGS}
        assert dests >= EARLY_DESTS


class TestYamlValuesCountAsUserSet:
    """A value pinned in the config file is as deliberate as a CLI flag.

    Regression: ``_explicit`` was populated from argparse only, so
    auto-detection silently overrode YAML-set ``processing.time_field`` and
    ``input.file_extension`` while the CLI equivalents were respected.
    """

    def test_yaml_time_field_is_explicit(self):
        args = _args()

        resolve(args, {"processing": {"time_field": "UtcTime"}})

        assert args.timefield == "UtcTime"
        assert zircolite_script._is_explicit(args, "timefield", "SystemTime")

    def test_yaml_file_extension_is_explicit(self):
        args = _args()

        resolve(args, {"input": {"file_extension": "xml"}})

        assert args.fileext == "xml"
        assert zircolite_script._fileext_is_explicit(args)

    def test_unset_keys_stay_implicit(self):
        args = _args()

        resolve(args, {"input": {"path": "logs/"}})

        assert not zircolite_script._is_explicit(args, "timefield", "SystemTime")
        assert not zircolite_script._fileext_is_explicit(args)

    def test_detection_does_not_override_a_yaml_time_field(self):
        """The whole point: auto-detection must leave a pinned field alone."""
        from zircolite.detector import DetectionResult

        args = _args()
        resolve(args, {"processing": {"time_field": "UtcTime"}})

        detection = DetectionResult(
            input_type="json",
            log_source="generic_json",
            confidence="high",
            timestamp_field="@timestamp",
        )
        zircolite_script._apply_detection_result(args, detection, logging.getLogger("t"))

        assert args.timefield == "UtcTime"


class TestScalarWhereAListIsExpected:
    """A bare string for a list-valued key must mean one item, not one per character.

    YAML makes this an easy mistake -- `rulesets: rules/x.json` reads perfectly
    naturally -- and iterating the string produced one single-character entry
    per character, gutting the ruleset, the filters or the file selection.
    """

    def test_ruleset_scalar_becomes_one_entry(self):
        args = _args()
        resolve(args, {"rules": {"rulesets": "rules/rules_windows_generic.json"}},
                skip=EARLY_DESTS)
        assert flatten_groups(args.ruleset) == ["rules/rules_windows_generic.json"]

    def test_select_scalar_becomes_one_entry(self):
        args = _args()
        resolve(args, {"input": {"select": "Security"}}, skip=EARLY_DESTS)
        assert flatten_groups(args.select) == ["Security"]

    def test_rulefilter_scalar_becomes_one_entry(self):
        args = _args()
        resolve(args, {"rules": {"filters": "Noisy Rule"}}, skip=EARLY_DESTS)
        assert flatten_groups(args.rulefilter) == ["Noisy Rule"]

    def test_concat_setting_scalar_becomes_one_entry(self):
        args = _args()
        resolve(args, {"processing": {"add_index": "CommandLine"}}, skip=EARLY_DESTS)
        assert flatten_groups(args.add_index) == ["CommandLine"]

    def test_a_real_list_is_still_a_list(self):
        args = _args()
        resolve(args, {"input": {"select": ["Security", "System"]}}, skip=EARLY_DESTS)
        assert flatten_groups(args.select) == ["Security", "System"]


class TestGeneratedConfigRoundTrip:
    """`--generate-config` must not write a config that changes behaviour.

    resolve() treats any non-null YAML value as a deliberate choice, so a
    generated file pinning a conditional default silently switches it off --
    even though the user changed nothing.
    """

    def _generated(self, tmp_path):
        import yaml as _yaml

        from zircolite.config_loader import create_default_config_file

        target = tmp_path / "generated.yaml"
        create_default_config_file(str(target))
        return _yaml.safe_load(target.read_text()) or {}

    def test_timestamp_auto_detection_survives(self, tmp_path):
        """A pinned time_field counts as explicit and disables auto-detection."""
        args = _args()
        resolve(args, self._generated(tmp_path), skip=EARLY_DESTS)
        assert "timefield" not in args._explicit, (
            "the generated config turned off timestamp auto-detection"
        )

    def test_csv_output_still_picks_the_csv_name(self, tmp_path):
        """A pinned output.file makes --csv write CSV into detected_events.json."""
        args = _args(csv=True)
        resolve(args, self._generated(tmp_path), skip=EARLY_DESTS)
        assert args.outfile == "detected_events.csv"

    def test_no_setting_differs_from_a_run_without_the_file(self, tmp_path):
        """The whole point: generating a config and passing it back is a no-op.

        `rules.rulesets` is excluded: it names the very file zircolite.py
        applies when no ruleset is given, and nothing reads its explicitness,
        so pinning it is the one difference that cannot change an outcome.
        """
        generated = self._generated(tmp_path)

        without = _args()
        resolve(without, {}, skip=EARLY_DESTS)
        with_file = _args()
        resolve(with_file, generated, skip=EARLY_DESTS)

        differences = {
            setting.dest: (
                getattr(without, setting.dest, None),
                getattr(with_file, setting.dest, None),
            )
            for setting in run_config.SETTINGS
            if setting.dest != "ruleset"
            and getattr(without, setting.dest, None)
            != getattr(with_file, setting.dest, None)
        }
        assert differences == {}
