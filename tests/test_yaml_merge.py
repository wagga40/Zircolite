"""Tests for the YAML config -> CLI args merge helpers in zircolite.py."""
import argparse
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zircolite.config_loader import ZircoliteConfig

WORKSPACE_ROOT = Path(__file__).parent.parent


def load_zircolite_script():
    """Load zircolite.py script directly, bypassing the package."""
    spec = importlib.util.spec_from_file_location(
        "zircolite_script", WORKSPACE_ROOT / "zircolite.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


zircolite_script = load_zircolite_script()


def _args(**overrides):
    """Minimal argparse namespace for the merge helpers."""
    defaults = dict(
        ruleset=None,
        pipeline=None,
        rulefilter=None,
        save_ruleset=False,
        no_parallel=False,
        parallel_workers=None,
        no_event_filter=False,
        auto_index=0,
        add_index=None,
        remove_index=None,
        strict=False,
        after="1970-01-01T00:00:00",
        before="9999-12-12T23:59:59",
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
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestApplyYamlRulesConfig:
    """Tests for _apply_yaml_rules_config."""

    def test_yaml_rulesets_keep_argparse_nested_shape(self):
        """YAML rulesets must be wrapped per-element so main()'s flatten works."""
        yaml_config = ZircoliteConfig()
        yaml_config.rules.rulesets = ["rules/a.json", "rules/b.json"]
        args = _args()

        zircolite_script._apply_yaml_rules_config(yaml_config, args)

        assert args.ruleset == [["rules/a.json"], ["rules/b.json"]]
        # Simulate the flatten performed in main()
        flattened = [item for sublist in args.ruleset for item in sublist]
        assert flattened == ["rules/a.json", "rules/b.json"]

    def test_cli_ruleset_takes_precedence_over_yaml(self):
        yaml_config = ZircoliteConfig()
        yaml_config.rules.rulesets = ["rules/a.json"]
        args = _args(ruleset=[["cli/rules.json"]])

        zircolite_script._apply_yaml_rules_config(yaml_config, args)

        assert args.ruleset == [["cli/rules.json"]]

    def test_yaml_pipelines_and_filters_are_nested(self):
        yaml_config = ZircoliteConfig()
        yaml_config.rules.rulesets = ["rules/a.json"]
        yaml_config.rules.pipelines = ["pipeline_x"]
        yaml_config.rules.filters = ["Noisy"]
        args = _args()

        zircolite_script._apply_yaml_rules_config(yaml_config, args)

        assert args.pipeline == [["pipeline_x"]]
        assert args.rulefilter == [["Noisy"]]


class TestApplyYamlParallelConfig:
    """Tests for the parallel section of _apply_yaml_processing_config."""

    def test_yaml_without_parallel_section_keeps_parallel_enabled(self):
        """A YAML file with no parallel section must not set --no-parallel."""
        yaml_config = ZircoliteConfig()
        args = _args()

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert args.no_parallel is False

    def test_yaml_parallel_enabled_false_disables_parallel(self):
        yaml_config = ZircoliteConfig()
        yaml_config.parallel.enabled = False
        args = _args()

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert args.no_parallel is True

    def test_yaml_parallel_enabled_true_keeps_parallel(self):
        yaml_config = ZircoliteConfig()
        yaml_config.parallel.enabled = True
        args = _args()

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert args.no_parallel is False


class TestApplyYamlNewlyWiredOptions:
    """Regression tests for YAML options that were parsed but never applied."""

    def test_yaml_select_and_avoid_applied(self):
        yaml_config = ZircoliteConfig()
        yaml_config.input.select = ["sysmon", "security"]
        yaml_config.input.avoid = ["backup"]
        args = _args(select=None, avoid=None)

        zircolite_script._apply_yaml_input_config(yaml_config, args)

        assert args.select == [["sysmon"], ["security"]]
        assert args.avoid == [["backup"]]

    def test_cli_select_takes_precedence_over_yaml(self):
        yaml_config = ZircoliteConfig()
        yaml_config.input.select = ["yamlpick"]
        args = _args(select=[["clipick"]], avoid=None)

        zircolite_script._apply_yaml_input_config(yaml_config, args)

        assert args.select == [["clipick"]]

    def test_yaml_event_filter_disabled(self):
        yaml_config = ZircoliteConfig()
        yaml_config.processing.event_filter_enabled = False
        args = _args()

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert args.no_event_filter is True

    def test_yaml_event_filter_enabled_by_default(self):
        yaml_config = ZircoliteConfig()
        args = _args()

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert args.no_event_filter is False

    def test_yaml_auto_index_applied(self):
        yaml_config = ZircoliteConfig()
        yaml_config.processing.auto_index = 5
        args = _args()

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert args.auto_index == 5

    def test_cli_auto_index_takes_precedence_over_yaml(self):
        yaml_config = ZircoliteConfig()
        yaml_config.processing.auto_index = 5
        args = _args(auto_index=10)

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert args.auto_index == 10


class TestApplyYamlParallelWorkers:
    """YAML parallel.min_workers / adaptive must reach the CLI args."""

    def test_yaml_min_workers_applied(self):
        yaml_config = ZircoliteConfig()
        yaml_config.parallel.min_workers = 3
        args = _args()

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert args.parallel_min_workers == 3

    def test_yaml_adaptive_false_applied(self):
        yaml_config = ZircoliteConfig()
        yaml_config.parallel.adaptive = False
        args = _args()

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert args.parallel_adaptive is False

    def test_yaml_parallel_defaults_leave_args_untouched(self):
        yaml_config = ZircoliteConfig()
        args = _args()

        zircolite_script._apply_yaml_processing_config(yaml_config, args)

        assert not hasattr(args, "parallel_min_workers")
        assert not hasattr(args, "parallel_adaptive")


class TestYamlLoggingOverrides:
    """debug/log_file/no_output must reach the logger, which is built early."""

    def test_debug_true_sets_args_debug(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("processing:\n  debug: true\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False,
                     logfile="zircolite.log")

        zircolite_script.apply_yaml_logging_overrides(args)

        assert args.debug is True

    def test_log_file_overrides_default(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("output:\n  log_file: custom.log\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False,
                     logfile="zircolite.log")

        zircolite_script.apply_yaml_logging_overrides(args)

        assert args.logfile == "custom.log"

    def test_cli_log_file_wins_over_yaml(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("output:\n  log_file: from_yaml.log\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False,
                     logfile="from_cli.log")

        zircolite_script.apply_yaml_logging_overrides(args)

        assert args.logfile == "from_cli.log"

    def test_no_output_sets_nolog(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("output:\n  no_output: true\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False,
                     logfile="zircolite.log")

        zircolite_script.apply_yaml_logging_overrides(args)

        assert args.nolog is True

    def test_missing_or_broken_file_is_left_to_the_real_merge(self, tmp_path):
        """A parse error here must not crash: load_yaml_config_and_merge reports it."""
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("output: [this is not a mapping\n")
        args = _args(yaml_config=str(cfg), debug=False, nolog=False,
                     logfile="zircolite.log")

        zircolite_script.apply_yaml_logging_overrides(args)

        assert args.debug is False
        assert args.logfile == "zircolite.log"

    def test_no_yaml_config_is_a_noop(self):
        args = _args(yaml_config=None, debug=False, nolog=False,
                     logfile="zircolite.log")

        zircolite_script.apply_yaml_logging_overrides(args)

        assert args.debug is False
        assert args.logfile == "zircolite.log"


class TestMergeWithArgsParallel:
    """merge_with_args must reflect the real --no-parallel flag."""

    def test_no_parallel_disables_enabled(self):
        from zircolite.config_loader import ConfigLoader
        config = ZircoliteConfig()
        args = _args(no_parallel=True)

        merged = ConfigLoader().merge_with_args(config, args)

        assert merged.parallel.enabled is False

    def test_default_leaves_parallel_enabled(self):
        from zircolite.config_loader import ConfigLoader
        config = ZircoliteConfig()

        merged = ConfigLoader().merge_with_args(config, _args())

        assert merged.parallel.enabled is True

    def test_cli_rulesets_are_flattened(self):
        """args.ruleset is still argparse's list-of-lists at merge time."""
        from zircolite.config_loader import ConfigLoader
        config = ZircoliteConfig()
        args = _args(ruleset=[["a.json"], ["b.json"]])

        merged = ConfigLoader().merge_with_args(config, args)

        assert merged.rules.rulesets == ["a.json", "b.json"]
