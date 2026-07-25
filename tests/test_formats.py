"""
Tests for the input-format registry.

The parity table below is written from the behaviour of the individual
format switches as they existed before centralisation, so it doubles as a
regression net: any drift between the registry and the CLI/config/streaming
call sites shows up here as a table diff rather than as a silent change in
which files get processed.
"""

import argparse
import dataclasses
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

import zircolite as zc_pkg
from zircolite.config import ExtractorConfig
from zircolite.config_loader import ConfigLoader, ZircoliteConfig
from zircolite.formats import (
    DEFAULT_INPUT_FORMAT,
    INPUT_FLAG_PRECEDENCE,
    INPUT_FORMATS,
    NON_WINDOWS_INPUT_FLAGS,
    YAML_INPUT_FORMATS,
    format_by_name,
    format_by_yaml,
    format_from_args,
    format_from_flags,
    has_explicit_format,
)
from zircolite.processing import create_extractor
from zircolite.streaming import StreamingEventProcessor

# The CLI lives in top-level zircolite.py, whose name is shadowed by the
# package, so it has to be loaded from its path.
_spec = importlib.util.spec_from_file_location(
    "zircolite_cli", Path(__file__).parent.parent / "zircolite.py"
)
zircolite_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zircolite_cli)


# Every format flag the CLI can set, so a namespace is always complete.
ALL_FLAGS = (
    "db_input",
    "json_input",
    "json_array_input",
    "xml_input",
    "sysmon_linux_input",
    "auditd_input",
    "csv_input",
    "evtxtract_input",
)


def make_args(flag=None, **overrides):
    """Namespace with every format flag False except *flag*."""
    ns = argparse.Namespace(**{f: False for f in ALL_FLAGS})
    if flag is not None:
        setattr(ns, flag, True)
    ns.fileext = None
    ns.file_pattern = None
    ns.timefield = "SystemTime"
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


# (flag, input_type, explicit?, extension, yaml_format)
#
# `evtxtract` maps to the ".log" extension its CLI help has always
# documented; before centralisation the switch silently fell through to
# "evtx". `None` for the flag is the no-flag-set (default EVTX) case.
PARITY_TABLE = [
    (None, "evtx", False, "evtx", "evtx"),
    ("db_input", "sqlite", True, "evtx", "sqlite"),
    ("json_input", "json", True, "json", "json"),
    ("json_array_input", "json_array", True, "json", "json_array"),
    ("xml_input", "xml", True, "xml", "xml"),
    ("sysmon_linux_input", "sysmon_linux", True, "log", "sysmon_linux"),
    ("auditd_input", "auditd", True, "log", "auditd"),
    ("csv_input", "csv", True, "csv", "csv"),
    ("evtxtract_input", "evtxtract", True, "log", "evtxtract"),
]


@pytest.mark.parametrize("flag,input_type,explicit,extension,yaml_format", PARITY_TABLE)
class TestFormatParity:
    """Every format switch must agree with the registry."""

    def test_get_input_type(self, flag, input_type, explicit, extension, yaml_format):
        assert zircolite_cli.get_input_type(make_args(flag)) == input_type

    def test_has_explicit_format_flag(
        self, flag, input_type, explicit, extension, yaml_format
    ):
        assert zircolite_cli._has_explicit_format_flag(make_args(flag)) is explicit

    def test_format_flag_extension(
        self, flag, input_type, explicit, extension, yaml_format
    ):
        assert zircolite_cli._format_flag_extension(make_args(flag)) == extension

    def test_merge_with_args_sets_yaml_format(
        self, flag, input_type, explicit, extension, yaml_format
    ):
        loader = ConfigLoader()
        config = ZircoliteConfig()
        merged = loader.merge_with_args(config, make_args(flag))
        # No flag set leaves the configured default in place
        expected = yaml_format if flag is not None else "evtx"
        assert merged.input.format == expected

    def test_yaml_format_round_trip(
        self, flag, input_type, explicit, extension, yaml_format
    ):
        """A YAML `input.format` must set the flag `get_input_type` reads back."""
        config = ZircoliteConfig()
        config.input.format = yaml_format
        args = make_args(None, evtx=None, no_recursion=False)
        zircolite_cli._apply_yaml_input_config(config, args)
        assert zircolite_cli.get_input_type(args) == input_type

    def test_chosen_input(
        self, flag, input_type, explicit, extension, yaml_format, field_mappings_file
    ):
        processor = StreamingEventProcessor(
            config_file=field_mappings_file, args_config=make_args(flag)
        )
        expected = flag if flag is not None else "evtx_input"
        assert processor.chosen_input == expected

    def test_validate_config_accepts_format(
        self, flag, input_type, explicit, extension, yaml_format
    ):
        loader = ConfigLoader()
        config = ZircoliteConfig()
        config.input.format = yaml_format
        config.input.path = "."
        issues = loader.validate_config(config)
        assert not any("Invalid input format" in i for i in issues)


class TestValidationRejectsUnknown:
    def test_unknown_format_is_reported(self):
        loader = ConfigLoader()
        config = ZircoliteConfig()
        config.input.format = "not_a_format"
        config.input.path = "."
        issues = loader.validate_config(config)
        assert any("Invalid input format" in i for i in issues)


class TestRegistryInvariants:
    """Structural guarantees the call sites depend on."""

    def test_names_are_unique(self):
        for attr in ("name", "args_flag", "yaml_format"):
            values = [getattr(f, attr) for f in INPUT_FORMATS]
            assert len(values) == len(set(values)), attr

    def test_extractor_flags_are_real_fields(self):
        fields = {f.name for f in dataclasses.fields(ExtractorConfig)}
        for spec in INPUT_FORMATS:
            if spec.extractor_flag is not None:
                assert spec.extractor_flag in fields, spec.name

    def test_stream_methods_exist(self):
        for spec in INPUT_FORMATS:
            if spec.stream_method is not None:
                assert callable(
                    getattr(StreamingEventProcessor, spec.stream_method, None)
                ), spec.name

    def test_precedence_is_frozen(self):
        assert INPUT_FLAG_PRECEDENCE == (
            "db_input",
            "json_input",
            "json_array_input",
            "xml_input",
            "sysmon_linux_input",
            "auditd_input",
            "csv_input",
            "evtxtract_input",
            "evtx_input",
        )

    def test_non_windows_inputs(self):
        assert NON_WINDOWS_INPUT_FLAGS == frozenset(
            {"auditd_input", "sysmon_linux_input"}
        )

    def test_evtx_is_the_only_implicit_format(self):
        implicit = [f for f in INPUT_FORMATS if not f.has_cli_flag]
        assert [f.name for f in implicit] == ["evtx"]
        assert DEFAULT_INPUT_FORMAT.name == "evtx"

    def test_every_cli_flag_is_a_real_argparse_dest(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["zircolite.py"])
        parser_args = zircolite_cli.parse_arguments()
        for spec in INPUT_FORMATS:
            if spec.has_cli_flag:
                assert hasattr(parser_args, spec.args_flag), spec.args_flag

    def test_yaml_formats_match_table(self):
        assert set(YAML_INPUT_FORMATS) == {f.yaml_format for f in INPUT_FORMATS}


class TestLookups:
    def test_format_by_name_unknown(self):
        assert format_by_name("nope") is None

    def test_format_by_yaml_unknown(self):
        assert format_by_yaml("nope") is None

    def test_format_from_args_defaults_to_evtx(self):
        assert format_from_args(make_args(None)).name == "evtx"

    def test_format_from_args_tolerates_missing_attributes(self):
        """Partial namespaces must not raise — library callers build these."""
        ns = argparse.Namespace(json_input=True)
        assert format_from_args(ns).name == "json"

    def test_precedence_when_several_flags_set(self):
        ns = make_args("json_input")
        ns.evtxtract_input = True
        assert format_from_args(ns).name == "json"

    def test_has_explicit_format_ignores_evtx(self):
        assert has_explicit_format(make_args(None)) is False


class TestFormatFromFlagsUsesVars:
    """``format_from_flags`` reads ``vars()`` and must stay that way.

    The regression runners in ``tools/`` and ``helpers/`` pass an instance of
    a throwaway class whose flags are declared on the class body. Those never
    reach the instance ``__dict__``, so ``vars()`` does not see them and such
    callers resolve to the EVTX default. Switching this helper to ``getattr``
    would silently change which transforms fire for those runs.
    """

    def test_class_level_attributes_are_not_seen(self):
        class Args:
            json_array_input = True

        assert format_from_flags(vars(Args())).name == "evtx"

    def test_instance_attributes_are_seen(self):
        assert format_from_flags(vars(make_args("json_array_input"))).name == "json_array"


class TestCreateExtractor:
    """``create_extractor`` must keep deriving encoding from the format."""

    @pytest.mark.parametrize(
        "input_type,expected_encoding",
        [
            ("sysmon_linux", "ISO-8859-1"),
            ("auditd", "utf-8"),
            ("xml", "utf-8"),
            ("evtxtract", "utf-8"),
        ],
    )
    def test_encoding_derived_per_format(
        self, input_type, expected_encoding, test_logger
    ):
        args = make_args(logs_encoding=None)
        extractor = create_extractor(args, test_logger, input_type)
        assert extractor is not None
        assert extractor.encoding == expected_encoding

    @pytest.mark.parametrize("input_type", ["evtx", "json", "json_array", "csv", "sqlite", "bogus"])
    def test_formats_without_extractor(self, input_type, test_logger):
        args = make_args(logs_encoding=None)
        assert create_extractor(args, test_logger, input_type) is None

    def test_explicit_encoding_wins(self, test_logger):
        args = make_args(logs_encoding="utf-16")
        extractor = create_extractor(args, test_logger, "sysmon_linux")
        assert extractor.encoding == "utf-16"


class TestPackageExports:
    def test_registry_is_exported(self):
        for name in ("InputFormat", "INPUT_FORMATS", "format_by_name"):
            assert hasattr(zc_pkg, name), name
            assert name in zc_pkg.__all__, name
