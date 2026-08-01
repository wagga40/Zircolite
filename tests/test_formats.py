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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

import zircolite as zc_pkg
from zircolite import cli as zircolite_cli
from zircolite import run_config
from zircolite.config import ExtractorConfig
from zircolite.config_loader import ConfigLoader, ZircoliteConfig
from zircolite.formats import (
    ALIAS_EXTENSIONS,
    DEFAULT_INPUT_FORMAT,
    EXTENSION_FALLBACKS,
    INPUT_FORMATS,
    NON_WINDOWS_INPUT_FLAGS,
    YAML_INPUT_FORMATS,
    format_by_name,
    format_by_yaml,
    format_from_args,
    has_explicit_format,
    json_array_requested,
)
from zircolite.processing import create_extractor
from zircolite.streaming import StreamingEventProcessor

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

# The rows that actually carry a CLI flag. EVTX is the implicit default and has
# no flag, so "the flag beats the YAML value" is not a question that can be
# asked of it -- its side of the contract is the opposite one, and is asserted
# by TestImplicitEvtxDefault below.
FLAGGED_FORMATS = [row for row in PARITY_TABLE if row[0] is not None]


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

    def test_yaml_format_round_trip(
        self, flag, input_type, explicit, extension, yaml_format
    ):
        """A YAML `input.format` must set the flag `get_input_type` reads back."""
        args = make_args(None, evtx=None, no_recursion=False)
        run_config.resolve(args, {"input": {"format": yaml_format}})
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


@pytest.mark.parametrize(
    "flag,input_type,explicit,extension,yaml_format", FLAGGED_FORMATS
)
class TestExplicitFlagPrecedence:
    """A CLI format flag outranks `input.format` in the YAML document."""

    def test_cli_flag_wins_over_yaml_format(
        self, flag, input_type, explicit, extension, yaml_format
    ):
        args = make_args(flag, evtx=None, no_recursion=False)
        # Deliberately pick a different format in the YAML document
        other = "csv" if yaml_format != "csv" else "json"
        run_config.resolve(args, {"input": {"format": other}})
        assert zircolite_cli.get_input_type(args) == input_type


class TestImplicitEvtxDefault:
    """EVTX carries no flag, so it holds the other side of that contract.

    With nothing on the command line there is no flag to outrank the YAML
    document, and `input.format` must therefore decide -- including when it
    selects EVTX itself.
    """

    @pytest.mark.parametrize(
        "yaml_format,expected", [(row[4], row[1]) for row in PARITY_TABLE]
    )
    def test_yaml_format_decides_when_no_flag_is_given(self, yaml_format, expected):
        args = make_args(None, evtx=None, no_recursion=False)
        run_config.resolve(args, {"input": {"format": yaml_format}})
        assert zircolite_cli.get_input_type(args) == expected

    def test_no_flag_and_no_yaml_format_is_evtx(self):
        args = make_args(None, evtx=None, no_recursion=False)
        run_config.resolve(args, {})
        assert zircolite_cli.get_input_type(args) == "evtx"
        assert zircolite_cli._has_explicit_format_flag(args) is False


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
        """Registry order is the tie-break when several flags are truthy."""
        assert tuple(f.args_flag for f in INPUT_FORMATS) == (
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
        assert frozenset(
            {"auditd_input", "sysmon_linux_input"}
        ) == NON_WINDOWS_INPUT_FLAGS

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


class TestSingleFormatResolver:
    """One resolver, so a namespace cannot resolve two different ways.

    There used to be a second ``vars()``-based resolver, which could not see
    the class-body attributes the regression runners declared. Those runs
    resolved to EVTX in the streaming processor while ``core`` -- reading the
    same object through ``getattr`` -- saw the array flag.
    """

    def test_class_level_attributes_resolve(self):
        class Args:
            json_array_input = True

        assert format_from_args(Args()).name == "json_array"

    def test_instance_attributes_resolve(self):
        assert format_from_args(make_args("json_array_input")).name == "json_array"

    def test_regression_runner_namespace_resolves(self, field_mappings_file):
        """The runners now build a Namespace; the processor must agree."""
        args = argparse.Namespace(
            json_array_input=True, all_transforms=False, transform_categories=None
        )
        processor = StreamingEventProcessor(
            config_file=field_mappings_file, args_config=args
        )

        assert processor.chosen_input == "json_array_input"
        assert json_array_requested(args) is True

    def test_no_evtx_only_transform_is_gated_out_by_this(self):
        """Locks the property that made the collapse behaviour-neutral.

        Every shipped source_condition that lists evtx_input also lists
        json_array_input, so the two resolve to the same set of transforms.
        A future config edit that breaks this should say so here.
        """
        import yaml

        config = yaml.safe_load(
            (Path(__file__).parent.parent / "config" / "config.yaml").read_text()
        )
        for category, items in (config.get("transforms") or {}).items():
            for transform in items:
                sources = set(transform.get("source_condition", []))
                assert ("evtx_input" in sources) == ("json_array_input" in sources), (
                    f"{category}: {transform.get('alias_name')}"
                )


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


class TestExtensionFallbacks:
    """The extension table is hand-written on purpose; keep it honest."""

    def test_every_fallback_names_a_real_format(self):
        for ext, fallback in EXTENSION_FALLBACKS.items():
            assert format_by_name(fallback.format_name) is not None, ext

    def test_unambiguous_extensions_agree_with_the_registry(self):
        """When exactly one format claims an extension, that must be the guess.

        Catches drift such as changing a format's default_extension without
        updating this table. Extensions claimed by several formats (".log" by
        three, ".json" by two) are judgement calls documented next to the
        table, and aliases are claimed by none.
        """
        for ext, fallback in EXTENSION_FALLBACKS.items():
            if ext in ALIAS_EXTENSIONS:
                continue
            claimants = {
                f.name for f in INPUT_FORMATS
                if f.default_extension == ext.lstrip(".")
            }
            if len(claimants) != 1:
                continue
            assert fallback.format_name in claimants, (
                f"{ext} -> {fallback.format_name}, but only {claimants} claim it"
            )

    def test_ambiguous_extensions_are_documented_judgement_calls(self):
        """.log is claimed by three formats and guesses none of them.

        Reaching the fallback means none of their content markers were found,
        so a readable text format is the least-bad answer.
        """
        log_claimants = {
            f.name for f in INPUT_FORMATS if f.default_extension == "log"
        }
        assert len(log_claimants) > 1
        assert EXTENSION_FALLBACKS[".log"].format_name == "json"

    def test_alias_extensions_are_not_claimed_by_any_format(self):
        claimed = {f".{f.default_extension}" for f in INPUT_FORMATS if f.default_extension}
        assert ALIAS_EXTENSIONS.isdisjoint(claimed)

    def test_detector_uses_the_shared_table(self, test_logger):
        from zircolite.detector import LogTypeDetector

        detector = LogTypeDetector(logger=test_logger)
        for ext, fallback in EXTENSION_FALLBACKS.items():
            result = detector._fallback_by_extension(ext, "test")
            assert result.input_type == fallback.format_name
            assert result.log_source == fallback.log_source
            assert result.confidence == "low"

    def test_unknown_extension_is_unknown(self, test_logger):
        from zircolite.detector import LogTypeDetector

        detector = LogTypeDetector(logger=test_logger)
        assert detector._fallback_by_extension(".zzz", "test").log_source == "unknown"


class TestDefaultEncodings:
    """Per-format encodings live in the registry, not in three other places."""

    def test_text_formats_declare_an_encoding(self):
        for spec in INPUT_FORMATS:
            if spec.stream_method and spec.name != "evtx":
                assert spec.default_encoding is not None, spec.name

    def test_binary_formats_declare_none(self):
        assert format_by_name("evtx").default_encoding is None
        assert format_by_name("sqlite").default_encoding is None

    @pytest.mark.parametrize("flag,expected", [
        ("sysmon4linux", "ISO-8859-1"),
        ("auditd_logs", "utf-8"),
        ("evtxtract", "utf-8"),
        ("xml_logs", "utf-8"),
    ])
    def test_extractor_config_reads_the_registry(self, flag, expected):
        assert ExtractorConfig(**{flag: True}).encoding == expected

    def test_explicit_encoding_is_never_overridden(self):
        cfg = ExtractorConfig(sysmon4linux=True, encoding="cp1252")
        assert cfg.encoding == "cp1252"


class TestJsonArrayRequested:
    """core.py used to read the json_array_input flag name directly."""

    def test_true_only_for_array_formats(self):
        for spec in INPUT_FORMATS:
            args = make_args(spec.args_flag)
            assert json_array_requested(args) is spec.json_array, spec.name

    def test_false_for_a_bare_namespace(self):
        assert json_array_requested(argparse.Namespace()) is False

    def test_array_wins_even_when_lines_takes_precedence(self):
        """json_input sorts first, but the array request must still be seen."""
        args = make_args("json_input")
        args.json_array_input = True
        assert format_from_args(args).name == "json"
        assert json_array_requested(args) is True


class TestGeneratedConfigDescribesEveryFormat:
    """The generated config file lists the formats from the registry.

    The old hand-written example enumerated them in prose, which is how it
    came to describe formats that no longer matched the code.
    """

    def test_every_format_is_listed_and_described(self, tmp_path):
        from zircolite.config_loader import _FORMAT_NOTES, create_default_config_file

        target = tmp_path / "generated.yaml"
        create_default_config_file(str(target))
        text = target.read_text()

        for spec in INPUT_FORMATS:
            assert f"#   {spec.yaml_format}" in text, spec.yaml_format
            assert spec.yaml_format in _FORMAT_NOTES, (
                f"{spec.yaml_format} has no description in _FORMAT_NOTES"
            )

    def test_no_note_describes_a_format_that_was_removed(self):
        from zircolite.config_loader import _FORMAT_NOTES

        assert set(_FORMAT_NOTES) <= set(YAML_INPUT_FORMATS)
