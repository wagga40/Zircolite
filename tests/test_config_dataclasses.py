"""
Tests for configuration dataclasses in zircolite.config.

Covers defaults and field types for ProcessingConfig, ExtractorConfig,
RulesetConfig, TemplateConfig, and GuiConfig. ExtractorConfig.__post_init__
encoding logic is asserted directly.
"""

from zircolite.config import (
    ProcessingConfig,
    ExtractorConfig,
    RulesetConfig,
    TemplateConfig,
    GuiConfig,
)


# =============================================================================
# ExtractorConfig encoding (__post_init__)
# =============================================================================


class TestExtractorConfigEncoding:
    """ExtractorConfig.__post_init__ encoding defaults."""

    def test_sysmon4linux_sets_latin1(self):
        cfg = ExtractorConfig(sysmon4linux=True)
        assert cfg.encoding == "ISO-8859-1"

    def test_auditd_sets_utf8(self):
        cfg = ExtractorConfig(auditd_logs=True)
        assert cfg.encoding == "utf-8"

    def test_xml_sets_utf8(self):
        cfg = ExtractorConfig(xml_logs=True)
        assert cfg.encoding == "utf-8"

    def test_evtxtract_sets_utf8(self):
        cfg = ExtractorConfig(evtxtract=True)
        assert cfg.encoding == "utf-8"

    def test_explicit_encoding_not_overridden(self):
        cfg = ExtractorConfig(sysmon4linux=True, encoding="utf-16")
        assert cfg.encoding == "utf-16"

    def test_plain_evtx_has_no_encoding(self):
        cfg = ExtractorConfig()
        assert cfg.encoding is None

    def test_csv_input_no_default_encoding(self):
        cfg = ExtractorConfig(csv_input=True)
        assert cfg.encoding is None

    def test_strict_evtx_default_false(self):
        cfg = ExtractorConfig()
        assert cfg.strict_evtx is False

    def test_strict_evtx_set_true(self):
        cfg = ExtractorConfig(strict_evtx=True)
        assert cfg.strict_evtx is True


# =============================================================================
# RulesetConfig
# =============================================================================


class TestRulesetConfig:
    """RulesetConfig defaults and field types."""

    def test_defaults(self):
        cfg = RulesetConfig()
        assert cfg.ruleset == []
        assert cfg.pipeline is None
        assert cfg.save_ruleset is False

    def test_custom_ruleset(self):
        cfg = RulesetConfig(ruleset=["a.json", "b.json"], save_ruleset=True)
        assert cfg.ruleset == ["a.json", "b.json"]
        assert cfg.save_ruleset is True


# =============================================================================
# TemplateConfig
# =============================================================================


class TestTemplateConfig:
    """TemplateConfig defaults and list independence."""

    def test_defaults(self):
        cfg = TemplateConfig()
        assert cfg.template == []
        assert cfg.template_output == []
        assert cfg.time_field == ""

    def test_list_independence(self):
        a = TemplateConfig()
        b = TemplateConfig()
        a.template.append(["x.tmpl"])
        assert b.template == []


# =============================================================================
# GuiConfig
# =============================================================================


class TestGuiConfig:
    """GuiConfig defaults."""

    def test_defaults(self):
        cfg = GuiConfig()
        assert cfg.package_dir == ""
        assert cfg.template_file == ""
        assert cfg.time_field == ""


# =============================================================================
# ProcessingConfig defaults
# =============================================================================


class TestProcessingConfigDefaults:
    """ProcessingConfig default values."""

    def test_time_boundaries(self):
        cfg = ProcessingConfig()
        assert cfg.time_after == "1970-01-01T00:00:00"
        assert cfg.time_before == "9999-12-12T23:59:59"

    def test_batch_size_default(self):
        cfg = ProcessingConfig()
        assert cfg.batch_size == 5000

    def test_limit_default_negative_one(self):
        cfg = ProcessingConfig()
        assert cfg.limit == -1

    def test_add_index_remove_index_default_empty(self):
        cfg = ProcessingConfig()
        assert cfg.add_index == []
        assert cfg.remove_index == []

    def test_strict_evtx_default_false(self):
        cfg = ProcessingConfig()
        assert cfg.strict_evtx is False

    def test_strict_evtx_set_true(self):
        cfg = ProcessingConfig(strict_evtx=True)
        assert cfg.strict_evtx is True
