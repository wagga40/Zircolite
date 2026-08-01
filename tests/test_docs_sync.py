"""Fail the build when the documentation and the code disagree.

CLAUDE.md asks for docs to be updated alongside behaviour, and README/Usage
carry hand-written tables of every flag and every YAML key. Conventions do not
survive contact with a busy afternoon: the audit that prompted these tests
found a flag table missing four short forms, a CLI-only list missing one of its
own entries, and a supported-versions table two minor releases behind.

Everything here is derived from the code at run time, so the failure message
names exactly what to add.
"""

import argparse
import contextlib
import re
import sys
from pathlib import Path

import pytest

WORKSPACE_ROOT = Path(__file__).parent.parent
DOCS = WORKSPACE_ROOT / "docs"
USAGE = DOCS / "Usage.md"

sys.path.insert(0, str(WORKSPACE_ROOT))

from zircolite import __version__  # noqa: E402
from zircolite import cli as zircolite_script  # noqa: E402
from zircolite.config_loader import SECTIONS  # noqa: E402
from zircolite.run_config import SETTINGS  # noqa: E402


def all_option_strings() -> set[str]:
    """Every flag argparse accepts, short forms included."""
    return {flag for action in _parser_actions() for flag in action.option_strings}


class _Stop(Exception):
    """Unwind out of parse_args once the built parser has been captured."""


USAGE_TEXT = USAGE.read_text(encoding="utf-8")
ALL_DOCS_TEXT = "\n".join(
    p.read_text(encoding="utf-8")
    for p in [*sorted(DOCS.glob("*.md")), WORKSPACE_ROOT / "README.md"]
)

# The generated run-configuration template is the documented reference for the
# YAML schema -- Usage.md says so, and it is committed and tested against the
# generator -- so a key described only there is described.
CONFIG_REFERENCE_TEXT = (
    WORKSPACE_ROOT / "config" / "zircolite_example.yaml"
).read_text(encoding="utf-8")
YAML_DOCS_TEXT = ALL_DOCS_TEXT + "\n" + CONFIG_REFERENCE_TEXT


class TestEveryFlagIsDocumented:
    """A flag users can type has to appear in the reference."""

    def test_no_undocumented_flag(self):
        documented = set(re.findall(r"`(--?[A-Za-z0-9][\w-]*)`", ALL_DOCS_TEXT))
        missing = sorted(all_option_strings() - documented)
        assert missing == [], (
            "these flags exist but appear nowhere in docs/ or README.md: "
            f"{missing}"
        )

    def test_no_documented_flag_that_does_not_exist(self):
        """Catches a flag renamed in the code and left behind in the docs."""
        # Only Usage.md's option tables: prose elsewhere quotes other tools'
        # switches (sigma-cli's -t, PowerShell's -enc) that are not ours.
        table_rows = re.findall(r"^\|\s*(`-[^|]+?`)\s*\|", USAGE_TEXT, re.MULTILINE)
        documented = {
            flag
            for row in table_rows
            for flag in re.findall(r"`(--?[A-Za-z0-9][\w-]*)`", row)
        }
        unknown = sorted(documented - all_option_strings())
        assert unknown == [], (
            f"docs/Usage.md documents flags the code does not define: {unknown}"
        )


class TestYamlKeysAreDocumented:
    """Every accepted `section.key` is described somewhere in the docs."""

    def test_every_settings_key_appears(self):
        missing = sorted(
            f"{setting.section}.{setting.key}"
            for setting in SETTINGS
            if setting.key and setting.key not in YAML_DOCS_TEXT
        )
        assert missing == [], f"undocumented YAML keys: {missing}"

    def test_every_dataclass_field_appears(self):
        from dataclasses import fields as dc_fields

        missing = sorted(
            f"{section}.{f.name}"
            for section, cls in SECTIONS.items()
            for f in dc_fields(cls)
            if f.name not in YAML_DOCS_TEXT
        )
        assert missing == [], f"undocumented configuration keys: {missing}"


class TestCliOnlyListIsComplete:
    """The list of options with no YAML equivalent has to be the real list."""

    SENTENCE = re.compile(
        r"Some options have no equivalent key and must be passed on the command line:(.+?)\.\n",
        re.DOTALL,
    )

    def test_every_cli_only_option_is_listed(self):
        match = self.SENTENCE.search(USAGE_TEXT)
        assert match, "the CLI-only sentence in docs/Usage.md moved or was removed"
        listed = set(re.findall(r"`(--?[A-Za-z0-9][\w-]*)`", match.group(1)))

        has_yaml = {setting.dest for setting in SETTINGS}
        # Format flags are covered by `input.format`, not by a SETTINGS row.
        from zircolite.formats import INPUT_FORMATS

        format_flags = {spec.args_flag for spec in INPUT_FORMATS}

        parser_actions = {}
        for action in _parser_actions():
            parser_actions[action.dest] = action.option_strings

        missing = sorted(
            dest
            for dest, flags in parser_actions.items()
            if dest not in has_yaml
            and dest not in format_flags
            and dest not in {"help", "csv", "template", "templateOutput", "evtx"}
            and not (set(flags) & listed)
        )
        assert missing == [], (
            "these options have no YAML key and are not named in the CLI-only "
            f"list in docs/Usage.md: {missing}"
        )


def _parser_actions():
    """The argparse actions, captured without letting parse_arguments exit.

    parse_arguments() both builds the parser and parses sys.argv, so the parser
    is intercepted on its way into parse_args rather than rebuilt here -- a
    second copy would be exactly the drift these tests exist to catch.
    """
    with pytest.MonkeyPatch.context() as mp:
        captured: dict = {}

        def capture(self, *args, **kwargs):
            captured["parser"] = self
            raise _Stop

        mp.setattr(argparse.ArgumentParser, "parse_args", capture)
        mp.setattr(sys, "argv", ["zircolite.py"])
        with contextlib.suppress(_Stop):
            zircolite_script.parse_arguments()
        return [a for a in captured["parser"]._actions if a.dest != "help"]


class TestVersionHasOneSource:
    """No document may carry the version literal; they must reference it."""

    @pytest.mark.parametrize(
        "doc", ["docs/README.md", "README.md", "docs/Usage.md", "docs/Advanced.md",
                "docs/Internals.md"]
    )
    def test_docs_do_not_pin_the_version(self, doc):
        text = (WORKSPACE_ROOT / doc).read_text(encoding="utf-8")
        assert __version__ not in text, (
            f"{doc} duplicates the version literal; reference it instead"
        )

    def test_security_policy_names_the_current_release_line(self):
        """SECURITY.md sat two minor versions behind for months."""
        text = (WORKSPACE_ROOT / "SECURITY.md").read_text(encoding="utf-8")
        major_minor = ".".join(__version__.split(".")[:2])
        assert f"{major_minor}.x" in text, (
            f"SECURITY.md does not list {major_minor}.x as supported"
        )
