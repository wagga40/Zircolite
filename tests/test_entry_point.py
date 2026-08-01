"""The entry point must stay a shim.

mypy is pointed at the ``zircolite`` package and cannot also be pointed at
``zircolite.py``: the two share a module name, and passing both makes mypy
abort with "Duplicate module named zircolite" without checking anything at all.
So whatever lives in ``zircolite.py`` is checked by nothing. It held the whole
CLI that way for as long as it existed. These tests keep it at zero.

The asset tests are here for a related reason: ``_bundled_asset`` moved one
directory deeper with the CLI. ``test_cli.py`` already drives that path through
whole runs from a foreign directory; these pin the resolved path itself, so a
failure names the wrong directory instead of reporting a run that produced no
output. The frozen branch has no other coverage at all -- the binaries are
built only on release.
"""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from zircolite import cli as zircolite_cli

WORKSPACE_ROOT = Path(__file__).parent.parent
ENTRY_POINT = WORKSPACE_ROOT / "zircolite.py"


def test_the_entry_point_holds_no_logic():
    """Anything added here would ship unchecked, so nothing may be added here."""
    body = ast.parse(ENTRY_POINT.read_text(encoding="utf-8")).body

    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]  # module docstring

    assert len(body) == 2, (
        "zircolite.py must contain only the import and the __main__ guard; found "
        f"{[type(node).__name__ for node in body]}"
    )

    imported, guard = body

    assert isinstance(imported, ast.ImportFrom)
    assert imported.module == "zircolite.cli"
    assert [alias.name for alias in imported.names] == ["main"]

    assert isinstance(guard, ast.If)
    assert isinstance(guard.test, ast.Compare)
    assert ast.unparse(guard.test.left) == "__name__"
    assert [node.value for node in guard.test.comparators] == ["__main__"]
    assert [ast.unparse(stmt) for stmt in guard.body] == ["main()"]


@pytest.mark.parametrize("parts", [
    ("config", "config.yaml"),
    ("rules", "rules_windows_generic.json"),
    ("templates", "exportForZircoGui.tmpl"),
    ("gui", "zircogui.zip"),
])
def test_bundled_assets_resolve_from_another_directory(parts, tmp_path, monkeypatch):
    """The defaults are relative paths, so a run from elsewhere must still find them."""
    monkeypatch.chdir(tmp_path)

    resolved = zircolite_cli._bundled_asset(*parts)

    assert resolved == WORKSPACE_ROOT.resolve().joinpath(*parts)
    assert resolved.is_file(), f"{resolved} does not exist"


def test_bundled_asset_uses_the_bootloader_root_when_frozen(tmp_path, monkeypatch):
    """A PyInstaller build unpacks the data beside the bootloader, not beside the module."""
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    assert zircolite_cli._bundled_asset("config", "config.yaml") == tmp_path / "config" / "config.yaml"


@pytest.mark.parametrize("argv", [
    [sys.executable, str(ENTRY_POINT), "--help"],
    [sys.executable, "-m", "zircolite", "--help"],
])
def test_both_invocations_reach_the_same_cli(argv):
    result = subprocess.run(argv, capture_output=True, text=True, cwd=str(WORKSPACE_ROOT))

    assert result.returncode == 0, result.stderr
    assert "--ruleset" in result.stdout


def test_the_entry_point_runs_from_another_directory(tmp_path):
    """sys.path[0] is the script's directory, not the CWD, so the package still imports."""
    result = subprocess.run(
        [sys.executable, str(ENTRY_POINT), "-v"],
        capture_output=True, text=True, cwd=str(tmp_path),
    )

    assert result.returncode == 0, result.stderr
