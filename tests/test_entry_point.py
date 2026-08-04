"""The entry point must stay a shim.

mypy is pointed at the ``zircolite`` package and cannot also be pointed at
``zircolite.py``: the two share a module name, and passing both makes mypy
abort with "Duplicate module named zircolite" without checking anything at all.
So whatever lives in ``zircolite.py`` is checked by nothing. It held the whole
CLI that way for as long as it existed. These tests keep it at zero.

The asset tests are here for a related reason: ``bundled_asset`` moved one
directory deeper with the CLI, and then out of it again into ``assets``.
``test_cli.py`` already drives that path through whole runs from a foreign
directory; these pin the resolved path itself, so a failure names the wrong
directory instead of reporting a run that produced no output. The frozen branch
has no other coverage at all -- the binaries are built only on release.
"""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from zircolite import assets

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

    resolved = assets.bundled_asset(*parts)

    assert resolved == WORKSPACE_ROOT.resolve().joinpath(*parts)
    assert resolved.is_file(), f"{resolved} does not exist"


def test_bundled_asset_uses_the_bootloader_root_when_frozen(tmp_path, monkeypatch):
    """A PyInstaller build unpacks the data beside the bootloader, not beside the module."""
    unpacked = tmp_path / "unpacked"
    (unpacked / "config").mkdir(parents=True)
    (unpacked / "config" / "config.yaml").write_text("", encoding="utf-8")
    beside = tmp_path / "beside"
    beside.mkdir()

    monkeypatch.setattr(sys, "executable", str(beside / "Zircolite"))
    monkeypatch.setattr(sys, "_MEIPASS", str(unpacked), raising=False)

    resolved = assets.bundled_asset("config", "config.yaml")

    assert resolved == unpacked / "config" / "config.yaml"


def test_bundled_asset_prefers_the_copy_beside_the_binary(tmp_path, monkeypatch):
    """The release archive ships gui/ and rules/ beside the binary so they can be edited."""
    unpacked = tmp_path / "unpacked"
    beside = tmp_path / "beside"
    for root in (unpacked, beside):
        (root / "gui").mkdir(parents=True)
        (root / "gui" / "zircogui.zip").write_bytes(b"")

    monkeypatch.setattr(sys, "executable", str(beside / "Zircolite"))
    monkeypatch.setattr(sys, "_MEIPASS", str(unpacked), raising=False)

    resolved = assets.bundled_asset("gui", "zircogui.zip")

    assert resolved == beside / "gui" / "zircogui.zip"


def test_bundled_asset_names_a_path_a_user_can_act_on_when_nothing_holds_the_file(tmp_path, monkeypatch):
    """The caller prints this path; a temporary _MEIxxxx directory tells a user nothing."""
    unpacked = tmp_path / "unpacked"
    unpacked.mkdir()
    beside = tmp_path / "beside"
    beside.mkdir()

    monkeypatch.setattr(sys, "executable", str(beside / "Zircolite"))
    monkeypatch.setattr(sys, "_MEIPASS", str(unpacked), raising=False)

    # A name no root can hold. Asking for a real asset would find the source
    # tree, which is the third root here but is inside _MEIPASS in a real build.
    resolved = assets.bundled_asset("gui", "no-such-archive.zip")

    assert resolved == beside / "gui" / "no-such-archive.zip"
    assert not resolved.is_file()


def _pretend_frozen(monkeypatch, beside: Path, unpacked: Path) -> None:
    monkeypatch.setattr(sys, "executable", str(beside / "Zircolite"))
    monkeypatch.setattr(sys, "_MEIPASS", str(unpacked), raising=False)


def test_a_bundled_ruleset_directory_resolves(tmp_path, monkeypatch):
    """--ruleset also takes a directory of native Sigma YAML, and is_file() rejects those."""
    beside = tmp_path / "beside"
    (beside / "rules" / "sigma").mkdir(parents=True)
    _pretend_frozen(monkeypatch, beside, tmp_path / "unpacked")
    monkeypatch.chdir(tmp_path)

    assert assets.resolve_default_path("rules/sigma", "rules", "sigma") == "rules/sigma"
    assert assets.resolve_shipped_ruleset("rules/sigma") == str(beside / "rules" / "sigma")


def test_a_ruleset_outside_the_shipped_directory_is_left_alone(tmp_path, monkeypatch):
    """`-r myrules/x.json` must report itself missing, not load rules/x.json."""
    beside = tmp_path / "beside"
    (beside / "rules").mkdir(parents=True)
    (beside / "rules" / "windows.json").write_text("[]", encoding="utf-8")
    _pretend_frozen(monkeypatch, beside, tmp_path / "unpacked")
    monkeypatch.chdir(tmp_path)

    assert assets.resolve_shipped_ruleset("myrules/windows.json") == "myrules/windows.json"
    assert assets.resolve_shipped_ruleset("rules/windows.json") == str(
        beside / "rules" / "windows.json"
    )


def test_bundled_dir_prefers_the_copy_beside_the_binary(tmp_path, monkeypatch):
    """-U has to write where the next run will read, and that is the editable copy."""
    beside, unpacked = tmp_path / "beside", tmp_path / "unpacked"
    for root in (beside, unpacked):
        (root / "rules").mkdir(parents=True)
    _pretend_frozen(monkeypatch, beside, unpacked)

    assert assets.bundled_dir("rules") == beside / "rules"


def test_bundled_dir_skips_a_directory_it_cannot_write_to(tmp_path, monkeypatch):
    """_MEIPASS is writable but a read-only install directory is not."""
    beside, unpacked = tmp_path / "beside", tmp_path / "unpacked"
    for root in (beside, unpacked):
        (root / "rules").mkdir(parents=True)
    _pretend_frozen(monkeypatch, beside, unpacked)
    # Permissions are not a reliable signal: CI containers run as root.
    monkeypatch.setattr(
        assets.os, "access", lambda path, mode: Path(path) != beside / "rules"
    )

    assert assets.bundled_dir("rules") == unpacked / "rules"


@pytest.mark.parametrize("argv", [
    [sys.executable, str(ENTRY_POINT), "--help"],
    [sys.executable, "-m", "zircolite", "--help"],
])
def test_both_invocations_reach_the_same_cli(argv):
    result = subprocess.run(
        argv, capture_output=True, text=True, encoding="utf-8", cwd=str(WORKSPACE_ROOT)
    )

    assert result.returncode == 0, result.stderr
    assert "--ruleset" in result.stdout


def test_the_entry_point_runs_from_another_directory(tmp_path):
    """sys.path[0] is the script's directory, not the CWD, so the package still imports."""
    result = subprocess.run(
        [sys.executable, str(ENTRY_POINT), "-v"],
        capture_output=True, text=True, encoding="utf-8", cwd=str(tmp_path),
    )

    assert result.returncode == 0, result.stderr


def _spec_bundled_directories() -> set[str]:
    """Destination names in the literal ``datas = [...]`` of Zircolite.spec.

    The ``datas += collect_all(...)`` lines below it carry third-party payloads
    resolved at build time, not Zircolite's own assets, so they are not read.
    """
    spec = ast.parse((WORKSPACE_ROOT / "Zircolite.spec").read_text(encoding="utf-8"))

    for node in spec.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "datas" for target in node.targets):
            continue
        assert isinstance(node.value, ast.List), (
            "datas must stay a list literal, otherwise nothing here can read it"
        )
        names = set()
        for element in node.value.elts:
            assert isinstance(element, ast.Tuple) and len(element.elts) == 2, (
                "every datas entry must stay a (source, destination) pair"
            )
            destination = element.elts[1]
            assert isinstance(destination, ast.Constant) and isinstance(destination.value, str)
            names.add(destination.value)
        return names

    raise AssertionError("Zircolite.spec has no top-level `datas = [...]` assignment")


def _asset_directories_the_code_asks_for() -> tuple[set[str], list[str]]:
    """Top-level directories the package resolves through the asset helpers.

    The ``bundled_*`` helpers take the directory first; the ``resolve_*`` ones
    take the relative default first and the directory second. Forwarding calls
    that pass ``*parts`` are skipped.

    Every helper that accepts a directory must be listed here. One that is not
    resolves whatever it likes without the spec ever being consulted, which is
    how ``gui/`` went missing.
    """
    positions = {
        "bundled_asset": 0,
        "bundled_path": 0,
        "bundled_dir": 0,
        "resolve_default_path": 1,
        "resolve_asset_path": 1,
    }
    wanted: set[str] = set()
    unreadable: list[str] = []

    for module in sorted((WORKSPACE_ROOT / "zircolite").glob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            index = positions.get(node.func.id)
            if index is None or len(node.args) <= index:
                continue
            argument = node.args[index]
            if isinstance(argument, ast.Starred):
                continue
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                wanted.add(argument.value)
            else:
                unreadable.append(f"{module.name}:{node.lineno}")

    return wanted, unreadable


def test_every_asset_the_code_asks_for_is_bundled():
    """A directory reachable through the asset helpers but absent from the spec
    resolves to nothing in a PyInstaller build. gui/ was missing that way and
    --package failed in every binary ever shipped."""
    wanted, unreadable = _asset_directories_the_code_asks_for()

    assert not unreadable, (
        "asset helper called with a computed directory at "
        f"{', '.join(unreadable)}; this test can no longer tell what needs bundling"
    )
    assert wanted, "no asset helper call sites found, so the scan is broken, not clean"

    missing = wanted - _spec_bundled_directories()

    assert not missing, (
        f"Zircolite.spec does not bundle {sorted(missing)}; a PyInstaller build "
        "cannot resolve them and whatever needs them fails at runtime"
    )
