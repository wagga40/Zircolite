"""
Resolution of the files Zircolite ships with itself.

``config/``, ``rules/``, ``templates/`` and ``gui/`` ship with Zircolite and the
paths pointing at them are relative, so they have to resolve whatever the working
directory is.

These helpers live in their own module rather than in ``cli.py`` because
``config_loader`` needs them too, and ``config_loader`` cannot import ``cli`` --
``cli`` imports it in turn, and nothing inside the package may import ``cli``
anyway.

Only the standard library is imported here, so this module sits at the bottom of
the package's import graph.
"""

import os
import sys
from pathlib import Path


def asset_roots() -> list[Path]:
    """The directories a shipped asset can live in, most specific first."""
    # A PyInstaller build unpacks config/, rules/, templates/ and gui/ into a
    # temporary directory the bootloader names, but the release archive also
    # ships them beside the binary, where a user can edit a rule or drop in a
    # newer Mini-GUI. Prefer that copy, fall back to the bundle.
    roots: list[Path] = []
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root is not None:
        roots.append(Path(sys.executable).resolve().parent)
        roots.append(Path(frozen_root))
    roots.append(Path(__file__).resolve().parent.parent)
    return roots


def bundled_asset(*parts: str) -> Path:
    """Resolve a file shipped with Zircolite, independent of the current directory."""
    # When neither root holds the file, name the editable location -- it is the
    # only one of the two a user can do anything about.
    roots = asset_roots()
    for root in roots:
        candidate = root.joinpath(*parts)
        if candidate.is_file():
            return candidate
    return roots[0].joinpath(*parts)


def bundled_path(*parts: str) -> Path:
    """Resolve a shipped file *or* directory, independent of the current directory."""
    roots = asset_roots()
    for root in roots:
        candidate = root.joinpath(*parts)
        if candidate.exists():
            return candidate
    return roots[0].joinpath(*parts)


def bundled_dir(*parts: str) -> Path:
    """Resolve a shipped directory to write into.

    Unlike :func:`bundled_asset` this names a directory rather than a file inside
    one, so an existing writable directory wins and, failing that, the first root
    that can be written to -- ``-U`` has to create ``rules/`` the first time it
    runs. When no root can be written to, the caller is expected to fall back.
    """
    roots = asset_roots()
    for root in roots:
        candidate = root.joinpath(*parts)
        if candidate.is_dir() and os.access(candidate, os.W_OK):
            return candidate
    for root in roots:
        if root.is_dir() and os.access(root, os.W_OK):
            return root.joinpath(*parts)
    return roots[0].joinpath(*parts)


def resolve_default_path(value: str, *parts: str) -> str:
    """Fall back to the bundled copy of a default path when it is not in the CWD.

    Defaults such as ``config/config.yaml`` are relative, so they only resolve
    when Zircolite runs from its own directory. A file of the same name in the
    working directory still wins, keeping local overrides working.
    """
    if Path(value).is_file():
        return value
    bundled = bundled_asset(*parts)
    return str(bundled) if bundled.is_file() else value


def resolve_asset_path(value: str, *parts: str) -> str:
    """Same as :func:`resolve_default_path` for values that may name a directory.

    ``--ruleset`` takes either a ruleset file or a directory of native Sigma
    YAML, so testing for a file alone would leave every bundled directory
    unresolved and report it as missing.
    """
    if Path(value).exists():
        return value
    bundled = bundled_path(*parts)
    return str(bundled) if bundled.exists() else value


def _needs_fallback(value: str, directory: str) -> bool:
    """True when *value* is a relative path under *directory* that the CWD lacks.

    Only a value already rooted at the shipped directory may fall back to it.
    ``-r myrules/windows.json`` must keep reporting that it is missing rather
    than quietly loading ``rules/windows.json``, which is a different ruleset.
    """
    path = Path(value)
    return (
        not path.is_absolute()
        and not path.exists()
        and path.parent == Path(directory)
    )


def resolve_shipped_ruleset(value: str) -> str:
    """Resolve ``rules/...`` against the install when the CWD has no ``rules/``.

    A ruleset is either a JSON file or a directory of native Sigma YAML, so this
    resolves on existence rather than on being a file.
    """
    if _needs_fallback(value, "rules"):
        return resolve_asset_path(value, "rules", Path(value).name)
    return value


def resolve_shipped_template(value: str) -> str:
    """Resolve ``templates/...`` against the install when the CWD has none."""
    if _needs_fallback(value, "templates"):
        return resolve_default_path(value, "templates", Path(value).name)
    return value
