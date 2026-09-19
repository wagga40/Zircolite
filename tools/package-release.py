#!/usr/bin/env python3
"""Turn the PyInstaller onedir build into a release archive.

    ZIRCOLITE_TARGET=linux-x64 pdm run python tools/package-release.py
    pdm run python tools/package-release.py --check-tag vX.Y.Z

The first form stages dist/Zircolite-<version>-<target>/ -- the onedir build,
editable copies of config/, rules/, templates/ and gui/, the documentation,
LICENSE and a generated THIRD_PARTY_LICENSES -- and writes it to
dist/Zircolite-<version>-<target>.zip. The archive path is the only thing
printed on stdout.

The second checks a release tag against every place the version is written
down, including what the built binary reports.

It needs the standard library, plus `packaging` to evaluate environment
markers while it gathers the licences. PyInstaller depends on `packaging`, so
any environment that can build the binary has it. Versions are read with
regexes rather than tomllib, which Python 3.10 lacks.
"""

from __future__ import annotations

import argparse
import importlib.metadata as metadata
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath

TARGETS = ("linux-x64", "linux-arm64", "macos-arm64", "windows-x64", "windows-arm64")
REPO_ROOT = Path(__file__).resolve().parent.parent
VENDORED_LICENCES = Path(__file__).resolve().parent / "licenses"
RULES_LICENCE = "DRL-1.1.txt"
# CPython's LICENSE.txt appends these libraries' notices on Windows only.
RUNTIME_LIBRARIES_LICENCE = "python-runtime-libraries.txt"

ONEDIR = "Zircolite"
# Shipped outside the bundle so users can edit them; the binary prefers these
# over its own copies.
EDITABLE_ASSETS = ("config", "rules", "templates", "gui")
DOCUMENTATION = ("docs", "pics")
TOP_LEVEL_FILES = ("README.md", "LICENSE")
ASSET_CLUTTER = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")

# jq backs a single pySigma transformation Zircolite never uses, and it cannot
# be built for Windows on ARM, so that build is the one allowed to lack it.
ALLOWED_ABSENT = {"windows-arm64": frozenset({"jq"})}

# PyInstaller's runtime hooks come from the contrib package and end up inside
# the executable next to the bootloader.
BUILD_TOOLS = ("pyinstaller", "pyinstaller-hooks-contrib")

LICENCE_NAME = re.compile(r"(licen[cs]e|copying|notice|authors)", re.IGNORECASE)
VERSION_LINE = re.compile(r"Zircolite - v(\S+)")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
SAFE_VERSION = re.compile(r"[0-9][0-9A-Za-z.+!-]*")
SEPARATOR = "=" * 79


class PackagingError(Exception):
    """A condition that must stop the release rather than produce a partial one."""


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------

def package_version(root: Path) -> str:
    """__version__ from zircolite/__init__.py, read without importing the package."""
    source = root / "zircolite" / "__init__.py"
    match = re.search(r"""^__version__\s*=\s*["']([^"']+)["']""",
                      source.read_text(encoding="utf-8"), re.MULTILINE)
    if not match:
        raise PackagingError(f"no __version__ assignment in {source}")
    version = match.group(1)
    if not SAFE_VERSION.fullmatch(version):
        raise PackagingError(f"{source} declares an unusable version {version!r}")
    return version


def pyproject_version(root: Path) -> str:
    """The [project] version. A regex, because tomllib only arrived in 3.11."""
    source = root / "pyproject.toml"
    table = re.search(r"^\[project\][ \t]*$(.*?)(?=^\[|\Z)",
                      source.read_text(encoding="utf-8"), re.MULTILINE | re.DOTALL)
    if not table:
        raise PackagingError(f"no [project] table in {source}")
    match = re.search(r"""^version\s*=\s*["']([^"']+)["']""", table.group(1), re.MULTILINE)
    if not match:
        raise PackagingError(f"no version in the [project] table of {source}")
    return match.group(1)


def version_from_output(output: str) -> str:
    """Pick the version out of `Zircolite --version`, which also prints a banner."""
    match = VERSION_LINE.search(ANSI_ESCAPE.sub("", output))
    if not match:
        raise PackagingError(f"no 'Zircolite - v<version>' line in the output:\n{output}")
    return match.group(1)


def binary_version(executable: Path) -> str:
    if not executable.is_file():
        raise PackagingError(f"{executable} does not exist; build it with "
                             "`pdm run pyinstaller --noconfirm Zircolite.spec`")
    # A scratch directory, because the binary writes its log file to the CWD.
    with tempfile.TemporaryDirectory(prefix="zircolite-version-") as scratch:
        try:
            result = subprocess.run(  # noqa: S603 -- our own build, run with fixed arguments
                [str(executable), "--version"], cwd=scratch, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=300,
                env={**os.environ, "NO_COLOR": "1"}, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PackagingError(f"could not run {executable} --version: {error}") from error
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise PackagingError(f"{executable} --version exited {result.returncode}:\n{output}")
    return version_from_output(output)


def check_tag(tag: str, root: Path, executable: Path) -> None:
    sources = {
        "zircolite/__init__.py __version__": package_version(root),
        "pyproject.toml [project] version": pyproject_version(root),
        f"{executable} --version": binary_version(executable),
    }
    mismatches = [f"  {where}: {version}"
                  for where, version in sources.items() if tag != f"v{version}"]
    if mismatches:
        raise PackagingError(f"tag {tag!r} does not match:\n" + "\n".join(mismatches))


# --------------------------------------------------------------------------
# Environment markers (PEP 508)
# --------------------------------------------------------------------------

def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def marker_environment() -> dict[str, str]:
    implementation = sys.implementation.version
    implementation_version = f"{implementation.major}.{implementation.minor}.{implementation.micro}"
    if implementation.releaselevel != "final":
        implementation_version += f"{implementation.releaselevel[0]}{implementation.serial}"
    return {
        "implementation_name": sys.implementation.name,
        "implementation_version": implementation_version,
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_python_implementation": platform.python_implementation(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "python_version": ".".join(platform.python_version_tuple()[:2]),
        "sys_platform": sys.platform,
        "extra": "",
    }


def evaluate_marker(marker: str, environment: dict[str, str]) -> bool:
    # Imported here so that reading versions and checking a tag need nothing
    # outside the standard library.
    from packaging.markers import (
        InvalidMarker,
        Marker,
        UndefinedComparison,
        UndefinedEnvironmentName,
    )

    try:
        return Marker(marker).evaluate(environment)
    # Before packaging 26.3, a name missing from the environment raised a bare KeyError.
    except (InvalidMarker, UndefinedComparison, UndefinedEnvironmentName, KeyError) as error:
        raise PackagingError(f"cannot evaluate marker {marker!r}: {error}") from error


# --------------------------------------------------------------------------
# Third-party licences
# --------------------------------------------------------------------------

REQUIREMENT = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([^\]]*)\])?")


def parse_requirement(line: str) -> tuple[str, frozenset[str], str | None]:
    """Name, requested extras and marker of one Requires-Dist entry."""
    specification, _, marker = line.partition(";")
    match = REQUIREMENT.match(specification)
    if not match:
        raise PackagingError(f"cannot parse requirement {line!r}")
    extras = frozenset(canonical_name(extra.strip())
                       for extra in (match.group(2) or "").split(",") if extra.strip())
    return match.group(1), extras, marker.strip() or None


def runtime_closure(
    root_name: str,
    allowed_absent: frozenset[str] = frozenset(),
    lookup: Callable[[str], metadata.Distribution] = metadata.distribution,
) -> list[metadata.Distribution]:
    """Every installed distribution `root_name` needs at run time, root excluded.

    Requirements guarded by an extra nobody asked for are skipped; other markers
    are evaluated for this interpreter. A required distribution that is not
    installed is an error unless `allowed_absent` names it.
    """
    environment = marker_environment()
    found: dict[str, metadata.Distribution] = {}
    missing: list[str] = []
    visited: set[tuple[str, frozenset[str]]] = set()
    pending: list[tuple[str, frozenset[str], str]] = [(root_name, frozenset(), "")]
    while pending:
        name, extras, required_by = pending.pop()
        key = canonical_name(name)
        if (key, extras) in visited:
            continue
        visited.add((key, extras))
        distribution = found.get(key)
        if distribution is None:
            try:
                distribution = lookup(name)
            except metadata.PackageNotFoundError:
                if key not in allowed_absent:
                    missing.append(f"{name} (required by {required_by})" if required_by
                                   else f"{name} (the project itself; run `pdm install`)")
                continue
            found[key] = distribution
        for requirement in distribution.requires or ():
            requirement_name, requirement_extras, marker = parse_requirement(requirement)
            if marker is None or any(
                evaluate_marker(marker, {**environment, "extra": extra}) for extra in ("", *extras)
            ):
                pending.append((requirement_name, requirement_extras, name))
    if missing:
        raise PackagingError(
            "not installed in this environment: " + ", ".join(sorted(missing))
            + ". Package from the environment dist/Zircolite was built in."
        )
    found.pop(canonical_name(root_name), None)
    return sorted(found.values(), key=lambda dist: canonical_name(dist.metadata["Name"]))


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n").strip()


def shipped_licences(distribution: metadata.Distribution) -> list[tuple[str, str]]:
    """(name, text) of each licence file in the distribution's own metadata directory.

    That is what License-File declares, plus anything under licenses/ or named
    like a licence. Licences of projects the distribution vendors live in its
    package directories and are left to its own licence file to cover.
    """
    texts: dict[str, str] = {}
    declared = distribution.metadata.get_all("License-File") or []
    if distribution.files is not None:
        for file in distribution.files:
            parts = PurePosixPath(file.as_posix()).parts
            if len(parts) < 2 or not parts[0].endswith((".dist-info", ".egg-info")):
                continue
            inside = PurePosixPath(*parts[1:]).as_posix()
            if (parts[1] == "licenses" or inside in declared
                    or (len(parts) == 2 and LICENCE_NAME.match(parts[1]))):
                texts[inside] = _decode(file.read_binary())
    else:
        for entry in declared:
            for candidate in (f"licenses/{entry}", entry):
                text = distribution.read_text(candidate)
                if text is not None:
                    texts[candidate] = text.replace("\r\n", "\n").strip()
                    break
    return [(name, text) for name, text in sorted(texts.items()) if text]


def declared_licence(distribution: metadata.Distribution) -> str | None:
    fields = distribution.metadata
    expression = (fields.get_all("License-Expression") or [""])[0].strip()
    if expression:
        return expression
    # Some projects paste their whole licence into this field.
    licence = (fields.get_all("License") or [""])[0].strip()
    if licence and "\n" not in licence and len(licence) <= 80:
        return licence
    classifiers = [classifier.split("::")[-1].strip()
                   for classifier in fields.get_all("Classifier") or []
                   if classifier.startswith("License ::")]
    return ", ".join(classifiers) or None


def section(title: str, licence: str | None, texts: list[tuple[str, str]]) -> str:
    header = [SEPARATOR, title]
    if licence:
        header.append(f"License: {licence}")
    header.append(SEPARATOR)
    body = [f"--- {name} ---\n\n{text.strip()}\n" for name, text in texts]
    return "\n".join(header) + "\n\n" + "\n".join(body)


def python_licence() -> Path:
    """The licence of the interpreter PyInstaller bundled, found beside its stdlib."""
    candidates = [
        Path(sysconfig.get_path("stdlib")) / "LICENSE.txt",
        Path(sys.base_prefix) / "LICENSE.txt",
        Path(sys.base_prefix) / "LICENSE",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise PackagingError("the Python licence is not in any of: "
                         + ", ".join(str(candidate) for candidate in candidates))


def vendored(name: str, reason: str) -> tuple[str, str]:
    path = VENDORED_LICENCES / name
    if not path.is_file():
        raise PackagingError(f"{path} is missing ({reason})")
    return f"tools/licenses/{name}", path.read_text(encoding="utf-8").strip()


def distribution_section(distribution: metadata.Distribution) -> str | None:
    """A section for the distribution, or None when it ships no licence and none is vendored."""
    name = distribution.metadata["Name"]
    texts = shipped_licences(distribution)
    if not texts:
        fallback = VENDORED_LICENCES / f"{canonical_name(name)}.txt"
        if not fallback.is_file():
            return None
        texts = [vendored(fallback.name, f"{name} ships no licence file")]
    return section(f"{name} {distribution.version}", declared_licence(distribution), texts)


def third_party_licences(version: str, target: str) -> str:
    parts = [
        f"Third-party software in Zircolite {version} ({target})\n\n"
        "This package contains the Python interpreter and the native libraries it was\n"
        "built with, the PyInstaller bootloader and runtime hooks, and the Python\n"
        "distributions Zircolite depends on. Each section names one of them, with the\n"
        "licence it declares and the licence texts it ships. The rulesets in rules/ are\n"
        "covered by the Detection Rule License in the last section.\n"
    ]

    interpreter = python_licence()
    parts.append(section(f"Python {platform.python_version()} ({platform.python_implementation()})",
                         "Python-2.0", [(interpreter.name, _decode(interpreter.read_bytes()))]))
    if not target.startswith("windows-"):
        parts.append(section("Libraries linked into the Python runtime", None, [
            vendored(RUNTIME_LIBRARIES_LICENCE,
                     "the Python licence on Linux and macOS leaves these notices out"),
        ]))

    for tool in BUILD_TOOLS:
        try:
            distribution = metadata.distribution(tool)
        except metadata.PackageNotFoundError as error:
            raise PackagingError(f"{tool} is not installed; the binary cannot have been "
                                 "built from this environment") from error
        rendered = distribution_section(distribution)
        if rendered is None:
            raise PackagingError(f"{tool} ships no licence file")
        if tool == "pyinstaller" and "bootloader" not in rendered.lower():
            raise PackagingError("the PyInstaller licence no longer mentions the bootloader "
                                 "exception; check what it grants before shipping")
        parts.append(rendered)

    unlicensed = []
    for distribution in runtime_closure("Zircolite", ALLOWED_ABSENT.get(target, frozenset())):
        rendered = distribution_section(distribution)
        if rendered is None:
            unlicensed.append(distribution.metadata["Name"])
        else:
            parts.append(rendered)
    if unlicensed:
        raise PackagingError(
            "no licence text for: " + ", ".join(unlicensed)
            + ". Add tools/licenses/<name>.txt with the text the project publishes."
        )

    parts.append(section("Detection rules (rules/)", "DRL-1.1",
                         [vendored(RULES_LICENCE, "the licence of rules/")]))
    return "\n".join(parts)


# --------------------------------------------------------------------------
# Staging and archiving
# --------------------------------------------------------------------------

def executable_name(target: str) -> str:
    return "Zircolite.exe" if target.startswith("windows-") else "Zircolite"


def resolve_target(value: str | None) -> str:
    if not value:
        raise PackagingError("set ZIRCOLITE_TARGET to one of: " + ", ".join(TARGETS))
    if value not in TARGETS:
        raise PackagingError(f"ZIRCOLITE_TARGET={value!r} is not one of: " + ", ".join(TARGETS))
    return value


def copied_symlinks(root: Path) -> list[Path]:
    """Symlinks among what stage() copies from the checkout.

    The onedir build is not searched: it legitimately holds symlinks on macOS
    (Python.framework) and Linux (to the libraries a wheel keeps in its .libs
    directory).
    """
    found = []
    for name in EDITABLE_ASSETS + DOCUMENTATION + TOP_LEVEL_FILES:
        path = root / name
        if path.is_symlink():
            found.append(path)
        elif path.is_dir():
            found.extend(entry for entry in walk(path) if entry.is_symlink())
    return found


def stage(root: Path, version: str, target: str) -> Path:
    onedir = root / "dist" / ONEDIR
    executable = onedir / executable_name(target)
    build_hint = "build it with `pdm run pyinstaller --noconfirm Zircolite.spec`"
    if not onedir.is_dir():
        raise PackagingError(f"{onedir} does not exist; {build_hint}")
    if not executable.is_file():
        raise PackagingError(f"{executable} does not exist; {build_hint}")
    if not (onedir / "_internal").is_dir():
        raise PackagingError(f"{onedir} has no _internal/ beside the executable: "
                             "that is not a onedir build")

    for directory in EDITABLE_ASSETS + DOCUMENTATION:
        if not (root / directory).is_dir():
            raise PackagingError(f"{root / directory} does not exist")
    for name in TOP_LEVEL_FILES:
        if not (root / name).is_file():
            raise PackagingError(f"{root / name} does not exist")
    # Only a Windows archive cannot hold a symlink, but refusing them for every
    # target lets the linux-x64 canary build catch one, rather than the Windows
    # legs of a release.
    links = copied_symlinks(root)
    if links:
        raise PackagingError(
            "symlinks cannot be extracted from the Windows archives, so none is packaged "
            "for any target; replace each with the file it points to: "
            + ", ".join(link.relative_to(root).as_posix() for link in links))
    # Before anything is copied, so a gap in the notices leaves no half-built tree.
    notices = third_party_licences(version, target)

    staging = root / "dist" / f"Zircolite-{version}-{target}"
    if staging.exists():
        shutil.rmtree(staging)
    log(f"Staging {staging}")
    shutil.copytree(onedir, staging, symlinks=True, ignore=shutil.ignore_patterns(".DS_Store"))
    for directory in EDITABLE_ASSETS + DOCUMENTATION:
        shutil.copytree(root / directory, staging / directory, symlinks=True, ignore=ASSET_CLUTTER)
    for name in TOP_LEVEL_FILES:
        shutil.copy2(root / name, staging / name)
    (staging / "THIRD_PARTY_LICENSES").write_text(notices, encoding="utf-8", newline="\n")
    return staging


def walk(directory: Path) -> Iterator[Path]:
    """Every entry under `directory` in a stable order, without following symlinks."""
    for entry in sorted(directory.iterdir(), key=lambda path: path.name):
        yield entry
        if entry.is_dir() and not entry.is_symlink():
            yield from walk(entry)


def source_date_epoch() -> int | None:
    value = os.environ.get("SOURCE_DATE_EPOCH")
    return int(value) if value else None


def _zip_timestamp(path: Path, epoch: int | None) -> tuple[int, int, int, int, int, int]:
    mtime = path.lstat().st_mtime
    if epoch is not None:
        mtime = min(mtime, epoch)
    # Zip timestamps have no time zone and start in 1980.
    return max(time.gmtime(mtime)[:6], (1980, 1, 1, 0, 0, 0))


def write_zip(staging: Path, archive: Path, executable: str, target: str) -> None:
    """Write `staging` as a zip that keeps what a Unix extraction needs.

    unzip and macOS's Archive Utility restore the Unix mode and symlinks that
    an entry records when its "made by" system is Unix, which the executable
    bit and the macOS build's Python.framework links depend on. Windows cannot
    extract a symlink from a zip, and no Windows build has one.
    """
    epoch = source_date_epoch()
    windows = target.startswith("windows-")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in [staging, *walk(staging)]:
            relative = path.relative_to(staging).as_posix()
            name = staging.name if relative == "." else f"{staging.name}/{relative}"
            if path.is_symlink():
                if windows:
                    raise PackagingError(f"{path} is a symlink, which Windows cannot extract "
                                         "from a zip archive")
                info = zipfile.ZipInfo(name, date_time=_zip_timestamp(path, epoch))
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                bundle.writestr(info, os.readlink(path))
                continue
            info = zipfile.ZipInfo.from_file(path, name, strict_timestamps=False)
            info.date_time = _zip_timestamp(path, epoch)
            if not windows:
                # Recorded as Unix whatever the packaging host, so the mode is honoured.
                info.create_system = 3
            if path.is_dir():
                bundle.writestr(info, b"", compress_type=zipfile.ZIP_STORED)
                continue
            # The mode on disk is whatever the checkout or an artifact
            # round-trip left; the executable must come out executable.
            if relative == executable:
                info.external_attr |= 0o755 << 16
            bundle.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                            compresslevel=9)


def package(root: Path, target: str) -> Path:
    version = package_version(root)
    staging = stage(root, version, target)
    archive = staging.with_name(f"{staging.name}.zip")
    archive.unlink(missing_ok=True)
    log(f"Writing {archive}")
    write_zip(staging, archive, executable_name(target), target)
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Package dist/Zircolite as a release archive for the target in ZIRCOLITE_TARGET.")
    parser.add_argument("--check-tag", metavar="TAG",
                        help="only check that TAG is v<version> for the package, pyproject.toml "
                             "and the built binary")
    parser.add_argument("--root", type=Path, default=REPO_ROOT,
                        help="checkout holding dist/Zircolite and the assets (default: this one)")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.check_tag is not None:
            target = os.environ.get("ZIRCOLITE_TARGET")
            name = executable_name(resolve_target(target)) if target else (
                "Zircolite.exe" if os.name == "nt" else "Zircolite")
            check_tag(args.check_tag, root, root / "dist" / ONEDIR / name)
            log(f"Tag {args.check_tag} matches the package, pyproject.toml and the binary")
            return 0
        archive = package(root, resolve_target(os.environ.get("ZIRCOLITE_TARGET")))
    except PackagingError as error:
        log(f"package-release: {error}")
        return 1
    print(archive)
    return 0


if __name__ == "__main__":
    sys.exit(main())
