"""Every locked dependency must install from a wheel wherever the lock is installed.

duckdb 2 publishes cp312-abi3 wheels only. While Python 3.11 was still in the
CI matrix, every 3.11 leg compiled DuckDB from its sdist inside `pdm install`:
50 minutes on Windows, 20 on Linux, and nothing failed. A source build is
invisible until someone reads the timings, so this test makes a lock that
needs one fail on the commit that introduces it.

The targets are the interpreters and platforms that actually install the lock:
the CI test legs, lint, the external-tests image, the release binaries and
Docker. Windows ARM64 is left out: evtx has no wheel there and jq does not
build, which tools/install-win-arm64.py works around.
"""

import re
import tomllib
from pathlib import Path

import pytest
from packaging.markers import Marker
from packaging.tags import Tag, compatible_tags, cpython_tags, mac_platforms
from packaging.utils import parse_wheel_filename

LOCK = Path(__file__).parent.parent / "pdm.lock"

WINDOWS_X64 = {"sys_platform": "win32", "platform_system": "Windows", "os_name": "nt",
               "platform_machine": "AMD64"}
LINUX_X64 = {"sys_platform": "linux", "platform_system": "Linux", "os_name": "posix",
             "platform_machine": "x86_64"}
LINUX_ARM64 = {"sys_platform": "linux", "platform_system": "Linux", "os_name": "posix",
               "platform_machine": "aarch64"}
MACOS_ARM64 = {"sys_platform": "darwin", "platform_system": "Darwin", "os_name": "posix",
               "platform_machine": "arm64"}


def manylinux(arch: str, glibc_minor: int) -> list[str]:
    """Platform tags a glibc 2.<glibc_minor> system accepts, newest first."""
    tags = [f"manylinux_2_{minor}_{arch}" for minor in range(glibc_minor, 4, -1)]
    legacy = {17: "manylinux2014", 12: "manylinux2010", 5: "manylinux1"}
    return tags + [f"{name}_{arch}" for minor, name in legacy.items() if minor <= glibc_minor]


# (python, marker environment, platform tags). GitHub's ubuntu-24.04 runners and
# the Forgejo job image carry glibc 2.39; the Linux binaries build in
# manylinux_2_28, so 3.14 is held to that. macOS is held to the binaries' floor.
TARGETS = {
    "cp312-win_amd64": ((3, 12), WINDOWS_X64, ["win_amd64"]),
    "cp312-linux_x86_64": ((3, 12), LINUX_X64, manylinux("x86_64", 39)),
    "cp312-macos_arm64": ((3, 12), MACOS_ARM64, list(mac_platforms((15, 0), "arm64"))),
    "cp313-linux_x86_64": ((3, 13), LINUX_X64, manylinux("x86_64", 39)),
    "cp314-win_amd64": ((3, 14), WINDOWS_X64, ["win_amd64"]),
    "cp314-linux_x86_64": ((3, 14), LINUX_X64, manylinux("x86_64", 28)),
    "cp314-linux_aarch64": ((3, 14), LINUX_ARM64, manylinux("aarch64", 28)),
    "cp314-macos_arm64": ((3, 14), MACOS_ARM64, list(mac_platforms((15, 0), "arm64"))),
}


def supported_tags(python: tuple[int, int], platforms: list[str]) -> set[Tag]:
    interpreter = f"cp{python[0]}{python[1]}"
    return set(cpython_tags(python, platforms=platforms)) | set(
        compatible_tags(python, interpreter, platforms)
    )


def marker_environment(python: tuple[int, int], platform: dict[str, str]) -> dict[str, str]:
    version = f"{python[0]}.{python[1]}"
    return {
        **platform,
        "python_version": version,
        "python_full_version": f"{version}.0",
        "implementation_name": "cpython",
        "platform_python_implementation": "CPython",
    }


def missing_wheels(lock: dict, python: tuple[int, int], platform: dict[str, str],
                   platforms: list[str]) -> list[str]:
    """Locked packages this target would have to build from source."""
    tags = supported_tags(python, platforms)
    environment = marker_environment(python, platform)
    missing = []
    for package in lock["package"]:
        marker = package.get("marker")
        if marker and not Marker(marker).evaluate(environment):
            continue
        wheels = [f["file"] for f in package.get("files", []) if f["file"].endswith(".whl")]
        if not any(parse_wheel_filename(wheel)[3] & tags for wheel in wheels):
            missing.append(f"{package['name']} {package['version']}")
    return missing


@pytest.fixture(scope="module")
def lock() -> dict:
    with LOCK.open("rb") as handle:
        return tomllib.load(handle)


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_every_locked_package_has_a_wheel(lock, target):
    python, platform, platforms = TARGETS[target]

    missing = missing_wheels(lock, python, platform, platforms)

    assert not missing, (
        f"{target} would build {', '.join(missing)} from source during `pdm install`. "
        "Pin a release that ships a wheel for it, or drop the target from the lock "
        "and the CI matrix."
    )


def test_every_python_the_lock_targets_is_checked(lock):
    """A Python added to the lock must be added here too, or it goes unchecked."""
    locked = {
        tuple(int(part) for part in match.groups())
        for target in lock["metadata"]["targets"]
        if (match := re.fullmatch(r"==(\d+)\.(\d+)\.\*", target.get("requires_python", "")))
    }
    checked = {python for python, _, _ in TARGETS.values()}

    assert locked, "pdm.lock lists no ==3.X.* targets; this test no longer reads it correctly"
    assert locked <= checked, (
        f"pdm.lock targets Python {sorted(locked - checked)} but TARGETS checks none of its wheels"
    )
