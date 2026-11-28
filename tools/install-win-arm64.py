#!/usr/bin/env python3
"""Install the development environment on Windows on ARM64.

    python tools/install-win-arm64.py --wheels <directory holding the evtx wheel>

`pdm install` cannot work there: evtx publishes no win_arm64 wheel and no
sdist, and jq cannot be built for the platform. So the lock is exported and
installed with uv, minus those two:

- evtx comes from a wheel built beforehand from pyevtx-rs with maturin, and
  must be the version the lock pins;
- jq is left out. pySigma imports it only inside its jq transformation, which
  Zircolite never uses.

Everything goes in with --no-deps, or uv would resolve jq back in, and with
--no-config, so the project's [tool.uv] exclude-newer cannot reject a version
the lock already pinned. The project goes in editable, which builds the
flattening kernel in place where Zircolite.spec looks for it; set
ZIRCOLITE_REQUIRE_NATIVE=1 to make a failed compile fail the install. Finally
PDM is pointed at the new environment, so every later `pdm run` uses it.

An existing .venv is replaced.
"""

from __future__ import annotations

import argparse
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = Path("dist") / "reqs.txt"
VENV = Path(".venv")
DROPPED = frozenset({"evtx", "jq"})
REQUIREMENT_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
PINNED_REQUIREMENT = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==([^\s;\\]+)")


class InstallError(Exception):
    pass


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_records(text: str) -> list[list[str]]:
    """Group lines into requirements: a trailing backslash continues onto the next line."""
    records: list[list[str]] = []
    continued = False
    for line in text.splitlines(keepends=True):
        if continued:
            records[-1].append(line)
        else:
            records.append([line])
        continued = line.rstrip("\r\n").endswith("\\")
    return records


def drop_requirements(text: str, names: Iterable[str] = DROPPED) -> tuple[str, set[str]]:
    """Remove the named requirements, hash lines included; return the text and what was removed."""
    unwanted = {canonical_name(name) for name in names}
    kept: list[str] = []
    removed: set[str] = set()
    for record in requirement_records(text):
        first = record[0].lstrip()
        match = None if first.startswith(("#", "-")) else REQUIREMENT_NAME.match(first)
        if match and canonical_name(match.group(1)) in unwanted:
            removed.add(canonical_name(match.group(1)))
            continue
        kept.extend(record)
    return "".join(kept), removed


def run(command: list[str]) -> None:
    print("+ " + shlex.join(command), flush=True)
    executable = shutil.which(command[0])
    if executable is None:
        raise InstallError(f"{command[0]} is not on PATH")
    # Inherits the environment, so ZIRCOLITE_REQUIRE_NATIVE reaches setup.py.
    result = subprocess.run([executable, *command[1:]], cwd=ROOT, check=False)  # noqa: S603 -- fixed commands, no shell
    if result.returncode != 0:
        raise InstallError(f"{command[0]} exited {result.returncode}")


def pinned_version(text: str, name: str) -> str | None:
    """The version a requirements export pins ``name`` to, if it pins one."""
    wanted = canonical_name(name)
    for record in requirement_records(text):
        match = PINNED_REQUIREMENT.match(record[0])
        if match and canonical_name(match.group(1)) == wanted:
            return match.group(2)
    return None


def evtx_wheel(directory: Path) -> Path:
    wheels = sorted(directory.glob("evtx-*.whl"))
    if len(wheels) != 1:
        found = ", ".join(wheel.name for wheel in wheels) or "none"
        raise InstallError(f"expected exactly one evtx-*.whl in {directory}, found {found}")
    return wheels[0].resolve()


def install(wheels: Path) -> None:
    wheel = evtx_wheel(wheels)
    (ROOT / REQUIREMENTS).parent.mkdir(parents=True, exist_ok=True)
    run(["pdm", "export", "-G", "dev", "-o", REQUIREMENTS.as_posix()])

    exported = (ROOT / REQUIREMENTS).read_text(encoding="utf-8")
    filtered, removed = drop_requirements(exported)
    if removed != DROPPED:
        # Either the lock no longer pins one of them or the export format
        # changed; both mean this recipe needs a look before it is trusted.
        raise InstallError(f"{REQUIREMENTS} has no requirement for: "
                           + ", ".join(sorted(DROPPED - removed)))
    # A wheel left behind by an older pyevtx-rs commit would install without a
    # word, and the binary would parse EVTX unlike every other target.
    built, locked = wheel.name.split("-")[1], pinned_version(exported, "evtx")
    if built != locked:
        raise InstallError(f"{wheel.name} is evtx {built}, but the lock pins {locked}")
    (ROOT / REQUIREMENTS).write_text(filtered, encoding="utf-8")
    print(f"Dropped {', '.join(sorted(removed))} from {REQUIREMENTS.as_posix()}", flush=True)

    venv = VENV.as_posix()
    run(["uv", "venv", "--clear", venv, "--python", sys.executable])
    run(["uv", "pip", "install", "--no-config", "--no-deps", "--python", venv,
         "-r", REQUIREMENTS.as_posix()])
    run(["uv", "pip", "install", "--no-config", "--no-deps", "--python", venv, str(wheel)])
    run(["uv", "pip", "install", "--no-config", "--no-deps", "--python", venv, "-e", "."])
    run(["pdm", "use", "-f", venv])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install the development environment on Windows on ARM64 without evtx or jq "
                    "from the lock.")
    parser.add_argument("--wheels", type=Path, required=True,
                        help="directory holding the evtx wheel built for this platform")
    args = parser.parse_args(argv)
    try:
        install(args.wheels)
    except InstallError as error:
        print(f"install-win-arm64: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
