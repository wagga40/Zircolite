"""The Forgejo workflows must keep running what the GitHub workflows run.

``.forgejo/workflows/`` is a pre-flight mirror: Forgejo runs it before a push so
a broken workflow is found locally instead of on master. That only works while
the two sets execute the same commands. Nothing enforces that -- the forges read
disjoint directories and never compare them -- so a change to ``.github`` alone
leaves a mirror that passes while testing something else, which is worse than no
mirror at all.

These tests pin the payload, not the YAML. Runner labels, job images and the
matrix legs a single x86_64 Linux runner cannot serve are expected to differ and
are documented in ``.forgejo/README.md``; the commands under test are not.
"""

from pathlib import Path

import pytest
import yaml

WORKSPACE_ROOT = Path(__file__).parent.parent
GITHUB_WORKFLOWS = WORKSPACE_ROOT / ".github" / "workflows"
FORGEJO_WORKFLOWS = WORKSPACE_ROOT / ".forgejo" / "workflows"

# The commands each workflow exists to run. A mirror that no longer issues one
# of these is not testing the thing its GitHub counterpart tests.
#
# Matched against the *end* of a command line, not anywhere in it. A substring
# test passes for `pdm run pytest -x`, so appending a flag on one forge and not
# the other would go unnoticed -- which is exactly the drift worth catching.
# The interpreter prefix is free to differ: external_tests drives the harness
# through pdm on GitHub and a bare venv on Forgejo.
LOAD_BEARING_COMMANDS = {
    "lint_python.yml": [
        "pdm run ruff check .",
        "pdm run python -m mypy zircolite",
        "pdm run ruff format --check zircolite/ zircolite.py || true",
    ],
    "tests.yml": [
        "pdm run pytest",
    ],
    "external_tests.yml": [
        "tests/external/run_external_tests.py --build --parallel 4",
    ],
    "build_pyinstaller.yml": [
        "pyinstaller --noconfirm Zircolite.spec",
    ],
}

# Arguments that appear mid-command, so they cannot be anchored to a line end.
REQUIRED_ARGUMENTS = {
    "build_pyinstaller.yml": [
        "rules/rules_windows_sysmon.json",
        "--package",
    ],
}


def _workflow_names(directory: Path) -> set[str]:
    return {path.name for path in directory.glob("*.yml")}


def _run_script(path: Path) -> str:
    """Every ``run:`` body in a workflow, concatenated.

    Read from the parsed YAML rather than the raw text so a command that moved
    between steps, or gained a line continuation, still counts as present.
    """
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    scripts = []
    for job in (document.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            if "run" in step:
                scripts.append(str(step["run"]))
    return "\n".join(scripts)


def _uses(path: Path) -> set[str]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {
        step["uses"]
        for job in (document.get("jobs") or {}).values()
        for step in job.get("steps") or []
        if "uses" in step
    }


def test_every_github_workflow_has_a_forgejo_counterpart():
    """A workflow added to one forge and not the other is silently untested here."""
    missing = _workflow_names(GITHUB_WORKFLOWS) - _workflow_names(FORGEJO_WORKFLOWS)

    assert not missing, (
        f"{sorted(missing)} exist under .github/workflows but not .forgejo/workflows; "
        "the pre-flight run would not cover them"
    )


def _ends_a_command_line(script: str, command: str) -> bool:
    return any(line.strip().endswith(command) for line in script.splitlines())


@pytest.mark.parametrize("name", sorted(LOAD_BEARING_COMMANDS))
def test_the_mirror_runs_the_same_commands(name):
    """The forges may differ in plumbing; they may not differ in what they test."""
    github_script = _run_script(GITHUB_WORKFLOWS / name)
    forgejo_script = _run_script(FORGEJO_WORKFLOWS / name)

    for command in LOAD_BEARING_COMMANDS[name]:
        assert _ends_a_command_line(github_script, command), (
            f"no command in .github/workflows/{name} ends with {command!r}. If that "
            "is intended, update LOAD_BEARING_COMMANDS and the Forgejo mirror together."
        )
        assert _ends_a_command_line(forgejo_script, command), (
            f"a command in .github/workflows/{name} ends with {command!r} but "
            f"nothing in .forgejo/workflows/{name} does; the mirror has drifted"
        )

    for argument in REQUIRED_ARGUMENTS.get(name, []):
        assert argument in github_script, (
            f"{argument!r} is no longer in .github/workflows/{name}"
        )
        assert argument in forgejo_script, (
            f"{argument!r} is in .github/workflows/{name} but not "
            f".forgejo/workflows/{name}; the mirror has drifted"
        )


@pytest.mark.parametrize("name", sorted(LOAD_BEARING_COMMANDS))
def test_the_mirror_is_valid_yaml_with_jobs(name):
    document = yaml.safe_load((FORGEJO_WORKFLOWS / name).read_text(encoding="utf-8"))

    assert document.get("jobs"), f".forgejo/workflows/{name} defines no jobs"


@pytest.mark.parametrize("name", sorted(LOAD_BEARING_COMMANDS))
def test_setup_pdm_is_substituted_rather_than_dropped(name):
    """data.forgejo.org has no mirror for pdm-project/setup-pdm, so the Forgejo
    workflows install pdm with pip instead. If GitHub stops using the action the
    substitution is pointless and both sides should be revisited."""
    github_uses = _uses(GITHUB_WORKFLOWS / name)
    uses_setup_pdm = any(action.startswith("pdm-project/setup-pdm") for action in github_uses)

    if not uses_setup_pdm:
        pytest.skip(f".github/workflows/{name} does not use setup-pdm")

    forgejo_uses = _uses(FORGEJO_WORKFLOWS / name)

    assert not any(action.startswith("pdm-project/setup-pdm") for action in forgejo_uses), (
        f".forgejo/workflows/{name} references pdm-project/setup-pdm, which does "
        "not resolve on Forgejo"
    )

    # external_tests drives the harness from a bare venv instead: it needs only
    # rich, and the project dependencies live in the image it builds. A mirror
    # that calls pdm without installing it would fail at the first step.
    forgejo_script = _run_script(FORGEJO_WORKFLOWS / name)
    if "pdm " not in forgejo_script:
        return

    assert "pip install --upgrade --quiet pip pdm" in forgejo_script, (
        f".forgejo/workflows/{name} calls pdm but never installs it; setup-pdm "
        "was dropped without a replacement"
    )
