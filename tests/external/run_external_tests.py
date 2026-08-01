#!/usr/bin/env python3
"""
Run Docker-based external tests for Zircolite.

Builds an image from tests/external/Dockerfile.external-tests (current tree), runs each
scenario under tests/external/scenarios/, and compares output to expected/
files. Invoke via: pdm run python tests/external/run_external_tests.py [--build]
"""

import argparse
import dataclasses
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from xml.etree.ElementTree import Element, ElementTree, SubElement, indent

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[@-Z\\-_]")

console = Console()

DEFAULT_IMAGE_TAG = "zircolite:external-test"
DEFAULT_DOCKERFILE = "tests/external/Dockerfile.external-tests"
DEFAULT_RUNNER_CONFIG = "runner.yaml"
DEFAULT_TIMEOUT = 120
SCENARIOS_DIR = "scenarios"
CONTAINER_INPUT = "/data/input"
CONTAINER_OUTPUT = "/data/output"

_TRACEBACK_PATTERNS = [
    "Traceback (most recent call last)",
    "SyntaxError:",
    "ModuleNotFoundError:",
    "ImportError:",
]


@dataclasses.dataclass
class ScenarioResult:
    name: str
    ok: bool
    message: str
    status: str  # "pass", "fail", "skip"
    # Container I/O
    stdout: str
    stderr: str
    exit_code: int
    expected_exit_code: int
    # What was run
    docker_command: list[str]
    zircolite_args: list[str]
    # Timing
    duration: float  # wall-clock seconds


def get_repo_root() -> Path:
    script_dir = Path(__file__).resolve().parent
    return script_dir.parent.parent


def load_runner_config(path: Path) -> dict:
    """Load runner.yaml if it exists; silently return empty dict otherwise."""
    if not path.exists():
        return {}
    import yaml
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_scenario_yaml(scenario_dir: Path) -> dict:
    import yaml
    path = scenario_dir / "scenario.yaml"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _check_skip(manifest: dict, scenario_dir: Path) -> str | None:
    """Return a skip reason if the scenario should be skipped, or None."""
    skip_if = manifest.get("skip_if", {})
    if not skip_if:
        return None
    if skip_if.get("missing_input"):
        input_dir = scenario_dir / "input"
        command = manifest.get("command", [])
        for arg in command:
            if isinstance(arg, str) and arg.startswith("/data/input/"):
                filename = arg[len("/data/input/"):]
                if not (input_dir / filename).exists():
                    return f"missing input file: {filename}"
        # For directory-based scenarios (-e /data/input -f <ext>): check that at
        # least one file with the declared extension exists in input/.
        if "/data/input" in command and not input_dir.exists():
            return "input directory does not exist"
        try:
            f_idx = command.index("-f")
            ext = command[f_idx + 1] if f_idx + 1 < len(command) else None
        except ValueError:
            ext = None
        if ext and "/data/input" in command:
            matches = list(input_dir.glob(f"*.{ext}"))
            if not matches:
                return f"no .{ext} files in input directory"
    return None


def build_image(repo_root: Path, dockerfile: Path, image_tag: str) -> bool:
    cmd = [
        "docker", "build",
        "-f", str(dockerfile),
        "-t", image_tag,
        str(repo_root),
    ]
    console.print(f"  [dim]Running: docker build -f {dockerfile.name} -t {image_tag} .[/]")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo_root))
    if result.returncode != 0:
        console.print(Panel(result.stderr or result.stdout, title="[red]Docker build failed[/]", border_style="red"))
        return False
    return True


def image_exists(image_tag: str) -> bool:
    result = subprocess.run(
        # S607: docker is resolved from PATH on purpose. Its location differs
        # between Docker Desktop, Colima and a Linux package, and a developer
        # tool has no threat model that pinning the path would improve.
        ["docker", "image", "inspect", image_tag],  # noqa: S607
        capture_output=True,
        cwd=os.getcwd(),
    )
    return result.returncode == 0


def run_scenario(
    scenario_name: str,
    scenario_dir: Path,
    repo_root: Path,
    image_tag: str,
    default_timeout: int = DEFAULT_TIMEOUT,
) -> ScenarioResult:
    manifest = load_scenario_yaml(scenario_dir)
    zircolite_args: list[str] = manifest.get("command", [])
    expected_exit_code: int = manifest.get("expected_exit_code", 0)
    stdout_contains: list[str] = manifest.get("stdout_contains", [])
    stdout_not_contains: list[str] = manifest.get("stdout_not_contains", [])
    stderr_contains: list[str] = manifest.get("stderr_contains", [])
    compare_files_spec: list[dict] = manifest.get("compare_files", [])
    allow_stderr_errors: bool = manifest.get("allow_stderr_errors", False)
    timeout: int = manifest.get("timeout", default_timeout)

    input_dir = scenario_dir / "input"
    expected_dir = scenario_dir / "expected"
    use_input = input_dir.exists()

    skip_reason = _check_skip(manifest, scenario_dir)
    if skip_reason:
        return ScenarioResult(
            name=scenario_name, ok=True, message=skip_reason, status="skip",
            stdout="", stderr="", exit_code=-1, expected_exit_code=expected_exit_code,
            docker_command=[], zircolite_args=zircolite_args, duration=0.0,
        )

    def _fail(msg: str, docker_cmd: list[str], stdout: str, stderr: str, exit_code: int, duration: float) -> ScenarioResult:
        return ScenarioResult(
            name=scenario_name, ok=False, message=msg, status="fail",
            stdout=stdout, stderr=stderr,
            exit_code=exit_code, expected_exit_code=expected_exit_code,
            docker_command=docker_cmd, zircolite_args=zircolite_args,
            duration=duration,
        )

    with tempfile.TemporaryDirectory(prefix="zircolite_external_") as tmp:
        host_output = Path(tmp) / "output"
        host_output.mkdir()

        mount_input = str(input_dir.resolve()) if use_input else None
        volumes = [f"{host_output.resolve()}:{CONTAINER_OUTPUT}"]
        if mount_input:
            volumes.append(f"{mount_input}:{CONTAINER_INPUT}")

        docker_cmd = ["docker", "run", "--rm", "-e", "PYTHONUNBUFFERED=1"]
        for v in volumes:
            docker_cmd.extend(["-v", v])
        docker_cmd.append(image_tag)
        docker_cmd.extend(zircolite_args)

        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                cwd=str(repo_root),
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - t0
            return _fail(
                f"timed out after {timeout}s",
                docker_cmd, "", "", -1, duration,
            )
        duration = time.monotonic() - t0

        stdout = _ANSI_ESCAPE.sub("", proc.stdout or "")
        stderr = _ANSI_ESCAPE.sub("", proc.stderr or "")
        exit_code = proc.returncode

        if exit_code != expected_exit_code:
            return _fail(
                f"exit code {exit_code} (expected {expected_exit_code})",
                docker_cmd, stdout, stderr, exit_code, duration,
            )

        combined = stdout + stderr
        for needle in stdout_contains:
            if needle not in combined:
                return _fail(
                    f"expected stdout/stderr to contain {needle!r}",
                    docker_cmd, stdout, stderr, exit_code, duration,
                )
        for needle in stdout_not_contains:
            if needle in combined:
                return _fail(
                    f"expected stdout/stderr NOT to contain {needle!r}",
                    docker_cmd, stdout, stderr, exit_code, duration,
                )
        for needle in stderr_contains:
            if needle not in stderr:
                return _fail(
                    f"expected stderr to contain {needle!r}",
                    docker_cmd, stdout, stderr, exit_code, duration,
                )

        if not allow_stderr_errors:
            for pattern in _TRACEBACK_PATTERNS:
                if pattern in stderr:
                    return _fail(
                        f"stderr contains unexpected error: {pattern!r}",
                        docker_cmd, stdout, stderr, exit_code, duration,
                    )

        _MODES_WITHOUT_EXPECTED = (
            "json_count_min", "json_exact_count", "json_all_have_field",
            "json_matches_all_have_field", "json_schema", "json_contains_titles",
            "exists", "lines_min",
        )
        for pair in compare_files_spec:
            actual_path = pair.get("actual")
            expected_name = pair.get("expected")
            if not actual_path:
                continue
            host_actual = host_output / Path(actual_path).name
            if not host_actual.exists():
                return _fail(
                    f"output file missing: {actual_path}",
                    docker_cmd, stdout, stderr, exit_code, duration,
                )
            expected_path = expected_dir / expected_name if expected_name else None
            compare_mode = pair.get("compare", "content")
            needs_expected = compare_mode not in _MODES_WITHOUT_EXPECTED or expected_name
            if needs_expected and (not expected_path or not expected_path.exists()):
                return _fail(
                    f"expected file missing: {expected_path}",
                    docker_cmd, stdout, stderr, exit_code, duration,
                )
            ok, reason = _compare_files(host_actual, expected_path, pair)
            if not ok:
                return _fail(
                    f"output check failed for {actual_path}: {reason}",
                    docker_cmd, stdout, stderr, exit_code, duration,
                )

    return ScenarioResult(
        name=scenario_name, ok=True, message="", status="pass",
        stdout=stdout, stderr=stderr,
        exit_code=exit_code, expected_exit_code=expected_exit_code,
        docker_command=docker_cmd, zircolite_args=zircolite_args,
        duration=duration,
    )


def _compare_files(actual_path: Path, expected_path: Path | None, pair: dict) -> tuple[bool, str]:
    compare_mode = pair.get("compare", "content")

    if compare_mode == "content":
        if not expected_path:
            return False, "no expected file specified"
        actual = actual_path.read_bytes()
        expected = expected_path.read_bytes()
        if actual != expected:
            return False, f"content differs ({len(actual)} vs {len(expected)} bytes)"
        return True, ""

    if compare_mode == "json_keys":
        if not expected_path:
            return False, "no expected file specified"
        a = json.loads(actual_path.read_text())
        e = json.loads(expected_path.read_text())
        if not isinstance(a, list) or not isinstance(e, list):
            if a != e:
                return False, f"values differ: {a!r} != {e!r}"
            return True, ""
        if len(a) != len(e):
            return False, f"list length differs: {len(a)} != {len(e)}"
        for i, (ax, ex) in enumerate(zip(a, e, strict=True)):
            if not isinstance(ax, dict) or not isinstance(ex, dict):
                if ax != ex:
                    return False, f"item {i} differs: {ax!r} != {ex!r}"
                continue
            for k in ex:
                if k not in ax:
                    return False, f"item {i} missing key {k!r}"
                if ax[k] != ex[k]:
                    return False, f"item {i} key {k!r}: {ax[k]!r} != {ex[k]!r}"
        return True, ""

    if compare_mode == "json_count_min":
        a = json.loads(actual_path.read_text())
        min_count = pair.get("min_count", 0)
        count = len(a) if isinstance(a, list) else -1
        if count < min_count:
            return False, f"expected >= {min_count} items, got {count}"
        return True, ""

    if compare_mode == "json_exact_count":
        a = json.loads(actual_path.read_text())
        expected_count = pair.get("count", 0)
        count = len(a) if isinstance(a, list) else -1
        if count != expected_count:
            return False, f"expected exactly {expected_count} items, got {count}"
        return True, ""

    if compare_mode == "json_all_have_field":
        a = json.loads(actual_path.read_text())
        field = pair.get("field", "")
        if not isinstance(a, list) or not a:
            return False, f"expected non-empty list, got {type(a).__name__}"
        missing = [i for i, item in enumerate(a) if not isinstance(item, dict) or field not in item]
        if missing:
            return False, f"items missing field {field!r} at indices {missing[:5]}"
        return True, ""

    if compare_mode == "json_matches_all_have_field":
        # Checks that field exists in every item inside each rule's "matches" list.
        # Matches Zircolite's output structure: [{..., "matches": [{field: ...}]}]
        a = json.loads(actual_path.read_text())
        field = pair.get("field", "")
        if not isinstance(a, list) or not a:
            return False, f"expected non-empty list, got {type(a).__name__}"
        for rule_idx, rule_entry in enumerate(a):
            matches = rule_entry.get("matches", []) if isinstance(rule_entry, dict) else []
            for match_idx, match in enumerate(matches):
                if not isinstance(match, dict) or field not in match:
                    return False, f"rule[{rule_idx}].matches[{match_idx}] missing field {field!r}"
        return True, ""

    if compare_mode == "exists":
        if actual_path.exists():
            return True, ""
        return False, "file does not exist"

    if compare_mode == "lines_min":
        min_lines = pair.get("min_count", 0)
        lines = len(actual_path.read_text().strip().splitlines())
        if lines < min_lines:
            return False, f"expected >= {min_lines} lines, got {lines}"
        return True, ""

    if compare_mode == "json_schema":
        a = json.loads(actual_path.read_text())
        required_keys = pair.get("required_keys", [])
        matches_min = pair.get("matches_min", 0)
        if not isinstance(a, list):
            return False, f"expected list, got {type(a).__name__}"
        for idx, item in enumerate(a):
            if not isinstance(item, dict):
                return False, f"item[{idx}] is not a dict"
            for key in required_keys:
                if key not in item:
                    return False, f"item[{idx}] missing required key {key!r}"
            if matches_min > 0:
                matches = item.get("matches", [])
                if not isinstance(matches, list) or len(matches) < matches_min:
                    count = len(matches) if isinstance(matches, list) else 0
                    return False, f"item[{idx}] has {count} matches, expected >= {matches_min}"
        return True, ""

    if compare_mode == "json_contains_titles":
        a = json.loads(actual_path.read_text())
        expected_titles = set(pair.get("titles", []))
        if not isinstance(a, list):
            return False, f"expected list, got {type(a).__name__}"
        found_titles = {item.get("title") for item in a if isinstance(item, dict)}
        missing = expected_titles - found_titles
        if missing:
            return False, f"missing expected rule titles: {sorted(missing)}"
        return True, ""

    return False, f"unknown compare mode: {compare_mode!r}"


def _md_details_block(summary: str, content: str, lang: str = "") -> list[str]:
    """Return lines for a collapsible <details> block with a fenced code block inside."""
    return [
        f"<details><summary>{summary}</summary>",
        "",
        f"```{lang}",
        content.rstrip(),
        "```",
        "",
        "</details>",
        "",
    ]


def _write_markdown_file(
    path: Path,
    image_tag: str,
    results: list[ScenarioResult],
    total_duration: float,
) -> None:
    """Write a human-readable Markdown results report to *path*.

    Covers the same data as the JSON results log: timestamp, image, all scenario
    results with exit codes, durations, docker commands, zircolite args, and full
    stdout/stderr — formatted for human reading.
    """
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    skipped = sum(1 for r in results if r.status == "skip")
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    L: list[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    L.append("# Zircolite External Test Results")
    L.append("")
    L.append("| | |")
    L.append("|---|---|")
    L.append(f"| **Date** | {ts} |")
    L.append(f"| **Image** | `{image_tag}` |")
    L.append(f"| **Total scenarios** | {len(results)} |")
    L.append(f"| **Passed** | ✅ {passed} |")
    L.append(f"| **Failed** | {'❌ ' + str(failed) if failed else '—'} |")
    L.append(f"| **Skipped** | {'⏭ ' + str(skipped) if skipped else '—'} |")
    L.append(f"| **Total duration** | {total_duration:.1f}s |")
    L.append("")

    # ── Summary table ────────────────────────────────────────────────────────
    L.append("## Summary")
    L.append("")
    L.append("| Scenario | Result | Exit code | Duration | Message |")
    L.append("|----------|:------:|:---------:|----------:|---------|")
    for r in results:
        if r.status == "skip":
            result_cell = "⏭ SKIP"
        elif r.ok:
            result_cell = "✅ PASS"
        else:
            result_cell = "❌ FAIL"
        msg = "—" if r.ok else (r.message[:100] + "…" if len(r.message) > 100 else r.message)
        if r.status == "skip":
            msg = r.message or "skipped"
        L.append(f"| `{r.name}` | {result_cell} | {r.exit_code} | {r.duration:.1f}s | {msg} |")
    L.append("")

    # ── Per-scenario detail ───────────────────────────────────────────────────
    L.append("## Scenario Details")
    L.append("")
    for r in results:
        if r.status == "skip":
            icon = "⏭"
            result_label = "SKIP"
        elif r.ok:
            icon = "✅"
            result_label = "PASS"
        else:
            icon = "❌"
            result_label = "FAIL"
        L.append(f"### {icon} `{r.name}`")
        L.append("")
        L.append("| | |")
        L.append("|---|---|")
        L.append(f"| **Result** | {result_label} |")
        if not r.ok:
            L.append(f"| **Failure reason** | {r.message} |")
        L.append(f"| **Exit code** | {r.exit_code} (expected {r.expected_exit_code}) |")
        L.append(f"| **Duration** | {r.duration:.1f}s |")
        L.append("")

        # Zircolite args
        args_str = " ".join(r.zircolite_args)
        L.append(f"**Zircolite args:** `{args_str}`")
        L.append("")

        # Full docker command (collapsible)
        docker_str = " ".join(r.docker_command)
        L.extend(_md_details_block("Docker command", docker_str, "sh"))

        # stdout / stderr (always included, collapsible)
        stdout_summary = "stdout" if r.ok else "stdout ⚠️"
        L.extend(_md_details_block(stdout_summary, r.stdout if r.stdout.strip() else "(empty)"))
        stderr_label = "stderr" if r.ok else "stderr ⚠️"
        L.extend(_md_details_block(stderr_label, r.stderr if r.stderr.strip() else "(empty)"))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def _write_results_file(
    path: Path,
    image_tag: str,
    results: list[ScenarioResult],
    total_duration: float,
) -> None:
    """Write a detailed JSON results log to *path*.

    Each scenario entry includes the full docker command, exit code, wall-clock
    duration, and the complete stdout/stderr captured from the container so the
    log is self-contained for CI archiving and post-mortem review.
    """
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    skipped = sum(1 for r in results if r.status == "skip")

    scenarios_out = []
    for r in results:
        scenarios_out.append({
            "name": r.name,
            "result": r.status,
            "message": r.message,
            "exit_code": r.exit_code,
            "expected_exit_code": r.expected_exit_code,
            "duration_seconds": round(r.duration, 3),
            "docker_command": r.docker_command,
            "zircolite_args": r.zircolite_args,
            "stdout": r.stdout,
            "stderr": r.stderr,
        })

    summary = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "image": image_tag,
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total_duration_seconds": round(total_duration, 3),
        "scenarios": scenarios_out,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_junit_file(
    path: Path,
    results: list[ScenarioResult],
    total_duration: float,
) -> None:
    """Write a JUnit XML report for CI systems (GitHub Actions, GitLab CI, Jenkins)."""
    failed = sum(1 for r in results if r.status == "fail")
    skipped = sum(1 for r in results if r.status == "skip")

    testsuites = Element("testsuites")
    suite = SubElement(testsuites, "testsuite", {
        "name": "zircolite-external",
        "tests": str(len(results)),
        "failures": str(failed),
        "skipped": str(skipped),
        "time": f"{total_duration:.3f}",
    })

    for r in results:
        tc = SubElement(suite, "testcase", {
            "name": r.name,
            "classname": "external",
            "time": f"{r.duration:.3f}",
        })
        if r.status == "skip":
            skip_el = SubElement(tc, "skipped")
            skip_el.set("message", r.message)
        elif r.status == "fail":
            fail_el = SubElement(tc, "failure")
            fail_el.set("message", r.message[:500])
            detail = r.stderr.strip() or r.stdout.strip()
            if detail:
                fail_el.text = detail[:4000]

    indent(testsuites, space="  ")
    path.parent.mkdir(parents=True, exist_ok=True)
    tree = ElementTree(testsuites)
    tree.write(str(path), encoding="unicode", xml_declaration=True)


def _filter_by_tags(scenario_dirs: list[Path], required_tags: list[str]) -> list[Path]:
    """Keep only scenarios whose tags intersect with *required_tags*."""
    if not required_tags:
        return scenario_dirs
    tag_set = set(required_tags)
    filtered = []
    for d in scenario_dirs:
        manifest = load_scenario_yaml(d)
        scenario_tags = set(manifest.get("tags", []))
        if scenario_tags & tag_set:
            filtered.append(d)
    return filtered


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Docker-based external tests for Zircolite.")
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build the Docker image before running scenarios",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root (default: auto-detect)",
    )
    parser.add_argument(
        "--dockerfile",
        type=Path,
        default=None,
        help=f"Dockerfile path (default: {DEFAULT_DOCKERFILE})",
    )
    parser.add_argument(
        "--image-tag",
        type=str,
        default=None,
        help=f"Docker image tag (default: {DEFAULT_IMAGE_TAG})",
    )
    parser.add_argument(
        "--results-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write a detailed JSON results log (stdout, stderr, timings) to this file after the run",
    )
    parser.add_argument(
        "--markdown-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write a Markdown results report to this file after the run",
    )
    parser.add_argument(
        "--junit-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write a JUnit XML report to this file (for CI systems)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help=f"Runner YAML config file (default: {DEFAULT_RUNNER_CONFIG} next to this script)",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=None,
        metavar="N",
        help="Run up to N scenarios concurrently (default: 1 = sequential)",
    )
    parser.add_argument(
        "--tag",
        action="append",
        dest="tags",
        default=[],
        metavar="TAG",
        help="Run only scenarios with this tag (repeatable, union match)",
    )
    parser.add_argument(
        "scenarios",
        nargs="*",
        help="Scenario names to run (default: all)",
    )
    args = parser.parse_args()

    external_dir = Path(__file__).resolve().parent

    config_path = args.config or (external_dir / DEFAULT_RUNNER_CONFIG)
    runner_cfg = load_runner_config(config_path)

    image_tag: str = args.image_tag or runner_cfg.get("image_tag") or DEFAULT_IMAGE_TAG
    default_timeout: int = runner_cfg.get("default_timeout", DEFAULT_TIMEOUT)
    parallel: int = args.parallel or runner_cfg.get("parallel", 1)
    results_file: Path | None = args.results_file or (
        Path(runner_cfg["results_file"]) if runner_cfg.get("results_file") else None
    )
    markdown_file: Path | None = args.markdown_file or (
        Path(runner_cfg["markdown_file"]) if runner_cfg.get("markdown_file") else None
    )
    junit_file: Path | None = args.junit_file or (
        Path(runner_cfg["junit_file"]) if runner_cfg.get("junit_file") else None
    )

    repo_root: Path = args.repo_root or get_repo_root()
    scenarios_dir = external_dir / SCENARIOS_DIR

    _dockerfile_cfg = runner_cfg.get("dockerfile")
    dockerfile: Path = (
        args.dockerfile
        or (Path(_dockerfile_cfg) if _dockerfile_cfg else None)
        or repo_root / DEFAULT_DOCKERFILE
    )

    if not scenarios_dir.exists():
        console.print(f"[red]Scenarios dir not found: {scenarios_dir}[/]")
        return 2

    config_note = f"  ·  Config: [cyan]{config_path.name}[/]" if config_path.exists() else ""
    console.print(Panel(
        "[bold]Zircolite external tests[/]\n"
        f"Image: [cyan]{image_tag}[/]  ·  Scenarios: [cyan]{scenarios_dir}[/]{config_note}",
        title="Docker external tests",
        border_style="blue",
    ))

    if args.build or not image_exists(image_tag):
        if not dockerfile.exists():
            console.print(f"[red]Dockerfile not found: {dockerfile}[/]")
            console.print("Create it or run from repo root. See tests/external/README.md.")
            return 2
        console.print("[bold blue]Building Docker image...[/]")
        if not build_image(repo_root, dockerfile, image_tag):
            return 1
        console.print("[green]✓ Image built[/]")
    else:
        console.print("[dim]Using existing image (use --build to rebuild)[/]")

    scenario_dirs = sorted(d for d in scenarios_dir.iterdir() if d.is_dir() and not d.name.startswith("."))
    if args.scenarios:
        scenario_dirs = [d for d in scenario_dirs if d.name in args.scenarios]
        if len(scenario_dirs) != len(args.scenarios):
            requested = set(args.scenarios)
            found = {d.name for d in scenario_dirs}
            console.print(f"[red]Unknown scenarios: {requested - found}[/]")
            return 2

    if args.tags:
        scenario_dirs = _filter_by_tags(scenario_dirs, args.tags)
        if not scenario_dirs:
            console.print(f"[yellow]No scenarios match tags: {args.tags}[/]")
            return 0

    console.print(f"\n[bold]Running {len(scenario_dirs)} scenario(s)[/]\n")
    all_results: list[ScenarioResult] = []
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Scenario", style="cyan")
    table.add_column("Result", justify="center")
    table.add_column("Time", justify="right", style="dim")
    table.add_column("Details", style="dim")

    scenario_order = [d.name for d in scenario_dirs]
    run_start = time.monotonic()

    if parallel > 1:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            ptask = progress.add_task(f"[cyan]Running ({parallel} workers)[/]", total=len(scenario_dirs))
            with ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {
                    executor.submit(
                        run_scenario, d.name, d, repo_root, image_tag, default_timeout
                    ): d.name
                    for d in scenario_dirs
                }
                for future in as_completed(futures):
                    all_results.append(future.result())
                    progress.advance(ptask)
        all_results.sort(key=lambda r: scenario_order.index(r.name))
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            ptask = progress.add_task("Scenarios…", total=len(scenario_dirs))
            for scenario_dir in scenario_dirs:
                name = scenario_dir.name
                progress.update(ptask, description=f"[cyan]{name}[/]")
                result = run_scenario(name, scenario_dir, repo_root, image_tag, default_timeout)
                all_results.append(result)
                progress.advance(ptask)

    total_duration = time.monotonic() - run_start

    for result in all_results:
        duration_str = f"{result.duration:.1f}s"
        if result.status == "skip":
            table.add_row(result.name, "[yellow]SKIP[/]", duration_str, result.message or "skipped")
        elif result.ok:
            table.add_row(result.name, "[green]PASS[/]", duration_str, "—")
        else:
            msg = result.message
            table.add_row(result.name, "[red]FAIL[/]", duration_str, msg[:80] + "…" if len(msg) > 80 else msg)
    console.print(table)

    if results_file:
        _write_results_file(
            path=results_file,
            image_tag=image_tag,
            results=all_results,
            total_duration=total_duration,
        )
        console.print(f"[dim]Results written to {results_file}[/]")
    if markdown_file:
        _write_markdown_file(
            path=markdown_file,
            image_tag=image_tag,
            results=all_results,
            total_duration=total_duration,
        )
        console.print(f"[dim]Markdown report written to {markdown_file}[/]")
    if junit_file:
        _write_junit_file(
            path=junit_file,
            results=all_results,
            total_duration=total_duration,
        )
        console.print(f"[dim]JUnit report written to {junit_file}[/]")

    failed = [(r.name, r.message) for r in all_results if r.status == "fail"]
    skipped_count = sum(1 for r in all_results if r.status == "skip")
    if failed:
        console.print(Panel(
            "\n".join(f"• [red]{n}[/]: {m[:200]}{'…' if len(m) > 200 else ''}" for n, m in failed),
            title=f"[red]{len(failed)} scenario(s) failed[/]",
            border_style="red",
        ))
        return 1

    skip_note = f" ({skipped_count} skipped)" if skipped_count else ""
    passed_count = sum(1 for r in all_results if r.status == "pass")
    console.print(Panel(
        f"[green]{passed_count}[/] scenario(s) passed{skip_note} in {total_duration:.1f}s.",
        title="[green]External tests passed[/]",
        border_style="green",
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
