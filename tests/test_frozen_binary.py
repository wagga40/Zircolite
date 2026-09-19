"""Checks that only a built binary can fail.

Everything here runs the executable named by ``ZIRCOLITE_BINARY`` -- the one in
a PyInstaller onedir build, ``dist/Zircolite/Zircolite`` (``Zircolite.exe`` on
Windows) -- and most cases compare it with ``python -m zircolite`` from this
checkout, run with the same arguments. A frozen build can lose a module, a data
file or a plugin that the source tree always has, and still exit 0: that is how
the pySigma pipelines went missing and converted rules lost their EventID
constraint. A detection-only check cannot see that, a comparison can.

Each invocation gets its own empty working directory, so nothing resolves from
the checkout by accident, and output that is written per file is folded by rule
id before it is compared.

Point ``ZIRCOLITE_BINARY`` at the raw ``dist/Zircolite/`` (the executable and
``_internal/`` only), not at an extracted release package: the package ships
``config/``, ``rules/``, ``templates/`` and ``gui/`` beside the executable, and
those would hide a file missing from the bundle.

Off unless asked for:

* ``ZIRCOLITE_TEST_NETWORK=1`` also runs ``-U`` against GitHub;
* ``ZIRCOLITE_GLIBC_FLOOR=2.28`` fails on Linux when any bundled ELF needs a
  newer glibc, or libpython asks for an executable stack;
* ``ZIRCOLITE_MACOS_FLOOR=15.0`` fails on macOS when any bundled Mach-O needs a
  newer macOS.
"""

import bz2
import contextlib
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = WORKSPACE_ROOT / "tests" / "fixtures"
SIGMA_FIXTURES = FIXTURES / "sigma"
BINARY_ENV = os.environ.get("ZIRCOLITE_BINARY")

pytestmark = pytest.mark.skipif(
    not BINARY_ENV, reason="Set ZIRCOLITE_BINARY to test a built binary"
)

RUN_TIMEOUT = 240

MATCH_ALL_RULESET = [{
    "title": "Any event",
    "id": "frozen-00000000-0000-0000-0000-000000000001",
    "level": "informational",
    "tags": [],
    "rule": ["SELECT * FROM logs"],
}]

# A command line only some generated events carry, so a count is exact.
MARKER = "whoami /all"
MARKER_RULESET = [{
    "title": "Marker command line",
    "id": "frozen-00000000-0000-0000-0000-000000000002",
    "level": "high",
    "tags": [],
    "rule": [f"SELECT * FROM logs WHERE CommandLine LIKE '%{MARKER}%'"],
}]

ARCHIVE_PASSWORD = "frozen-test-password"


# =============================================================================
# Running the binary and the source oracle
# =============================================================================

@dataclass
class Run:
    returncode: int
    stdout: str
    stderr: str
    cwd: Path
    tmp: Path
    children: set[tuple[int, float]] = field(default_factory=set)

    @property
    def output(self) -> str:
        return self.stdout + self.stderr

    def detections(self, name: str = "detected.json") -> list[dict]:
        return json.loads((self.cwd / name).read_text(encoding="utf-8"))


def _watch_children(pid: int, seen: set[tuple[int, float]], done: threading.Event) -> None:
    import psutil

    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    while not done.is_set():
        try:
            for child in parent.children(recursive=True):
                with contextlib.suppress(psutil.NoSuchProcess):
                    seen.add((child.pid, child.create_time()))
        except psutil.NoSuchProcess:
            return
        done.wait(0.05)


def _assert_no_orphans(children: set[tuple[int, float]], grace: float = 10.0) -> None:
    import psutil

    def alive() -> list[int]:
        living = []
        for pid, created in children:
            try:
                process = psutil.Process(pid)
                # A child re-parented to a container's PID 1 stays a zombie
                # when that PID 1 never reaps: it has exited all the same.
                if process.create_time() == created and process.status() != psutil.STATUS_ZOMBIE:
                    living.append(pid)
            except psutil.NoSuchProcess:
                pass
        return living

    deadline = time.monotonic() + grace
    while alive() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not alive(), f"worker processes outlived the run: {alive()}"


_ERROR_LINE = re.compile(r"^\s*\[-\]", re.MULTILINE)


def _assert_clean(run: Run, label: str) -> None:
    assert run.returncode == 0, (
        f"{label} exited {run.returncode}\n--- stdout\n{run.stdout}\n--- stderr\n{run.stderr}"
    )
    assert "Traceback" not in run.output, f"{label} printed a traceback:\n{run.output}"
    errors = [line for line in run.output.splitlines() if _ERROR_LINE.match(line)]
    assert not errors, f"{label} reported errors on a happy path:\n" + "\n".join(errors)


class Runner:
    """Runs the binary or ``python -m zircolite``, each in a fresh directory."""

    def __init__(self, factory: pytest.TempPathFactory, binary: Path) -> None:
        self.factory = factory
        self.executable = binary

    def workspace(self, name: str) -> tuple[Path, Path, Path]:
        root = self.factory.mktemp(name)
        cwd, tmp = root / "cwd", root / "tmp"
        cwd.mkdir()
        tmp.mkdir()
        return root, cwd, tmp

    @staticmethod
    def environment(tmp: Path, oracle: bool) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        # Rich wraps at 80 columns when it writes to a pipe, which splits the
        # lines these tests parse.
        env["COLUMNS"] = "500"
        # Temporary files land somewhere the test can inspect afterwards.
        for name in ("TMPDIR", "TEMP", "TMP"):
            env[name] = str(tmp)
        if oracle:
            env["PYTHONPATH"] = str(WORKSPACE_ROOT)
        return env

    def _execute(
        self, command: list[str], name: str, oracle: bool, check: bool,
        watch_children: bool, executable: Path | None = None,
    ) -> Run:
        _, cwd, tmp = self.workspace(name)
        process = subprocess.Popen(
            command, cwd=cwd, env=self.environment(tmp, oracle),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        children: set[tuple[int, float]] = set()
        done = threading.Event()
        watcher = None
        if watch_children:
            watcher = threading.Thread(
                target=_watch_children, args=(process.pid, children, done), daemon=True
            )
            watcher.start()
        try:
            stdout, stderr = process.communicate(timeout=RUN_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(
                f"{command[0]} timed out after {RUN_TIMEOUT}s\n"
                + stdout.decode("utf-8", "replace") + stderr.decode("utf-8", "replace")
            )
        finally:
            done.set()
            if watcher is not None:
                watcher.join()
        run = Run(
            process.returncode, stdout.decode("utf-8", "replace"),
            stderr.decode("utf-8", "replace"), cwd, tmp, children,
        )
        if check:
            _assert_clean(run, "python -m zircolite" if oracle else str(executable or self.executable))
        return run

    def binary(
        self, *args: str, check: bool = True, watch_children: bool = False,
        executable: Path | None = None,
    ) -> Run:
        target = executable or self.executable
        return self._execute(
            [str(target), *args], "binary", oracle=False, check=check,
            watch_children=watch_children, executable=target,
        )

    def source(self, *args: str, check: bool = True, watch_children: bool = False) -> Run:
        return self._execute(
            [sys.executable, "-m", "zircolite", *args], "source", oracle=True,
            check=check, watch_children=watch_children,
        )


def fold_by_rule(detections: list[dict]) -> dict[str, list[str]]:
    """Every match per rule id, whichever per-file entry it came from.

    ``row_id`` is dropped: it numbers rows inside one working database and
    says nothing about what was detected.
    """
    folded: dict[str, list[str]] = {}
    for detection in detections:
        rows = folded.setdefault(detection["id"], [])
        rows.extend(
            json.dumps({k: v for k, v in match.items() if k != "row_id"}, sort_keys=True)
            for match in detection["matches"]
        )
    return {rule: sorted(rows) for rule, rows in folded.items()}


def match_count(detections: list[dict]) -> int:
    return sum(len(detection["matches"]) for detection in detections)


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for directory, dirnames, filenames in os.walk(root):
        dirnames.sort()
        base = Path(directory)
        for name in sorted(filenames + [d for d in dirnames if (base / d).is_symlink()]):
            path = base / name
            digest.update(path.relative_to(root).as_posix().encode())
            if path.is_symlink():
                digest.update(b"->" + os.readlink(path).encode())
            else:
                digest.update(b"=" + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def copy_dist(dist: Path, destination: Path) -> Path:
    shutil.copytree(dist, destination, symlinks=True)
    return destination


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="module")
def binary() -> Path:
    assert BINARY_ENV
    path = Path(BINARY_ENV).resolve()
    if not path.is_file():
        pytest.fail(f"ZIRCOLITE_BINARY names {path}, which does not exist")
    return path


@pytest.fixture(scope="module")
def dist(binary: Path) -> Path:
    return binary.parent


@pytest.fixture(scope="module")
def runner(tmp_path_factory: pytest.TempPathFactory, binary: Path) -> Runner:
    return Runner(tmp_path_factory, binary)


@pytest.fixture(scope="module", autouse=True)
def bundle_digest_at_start(binary: Path) -> str:
    return tree_digest(binary.parent / "_internal")


@pytest.fixture(scope="module")
def inputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Rulesets shared by the whole module."""
    root = tmp_path_factory.mktemp("inputs")
    (root / "match_all.json").write_text(json.dumps(MATCH_ALL_RULESET))
    (root / "marker.json").write_text(json.dumps(MARKER_RULESET))
    return root


def _generated_events(index: int, count: int) -> tuple[str, int]:
    lines, marked = [], 0
    for event in range(count):
        is_marked = event % 7 == 0
        marked += is_marked
        lines.append(json.dumps({"Event": {
            "System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
                       "Computer": f"host-{index}"},
            "EventData": {
                "CommandLine": f"cmd.exe /c {MARKER}" if is_marked else f"cmd.exe /c echo {event}",
                "Image": "C:\\Windows\\System32\\cmd.exe", "ProcessId": event,
            },
        }}))
    return "\n".join(lines) + "\n", marked


@pytest.fixture(scope="module")
def executor_corpora(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[Path, int]]:
    """Three different files for processes, four copies of one for threads."""
    root = tmp_path_factory.mktemp("executor-corpora")
    distinct, copies = root / "distinct", root / "copies"
    distinct.mkdir()
    copies.mkdir()
    distinct_marked = 0
    for index in range(3):
        text, marked = _generated_events(index, 1500 + 500 * index)
        (distinct / f"events{index}.json").write_text(text)
        distinct_marked += marked
    text, marked = _generated_events(9, 2000)
    for index in range(4):
        (copies / f"copy{index}.json").write_text(text)
    return {"distinct": (distinct, distinct_marked), "copies": (copies, 4 * marked)}


# =============================================================================
# Identity and layout
# =============================================================================

_MACHINES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "arm64", "arm64": "arm64",
             "i386": "x86", "i686": "x86", "x86": "x86"}
_ELF_MACHINES = {0x3E: "x86_64", 0xB7: "arm64", 0x03: "x86"}
_MACHO_CPUS = {0x01000007: "x86_64", 0x0100000C: "arm64", 0x07: "x86"}
_PE_MACHINES = {0x8664: "x86_64", 0xAA64: "arm64", 0x014C: "x86"}


def executable_architectures(path: Path) -> set[str]:
    """The CPU architectures an executable is built for, read from its header."""
    data = path.read_bytes()
    if data[:4] == b"\x7fELF":
        order = "<" if data[5] == 1 else ">"
        (machine,) = struct.unpack_from(order + "H", data, 18)
        return {_ELF_MACHINES.get(machine, hex(machine))}
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        (cpu,) = struct.unpack_from("<I", data, 4)
        return {_MACHO_CPUS.get(cpu, hex(cpu))}
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        (count,) = struct.unpack_from(">I", data, 4)
        stride = 20 if data[3] == 0xBE else 32
        cpus = (struct.unpack_from(">I", data, 8 + i * stride)[0] for i in range(count))
        return {_MACHO_CPUS.get(cpu, hex(cpu)) for cpu in cpus}
    if data[:2] == b"MZ":
        (offset,) = struct.unpack_from("<I", data, 0x3C)
        assert data[offset:offset + 4] == b"PE\0\0", f"{path} has no PE header"
        (machine,) = struct.unpack_from("<H", data, offset + 4)
        return {_PE_MACHINES.get(machine, hex(machine))}
    raise AssertionError(f"{path} is not an ELF, Mach-O or PE executable")


class TestIdentityAndLayout:
    def test_version_is_the_package_version(self, runner):
        from zircolite import __version__

        run = runner.binary("--version")
        reported = re.search(r"Zircolite - v(\S+)", run.stdout)
        assert reported, f"no version line in:\n{run.stdout}"
        assert reported.group(1) == __version__

    def test_help_exits_zero(self, runner):
        run = runner.binary("--help")
        assert "--pipeline-list" in run.stdout

    def test_onedir_layout(self, dist):
        """The executable sits beside _internal/, with no shipped assets next to it.

        Without _internal/ this is a onefile build, which unpacks itself on every
        run. A config/, rules/, templates/ or gui/ beside the executable, as a
        release package has, would answer for a file missing from the bundle.
        """
        assert (dist / "_internal" / "base_library.zip").is_file()
        beside = [name for name in ("config", "rules", "templates", "gui") if (dist / name).exists()]
        assert not beside, f"ZIRCOLITE_BINARY must be the raw build, not a package: found {beside}"

    def test_no_build_tooling_is_bundled(self, dist):
        """The spec excludes these; a hook that aliased its way back would ship
        code that THIRD_PARTY_LICENSES has no notice for."""
        internal = dist / "_internal"
        bundled = [name for name in ("setuptools", "_distutils_hack", "pkg_resources", "Cython", "pytest")
                   if (internal / name).exists()]
        assert not bundled, f"build tooling in the bundle: {bundled}"

    def test_architecture_matches_the_interpreter(self, binary):
        """A cross-built or emulated leg would ship the wrong CPU under the right name."""
        expected = _MACHINES.get(platform.machine().lower(), platform.machine().lower())
        assert executable_architectures(binary) == {expected}


# =============================================================================
# pySigma
# =============================================================================

PIPELINE_VARIANTS = {
    "no-pipeline": [],
    "sysmon": ["-p", "sysmon"],
    "windows": ["-p", "windows-logsources", "-p", "windows-audit"],
}


def _installed_pipelines(run: Run) -> set[str]:
    listed = re.search(r"Installed pipelines : (.*)$", run.stdout, re.MULTILINE)
    assert listed, f"no pipeline list in:\n{run.stdout}"
    return {name.strip() for name in listed.group(1).split(",") if name.strip()}


def _convert(run_with, variant: str) -> list[dict]:
    run = run_with(
        "-sr", "-r", str(SIGMA_FIXTURES), *PIPELINE_VARIANTS[variant],
        "-e", str(FIXTURES / "sample_events.json"), "-j", "-o", "detected.json",
    )
    saved = sorted(run.cwd.glob("ruleset-*.json"))
    assert len(saved) == 1, f"expected one saved ruleset, found {saved}\n{run.output}"
    return json.loads(saved[0].read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def conversions(runner) -> dict[str, dict[str, list[dict]]]:
    return {
        variant: {"binary": _convert(runner.binary, variant),
                  "source": _convert(runner.source, variant)}
        for variant in PIPELINE_VARIANTS
    }


def _by_id(ruleset: list[dict]) -> dict[str, dict]:
    return {rule["id"]: rule for rule in ruleset}


class TestSigma:
    def test_pipeline_list_matches_source(self, runner):
        binary = _installed_pipelines(runner.binary("--pipeline-list", "-n"))
        source = _installed_pipelines(runner.source("--pipeline-list", "-n"))
        assert binary == source
        assert {"sysmon", "windows-logsources", "windows-audit"} <= binary

    @pytest.mark.parametrize("variant", list(PIPELINE_VARIANTS))
    def test_converted_rules_match_source(self, conversions, variant):
        converted = conversions[variant]
        assert len(converted["source"]) == len(list(SIGMA_FIXTURES.glob("*.yml")))
        assert _by_id(converted["binary"]) == _by_id(converted["source"])

    def test_the_pipelines_change_the_sql(self, conversions):
        """Parity proves nothing if the fixtures convert the same with or without a pipeline."""
        sql = {
            variant: {rule_id: rule["rule"] for rule_id, rule in _by_id(c["source"]).items()}
            for variant, c in conversions.items()
        }
        assert sql["no-pipeline"] != sql["sysmon"]
        assert sql["no-pipeline"] != sql["windows"]
        assert sql["sysmon"] != sql["windows"]
        bitsadmin = "3f6b1e2a-7c4d-4e8f-9a0b-1c2d3e4f5a60"
        special_logon = "3f6b1e2a-7c4d-4e8f-9a0b-1c2d3e4f5a62"
        assert "EventID=1 " in sql["sysmon"][bitsadmin][0]
        assert "EventID=1 " not in sql["no-pipeline"][bitsadmin][0]
        assert "Channel='Security'" in sql["windows"][special_logon][0]
        assert "Channel='Security'" not in sql["no-pipeline"][special_logon][0]

    def test_an_unknown_pipeline_is_fatal(self, runner):
        run = runner.binary(
            "-r", str(SIGMA_FIXTURES), "-p", "nope",
            "-e", str(FIXTURES / "sample_events.json"), "-j", "-n", check=False,
        )
        assert run.returncode == 2, run.output
        assert "nope" in run.output


# =============================================================================
# Archives
# =============================================================================

def _write_7z(target: Path, source: Path, filters=None, password=None, header_encryption=False):
    import py7zr

    try:
        with py7zr.SevenZipFile(
            target, "w", filters=filters, password=password,
            header_encryption=header_encryption,
        ) as archive:
            archive.write(source, source.name)
    except (py7zr.exceptions.UnsupportedCompressionMethodError, ImportError) as exc:
        pytest.skip(f"py7zr cannot write this archive here: {exc}")


def _build_archive(kind: str, source: Path, directory: Path) -> tuple[Path, list[str]]:
    """Write *source* into an archive of *kind*; return it and the flags it needs."""
    if kind == "gz":
        target = directory / f"{source.name}.gz"
        target.write_bytes(gzip.compress(source.read_bytes()))
        return target, []
    if kind == "bz2":
        target = directory / f"{source.name}.bz2"
        target.write_bytes(bz2.compress(source.read_bytes()))
        return target, []
    if kind == "zip":
        target = directory / f"{source.name}.zip"
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(source, source.name)
        return target, []

    py7zr = pytest.importorskip("py7zr")
    target = directory / f"{source.name}.7z"
    filters = {
        "7z-lzma2": [{"id": py7zr.FILTER_LZMA2, "preset": 7}],
        "7z-zstd": [{"id": py7zr.FILTER_ZSTD}],
        "7z-ppmd": [{"id": py7zr.FILTER_PPMD}],
        "7z-bcj": [{"id": py7zr.FILTER_X86}, {"id": py7zr.FILTER_LZMA2}],
        "7z-brotli": [{"id": py7zr.FILTER_BROTLI}],
    }
    if kind in filters:
        _write_7z(target, source, filters=filters[kind])
        return target, []
    if kind == "7z-aes":
        _write_7z(target, source, password=ARCHIVE_PASSWORD)
    elif kind == "7z-encrypted-header":
        _write_7z(target, source, password=ARCHIVE_PASSWORD, header_encryption=True)
    else:
        raise AssertionError(f"unknown archive kind {kind}")
    return target, ["--archive-password", ARCHIVE_PASSWORD]


ARCHIVE_KINDS = ["gz", "bz2", "zip", "7z-lzma2", "7z-zstd", "7z-ppmd", "7z-bcj",
                 "7z-brotli", "7z-aes", "7z-encrypted-header"]


class TestArchives:
    @pytest.mark.parametrize("kind", ARCHIVE_KINDS)
    def test_archive_detections_match_source(self, runner, inputs, tmp_path, kind):
        archive, flags = _build_archive(kind, FIXTURES / "sample_bitsadmin.evtx", tmp_path)
        args = ("-e", str(archive), "-r", str(inputs / "match_all.json"),
                "-o", "detected.json", *flags)

        binary = runner.binary(*args).detections()
        source = runner.source(*args).detections()

        assert match_count(binary) > 0, f"nothing read from the {kind} archive"
        assert fold_by_rule(binary) == fold_by_rule(source)


# =============================================================================
# Executors
# =============================================================================

def _assert_no_leftovers(run: Run) -> None:
    leftovers = [
        path.name for pattern in ("_MEI*", "zircolite-db-*", "zircolite-results-*")
        for path in run.tmp.glob(pattern)
    ]
    assert not leftovers, f"left behind in the temporary directory: {leftovers}"


class TestExecutors:
    """Process and thread workers, with auto-mode off so the runner cannot pick the path."""

    def test_process_executor(self, runner, inputs, executor_corpora):
        corpus, marked = executor_corpora["distinct"]
        args = ("-e", str(corpus), "-j", "-r", str(inputs / "marker.json"), "-o", "detected.json",
                "--no-auto-mode", "--executor", "process", "-w", "2", "--working-db", "disk")

        run = runner.binary(*args, watch_children=True)

        assert "[+] Executor: process" in run.stdout, run.stdout
        detections = run.detections()
        assert match_count(detections) == marked
        assert fold_by_rule(detections) == fold_by_rule(runner.source(*args).detections())
        assert run.children, "no worker process was ever started"
        _assert_no_leftovers(run)
        _assert_no_orphans(run.children)

    def test_thread_executor_is_repeatable(self, runner, inputs, executor_corpora):
        corpus, marked = executor_corpora["copies"]
        args = ("-e", str(corpus), "-j", "-r", str(inputs / "marker.json"), "-o", "detected.json",
                "--no-auto-mode", "--executor", "thread", "-w", "4")
        expected = fold_by_rule(runner.source(*args).detections())

        for attempt in range(5):
            run = runner.binary(*args, watch_children=True)
            assert "[+] Executor: thread" in run.stdout, run.stdout
            detections = run.detections()
            assert match_count(detections) == marked, f"attempt {attempt + 1}"
            assert fold_by_rule(detections) == expected, f"attempt {attempt + 1}"
            _assert_no_leftovers(run)
            _assert_no_orphans(run.children)


# =============================================================================
# Assets, from a working directory that has none of them
# =============================================================================

class TestAssets:
    def test_default_config_resolves(self, runner, inputs):
        args = ("-e", str(FIXTURES / "sample_events.json"), "-j",
                "-r", str(inputs / "match_all.json"), "-o", "detected.json")

        binary = runner.binary(*args).detections()

        assert match_count(binary) > 0
        assert fold_by_rule(binary) == fold_by_rule(runner.source(*args).detections())

    def test_a_shipped_template_renders(self, runner):
        args = ("-e", str(FIXTURES / "sample_bitsadmin.evtx"),
                "-r", "rules/rules_windows_sysmon.json", "-o", "detected.json",
                "-t", "templates/exportForSplunk.tmpl", "-T", "splunk.json")

        binary = runner.binary(*args)
        source = runner.source(*args)

        rendered = (binary.cwd / "splunk.json").read_text(encoding="utf-8")
        assert rendered.strip(), "the template rendered nothing"
        assert rendered == (source.cwd / "splunk.json").read_text(encoding="utf-8")

    def test_package_contains_the_gui(self, runner, inputs):
        run = runner.binary(
            "-e", str(FIXTURES / "sample_bitsadmin.evtx"),
            "-r", str(inputs / "match_all.json"), "-o", "detected.json", "--package",
        )

        packages = list(run.cwd.glob("zircogui-output-*.zip"))
        assert len(packages) == 1, f"expected one package, found {packages}"
        with zipfile.ZipFile(packages[0]) as package:
            assert "index.html" in package.namelist()

    def test_rules_beside_the_executable_win_over_the_bundle(self, runner, dist, tmp_path):
        copy = copy_dist(dist, tmp_path / "dist")
        (copy / "rules").mkdir()
        edited = [{**MATCH_ALL_RULESET[0], "title": "Edited beside the executable"}]
        (copy / "rules" / "rules_windows_sysmon.json").write_text(json.dumps(edited))

        run = runner.binary(
            "-e", str(FIXTURES / "sample_bitsadmin.evtx"),
            "-r", "rules/rules_windows_sysmon.json", "-o", "detected.json",
            executable=copy / runner.executable.name,
        )

        assert {d["title"] for d in run.detections()} == {"Edited beside the executable"}


# =============================================================================
# Transforms
# =============================================================================

TRANSFORM_INPUTS = [
    ("auditd", "audit_sample.log", ["-AU"]),
    ("json", "sample_events.json", ["-j"]),
    ("evtx", "sample_bitsadmin.evtx", []),
]


def _flattened(run: Run) -> list[str]:
    files = list(run.cwd.glob("flattened_events_*.json"))
    assert len(files) == 1, f"expected one --keepflat file, found {files}"
    lines = files[0].read_text(encoding="utf-8").splitlines()
    return sorted(json.dumps(json.loads(line), sort_keys=True) for line in lines if line.strip())


class TestTransforms:
    @pytest.mark.parametrize(
        "fmt,filename,flags", TRANSFORM_INPUTS, ids=[t[0] for t in TRANSFORM_INPUTS]
    )
    def test_all_transforms_match_source(self, runner, inputs, fmt, filename, flags):
        args = ("-e", str(FIXTURES / filename), *flags, "-r", str(inputs / "match_all.json"),
                "-o", "detected.json", "--all-transforms", "--keepflat")

        binary = runner.binary(*args)
        source = runner.source(*args)

        for run in (binary, source):
            assert "Transform file not found" not in run.output, run.output
        assert _flattened(binary), f"{fmt}: nothing was flattened"
        assert _flattened(binary) == _flattened(source)
        assert fold_by_rule(binary.detections()) == fold_by_rule(source.detections())


# =============================================================================
# Hygiene
# =============================================================================

class TestHygiene:
    def test_debug_run(self, runner, inputs):
        run = runner.binary(
            "--debug", "-e", str(FIXTURES / "sample_bitsadmin.evtx"),
            "-r", str(inputs / "match_all.json"), "-o", "detected.json",
        )
        assert match_count(run.detections()) > 0

    def test_generate_config(self, runner, tmp_path):
        binary_config, source_config = tmp_path / "binary.yaml", tmp_path / "source.yaml"

        runner.binary("--generate-config", str(binary_config))
        runner.source("--generate-config", str(source_config))

        assert binary_config.read_text(encoding="utf-8") == source_config.read_text(encoding="utf-8")

    def test_transform_list(self, runner):
        binary = runner.binary("--transform-list", "-n")
        source = runner.source("--transform-list", "-n")
        assert "Category" in binary.stdout
        assert binary.stdout == source.stdout


# =============================================================================
# Compiled flattening kernel
# =============================================================================

class TestKernel:
    @pytest.mark.parametrize("source,flags", [
        ("sample_bitsadmin.evtx", []),
        ("sample_events.json", ["-j"]),
        ("audit_sample.log", ["-AU"]),
    ], ids=["evtx", "json", "auditd"])
    def test_auto_selects_the_compiled_kernel(self, runner, inputs, tmp_path, source, flags):
        report = tmp_path / "performance.json"

        runner.binary(
            "-e", str(FIXTURES / source), *flags, "-r", str(inputs / "match_all.json"),
            "-o", "detected.json", "--performance-json", str(report),
        )

        files = json.loads(report.read_text(encoding="utf-8"))["files"]
        assert files
        assert [f["flattening"]["selected"] for f in files] == ["cython"] * len(files)

    def test_frozen_native_binary(self, runner, tmp_path):
        """Forcing the Cython kernel fails the run outright when the bundle lacks it."""
        events, rules = tmp_path / "events.json.gz", tmp_path / "rules.json"
        events.write_bytes(gzip.compress(
            b'{"CommandLine":"whoami"}\n' + b'{"CommandLine":"quiet"}\n' * 999
        ))
        queries = ["SELECT * FROM logs WHERE CommandLine LIKE '%whoami%'"]
        queries += [f"SELECT * FROM logs WHERE CommandLine LIKE '%missing{i}%'" for i in range(31)]
        rules.write_text(json.dumps(
            [{"title": "native smoke", "id": "native", "level": "high", "rule": queries}]
        ))

        run = runner.binary(
            "-e", str(events), "-r", str(rules), "-o", "output.json", "--quiet",
            "--no-parallel", "--no-auto-mode", "--json-input", "--working-db", "disk",
            "--flatten-backend", "cython",
        )

        assert match_count(run.detections("output.json")) == 1


# =============================================================================
# Platform floors
# =============================================================================

def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _files_with_magic(root: Path, magics: tuple[bytes, ...]) -> list[Path]:
    found = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as handle:
            if handle.read(4) in magics:
                found.append(path)
    return found


def _macos_minimums(load_commands: str) -> list[tuple[int, ...]]:
    """Minimum macOS versions named in ``otool -l`` output, old and new style."""
    minimums, command = [], None
    for line in load_commands.splitlines():
        words = line.split()
        if len(words) != 2:
            continue
        if words[0] == "cmd":
            command = words[1]
        elif (command, words[0]) in (("LC_BUILD_VERSION", "minos"),
                                     ("LC_VERSION_MIN_MACOSX", "version")):
            minimums.append(_version_tuple(words[1]))
    return minimums


def _required_tool(name: str) -> str:
    tool = shutil.which(name)
    if tool is None:
        pytest.fail(f"{name} is required to check the platform floor and is not installed")
    return tool


GLIBC_FLOOR = os.environ.get("ZIRCOLITE_GLIBC_FLOOR")
MACOS_FLOOR = os.environ.get("ZIRCOLITE_MACOS_FLOOR")


class TestPlatformFloors:
    @pytest.mark.skipif(not sys.platform.startswith("linux") or not GLIBC_FLOOR,
                        reason="set ZIRCOLITE_GLIBC_FLOOR on Linux")
    def test_no_elf_needs_a_newer_glibc(self, dist):
        assert GLIBC_FLOOR
        objdump = _required_tool("objdump")
        floor = _version_tuple(GLIBC_FLOOR)
        elves = _files_with_magic(dist, (b"\x7fELF",))
        assert elves, f"no ELF file under {dist}"

        too_new = {}
        for elf in elves:
            symbols = subprocess.run(
                [objdump, "-T", str(elf)], capture_output=True, text=True, check=True
            ).stdout
            versions = [_version_tuple(v) for v in re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", symbols)]
            if versions and max(versions) > floor:
                too_new[str(elf.relative_to(dist))] = ".".join(map(str, max(versions)))
        assert not too_new, f"need a glibc newer than {GLIBC_FLOOR}: {too_new}"

    @pytest.mark.skipif(not sys.platform.startswith("linux") or not GLIBC_FLOOR,
                        reason="set ZIRCOLITE_GLIBC_FLOOR on Linux")
    def test_libpython_stack_is_not_executable(self, dist):
        """glibc 2.41 refuses to load a library that asks for an executable stack."""
        readelf = _required_tool("readelf")
        libraries = sorted((dist / "_internal").rglob("libpython3*.so*"))
        assert libraries, "no libpython in the bundle"

        for library in libraries:
            headers = subprocess.run(
                [readelf, "-lW", str(library)], capture_output=True, text=True, check=True
            ).stdout
            stack = re.search(r"GNU_STACK(?:\s+0x[0-9a-fA-F]+){5}\s+([RWE ]+?)\s+0x", headers)
            assert stack, f"no GNU_STACK header in {library}"
            assert "E" not in stack.group(1), f"{library.name} has an executable stack"

    @pytest.mark.skipif(sys.platform != "darwin" or not MACOS_FLOOR,
                        reason="set ZIRCOLITE_MACOS_FLOOR on macOS")
    def test_no_macho_needs_a_newer_macos(self, dist):
        assert MACOS_FLOOR
        otool = _required_tool("otool")
        floor = _version_tuple(MACOS_FLOOR)
        machos = _files_with_magic(dist, (
            b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf",
        ))
        assert machos, f"no Mach-O file under {dist}"

        too_new = {}
        for macho in machos:
            commands = subprocess.run(
                [otool, "-l", str(macho)], capture_output=True, text=True, check=True
            ).stdout
            versions = _macos_minimums(commands)
            if versions and max(versions) > floor:
                too_new[str(macho.relative_to(dist))] = ".".join(map(str, max(versions)))
        assert not too_new, f"need a macOS newer than {MACOS_FLOOR}: {too_new}"


# =============================================================================
# Ctrl+C
# =============================================================================

@pytest.fixture(scope="module")
def interruptible_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A few tens of MB of JSONL and slow rules: seconds of work left to interrupt."""
    root = tmp_path_factory.mktemp("interrupt")
    events = root / "events.json"
    with events.open("w", encoding="utf-8") as handle:
        for index in range(150_000):
            handle.write(json.dumps({"Event": {
                "System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1},
                "EventData": {"CommandLine": f"cmd.exe /c echo {index}", "ProcessId": index},
            }}) + "\n")
    rules = root / "rules.json"
    rules.write_text(json.dumps([
        {"title": f"slow {i}", "id": f"slow-{i}", "level": "low", "tags": [],
         "rule": [f"SELECT * FROM logs WHERE CommandLine REGEXP 'x{{{i + 2}}}y'"]}
        for i in range(30)
    ]))
    return events, rules


class TestInterrupt:
    @pytest.mark.skipif(sys.platform == "win32", reason="SIGINT is delivered this way on POSIX only")
    def test_sigint_shuts_down_with_130(self, runner, interruptible_run):
        # The process executor is left out: a signal can land while a worker is
        # still starting, and that breaks the pool rather than the shutdown path.
        events, rules = interruptible_run
        _, cwd, tmp = runner.workspace("interrupt")
        process = subprocess.Popen(
            [str(runner.executable), "-e", str(events), "-j", "-r", str(rules),
             "--no-parallel", "--no-auto-mode", "-o", "detected.json"],
            cwd=cwd, env=runner.environment(tmp, oracle=False),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout: list[str] = []
        stderr: list[bytes] = []
        processing = threading.Event()

        def read_stdout() -> None:
            assert process.stdout is not None
            for raw in process.stdout:
                line = raw.decode("utf-8", "replace")
                stdout.append(line)
                if "Processing events" in line:
                    processing.set()
            processing.set()

        def read_stderr() -> None:
            assert process.stderr is not None
            stderr.append(process.stderr.read())

        readers = [threading.Thread(target=read_stdout, daemon=True),
                   threading.Thread(target=read_stderr, daemon=True)]
        for reader in readers:
            reader.start()
        try:
            assert processing.wait(RUN_TIMEOUT), "the run never started processing"
            assert process.poll() is None, (
                "the run finished before it could be interrupted:\n" + "".join(stdout)
            )
            process.send_signal(signal.SIGINT)
            returncode = process.wait(timeout=RUN_TIMEOUT)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            for reader in readers:
                reader.join(timeout=10)

        errors = b"".join(stderr).decode("utf-8", "replace")
        assert "Interrupt received" in errors, errors + "".join(stdout)
        assert returncode == 130, errors + "".join(stdout)


# =============================================================================
# -U, which needs the network
# =============================================================================

class TestUpdateRules:
    @pytest.mark.skipif(os.environ.get("ZIRCOLITE_TEST_NETWORK") != "1",
                        reason="set ZIRCOLITE_TEST_NETWORK=1 to download rulesets")
    def test_update_writes_beside_the_executable(self, runner, dist, tmp_path):
        copy = copy_dist(dist, tmp_path / "dist")
        bundled = tree_digest(copy / "_internal" / "rules")

        run = runner.binary("-U", executable=copy / runner.executable.name)

        assert sorted(p.name for p in (copy / "rules").glob("*.json")), run.output
        assert (copy / "rules" / "rules_windows_sysmon.json").is_file()
        assert tree_digest(copy / "_internal" / "rules") == bundled
        assert not (run.cwd / "rules").exists()


# =============================================================================
# Runs last in this module
# =============================================================================

def test_no_run_changed_the_bundle(binary, bundle_digest_at_start):
    assert tree_digest(binary.parent / "_internal") == bundle_digest_at_start
