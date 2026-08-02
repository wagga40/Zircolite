# Frozen `--package` Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `--package` work in PyInstaller builds by bundling `gui/` and turning `_bundled_asset` into an ordered search, and add the guards that would have caught the regression.

**Architecture:** `zircolite/cli.py::_bundled_asset` currently returns a single unchecked path (`sys._MEIPASS` when frozen, the source tree otherwise). It becomes a search over an ordered list of roots, returning the first that holds the file. `Zircolite.spec` gains `('gui','gui')` so a bare binary carries the Mini-GUI archive. A static `ast`-based test keeps the spec and the call sites in agreement.

**Tech Stack:** Python 3.10+, pytest, PyInstaller 6.x, PDM, GitHub Actions.

## Global Constraints

- Branch: `fix-frozen-gui-package`, already created off `master`.
- Every path operation uses `pathlib.Path`. Never string-concatenate separators.
- Type hints on all function signatures. `pdm run python -m mypy zircolite` must stay clean.
- `pdm run ruff check .` must stay clean. Do **not** run `ruff format` — it would rewrite most of the codebase.
- Comments explain **why**, not **what**. No AI-trace comments, no optimization markers, no changelog-style inline notes. No AI attribution in commit messages — no trailers, no "Generated with" lines.
- Commit messages: imperative subject, sentence case, no trailing period; body explains why.
- Run `pdm run pytest` before every commit.
- Design doc: `docs/superpowers/specs/2026-08-02-frozen-gui-package-design.md`.

**Reference numbers (already measured — do not re-derive):**
- Binary without `gui` bundled: 31,137,408 bytes. With: 37,230,384 bytes (+5.81 MB, +19.6%).
- Frozen `--package` today fails with exit 1 and `Cannot create GUI package: missing file(s): /var/folders/.../_MEIxxxx/gui/zircogui.zip`.

## File Structure

| File | Responsibility | Task |
|------|----------------|------|
| `zircolite/cli.py:539-548` | `_bundled_asset` — ordered root search | 1 |
| `zircolite/cli.py:1140,1151` | `--timesketch` / `--navigator-output` template resolution | 2 |
| `tests/test_entry_point.py` | owns every `_bundled_asset` case, and the new spec/call-site sync guard | 1, 3 |
| `tests/test_cli.py` (`TestCLIRegressionFixes`) | end-to-end CWD-override behaviour of the implicit templates | 2 |
| `Zircolite.spec` | what a PyInstaller build carries | 3 |
| `.github/workflows/build_pyinstaller.yml` | end-to-end `--package` guard | 4 |
| `docs/Internals.md`, `docs/Advanced.md`, `docs/Usage.md` | resolution order and override rules | 5 |

---

### Task 1: `_bundled_asset` searches an ordered list of roots

**Files:**
- Modify: `zircolite/cli.py:539-548`
- Test: `tests/test_entry_point.py:56-77` (rewrite one test, add three)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `_bundled_asset(*parts: str) -> Path` — unchanged signature. New contract: returns the first existing candidate across (frozen only) the directory holding `sys.executable`, then `sys._MEIPASS`, then always the source tree `Path(__file__).resolve().parent.parent`. When no root holds the file it returns the **first** root's candidate, not the last.

- [ ] **Step 1: Write the failing tests**

In `tests/test_entry_point.py`, replace the existing `test_bundled_asset_uses_the_bootloader_root_when_frozen` with the version below and add the two tests after it. Keep the existing `test_bundled_assets_resolve_from_another_directory` exactly as it is — it must keep passing unchanged.

```python
def test_bundled_asset_uses_the_bootloader_root_when_frozen(tmp_path, monkeypatch):
    """A PyInstaller build unpacks the data beside the bootloader, not beside the module."""
    unpacked = tmp_path / "unpacked"
    (unpacked / "config").mkdir(parents=True)
    (unpacked / "config" / "config.yaml").write_text("", encoding="utf-8")
    beside = tmp_path / "beside"
    beside.mkdir()

    monkeypatch.setattr(sys, "executable", str(beside / "Zircolite"))
    monkeypatch.setattr(sys, "_MEIPASS", str(unpacked), raising=False)

    resolved = zircolite_cli._bundled_asset("config", "config.yaml")

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

    resolved = zircolite_cli._bundled_asset("gui", "zircogui.zip")

    assert resolved == beside / "gui" / "zircogui.zip"


def test_bundled_asset_names_a_path_a_user_can_act_on_when_nothing_holds_the_file(tmp_path, monkeypatch):
    """The caller prints this path; a temporary _MEIxxxx directory tells a user nothing."""
    unpacked = tmp_path / "unpacked"
    unpacked.mkdir()
    beside = tmp_path / "beside"
    beside.mkdir()

    monkeypatch.setattr(sys, "executable", str(beside / "Zircolite"))
    monkeypatch.setattr(sys, "_MEIPASS", str(unpacked), raising=False)

    resolved = zircolite_cli._bundled_asset("gui", "zircogui.zip")

    assert resolved == beside / "gui" / "zircogui.zip"
    assert not resolved.is_file()
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
pdm run pytest tests/test_entry_point.py -q
```

Expected: exactly two failures — `test_bundled_asset_prefers_the_copy_beside_the_binary` and `test_bundled_asset_names_a_path_a_user_can_act_on_when_nothing_holds_the_file`. Both assert `beside/...`; today the resolver returns the `_MEIPASS` candidate unconditionally.

`test_bundled_asset_uses_the_bootloader_root_when_frozen` passes both before and after. That is expected: it is rewritten not to fail now, but so it keeps asserting something once the resolver searches. Its old form monkeypatched `_MEIPASS` to an empty directory, which a search resolver would fall straight through.

- [ ] **Step 3: Replace the implementation**

In `zircolite/cli.py`, replace lines 539-548 with:

```python
def _bundled_asset(*parts: str) -> Path:
    """Resolve a file shipped with Zircolite, independent of the current directory."""
    # A PyInstaller build unpacks config/, rules/, templates/ and gui/ into a
    # temporary directory the bootloader names, but the release archive also
    # ships them beside the binary, where a user can edit a rule or drop in a
    # newer Mini-GUI. Prefer that copy, fall back to the bundle, and when
    # neither holds the file name the editable location -- it is the only one
    # of the two a user can do anything about.
    roots: list[Path] = []
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root is not None:
        roots.append(Path(sys.executable).resolve().parent)
        roots.append(Path(frozen_root))
    roots.append(Path(__file__).resolve().parent.parent)

    for root in roots:
        candidate = root.joinpath(*parts)
        if candidate.is_file():
            return candidate
    return roots[0].joinpath(*parts)
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
pdm run pytest tests/test_entry_point.py -q
pdm run pytest -q
pdm run ruff check . && pdm run python -m mypy zircolite
```

Expected: all pass, ruff clean, mypy clean.

- [ ] **Step 5: Commit**

```bash
git add zircolite/cli.py tests/test_entry_point.py
git commit -F - <<'EOF'
Search for a bundled asset instead of guessing one path

_bundled_asset returned sys._MEIPASS/<parts> whenever the process was frozen
and never checked that anything was there. Zircolite.spec does not bundle gui/,
so --package could not work in any PyInstaller build: it reported
_MEIxxxx/gui/zircogui.zip missing while the file sat in the working directory.

It now tries the directory holding the binary, then the unpacked bundle, then
the source tree, and returns the first that holds the file. The copy beside the
binary winning is the point -- the release archive ships config/, rules/,
templates/ and gui/ there so they can be edited, and that is the precedence
_resolve_default_path already gives the working directory.

On a total miss it returns the first candidate rather than the last, so the
caller's "missing file(s)" error names a directory the user can write to.
EOF
```

---

### Task 2: the implicit templates get the same working-directory override

**Files:**
- Modify: `zircolite/cli.py:1140`, `zircolite/cli.py:1151`
- Test: `tests/test_cli.py`, class `TestCLIRegressionFixes`, after `test_bundled_templates_resolve_from_any_cwd` (line 3108-3119)

**Interfaces:**
- Consumes: `_bundled_asset` from Task 1 (via `_resolve_default_path`, which already calls it).
- Produces: no new symbols. `args.template` entries for `--timesketch` and `--navigator-output` become the return of `_resolve_default_path(...)`, which is already a `str`, so the `str(...)` wrapper goes away.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_cli.py` inside `class TestCLIRegressionFixes`, directly after `test_bundled_templates_resolve_from_any_cwd`:

```python
    def test_a_local_timesketch_template_overrides_the_bundled_one(self, tmp_path, monkeypatch):
        """--config and --ruleset defaults let the CWD win; these templates must too."""
        ruleset, config, events = self._fixture(tmp_path)
        workdir = tmp_path / "elsewhere"
        (workdir / "templates").mkdir(parents=True)
        (workdir / "templates" / "exportForTimesketch.tmpl").write_text(
            "LOCAL-OVERRIDE", encoding="utf-8"
        )
        monkeypatch.chdir(workdir)

        with patch('sys.argv', ['zircolite.py', '-e', str(events), '-j', '-r', str(ruleset), '-c', str(config), '-o', str(tmp_path / "out.json"), '--timesketch', *get_log_arg(tmp_path)]):
            zircolite_script.main()

        produced = list(workdir.glob("timesketch-*.json"))
        assert produced, "the --timesketch shortcut produced no output"
        assert "LOCAL-OVERRIDE" in produced[0].read_text(encoding="utf-8")
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pdm run pytest "tests/test_cli.py::TestCLIRegressionFixes::test_a_local_timesketch_template_overrides_the_bundled_one" -q
```

Expected: FAIL — the produced file holds the rendered bundled Timesketch NDJSON, not `LOCAL-OVERRIDE`, because `_bundled_asset` never consults the working directory.

- [ ] **Step 3: Route both shortcuts through `_resolve_default_path`**

In `zircolite/cli.py`, change line 1140 from:

```python
        args.template.append([str(_bundled_asset("templates", "exportForTimesketch.tmpl"))])
```

to:

```python
        args.template.append([_resolve_default_path(
            "templates/exportForTimesketch.tmpl", "templates", "exportForTimesketch.tmpl"
        )])
```

and line 1151 from:

```python
        args.template.append([str(_bundled_asset("templates", "exportForAttackNavigator.tmpl"))])
```

to:

```python
        args.template.append([_resolve_default_path(
            "templates/exportForAttackNavigator.tmpl", "templates", "exportForAttackNavigator.tmpl"
        )])
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
pdm run pytest tests/test_cli.py -q
pdm run pytest -q
pdm run ruff check . && pdm run python -m mypy zircolite
```

Expected: all pass. `test_bundled_templates_resolve_from_any_cwd` must still pass — a working-directory miss falls through to the bundled copy.

- [ ] **Step 5: Commit**

```bash
git add zircolite/cli.py tests/test_cli.py
git commit -F - <<'EOF'
Let a local template override the --timesketch and --navigator-output defaults

Both shortcuts called _bundled_asset directly, so they always took the shipped
template and silently ignored an edited copy in the working directory. Every
other default path -- --config, --ruleset -- goes through _resolve_default_path
and lets the working directory win. These now do too; a miss still falls
through to the shipped copy, so running from an arbitrary directory is
unchanged.
EOF
```

---

### Task 3: bundle the GUI, and keep the spec honest with a static test

**Files:**
- Modify: `Zircolite.spec:4`
- Test: `tests/test_entry_point.py` — add the imports it needs and three functions at the end

**Interfaces:**
- Consumes: `_bundled_asset` (Task 1) and the `_resolve_default_path` call sites (Task 2) — the scanner reads both.
- Produces: `_spec_bundled_directories() -> set[str]`, `_asset_directories_the_code_asks_for() -> tuple[set[str], list[str]]` (the directories found, and the `module:line` of any call site whose directory could not be read statically), `test_every_asset_the_code_asks_for_is_bundled()`.

- [ ] **Step 1: Write the failing test**

`tests/test_entry_point.py` already imports `ast` and defines `WORKSPACE_ROOT`. Append:

```python
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
    """Top-level directories the package resolves through the two asset helpers.

    ``_bundled_asset`` takes the directory first; ``_resolve_default_path`` takes
    the relative default first and the directory second. The forwarding call
    inside ``_resolve_default_path`` passes ``*parts`` and is skipped.
    """
    positions = {"_bundled_asset": 0, "_resolve_default_path": 1}
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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
pdm run pytest "tests/test_entry_point.py::test_every_asset_the_code_asks_for_is_bundled" -q
```

Expected: FAIL with `Zircolite.spec does not bundle ['gui']`.

- [ ] **Step 3: Bundle the GUI**

In `Zircolite.spec`, change line 4 from:

```python
datas = [('config', 'config'), ('rules', 'rules'), ('templates', 'templates')]
```

to:

```python
datas = [('config', 'config'), ('gui', 'gui'), ('rules', 'rules'), ('templates', 'templates')]
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
pdm run pytest tests/test_entry_point.py -q
pdm run pytest -q
pdm run ruff check . && pdm run python -m mypy zircolite
```

Expected: all pass.

- [ ] **Step 5: Prove it against a real build**

This is the only step in the plan that builds a binary. It takes a few minutes.

```bash
SP=$(mktemp -d)
pdm run pyinstaller --noconfirm --distpath "$SP/dist" --workpath "$SP/build" Zircolite.spec
mkdir -p "$SP/bare" && cp "$SP/dist/Zircolite" "$SP/bare/"
cd "$SP/bare" && ./Zircolite \
  -e "$OLDPWD/tests/fixtures/sample_bitsadmin.evtx" \
  -r "$OLDPWD/rules/rules_windows_sysmon.json" \
  -o "$SP/out.json" --package
ls zircogui-output-*.zip
```

Expected: exit 0 and one `zircogui-output-XXXX.zip`. The directory deliberately holds nothing but the binary, so a pass proves the bundled copy is what was used. Delete `$SP` afterwards; do not leave build artifacts in the repository.

- [ ] **Step 6: Commit**

```bash
git add Zircolite.spec tests/test_entry_point.py
git commit -F - <<'EOF'
Bundle the Mini-GUI archive and fail the suite when an asset is not bundled

Zircolite.spec carried config/, rules/ and templates/ but never gui/, so a
frozen --package had nothing to unpack and every binary build failed on it.
Bundling gui/zircogui.zip costs 5.8 MB, taking the binary from 31.1 MB to
37.2 MB, and makes --package work with nothing on disk but the executable.

The test is the part that matters. It reads the datas literal out of the spec
and every directory the code resolves through _bundled_asset or
_resolve_default_path, and fails when the second is not covered by the first.
It also refuses to pass if a call site starts computing its directory, since a
scanner that cannot read the call sites reports success while checking nothing.
EOF
```

---

### Task 4: prove it end to end in the binary workflow

**Files:**
- Modify: `.github/workflows/build_pyinstaller.yml` — insert one step after `Verify EVTX output` and before `Prepare release package`

**Interfaces:**
- Consumes: the bundled `gui/` from Task 3.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Add the step**

Insert this step immediately after the `Verify EVTX output` step:

```yaml
      # Run from a directory holding nothing but the binary. The prepared
      # release package has gui/ beside it, which the asset search prefers, so
      # a --package run from there would pass even with the archive missing
      # from the bundle -- exactly the regression this guards.
      - name: Verify --package works from the bundle alone
        run: |
          mkdir -p bare
          cp "${{ matrix.binary_path }}" bare/
          cd bare
          ./${{ matrix.binary_name }} -e ../evtx_sample.evtx -r ../rules/rules_windows_sysmon.json -o ../detected_for_package.json --package
          cd ..
          python -c "
          import pathlib, sys, zipfile
          zips = sorted(pathlib.Path('bare').glob('zircogui-output-*.zip'))
          if not zips:
              print('No zircogui-output-*.zip: gui/zircogui.zip is not in the bundle')
              sys.exit(1)
          names = zipfile.ZipFile(zips[0]).namelist()
          if 'index.html' not in names:
              print(f'{zips[0]} has no index.html; got {names[:10]}')
              sys.exit(1)
          print(f'Package OK: {zips[0]} ({len(names)} entries)')
          "
        shell: bash
```

- [ ] **Step 2: Verify the YAML parses**

```bash
python -c "
import yaml, pathlib
doc = yaml.safe_load(pathlib.Path('.github/workflows/build_pyinstaller.yml').read_text())
steps = [s['name'] for s in doc['jobs']['build']['steps'] if 'name' in s]
print(steps)
assert 'Verify --package works from the bundle alone' in steps
assert steps.index('Verify --package works from the bundle alone') < steps.index('Prepare release package')
"
```

Expected: the step list prints and both assertions hold.

- [ ] **Step 3: Know which archive the check reads**

The step inspects the **produced** `zircogui-output-*.zip`, not the source `gui/zircogui.zip`. They have different layouts and confusing them breaks the check:

- `gui/zircogui.zip` — 2045 entries, all nested under `zircogui/`, nothing at the root.
- `zircogui-output-*.zip` — 2044 entries with `index.html`, `Readme.md` and `data.js` at the root, because `ZircoliteGuiGenerator` archives the *contents* of `zircogui/` (`shutil.make_archive(self.outputFile, 'zip', f"{self.tmpDir}/zircogui")` in `zircolite/templates.py:285`).

Asserting `index.html` at the root of the produced archive is therefore correct, and is also what proves the generator ran rather than the archive merely being copied. No action needed in this step beyond not "fixing" the check to match the source archive.

- [ ] **Step 4: Run the suite**

```bash
pdm run pytest -q
```

Expected: unchanged, all pass. This task touches no Python.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/build_pyinstaller.yml
git commit -F - <<'EOF'
Run --package against the built binary in the release workflow

The workflow built binaries, ran them and shipped them without ever exercising
--package, which is why a build that could not produce a Mini-GUI package went
out unnoticed.

The step runs from a directory holding only the binary. The prepared release
package has gui/ beside it and the asset search prefers that copy, so checking
there would pass whether or not the archive is in the bundle.
EOF
```

---

### Task 5: document the resolution order and the override rules

**Files:**
- Modify: `docs/Internals.md` — after the project-layout tree (around line 330)
- Modify: `docs/Advanced.md` — the Mini-GUI "Automatic Generation" section (around line 968)
- Modify: `docs/Usage.md` — the "Templating and Mini-GUI" section (starts line 359)

**Interfaces:**
- Consumes: the behaviour from Tasks 1-3.
- Produces: nothing.

- [ ] **Step 1: Add the resolution order to `docs/Internals.md`**

After the project-layout tree, add:

```markdown
### Bundled Asset Resolution

`config/`, `rules/`, `templates/` and `gui/` ship with Zircolite, and the paths
that point at them are relative, so they have to resolve whatever the working
directory is. Two helpers in `zircolite/cli.py` do it.

`_resolve_default_path` handles values a user can override on the command line
(`--config`, `--ruleset`, and the templates behind `--timesketch` and
`--navigator-output`): a file of that name in the working directory wins, and
anything else falls through to `_bundled_asset`.

`_bundled_asset` returns the first of these that holds the file:

| Order | Root | Applies to |
|-------|------|-----------|
| 1 | the directory holding the executable | PyInstaller builds only |
| 2 | `sys._MEIPASS`, where PyInstaller unpacks `datas` | PyInstaller builds only |
| 3 | the repository root, two levels up from `cli.py` | always |

Root 1 comes first because the release archive ships `config/`, `rules/`,
`templates/` and `gui/` beside the binary so they can be edited; a rule set
updated there takes effect without a rebuild. When no root holds the file the
first candidate is returned, so the error names a directory the user can write
to rather than a temporary `_MEIxxxx` path.

Anything reachable this way must be listed in `datas` in `Zircolite.spec`.
`tests/test_entry_point.py::test_every_asset_the_code_asks_for_is_bundled`
fails the build when it is not.
```

- [ ] **Step 2: Add the override note to `docs/Advanced.md`**

In the Mini-GUI section, after the `--package --package-dir` example block, add:

```markdown
`--package` needs `gui/zircogui.zip`. Zircolite looks for it beside the
executable first, then inside the binary itself — the standalone binaries carry
a copy, so `--package` works with nothing on disk but the executable. Dropping
an updated `gui/zircogui.zip` next to the binary replaces the built-in Mini-GUI
without a rebuild.
```

- [ ] **Step 3: Add the template override note to `docs/Usage.md`**

In the "Templating and Mini-GUI" section, after the `--timesketch` and
`--navigator-output` table rows (lines 366-367), add:

```markdown
Both shortcuts use the template of the same name from `templates/` in the
working directory when there is one, and the shipped template otherwise. The
same rule applies to `-c`/`--config` and `-r`/`--ruleset` defaults.
```

- [ ] **Step 4: Run the documentation tests**

```bash
pdm run pytest tests/test_docs_sync.py -q
pdm run pytest -q
```

Expected: all pass. `test_docs_sync.py` derives its expectations from the code, and `test_version_has_a_single_source` forbids the version literal in `README.md` and `docs/README.md` — none of these edits add one.

- [ ] **Step 5: Commit**

```bash
git add docs/Internals.md docs/Advanced.md docs/Usage.md
git commit -F - <<'EOF'
Document where Zircolite looks for the files it ships with

The resolution order is now load-bearing: it decides whether a binary can build
a Mini-GUI package, and it is what lets a user edit a rule set beside the binary
instead of rebuilding. None of it was written down.
EOF
```

---

## Verification

After Task 5, from a clean tree:

```bash
pdm run pytest -q
pdm run ruff check .
pdm run python -m mypy zircolite
git log --oneline master..HEAD
```

Expected: **1638 passed, 1 skipped** — the suite is at 1634 passed / 1 skipped today, and the plan adds four tests (two in Task 1, one in Task 2, one in Task 3; the Task 1 rewrite replaces a test rather than adding one). Ruff clean, mypy clean, six commits on the branch (the design doc plus the five above). Nothing is pushed — merging is a separate decision.

## Self-Review Notes

- Task 1 changes behaviour that Task 3's static test then locks in; Task 3 must not run before Task 1, because its scanner reads `_resolve_default_path` call sites that Task 2 adds. Running the tasks out of order gives a `wanted` set missing `templates`, and the test would still pass — wrongly. Keep the order.
- The `+5.81 MB` figure and the `31.1 → 37.2 MB` sizes are measured on macOS arm64. Linux and Windows binaries will differ in absolute size; the delta is the archive, 6.47 MB on disk, and is the same everywhere.
