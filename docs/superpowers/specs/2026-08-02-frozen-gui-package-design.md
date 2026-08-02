# Frozen builds cannot find `gui/zircogui.zip`

*2026-08-02*

## The defect

`--package` fails in every PyInstaller build. Reproduced against a real build
(PyInstaller 6.21.0, `Zircolite.spec` unmodified), run from a directory laid out
exactly as `build_pyinstaller.yml` prepares the release artifact:

```
$ ./Zircolite -e sample.evtx -r rules/rules_windows_sysmon.json -o out.json --package
[-] Cannot create GUI package: missing file(s):
    /var/folders/.../T/_MEI1ShFc2/gui/zircogui.zip
exit 1
```

`gui/zircogui.zip` was in the working directory at the time. The binary did not
look there.

## Why

`_bundled_asset` (`zircolite/cli.py`) returns exactly one path and never checks
whether anything is at it:

```python
frozen_root = getattr(sys, "_MEIPASS", None)
if frozen_root is not None:
    return Path(frozen_root).joinpath(*parts)
return Path(__file__).resolve().parent.parent.joinpath(*parts)
```

`Zircolite.spec` bundles `config`, `rules` and `templates`. It has never bundled
`gui`. So `_MEIPASS/gui/zircogui.zip` cannot exist, and no other path is tried.

This is a regression, not a latent gap. Until `e15f34c` (*Harden input handling,
detection and processing paths*, 2026-07-25) the path was `Path("gui/zircogui.zip")`
— working-directory relative, so a frozen binary run from its own package
directory found the file that ships beside it. `e15f34c` introduced
`_bundled_asset` and made the lookup `_MEIPASS`-only.

The root cause is an asymmetry between the two resolvers. `_resolve_default_path`
tries the working directory first and falls back to the bundle. `_bundled_asset`,
called directly for the GUI archive (`cli.py:589`) and for the `--timesketch` and
`--navigator-output` templates (`cli.py:1140,1151`), has no fallback at all. The
templates happen to work because `templates` is bundled, but a user-edited copy
beside the binary is silently ignored.

## Design

### 1. `_bundled_asset` becomes an ordered search

First root that actually holds the file wins:

| order | root | when |
|-------|------|------|
| 1 | `Path(sys.executable).resolve().parent` | frozen only |
| 2 | `Path(sys._MEIPASS)` | frozen only |
| 3 | `Path(__file__).resolve().parent.parent` | always |

`sys._MEIPASS` stays the signal for "frozen" — PyInstaller sets it for both
onefile and onedir builds. `sys.executable` is consulted only when frozen,
because in a source checkout it is the interpreter, not the application.

On a total miss the function returns the **first** candidate rather than the
last. The caller prints that path in its "missing file(s)" error, and
`<directory holding the binary>/gui/zircogui.zip` tells a user where to put the
file; `/var/folders/.../_MEIxxxx/gui/zircogui.zip` does not.

The deliberate consequence: `gui/`, `rules/`, `config/` or `templates/` placed
beside the binary now override the bundled copies. That is the same precedence
`_resolve_default_path` already gives the working directory, and it is why the
release artifact ships those directories beside the binary.

### 2. `Zircolite.spec` bundles the GUI

```python
datas = [('config', 'config'), ('gui', 'gui'), ('rules', 'rules'), ('templates', 'templates')]
```

Measured cost: 31,137,408 → 37,230,384 bytes (+5.81 MB, +19.6%). Verified: a
binary alone in an empty directory produces `zircogui-output-XXXX.zip`.

Both halves are needed. The bundle makes a bare `dist/Zircolite` work; the
search order lets a shipped or updated `gui/` beside the binary take precedence
over the frozen-in copy.

### 3. The implicit templates get the same override

`--timesketch` and `--navigator-output` move from `_bundled_asset` to
`_resolve_default_path`, so they resolve working directory → beside the binary →
bundle → source tree, like every other default path.

`tests/test_cli.py:3109` already pins that these two must not depend on the
working directory; a working-directory miss still falls through to the bundle,
so it keeps passing.

## Guards

### Static: the spec and the call sites must agree

A test in `tests/test_entry_point.py`, which already owns the `_bundled_asset`
cases. No build required — `Zircolite.spec` is a plain module and its `datas`
literal is statically parseable.

- `ast`-parse `Zircolite.spec`; take the module-level `datas = [...]` assignment
  and collect the destination name of each `(src, dst)` tuple. The `datas +=`
  lines fed by `collect_all` are ignored; they carry third-party payloads, not
  Zircolite assets.
- `ast`-parse every module under `zircolite/`; collect the first positional
  argument of every `_bundled_asset(...)` call.
- Assert each is a bundled directory.
- Assert no call site passes a non-constant first argument. Without this the
  test goes blind the day someone writes `_bundled_asset(kind, name)` and
  reports success while checking nothing.

### End-to-end: the binary must actually package

A step in `build_pyinstaller.yml` that runs `dist/Zircolite` with `--package`
from a scratch directory containing **no `gui/`**, and asserts a
`zircogui-output-*.zip` exists and contains `index.html`.

Running it from the prepared release directory instead would exercise the
beside-the-binary override and prove nothing about the bundle. The existing
"Verify package runs (from package dir)" step already covers that layout.

This workflow only fires on `Release v` commits and `workflow_dispatch`, so the
static test is the primary guard and this one is the backstop.

## Tests

| test | change |
|------|--------|
| `test_bundled_assets_resolve_from_another_directory` | unchanged — still passes, source-tree root is last but is the only root outside a frozen build |
| `test_bundled_asset_uses_the_bootloader_root_when_frozen` | rewritten: monkeypatching `_MEIPASS` to an empty `tmp_path` finds nothing under a search resolver, so the test must create the file and assert it is found |
| beside-the-binary precedence | new: with both roots populated, the copy beside `sys.executable` wins |
| miss reporting | new: with no root holding the file, the returned path is under the first root |
| spec/call-site sync | new, described above |

## Documentation

- `docs/Internals.md` — the resolution order, as a table.
- `docs/Advanced.md` (Mini-GUI) — `--package` works from the binary alone, and a
  `gui/zircogui.zip` beside it or in the working directory overrides the bundled
  Mini-GUI.
- `docs/Usage.md` — the override rule for `--timesketch` and
  `--navigator-output` templates.

## Shape

Branch `fix-frozen-gui-package` off `master`. Three commits:

1. The resolver change and the template call sites, with their tests.
2. `Zircolite.spec` plus both guards.
3. Documentation.

The defect predates and is independent of the CLI move, so this can ship on its
own.

## Out of scope

- Shrinking the binary. +5.81 MB is the accepted cost of a `--package` that
  works with nothing on disk but the executable.
- Removing `gui` from the release artifact's `cp -r`. It is now the override
  source, not dead weight.
- `git bisect` across `2c37d44`/`df0f467`. Those trees have no entry point and
  the branch was merged rather than restructured; `--skip` handles it.
