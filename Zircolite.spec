# -*- mode: python ; coding: utf-8 -*-
import hashlib
import importlib
import os
import sys
from importlib.util import find_spec
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules

# Analysis bundles the zircolite package that sits beside this spec, so the
# kernel check below has to look at that tree and not at an installed copy.
sys.path.insert(0, SPECPATH)

datas = [('config', 'config'), ('gui', 'gui'), ('rules', 'rules'), ('templates', 'templates')]
binaries = []
# py7zr is only ever imported inside a function, so it reaches the bundle
# through the bytecode scan alone. Name it, or a .7z input fails in a binary
# that no CI step feeds one to.
hiddenimports = ['py7zr']


def _not_a_test_module(name):
    return '.test' not in name


# pySigma discovers pipelines and backends with pkgutil.iter_modules at run
# time, which the bytecode scan cannot follow. Without them `-p sysmon` finds
# nothing to apply and the rules convert without their EventID conditions.
hiddenimports += collect_submodules('sigma.pipelines', filter=_not_a_test_module)
hiddenimports += collect_submodules('sigma.backends', filter=_not_a_test_module)
for library in ('evtx', 'ijson'):
    library_data, library_binaries, library_imports = collect_all(library)
    datas += library_data
    binaries += library_binaries
    hiddenimports += library_imports

# streaming.py loads the kernel through importlib, so the scan misses it too.
# A frozen build ships no flatten_kernel.py for the run-time staleness check to
# read, which makes this the last point where a stale kernel can be caught.
kernel_source = Path(SPECPATH, 'zircolite', 'flatten_kernel.py')
kernel = find_spec('zircolite._flatten_native')
kernel_problem = None
if kernel is None:
    kernel_problem = f'zircolite._flatten_native is not built beside {kernel_source}'
elif Path(kernel.origin).resolve().parent != kernel_source.resolve().parent:
    # An editable install's import hook can answer for a package tree other
    # than the one Analysis is about to bundle.
    kernel_problem = f'found {kernel.origin}, which is not beside {kernel_source}'
else:
    try:
        built_from = importlib.import_module('zircolite._flatten_native').SOURCE_SHA256
    except (ImportError, AttributeError) as exc:
        kernel_problem = f'{kernel.origin} cannot be used ({exc})'
    else:
        if built_from != hashlib.sha256(kernel_source.read_bytes()).hexdigest():
            kernel_problem = f'{kernel.origin} was compiled from an older {kernel_source}'
if kernel_problem is None:
    hiddenimports += ['zircolite._flatten_native']
elif os.environ.get('ZIRCOLITE_REQUIRE_NATIVE') == '1':
    raise SystemExit(
        f'ZIRCOLITE_REQUIRE_NATIVE=1: {kernel_problem}. The kernel must be built in '
        'place, beside flatten_kernel.py: run pdm install (or another editable '
        'install of the project) with a C compiler available, then build again.'
    )
else:
    print(f'WARNING: {kernel_problem}; the binary will flatten events in Python.')


a = Analysis(
    ['zircolite.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', '_tkinter', 'pytest', 'Cython', 'IPython'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

# One directory rather than one file: a onefile build unpacks itself on every
# start, which costs seconds on macOS and fails where /tmp is mounted noexec.
# The default _internal/ contents directory is kept on purpose; '.' would put
# zircolite/ beside the Zircolite executable, and those collide on
# case-insensitive filesystems.
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Zircolite',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='Zircolite',
)
