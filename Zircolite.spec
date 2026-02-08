# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('config', 'config'), ('rules', 'rules'), ('templates', 'templates')]
binaries = []
hiddenimports = ['zircolite', 'zircolite.config', 'zircolite.config_loader', 'zircolite.console', 'zircolite.core', 'zircolite.detector', 'zircolite.extractor', 'zircolite.flattener', 'zircolite.parallel', 'zircolite.rules', 'zircolite.streaming', 'zircolite.templates', 'zircolite.utils']
tmp_ret = collect_all('evtx')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['zircolite.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Zircolite',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
