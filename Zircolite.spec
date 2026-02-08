# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('config', 'config'), ('rules', 'rules'), ('templates', 'templates')]
binaries = []
hiddenimports = ['zircolite', 'zircolite.config', 'zircolite.config_loader', 'zircolite.console', 'zircolite.core', 'zircolite.detector', 'zircolite.extractor', 'zircolite.flattener', 'zircolite.parallel', 'zircolite.rules', 'zircolite.streaming', 'zircolite.templates', 'zircolite.utils']
tmp_ret = collect_all('evtx')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
# Rich: bundle full package and explicitly include dynamic unicode data modules (e.g. unicode17-0-0)
tmp_ret = collect_all('rich')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
try:
    import os
    import rich._unicode_data as _ud
    _ud_path = getattr(_ud, '__path__', [os.path.dirname(getattr(_ud, '__file__', ''))])
    if _ud_path:
        for _f in os.listdir(_ud_path[0]):
            if _f.startswith('unicode') and _f.endswith('.py') and _f != '__init__.py':
                hiddenimports.append('rich._unicode_data.' + _f[:-3])
except Exception:
    pass


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
