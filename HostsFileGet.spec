# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


project_root = Path(SPECPATH).resolve()
datas = []
if (project_root / "icon.png").exists():
    datas.append(("icon.png", "."))
if (project_root / "icon.ico").exists():
    datas.append(("icon.ico", "."))
source_manifest_path = project_root / "data" / "blocklist_sources.json"
if source_manifest_path.exists():
    datas.append((str(source_manifest_path), "data"))
i18n_dir = project_root / "data" / "i18n"
if i18n_dir.exists():
    for catalog_path in i18n_dir.glob("*.json"):
        datas.append((str(catalog_path), "data/i18n"))

icon_args = []
if (project_root / "icon.ico").exists():
    icon_args = ["icon.ico"]


a = Analysis(
    ['hosts_editor.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
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
    name='HostsFileGet',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=icon_args,
)
