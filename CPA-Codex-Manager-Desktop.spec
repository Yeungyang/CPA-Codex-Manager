# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path


project_root = Path.cwd()
block_cipher = None
app_name = "CPA-Codex-Manager"
macos_icon = project_root / "assets" / "macOS" / "AppIcon.icns"
if not macos_icon.exists():
    macos_icon = project_root / "assets" / "icon.icns"
windows_icon = project_root / "assets" / "icon.ico"
is_macos = sys.platform == "darwin"
is_windows = sys.platform.startswith("win")

datas = [
    (str(project_root / "templates"), "templates"),
    (str(project_root / "static"), "static"),
    (str(project_root / ".env.example"), "."),
]

hiddenimports = [
    "aiohttp",
    "webview",
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "websockets",
    "websockets.legacy",
    "jinja2",
    "aiosqlite",
    "src.services.outlook.providers.imap_old",
    "src.services.outlook.providers.imap_new",
    "src.services.outlook.providers.graph_api",
]


a = Analysis(
    ["desktop.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=app_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(windows_icon) if is_windows and windows_icon.exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=app_name,
)

if is_macos:
    app = BUNDLE(
        coll,
        name=f"{app_name}.app",
        icon=str(macos_icon) if macos_icon.exists() else None,
        bundle_identifier="com.maoleio.cpacodexmanager",
        info_plist={
            "CFBundleName": app_name,
            "CFBundleDisplayName": app_name,
            "CFBundleExecutable": app_name,
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1.0.0",
            "LSMinimumSystemVersion": "11.0",
        },
    )
else:
    app = coll