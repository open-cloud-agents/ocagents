# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller specification for compiling Open Cloud Agents (ocagents)
into a hermetic, single-file native executable.
"""
import os
import sys
from pathlib import Path

# When PyInstaller executes this spec, current working directory is the repository root
REPO_ROOT = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd())).resolve()

datas = [
    (str(REPO_ROOT / "agents"), "agents"),
    (str(REPO_ROOT / "skills"), "skills"),
    (str(REPO_ROOT / "rules"), "rules"),
    (str(REPO_ROOT / "scripts"), "scripts"),
    (str(REPO_ROOT / "schemas"), "schemas"),
    (str(REPO_ROOT / "docs"), "docs"),
    (str(REPO_ROOT / "AGENTS.md"), "."),
    (str(REPO_ROOT / "README.md"), "."),
    (str(REPO_ROOT / "CHANGELOG.md"), "."),
    (str(REPO_ROOT / "LICENSE"), "."),
]

a = Analysis(
    [str(REPO_ROOT / "src" / "ocagents" / "cli.py")],
    pathex=[str(REPO_ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=["yaml"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "boto3",
        "botocore",
        "google",
        "torch",
        "scipy",
        "numpy",
        "matplotlib",
        "tkinter",
        "test",
        "unittest",
    ],
    noarchive=False,
    optimize=2,
)

pyz = PYZ(a.pure)

# 1. High-Performance Pre-Extracted Onedir Distribution (Instantaneous Startup)
exe_onedir = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ocagents",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe_onedir,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="ocagents",
)

# 2. Monolithic Single-File Executable (Fallback for raw binary downloads)
exe_onefile = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ocagents-onefile",
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

