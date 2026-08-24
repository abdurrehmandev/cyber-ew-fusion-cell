# PyInstaller spec for Cyber-EW Fusion Cell.
#
# Build:
#   venv\Scripts\pyinstaller.exe packaging\cyber_ew_fusion_cell.spec --clean

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

block_cipher = None
root = Path.cwd()


def project_path(*parts):
    return str(root.joinpath(*parts))

a = Analysis(
    [project_path("desktop_app.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (project_path("config"), "config"),
        (project_path("core"), "core"),
        (project_path("interfaces"), "interfaces"),
        (project_path("scripts"), "scripts"),
        (project_path("storage"), "storage"),
        (project_path("utils"), "utils"),
        (project_path("interfaces", "__init__.py"), "interfaces"),
        (project_path("interfaces", "api.py"), "interfaces"),
        (project_path("interfaces", "dashboard.py"), "interfaces"),
        (project_path("data", "signatures"), "data/signatures"),
        (project_path("data", "threat_intel"), "data/threat_intel"),
        (project_path("requirements.txt"), "."),
        (project_path("README.md"), "."),
        *collect_data_files("streamlit", include_py_files=False),
        *copy_metadata("streamlit"),
        *copy_metadata("fastapi"),
        *copy_metadata("uvicorn"),
        *copy_metadata("pywebview"),
    ],
    hiddenimports=[
        *collect_submodules("streamlit"),
        *collect_submodules("fastapi"),
        *collect_submodules("webview"),
        *collect_submodules("uvicorn"),
        *collect_submodules("config"),
        *collect_submodules("core"),
        *collect_submodules("storage"),
        *collect_submodules("utils"),
        "interfaces",
        "interfaces.api",
        "interfaces.dashboard",
        "webview",
        "webview.platforms.edgechromium",
        "webview.platforms.winforms",
        "clr",
        "sklearn",
        "joblib",
        "yara",
        "win32evtlog",
        "win32service",
        "win32serviceutil",
        "servicemanager",
        "scapy.all",
    ],
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
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="Cyber-EW Fusion Cell",
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
)
