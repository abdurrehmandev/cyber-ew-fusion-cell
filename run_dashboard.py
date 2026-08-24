#!/usr/bin/env python3
"""Launch the Cyber-EW Fusion Cell Streamlit dashboard."""
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    dashboard = root / "interfaces" / "dashboard.py"
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(dashboard),
        "--server.address",
        "127.0.0.1",
        "--server.port",
        "8501",
    ]
    return subprocess.call(cmd, cwd=root)


if __name__ == "__main__":
    raise SystemExit(main())
