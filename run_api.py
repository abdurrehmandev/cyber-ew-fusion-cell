#!/usr/bin/env python3
"""Run the Cyber-EW Fusion Cell REST API."""
from __future__ import annotations

import os
import sys


def main() -> int:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed. Run: python -m pip install fastapi uvicorn")
        return 1

    port = int(os.environ.get("CYBER_EW_API_PORT", "8080"))
    uvicorn.run("interfaces.api:app", host="127.0.0.1", port=port, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
