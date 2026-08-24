#!/usr/bin/env python3
"""
Run Cyber-EW Fusion Cell as a local live service.

Starts the detection pipeline, optionally starts the dashboard, and writes a
small service status heartbeat for the UI.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

IS_FROZEN = bool(getattr(sys, "frozen", False))
ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)).resolve()
RUNTIME_ROOT = Path(sys.executable).resolve().parent if IS_FROZEN else ROOT

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("CYBER_EW_DATA_DIR", str(RUNTIME_ROOT / "data"))
os.environ.setdefault("CYBER_EW_LOG_DIR", str(RUNTIME_ROOT / "logs"))

from config.settings import CONFIG
from core.pipeline import CyberEWPipeline


SERVICE_STATUS = CONFIG.data_dir / "outputs" / "service_status.json"


def write_status(
    status: str,
    pipeline: Optional[CyberEWPipeline] = None,
    dashboard_pid: Optional[int] = None,
    api_pid: Optional[int] = None,
    message: str = "",
) -> None:
    SERVICE_STATUS.parent.mkdir(parents=True, exist_ok=True)
    payload: Dict[str, Any] = {
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "service_pid": os.getpid(),
        "dashboard_pid": dashboard_pid,
        "api_pid": api_pid,
        "message": message,
    }
    if pipeline is not None:
        try:
            payload["pipeline"] = pipeline.get_statistics()
            if hasattr(pipeline.output_engine, "alert_store"):
                payload["persisted_alerts"] = pipeline.output_engine.alert_store.count()
        except Exception as exc:
            payload["pipeline_error"] = str(exc)

    SERVICE_STATUS.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def start_dashboard(port: int, host: str) -> subprocess.Popen:
    if IS_FROZEN:
        cmd = [
            sys.executable,
            "--dashboard-child",
            "--dashboard-port",
            str(port),
            "--host",
            host,
        ]
    else:
        cmd = [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(ROOT / "interfaces" / "dashboard.py"),
            "--server.address",
            host,
            "--server.port",
            str(port),
            "--server.headless",
            "true",
        ]
    return subprocess.Popen(cmd, cwd=RUNTIME_ROOT)


def start_api(port: int, host: str) -> subprocess.Popen:
    if IS_FROZEN:
        cmd = [
            sys.executable,
            "--api-child",
            "--api-port",
            str(port),
            "--host",
            host,
        ]
    else:
        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "interfaces.api:app",
            "--host",
            host,
            "--port",
            str(port),
        ]
    return subprocess.Popen(cmd, cwd=RUNTIME_ROOT)


def open_dashboard_later(url: str, delay_seconds: float = 4.0) -> None:
    timer = threading.Timer(delay_seconds, lambda: webbrowser.open(url))
    timer.daemon = True
    timer.start()


def run_dashboard_child(port: int, host: str) -> int:
    import streamlit.runtime.scriptrunner.magic_funcs  # noqa: F401
    from streamlit.web import bootstrap

    script_path = str(ROOT / "interfaces" / "dashboard.py")
    flag_options = {
        "global_developmentMode": False,
        "server_address": host,
        "server_port": port,
        "server_headless": True,
        "logger_level": "info",
    }
    bootstrap.load_config_options(flag_options)
    bootstrap.run(script_path, False, [], flag_options)
    return 0


def run_api_child(port: int, host: str) -> int:
    import uvicorn

    uvicorn.run(
        "interfaces.api:app",
        host=host,
        port=port,
        log_level="warning",
        log_config=None,
        access_log=False,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Cyber-EW Fusion Cell live service")
    parser.add_argument("--dashboard-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--api-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-dashboard", action="store_true", help="Run only the detection pipeline")
    parser.add_argument("--no-api", action="store_true", help="Do not start the REST API")
    parser.add_argument("--dashboard-port", type=int, default=int(os.environ.get("CYBER_EW_DASHBOARD_PORT", "8501")))
    parser.add_argument("--api-port", type=int, default=int(os.environ.get("CYBER_EW_API_PORT", "8080")))
    parser.add_argument("--host", default=os.environ.get("CYBER_EW_BIND_HOST", "127.0.0.1"))
    parser.add_argument("--duration", type=int, default=0, help="Optional run duration in seconds for smoke tests")
    parser.add_argument("--open-browser", action="store_true", help="Open the dashboard in the default browser after startup")
    args = parser.parse_args()

    if args.dashboard_child:
        return run_dashboard_child(args.dashboard_port, args.host)
    if args.api_child:
        return run_api_child(args.api_port, args.host)

    if args.no_dashboard:
        os.environ["CYBER_EW_DISABLE_MOCK_SOURCES"] = "1"

    dashboard_process: Optional[subprocess.Popen] = None
    api_process: Optional[subprocess.Popen] = None
    pipeline = CyberEWPipeline()

    try:
        if not args.no_dashboard:
            dashboard_process = start_dashboard(args.dashboard_port, args.host)
        if not args.no_api:
            api_process = start_api(args.api_port, args.host)

        pipeline.start()
        dashboard_url = f"http://{args.host}:{args.dashboard_port}"
        if args.open_browser and not args.no_dashboard:
            open_dashboard_later(dashboard_url)
        started = time.time()
        print("Cyber-EW live service running")
        print(f"Dashboard: {dashboard_url}" if not args.no_dashboard else "Dashboard: disabled")
        print(f"API: http://{args.host}:{args.api_port}" if not args.no_api else "API: disabled")
        print("Drop JSON telemetry into data/inputs/live/")
        print("Press Ctrl+C to stop")

        while True:
            dashboard_pid = dashboard_process.pid if dashboard_process else None
            api_pid = api_process.pid if api_process else None
            write_status("running", pipeline, dashboard_pid, api_pid)
            time.sleep(2)

            if args.duration and (time.time() - started) >= args.duration:
                break

    except KeyboardInterrupt:
        print("\nStopping Cyber-EW live service...")
    finally:
        pipeline.stop()
        if dashboard_process and dashboard_process.poll() is None:
            dashboard_process.terminate()
            try:
                dashboard_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                dashboard_process.kill()
        if api_process and api_process.poll() is None:
            api_process.terminate()
            try:
                api_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                api_process.kill()
        write_status("stopped", pipeline, None, None, "Service stopped")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
