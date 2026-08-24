#!/usr/bin/env python3
"""
Standalone Windows desktop launcher for Cyber-EW Fusion Cell.

The desktop app starts the local detection engine, dashboard, and API in the
background, then hosts the dashboard inside a native WebView window.
"""
from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import requests


_STDIO_HANDLES: list[object] = []


def configure_desktop_environment() -> None:
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    runtime_root = appdata / "Cyber-EW Fusion Cell"
    os.environ["CYBER_EW_DATA_DIR"] = str(runtime_root / "data")
    os.environ["CYBER_EW_LOG_DIR"] = str(runtime_root / "logs")
    registry = read_desktop_registry()

    operation_mode = str(registry.get("OperationMode") or "demo").lower()
    os.environ.setdefault("CYBER_EW_OPERATION_MODE", operation_mode)
    os.environ.setdefault("CYBER_EW_ENABLE_EVENTLOG", str(registry.get("EnableEventLog", "1")))
    os.environ.setdefault("CYBER_EW_ENABLE_PCAP", str(registry.get("EnablePacketCapture", "0")))

    if registry.get("EventLogChannels"):
        os.environ.setdefault("CYBER_EW_EVENTLOG_CHANNELS", str(registry["EventLogChannels"]))
    if registry.get("PacketInterface"):
        os.environ.setdefault("CYBER_EW_PCAP_INTERFACE", str(registry["PacketInterface"]))
    if registry.get("PacketBpfFilter"):
        os.environ.setdefault("CYBER_EW_PCAP_FILTER", str(registry["PacketBpfFilter"]))

    if "CYBER_EW_DISABLE_MOCK_SOURCES" not in os.environ:
        os.environ["CYBER_EW_DISABLE_MOCK_SOURCES"] = "1" if operation_mode == "production" else "0"
    if "CYBER_EW_ENABLE_MOCK_TELEMETRY" not in os.environ:
        os.environ["CYBER_EW_ENABLE_MOCK_TELEMETRY"] = "0" if operation_mode == "production" else "1"


def read_desktop_registry() -> dict[str, object]:
    if os.name != "nt":
        return {}
    try:
        import winreg
    except Exception:
        return {}

    settings: dict[str, object] = {}
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, r"Software\CyberEW") as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    settings[name] = value
                    index += 1
        except OSError:
            continue
    return settings


class NullInput:
    encoding = "utf-8"

    def read(self, *_: object, **__: object) -> str:
        return ""

    def readline(self, *_: object, **__: object) -> str:
        return ""

    def isatty(self) -> bool:
        return False


def ensure_windowed_stdio() -> None:
    """Give windowed/frozen child processes real streams for logging libraries."""
    log_dir = Path(os.environ["CYBER_EW_LOG_DIR"])
    log_dir.mkdir(parents=True, exist_ok=True)
    frozen = bool(getattr(sys, "frozen", False))

    if sys.stdin is None:
        sys.stdin = NullInput()  # type: ignore[assignment]
        sys.__stdin__ = sys.stdin

    if frozen or sys.stdout is None or not hasattr(sys.stdout, "isatty"):
        stdout = (log_dir / "desktop_stdout.log").open("a", encoding="utf-8", buffering=1)
        _STDIO_HANDLES.append(stdout)
        sys.stdout = stdout
        sys.__stdout__ = stdout

    if frozen or sys.stderr is None or not hasattr(sys.stderr, "isatty"):
        stderr = (log_dir / "desktop_stderr.log").open("a", encoding="utf-8", buffering=1)
        _STDIO_HANDLES.append(stderr)
        sys.stderr = stderr
        sys.__stderr__ = stderr


configure_desktop_environment()
ensure_windowed_stdio()

from config.settings import CONFIG
from core.pipeline import CyberEWPipeline
from run_live import (
    run_api_child,
    run_dashboard_child,
    start_api,
    start_dashboard,
    write_status,
)


APP_NAME = "Cyber-EW Fusion Cell"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_DASHBOARD_PORT = 8765
DEFAULT_API_PORT = 8766


def configure_logging() -> None:
    CONFIG.log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(CONFIG.log_dir / "desktop_app.log"),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def wait_for_http(
    url: str,
    timeout_seconds: int = 45,
    *,
    expected_status: int = 200,
    content_marker: str | None = None,
) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == expected_status:
                if content_marker is None or content_marker.lower() in response.text.lower():
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False


def wait_for_dashboard(url: str, timeout_seconds: int = 45) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            response = requests.get(url, timeout=2)
            body = response.text.lower()
            if response.status_code == 200 and ("streamlit" in body or "stcore" in body):
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def stop_process(process: Optional[subprocess.Popen]) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def start_status_heartbeat(
    stop_event: threading.Event,
    pipeline: CyberEWPipeline,
    dashboard_process: Optional[subprocess.Popen],
    api_process: Optional[subprocess.Popen],
) -> threading.Thread:
    def worker() -> None:
        while not stop_event.is_set():
            try:
                write_status(
                    "running",
                    pipeline,
                    dashboard_process.pid if dashboard_process else None,
                    api_process.pid if api_process else None,
                )
            except Exception:
                logging.exception("Failed to write desktop status heartbeat")
            stop_event.wait(2)

    thread = threading.Thread(target=worker, name="desktop-status-heartbeat", daemon=True)
    thread.start()
    return thread


def show_error(message: str) -> None:
    try:
        import tkinter.messagebox as messagebox

        messagebox.showerror(APP_NAME, message)
    except Exception:
        logging.error(message)


def run_desktop(args: argparse.Namespace) -> int:
    configure_logging()
    dashboard_url = f"http://{args.host}:{args.dashboard_port}"
    health_url = f"http://{args.host}:{args.api_port}/health"
    stop_event = threading.Event()
    dashboard_process: Optional[subprocess.Popen] = None
    api_process: Optional[subprocess.Popen] = None
    pipeline = CyberEWPipeline()

    try:
        dashboard_process = start_dashboard(args.dashboard_port, args.host)
        api_process = start_api(args.api_port, args.host)
        pipeline.start()
        start_status_heartbeat(stop_event, pipeline, dashboard_process, api_process)

        dashboard_ready = wait_for_dashboard(dashboard_url, timeout_seconds=args.startup_timeout)
        api_ready = wait_for_http(health_url, timeout_seconds=args.startup_timeout)
        if dashboard_process.poll() is not None:
            raise RuntimeError(f"Dashboard child exited early with code {dashboard_process.returncode}")
        if api_process.poll() is not None:
            raise RuntimeError(f"API child exited early with code {api_process.returncode}")
        if not dashboard_ready:
            raise RuntimeError(f"Dashboard did not start on {dashboard_url}")
        if not api_ready:
            if args.smoke_test:
                raise RuntimeError(f"API health endpoint did not answer on {health_url}")
            logging.warning("API health endpoint did not answer before the desktop window opened")

        if args.smoke_test:
            time.sleep(max(0, args.duration))
            return 0

        try:
            import webview
        except Exception as exc:
            raise RuntimeError("Desktop WebView dependency is not available.") from exc

        window = webview.create_window(
            APP_NAME,
            dashboard_url,
            width=1440,
            height=900,
            min_size=(1100, 720),
            text_select=True,
        )
        webview.start(gui="edgechromium", debug=False)
        logging.info("Desktop window closed: %s", getattr(window, "title", APP_NAME))
        return 0

    except Exception as exc:
        logging.exception("Desktop app failed")
        if not args.smoke_test:
            show_error(str(exc))
        return 1
    finally:
        stop_event.set()
        pipeline.stop()
        stop_process(dashboard_process)
        stop_process(api_process)
        try:
            write_status("stopped", pipeline, None, None, "Desktop app stopped")
        except Exception:
            logging.exception("Failed to write stopped status")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} desktop application")
    parser.add_argument("--dashboard-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--api-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dashboard-port", type=int, default=DEFAULT_DASHBOARD_PORT)
    parser.add_argument("--api-port", type=int, default=DEFAULT_API_PORT)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--duration", type=int, default=3, help=argparse.SUPPRESS)
    parser.add_argument("--startup-timeout", type=int, default=45, help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.dashboard_child:
            configure_logging()
            return run_dashboard_child(args.dashboard_port, args.host)
        if args.api_child:
            configure_logging()
            return run_api_child(args.api_port, args.host)
        return run_desktop(args)
    except Exception:
        configure_logging()
        logging.exception("Desktop app process failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
