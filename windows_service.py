#!/usr/bin/env python3
"""Windows Service wrapper for Cyber-EW Fusion Cell.

This module is intentionally optional. It imports pywin32 service modules only
when service commands are used, so ordinary development and tests still work on
systems without Windows Service support.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, List


ROOT = Path(__file__).resolve().parent
SERVICE_NAME = "CyberEWFusionCell"
SERVICE_DISPLAY = "Cyber-EW Fusion Cell"
SERVICE_DESCRIPTION = "Cyber-EW Fusion Cell local SOC fusion service"


class ServiceDependencyError(RuntimeError):
    pass


def _service_imports():
    try:
        import win32event  # type: ignore
        import win32service  # type: ignore
        import win32serviceutil  # type: ignore
        import servicemanager  # type: ignore
    except Exception as exc:  # pragma: no cover - platform dependent
        raise ServiceDependencyError("pywin32 service modules are required for Windows Service mode") from exc
    return win32event, win32service, win32serviceutil, servicemanager


win32event, win32service, win32serviceutil, servicemanager = (None, None, None, None)
try:  # pragma: no cover - import success depends on Windows service context
    win32event, win32service, win32serviceutil, servicemanager = _service_imports()
except ServiceDependencyError:
    pass


if win32serviceutil is not None:

    class CyberEWWindowsService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.process: subprocess.Popen | None = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY} starting")
            env = os.environ.copy()
            env.setdefault("CYBER_EW_PROFILE", "production")
            env.setdefault("CYBER_EW_ENABLE_EVENTLOG", "1")
            self.process = subprocess.Popen(
                [sys.executable, str(ROOT / "run_live.py")],
                cwd=ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            while True:
                rc = win32event.WaitForSingleObject(self.stop_event, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                if self.process.poll() is not None:
                    servicemanager.LogErrorMsg(f"{SERVICE_DISPLAY} child process exited with {self.process.returncode}")
                    break
            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY} stopped")

else:

    class CyberEWWindowsService:  # type: ignore[no-redef]
        pass


def handle_service_command(argv: Iterable[str]) -> int:
    """Handle service actions from main.py."""
    _service_imports()
    args = list(argv)
    action = args[0] if args else "help"

    if action == "install-service":
        win32serviceutil.InstallService(  # type: ignore[union-attr]
            pythonClassString=f"{__name__}.CyberEWWindowsService",
            serviceName=SERVICE_NAME,
            displayName=SERVICE_DISPLAY,
            description=SERVICE_DESCRIPTION,
            startType=win32service.SERVICE_AUTO_START,  # type: ignore[union-attr]
        )
        print(f"Installed Windows service: {SERVICE_DISPLAY}")
        return 0
    if action == "remove-service":
        win32serviceutil.RemoveService(SERVICE_NAME)  # type: ignore[union-attr]
        print(f"Removed Windows service: {SERVICE_DISPLAY}")
        return 0
    if action == "start-service":
        win32serviceutil.StartService(SERVICE_NAME)  # type: ignore[union-attr]
        print(f"Started Windows service: {SERVICE_DISPLAY}")
        return 0
    if action == "stop-service":
        win32serviceutil.StopService(SERVICE_NAME)  # type: ignore[union-attr]
        print(f"Stopped Windows service: {SERVICE_DISPLAY}")
        return 0

    print("Service commands: install-service, remove-service, start-service, stop-service")
    return 1


if __name__ == "__main__":
    if win32serviceutil is None:
        print("pywin32 service modules are required for Windows Service mode", file=sys.stderr)
        raise SystemExit(1)
    win32serviceutil.HandleCommandLine(CyberEWWindowsService)
