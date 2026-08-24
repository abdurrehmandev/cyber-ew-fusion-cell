#!/usr/bin/env python3
"""
Operator CLI for Cyber-EW Fusion Cell.

This is the main local operations entry point for starting, stopping,
checking, and testing the project after deployment.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.error import URLError
from urllib.request import urlopen

from config.deployment import DeploymentProfile, get_profile, profile_environment, profile_names
from core.collectors.manager import collector_readiness


ROOT = Path(__file__).resolve().parent
PYTHON = Path(sys.executable)
SERVICE_STATUS = ROOT / "data" / "outputs" / "service_status.json"
HEALTH_REPORT = ROOT / "data" / "outputs" / "operator_health.json"
DASHBOARD_URL = "http://127.0.0.1:8501"
API_URL = "http://127.0.0.1:8080"
API_KEY_FILE = ROOT / "data" / "outputs" / "cyber_ew_api_key.txt"


REQUIRED_MODULES = {
    "yaml": "pyyaml",
    "requests": "requests",
    "pandas": "pandas",
    "numpy": "numpy",
    "sklearn": "scikit-learn",
    "joblib": "joblib",
    "streamlit": "streamlit",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "pytest": "pytest",
    "yara": "yara-python",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def profile_from_args(args: Optional[argparse.Namespace] = None) -> DeploymentProfile:
    return get_profile(getattr(args, "profile", None) if args else None)


def api_url(profile: Optional[DeploymentProfile] = None) -> str:
    return (profile or get_profile()).api_url


def dashboard_url(profile: Optional[DeploymentProfile] = None) -> str:
    return (profile or get_profile()).dashboard_url


def read_json(path: Path, fallback: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback
    return fallback


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def is_port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def http_json(url: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    try:
        with urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, json.JSONDecodeError):
        return None


def run_command(args: List[str], timeout: int = 120) -> Dict[str, Any]:
    started = time.time()
    proc = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return {
        "command": " ".join(args),
        "returncode": proc.returncode,
        "duration_seconds": round(time.time() - started, 3),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def pipeline_events_processed(status_payload: Dict[str, Any]) -> int:
    status_file = status_payload.get("status_file") or {}
    pipeline = status_file.get("pipeline", {}) if isinstance(status_file, dict) else {}
    return int(pipeline.get("events_processed", 0) or 0)


def process_exists(pid: Optional[int]) -> bool:
    if not pid:
        return False
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            text=True,
            capture_output=True,
        )
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def terminate_pid(pid: int) -> bool:
    if pid == os.getpid() or not process_exists(pid):
        return False
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], text=True, capture_output=True)
    else:
        os.kill(pid, 15)
    return True


def ensure_profile_api_key(profile: DeploymentProfile, env: Dict[str, str]) -> None:
    """Require an API key for hardened profiles, generating a local one if absent."""
    if not profile.api_key_required or env.get("CYBER_EW_API_KEY"):
        return
    API_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if API_KEY_FILE.exists():
        key = API_KEY_FILE.read_text(encoding="utf-8").strip()
    else:
        key = secrets.token_urlsafe(32)
        API_KEY_FILE.write_text(key + "\n", encoding="utf-8")
    env["CYBER_EW_API_KEY"] = key


def collect_status(profile: Optional[DeploymentProfile] = None) -> Dict[str, Any]:
    profile = profile or get_profile()
    status = read_json(SERVICE_STATUS, {})
    health = http_json(f"{profile.api_url}/health")
    readiness = http_json(f"{profile.api_url}/readiness")
    return {
        "generated_at": utc_now(),
        "profile": profile.as_dict(),
        "status_file": status,
        "api_health": health,
        "api_readiness": readiness,
        "urls": {
            "dashboard": profile.dashboard_url,
            "api": profile.api_url,
        },
        "ports": {
            f"dashboard_{profile.dashboard_port}": is_port_open(profile.dashboard_port, profile.bind_host),
            f"api_{profile.api_port}": is_port_open(profile.api_port, profile.bind_host),
        },
        "processes": {
            "service": process_exists(status.get("service_pid") if isinstance(status, dict) else None),
            "dashboard": process_exists(status.get("dashboard_pid") if isinstance(status, dict) else None),
            "api": process_exists(status.get("api_pid") if isinstance(status, dict) else None),
        },
    }


def print_status(payload: Dict[str, Any]) -> None:
    health = payload.get("api_health") or {}
    readiness = payload.get("api_readiness") or {}
    status_file = payload.get("status_file") or {}
    pipeline = status_file.get("pipeline", {}) if isinstance(status_file, dict) else {}
    profile = payload.get("profile") or {}
    urls = payload.get("urls") or {}
    print("Cyber-EW Fusion Cell Status")
    print("-" * 34)
    print(f"Profile: {profile.get('name', 'dev')}")
    print(f"API health: {health.get('status', 'unknown')}")
    print(f"Live service: {health.get('live_service', False)}")
    print(f"Service PID: {status_file.get('service_pid', '')}")
    print(f"Dashboard PID: {status_file.get('dashboard_pid', '')}")
    print(f"API PID: {status_file.get('api_pid', '')}")
    print(f"Events processed: {pipeline.get('events_processed', 0)}")
    print(f"Alerts generated: {pipeline.get('alerts_generated', 0)}")
    print(f"Persisted alerts: {status_file.get('persisted_alerts', health.get('persisted_alerts', 0))}")
    print(f"ML ready: {readiness.get('engines', {}).get('ml_available', False)}")
    print(f"YARA ready: {readiness.get('engines', {}).get('yara_available', False)}")
    print(f"Dashboard: {urls.get('dashboard', DASHBOARD_URL)}")
    print(f"API: {urls.get('api', API_URL)}")


def command_start(args: argparse.Namespace) -> int:
    profile = profile_from_args(args)
    status = collect_status(profile)
    dashboard_open = status["ports"].get(f"dashboard_{profile.dashboard_port}", False)
    api_open = status["ports"].get(f"api_{profile.api_port}", False)
    if status["processes"]["service"] and dashboard_open and api_open:
        print("Cyber-EW Fusion Cell is already running.")
        print_status(status)
        return 0

    env = profile_environment(profile)
    ensure_profile_api_key(profile, env)
    subprocess.Popen(
        [
            str(PYTHON),
            "run_live.py",
            "--host",
            profile.bind_host,
            "--dashboard-port",
            str(profile.dashboard_port),
            "--api-port",
            str(profile.api_port),
        ],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )

    for _ in range(30):
        time.sleep(1)
        health = http_json(f"{profile.api_url}/health")
        if health and health.get("status") == "ok":
            break

    print_status(collect_status(profile))
    if profile.api_key_required:
        print(f"API key file: {API_KEY_FILE}")
    return 0


def command_stop(_: argparse.Namespace) -> int:
    status = read_json(SERVICE_STATUS, {})
    pids = []
    if isinstance(status, dict):
        pids = [status.get("api_pid"), status.get("dashboard_pid"), status.get("service_pid")]
    stopped = [pid for pid in pids if isinstance(pid, int) and terminate_pid(pid)]
    if stopped:
        print(f"Stopped PIDs: {', '.join(str(pid) for pid in stopped)}")
    else:
        print("No managed Cyber-EW processes found from the status file.")
    return 0


def command_restart(args: argparse.Namespace) -> int:
    command_stop(args)
    time.sleep(2)
    return command_start(args)


def command_status(args: argparse.Namespace) -> int:
    payload = collect_status(profile_from_args(args))
    write_json(HEALTH_REPORT, payload)
    print_status(payload)
    print(f"Health report: {HEALTH_REPORT}")
    return 0 if (payload.get("api_health") or {}).get("status") == "ok" else 1


def command_open(args: argparse.Namespace) -> int:
    url = dashboard_url(profile_from_args(args))
    webbrowser.open(url)
    print(f"Opened {url}")
    return 0


def command_test(_: argparse.Namespace) -> int:
    checks = [
        [str(PYTHON), "-m", "compileall", "config", "core", "interfaces", "packaging", "scripts", "storage", "manage.py", "main.py", "run_live.py", "desktop_app.py", "run_api.py", "windows_service.py", "test_all.py"],
        [str(PYTHON), "test_all.py"],
        [str(PYTHON), "-m", "pytest", "tests", "-q"],
        [str(PYTHON), "main.py", "--test"],
    ]

    failures = []
    report = {"generated_at": utc_now(), "checks": []}
    for cmd in checks:
        print(f"Running: {' '.join(cmd)}")
        result = run_command(cmd, timeout=180)
        report["checks"].append(result)
        if result["returncode"] != 0:
            failures.append(result)
            print(result["stdout"])
            print(result["stderr"])

    write_json(ROOT / "data" / "outputs" / "operator_test_report.json", report)
    if failures:
        print(f"{len(failures)} checks failed.")
        return 1

    print("All operator tests passed.")
    return 0


def command_demo(args: argparse.Namespace) -> int:
    from scripts.generate_sample_data import generate_events, write_syslog

    profile = profile_from_args(args)
    status = collect_status(profile)
    if (status.get("api_health") or {}).get("status") != "ok":
        print("Cyber-EW Fusion Cell is not running. Starting it first...")
        command_start(args)
        status = collect_status(profile)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    events = json.loads(json.dumps(generate_events(args.count, args.seed)))
    start_time = datetime.now(timezone.utc) - timedelta(seconds=max(len(events) * 2, 60))

    for index, event in enumerate(events):
        event["timestamp"] = (start_time + timedelta(seconds=index * 2)).isoformat()
        event["demo_run_id"] = run_id
        event.setdefault("details", {})["demo_run_id"] = run_id
        event.setdefault("source_name", f"demo_{run_id}.json")

    live_dir = ROOT / "data" / "inputs" / "live"
    sample_dir = ROOT / "data" / "inputs" / "sample_generated"
    live_file = live_dir / f"demo_{run_id}.json"
    syslog_file = sample_dir / f"demo_{run_id}.log"

    write_json(live_file, events)
    sample_dir.mkdir(parents=True, exist_ok=True)
    write_syslog(events, syslog_file)

    if args.clear_alerts:
        from storage.alert_store import AlertStore

        AlertStore(ROOT / "data" / "outputs" / "alerts.jsonl").clear()

    if args.seed_alerts:
        run_command([str(PYTHON), "scripts/simulate_live_alerts.py", "--count", str(args.seed_alerts)], timeout=60)

    before = pipeline_events_processed(status)
    final_status = collect_status(profile)
    for _ in range(max(args.wait, 0)):
        time.sleep(1)
        final_status = collect_status(profile)
        if pipeline_events_processed(final_status) >= before + min(len(events), 25):
            break

    print("Cyber-EW Demo Scenario Injected")
    print("-" * 31)
    print(f"Telemetry events: {len(events)}")
    print(f"Live input: {live_file}")
    print(f"Syslog copy: {syslog_file}")
    print(f"Events processed now: {pipeline_events_processed(final_status)}")
    print(f"Seeded alert records: {args.seed_alerts}")
    print(f"Dashboard: {profile.dashboard_url}")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    profile = profile_from_args(args)
    report: Dict[str, Any] = {
        "generated_at": utc_now(),
        "python": str(PYTHON),
        "profile": profile.as_dict(),
        "module_checks": {},
        "path_checks": {},
        "service": collect_status(profile),
        "sensor_checks": collector_readiness(),
        "disk": {
            "root": str(ROOT),
            "free_gb": round(shutil.disk_usage(ROOT).free / (1024 ** 3), 2),
        },
        "recommendations": [],
    }

    for module, package in REQUIRED_MODULES.items():
        available = importlib.util.find_spec(module) is not None
        report["module_checks"][module] = {"available": available, "package": package}
        if not available:
            report["recommendations"].append(f"Install missing package: {package}")

    for path in [
        ROOT / "data" / "inputs" / "live",
        ROOT / "data" / "outputs",
        ROOT / "data" / "signatures",
        ROOT / "logs",
    ]:
        path.mkdir(parents=True, exist_ok=True)
        report["path_checks"][str(path)] = {"exists": path.exists(), "writable": os.access(path, os.W_OK)}

    write_json(HEALTH_REPORT, report)
    missing = [name for name, item in report["module_checks"].items() if not item["available"]]
    dashboard_open = report["service"]["ports"].get(f"dashboard_{profile.dashboard_port}", False)
    api_open = report["service"]["ports"].get(f"api_{profile.api_port}", False)
    print("Cyber-EW Deployment Doctor")
    print("-" * 28)
    print(f"Profile: {profile.name} ({profile.description})")
    print(f"Python: {PYTHON}")
    print(f"Missing modules: {', '.join(missing) if missing else 'none'}")
    print(f"Dashboard port open: {dashboard_open}")
    print(f"API port open: {api_open}")
    if not dashboard_open or not api_open:
        print("Service note: ports are expected to be closed until you run `python manage.py start`.")
    if profile.api_key_required and not os.environ.get("CYBER_EW_API_KEY") and not API_KEY_FILE.exists():
        print("Security note: this profile requires an API key; `manage.py start` will create one locally.")
    if report["recommendations"]:
        print("Recommendations:")
        for recommendation in report["recommendations"]:
            print(f"- {recommendation}")
    print("Sensor checks:")
    for line in summarize_sensor_status(report["sensor_checks"]):
        print(f"- {line}")
    print(f"Disk free: {report['disk']['free_gb']} GB")
    print(f"Health report: {HEALTH_REPORT}")
    return 1 if missing else 0


def command_profiles(args: argparse.Namespace) -> int:
    profiles = [get_profile(name) for name in profile_names()]
    if args.name:
        profile = get_profile(args.name)
        print(json.dumps(profile.as_dict(), indent=2))
        return 0

    print("Cyber-EW Deployment Profiles")
    print("-" * 30)
    for profile in profiles:
        marker = "*" if profile.name == profile_from_args(args).name else " "
        print(f"{marker} {profile.name:<10} {profile.description}")
        print(f"  Dashboard {profile.dashboard_url} | API {profile.api_url} | API key required: {profile.api_key_required}")
    return 0


def parse_record_timestamp(record: Dict[str, Any]) -> Optional[datetime]:
    value = record.get("timestamp")
    if not value and isinstance(record.get("event"), dict):
        value = record["event"].get("timestamp")
    if not value:
        return None
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)
    except ValueError:
        return None


def rotate_jsonl_by_timestamp(path: Path, retention_days: int, dry_run: bool) -> Dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    result = {"path": str(path), "kept": 0, "archived": 0, "archive_path": ""}
    if not path.exists():
        return result

    kept: List[str] = []
    archived: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            kept.append(line)
            continue
        timestamp = parse_record_timestamp(record)
        if timestamp and timestamp < cutoff:
            archived.append(line)
        else:
            kept.append(line)

    result["kept"] = len(kept)
    result["archived"] = len(archived)
    if archived:
        archive_dir = ROOT / "data" / "archive" / "outputs"
        archive_path = archive_dir / f"{path.stem}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"
        result["archive_path"] = str(archive_path)
        if not dry_run:
            archive_dir.mkdir(parents=True, exist_ok=True)
            archive_path.write_text("\n".join(archived) + "\n", encoding="utf-8")
            path.write_text(("\n".join(kept) + "\n") if kept else "", encoding="utf-8")
    return result


def archive_old_files(directory: Path, days: int, patterns: Iterable[str], dry_run: bool) -> Dict[str, Any]:
    cutoff = time.time() - (days * 86400)
    archive_dir = ROOT / "data" / "archive" / directory.relative_to(ROOT)
    archived: List[str] = []
    if not directory.exists():
        return {"directory": str(directory), "archived": archived}

    for pattern in patterns:
        for item in directory.glob(pattern):
            if not item.is_file() or item.stat().st_mtime >= cutoff:
                continue
            archived.append(str(item))
            if not dry_run:
                archive_dir.mkdir(parents=True, exist_ok=True)
                target = archive_dir / item.name
                if target.exists():
                    target = archive_dir / f"{item.stem}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}{item.suffix}"
                shutil.move(str(item), str(target))
    return {"directory": str(directory), "archive_directory": str(archive_dir), "archived": archived}


def build_security_checks(profile: DeploymentProfile, status: Dict[str, Any]) -> List[Dict[str, Any]]:
    api_key_present = bool(os.environ.get("CYBER_EW_API_KEY") or API_KEY_FILE.exists())
    paths = status.get("ports", {})
    disk = shutil.disk_usage(ROOT)
    disk_free_gb = round(disk.free / (1024 ** 3), 2)
    return [
        {
            "check": "Local-only binding",
            "status": "pass" if profile.bind_host in {"127.0.0.1", "localhost"} else "review",
            "detail": f"Bind host is {profile.bind_host}",
        },
        {
            "check": "API key for hardened profile",
            "status": "pass" if (not profile.api_key_required or api_key_present) else "fail",
            "detail": "API key is required by this profile" if profile.api_key_required else "API key optional for this profile",
        },
        {
            "check": "Dashboard port",
            "status": "pass" if paths.get(f"dashboard_{profile.dashboard_port}") else "info",
            "detail": f"{profile.dashboard_url}",
        },
        {
            "check": "API port",
            "status": "pass" if paths.get(f"api_{profile.api_port}") else "info",
            "detail": f"{profile.api_url}",
        },
        {
            "check": "Retention policy",
            "status": "pass",
            "detail": f"alerts={profile.alert_retention_days}d logs={profile.log_retention_days}d inputs={profile.archive_inputs_days}d",
        },
        {
            "check": "Disk free",
            "status": "pass" if disk_free_gb >= 5 else "review",
            "detail": f"{disk_free_gb} GB free at {ROOT}",
        },
    ]


def summarize_sensor_status(sensor_status: Dict[str, Any]) -> List[str]:
    eventlog = sensor_status.get("windows_eventlog", {})
    sysmon = sensor_status.get("sysmon", {})
    pcap = sensor_status.get("pcap_live", {})
    eventlog_channels = eventlog.get("channels", {}) if isinstance(eventlog, dict) else {}
    readable_channels = sum(1 for item in eventlog_channels.values() if item.get("available"))
    return [
        f"Windows Event Log: {'available' if eventlog.get('available') else 'unavailable'} ({readable_channels}/{len(eventlog_channels)} channels readable)",
        f"Sysmon channel: {'available' if sysmon.get('installed') else 'not detected'}",
        f"Packet capture: {'available' if pcap.get('available') else 'unavailable'}; libpcap/Npcap: {'available' if pcap.get('libpcap_available') else 'not detected'} ({len(pcap.get('interfaces', []))} interfaces)",
    ]


def command_cleanup(args: argparse.Namespace) -> int:
    profile = profile_from_args(args)
    dry_run = bool(args.dry_run)
    results = {
        "generated_at": utc_now(),
        "profile": profile.as_dict(),
        "dry_run": dry_run,
        "alerts": rotate_jsonl_by_timestamp(ROOT / "data" / "outputs" / "alerts.jsonl", args.alert_days or profile.alert_retention_days, dry_run),
        "audit": rotate_jsonl_by_timestamp(ROOT / "data" / "outputs" / "audit_log.jsonl", args.alert_days or profile.alert_retention_days, dry_run),
        "inputs": archive_old_files(
            ROOT / "data" / "inputs" / "live",
            args.input_days or profile.archive_inputs_days,
            ["*.json", "*.jsonl", "*.ndjson", "*.eve", "*.log", "*.tsv"],
            dry_run,
        ),
        "sample_inputs": archive_old_files(
            ROOT / "data" / "inputs" / "sample_generated",
            args.input_days or profile.archive_inputs_days,
            ["*.json", "*.log", "*.txt", "*.csv"],
            dry_run,
        ),
        "logs": archive_old_files(ROOT / "logs", args.log_days or profile.log_retention_days, ["*.log"], dry_run),
    }
    write_json(ROOT / "data" / "outputs" / "cleanup_report.json", results)
    print("Cyber-EW Retention Cleanup")
    print("-" * 28)
    print(f"Profile: {profile.name}")
    print(f"Dry run: {dry_run}")
    print(f"Archived alert rows: {results['alerts']['archived']}")
    print(f"Archived audit rows: {results['audit']['archived']}")
    print(f"Archived input files: {len(results['inputs']['archived']) + len(results['sample_inputs']['archived'])}")
    print(f"Archived log files: {len(results['logs']['archived'])}")
    print(f"Cleanup report: {ROOT / 'data' / 'outputs' / 'cleanup_report.json'}")
    return 0


def command_report(args: argparse.Namespace) -> int:
    profile = profile_from_args(args)
    status = collect_status(profile)
    report = {
        "generated_at": utc_now(),
        "profile": profile.as_dict(),
        "status": status,
        "security_checks": build_security_checks(profile, status),
        "sensor_checks": collector_readiness(),
        "required_modules": {
            module: importlib.util.find_spec(module) is not None
            for module in REQUIRED_MODULES
        },
        "operator_commands": [
            "python manage.py doctor",
            "python manage.py start",
            "python manage.py status",
            "python manage.py demo",
            "python manage.py cleanup",
            "python manage.py stop",
        ],
    }
    output_path = ROOT / "data" / "outputs" / "deployment_report.json"
    write_json(output_path, report)

    md_path = ROOT / "data" / "outputs" / "deployment_report.md"
    lines = [
        "# Cyber-EW Deployment Report",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Profile: {profile.name}",
        f"- Dashboard: {profile.dashboard_url}",
        f"- API: {profile.api_url}",
        "",
        "## Security Checks",
        "",
    ]
    for check in report["security_checks"]:
        lines.append(f"- {check['status'].upper()}: {check['check']} - {check['detail']}")
    lines.extend(["", "## Sensor Checks", ""])
    for line in summarize_sensor_status(report["sensor_checks"]):
        lines.append(f"- {line}")
    lines.extend(["", "## Service", "", f"- API health: {(status.get('api_health') or {}).get('status', 'unknown')}", f"- Live service: {(status.get('api_health') or {}).get('live_service', False)}"])
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("Cyber-EW Deployment Report")
    print("-" * 28)
    print(f"Profile: {profile.name}")
    print(f"JSON: {output_path}")
    print(f"Markdown: {md_path}")
    for check in report["security_checks"]:
        print(f"{check['status'].upper()}: {check['check']} - {check['detail']}")
    for line in summarize_sensor_status(report["sensor_checks"]):
        print(f"SENSOR: {line}")
    return 0


def command_logs(args: argparse.Namespace) -> int:
    logs = sorted((ROOT / "logs").glob("*.log"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not logs:
        print("No logs found.")
        return 0
    latest = logs[0]
    lines = latest.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-args.lines :]:
        print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Operate Cyber-EW Fusion Cell")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_profile_arg(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--profile", choices=profile_names(), default=os.environ.get("CYBER_EW_PROFILE", "dev"))

    commands = {
        "start": (command_start, "Start pipeline, dashboard, and API"),
        "stop": (command_stop, "Stop managed Cyber-EW processes"),
        "restart": (command_restart, "Restart all managed services"),
        "status": (command_status, "Show service health and write operator health report"),
        "doctor": (command_doctor, "Check dependencies, paths, ports, and service state"),
        "test": (command_test, "Run compile, unit, smoke, and pipeline tests"),
        "open": (command_open, "Open the dashboard in the default browser"),
    }

    for name, (handler, help_text) in commands.items():
        subparser = subparsers.add_parser(name, help=help_text)
        if name in {"start", "restart", "status", "doctor", "open"}:
            add_profile_arg(subparser)
        subparser.set_defaults(handler=handler)

    logs_parser = subparsers.add_parser("logs", help="Show latest log tail")
    logs_parser.add_argument("--lines", type=int, default=80)
    logs_parser.set_defaults(handler=command_logs)

    demo_parser = subparsers.add_parser("demo", help="Inject a fresh SOC attack scenario into the live pipeline")
    add_profile_arg(demo_parser)
    demo_parser.add_argument("--count", type=int, default=120, help="Number of baseline events before attack behaviors")
    demo_parser.add_argument("--seed", type=int, default=1337, help="Random seed for repeatable demo telemetry")
    demo_parser.add_argument("--wait", type=int, default=15, help="Seconds to wait for the live pipeline to ingest the demo")
    demo_parser.add_argument("--seed-alerts", type=int, default=0, help="Also write guaranteed alert records for dashboard demos")
    demo_parser.add_argument("--clear-alerts", action="store_true", help="Clear existing persisted alerts before seeding")
    demo_parser.set_defaults(handler=command_demo)

    profiles_parser = subparsers.add_parser("profiles", help="List or show deployment profiles")
    add_profile_arg(profiles_parser)
    profiles_parser.add_argument("name", nargs="?", choices=profile_names())
    profiles_parser.set_defaults(handler=command_profiles)

    cleanup_parser = subparsers.add_parser("cleanup", help="Apply retention policy and archive old local artifacts")
    add_profile_arg(cleanup_parser)
    cleanup_parser.add_argument("--dry-run", action="store_true", help="Show what would be archived without moving or rewriting files")
    cleanup_parser.add_argument("--alert-days", type=int, default=0, help="Override alert/audit retention days")
    cleanup_parser.add_argument("--input-days", type=int, default=0, help="Override telemetry input archive age")
    cleanup_parser.add_argument("--log-days", type=int, default=0, help="Override log archive age")
    cleanup_parser.set_defaults(handler=command_cleanup)

    report_parser = subparsers.add_parser("report", help="Write deployment and security readiness reports")
    add_profile_arg(report_parser)
    report_parser.set_defaults(handler=command_report)
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
