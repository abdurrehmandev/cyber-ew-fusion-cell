"""Deployment profile helpers for Cyber-EW Fusion Cell."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parents[1]
PROFILES_PATH = Path(__file__).with_name("deployment_profiles.json")
DEFAULT_PROFILE = "dev"


@dataclass(frozen=True)
class DeploymentProfile:
    name: str
    description: str
    dashboard_port: int
    api_port: int
    bind_host: str
    api_key_required: bool
    retention_days: int
    archive_inputs_days: int
    log_retention_days: int
    alert_retention_days: int
    offline_mode: bool

    @property
    def dashboard_url(self) -> str:
        return f"http://{self.bind_host}:{self.dashboard_port}"

    @property
    def api_url(self) -> str:
        return f"http://{self.bind_host}:{self.api_port}"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "dashboard_port": self.dashboard_port,
            "api_port": self.api_port,
            "bind_host": self.bind_host,
            "api_key_required": self.api_key_required,
            "retention_days": self.retention_days,
            "archive_inputs_days": self.archive_inputs_days,
            "log_retention_days": self.log_retention_days,
            "alert_retention_days": self.alert_retention_days,
            "offline_mode": self.offline_mode,
            "dashboard_url": self.dashboard_url,
            "api_url": self.api_url,
        }


def load_profiles() -> Dict[str, Dict[str, Any]]:
    if not PROFILES_PATH.exists():
        return {}
    return json.loads(PROFILES_PATH.read_text(encoding="utf-8"))


def profile_names() -> list[str]:
    return sorted(load_profiles())


def get_profile(name: str | None = None) -> DeploymentProfile:
    profiles = load_profiles()
    selected = name or os.environ.get("CYBER_EW_PROFILE") or DEFAULT_PROFILE
    if selected not in profiles:
        available = ", ".join(sorted(profiles)) or "none"
        raise ValueError(f"Unknown deployment profile '{selected}'. Available profiles: {available}")

    data = profiles[selected]
    return DeploymentProfile(
        name=selected,
        description=str(data.get("description", "")),
        dashboard_port=int(data.get("dashboard_port", 8501)),
        api_port=int(data.get("api_port", 8080)),
        bind_host=str(data.get("bind_host", "127.0.0.1")),
        api_key_required=bool(data.get("api_key_required", False)),
        retention_days=int(data.get("retention_days", 90)),
        archive_inputs_days=int(data.get("archive_inputs_days", 30)),
        log_retention_days=int(data.get("log_retention_days", 90)),
        alert_retention_days=int(data.get("alert_retention_days", 180)),
        offline_mode=bool(data.get("offline_mode", False)),
    )


def profile_environment(profile: DeploymentProfile) -> Dict[str, str]:
    env = os.environ.copy()
    env["CYBER_EW_PROFILE"] = profile.name
    env["CYBER_EW_DASHBOARD_PORT"] = str(profile.dashboard_port)
    env["CYBER_EW_API_PORT"] = str(profile.api_port)
    env["CYBER_EW_BIND_HOST"] = profile.bind_host
    env["CYBER_EW_OFFLINE_MODE"] = "1" if profile.offline_mode else "0"
    if profile.name in {"offline", "production"}:
        env.setdefault("CYBER_EW_ENABLE_EVENTLOG", "1")
        env.setdefault("CYBER_EW_ENABLE_PCAP", "0")
    return env
