"""Local SOAR playbook engine with safe-by-default actions."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.settings import CONFIG
from storage.soc_store import AuditLog


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class PlaybookAction:
    action: str
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    destructive: bool = False


@dataclass
class Playbook:
    playbook_id: str
    name: str
    category: str
    description: str
    trigger: str
    actions: List[PlaybookAction]


BASE_PLAYBOOKS = [
    Playbook(
        "PB-001",
        "Credential Attack Triage",
        "Credential Access",
        "Open a case, add source IP to watchlist, and produce password-spray guidance.",
        "authentication failures or credential attack pattern",
        [
            PlaybookAction("create_case", "alert"),
            PlaybookAction("add_ioc", "source_ip"),
            PlaybookAction("notify", "soc_channel", {"message": "Credential attack investigation required"}),
        ],
    ),
    Playbook(
        "PB-002",
        "Ransomware Containment",
        "Impact",
        "Prepare host isolation, add hashes/paths to evidence, and export a containment checklist.",
        "ransomware activity",
        [
            PlaybookAction("create_case", "alert"),
            PlaybookAction("quarantine_endpoint", "host", destructive=True),
            PlaybookAction("notify", "incident_commander", {"priority": "critical"}),
        ],
    ),
    Playbook(
        "PB-003",
        "C2 Beacon Block",
        "Command and Control",
        "Prepare firewall block action and add destination to IOC watchlist.",
        "c2 beaconing",
        [
            PlaybookAction("add_ioc", "destination_ip"),
            PlaybookAction("block_ip", "destination_ip", destructive=True),
            PlaybookAction("create_case", "alert"),
        ],
    ),
    Playbook(
        "PB-004",
        "Data Exfiltration Response",
        "Exfiltration",
        "Open a case, tag destination, and build evidence collection guidance.",
        "large outbound transfer or exfiltration pattern",
        [
            PlaybookAction("create_case", "alert"),
            PlaybookAction("add_ioc", "destination_ip"),
            PlaybookAction("notify", "data_protection_owner", {"priority": "high"}),
        ],
    ),
    Playbook(
        "PB-005",
        "Privilege Escalation Review",
        "Privilege Escalation",
        "Collect process and scheduled-task evidence and open an analyst case.",
        "privilege escalation pattern",
        [
            PlaybookAction("create_case", "alert"),
            PlaybookAction("collect_evidence", "host"),
            PlaybookAction("notify", "soc_channel", {"message": "Privilege escalation review"}),
        ],
    ),
]


def generated_playbooks() -> List[Playbook]:
    categories = [
        "Reconnaissance",
        "Initial Access",
        "Execution",
        "Persistence",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Exfiltration",
    ]
    playbooks = list(BASE_PLAYBOOKS)
    index = 6
    for category in categories:
        for severity in ("Medium", "High", "Critical", "Hunt", "Audit"):
            playbooks.append(
                Playbook(
                    f"PB-{index:03d}",
                    f"{category} {severity} Response",
                    category,
                    f"Template response workflow for {severity.lower()} {category.lower()} activity.",
                    f"{category.lower()} {severity.lower()} signal",
                    [
                        PlaybookAction("create_case", "alert"),
                        PlaybookAction("collect_evidence", "entity"),
                        PlaybookAction("notify", "soc_channel", {"priority": severity.lower()}),
                    ],
                )
            )
            index += 1
    return playbooks


class PlaybookEngine:
    """Execute playbooks in dry-run mode unless explicitly approved."""

    def __init__(self, audit_log: Optional[AuditLog] = None, run_log_path: Optional[Path | str] = None) -> None:
        self.audit_log = audit_log or AuditLog()
        self.run_log_path = Path(run_log_path) if run_log_path else CONFIG.data_dir / "outputs" / "playbook_runs.jsonl"
        self.run_log_path.parent.mkdir(parents=True, exist_ok=True)

    def list_playbooks(self) -> List[Dict[str, Any]]:
        return [self._playbook_to_dict(playbook) for playbook in generated_playbooks()]

    def get(self, playbook_id: str) -> Optional[Playbook]:
        return next((item for item in generated_playbooks() if item.playbook_id == playbook_id), None)

    def run(self, playbook_id: str, alert: Optional[Dict[str, Any]] = None, approved: bool = False, actor: str = "local-analyst") -> Dict[str, Any]:
        playbook = self.get(playbook_id)
        if playbook is None:
            raise ValueError(f"Unknown playbook '{playbook_id}'")

        run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        alert = alert or {}
        steps = [self._execute_action(action, alert, approved) for action in playbook.actions]
        status = "executed" if approved else "dry_run"
        result = {
            "run_id": run_id,
            "playbook_id": playbook.playbook_id,
            "playbook": playbook.name,
            "status": status,
            "approved": approved,
            "actor": actor,
            "started_at": utc_now(),
            "steps": steps,
        }
        with self.run_log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(result, default=str))
            f.write("\n")
        self.audit_log.append("playbook.run", run_id, {"playbook_id": playbook_id, "approved": approved}, actor=actor)
        return result

    def recent_runs(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.run_log_path.exists():
            return []
        records: List[Dict[str, Any]] = []
        for line in self.run_log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        records.sort(key=lambda item: item.get("started_at", ""), reverse=True)
        return records[:limit]

    def _execute_action(self, action: PlaybookAction, alert: Dict[str, Any], approved: bool) -> Dict[str, Any]:
        target_value = self._resolve_target(action.target, alert)
        if action.destructive and not approved:
            return {
                "action": action.action,
                "target": target_value,
                "status": "approval_required",
                "detail": "Action is prepared but not executed without analyst approval.",
                "command_preview": self._command_preview(action.action, target_value),
            }
        return {
            "action": action.action,
            "target": target_value,
            "status": "completed" if approved or not action.destructive else "approval_required",
            "detail": self._safe_action_detail(action.action, target_value),
            "parameters": action.parameters,
        }

    def _resolve_target(self, target: str, alert: Dict[str, Any]) -> str:
        event = alert.get("event", {}) if isinstance(alert.get("event"), dict) else alert
        if target == "source_ip":
            return str(event.get("source_ip", ""))
        if target == "destination_ip":
            return str(event.get("destination_ip", ""))
        if target in {"host", "endpoint"}:
            return str(event.get("source_host") or event.get("destination_host") or event.get("source_ip") or "")
        if target in {"alert", "entity"}:
            return str(alert.get("alert_id") or event.get("event_id") or "current-alert")
        return target

    def _command_preview(self, action: str, target: str) -> str:
        if action == "block_ip" and target:
            return f'netsh advfirewall firewall add rule name="Cyber-EW Block {target}" dir=out action=block remoteip={target}'
        if action == "quarantine_endpoint":
            return "Requires EDR connector approval; no local destructive action is run by default."
        return "No shell command generated."

    def _safe_action_detail(self, action: str, target: str) -> str:
        if action == "create_case":
            return f"Case creation prepared for {target}."
        if action == "add_ioc":
            return f"IOC enrichment prepared for {target}."
        if action == "notify":
            return "Notification event written to local playbook log."
        if action == "collect_evidence":
            return f"Evidence checklist prepared for {target}."
        return f"{action} prepared for {target}."

    def _playbook_to_dict(self, playbook: Playbook) -> Dict[str, Any]:
        return {
            "playbook_id": playbook.playbook_id,
            "name": playbook.name,
            "category": playbook.category,
            "description": playbook.description,
            "trigger": playbook.trigger,
            "actions": [action.__dict__ for action in playbook.actions],
        }

