"""
Core configuration for Cyber-EW Fusion Cell
"""
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    import yaml
except Exception:  # pragma: no cover - dependency checks cover availability
    yaml = None

@dataclass
class PipelineConfig:
    """Pipeline processing configuration"""
    batch_size: int = 1000
    max_queue_size: int = 10000
    processing_interval: float = 1.0  # seconds
    enable_parallel: bool = True
    worker_count: int = 4

@dataclass
class IngestConfig:
    """Ingestion source configuration"""
    sources: Optional[List[Dict]] = None
    pcap_enabled: bool = True
    syslog_enabled: bool = True
    json_enabled: bool = True
    windows_events_enabled: bool = True
    threat_intel_enabled: bool = True
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    
    def __post_init__(self):
        if self.sources is None:
            self.sources = [
                {"type": "pcap", "path": "/data/inputs/pcaps"},
                {"type": "syslog", "port": 514},
                {"type": "json", "path": "data/inputs/live"},
                {"type": "windows_event", "channel": "Security"},
                {"type": "threat_intel", "feed_url": "https://feeds.threatfox.abuse.ch"}
            ]

@dataclass
class CorrelationConfig:
    """Correlation engine configuration"""
    time_window_seconds: int = 300  # 5-minute correlation window
    entity_linking_enabled: bool = True
    max_cluster_size: int = 1000
    similarity_threshold: float = 0.7

@dataclass
class BehaviorConfig:
    """Behavior analysis configuration"""
    baseline_days: int = 30
    learning_rate: float = 0.1
    anomaly_threshold: float = 3.0  # Standard deviations
    profile_update_interval: int = 3600  # 1 hour

@dataclass
class ScoringConfig:
    """Threat scoring configuration"""
    weights: Optional[Dict[str, float]] = None
    confidence_decay_hours: float = 24.0
    min_confidence: float = 0.3
    
    def __post_init__(self):
        if self.weights is None:
            self.weights = {
                "severity": 0.3,
                "confidence": 0.25,
                "correlation": 0.2,
                "behavior": 0.15,
                "recency": 0.1
            }

@dataclass
class CollectorConfig:
    """Optional live sensor collector configuration"""
    eventlog_enabled: bool = False
    eventlog_channels: Optional[List[str]] = None
    eventlog_poll_seconds: float = 3.0
    pcap_enabled: bool = False
    pcap_interface: str = ""
    pcap_bpf_filter: str = "ip"
    pcap_sample_rate: int = 10

    def __post_init__(self):
        if self.eventlog_channels is None:
            self.eventlog_channels = [
                "Security",
                "System",
                "Application",
                "Microsoft-Windows-Sysmon/Operational",
            ]

@dataclass
class SystemConfig:
    """System-wide configuration"""
    project_root: Path = Path(__file__).parent.parent
    data_dir: Path = project_root / "data"
    log_dir: Path = project_root / "logs"
    temp_dir: Path = project_root / "temp"
    
    log_level: str = "INFO"
    audit_log_enabled: bool = True
    data_retention_days: int = 90
    
    def __post_init__(self):
        # Create required directories
        for directory in [self.data_dir, self.log_dir, self.temp_dir]:
            directory.mkdir(exist_ok=True, parents=True)


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}


def _load_yaml_settings() -> Dict[str, Any]:
    config_path = Path(os.environ.get("CYBER_EW_CONFIG", Path(__file__).with_name("settings.yaml")))
    if not config_path.exists() or yaml is None:
        return {}
    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def _load_registry_settings() -> Dict[str, Any]:
    if os.name != "nt":
        return {}
    try:
        import winreg
    except Exception:
        return {}

    settings: Dict[str, Any] = {}
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
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


def _apply_external_overrides() -> None:
    """Apply YAML, Registry, then environment overrides."""
    yaml_settings = _load_yaml_settings()
    registry = _load_registry_settings()

    system = yaml_settings.get("system", {}) if isinstance(yaml_settings.get("system"), dict) else {}
    collectors = yaml_settings.get("collectors", {}) if isinstance(yaml_settings.get("collectors"), dict) else {}

    data_dir = os.environ.get("CYBER_EW_DATA_DIR") or registry.get("DataDir") or system.get("data_dir")
    log_dir = os.environ.get("CYBER_EW_LOG_DIR") or registry.get("LogDir") or system.get("log_dir")
    retention = os.environ.get("CYBER_EW_RETENTION_DAYS") or registry.get("RetentionDays") or system.get("data_retention_days")

    if data_dir:
        CONFIG.data_dir = Path(data_dir)
    if log_dir:
        CONFIG.log_dir = Path(log_dir)
    if retention:
        CONFIG.data_retention_days = int(retention)

    eventlog_enabled = os.environ.get("CYBER_EW_ENABLE_EVENTLOG")
    pcap_enabled = os.environ.get("CYBER_EW_ENABLE_PCAP")
    if eventlog_enabled is not None:
        COLLECTOR_CONFIG.eventlog_enabled = _bool(eventlog_enabled)
    elif "EnableEventLog" in registry:
        COLLECTOR_CONFIG.eventlog_enabled = _bool(registry.get("EnableEventLog"))
    elif "eventlog_enabled" in collectors:
        COLLECTOR_CONFIG.eventlog_enabled = _bool(collectors.get("eventlog_enabled"))

    if pcap_enabled is not None:
        COLLECTOR_CONFIG.pcap_enabled = _bool(pcap_enabled)
    elif "EnablePacketCapture" in registry:
        COLLECTOR_CONFIG.pcap_enabled = _bool(registry.get("EnablePacketCapture"))
    elif "pcap_enabled" in collectors:
        COLLECTOR_CONFIG.pcap_enabled = _bool(collectors.get("pcap_enabled"))

    channels = os.environ.get("CYBER_EW_EVENTLOG_CHANNELS") or registry.get("EventLogChannels") or collectors.get("eventlog_channels")
    if isinstance(channels, str):
        COLLECTOR_CONFIG.eventlog_channels = [item.strip() for item in channels.split(",") if item.strip()]
    elif isinstance(channels, list):
        COLLECTOR_CONFIG.eventlog_channels = [str(item) for item in channels]

    COLLECTOR_CONFIG.pcap_interface = str(os.environ.get("CYBER_EW_PCAP_INTERFACE") or registry.get("PacketInterface") or collectors.get("pcap_interface") or COLLECTOR_CONFIG.pcap_interface)
    COLLECTOR_CONFIG.pcap_bpf_filter = str(os.environ.get("CYBER_EW_PCAP_FILTER") or registry.get("PacketBpfFilter") or collectors.get("pcap_bpf_filter") or COLLECTOR_CONFIG.pcap_bpf_filter)

    for directory in [CONFIG.data_dir, CONFIG.log_dir, CONFIG.temp_dir]:
        directory.mkdir(exist_ok=True, parents=True)


# Create configuration instances
CONFIG = SystemConfig()
PIPELINE_CONFIG = PipelineConfig()
INGEST_CONFIG = IngestConfig()
CORRELATION_CONFIG = CorrelationConfig()
BEHAVIOR_CONFIG = BehaviorConfig()
SCORING_CONFIG = ScoringConfig()
COLLECTOR_CONFIG = CollectorConfig()
_apply_external_overrides()

# Export all configs
__all__ = [
    'CONFIG',
    'PIPELINE_CONFIG', 
    'INGEST_CONFIG',
    'CORRELATION_CONFIG',
    'BEHAVIOR_CONFIG',
    'SCORING_CONFIG',
    'COLLECTOR_CONFIG'
]
