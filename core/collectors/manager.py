"""Collector manager for optional enterprise live sensors."""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, Optional

from config.settings import COLLECTOR_CONFIG
from core.collectors.pcap_live import LivePacketCollector, probe_pcap_status
from core.collectors.win_eventlog import WindowsEventLogCollector, detect_sysmon_installed, probe_eventlog_access


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


class CollectorManager:
    """Start/stop live collectors and expose readiness statistics."""

    def __init__(self, callback: Callable[[Dict[str, Any]], None], config: Optional[Dict[str, Any]] = None) -> None:
        config = config or {}
        eventlog_enabled = bool(config.get("eventlog_enabled", COLLECTOR_CONFIG.eventlog_enabled))
        pcap_enabled = bool(config.get("pcap_enabled", COLLECTOR_CONFIG.pcap_enabled))

        eventlog_enabled = env_bool("CYBER_EW_ENABLE_EVENTLOG", eventlog_enabled)
        pcap_enabled = env_bool("CYBER_EW_ENABLE_PCAP", pcap_enabled)

        channels = os.environ.get("CYBER_EW_EVENTLOG_CHANNELS")
        channel_list = [item.strip() for item in channels.split(",") if item.strip()] if channels else COLLECTOR_CONFIG.eventlog_channels

        self.collectors = {
            "windows_eventlog": WindowsEventLogCollector(
                callback,
                channels=channel_list,
                poll_interval=float(os.environ.get("CYBER_EW_EVENTLOG_POLL_SECONDS", COLLECTOR_CONFIG.eventlog_poll_seconds)),
                enabled=eventlog_enabled,
            ),
            "pcap_live": LivePacketCollector(
                callback,
                interface=os.environ.get("CYBER_EW_PCAP_INTERFACE", COLLECTOR_CONFIG.pcap_interface),
                bpf_filter=os.environ.get("CYBER_EW_PCAP_FILTER", COLLECTOR_CONFIG.pcap_bpf_filter),
                sample_rate=int(os.environ.get("CYBER_EW_PCAP_SAMPLE_RATE", COLLECTOR_CONFIG.pcap_sample_rate)),
                enabled=pcap_enabled,
            ),
        }

    def start(self) -> None:
        for collector in self.collectors.values():
            collector.start()

    def stop(self) -> None:
        for collector in self.collectors.values():
            collector.stop()

    def get_stats(self) -> Dict[str, Any]:
        return {name: collector.get_stats() for name, collector in self.collectors.items()}


def collector_readiness() -> Dict[str, Any]:
    """Probe collector readiness without enabling capture/subscription."""
    return {
        "windows_eventlog": probe_eventlog_access(),
        "sysmon": detect_sysmon_installed(),
        "pcap_live": probe_pcap_status(),
    }
