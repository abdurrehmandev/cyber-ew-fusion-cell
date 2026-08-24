"""Live packet capture collector using Scapy/Npcap when available."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

try:  # pragma: no cover - runtime/driver dependent
    from scapy.all import IP, TCP, UDP, conf, get_if_list, sniff  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = None  # type: ignore
    conf = None  # type: ignore
    get_if_list = sniff = None  # type: ignore


class LivePacketCollector:
    """Capture packets and emit metadata events into the pipeline."""

    def __init__(
        self,
        callback: Callable[[Dict[str, Any]], None],
        interface: str = "",
        bpf_filter: str = "ip",
        sample_rate: int = 1,
        enabled: bool = False,
    ) -> None:
        self.callback = callback
        self.interface = interface or None
        self.bpf_filter = bpf_filter or "ip"
        self.sample_rate = max(int(sample_rate or 1), 1)
        self.enabled = enabled
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.packet_count = 0
        self.stats: Dict[str, Any] = {
            "enabled": enabled,
            "available": sniff is not None,
            "interface": self.interface or "default",
            "bpf_filter": self.bpf_filter,
            "packets_seen": 0,
            "events_emitted": 0,
            "errors": 0,
        }

    def start(self) -> None:
        if self.running or not self.enabled:
            return
        if sniff is None:
            self.stats["errors"] += 1
            self.stats["last_error"] = "scapy is not available"
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, name="live_packet_collector", daemon=True)
        self.thread.start()
        logger.info("Live packet collector started on interface=%s filter=%s", self.interface or "default", self.bpf_filter)

    def stop(self) -> None:
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)

    def _run(self) -> None:
        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self._handle_packet,
                    store=False,
                    timeout=2,
                    count=0,
                    stop_filter=lambda _packet: not self.running,
                )
            except Exception as exc:
                self.stats["errors"] += 1
                self.stats["last_error"] = str(exc)
                logger.debug("Live packet collector error: %s", exc)
                self.running = False

    def _handle_packet(self, packet: Any) -> None:
        self.packet_count += 1
        self.stats["packets_seen"] = self.packet_count
        if self.packet_count % self.sample_rate != 0:
            return

        event = packet_to_event(packet)
        if event:
            self.callback(event)
            self.stats["events_emitted"] += 1


def packet_to_event(packet: Any) -> Dict[str, Any]:
    """Convert a Scapy packet into a raw network event."""
    if IP is None or not packet.haslayer(IP):
        return {}

    protocol = "IP"
    port = None
    source_port = None
    if TCP is not None and packet.haslayer(TCP):
        protocol = "TCP"
        source_port = int(packet[TCP].sport)
        port = int(packet[TCP].dport)
    elif UDP is not None and packet.haslayer(UDP):
        protocol = "UDP"
        source_port = int(packet[UDP].sport)
        port = int(packet[UDP].dport)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "network_connection",
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "source_port": source_port,
        "destination_port": port,
        "protocol": protocol,
        "bytes_sent": len(packet),
        "severity": "info",
        "details": {
            "sensor": "live_packet_capture",
            "ttl": int(packet[IP].ttl),
            "packet_len": len(packet),
        },
        "source_type": "pcap_live",
        "source_name": "live_packet_capture",
    }


def probe_pcap_status() -> Dict[str, Any]:
    """Return packet-capture readiness without starting a capture."""
    result: Dict[str, Any] = {
        "available": sniff is not None,
        "libpcap_available": bool(getattr(conf, "use_pcap", False)) if conf is not None else False,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "interfaces": [],
    }
    if get_if_list is None:
        result["error"] = "scapy is not available"
        return result

    try:
        result["interfaces"] = list(get_if_list())
        if result["libpcap_available"]:
            result["npcap_hint"] = "libpcap/Npcap provider available"
        elif result["interfaces"]:
            result["npcap_hint"] = "interfaces available, but libpcap/Npcap provider was not detected"
        else:
            result["npcap_hint"] = "no interfaces returned; Npcap may be missing"
    except Exception as exc:
        result["error"] = str(exc)
    return result
