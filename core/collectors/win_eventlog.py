"""Live Windows Event Log and Sysmon collector.

The collector uses pywin32 when available. It polls Event Log channels using
EvtQuery/EvtRender so it can run inside the existing threaded pipeline without
requiring a separate agent process.
"""
from __future__ import annotations

import logging
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

try:  # pragma: no cover - availability is platform dependent
    import win32evtlog  # type: ignore
except Exception:  # pragma: no cover
    win32evtlog = None  # type: ignore


DEFAULT_CHANNELS = ["Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational"]
EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class WindowsEventLogCollector:
    """Poll Windows Event Log channels and emit raw event dictionaries."""

    def __init__(
        self,
        callback: Callable[[Dict[str, Any]], None],
        channels: Optional[Iterable[str]] = None,
        poll_interval: float = 3.0,
        max_events_per_poll: int = 50,
        enabled: bool = False,
    ) -> None:
        self.callback = callback
        self.channels = list(channels or DEFAULT_CHANNELS)
        self.poll_interval = poll_interval
        self.max_events_per_poll = max_events_per_poll
        self.enabled = enabled
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.watermarks: Dict[str, int] = {}
        self.stats: Dict[str, Any] = {
            "enabled": enabled,
            "available": win32evtlog is not None,
            "channels": {},
            "events_emitted": 0,
            "errors": 0,
        }

    def start(self) -> None:
        if self.running or not self.enabled:
            return
        if win32evtlog is None:
            self.stats["errors"] += 1
            self.stats["last_error"] = "pywin32 win32evtlog is not available"
            return
        self.running = True
        self._initialize_watermarks()
        self.thread = threading.Thread(target=self._run, name="windows_eventlog_collector", daemon=True)
        self.thread.start()
        logger.info("Windows Event Log collector started for channels: %s", ", ".join(self.channels))

    def stop(self) -> None:
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)

    def _initialize_watermarks(self) -> None:
        for channel in self.channels:
            try:
                latest = self._read_channel(channel, max_events=1)
                watermark = max((item.get("_record_id", 0) for item in latest), default=0)
                self.watermarks[channel] = int(watermark or 0)
                self.stats["channels"][channel] = {"available": True, "last_record_id": self.watermarks[channel]}
            except Exception as exc:
                self.stats["channels"][channel] = {"available": False, "error": str(exc)}
                self.stats["errors"] += 1

    def _run(self) -> None:
        while self.running:
            for channel in self.channels:
                try:
                    last_id = self.watermarks.get(channel, 0)
                    events = [
                        item
                        for item in self._read_channel(channel, self.max_events_per_poll)
                        if int(item.get("_record_id", 0) or 0) > last_id
                    ]
                    for event in sorted(events, key=lambda item: int(item.get("_record_id", 0) or 0)):
                        self.watermarks[channel] = int(event.get("_record_id", last_id) or last_id)
                        self.callback(event)
                        self.stats["events_emitted"] += 1
                    if channel in self.stats["channels"]:
                        self.stats["channels"][channel]["last_record_id"] = self.watermarks.get(channel, 0)
                except Exception as exc:
                    self.stats["errors"] += 1
                    self.stats["channels"].setdefault(channel, {})["error"] = str(exc)
                    logger.debug("Windows Event Log collector channel error for %s: %s", channel, exc)
            time.sleep(self.poll_interval)

    def _read_channel(self, channel: str, max_events: int) -> List[Dict[str, Any]]:
        if win32evtlog is None:
            raise RuntimeError("pywin32 win32evtlog is not available")
        query = "*[System]"
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        handle = win32evtlog.EvtQuery(channel, flags, query)
        events = []
        while len(events) < max_events:
            batch = win32evtlog.EvtNext(handle, min(10, max_events - len(events)))
            if not batch:
                break
            for event_handle in batch:
                xml_text = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
                events.append(event_xml_to_raw(xml_text, channel))
        return events


def event_xml_to_raw(xml_text: str, channel_hint: str = "") -> Dict[str, Any]:
    """Convert Windows Event XML into a sensor-parser-compatible raw record."""
    root = ET.fromstring(xml_text)
    system = root.find("e:System", EVENT_NS)
    event_data = root.find("e:EventData", EVENT_NS)

    provider = system.find("e:Provider", EVENT_NS) if system is not None else None
    event_id = system.findtext("e:EventID", default="", namespaces=EVENT_NS) if system is not None else ""
    record_id = system.findtext("e:EventRecordID", default="0", namespaces=EVENT_NS) if system is not None else "0"
    channel = system.findtext("e:Channel", default=channel_hint, namespaces=EVENT_NS) if system is not None else channel_hint
    computer = system.findtext("e:Computer", default="", namespaces=EVENT_NS) if system is not None else ""
    time_created = system.find("e:TimeCreated", EVENT_NS) if system is not None else None

    data: Dict[str, Any] = {}
    if event_data is not None:
        for item in event_data.findall("e:Data", EVENT_NS):
            name = item.attrib.get("Name") or f"Data{len(data) + 1}"
            data[name] = item.text or ""

    raw = {
        "EventID": int(event_id) if str(event_id).isdigit() else event_id,
        "EventTime": time_created.attrib.get("SystemTime") if time_created is not None else datetime.now(timezone.utc).isoformat(),
        "Computer": computer,
        "Channel": channel,
        "ProviderName": provider.attrib.get("Name") if provider is not None else "",
        "EventData": data,
        "_record_id": int(record_id) if str(record_id).isdigit() else 0,
        "source_type": "windows_event",
        "source_name": channel,
    }
    raw.update(data)
    return raw


def probe_eventlog_access(channels: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Return Windows Event Log readiness without starting a live collector."""
    result: Dict[str, Any] = {
        "available": win32evtlog is not None,
        "channels": {},
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if win32evtlog is None:
        result["error"] = "pywin32 win32evtlog is not available"
        return result

    collector = WindowsEventLogCollector(lambda _event: None, channels=channels or DEFAULT_CHANNELS, enabled=False)
    for channel in collector.channels:
        try:
            events = collector._read_channel(channel, 1)
            result["channels"][channel] = {"available": True, "sample_count": len(events)}
        except Exception as exc:
            result["channels"][channel] = {"available": False, "error": str(exc)}
    return result


def detect_sysmon_installed() -> Dict[str, Any]:
    """Check whether the Sysmon operational channel can be read."""
    channel = "Microsoft-Windows-Sysmon/Operational"
    status = probe_eventlog_access([channel])
    channel_status = status.get("channels", {}).get(channel, {})
    return {
        "installed": bool(channel_status.get("available")),
        "channel": channel,
        "detail": channel_status,
    }
