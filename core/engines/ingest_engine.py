"""
Ingest Engine for Cyber-EW Fusion Cell
"""
import os
import time
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
import socket
import threading
from queue import Queue

from core.models.event_models import EventSeverity, EventType, NormalizedEvent
from core.sensor_parsers import parse_sensor_file
from config.settings import CONFIG, INGEST_CONFIG


def runtime_data_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    if candidate.parts and candidate.parts[0].lower() == "data":
        return CONFIG.data_dir.joinpath(*candidate.parts[1:])
    return candidate

class DataSource:
    """Base class for all data sources"""
    
    def __init__(self, source_id: str, config: Dict[str, Any]):
        self.source_id = source_id
        self.config = config
        self.is_running = False
        self.last_read = None
        self.stats = {
            "events_read": 0,
            "bytes_read": 0,
            "errors": 0
        }
    
    def start(self):
        """Start the data source"""
        self.is_running = True
    
    def stop(self):
        """Stop the data source"""
        self.is_running = False
    
    def read_events(self) -> List[Dict[str, Any]]:
        """Read events from the source (to be implemented by subclasses)"""
        raise NotImplementedError
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for this source"""
        return self.stats.copy()

class PCAPSource(DataSource):
    """PCAP file data source"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("pcap_source", config)
        self.pcap_dir = runtime_data_path(config.get("path", "data/inputs/pcaps"))
        self.processed_files = set()
        self.current_file = None
    
    def read_events(self) -> List[Dict[str, Any]]:
        """Read events from PCAP files"""
        events = []
        
        if not self.pcap_dir.exists():
            return events
        
        # Find new PCAP files
        for pcap_file in self.pcap_dir.glob("*.pcap"):
            if pcap_file.name not in self.processed_files:
                try:
                    file_events = self._parse_pcap(pcap_file)
                    events.extend(file_events)
                    self.processed_files.add(pcap_file.name)
                    self.stats["events_read"] += len(file_events)
                    self.stats["bytes_read"] += pcap_file.stat().st_size
                except Exception as e:
                    print(f"Error parsing PCAP file {pcap_file}: {e}")
                    self.stats["errors"] += 1
        
        return events
    
    def _parse_pcap(self, pcap_file: Path) -> List[Dict[str, Any]]:
        """Parse a PCAP file and extract events"""
        # This is a simplified version
        # In production, use scapy or pyshark for actual parsing
        events = []
        
        # Simulate parsing network traffic
        # For now, create mock network events
        import random
        from datetime import timezone
        
        protocols = ["TCP", "UDP", "ICMP"]
        services = ["HTTP", "HTTPS", "DNS", "SSH", "RDP", "SMB"]
        
        # Generate 5-10 mock events per file
        for i in range(random.randint(5, 10)):
            events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "destination_ip": f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "source_port": random.randint(1024, 65535),
                "destination_port": random.choice([80, 443, 53, 22, 3389, 445]),
                "protocol": random.choice(protocols),
                "event_type": "network_connection",
                "bytes": random.randint(64, 1500),
                "details": {
                    "file_path": str(pcap_file),
                    "service": random.choice(services),
                    "flags": random.choice(["SYN", "ACK", "PSH", "FIN", "RST"])
                }
            })
        
        return events

class SyslogSource(DataSource):
    """Syslog data source"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("syslog_source", config)
        self.port = config.get("port", 514)
        self.host = config.get("host", os.environ.get("CYBER_EW_SYSLOG_HOST", "0.0.0.0"))
        self.server: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.buffer = []
        self.buffer_lock = threading.Lock()
        self.max_buffer = 1000
        self.mock_counter = 0
        self.mock_enabled = bool(config.get("mock_enabled", True))
    
    def start(self):
        """Start syslog server"""
        super().start()
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, int(self.port)))
            self.server.settimeout(1.0)
            self.thread = threading.Thread(target=self._receive_loop, name="syslog_udp_listener", daemon=True)
            self.thread.start()
            print(f"Syslog source started (listening on UDP {self.host}:{self.port})")
        except Exception as exc:
            self.stats["errors"] += 1
            self.stats["last_error"] = str(exc)
            self.server = None
            print(f"Syslog source could not bind UDP {self.port}: {exc}")

    def stop(self):
        """Stop syslog server."""
        super().stop()
        if self.server is not None:
            try:
                self.server.close()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def _receive_loop(self):
        while self.is_running and self.server is not None:
            try:
                data, address = self.server.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as exc:
                self.stats["errors"] += 1
                self.stats["last_error"] = str(exc)
                continue

            message = data.decode("utf-8", errors="replace").strip()
            event = self._parse_syslog_message(message, address[0])
            with self.buffer_lock:
                self.buffer.append(event)
                if len(self.buffer) > self.max_buffer:
                    self.buffer = self.buffer[-self.max_buffer :]
    
    def read_events(self) -> List[Dict[str, Any]]:
        """Read syslog messages"""
        with self.buffer_lock:
            events = list(self.buffer)
            self.buffer.clear()

        if events:
            self.stats["events_read"] += len(events)
            self.stats["bytes_read"] += sum(len(str(event.get("message", ""))) for event in events)
            return events

        if not self.mock_enabled:
            return []

        # Generate deterministic demo syslog messages only when demo telemetry is enabled.
        import random
        from datetime import timezone
        
        syslog_facilities = ["auth", "authpriv", "daemon", "cron", "mail", "kern"]
        syslog_levels = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
        
        # Generate 1-3 mock syslog events
        for _ in range(random.randint(1, 3)):
            self.mock_counter += 1
            events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "facility": random.choice(syslog_facilities),
                "severity": random.choice(syslog_levels),
                "source_ip": f"192.168.1.{random.randint(1, 254)}",
                "event_type": "system_log",
                "message": f"Mock syslog message #{self.mock_counter}",
                "details": {
                    "port": self.port,
                    "protocol": "UDP",
                    "original_message": f"<{random.randint(0, 191)}>Mock syslog data"
                }
            })
        
        return events

    def _parse_syslog_message(self, message: str, source_ip: str) -> Dict[str, Any]:
        from datetime import timezone

        severity = "info"
        lowered = message.lower()
        if any(token in lowered for token in ["panic", "emerg", "critical", "crit"]):
            severity = "critical"
        elif any(token in lowered for token in ["error", "failed", "denied", "blocked"]):
            severity = "high"
        elif any(token in lowered for token in ["warn", "alert", "scan"]):
            severity = "medium"

        event_type = "system_log"
        if any(token in lowered for token in ["login", "logon", "auth", "password", "failed"]):
            event_type = "authentication"
        elif any(token in lowered for token in ["connect", "firewall", "flow", "allow", "deny", "blocked"]):
            event_type = "network_connection"
        elif "dns" in lowered or "query" in lowered:
            event_type = "dns_query"

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "facility": "syslog",
            "severity": severity,
            "source_ip": source_ip,
            "event_type": event_type,
            "message": message,
            "details": {
                "port": self.port,
                "protocol": "UDP",
                "original_message": message,
                "listener": f"{self.host}:{self.port}",
            },
            "source_type": "syslog",
            "source_name": "udp_syslog",
        }

class FileLogSource(DataSource):
    """File-based log source"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("filelog_source", config)
        self.log_dir = runtime_data_path(config.get("path", "data/inputs/logs"))
        self.file_positions = {}  # file_path -> last read position
        self.file_encodings = ['utf-8', 'latin-1', 'cp1252']
        self.mock_counter = 0
        self.mock_enabled = bool(config.get("mock_enabled", True))
    
    def read_events(self) -> List[Dict[str, Any]]:
        """Read events from log files"""
        events = []
        
        if not self.log_dir.exists():
            self.log_dir.mkdir(parents=True, exist_ok=True)
            if self.mock_enabled:
                self._create_sample_log_file()
        
        # Find log files
        log_patterns = ["*.log", "*.txt", "*.csv", "*.json"]
        for pattern in log_patterns:
            for log_file in self.log_dir.glob(pattern):
                try:
                    file_events = self._read_log_file(log_file)
                    events.extend(file_events)
                except Exception as e:
                    print(f"Error reading log file {log_file}: {e}")
                    self.stats["errors"] += 1
        
        # If no files found, generate mock events
        if not events and self.mock_enabled:
            events = self._generate_mock_log_events()
        
        return events
    
    def _create_sample_log_file(self):
        """Create a sample log file for testing"""
        sample_file = self.log_dir / "sample.log"
        with open(sample_file, 'w') as f:
            f.write("2024-01-15 10:30:00 INFO User admin logged in from 192.168.1.100\n")
            f.write("2024-01-15 10:31:00 ERROR Failed login attempt from 10.0.0.5\n")
            f.write("2024-01-15 10:32:00 WARNING Port scan detected from 192.168.1.200\n")
    
    def _read_log_file(self, log_file: Path) -> List[Dict[str, Any]]:
        """Read a single log file"""
        events = []
        
        try:
            # Get last read position
            last_pos = self.file_positions.get(str(log_file), 0)
            
            # Read new lines
            with open(log_file, 'r', encoding=self._detect_encoding(log_file)) as f:
                f.seek(last_pos)
                lines = f.readlines()
                
                for line in lines:
                    event = self._parse_log_line(line.strip(), log_file.name)
                    if event:
                        events.append(event)
                
                # Update position
                self.file_positions[str(log_file)] = f.tell()
                self.stats["events_read"] += len(events)
                self.stats["bytes_read"] += len(b''.join([l.encode() for l in lines]))
        
        except UnicodeDecodeError:
            # Try different encoding
            pass
        
        return events
    
    def _detect_encoding(self, file_path: Path) -> str:
        """Detect file encoding"""
        for encoding in self.file_encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    f.read(1024)
                return encoding
            except UnicodeDecodeError:
                continue
        return 'utf-8'  # default
    
    def _parse_log_line(self, line: str, source_name: str) -> Optional[Dict[str, Any]]:
        """Parse a single log line"""
        if not line.strip():
            return None
        
        from datetime import timezone
        import re
        
        # Try to extract timestamp
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        if timestamp_match:
            timestamp_str = timestamp_match.group(1)
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)
        
        # Try to extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, line)
        
        source_ip = ips[0] if len(ips) > 0 else None
        dest_ip = ips[1] if len(ips) > 1 else None
        
        # Determine event type based on content
        event_type = "system_alert"
        line_lower = line.lower()
        
        if "auth" in line_lower or "login" in line_lower or "logged" in line_lower:
            event_type = "authentication"
        elif "connection" in line_lower or "connect" in line_lower:
            event_type = "network_connection"
        elif "dns" in line_lower or "query" in line_lower:
            event_type = "dns_query"
        elif "http" in line_lower or "https" in line_lower:
            event_type = "http_request"
        elif "error" in line_lower or "failed" in line_lower:
            event_type = "system_error"
        elif "warning" in line_lower or "alert" in line_lower:
            event_type = "system_alert"
        
        return {
            "raw_line": line,
            "timestamp": timestamp.isoformat(),
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "event_type": event_type,
            "source_name": source_name,
            "details": {"raw_message": line}
        }
    
    def _generate_mock_log_events(self) -> List[Dict[str, Any]]:
        """Generate mock log events for testing"""
        import random
        from datetime import timezone
        
        events = []
        event_types = ["authentication", "network_connection", "dns_query", "system_alert"]
        
        for _ in range(random.randint(2, 5)):
            self.mock_counter += 1
            event_type = random.choice(event_types)
            
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "event_type": event_type,
                "source_name": "mock_log",
                "details": {"message": f"Mock log event #{self.mock_counter}"}
            }
            
            if event_type == "network_connection":
                event["destination_ip"] = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
                event["destination_port"] = random.choice([80, 443, 22, 3389])
                event["protocol"] = random.choice(["TCP", "UDP"])
            
            events.append(event)
        
        return events

class JSONTelemetrySource(DataSource):
    """Production telemetry drop-folder source for JSON, JSONL, EVE, and Zeek TSV."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("json_source", config)
        self.json_dir = runtime_data_path(config.get("path", "data/inputs/live"))
        self.processed_files = set()

    def read_events(self) -> List[Dict[str, Any]]:
        """Read new JSON files from the drop folder."""
        events = []
        self.json_dir.mkdir(parents=True, exist_ok=True)

        supported_patterns = ("*.json", "*.jsonl", "*.ndjson", "*.eve", "*.log", "*.tsv")
        for telemetry_file in sorted(path for pattern in supported_patterns for path in self.json_dir.glob(pattern)):
            if telemetry_file.name in self.processed_files:
                continue

            try:
                records = parse_sensor_file(telemetry_file)
                for record in records:
                    if isinstance(record, dict):
                        record.setdefault("source_name", telemetry_file.name)
                        record.setdefault("source_type", "json")
                        events.append(record)

                self.processed_files.add(telemetry_file.name)
                self.stats["events_read"] += len(records)
                self.stats["bytes_read"] += telemetry_file.stat().st_size
            except Exception as e:
                print(f"Error reading telemetry {telemetry_file}: {e}")
                self.stats["errors"] += 1

        return events

    def _extract_records(self, parsed: Any) -> List[Dict[str, Any]]:
        """Extract event records from common JSON shapes."""
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]

        if isinstance(parsed, dict):
            for key in ("events", "alerts", "records", "data"):
                value = parsed.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            return [parsed]

        return []

class IngestEngine:
    """
    Ingest Engine for Cyber-EW Fusion Cell
    
    Collects raw cyber signals from various sources:
    - PCAP files (network traffic)
    - Syslog messages
    - File-based logs
    - Windows Event Logs
    - External threat feeds
    """
    
    def __init__(self, config: Any = None):
        self.config = config or INGEST_CONFIG
        self.sources: Dict[str, DataSource] = {}
        self.event_queue = Queue(maxsize=10000)
        self.is_running = False
        self.worker_thread = None
        self.callbacks = []  # NEW: List of callback functions
        
        # Statistics
        from datetime import timezone
        self.stats = {
            "total_events": 0,
            "source_stats": {},
            "start_time": datetime.now(timezone.utc),
            "last_activity": None
        }
        
        # Initialize data sources
        self._init_sources()
    
    def _init_sources(self):
        """Initialize data sources from configuration"""
        sources_list = self.config.sources if self.config.sources else []
        disable_mock_sources = os.environ.get("CYBER_EW_DISABLE_MOCK_SOURCES", "").lower() in {"1", "true", "yes"}
        explicit_mock = os.environ.get("CYBER_EW_ENABLE_MOCK_TELEMETRY")
        mock_enabled = explicit_mock.lower() in {"1", "true", "yes", "on"} if explicit_mock is not None else not disable_mock_sources
        
        # PCAP source
        if self.config.pcap_enabled and mock_enabled:
            pcap_config = next((s for s in sources_list if s["type"] == "pcap"), {})
            self.sources["pcap"] = PCAPSource(pcap_config)
        
        # Syslog source
        if self.config.syslog_enabled:
            syslog_config = next((s for s in sources_list if s["type"] == "syslog"), {})
            syslog_config["mock_enabled"] = mock_enabled
            self.sources["syslog"] = SyslogSource(syslog_config)

        # JSON telemetry source
        if getattr(self.config, "json_enabled", True):
            json_config = next((s for s in sources_list if s["type"] == "json"), {"path": "data/inputs/live"})
            self.sources["json"] = JSONTelemetrySource(json_config)
        
        # File log source (generic)
        filelog_config = {"path": "data/inputs/logs", "mock_enabled": mock_enabled}
        self.sources["filelog"] = FileLogSource(filelog_config)
    
    # NEW METHOD: Register callback
    def register_callback(self, callback: Callable):
        """
        Register a callback function to receive raw events
        
        Args:
            callback: Function that takes a raw event dict as parameter
        """
        self.callbacks.append(callback)
        print(f"IngestEngine: Callback registered ({len(self.callbacks)} total)")
    
    def _notify_callbacks(self, raw_event: Dict[str, Any]):
        """Notify all registered callbacks with raw event"""
        for callback in self.callbacks:
            try:
                callback(raw_event)
            except Exception as e:
                print(f"IngestEngine: Callback error: {e}")
    
    def start(self):
        """Start the ingest engine"""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Start all sources
        for source in self.sources.values():
            source.start()
        
        # Start worker thread for reading events
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        
        print(f"Ingest Engine started with {len(self.sources)} sources and {len(self.callbacks)} callbacks")
    
    def stop(self):
        """Stop the ingest engine"""
        self.is_running = False
        
        # Stop all sources
        for source in self.sources.values():
            source.stop()
        
        # Wait for worker thread to finish
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5.0)
        
        print("Ingest Engine stopped")
    
    def _worker_loop(self):
        """Worker thread loop for reading events"""
        while self.is_running:
            try:
                # Read events from all sources
                for source_name, source in self.sources.items():
                    try:
                        events = source.read_events()
                        
                        for event_data in events:
                            event_data.setdefault("source_type", source_name)
                            # NEW: Notify callbacks with raw event data
                            self._notify_callbacks(event_data)
                            
                            # Convert to NormalizedEvent (for queue)
                            normalized_event = self._normalize_event(event_data, source_name)
                            
                            if normalized_event:
                                # Put in queue (non-blocking with timeout)
                                try:
                                    self.event_queue.put(normalized_event, timeout=0.1)
                                    self.stats["total_events"] += 1
                                    from datetime import timezone
                                    self.stats["last_activity"] = datetime.now(timezone.utc)
                                    
                                    # Update source stats
                                    if source_name not in self.stats["source_stats"]:
                                        self.stats["source_stats"][source_name] = 0
                                    self.stats["source_stats"][source_name] += 1
                                    
                                except Exception as e:
                                    print(f"Error queuing event: {e}")
                    
                    except Exception as e:
                        print(f"Error reading from source {source_name}: {e}")
                
                # Sleep to prevent CPU spinning
                time.sleep(1.0)  # Increased from 0.1 to 1.0 for less CPU usage
                
            except Exception as e:
                print(f"Error in ingest worker loop: {e}")
                time.sleep(5.0)
    
    def _normalize_event(self, event_data: Dict[str, Any], source_name: str) -> Optional[NormalizedEvent]:
        """Convert raw event data to NormalizedEvent"""
        try:
            # Import the helper function from event_models
            from core.models.event_models import ensure_utc
            
            # Extract timestamp
            if isinstance(event_data.get("timestamp"), str):
                from dateutil.parser import isoparse
                timestamp = isoparse(event_data["timestamp"])
            elif isinstance(event_data.get("timestamp"), datetime):
                timestamp = event_data["timestamp"]
            else:
                from datetime import timezone
                timestamp = datetime.now(timezone.utc)
            
            # Ensure UTC using the function from event_models
            timestamp = ensure_utc(timestamp)
            
            # Extract event type
            event_type_str = event_data.get("event_type", "system_alert")
            try:
                event_type = EventType(event_type_str)
            except ValueError:
                event_type = EventType.SYSTEM_ALERT

            severity_str = event_data.get("severity") or event_data.get("level") or "info"
            try:
                severity = EventSeverity(str(severity_str).lower())
            except ValueError:
                severity = EventSeverity.INFO
            
            # Create NormalizedEvent
            event = NormalizedEvent(
                event_id=f"ingest_{self.stats['total_events']:08d}",
                event_type=event_type,
                timestamp=timestamp,
                source_ip=event_data.get("source_ip"),
                destination_ip=event_data.get("destination_ip"),
                source_host=event_data.get("source_host"),
                destination_host=event_data.get("destination_host"),
                username=event_data.get("username"),
                process_name=event_data.get("process_name"),
                file_path=event_data.get("file_path"),
                url=event_data.get("url"),
                port=event_data.get("port") or event_data.get("destination_port") or event_data.get("dest_port"),
                protocol=event_data.get("protocol"),
                bytes_sent=event_data.get("bytes_sent"),
                bytes_received=event_data.get("bytes_received"),
                severity=severity,
                confidence=float(event_data.get("confidence", 1.0) or 1.0),
                details=event_data.get("details", {}),
                source_id=f"{source_name}_{event_data.get('source_name', 'unknown')}",
                raw_event=event_data,
                tags=[source_name]
            )
            
            return event
            
        except Exception as e:
            print(f"Error normalizing event: {e}, Data: {event_data}")
            return None
    
    def get_event(self, timeout: float = 1.0) -> Optional[NormalizedEvent]:
        """Get an event from the queue (blocking)"""
        try:
            return self.event_queue.get(timeout=timeout)
        except Exception:
            return None
    
    def get_events_batch(self, max_count: int = 100, timeout: float = 1.0) -> List[NormalizedEvent]:
        """Get multiple events from the queue"""
        events = []
        start_time = time.time()
        
        while len(events) < max_count and (time.time() - start_time) < timeout:
            event = self.get_event(timeout=0.1)
            if event:
                events.append(event)
        
        return events
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        stats = self.stats.copy()
        from datetime import timezone
        stats["uptime"] = (datetime.now(timezone.utc) - stats["start_time"]).total_seconds()
        stats["queue_size"] = self.event_queue.qsize()
        stats["sources"] = {name: source.get_stats() for name, source in self.sources.items()}
        stats["callbacks_registered"] = len(self.callbacks)  # NEW
        
        return stats
    
    def test_ingest(self, test_data: Optional[List[Dict[str, Any]]] = None) -> List[NormalizedEvent]:
        """
        Test the ingest engine with sample data
        
        Args:
            test_data: Optional test data to ingest
            
        Returns:
            List of normalized events
        """
        if test_data is None:
            # Create sample test data
            from datetime import timezone
            test_data = [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": "192.168.1.100",
                    "destination_ip": "8.8.8.8",
                    "event_type": "dns_query",
                    "details": {"query": "google.com", "response": "142.250.185.78"}
                },
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": "192.168.1.100",
                    "destination_ip": "142.250.185.78",
                    "event_type": "http_request",
                    "port": 443,
                    "protocol": "TCP",
                    "details": {"method": "GET", "url": "https://google.com"}
                }
            ]
        
        events = []
        for data in test_data:
            event = self._normalize_event(data, "test_source")
            if event:
                events.append(event)
        
        return events
