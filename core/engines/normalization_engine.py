"""
Normalization Engine for Cyber-EW Fusion Cell
"""
import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import logging

# Fixed imports - only import what actually exists
from core.models.event_models import NormalizedEvent, EventType, EntityType, EventSeverity
from utils.time_utils import normalize_timestamp

# Remove the validators import since we don't have that file yet
# from utils.validators import validate_ip_address, validate_domain, validate_mac

logger = logging.getLogger(__name__)

class NormalizationEngine:
    """Normalizes events from various sources to common schema"""
    
    def __init__(self, config: Any = None):
        self.config = config or {}
        
        # Regex patterns for entity extraction
        self.patterns = {
            "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "ipv6": re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.I),
            "domain": re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b', re.I),
            "mac": re.compile(r'\b(?:[0-9A-F]{2}[:-]){5}(?:[0-9A-F]{2})\b', re.I),
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "url": re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*'),
        }
        
        # Field mappings for different source types
        self.field_mappings = {
            "pcap": self._map_pcap_fields,
            "syslog": self._map_syslog_fields,
            "windows_event": self._map_windows_event_fields,
            "threat_intel": self._map_threat_intel_fields,
            "suricata": self._map_suricata_fields,
            "zeek": self._map_zeek_fields
        }
        
        # Value normalizers
        self.normalizers = {
            "timestamp": self._normalize_timestamp,
            "ip_address": self._normalize_ip,
            "port": self._normalize_port,
            "protocol": self._normalize_protocol,
            "severity": self._normalize_severity,
            "action": self._normalize_action
        }
        
        # Statistics
        self.stats = {
            "events_normalized": 0,
            "errors": 0,
            "by_source_type": {}
        }
        
        logger.info("Normalization Engine initialized")
    
    def normalize(self, raw_event: Dict, source_type: str = "generic") -> Optional[NormalizedEvent]:
        """Normalize a raw event from any source"""
        try:
            # Get appropriate field mapper
            mapper = self.field_mappings.get(source_type, self._map_generic_fields)
            
            # Map fields
            mapped_data = mapper(raw_event)
            
            # Create normalized event
            event = self._create_normalized_event(mapped_data, source_type)
            
            # Apply additional normalization rules
            event = self._apply_normalization_rules(event)
            
            # Update statistics
            self.stats["events_normalized"] += 1
            if source_type not in self.stats["by_source_type"]:
                self.stats["by_source_type"][source_type] = 0
            self.stats["by_source_type"][source_type] += 1
            
            logger.debug(f"Normalized event: {event.event_id}")
            return event
            
        except Exception as e:
            logger.error(f"Normalization error: {str(e)}")
            self.stats["errors"] += 1
            import traceback
            logger.debug(traceback.format_exc())
            return None
    
    def _map_pcap_fields(self, pcap_data: Dict) -> Dict:
        """Map PCAP packet data to normalized schema"""
        mapped = {
            "timestamp": pcap_data.get("timestamp"),
            "source_ip": pcap_data.get("src_ip"),
            "source_port": pcap_data.get("src_port"),
            "destination_ip": pcap_data.get("dst_ip"),
            "destination_port": pcap_data.get("dst_port"),
            "protocol": pcap_data.get("protocol"),
            "packet_size": pcap_data.get("length"),
            "flags": pcap_data.get("tcp_flags", {})
        }
        
        # Add DNS/HTTP specific fields
        if pcap_data.get("dns_query"):
            mapped.update({
                "dns_query": pcap_data.get("dns_query"),
                "dns_type": pcap_data.get("dns_type"),
                "dns_response": pcap_data.get("dns_response")
            })
        
        elif pcap_data.get("http_method"):
            mapped.update({
                "http_method": pcap_data.get("http_method"),
                "http_host": pcap_data.get("http_host"),
                "http_uri": pcap_data.get("http_uri"),
                "user_agent": pcap_data.get("user_agent")
            })
        
        return mapped
    
    def _map_syslog_fields(self, syslog_data: Dict) -> Dict:
        """Map syslog data to normalized schema"""
        # Parse syslog message
        message = syslog_data.get("message", "")
        
        # Try to extract structured data
        extracted = self._parse_syslog_message(message)
        
        mapped = {
            "timestamp": syslog_data.get("timestamp"),
            "hostname": syslog_data.get("hostname"),
            "facility": syslog_data.get("facility"),
            "severity": syslog_data.get("severity"),
            "message": message,
            **extracted
        }
        
        return mapped
    
    def _parse_syslog_message(self, message: str) -> Dict:
        """Parse syslog message for structured data"""
        result = {}
        
        # Common patterns in security logs
        patterns = [
            (r'src=(?P<src_ip>\S+)', "source_ip"),
            (r'dst=(?P<dst_ip>\S+)', "destination_ip"),
            (r'spt=(?P<src_port>\d+)', "source_port"),
            (r'dpt=(?P<dst_port>\d+)', "destination_port"),
            (r'proto=(?P<protocol>\S+)', "protocol"),
            (r'action=(?P<action>\S+)', "action"),
            (r'user=(?P<user>\S+)', "user"),
            (r'status=(?P<status>\S+)', "status")
        ]
        
        for pattern, key in patterns:
            match = re.search(pattern, message)
            if match:
                result[key] = match.group(1)
        
        return result
    
    def _map_windows_event_fields(self, event_data: Dict) -> Dict:
        """Map Windows Event Log data to normalized schema"""
        mapped = {
            "timestamp": event_data.get("timestamp") or event_data.get("EventTime"),
            "event_type": event_data.get("event_type"),
            "event_id": event_data.get("event_id") or event_data.get("EventID"),
            "computer": event_data.get("source_host") or event_data.get("Computer"),
            "channel": event_data.get("Channel"),
            "level": event_data.get("severity") or self._map_windows_event_level(event_data.get("Level")),
            "message": event_data.get("Message"),
            "user": event_data.get("username") or event_data.get("TargetUserName"),
            "domain": event_data.get("TargetDomainName"),
            "logon_type": event_data.get("LogonType"),
            "source_ip": event_data.get("source_ip") or event_data.get("IpAddress") or event_data.get("SourceIp"),
            "destination_ip": event_data.get("destination_ip") or event_data.get("DestinationIp"),
            "destination_port": event_data.get("destination_port") or event_data.get("DestinationPort"),
            "process_name": event_data.get("process_name") or event_data.get("NewProcessName"),
            "file_path": event_data.get("file_path") or event_data.get("TargetFilename"),
            "details": event_data.get("details", {})
        }
        
        return mapped
    
    def _map_windows_event_level(self, level: str) -> str:
        """Map Windows Event level to standard severity"""
        level_map = {
            "0": "critical",    # Emergency
            "1": "critical",    # Alert
            "2": "high",        # Critical
            "3": "high",        # Error
            "4": "medium",      # Warning
            "5": "low",         # Notice
            "6": "info",        # Informational
            "7": "debug"        # Debug
        }
        return level_map.get(str(level), "info")
    
    def _map_threat_intel_fields(self, intel_data: Dict) -> Dict:
        """Map threat intelligence data to normalized schema"""
        mapped = {
            "timestamp": intel_data.get("first_seen"),
            "ioc": intel_data.get("ioc"),
            "ioc_type": intel_data.get("ioc_type"),
            "threat_type": intel_data.get("threat_type"),
            "malware": intel_data.get("malware"),
            "confidence": intel_data.get("confidence_level"),
            "description": intel_data.get("description"),
            "reference": intel_data.get("reference")
        }
        
        return mapped
    
    def _map_suricata_fields(self, suricata_data: Dict) -> Dict:
        """Map Suricata IDS/IPS data to normalized schema"""
        mapped = {
            "timestamp": suricata_data.get("timestamp"),
            "source_ip": suricata_data.get("source_ip") or suricata_data.get("src_ip"),
            "source_port": suricata_data.get("source_port") or suricata_data.get("src_port"),
            "destination_ip": suricata_data.get("destination_ip") or suricata_data.get("dest_ip"),
            "destination_port": suricata_data.get("destination_port") or suricata_data.get("dest_port"),
            "protocol": suricata_data.get("protocol") or suricata_data.get("proto"),
            "event_type": suricata_data.get("event_type"),
            "signature": suricata_data.get("alert", {}).get("signature"),
            "category": suricata_data.get("alert", {}).get("category"),
            "severity": suricata_data.get("severity") or suricata_data.get("alert", {}).get("severity"),
            "url": suricata_data.get("url"),
            "details": suricata_data.get("details", {})
        }
        
        return mapped
    
    def _map_zeek_fields(self, zeek_data: Dict) -> Dict:
        """Map Zeek (formerly Bro) network monitoring data to normalized schema"""
        mapped = {
            "timestamp": zeek_data.get("timestamp") or zeek_data.get("ts"),
            "event_type": zeek_data.get("event_type"),
            "source_ip": zeek_data.get("source_ip") or zeek_data.get("id.orig_h"),
            "source_port": zeek_data.get("source_port") or zeek_data.get("id.orig_p"),
            "destination_ip": zeek_data.get("destination_ip") or zeek_data.get("id.resp_h"),
            "destination_port": zeek_data.get("destination_port") or zeek_data.get("id.resp_p"),
            "protocol": zeek_data.get("protocol") or zeek_data.get("proto"),
            "service": zeek_data.get("service"),
            "duration": zeek_data.get("duration"),
            "bytes_sent": zeek_data.get("bytes_sent") or zeek_data.get("orig_bytes"),
            "bytes_received": zeek_data.get("bytes_received") or zeek_data.get("resp_bytes"),
            "url": zeek_data.get("url"),
            "severity": zeek_data.get("severity"),
            "details": zeek_data.get("details", {})
        }
        
        return mapped
    
    def _map_generic_fields(self, data: Dict) -> Dict:
        """Generic field mapping for unknown sources"""
        # Extract common fields using regex patterns
        extracted = {}
        
        for field_name, pattern in self.patterns.items():
            matches = pattern.findall(str(data))
            if matches:
                extracted[f"_{field_name}"] = matches
        
        return {**data, **extracted}
    
    def _create_normalized_event(self, data: Dict, source_type: str) -> NormalizedEvent:
        """Create normalized event from mapped data"""
        # Determine event type
        event_type = self._determine_event_type(data, source_type)
        
        # Map severity
        severity_str = data.get("severity") or data.get("level") or "info"
        severity = self._map_severity(severity_str)
        
        # Create event
        event = NormalizedEvent(
            event_id="",  # Will be auto-generated in __post_init__
            event_type=event_type,
            timestamp=normalize_timestamp(data.get("timestamp")),
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            source_host=data.get("hostname") or data.get("computer"),
            destination_host=data.get("http_host"),
            username=data.get("user") or data.get("username"),
            process_name=data.get("process_name"),
            file_path=data.get("file_path"),
            url=data.get("url") or data.get("http_uri"),
            port=data.get("destination_port") or data.get("dpt"),
            protocol=data.get("protocol"),
            bytes_sent=data.get("bytes_sent") or data.get("orig_bytes"),
            bytes_received=data.get("bytes_received") or data.get("resp_bytes"),
            severity=severity,
            details=self._extract_details(data),
            source_id=source_type,
            raw_event=data
        )
        
        return event
    
    def _determine_event_type(self, data: Dict, source_type: str) -> EventType:
        """Determine event type based on data content"""
        explicit_type = data.get("event_type")
        if explicit_type:
            try:
                return EventType(str(explicit_type))
            except ValueError:
                pass

        # Check for specific indicators
        if "dns_query" in data or "dns_type" in data:
            return EventType.DNS_QUERY
        elif "http_method" in data or "http_uri" in data:
            return EventType.HTTP_REQUEST
        elif "logon_type" in data or "user" in data:
            return EventType.AUTHENTICATION
        elif "process_name" in data:
            return EventType.PROCESS_CREATION
        elif "ioc_type" in data or "threat_type" in data:
            return EventType.THREAT_INTEL_MATCH
        elif "file_path" in data:
            return EventType.FILE_ACCESS
        
        # Default based on source
        type_map = {
            "pcap": EventType.NETWORK_CONNECTION,
            "syslog": EventType.NETWORK_CONNECTION,
            "windows_event": EventType.AUTHENTICATION,
            "threat_intel": EventType.THREAT_INTEL_MATCH
        }
        
        return type_map.get(source_type, EventType.SYSTEM_ALERT)
    
    def _map_severity(self, severity_str: str) -> EventSeverity:
        """Map severity string to EventSeverity enum"""
        severity_str = str(severity_str).lower()
        
        severity_map = {
            "critical": EventSeverity.CRITICAL,
            "high": EventSeverity.HIGH,
            "medium": EventSeverity.MEDIUM,
            "low": EventSeverity.LOW,
            "info": EventSeverity.INFO,
            "informational": EventSeverity.INFO,
            "warning": EventSeverity.MEDIUM,
            "error": EventSeverity.HIGH,
            "debug": EventSeverity.LOW,
            "0": EventSeverity.CRITICAL,
            "1": EventSeverity.CRITICAL,
            "2": EventSeverity.HIGH,
            "3": EventSeverity.HIGH,
            "4": EventSeverity.MEDIUM,
            "5": EventSeverity.LOW,
            "6": EventSeverity.INFO,
            "7": EventSeverity.LOW
        }
        
        return severity_map.get(severity_str, EventSeverity.INFO)
    
    def _extract_details(self, data: Dict) -> Dict[str, Any]:
        """Extract details from mapped data"""
        details = {}
        
        # Add common details
        common_fields = [
            "message", "signature", "category", "event_id",
            "action", "status", "facility", "channel",
            "duration", "packet_size", "flags", "success",
            "operation", "command", "process_command_line",
            "repeat_count", "interval", "attempts", "reason",
            "service", "query", "dns_query"
        ]
        
        for field in common_fields:
            if field in data and data[field]:
                details[field] = data[field]

        if isinstance(data.get("details"), dict):
            details.update(data["details"])
        
        # Add extracted patterns
        for key, value in data.items():
            if key.startswith("_") and value:  # Extracted patterns
                details[key[1:]] = value
        
        return details
    
    def _apply_normalization_rules(self, event: NormalizedEvent) -> NormalizedEvent:
        """Apply additional normalization rules"""
        # Rule 1: Tag internal/external IPs
        if event.is_external:
            event.tags.append("external_traffic")
        else:
            event.tags.append("internal_traffic")
        
        # Rule 2: Tag suspicious ports
        if event.port:
            port = event.port
            if port in [22, 23, 3389, 5900]:  # SSH, Telnet, RDP, VNC
                event.tags.append("remote_access")
            elif port < 1024:
                event.tags.append("privileged_port")
        
        # Rule 3: Add threat indicators
        if event.event_type == EventType.THREAT_INTEL_MATCH:
            event.tags.append("known_malicious")
        
        return event
    
    def _normalize_timestamp(self, timestamp_input) -> datetime:
        """Normalize timestamp to UTC datetime"""
        return normalize_timestamp(timestamp_input)
    
    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address format"""
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            return ip
    
    def _normalize_port(self, port) -> int:
        """Normalize port number"""
        try:
            return int(port)
        except (ValueError, TypeError):
            return 0
    
    def _normalize_protocol(self, protocol: str) -> str:
        """Normalize protocol name"""
        if not protocol:
            return "unknown"
        
        protocol = protocol.lower().strip()
        
        protocol_map = {
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "http": "http",
            "https": "https",
            "dns": "dns",
            "ftp": "ftp",
            "ssh": "ssh",
            "smtp": "smtp"
        }
        
        return protocol_map.get(protocol, protocol)
    
    def _normalize_severity(self, severity) -> str:
        """Normalize severity levels"""
        return self._map_severity(severity).value
    
    def _normalize_action(self, action: str) -> str:
        """Normalize action names"""
        if not action:
            return "unknown"
        
        action = action.lower()
        
        action_map = {
            "allow": "allowed",
            "deny": "blocked",
            "drop": "blocked",
            "accept": "allowed",
            "reject": "blocked",
            "success": "success",
            "failure": "failed",
            "login": "authenticated",
            "logoff": "deauthenticated"
        }
        
        return action_map.get(action, action)
    
    def normalize_batch(self, raw_events: List[Dict], source_type: str = "generic") -> List[NormalizedEvent]:
        """Normalize a batch of raw events"""
        normalized_events = []
        
        for raw_event in raw_events:
            normalized = self.normalize(raw_event, source_type)
            if normalized:
                normalized_events.append(normalized)
        
        return normalized_events
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return self.stats.copy()
    
    def clear_stats(self):
        """Clear statistics"""
        self.stats = {
            "events_normalized": 0,
            "errors": 0,
            "by_source_type": {}
        }
