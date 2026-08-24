"""
Behavior models for Cyber-EW Fusion Cell
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
import statistics
import json

from core.models.event_models import EventType, EventSeverity, NormalizedEvent, EventCluster
from utils.time_utils import ensure_utc, datetime_now_utc, TimeSeriesBuffer

class BehaviorType(Enum):
    """Types of behavioral analyses"""
    BASELINE_DEVIATION = "baseline_deviation"
    SEQUENCE_PATTERN = "sequence_pattern"
    REPETITION_DETECTION = "repetition_detection"
    ESCALATION_DETECTION = "escalation_detection"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE_ESTABLISHMENT = "persistence_establishment"
    RANSOMWARE_ACTIVITY = "ransomware_activity"
    C2_BEACONING = "c2_beaconing"
    DATA_STAGING = "data_staging"

class BaselineStatus(Enum):
    """Status of behavioral baseline"""
    LEARNING = "learning"  # Still collecting baseline data
    ACTIVE = "active"      # Baseline established and active
    STALE = "stale"        # Baseline needs updating
    COMPROMISED = "compromised"  # Baseline may be compromised

@dataclass
class BehavioralProfile:
    """Behavioral profile for an entity (user, host, IP)"""
    entity_type: str  # "user", "host", "ip"
    entity_id: str    # e.g., username, hostname, IP address
    
    # Baseline period
    period_start: datetime
    period_end: datetime
    baseline_status: BaselineStatus = BaselineStatus.LEARNING
    
    # Statistical baselines
    event_frequencies: Dict[EventType, Dict[str, float]] = field(default_factory=dict)  # mean, std_dev
    hourly_pattern: Dict[int, float] = field(default_factory=dict)  # hour_of_day -> activity_level
    daily_pattern: Dict[int, float] = field(default_factory=dict)  # day_of_week -> activity_level
    
    # Destination profiles
    common_destinations: Dict[str, float] = field(default_factory=dict)  # dest_ip -> frequency
    common_ports: Dict[int, float] = field(default_factory=dict)  # port -> frequency
    
    # Session patterns
    avg_session_length: timedelta = timedelta(minutes=30)
    typical_work_hours: Optional[Tuple[int, int]] = None  # (start_hour, end_hour)
    
    # Alert thresholds
    anomaly_threshold: float = 3.0  # Standard deviations for anomaly detection
    
    def __post_init__(self):
        """Ensure timestamps are UTC"""
        self.period_start = ensure_utc(self.period_start)
        self.period_end = ensure_utc(self.period_end)
    
    def update_with_event(self, event: NormalizedEvent, current_time: datetime):
        """Update profile with a new event"""
        event_type = event.event_type
        
        # Update event frequency statistics
        if event_type not in self.event_frequencies:
            self.event_frequencies[event_type] = {"count": 1, "mean": 1.0, "std_dev": 0.0}
        else:
            stats = self.event_frequencies[event_type]
            stats["count"] += 1
            
            # Simple moving average for now (in production, use proper exponential moving avg)
            old_mean = stats["mean"]
            stats["mean"] = old_mean + (1 - old_mean) / stats["count"]
        
        # Update hourly pattern
        hour = event.timestamp.hour
        self.hourly_pattern[hour] = self.hourly_pattern.get(hour, 0) + 1
        
        # Update destination profiles
        if event.destination_ip:
            self.common_destinations[event.destination_ip] = \
                self.common_destinations.get(event.destination_ip, 0) + 1
        
        if event.port:
            self.common_ports[event.port] = self.common_ports.get(event.port, 0) + 1
        
        # Update period end
        self.period_end = max(self.period_end, ensure_utc(event.timestamp))
        
        # Check if baseline should be active
        baseline_duration = self.period_end - self.period_start
        if baseline_duration >= timedelta(days=30) and self.baseline_status == BaselineStatus.LEARNING:
            self.baseline_status = BaselineStatus.ACTIVE
            self._finalize_baseline()
    
    def _finalize_baseline(self):
        """Finalize baseline by normalizing frequencies"""
        # Normalize hourly pattern
        total_hours = sum(self.hourly_pattern.values())
        if total_hours > 0:
            for hour in self.hourly_pattern:
                self.hourly_pattern[hour] /= total_hours
        
        # Normalize destinations
        total_dests = sum(self.common_destinations.values())
        if total_dests > 0:
            for dest in self.common_destinations:
                self.common_destinations[dest] /= total_dests
        
        # Normalize ports
        total_ports = sum(self.common_ports.values())
        if total_ports > 0:
            for port in self.common_ports:
                self.common_ports[port] /= total_ports
    
    def calculate_anomaly_score(self, event: NormalizedEvent) -> float:
        """Calculate how anomalous this event is (0-1 scale)"""
        if self.baseline_status != BaselineStatus.ACTIVE:
            return 0.0  # Can't detect anomalies without baseline
        
        anomaly_factors = []
        
        # 1. Check event type frequency
        if event.event_type in self.event_frequencies:
            expected_freq = self.event_frequencies[event.event_type]["mean"]
            # For now, simple deviation (in production, use z-score)
            anomaly_factors.append(min(expected_freq * 2, 1.0))
        
        # 2. Check hour of day
        hour = event.timestamp.hour
        if hour in self.hourly_pattern:
            expected_hourly = self.hourly_pattern[hour]
            if expected_hourly < 0.01:  # Less than 1% of activity expected at this hour
                anomaly_factors.append(0.8)
        
        # 3. Check destination
        if event.destination_ip and event.destination_ip in self.common_destinations:
            dest_freq = self.common_destinations[event.destination_ip]
            if dest_freq < 0.05:  # Uncommon destination (<5% of traffic)
                anomaly_factors.append(0.6)
        
        # 4. Check port
        if event.port and event.port in self.common_ports:
            port_freq = self.common_ports[event.port]
            if port_freq < 0.05:  # Uncommon port
                anomaly_factors.append(0.4)
        
        # Return max anomaly factor
        return max(anomaly_factors) if anomaly_factors else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "baseline_status": self.baseline_status.value,
            "event_frequencies": {k.value: v for k, v in self.event_frequencies.items()},
            "hourly_pattern": self.hourly_pattern,
            "common_destinations": self.common_destinations,
            "common_ports": self.common_ports,
            "anomaly_threshold": self.anomaly_threshold
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehavioralProfile':
        """Create a behavioral profile from persisted JSON data."""
        from dateutil.parser import isoparse

        event_frequencies = {}
        for event_type, stats in data.get("event_frequencies", {}).items():
            try:
                event_frequencies[EventType(event_type)] = stats
            except ValueError:
                continue

        common_ports = {}
        for port, frequency in data.get("common_ports", {}).items():
            try:
                common_ports[int(port)] = frequency
            except (TypeError, ValueError):
                continue

        profile = cls(
            entity_type=data["entity_type"],
            entity_id=data["entity_id"],
            period_start=isoparse(data["period_start"]),
            period_end=isoparse(data["period_end"]),
            baseline_status=BaselineStatus(data.get("baseline_status", BaselineStatus.LEARNING.value)),
            event_frequencies=event_frequencies,
            hourly_pattern={int(k): v for k, v in data.get("hourly_pattern", {}).items()},
            common_destinations=data.get("common_destinations", {}),
            common_ports=common_ports,
            anomaly_threshold=float(data.get("anomaly_threshold", 3.0))
        )
        return profile

@dataclass
class BehaviorPattern:
    """Detected behavioral pattern"""
    pattern_id: str
    pattern_type: BehaviorType
    description: str
    confidence: float
    detected_at: datetime
    entities: List[str]  # List of entity IDs involved
    events: List[NormalizedEvent]  # Events that form the pattern
    severity: EventSeverity = EventSeverity.MEDIUM
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Ensure timestamp is UTC"""
        self.detected_at = ensure_utc(self.detected_at)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting"""
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type.value,
            "description": self.description,
            "confidence": self.confidence,
            "detected_at": self.detected_at.isoformat(),
            "entities": self.entities,
            "event_count": len(self.events),
            "severity": self.severity.value,
            "metadata": self.metadata
        }

@dataclass 
class AttackSignature:
    """Signatures for known attack patterns"""
    name: str
    description: str
    behavior_type: BehaviorType
    detection_logic: str  # JSONPath, regex, or function name
    confidence_threshold: float = 0.7
    severity: EventSeverity = EventSeverity.HIGH
    mitigation: str = ""

# Define known attack patterns
KNOWN_ATTACK_PATTERNS = [
    AttackSignature(
        name="Lateral Movement - SMB Scanning",
        description="Multiple failed SMB connections to different hosts",
        behavior_type=BehaviorType.LATERAL_MOVEMENT,
        detection_logic="event_type:network_connection AND port:445 AND success:false",
        confidence_threshold=0.8,
        severity=EventSeverity.HIGH,
        mitigation="Block SMB traffic from source, investigate host"
    ),
    AttackSignature(
        name="Credential Stuffing",
        description="Multiple failed authentication attempts from same source",
        behavior_type=BehaviorType.REPETITION_DETECTION,
        detection_logic="event_type:authentication AND success:false AND count>10",
        confidence_threshold=0.9,
        severity=EventSeverity.CRITICAL,
        mitigation="Lock account, block source IP, alert SOC"
    ),
    AttackSignature(
        name="Data Exfiltration - High Volume",
        description="Unusually large data transfers to external IP",
        behavior_type=BehaviorType.DATA_EXFILTRATION,
        detection_logic="bytes_sent>1000000 AND is_external:true",
        confidence_threshold=0.7,
        severity=EventSeverity.HIGH,
        mitigation="Block external connection, capture packet capture"
    ),
    AttackSignature(
        name="Persistence - Scheduled Task Creation",
        description="Creation of suspicious scheduled tasks",
        behavior_type=BehaviorType.PERSISTENCE_ESTABLISHMENT,
        detection_logic="event_type:scheduled_task AND (command:*powershell* OR command:*cmd*)",
        confidence_threshold=0.6,
        severity=EventSeverity.MEDIUM,
        mitigation="Review scheduled tasks, remove suspicious entries"
    ),
    AttackSignature(
        name="Ransomware - Rapid File Encryption",
        description="High-volume file modifications or encryption-like extensions on a host",
        behavior_type=BehaviorType.RANSOMWARE_ACTIVITY,
        detection_logic="event_type:file_access AND (operation:write|rename OR extension:encrypted|locked) AND count>20",
        confidence_threshold=0.85,
        severity=EventSeverity.CRITICAL,
        mitigation="Isolate host, preserve volatile evidence, disable affected credentials"
    ),
    AttackSignature(
        name="Privilege Escalation - Scheduled Task",
        description="Scheduled task or process creation used to gain elevated execution",
        behavior_type=BehaviorType.ESCALATION_DETECTION,
        detection_logic="event_type:scheduled_task|process_creation AND privilege:admin|system",
        confidence_threshold=0.75,
        severity=EventSeverity.HIGH,
        mitigation="Disable task, inspect parent process, rotate impacted credentials"
    ),
    AttackSignature(
        name="C2 Beaconing - Periodic External Callback",
        description="Repeated small outbound connections to the same external endpoint",
        behavior_type=BehaviorType.C2_BEACONING,
        detection_logic="event_type:network_connection AND is_external:true AND interval:periodic AND bytes_sent<5000",
        confidence_threshold=0.75,
        severity=EventSeverity.HIGH,
        mitigation="Block destination, isolate endpoint, collect memory and network artifacts"
    ),
    AttackSignature(
        name="Data Staging - Archive Creation",
        description="Archive or compressed file creation before possible exfiltration",
        behavior_type=BehaviorType.DATA_STAGING,
        detection_logic="event_type:file_access|process_creation AND archive_tool:zip|rar|7z|tar",
        confidence_threshold=0.65,
        severity=EventSeverity.MEDIUM,
        mitigation="Review staged files, validate business justification, monitor outbound transfer"
    )
]
