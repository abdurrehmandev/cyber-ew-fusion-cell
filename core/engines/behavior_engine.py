"""
Behavior Engine for Cyber-EW Fusion Cell - FIXED VERSION
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
import uuid
import json
from collections import defaultdict, deque
import statistics

from core.models.event_models import NormalizedEvent, EventCluster, EventType, EventSeverity
from core.models.behavior_models import (
    BehavioralProfile, BehaviorPattern, BehaviorType, 
    BaselineStatus, AttackSignature, KNOWN_ATTACK_PATTERNS
)
from utils.time_utils import ensure_utc, datetime_now_utc, TimeSeriesBuffer, TimeWindowIndex
from config.settings import BEHAVIOR_CONFIG

class BehaviorEngine:
    """
    Behavior engine for detecting anomalies, patterns, and attack behaviors.
    
    This engine:
    1. Builds behavioral profiles for entities
    2. Detects deviations from baseline behavior
    3. Identifies known attack patterns
    4. Tracks sequences and repetitions
    5. Scores behavioral risks
    """
    
    def __init__(self, config: Any = None, output_callback: Optional[Callable] = None):
        self.config = config or BEHAVIOR_CONFIG
        self.output_callback = output_callback  # Callback to output alerts
        
        # Behavioral profiles by entity
        self.profiles: Dict[Tuple[str, str], BehavioralProfile] = {}  # (entity_type, entity_id) -> profile
        
        # Event sequences for pattern detection
        self.entity_sequences: Dict[str, deque] = defaultdict(deque)  # entity_id -> deque of (timestamp, event)
        
        # Time-based buffers for different analyses
        self.auth_failures = TimeWindowIndex(window_seconds=3600)  # 1 hour for auth failures
        self.network_connections = TimeWindowIndex(window_seconds=300)  # 5 minutes for network
        
        # Detected patterns
        self.detected_patterns: List[BehaviorPattern] = []
        
        # Attack signatures
        self.attack_signatures = KNOWN_ATTACK_PATTERNS
        
        # Statistics
        self.stats = {
            "events_processed": 0,
            "profiles_created": 0,
            "profiles_updated": 0,
            "patterns_detected": 0,
            "anomalies_found": 0,
            "baseline_active": 0,
            "alerts_sent": 0
        }
    
    def set_output_callback(self, callback: Callable):
        """Set callback function for outputting alerts"""
        self.output_callback = callback
        print(f"Behavior Engine: Output callback set")
    
    def process_event(self, event: NormalizedEvent) -> List[BehaviorPattern]:
        """
        Process an event for behavioral analysis.
        
        Args:
            event: Normalized event to analyze
            
        Returns:
            List of behavior patterns detected from this event
        """
        self.stats["events_processed"] += 1
        
        detected_patterns = []
        
        # 1. Update behavioral profiles
        profile_patterns = self._update_profiles(event)
        detected_patterns.extend(profile_patterns)
        
        # 2. Check for known attack patterns
        attack_patterns = self._check_attack_patterns(event)
        detected_patterns.extend(attack_patterns)
        
        # 3. Check sequences and repetitions
        sequence_patterns = self._check_sequences(event)
        detected_patterns.extend(sequence_patterns)
        
        # 4. Track event for future correlation
        self._track_event(event)
        
        # 5. Send alerts for high-confidence patterns
        high_confidence_patterns = [p for p in detected_patterns if p.confidence > 0.5]
        for pattern in high_confidence_patterns:
            self._send_alert(pattern)
        
        # Store and update statistics
        if detected_patterns:
            self.detected_patterns.extend(detected_patterns)
            self.stats["patterns_detected"] += len(detected_patterns)
        
        return detected_patterns

    def analyze_event(self, event: NormalizedEvent) -> Dict[str, Any]:
        """Backward-compatible analysis API used by older tests/scripts."""
        patterns = self.process_event(event)
        risk_score = min(1.0, sum(pattern.confidence for pattern in patterns))
        anomalies = [
            pattern.to_dict()
            for pattern in patterns
            if pattern.pattern_type == BehaviorType.BASELINE_DEVIATION
        ]

        return {
            "risk_score": risk_score,
            "anomalies": anomalies,
            "patterns": [pattern.to_dict() for pattern in patterns],
            "pattern_count": len(patterns)
        }
    
    def process_cluster(self, cluster: EventCluster) -> List[BehaviorPattern]:
        """
        Process a cluster of correlated events for behavioral analysis.
        
        Args:
            cluster: Cluster of correlated events
            
        Returns:
            List of behavior patterns detected from this cluster
        """
        cluster_patterns = []
        
        # 1. Check for lateral movement patterns
        lateral_patterns = self._check_lateral_movement(cluster)
        cluster_patterns.extend(lateral_patterns)
        
        # 2. Check for escalation patterns
        escalation_patterns = self._check_escalation(cluster)
        cluster_patterns.extend(escalation_patterns)
        
        # 3. Check for data exfiltration patterns
        exfiltration_patterns = self._check_exfiltration(cluster)
        cluster_patterns.extend(exfiltration_patterns)
        
        # 4. Send alerts for high-confidence cluster patterns
        high_confidence_cluster_patterns = [p for p in cluster_patterns if p.confidence > 0.5]
        for pattern in high_confidence_cluster_patterns:
            self._send_alert(pattern)
        
        # Store patterns
        if cluster_patterns:
            self.detected_patterns.extend(cluster_patterns)
            self.stats["patterns_detected"] += len(cluster_patterns)
        
        return cluster_patterns
    
    def _send_alert(self, pattern: BehaviorPattern):
        """Send alert via output callback"""
        if not self.output_callback:
            return
        
        try:
            # Create alert data
            alert_data = {
                "pattern_id": pattern.pattern_id,
                "pattern_type": pattern.pattern_type.value,
                "description": pattern.description,
                "confidence": pattern.confidence,
                "severity": pattern.severity.value,
                "detected_at": pattern.detected_at.isoformat() if hasattr(pattern.detected_at, 'isoformat') else str(pattern.detected_at),
                "entities": pattern.entities,
                "event_count": len(pattern.events),
                "metadata": pattern.metadata
            }
            
            # Calculate threat score (0-100)
            # Based on confidence, severity, and event count
            base_score = pattern.confidence * 100
            
            # Adjust for severity
            severity_multiplier = {
                EventSeverity.CRITICAL: 1.5,
                EventSeverity.HIGH: 1.2,
                EventSeverity.MEDIUM: 1.0,
                EventSeverity.LOW: 0.8,
                EventSeverity.INFO: 0.5
            }.get(pattern.severity, 1.0)
            
            # Adjust for event count (more events = more evidence)
            event_count_multiplier = min(1.0 + (len(pattern.events) * 0.1), 2.0)
            
            threat_score = min(base_score * severity_multiplier * event_count_multiplier, 100)
            
            # FIXED: Call the output_callback with correct parameters
            # The callback should be set up to call output_engine.publish_alert_simple()
            if callable(self.output_callback):
                # Check if callback accepts the simple signature
                try:
                    # Try calling with the simple signature first
                    self.output_callback(alert_data, threat_score)
                    self.stats["alerts_sent"] += 1
                except TypeError as e:
                    # If that fails, try different signature
                    print(f"Behavior Engine: Output callback error: {e}")
                    print(f"  Alert data: {alert_data}")
                    print(f"  Threat score: {threat_score}")
                    
        except Exception as e:
            print(f"Behavior Engine: Error sending alert: {e}")
    
    def _update_profiles(self, event: NormalizedEvent) -> List[BehaviorPattern]:
        """Update behavioral profiles and check for anomalies"""
        patterns = []
        current_time = datetime_now_utc()
        
        # Extract entities from event
        entities = self._extract_entities(event)
        
        for entity_type, entity_id in entities:
            profile_key = (entity_type, entity_id)
            
            # Get or create profile
            if profile_key not in self.profiles:
                self.profiles[profile_key] = BehavioralProfile(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    period_start=current_time,
                    period_end=current_time
                )
                self.stats["profiles_created"] += 1
            else:
                self.stats["profiles_updated"] += 1
            
            # Update profile with event
            profile = self.profiles[profile_key]
            profile.update_with_event(event, current_time)
            
            # Check for anomalies if baseline is active
            if profile.baseline_status == BaselineStatus.ACTIVE:
                anomaly_score = profile.calculate_anomaly_score(event)
                
                if anomaly_score > profile.anomaly_threshold / 3.0:  # Threshold scaled
                    self.stats["anomalies_found"] += 1
                    
                    pattern = BehaviorPattern(
                        pattern_id=f"anomaly_{uuid.uuid4().hex[:8]}",
                        pattern_type=BehaviorType.BASELINE_DEVIATION,
                        description=f"Behavioral anomaly detected for {entity_type} {entity_id}",
                        confidence=anomaly_score,
                        detected_at=current_time,
                        entities=[entity_id],
                        events=[event],
                        severity=EventSeverity.HIGH if anomaly_score > 0.7 else EventSeverity.MEDIUM,
                        metadata={
                            "anomaly_score": anomaly_score,
                            "entity_type": entity_type,
                            "event_type": event.event_type.value,
                            "baseline_status": profile.baseline_status.value
                        }
                    )
                    patterns.append(pattern)
        
        # Update baseline active count
        self.stats["baseline_active"] = sum(
            1 for p in self.profiles.values() 
            if p.baseline_status == BaselineStatus.ACTIVE
        )
        
        return patterns
    
    def _check_attack_patterns(self, event: NormalizedEvent) -> List[BehaviorPattern]:
        """Check event against known attack patterns"""
        patterns = []
        current_time = datetime_now_utc()
        
        for signature in self.attack_signatures:
            if self._matches_signature(event, signature):
                pattern = BehaviorPattern(
                    pattern_id=f"attack_{uuid.uuid4().hex[:8]}",
                    pattern_type=signature.behavior_type,
                    description=f"Attack pattern detected: {signature.name}",
                    confidence=signature.confidence_threshold,
                    detected_at=current_time,
                    entities=[event.source_ip] if event.source_ip else [],
                    events=[event],
                    severity=signature.severity,
                    metadata={
                        "signature_name": signature.name,
                        "mitigation": signature.mitigation,
                        "detection_logic": signature.detection_logic
                    }
                )
                patterns.append(pattern)
        
        return patterns
    
    def _matches_signature(self, event: NormalizedEvent, signature: AttackSignature) -> bool:
        """Check if event matches an attack signature"""
        # Simple rule-based matching for now
        # In production, this would use a rules engine
        
        if "credential stuffing" in signature.name.lower():
            # Check for multiple failed auths
            return (event.event_type == EventType.AUTHENTICATION and 
                    event.details.get("success") is False)
        
        elif "lateral movement" in signature.name.lower():
            # Check for SMB connections
            return (event.event_type == EventType.NETWORK_CONNECTION and
                    event.port in [445, 139] and
                    event.details.get("success") is False)
        
        elif "data exfiltration" in signature.name.lower():
            # Check for large data transfers
            return bool(event.bytes_sent and event.bytes_sent > 1000000 and
                        event.is_external)

        elif "ransomware" in signature.name.lower():
            suspicious_extensions = (
                ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
                ".wannacry", ".ryuk", ".lockbit"
            )
            file_path = (event.file_path or event.details.get("file_path") or "").lower()
            operation = str(event.details.get("operation", "")).lower()
            message = str(event.details.get("message", "")).lower()

            return (
                event.event_type == EventType.FILE_ACCESS and
                (
                    any(file_path.endswith(ext) for ext in suspicious_extensions) or
                    operation in {"encrypt", "rename", "mass_write"} or
                    "encrypt" in message
                )
            )

        elif "privilege escalation" in signature.name.lower():
            command = " ".join([
                str(event.details.get("command", "")),
                str(event.details.get("process_command_line", "")),
                event.process_name or ""
            ]).lower()
            privilege = str(event.details.get("privilege", "")).lower()
            user = (event.username or "").lower()

            return (
                event.event_type in {EventType.SCHEDULED_TASK, EventType.PROCESS_CREATION} and
                (
                    privilege in {"admin", "administrator", "system", "root"} or
                    user in {"administrator", "system", "root"} or
                    any(token in command for token in ["schtasks", "runas", "token", "uac", "sudo"])
                )
            )

        elif "c2 beaconing" in signature.name.lower():
            interval = str(event.details.get("interval", "")).lower()
            message = str(event.details.get("message", "")).lower()
            small_transfer = (event.bytes_sent or 0) < 5000 and (event.bytes_received or 0) < 50000

            return (
                event.event_type == EventType.NETWORK_CONNECTION and
                event.is_external and
                small_transfer and
                (
                    interval in {"periodic", "regular", "beacon"} or
                    "beacon" in message or
                    event.details.get("repeat_count", 0) >= 3
                )
            )

        elif "data staging" in signature.name.lower():
            command = " ".join([
                str(event.details.get("command", "")),
                str(event.details.get("process_command_line", "")),
                event.process_name or "",
                event.file_path or str(event.details.get("file_path", ""))
            ]).lower()
            archive_tokens = [".zip", ".rar", ".7z", ".tar", ".gz", "compress", "archive", "winrar", "7z.exe"]

            return (
                event.event_type in {EventType.FILE_ACCESS, EventType.PROCESS_CREATION} and
                any(token in command for token in archive_tokens)
            )
        
        return False
    
    def _check_sequences(self, event: NormalizedEvent) -> List[BehaviorPattern]:
        """Check for suspicious sequences of events"""
        patterns = []
        
        if not event.source_ip:
            return patterns
        
        # Add event to sequence tracker
        seq_key = f"ip_{event.source_ip}"
        self.entity_sequences[seq_key].append((ensure_utc(event.timestamp), event))
        
        # Keep only last 50 events
        if len(self.entity_sequences[seq_key]) > 50:
            self.entity_sequences[seq_key].popleft()
        
        # Check for specific sequences
        sequence_patterns = self._detect_sequence_patterns(seq_key)
        patterns.extend(sequence_patterns)
        
        # Check for repetitions
        repetition_patterns = self._detect_repetitions(seq_key, event)
        patterns.extend(repetition_patterns)
        
        return patterns
    
    def _detect_sequence_patterns(self, seq_key: str) -> List[BehaviorPattern]:
        """Detect known malicious sequences"""
        patterns = []
        sequence = self.entity_sequences[seq_key]
        
        if len(sequence) < 2:
            return patterns
        
        # Example: Check for "Recon -> Exploitation" pattern
        # Looking for scanning followed by successful connection
        for i in range(len(sequence) - 1):
            time1, event1 = sequence[i]
            time2, event2 = sequence[i + 1]
            
            # Check time window (within 5 minutes)
            if (time2 - time1).total_seconds() > 300:
                continue
            
            # Pattern: Failed connections to multiple ports -> Successful connection
            if (event1.event_type == EventType.NETWORK_CONNECTION and
                event2.event_type == EventType.NETWORK_CONNECTION and
                event1.details.get("success") is False and
                event2.details.get("success") is True and
                event1.destination_ip == event2.destination_ip):
                
                pattern = BehaviorPattern(
                    pattern_id=f"seq_{uuid.uuid4().hex[:8]}",
                    pattern_type=BehaviorType.SEQUENCE_PATTERN,
                    description="Possible exploitation sequence: scanning followed by successful connection",
                    confidence=0.7,
                    detected_at=datetime_now_utc(),
                    entities=[event1.source_ip, event1.destination_ip],
                    events=[event1, event2],
                    severity=EventSeverity.HIGH,
                    metadata={
                        "sequence_type": "recon_exploitation",
                        "time_gap": (time2 - time1).total_seconds()
                    }
                )
                patterns.append(pattern)
        
        return patterns
    
    def _detect_repetitions(self, seq_key: str, current_event: NormalizedEvent) -> List[BehaviorPattern]:
        """Detect repetitive behaviors"""
        patterns = []
        sequence = self.entity_sequences[seq_key]
        
        # Count similar events in last hour
        one_hour_ago = datetime_now_utc() - timedelta(hours=1)
        similar_events = [
            e for _, e in sequence
            if e.event_type == current_event.event_type and
            e.destination_ip == current_event.destination_ip
        ]
        
        if len(similar_events) > 10:  # Threshold for repetition
            pattern = BehaviorPattern(
                pattern_id=f"rep_{uuid.uuid4().hex[:8]}",
                pattern_type=BehaviorType.REPETITION_DETECTION,
                description=f"Repetitive {current_event.event_type.value} activity detected",
                confidence=min(len(similar_events) / 20.0, 1.0),  # Cap at 1.0
                detected_at=datetime_now_utc(),
                entities=[current_event.source_ip] if current_event.source_ip else [],
                events=similar_events[-5:],  # Last 5 events
                severity=EventSeverity.MEDIUM if len(similar_events) < 20 else EventSeverity.HIGH,
                metadata={
                    "repetition_count": len(similar_events),
                    "event_type": current_event.event_type.value,
                    "time_window_hours": 1
                }
            )
            patterns.append(pattern)
        
        return patterns
    
    def _check_lateral_movement(self, cluster: EventCluster) -> List[BehaviorPattern]:
        """Check cluster for lateral movement patterns"""
        patterns = []
        
        # Extract unique source and destination IPs
        source_ips = set()
        dest_ips = set()
        
        # This would require access to event store
        # For now, return empty list
        return patterns
    
    def _check_escalation(self, cluster: EventCluster) -> List[BehaviorPattern]:
        """Check for privilege escalation patterns"""
        patterns = []
        # Implementation would check for sequences like:
        # 1. User login -> Admin command execution
        # 2. Service account -> System privilege
        return patterns
    
    def _check_exfiltration(self, cluster: EventCluster) -> List[BehaviorPattern]:
        """Check for data exfiltration patterns"""
        patterns = []
        # Implementation would check for:
        # 1. Large data transfers to external IPs
        # 2. Unusual protocols for data transfer
        # 3. Data compression before transfer
        return patterns
    
    def _extract_entities(self, event: NormalizedEvent) -> List[Tuple[str, str]]:
        """Extract entities from event for behavioral profiling"""
        entities = []
        
        if event.source_ip:
            entities.append(("ip", event.source_ip))
        if event.source_host:
            entities.append(("host", event.source_host))
        if event.username:
            entities.append(("user", event.username))
        
        return entities
    
    def _track_event(self, event: NormalizedEvent):
        """Track event in time-based indices"""
        if event.event_type == EventType.AUTHENTICATION and event.details.get("success") is False:
            self.auth_failures.add_event(event.timestamp, event.event_id)
        elif event.event_type == EventType.NETWORK_CONNECTION:
            self.network_connections.add_event(event.timestamp, event.event_id)
    
    def get_profiles(self, entity_type: Optional[str] = None) -> List[BehavioralProfile]:
        """Get behavioral profiles, optionally filtered by entity type"""
        if entity_type:
            return [p for (et, _), p in self.profiles.items() if et == entity_type]
        return list(self.profiles.values())
    
    def get_patterns(self, 
                    pattern_type: Optional[BehaviorType] = None,
                    limit: int = 100) -> List[BehaviorPattern]:
        """Get detected patterns, optionally filtered by type"""
        patterns = self.detected_patterns
        
        if pattern_type:
            patterns = [p for p in patterns if p.pattern_type == pattern_type]
        
        # Sort by detection time (newest first)
        patterns.sort(key=lambda p: p.detected_at, reverse=True)
        
        return patterns[:limit]
    
    def clear(self):
        """Clear all data from the engine"""
        self.profiles.clear()
        self.entity_sequences.clear()
        self.auth_failures.clear()
        self.network_connections.clear()
        self.detected_patterns.clear()
        
        self.stats = {
            "events_processed": 0,
            "profiles_created": 0,
            "profiles_updated": 0,
            "patterns_detected": 0,
            "anomalies_found": 0,
            "baseline_active": 0,
            "alerts_sent": 0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            **self.stats,
            "total_profiles": len(self.profiles),
            "active_sequences": len(self.entity_sequences),
            "total_patterns": len(self.detected_patterns)
        }
    
    def save_profiles(self, filepath: str):
        """Save behavioral profiles to file"""
        from pathlib import Path

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        profiles_data = {
            f"{key[0]}:{key[1]}": profile.to_dict()
            for key, profile in self.profiles.items()
        }
        
        with open(filepath, 'w') as f:
            json.dump(profiles_data, f, indent=2, default=str)
    
    def load_profiles(self, filepath: str):
        """Load behavioral profiles from file"""
        from pathlib import Path

        path = Path(filepath)
        if not path.exists():
            return

        with open(path, 'r') as f:
            profiles_data = json.load(f)

        loaded_profiles = {}
        for key, profile_data in profiles_data.items():
            try:
                profile = BehavioralProfile.from_dict(profile_data)
                loaded_profiles[(profile.entity_type, profile.entity_id)] = profile
            except Exception:
                # Keep loading other profiles if one record is damaged.
                continue

        self.profiles.update(loaded_profiles)
        self.stats["profiles_created"] = len(self.profiles)
