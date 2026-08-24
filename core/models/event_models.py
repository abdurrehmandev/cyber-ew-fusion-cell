"""
Event data models for normalized events - FIXED VERSION
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from enum import Enum
import hashlib
import uuid

# Add these helper functions at the top
def ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime object is timezone-aware in UTC"""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    elif dt.tzinfo != timezone.utc:
        return dt.astimezone(timezone.utc)
    return dt

def datetime_now_utc() -> datetime:
    """Get current UTC datetime with timezone"""
    return datetime.now(timezone.utc)

class EventType(Enum):
    """Standardized event types"""
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    AUTHENTICATION = "authentication"
    FILE_ACCESS = "file_access"
    PROCESS_CREATION = "process_creation"
    REGISTRY_MODIFICATION = "registry_modification"
    SCHEDULED_TASK = "scheduled_task"
    THREAT_INTEL_MATCH = "threat_intel_match"
    USER_ACTIVITY = "user_activity"
    SYSTEM_ALERT = "system_alert"

class EventSeverity(Enum):
    """Event severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# ADDED: EntityType Enum
class EntityType(Enum):
    """Entity types for correlation and behavior analysis"""
    IP = "ip"
    IP_ADDRESS = "ip"
    HOST = "host"
    USER = "user"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    SERVICE = "service"

# ADDED: Entity class
@dataclass(init=False)
class Entity:
    """Represents an entity (IP, host, user) for correlation"""
    entity_type: EntityType
    value: str
    id: Optional[str]
    first_seen: datetime = field(default_factory=datetime_now_utc)
    last_seen: datetime = field(default_factory=datetime_now_utc)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        entity_type: Optional[EntityType] = None,
        value: str = "",
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **legacy_fields: Any
    ):
        """Create an entity.

        Supports both the current shape, Entity(entity_type=..., value=...),
        and older project scripts that used Entity(id=..., type=..., value=...).
        """
        if entity_type is None:
            entity_type = legacy_fields.pop("type", None)

        if isinstance(entity_type, str):
            entity_type = EntityType(entity_type)

        if entity_type is None:
            entity_type = EntityType.IP

        self.entity_type = entity_type
        self.value = value
        self.id = legacy_fields.pop("id", value)
        self.first_seen = first_seen or datetime_now_utc()
        self.last_seen = last_seen or datetime_now_utc()
        self.metadata = metadata or {}
        self.__post_init__()
    
    def __post_init__(self):
        """Ensure timestamps are UTC"""
        self.first_seen = ensure_utc(self.first_seen)
        self.last_seen = ensure_utc(self.last_seen)
    
    def update_last_seen(self, timestamp: datetime = None):
        """Update the last seen timestamp"""
        self.last_seen = ensure_utc(timestamp) if timestamp else datetime_now_utc()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entity to dictionary"""
        return {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "type": self.entity_type.value,
            "value": self.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "metadata": self.metadata
        }

    @property
    def type(self) -> EntityType:
        """Backward-compatible alias for older tests and scripts."""
        return self.entity_type


@dataclass
class NormalizedEvent:
    """
    Normalized event structure with UTC timestamp enforcement.
    
    This is the common format for all events flowing through the pipeline.
    """
    event_id: str
    event_type: EventType
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_host: Optional[str] = None
    destination_host: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    url: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    severity: EventSeverity = EventSeverity.INFO
    confidence: float = 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    source_id: Optional[str] = None
    raw_event: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)
    source: Optional[Dict[str, Any]] = None
    source_entity: Optional[Entity] = None
    destination_entity: Optional[Entity] = None
    
    def __post_init__(self):
        """Ensure timestamp is timezone-aware in UTC"""
        # Generate event ID if not provided
        if not self.event_id:
            self.event_id = f"event_{uuid.uuid4().hex[:8]}"
        
        # Ensure timestamp is in UTC
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        elif self.timestamp.tzinfo != timezone.utc:
            self.timestamp = self.timestamp.astimezone(timezone.utc)
        
        # Ensure severity is Enum
        if not isinstance(self.severity, EventSeverity):
            try:
                self.severity = EventSeverity(self.severity)
            except ValueError:
                self.severity = EventSeverity.INFO
        
        # Ensure confidence is between 0 and 1
        self.confidence = max(0.0, min(1.0, self.confidence))

        # Backward compatibility for older scripts that pass source/destination
        # entities instead of flattened source_ip/source_host/username fields.
        if self.source_entity:
            if self.source_entity.entity_type == EntityType.IP and not self.source_ip:
                self.source_ip = self.source_entity.value
            elif self.source_entity.entity_type == EntityType.HOST and not self.source_host:
                self.source_host = self.source_entity.value
            elif self.source_entity.entity_type == EntityType.USER and not self.username:
                self.username = self.source_entity.value

        if self.destination_entity:
            if self.destination_entity.entity_type == EntityType.IP and not self.destination_ip:
                self.destination_ip = self.destination_entity.value
            elif self.destination_entity.entity_type == EntityType.HOST and not self.destination_host:
                self.destination_host = self.destination_entity.value
    
    @property
    def is_external(self) -> bool:
        """Check if event involves external IP"""
        if not self.source_ip or not self.destination_ip:
            return False
        
        internal_prefixes = ["192.168.", "10.", "172.16.", "172.17.", "172.18.", 
                           "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                           "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                           "172.29.", "172.30.", "172.31.", "127.0.0.1"]
        
        src_internal = any(self.source_ip.startswith(prefix) for prefix in internal_prefixes)
        dst_internal = any(self.destination_ip.startswith(prefix) for prefix in internal_prefixes)
        
        return not (src_internal and dst_internal)
    
    @property
    def hash_id(self) -> str:
        """Generate hash-based ID for deduplication"""
        hash_str = f"{self.event_type.value}_{self.timestamp.isoformat()}"
        
        if self.source_ip:
            hash_str += f"_{self.source_ip}"
        if self.destination_ip:
            hash_str += f"_{self.destination_ip}"
        if self.username:
            hash_str += f"_{self.username}"
        
        return hashlib.md5(hash_str.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "event_id": self.event_id,
            "hash_id": self.hash_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_host": self.source_host,
            "destination_host": self.destination_host,
            "username": self.username,
            "process_name": self.process_name,
            "file_path": self.file_path,
            "url": self.url,
            "port": self.port,
            "protocol": self.protocol,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "details": self.details,
            "source_id": self.source_id,
            "tags": self.tags,
            "source": self.source,
            "source_entity": self.source_entity.to_dict() if self.source_entity else None,
            "destination_entity": self.destination_entity.to_dict() if self.destination_entity else None,
            "is_external": self.is_external
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NormalizedEvent':
        """Create event from dictionary"""
        # Convert string timestamp back to datetime
        if isinstance(data.get('timestamp'), str):
            from dateutil.parser import isoparse
            data['timestamp'] = isoparse(data['timestamp'])
        
        # Convert string event_type to Enum
        if isinstance(data.get('event_type'), str):
            data['event_type'] = EventType(data['event_type'])
        
        # Convert string severity to Enum
        if isinstance(data.get('severity'), str):
            data['severity'] = EventSeverity(data['severity'])

        # Convert serialized entities back to Entity objects
        if isinstance(data.get('source_entity'), dict):
            entity_data = data['source_entity']
            data['source_entity'] = Entity(
                id=entity_data.get('id'),
                entity_type=entity_data.get('entity_type') or entity_data.get('type'),
                value=entity_data.get('value', ''),
                metadata=entity_data.get('metadata', {})
            )

        if isinstance(data.get('destination_entity'), dict):
            entity_data = data['destination_entity']
            data['destination_entity'] = Entity(
                id=entity_data.get('id'),
                entity_type=entity_data.get('entity_type') or entity_data.get('type'),
                value=entity_data.get('value', ''),
                metadata=entity_data.get('metadata', {})
            )
        
        return cls(**data)

@dataclass
class EventCluster:
    """Cluster of correlated events"""
    cluster_id: str
    event_ids: List[str]
    correlation_type: str
    confidence: float
    timestamp: datetime
    entities: Dict[str, List[str]]
    summary: Optional[str] = None
    
    def __post_init__(self):
        """Ensure timestamp is UTC"""
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        elif self.timestamp.tzinfo != timezone.utc:
            self.timestamp = self.timestamp.astimezone(timezone.utc)
    
    def add_event(self, event_id: str):
        """Add event to cluster"""
        if event_id not in self.event_ids:
            self.event_ids.append(event_id)
    
    def get_entity_count(self) -> int:
        """Get number of unique entities"""
        return sum(len(entities) for entities in self.entities.values())
