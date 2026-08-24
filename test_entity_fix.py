# Save as: test_entity_fix.py
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

print("Testing Entity.to_dict() fix...")

try:
    from core.models.event_models import Entity, EntityType, NormalizedEvent, EventType
    from datetime import datetime
    
    # Test Entity.to_dict()
    entity = Entity(
        id="test_entity",
        type=EntityType.IP_ADDRESS,
        value="192.168.1.100"
    )
    
    entity_dict = entity.to_dict()
    print(f"✓ Entity.to_dict() works: {entity_dict}")
    
    # Test NormalizedEvent.to_dict()
    timestamp = datetime.utcnow()
    source_entity = Entity(
        id="test_source",
        type=EntityType.IP_ADDRESS,
        value="192.168.1.100"
    )
    
    event = NormalizedEvent(
        event_id="test_event",
        timestamp=timestamp,
        event_type=EventType.NETWORK_CONNECTION,
        source={"system": "test"},
        source_entity=source_entity
    )
    
    event_dict = event.to_dict()
    print(f"✓ NormalizedEvent.to_dict() works: Event ID = {event_dict['event_id']}")
    print(f"✓ Source entity in dict: {event_dict['source_entity']}")
    
    # Test round-trip serialization
    event_from_dict = NormalizedEvent.from_dict(event_dict)
    print(f"✓ Round-trip serialization works: {event_from_dict.event_id}")
    
    print("\n✅ Entity serialization fix works!")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()