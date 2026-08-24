# Save as: test_correlation_fix.py
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

print("Testing CorrelationEngine fix...")

try:
    from config.settings import CORRELATION_CONFIG
    from core.engines.correlation_engine import CorrelationEngine
    from core.models.event_models import NormalizedEvent, EventType, Entity, EntityType
    from datetime import datetime
    
    # Create engine
    corr_engine = CorrelationEngine(CORRELATION_CONFIG)
    print("✓ CorrelationEngine created successfully")
    
    # Test with an authentication event
    timestamp = datetime.utcnow()
    source_entity = Entity(
        id="test_source",
        type=EntityType.IP_ADDRESS,
        value="192.168.1.100"
    )
    
    # Test credential access rule with failed auth
    auth_event = NormalizedEvent(
        event_id="test_auth_event",
        timestamp=timestamp,
        event_type=EventType.AUTHENTICATION,
        source={"system": "test"},
        source_entity=source_entity,
        outcome="failed",
        details={"reason": "invalid_credentials"}
    )
    
    clusters = corr_engine.process_event(auth_event)
    print(f"✓ process_event() executed with failed auth")
    print(f"  Found {len(clusters)} clusters")
    
    # Test persistence rule with scheduled task
    task_event = NormalizedEvent(
        event_id="test_task_event",
        timestamp=timestamp,
        event_type=EventType.SCHEDULED_TASK,
        source={"system": "test"},
        source_entity=source_entity,
        details={"task_name": "suspicious_task"}
    )
    
    clusters2 = corr_engine.process_event(task_event)
    print(f"✓ process_event() executed with scheduled task")
    print(f"  Found {len(clusters2)} clusters")
    
    # Test lateral movement rule with successful auth
    success_auth_event = NormalizedEvent(
        event_id="test_success_auth",
        timestamp=timestamp,
        event_type=EventType.AUTHENTICATION,
        source={"system": "test"},
        source_entity=source_entity,
        outcome="success"
    )
    
    clusters3 = corr_engine.process_event(success_auth_event)
    print(f"✓ process_event() executed with successful auth")
    print(f"  Found {len(clusters3)} clusters")
    
    print("\n✅ CorrelationEngine test passed!")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()