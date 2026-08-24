#!/usr/bin/env python3
"""
Quick integration test for Cyber-EW Fusion Cell
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timezone, timedelta

print("Cyber-EW Fusion Cell - Quick Integration Test")
print("=" * 60)

try:
    # Import modules
    from core.models.event_models import NormalizedEvent, EventType, EventSeverity
    from core.engines.correlation_engine import CorrelationEngine
    from core.engines.behavior_engine import BehaviorEngine
    from config.settings import CORRELATION_CONFIG, BEHAVIOR_CONFIG
    
    print("✓ Modules imported successfully")
    
    # Create engines
    corr_engine = CorrelationEngine(CORRELATION_CONFIG)
    behavior_engine = BehaviorEngine(BEHAVIOR_CONFIG)

    print("✓ Engines created")

    # Create test events
    events = []
    current_time = datetime.now(timezone.utc)

    # Event 1: Normal DNS query
    event1 = NormalizedEvent(
        event_id="test_dns_1",
        event_type=EventType.DNS_QUERY,
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        timestamp=current_time - timedelta(seconds=30),
        port=53,
        protocol="UDP",
        severity=EventSeverity.INFO,
        details={"query": "google.com", "response": "success"}
    )
    events.append(event1)

    # Event 2: Failed authentication
    event2 = NormalizedEvent(
        event_id="test_auth_1",
        event_type=EventType.AUTHENTICATION,
        source_ip="192.168.1.50",
        username="admin",
        timestamp=current_time - timedelta(seconds=20),
        severity=EventSeverity.HIGH,
        details={"success": False, "reason": "Invalid password", "attempts": 1}
    )
    events.append(event2)

    # Event 3: Network connection (same source as auth)
    event3 = NormalizedEvent(
        event_id="test_net_1",
        event_type=EventType.NETWORK_CONNECTION,
        source_ip="192.168.1.50",
        destination_ip="192.168.1.101",
        timestamp=current_time - timedelta(seconds=10),
        port=445,
        protocol="TCP",
        severity=EventSeverity.MEDIUM,
        details={"success": False, "error": "Connection refused"}
    )
    events.append(event3)

    print(f"✓ Created {len(events)} test events")

    # Process through correlation engine
    print("\nProcessing through Correlation Engine:")
    for event in events:
        clusters = corr_engine.process_event(event)
        print(f"  {event.event_id}: {len(clusters)} clusters")

    # Get correlation stats
    corr_stats = {}
    if hasattr(corr_engine, 'get_stats'):
        corr_stats = corr_engine.get_stats()
        print(f"  Correlation stats: {corr_stats.get('events_processed', 0)} events, "
              f"{corr_stats.get('clusters_active', 0)} clusters")
    else:
        print("  Correlation stats: Method 'get_stats' not available")

    # Process through behavior engine
    print("\nProcessing through Behavior Engine:")
    for event in events:
        patterns = behavior_engine.process_event(event)
        if patterns:
            print(f"  {event.event_id}: {len(patterns)} patterns detected")
            for pattern in patterns[:2]:  # Show first 2
                pattern_type = getattr(pattern, 'pattern_type', 'unknown')
                if hasattr(pattern_type, 'value'):
                    pattern_type = pattern_type.value
                
                description = getattr(pattern, 'description', 'No description')
                print(f"    - {pattern_type}: {description[:60]}...")

    # Get behavior stats
    behavior_stats = {}
    if hasattr(behavior_engine, 'get_stats'):
        behavior_stats = behavior_engine.get_stats()
        print(f"  Behavior stats: {behavior_stats.get('events_processed', 0)} events, "
              f"{behavior_stats.get('patterns_detected', 0)} patterns")
    else:
        print("  Behavior stats: Method 'get_stats' not available")

    print("\n" + "=" * 60)
    print("✅ INTEGRATION TEST COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    
    sys.exit(0)

except ImportError as e:
    print(f"\n❌ IMPORT ERROR: {e}")
    print("Make sure all modules are properly installed and in the Python path.")
    sys.exit(1)
except Exception as e:
    print(f"\n❌ INTEGRATION TEST FAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)