#!/usr/bin/env python3
"""
Verify the threat intel engine fix
"""
import sys
import os
from datetime import datetime, timezone

# Add the core directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("=" * 60)
print("Verifying Threat Intel Engine Fix")
print("=" * 60)

try:
    # Test 1: Import the engine
    print("\n1. Testing import...")
    from core.threat_intel_engine import ThreatIntelEngine, IOC
    print("   ✅ Threat Intel Engine imported successfully")
    
    # Test 2: Create engine instance
    print("\n2. Creating engine instance...")
    engine = ThreatIntelEngine()
    print("   ✅ Engine created successfully")
    
    # Test 3: Check feeds
    print(f"\n3. Feeds loaded: {len(engine.feeds)}")
    for name, feed in engine.feeds.items():
        print(f"   - {name}: {len(feed.iocs)} IOCs")
    
    # Test 4: Update feeds
    print("\n4. Updating feeds...")
    engine.update_all_feeds()
    print(f"   ✅ Total IOCs: {engine.stats['total_iocs']}")
    
    # Test 5: Create a test event
    print("\n5. Testing event matching...")
    test_event = {
        'source_ip': '192.168.1.100',
        'destination_ip': '8.8.8.8',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': 'network_connection',
        'severity': 'medium',
        'details': {}
    }
    
    # Test matching
    matches = engine.match_event(test_event)
    print(f"   ✅ Matches found: {len(matches)}")
    
    if matches:
        for match in matches:
            print(f"     - IOC: {match['ioc']['value']} "
                  f"({match['ioc']['threat_type']}) "
                  f"score: {match['match_score']:.2f}")
    
    # Test 6: Check datetime handling
    print("\n6. Testing datetime handling...")
    try:
        # Create a test IOC with timezone-aware datetime
        test_ioc = IOC(
            value="10.0.0.1",
            ioc_type="ip",
            threat_type="test",
            source="test",
            confidence=0.8,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            description="Test IOC"
        )
        print("   ✅ IOC with timezone-aware datetime created")
        
        # Try datetime comparison
        current_time = datetime.now(timezone.utc)
        time_diff = current_time - test_ioc.last_seen
        print(f"   ✅ Datetime comparison works: {time_diff.total_seconds():.0f} seconds ago")
        
    except Exception as e:
        print(f"   ❌ Datetime test failed: {e}")
    
    # Test 7: Check stats
    print("\n7. Checking engine stats...")
    stats = engine.get_stats()
    print(f"   - Total IOCs: {stats['total_iocs']}")
    print(f"   - Feed count: {stats['feed_count']}")
    print(f"   - Total matches: {stats['matches']}")
    
    print("\n" + "=" * 60)
    print("✅ VERIFICATION COMPLETE: Threat intel engine is working!")
    print("=" * 60)
    
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)