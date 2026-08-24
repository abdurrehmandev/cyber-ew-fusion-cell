#!/usr/bin/env python3
"""
Test and Fix Threat Intelligence
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("Testing and Fixing Threat Intelligence")
print("=" * 60)

try:
    from core.engines.threat_intel_engine import ThreatIntelEngine
    print("✓ Threat Intelligence Engine imported")
    
    # Create engine
    engine = ThreatIntelEngine()
    print("✓ Engine created")
    
    # Update feeds
    print("\nUpdating threat feeds...")
    engine.update_all_feeds()
    
    # Get stats
    stats = engine.get_stats()
    print(f"✓ Loaded {stats['total_iocs']} IOCs from feeds")
    
    # Create a test event that SHOULD match our local IOC
    test_event = {
        "event_id": "test_001",
        "event_type": "network_connection",
        "source_ip": "192.168.1.100",  # This is in our local IOCs!
        "destination_ip": "8.8.8.8",
        "timestamp": "2024-01-15T10:30:00Z",
        "details": {
            "query": "malicious-domain.com",  # This is also in our local IOCs!
            "port": 443,
            "protocol": "TCP"
        }
    }
    
    print("\n" + "-" * 60)
    print("Testing IOC Matching")
    print("-" * 60)
    
    # Test matching
    matches = engine.match_event(test_event)
    print(f"IOC Matches found: {len(matches)}")
    
    if matches:
        print("\n✅ IOC MATCHES:")
        for i, match in enumerate(matches, 1):
            ioc = match['ioc']
            print(f"  {i}. {ioc['value']} ({ioc['ioc_type']})")
            print(f"     Threat: {ioc['threat_type']}")
            print(f"     Confidence: {ioc['confidence']}")
            print(f"     Source: {ioc['source']}")
    else:
        print("\n❌ No IOC matches found.")
        print("\nChecking what IOCs are loaded...")
        
        # Check cache
        print(f"\nIOC Cache Contents:")
        for ioc_type, iocs in engine.ioc_cache.items():
            print(f"  {ioc_type}: {len(iocs)} IOCs")
            for ioc in iocs[:3]:  # Show first 3 of each type
                print(f"    - {ioc.value} ({ioc.threat_type})")
    
    # Test search functionality
    print("\n" + "-" * 60)
    print("Testing IOC Search")
    print("-" * 60)
    
    search_results = engine.search_iocs("192.168")
    print(f"Search for '192.168': {len(search_results)} results")
    
    # Add a test IOC
    print("\n" + "-" * 60)
    print("Testing Add Local IOC")
    print("-" * 60)
    
    new_ioc = {
        "value": "10.0.0.1",
        "ioc_type": "ip",
        "threat_type": "test_malware",
        "source": "test",
        "confidence": 0.8,
        "first_seen": "2024-01-15T10:00:00Z",
        "last_seen": "2024-01-15T10:00:00Z",
        "description": "Test IOC for verification",
        "tags": ["test", "malware"]
    }
    
    if engine.add_local_ioc(new_ioc):
        print("✅ Test IOC added successfully")
        
        # Verify it was added
        search_results = engine.search_iocs("10.0.0.1")
        print(f"Search for new IOC: {len(search_results)} results")
    else:
        print("❌ Failed to add test IOC")
    
    print("\n" + "=" * 60)
    print("✅ Threat Intelligence Test Complete!")
    print("=" * 60)
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()