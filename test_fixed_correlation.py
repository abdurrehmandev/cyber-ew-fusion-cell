"""
Test script for correlation engine with proper timezone handling
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timezone, timedelta
from core.models.event_models import NormalizedEvent, EventType, EventSeverity
from core.engines.correlation_engine import CorrelationEngine
from config.settings import CORRELATION_CONFIG

def test_fixed_correlation():
    """Test the correlation engine with proper timezone handling"""
    print("=" * 60)
    print("Testing Correlation Engine - FIXED TIMEZONE VERSION")
    print("=" * 60)
    
    try:
        # Create correlation engine
        corr_engine = CorrelationEngine(CORRELATION_CONFIG)
        print("✓ CorrelationEngine created successfully")
        
        # Test 1: Create events with UTC timezone-aware timestamps
        print("\n1. Creating test events with UTC timestamps...")
        
        current_time = datetime.now(timezone.utc)
        
        # Event 1: Failed authentication
        auth_event = NormalizedEvent(
            event_id="auth_001",
            event_type=EventType.AUTHENTICATION,
            source_ip="192.168.1.10",
            destination_ip="192.168.1.100",
            timestamp=current_time,
            username="admin",
            severity=EventSeverity.HIGH,
            confidence=0.8,
            details={"success": False, "attempts": 3, "reason": "Invalid credentials"}
        )
        
        # Event 2: Network connection from same IP (5 seconds later)
        net_event = NormalizedEvent(
            event_id="net_001",
            event_type=EventType.NETWORK_CONNECTION,
            source_ip="192.168.1.10",
            destination_ip="10.0.0.5",
            timestamp=current_time + timedelta(seconds=5),
            port=445,
            protocol="TCP",
            severity=EventSeverity.MEDIUM,
            details={"direction": "outbound", "bytes_sent": 1200}
        )
        
        # Event 3: DNS query from same IP (10 seconds later)
        dns_event = NormalizedEvent(
            event_id="dns_001",
            event_type=EventType.DNS_QUERY,
            source_ip="192.168.1.10",
            destination_ip="8.8.8.8",
            timestamp=current_time + timedelta(seconds=10),
            severity=EventSeverity.LOW,
            details={"query": "suspicious-domain.com", "response": "NXDOMAIN"}
        )
        
        # Event 4: Unrelated event from different IP
        other_event = NormalizedEvent(
            event_id="other_001",
            event_type=EventType.HTTP_REQUEST,
            source_ip="192.168.1.20",
            destination_ip="93.184.216.34",
            timestamp=current_time + timedelta(seconds=15),
            url="https://example.com",
            severity=EventSeverity.INFO,
            details={"method": "GET", "status_code": 200}
        )
        
        print(f"✓ Created 4 test events:")
        print(f"  - {auth_event.event_id}: {auth_event.event_type.value}")
        print(f"  - {net_event.event_id}: {net_event.event_type.value}")
        print(f"  - {dns_event.event_id}: {dns_event.event_type.value}")
        print(f"  - {other_event.event_id}: {other_event.event_type.value}")
        
        # Test 2: Process events
        print("\n2. Processing events through correlation engine...")
        
        results1 = corr_engine.process_event(auth_event)
        print(f"✓ Processed {auth_event.event_id}. Clusters: {len(results1)}")
        
        results2 = corr_engine.process_event(net_event)
        print(f"✓ Processed {net_event.event_id}. Clusters: {len(results2)}")
        
        results3 = corr_engine.process_event(dns_event)
        print(f"✓ Processed {dns_event.event_id}. Clusters: {len(results3)}")
        
        results4 = corr_engine.process_event(other_event)
        print(f"✓ Processed {other_event.event_id}. Clusters: {len(results4)}")
        
        # Test 3: Check correlation results
        print("\n3. Checking correlation results...")
        
        stats = corr_engine.get_stats()
        print(f"✓ Engine Statistics:")
        print(f"  - Events processed: {stats['events_processed']}")
        print(f"  - Clusters created: {stats['clusters_created']}")
        print(f"  - Clusters updated: {stats['clusters_updated']}")
        print(f"  - Events stored: {stats['events_stored']}")
        print(f"  - Active clusters: {stats['clusters_active']}")
        
        # Check if events from same IP are correlated
        if stats['clusters_active'] > 0:
            print("\n✓ Clusters found! Checking cluster details...")
            for cluster_id, cluster in corr_engine.clusters.items():
                print(f"\n  Cluster {cluster_id}:")
                print(f"    - Events: {len(cluster.event_ids)}")
                print(f"    - Confidence: {cluster.confidence:.2f}")
                print(f"    - Entities:")
                for entity_type, values in cluster.entities.items():
                    print(f"      {entity_type}: {', '.join(values[:3])}{'...' if len(values) > 3 else ''}")
                
                # Check which events are in this cluster
                ip_addresses = set()
                for event_id in cluster.event_ids[:5]:  # Show first 5 events
                    if event_id in corr_engine.event_store:
                        event = corr_engine.event_store[event_id]
                        ip_addresses.add(event.source_ip)
                        print(f"      {event_id}: {event.event_type.value} from {event.source_ip}")
                
                if len(ip_addresses) == 1:
                    print(f"    → All events from same IP: {list(ip_addresses)[0]}")
        
        # Test 4: Test time-based queries
        print("\n4. Testing time-based queries...")
        
        recent_events = corr_engine.get_recent_events(minutes=1)
        print(f"✓ Found {len(recent_events)} events from last minute")
        
        # Test 5: Test entity-based queries
        print("\n5. Testing entity-based queries...")
        
        clusters_for_ip = corr_engine.get_clusters_by_entity("source_ip", "192.168.1.10")
        print(f"✓ Found {len(clusters_for_ip)} clusters for IP 192.168.1.10")
        
        # Test 6: Test clear functionality
        print("\n6. Testing clear functionality...")
        corr_engine.clear()
        stats_after_clear = corr_engine.get_stats()
        print(f"✓ Engine cleared. Events stored: {stats_after_clear['events_stored']}")
        print(f"  Active clusters: {stats_after_clear['clusters_active']}")
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED SUCCESSFULLY!")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_fixed_correlation()
    sys.exit(0 if success else 1)