"""
Test script for Behavior Engine
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timezone, timedelta
from core.models.event_models import NormalizedEvent, EventType, EventSeverity
from core.models.behavior_models import BehavioralProfile, BehaviorPattern, BehaviorType, BaselineStatus
from core.engines.behavior_engine import BehaviorEngine
from config.settings import BEHAVIOR_CONFIG

def test_behavior_engine():
    """Test the Behavior Engine with various scenarios"""
    print("=" * 70)
    print("Testing Behavior Engine - Cyber-EW Fusion Cell")
    print("=" * 70)
    
    try:
        # Create behavior engine
        behavior_engine = BehaviorEngine(BEHAVIOR_CONFIG)
        print("✓ BehaviorEngine created successfully")
        
        # Test 1: Create normal baseline events
        print("\n1. Creating baseline events for normal behavior...")
        
        current_time = datetime.now(timezone.utc)
        baseline_time = current_time - timedelta(days=35)  # 35 days ago for baseline
        
        # Create normal user activity during work hours
        for i in range(50):  # 50 normal events
            event_time = baseline_time + timedelta(hours=i, minutes=i%60)
            
            normal_event = NormalizedEvent(
                event_id=f"baseline_{i:03d}",
                event_type=EventType.NETWORK_CONNECTION,
                source_ip="192.168.1.100",
                destination_ip="10.0.0.1",
                timestamp=event_time,
                port=443,
                protocol="TCP",
                severity=EventSeverity.INFO,
                details={"success": True, "bytes_sent": 1500}
            )
            
            behavior_engine.process_event(normal_event)
        
        print(f"✓ Processed 50 baseline events for IP 192.168.1.100")
        
        # Test 2: Test anomaly detection (unusual hour)
        print("\n2. Testing anomaly detection (activity at unusual hour)...")
        
        # Event at 3 AM (unusual for typical work patterns)
        unusual_event = NormalizedEvent(
            event_id="anomaly_001",
            event_type=EventType.NETWORK_CONNECTION,
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            timestamp=current_time.replace(hour=3, minute=0),  # 3 AM
            port=53,
            protocol="UDP",
            severity=EventSeverity.INFO,
            details={"success": True}
        )
        
        patterns1 = behavior_engine.process_event(unusual_event)
        print(f"✓ Processed unusual hour event. Patterns detected: {len(patterns1)}")
        
        if patterns1:
            for pattern in patterns1:
                print(f"  - {pattern.description}")
                print(f"    Confidence: {pattern.confidence:.2f}, Severity: {pattern.severity.value}")
        
        # Test 3: Test credential stuffing detection
        print("\n3. Testing credential stuffing detection...")
        
        # Multiple failed authentication attempts
        for i in range(15):  # 15 failed attempts (over threshold)
            auth_event = NormalizedEvent(
                event_id=f"auth_fail_{i:03d}",
                event_type=EventType.AUTHENTICATION,
                source_ip="192.168.1.50",
                username="administrator",
                timestamp=current_time + timedelta(seconds=i*5),  # Every 5 seconds
                severity=EventSeverity.HIGH,
                details={"success": False, "reason": "Invalid password", "attempts": i+1}
            )
            
            patterns2 = behavior_engine.process_event(auth_event)
            if patterns2:
                print(f"✓ Credential stuffing detected at attempt {i+1}!")
                for pattern in patterns2:
                    print(f"  - {pattern.description}")
                    print(f"    Mitigation: {pattern.metadata.get('mitigation', 'N/A')}")
                break
        
        # Test 4: Test lateral movement detection
        print("\n4. Testing lateral movement detection...")
        
        # Sequence: Multiple failed SMB connections to different hosts
        target_hosts = ["192.168.1.101", "192.168.1.102", "192.168.1.103", "192.168.1.104"]
        
        for i, target in enumerate(target_hosts):
            smb_event = NormalizedEvent(
                event_id=f"lateral_{i:03d}",
                event_type=EventType.NETWORK_CONNECTION,
                source_ip="192.168.1.200",  # Attacker IP
                destination_ip=target,
                timestamp=current_time + timedelta(seconds=10 + i*2),
                port=445,
                protocol="TCP",
                severity=EventSeverity.MEDIUM,
                details={"success": False, "error": "Connection refused"}
            )
            
            patterns3 = behavior_engine.process_event(smb_event)
        
        # Process one more to trigger sequence detection
        if target_hosts:
            final_smb = NormalizedEvent(
                event_id="lateral_success",
                event_type=EventType.NETWORK_CONNECTION,
                source_ip="192.168.1.200",
                destination_ip=target_hosts[0],  # Back to first target
                timestamp=current_time + timedelta(seconds=30),
                port=445,
                protocol="TCP",
                severity=EventSeverity.HIGH,
                details={"success": True, "session_id": "SMB-12345"}
            )
            
            patterns4 = behavior_engine.process_event(final_smb)
            if patterns4:
                print("✓ Lateral movement pattern detected!")
                for pattern in patterns4:
                    print(f"  - {pattern.description}")
                    print(f"    Entities involved: {', '.join(pattern.entities)}")
        
        # Test 5: Check engine statistics and profiles
        print("\n5. Checking engine statistics...")
        
        stats = behavior_engine.get_stats()
        print(f"✓ Engine Statistics:")
        print(f"  - Events processed: {stats['events_processed']}")
        print(f"  - Profiles created: {stats['profiles_created']}")
        print(f"  - Patterns detected: {stats['patterns_detected']}")
        print(f"  - Anomalies found: {stats['anomalies_found']}")
        print(f"  - Active baselines: {stats['baseline_active']}")
        print(f"  - Total profiles: {stats['total_profiles']}")
        
        # Show some profiles
        profiles = behavior_engine.get_profiles(entity_type="ip")
        if profiles:
            print(f"\n✓ Sample behavioral profile for IP {profiles[0].entity_id}:")
            profile_dict = profiles[0].to_dict()
            print(f"  - Baseline status: {profile_dict['baseline_status']}")
            print(f"  - Period: {profile_dict['period_start'][:10]} to {profile_dict['period_end'][:10]}")
            print(f"  - Event types tracked: {len(profile_dict['event_frequencies'])}")
        
        # Test 6: Get detected patterns
        print("\n6. Reviewing detected patterns...")
        
        all_patterns = behavior_engine.get_patterns(limit=10)
        if all_patterns:
            print(f"✓ Found {len(all_patterns)} patterns (showing {min(5, len(all_patterns))}):")
            for i, pattern in enumerate(all_patterns[:5]):
                print(f"\n  Pattern {i+1}:")
                print(f"    Type: {pattern.pattern_type.value}")
                print(f"    Description: {pattern.description[:60]}...")
                print(f"    Confidence: {pattern.confidence:.2f}")
                print(f"    Severity: {pattern.severity.value}")
                print(f"    Detected: {pattern.detected_at.strftime('%H:%M:%S')}")
        else:
            print("  No patterns detected yet (may need more events)")
        
        # Test 7: Test clear functionality
        print("\n7. Testing clear functionality...")
        behavior_engine.clear()
        stats_after = behavior_engine.get_stats()
        print(f"✓ Engine cleared successfully")
        print(f"  Events processed: {stats_after['events_processed']}")
        print(f"  Patterns stored: {stats_after['total_patterns']}")
        
        print("\n" + "=" * 70)
        print("✅ BEHAVIOR ENGINE TEST COMPLETED SUCCESSFULLY!")
        print("=" * 70)
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_behavior_engine()
    sys.exit(0 if success else 1)