#!/usr/bin/env python3
"""
Test Signature Engine
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("Testing Signature Engine")
print("=" * 60)

try:
    from core.engines.signature_engine import SignatureEngine
    print("✓ Signature Engine imported successfully")
    
    # Create engine
    engine = SignatureEngine()
    
    # Get stats
    stats = engine.get_stats()
    print(f"✓ Engine created with {stats['total_rules']} rules")
    print(f"  YARA available: {stats['yara_available']}")
    
    # Test with a simple event
    test_event = {
        'event_type': 'authentication',
        'source_ip': '192.168.1.100',
        'details': {
            'success': False,
            'attempts': 6,
            'message': 'Failed login attempt'
        }
    }
    
    matches = engine.scan_event(test_event)
    print(f"✓ Test event scanned: {len(matches)} matches")
    
    for match in matches:
        print(f"  Rule: {match['rule_name']} ({match['severity']})")
    
    print("\n" + "=" * 60)
    print("✅ Signature Engine test completed!")
    print("=" * 60)
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()