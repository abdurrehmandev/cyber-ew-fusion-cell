#!/usr/bin/env python3
"""
Simple test for Cyber-EW Fusion Cell fixes
"""

import sys
import os

# Add the core directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

# Test the fixed ML Engine
print("Testing Fixed ML Engine...")
try:
    from engines.fixed_ml_engine import FixedMLEngine
    ml_engine = FixedMLEngine()
    print("✓ ML Engine loaded successfully")
    
    # Test feature extraction
    test_event = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 44324,
        'dst_port': 80,
        'protocol': 'TCP',
        'packet_size': 512,
        'timestamp': '2024-01-01 12:00:00'
    }
    
    features = ml_engine.extract_features(test_event)
    print(f"✓ Feature extraction works. Got {len(features)} features: {features}")
    
except Exception as e:
    print(f"✗ ML Engine error: {e}")

print("\nTesting Fixed Signature Engine...")
try:
    from engines.fixed_signature_engine import FixedSignatureEngine
    sig_engine = FixedSignatureEngine()
    print("✓ Signature Engine loaded successfully")
    
    # Test signature matching
    test_event = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'payload': 'malicious_pattern_here',
        'protocol': 'TCP'
    }
    
    matches = sig_engine.match_signatures(test_event)
    print(f"✓ Signature matching works. Found {len(matches)} matches")
    
except Exception as e:
    print(f"✗ Signature Engine error: {e}")

print("\n✓ All tests completed!")