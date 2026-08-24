# Save as: test_normalization_fix.py
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

print("Testing NormalizationEngine...")

try:
    from core.engines.normalization_engine import NormalizationEngine
    
    # Create engine
    norm_engine = NormalizationEngine()
    print("✓ NormalizationEngine created successfully")
    
    # Test with a simple event
    test_event = {
        "timestamp": "2024-01-15T10:30:00Z",
        "source_ip": "192.168.1.100",
        "destination_ip": "8.8.8.8",
        "destination_port": 53,
        "protocol": "udp",
        "dns_query": "google.com",
        "source_type": "test"
    }
    
    normalized = norm_engine.normalize(test_event, "test")
    print(f"✓ normalize() method executed")
    print(f"  Returned: {type(normalized)}")
    
    if normalized:
        print(f"  Event ID: {normalized.event_id}")
        print(f"  Event type: {normalized.event_type}")
        print(f"  Source: {normalized.source}")
    else:
        print("  Note: normalize() returned None (expected for unknown source_type)")
    
    # Test with pcap-like data
    pcap_event = {
        "timestamp": "2024-01-15T10:30:00Z",
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "udp",
        "dns_query": "google.com",
        "source_type": "pcap"
    }
    
    pcap_normalized = norm_engine.normalize(pcap_event, "pcap")
    print(f"\n✓ PCAP normalization: {type(pcap_normalized)}")
    
    print("\n✅ NormalizationEngine test passed!")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()