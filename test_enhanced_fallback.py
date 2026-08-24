#!/usr/bin/env python3
"""
Test Enhanced Pipeline with Fallbacks
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("Testing Enhanced Pipeline with Fallbacks")
print("=" * 60)

try:
    # First, let's create necessary directories and files
    from pathlib import Path
    import json
    
    # Create data directories
    Path("data/threat_intel").mkdir(parents=True, exist_ok=True)
    Path("data/signatures").mkdir(parents=True, exist_ok=True)
    Path("data/ml_models").mkdir(parents=True, exist_ok=True)
    
    # Create local IOCs file
    iocs_file = Path("data/threat_intel/local_iocs.json")
    if not iocs_file.exists():
        iocs = [
            {
                "value": "192.168.1.100",
                "ioc_type": "ip",
                "threat_type": "malware_c2",
                "source": "local_observation",
                "confidence": 0.9,
                "first_seen": "2024-01-15T10:00:00Z",
                "last_seen": "2024-01-15T10:00:00Z",
                "description": "Internal C2 server observed during red team exercise",
                "tags": ["c2", "malware", "internal"]
            }
        ]
        with open(iocs_file, 'w') as f:
            json.dump(iocs, f, indent=2)
        print("✓ Created local IOCs file")
    
    # Create signature rules file
    rules_file = Path("data/signatures/network_attacks.json")
    if not rules_file.exists():
        rules = [
            {
                "id": "net_001",
                "name": "Port Scanning Detection",
                "description": "Detects port scanning activity",
                "severity": "medium",
                "category": "reconnaissance",
                "tags": ["scanning", "recon", "network"],
                "enabled": True,
                "logic": "any",
                "conditions": [
                    {
                        "type": "regex",
                        "field": "details.message",
                        "pattern": "port.*scan|scan.*port"
                    }
                ]
            }
        ]
        with open(rules_file, 'w') as f:
            json.dump(rules, f, indent=2)
        print("✓ Created signature rules file")
    
    # Now test the pipeline
    print("\n" + "-" * 60)
    print("Testing Pipeline Import")
    print("-" * 60)
    
    try:
        from core.pipeline import CyberEWPipeline
        print("✓ Pipeline imported successfully")
        
        # Create pipeline
        pipeline = CyberEWPipeline()
        print("✓ Pipeline created")
        
        # Run test
        print("\n" + "-" * 60)
        print("Running Pipeline Test")
        print("-" * 60)
        
        test_results = pipeline.test_pipeline()
        
        print("\n" + "=" * 60)
        print("TEST RESULTS:")
        print("=" * 60)
        print(f"Threat Intel Matches: {test_results.get('threat_intel_matches', 0)}")
        print(f"ML Anomalies Detected: {test_results.get('ml_anomalies_detected', 0)}")
        print(f"Signature Matches: {test_results.get('signature_matches', 0)}")
        print(f"Alerts Generated: {test_results.get('alerts_generated', 0)}")
        print(f"Events Processed: {test_results.get('events_processed', 0)}")
        
        # Check what worked
        print("\n" + "-" * 60)
        print("SYSTEM STATUS:")
        print("-" * 60)
        
        if test_results.get('threat_intel_matches', 0) > 0:
            print("✅ Threat Intelligence: WORKING")
        else:
            print("⚠️  Threat Intelligence: No matches (check IOCs)")
            
        if test_results.get('signature_matches', 0) > 0:
            print("✅ Signature Detection: WORKING")
        else:
            print("⚠️  Signature Detection: No matches (check rules)")
            
        if test_results.get('ml_anomalies_detected', 0) > 0:
            print("✅ ML Anomaly Detection: WORKING")
        else:
            print("ℹ️  ML Anomaly Detection: Using heuristic fallback")
        
        print("\n" + "=" * 60)
        print("✅ Enhanced pipeline test completed!")
        print("=" * 60)
        
    except ImportError as e:
        print(f"\n❌ Pipeline Import Error: {e}")
        print("\nMissing dependencies detected. Please install:")
        print("  pip install scikit-learn pandas numpy")
        print("\nOr the system will use fallback detection.")
        
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()