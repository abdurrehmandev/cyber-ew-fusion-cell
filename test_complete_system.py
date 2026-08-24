#!/usr/bin/env python3
"""
Complete System Test for Cyber-EW Fusion Cell
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("COMPLETE SYSTEM TEST - Cyber-EW Fusion Cell")
print("=" * 60)

# Check dependencies
print("\n" + "-" * 60)
print("Checking Dependencies")
print("-" * 60)

def check_dependency(module_name, import_name=None):
    """Check if a module is available"""
    import_name = import_name or module_name
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False

print("------------------------------------------------------------")
print("Checking Dependencies")
print("------------------------------------------------------------")

# Check sklearn correctly
try:
    import sklearn
    print("OK scikit-learn: Installed (version: {})".format(sklearn.__version__))
except ImportError:
    print("WARNING scikit-learn: NOT installed (ML features disabled)")

# Check other dependencies
deps = [
    ('pandas', 'pandas'),
    ('numpy', 'numpy'),
    ('yara', 'yara'),
    ('requests', 'requests'),
    ('dateutil', 'python-dateutil')
]

for display_name, import_name in deps:
    if check_dependency(import_name):
        print("OK {}: Installed".format(display_name))
    else:
        print("WARNING {}: NOT installed".format(display_name))

# Create necessary directories
from pathlib import Path
import json

print("\n" + "-" * 60)
print("Setting Up Test Environment")
print("-" * 60)

# Create all required directories
dirs = [
    "data/threat_intel",
    "data/signatures", 
    "data/ml_models",
    "data/inputs/logs",
    "data/inputs/pcaps",
    "logs"
]

for dir_path in dirs:
    Path(dir_path).mkdir(parents=True, exist_ok=True)
    print(f"✓ Created directory: {dir_path}")

# Create enhanced test IOCs
iocs_file = Path("data/threat_intel/local_iocs.json")
enhanced_iocs = [
    {
        "value": "192.168.1.100",
        "ioc_type": "ip",
        "threat_type": "malware_c2",
        "source": "local_observation",
        "confidence": 0.95,
        "first_seen": "2024-01-15T10:00:00Z",
        "last_seen": "2024-01-15T10:00:00Z",
        "description": "Internal C2 server - HIGH PRIORITY",
        "tags": ["c2", "malware", "internal", "critical"]
    },
    {
        "value": "malicious-domain.com",
        "ioc_type": "domain",
        "threat_type": "phishing",
        "source": "threat_feed",
        "confidence": 0.85,
        "first_seen": "2024-01-14T15:30:00Z",
        "last_seen": "2024-01-15T09:45:00Z",
        "description": "Active phishing campaign domain",
        "tags": ["phishing", "credential_theft", "active"]
    },
    {
        "value": "e99a18c428cb38d5f260853678922e03",
        "ioc_type": "hash_md5",
        "threat_type": "ransomware",
        "source": "virus_total",
        "confidence": 0.90,
        "first_seen": "2024-01-13T08:00:00Z",
        "last_seen": "2024-01-14T12:00:00Z",
        "description": "LockBit 3.0 ransomware sample",
        "tags": ["ransomware", "lockbit", "file_encryptor"]
    }
]

with open(iocs_file, 'w') as f:
    json.dump(enhanced_iocs, f, indent=2)
print("✓ Created enhanced IOCs file")

# Create enhanced signature rules
rules_file = Path("data/signatures/enhanced_rules.json")
enhanced_rules = [
    {
        "id": "rule_high_001",
        "name": "High Severity Brute Force",
        "description": "Multiple failed authentication attempts with high count",
        "severity": "high",
        "category": "credential_access",
        "tags": ["brute_force", "authentication", "critical"],
        "enabled": True,
        "logic": "all",
        "conditions": [
            {
                "type": "equals",
                "field": "event_type",
                "value": "authentication"
            },
            {
                "type": "regex",
                "field": "details.success",
                "pattern": "false|0|failed"
            },
            {
                "type": "greater_than",
                "field": "details.attempts",
                "value": "5"
            }
        ]
    },
    {
        "id": "rule_med_001",
        "name": "Suspicious Network Activity",
        "description": "Unusual network connections to known bad ports",
        "severity": "medium",
        "category": "network",
        "tags": ["scanning", "reconnaissance", "suspicious"],
        "enabled": True,
        "logic": "any",
        "conditions": [
            {
                "type": "in_list",
                "field": "port",
                "values": ["4444", "31337", "6667", "12345"]
            },
            {
                "type": "regex",
                "field": "details.message",
                "pattern": "port.*scan|scan.*port"
            }
        ]
    }
]

with open(rules_file, 'w') as f:
    json.dump(enhanced_rules, f, indent=2)
print("✓ Created enhanced signature rules")

print("\n" + "-" * 60)
print("Testing Complete Pipeline")
print("-" * 60)

try:
    from core.pipeline import CyberEWPipeline
    
    # Create pipeline
    pipeline = CyberEWPipeline()
    print("✓ Pipeline created successfully")
    
    # Get initial stats
    initial_stats = pipeline.get_stats()
    print(f"✓ Initial stats gathered")
    
    # Run comprehensive test
    print("\nRunning comprehensive pipeline test...")
    test_results = pipeline.test_pipeline()
    
    print("\n" + "=" * 60)
    print("COMPREHENSIVE TEST RESULTS")
    print("=" * 60)
    
    print(f"\n📊 Detection Results:")
    print(f"  Events Processed: {test_results.get('events_processed', 0)}")
    print(f"  Threat Intel Matches: {test_results.get('threat_intel_matches', 0)}")
    print(f"  ML Anomalies Detected: {test_results.get('ml_anomalies_detected', 0)}")
    print(f"  Signature Matches: {test_results.get('signature_matches', 0)}")
    print(f"  Alerts Generated: {test_results.get('alerts_generated', 0)}")
    
    print(f"\n🎯 Threat Scores:")
    if test_results.get('threat_scores'):
        for score in test_results['threat_scores']:
            print(f"  - {score['level'].upper()}: {score['score']:.2f} (confidence: {score['confidence']:.2f})")
    
    print(f"\n🔍 Detection Sources:")
    sources = []
    if test_results.get('threat_intel_matches', 0) > 0:
        sources.append("Threat Intelligence")
    if test_results.get('ml_anomalies_detected', 0) > 0:
        sources.append("ML Anomaly Detection")
    if test_results.get('signature_matches', 0) > 0:
        sources.append("Signature Detection")
    
    if sources:
        print(f"  Active sources: {', '.join(sources)}")
    else:
        print("  No detection sources active")
    
    # Test pipeline modes
    print("\n" + "-" * 60)
    print("Testing Pipeline Modes")
    print("-" * 60)
    
    # Test stats mode
    stats = pipeline.get_statistics()
    print(f"✓ Statistics retrieved: {len(stats)} metrics")
    
    # Test recent alerts
    recent_alerts = pipeline.get_recent_alerts(limit=3)
    print(f"✓ Recent alerts: {len(recent_alerts)} available")
    
    # Test threat intel search
    search_results = pipeline.search_threat_intel("192.168")
    print(f"✓ Threat intel search: {len(search_results)} results for '192.168'")
    
    print("\n" + "=" * 60)
    
    # Final assessment
    total_detections = (
        test_results.get('threat_intel_matches', 0) +
        test_results.get('ml_anomalies_detected', 0) +
        test_results.get('signature_matches', 0)
    )
    
    if total_detections >= 2:
        print("✅ EXCELLENT: Multiple detection sources working!")
        print("   Your Cyber-EW Fusion Cell is ready for deployment!")
    elif total_detections == 1:
        print("⚠️  GOOD: At least one detection source working")
        print("   Consider enabling additional detection methods")
    else:
        print("❌ NEEDS ATTENTION: No detections triggered")
        print("   Check configuration and test data")
    
    print("\n" + "=" * 60)
    print("🎉 SYSTEM TEST COMPLETE!")
    print("=" * 60)
    
    # Show recommendations
    print("\n" + "-" * 60)
    print("RECOMMENDATIONS")
    print("-" * 60)
    
    if not dependencies['scikit-learn']:
        print("📌 Install ML dependencies:")
        print("   pip install scikit-learn pandas numpy joblib")
    
    if not dependencies['yara']:
        print("📌 For enhanced signature detection:")
        print("   pip install yara-python  (or yara-python-win for Windows)")
    
    print("\n📌 Next steps:")
    print("   1. Run in monitor mode: python main.py --mode run --monitor")
    print("   2. Test with real data: Add logs to data/inputs/logs/")
    print("   3. Add custom IOCs: Use pipeline.add_local_ioc()")
    print("   4. Add custom rules: Use pipeline.add_signature_rule()")
    
except Exception as e:
    print(f"\n❌ Error during pipeline test: {e}")
    import traceback
    traceback.print_exc()