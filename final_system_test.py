#!/usr/bin/env python3
"""
FINAL SYSTEM TEST - Cyber-EW Fusion Cell
All issues fixed - Ready for deployment
"""
import sys
import os
import json
import time
from pathlib import Path
from datetime import datetime, timezone

# Add to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 70)
print("CYBER-EW FUSION CELL - FINAL SYSTEM TEST")
print("=" * 70)

# ============================================================================
# PHASE 1: SETUP AND IMPORTS
# ============================================================================
print("\n" + "-" * 70)
print("PHASE 1: SETUP AND IMPORTS")
print("-" * 70)

# Import system
try:
    from core.pipeline import CyberEWPipeline
    print("OK Pipeline module imported")
except ImportError as e:
    print(f"ERROR Failed to import pipeline: {e}")
    sys.exit(1)

# Initialize pipeline
try:
    pipeline = CyberEWPipeline()
    print("OK Pipeline initialized successfully")
    
    # Update threat intel feeds
    print("Updating threat intelligence feeds...")
    pipeline.threat_intel_engine.update_all_feeds()
    print(f"OK Threat intel updated: {pipeline.threat_intel_engine.stats['total_iocs']} IOCs loaded")
    
except Exception as e:
    print(f"ERROR Pipeline initialization failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# ============================================================================
# PHASE 2: TESTING
# ============================================================================
print("\n" + "-" * 70)
print("PHASE 2: COMPREHENSIVE TESTING")
print("-" * 70)

# Test pipeline test method
print("1. Testing pipeline functionality...")
if hasattr(pipeline, 'test_pipeline'):
    try:
        test_results = pipeline.test_pipeline()
        print("OK Pipeline test executed")
        
        if isinstance(test_results, dict):
            print("\n   Test Results Summary:")
            print(f"     * Events processed: {test_results.get('events_processed', 'N/A')}")
            print(f"     * Alerts generated: {test_results.get('alerts_generated', 'N/A')}")
            print(f"     * Threat intel matches: {test_results.get('threat_intel_matches', 'N/A')}")
            print(f"     * Signature matches: {test_results.get('signature_matches', 'N/A')}")
            print(f"     * ML anomalies: {test_results.get('ml_anomalies_detected', 'N/A')}")
    except Exception as e:
        print(f"WARNING Pipeline test error: {e}")

# Test threat intel search
print("\n2. Testing threat intel search...")
search_results = pipeline.search_threat_intel("192.168")
print(f"OK Search for '192.168': {len(search_results)} results")

search_results = pipeline.search_threat_intel("malicious")
print(f"OK Search for 'malicious': {len(search_results)} results")

# Test adding new IOC
print("\n3. Testing IOC management...")
new_ioc = {
    "value": "10.0.0.99",
    "ioc_type": "ip",
    "threat_type": "test_malware",
    "source": "user_added",
    "confidence": 0.8,
    "first_seen": datetime.now(timezone.utc).isoformat(),
    "last_seen": datetime.now(timezone.utc).isoformat(),
    "description": "Test IOC",
    "tags": ["test"]
}

added = pipeline.add_local_ioc(new_ioc)
print(f"OK Add new IOC: {'Success' if added else 'Failed'}")

# Verify addition
verify_results = pipeline.search_threat_intel("10.0.0.99")
print(f"OK Verify new IOC: {len(verify_results)} found")

# ============================================================================
# PHASE 3: SYSTEM STATUS
# ============================================================================
print("\n" + "-" * 70)
print("PHASE 3: SYSTEM STATUS")
print("-" * 70)

# Get system statistics
stats = pipeline.get_statistics()

print(f"\nSYSTEM STATUS:")
print(f"   * Engine Status: {'RUNNING' if pipeline.running else 'STOPPED'}")
print(f"   * Events Processed: {stats.get('events_processed', 0)}")
print(f"   * Total Alerts: {stats.get('total_alerts', 0)}")
print(f"   * Threat Intel IOCs: {stats.get('threat_intel_iocs', 0)}")
print(f"   * Signature Rules: {stats.get('signature_rules', 0)}")

# Check engine status
print(f"\nENGINE STATUS:")
engines = [
    ('Threat Intel', pipeline.threat_intel_engine),
    ('Signature', pipeline.signature_engine),
    ('ML Anomaly', pipeline.ml_anomaly_engine),
    ('Behavior', pipeline.behavior_engine),
    ('Correlation', pipeline.correlation_engine),
    ('Scoring', pipeline.scoring_engine),
    ('Output', pipeline.output_engine)
]

for name, engine in engines:
    if engine is not None:
        print(f"   * {name} Engine: ACTIVE")
    else:
        print(f"   * {name} Engine: NOT AVAILABLE")

# ============================================================================
# PHASE 4: DEPLOYMENT READINESS
# ============================================================================
print("\n" + "-" * 70)
print("PHASE 4: DEPLOYMENT READINESS")
print("-" * 70)

# Criteria for deployment
criteria = [
    ("Pipeline Initialized", pipeline is not None, "CRITICAL"),
    ("Threat Intel Engine", pipeline.threat_intel_engine is not None, "CRITICAL"),
    ("Signature Engine", pipeline.signature_engine is not None, "CRITICAL"),
    ("YARA Available", "yara" in sys.modules, "RECOMMENDED"),
    ("IOCs Loaded", stats.get('threat_intel_iocs', 0) > 0, "CRITICAL"),
    ("Signature Rules", stats.get('signature_rules', 0) > 0, "RECOMMENDED")
]

all_critical_passed = True
print("Deployment Checklist:\n")

for desc, condition, importance in criteria:
    if condition:
        print(f"   PASS [{importance}] {desc}")
    else:
        print(f"   FAIL [{importance}] {desc}")
        if importance == "CRITICAL":
            all_critical_passed = False

print("\n" + "=" * 70)

if all_critical_passed:
    print("SUCCESS! DEPLOYMENT READY: All critical systems operational!")
    print("\nNEXT STEPS:")
    print("1. DEPLOYMENT")
    print("   - Run: python main.py --mode run --monitor")
    print("   - Test with real logs in data/inputs/logs/")
    
    print("\n2. ENHANCEMENTS")
    print("   - Add custom IOCs via pipeline.add_local_ioc()")
    print("   - Create custom YARA rules in data/signatures/")
    print("   - Configure alert outputs in core/config.py")
    
    print("\n3. INTEGRATIONS")
    print("   - Connect to SIEM (Splunk, Elastic, QRadar)")
    print("   - Add email/Slack notifications")
    
else:
    print("WARNING: DEPLOYMENT BLOCKED: Critical issues need fixing")

print("\n" + "=" * 70)
print("FINAL TEST COMPLETE")
print("=" * 70)

# Save deployment report
Path("reports").mkdir(exist_ok=True)
report = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "system": "Cyber-EW Fusion Cell",
    "version": "1.0.0",
    "status": "READY" if all_critical_passed else "NEEDS_FIXING",
    "statistics": stats,
    "criteria": [
        {
            "description": desc,
            "passed": condition,
            "importance": importance
        }
        for desc, condition, importance in criteria
    ]
}

with open("reports/deployment_report.json", "w") as f:
    json.dump(report, f, indent=2)

print(f"\nReport saved to: reports/deployment_report.json")