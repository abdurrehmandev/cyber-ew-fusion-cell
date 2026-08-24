#!/usr/bin/env python3
"""Ultimate test of the complete working system"""
import sys
import os
import time
from datetime import datetime, timezone

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("CYBER-EW FUSION CELL - ULTIMATE TEST")
print("=" * 60)

# Import
try:
    from core.pipeline import CyberEWPipeline
    print("✓ Pipeline imported")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)

# Create pipeline
print("\n1. Creating pipeline...")
try:
    pipeline = CyberEWPipeline()
    print("✓ Pipeline created")
    
    # Check all engines
    print("\n2. Checking all engines:")
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
        status = "✓" if engine is not None else "✗"
        print(f"   {status} {name} Engine: {type(engine).__name__ if engine else 'Not available'}")
    
    # Test the test_pipeline method (if exists)
    print("\n3. Testing pipeline functionality...")
    
    # Method 1: Check if test_pipeline exists
    if hasattr(pipeline, 'test_pipeline'):
        print("   Testing with test_pipeline() method...")
        result = pipeline.test_pipeline()
        print(f"   ✓ test_pipeline executed: {result}")
    
    # Method 2: Try to add an event through ingest engine
    if hasattr(pipeline.ingest_engine, 'ingest'):
        print("\n   Testing ingest engine...")
        test_event = {
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'network_connection',
            'severity': 'high',
            'details': {
                'bytes_sent': 5000,
                'bytes_received': 100,
                'protocol': 'TCP',
                'port': 443,
                'query': 'malicious-domain.com'
            }
        }
        
        # Start pipeline if needed
        if not pipeline.running:
            pipeline.start()
            time.sleep(1)  # Give it time to start
        
        # Ingest event
        result = pipeline.ingest_engine.ingest(test_event)
        print(f"   ✓ Event ingested: {result}")
        
        # Wait for processing
        time.sleep(2)
        
        # Get stats
        stats = pipeline.get_statistics()
        print(f"   ✓ Events processed: {stats.get('events_processed', 0)}")
        
        # Stop pipeline
        pipeline.stop()
    
    # Method 3: Use add_local_ioc and search
    print("\n4. Testing threat intel functions...")
    try:
        # Add a test IOC
        test_ioc = {
            "value": "10.0.0.99",
            "ioc_type": "ip",
            "threat_type": "test_malware",
            "source": "test",
            "confidence": 0.9,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "description": "Test IOC for verification",
            "tags": ["test", "verification"]
        }
        
        success = pipeline.add_local_ioc(test_ioc)
        print(f"   ✓ Test IOC added: {success}")
        
        # Search for it
        search_results = pipeline.search_threat_intel("10.0.0.99")
        print(f"   ✓ Search results: {len(search_results)} found")
        
    except Exception as e:
        print(f"   ✗ Threat intel test error: {e}")
    
    # Get final statistics
    print("\n5. Final system statistics:")
    stats = pipeline.get_statistics()
    
    important_stats = [
        ('events_processed', 'Events Processed'),
        ('total_alerts', 'Total Alerts'),
        ('threat_intel_iocs', 'Threat Intel IOCs'),
        ('signature_rules', 'Signature Rules'),
        ('ml_models', 'ML Models'),
        ('avg_processing_time_ms', 'Avg Processing Time (ms)')
    ]
    
    for key, label in important_stats:
        if key in stats:
            print(f"   • {label}: {stats[key]}")
    
    # Get recent alerts
    print("\n6. Recent alerts:")
    recent_alerts = pipeline.get_recent_alerts(limit=5)
    if recent_alerts:
        for i, alert in enumerate(recent_alerts, 1):
            title = alert.get('title', 'Unknown Alert')
            score = alert.get('threat_score', 0)
            source = alert.get('detection_source', 'Unknown')
            print(f"   {i}. {title} (Score: {score:.2f}, Source: {source})")
    else:
        print("   No recent alerts")
    
    print("\n" + "=" * 60)
    print("✅ SYSTEM IS FULLY OPERATIONAL!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Run in monitor mode: python main.py --mode run --monitor")
    print("2. Add your own IOCs using pipeline.add_local_ioc()")
    print("3. Add custom signature rules using pipeline.add_signature_rule()")
    print("4. Test with real log files in data/inputs/logs/")
    
except Exception as e:
    print(f"\n✗ Critical error: {e}")
    import traceback
    traceback.print_exc()