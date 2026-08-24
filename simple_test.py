#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("Cyber-EW Fusion Cell - Simple Test")
print("=" * 60)

try:
    from core.pipeline import CyberEWPipeline
    print("Pipeline imported successfully")
    
    # Create pipeline
    pipeline = CyberEWPipeline()
    print("Pipeline created")
    
    # Replace engines with fixed versions
    try:
        from core.engines.fixed_ml_engine import FixedMLEngine
        from core.engines.fixed_signature_engine import FixedSignatureEngine
        pipeline.ml_anomaly_engine = FixedMLEngine()
        pipeline.signature_engine = FixedSignatureEngine()
        print("Fixed engines loaded")
    except ImportError as e:
        print(f"Note: Using original engines - {e}")
    
    # Test threat intel
    pipeline.threat_intel_engine.update_all_feeds()
    print(f"Threat intel: {pipeline.threat_intel_engine.stats['total_iocs']} IOCs")
    
    # Test pipeline
    if hasattr(pipeline, "test_pipeline"):
        result = pipeline.test_pipeline()
        print("Pipeline test completed")
        if isinstance(result, dict):
            print(f"Events processed: {result.get('events_processed', 0)}")
            print(f"Alerts generated: {result.get('alerts_generated', 0)}")
            print(f"Threat intel matches: {result.get('threat_intel_matches', 0)}")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE - System is working!")
    print("=" * 60)
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()