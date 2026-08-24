#!/usr/bin/env python3
"""
Test Threat Detection without requiring all dependencies immediately
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("Testing Cyber-EW Fusion Cell Threat Detection")
print("=" * 60)

try:
    # Test basic pipeline
    from core.pipeline import CyberEWPipeline
    
    print("✓ Pipeline imported successfully")
    
    # Create pipeline
    pipeline = CyberEWPipeline()
    print("✓ Pipeline created")
    
    # Run test
    test_results = pipeline.test_pipeline()
    
    print("\n" + "=" * 60)
    print("TEST RESULTS:")
    print("=" * 60)
    print(f"Threat Intel Matches: {test_results['threat_intel_matches']}")
    print(f"ML Anomalies Detected: {test_results['ml_anomalies_detected']}")
    print(f"Signature Matches: {test_results['signature_matches']}")
    print(f"Alerts Generated: {test_results['alerts_generated']}")
    print(f"Events Processed: {test_results['events_processed']}")
    
    if test_results['threat_intel_matches'] > 0:
        print("✓ Threat intelligence is working!")
    else:
        print("⚠️ No threat intel matches - check local IOCs file")
    
    if test_results['signature_matches'] > 0:
        print("✓ Signature detection is working!")
    else:
        print("⚠️ No signature matches - check signature rules")
    
    print("\n" + "=" * 60)
    print("✅ Enhanced threat detection test completed!")
    print("=" * 60)
    
except ImportError as e:
    print(f"\n❌ IMPORT ERROR: {e}")
    print("\nMissing dependencies. Installing required packages...")
    
    # Try to install missing packages
    import subprocess
    import importlib.util
    
    # Check which packages are missing
    missing_packages = []
    
    if importlib.util.find_spec("sklearn") is None:
        missing_packages.append("scikit-learn")
    if importlib.util.find_spec("pandas") is None:
        missing_packages.append("pandas")
    if importlib.util.find_spec("dateutil") is None:
        missing_packages.append("python-dateutil")
    
    if missing_packages:
        print(f"\nInstalling: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
            print("\n✅ Dependencies installed. Please run the test again.")
        except subprocess.CalledProcessError:
            print("\n❌ Failed to install dependencies. Please install manually:")
            print(f"pip install {' '.join(missing_packages)}")
    else:
        print("All required packages are installed. The error might be elsewhere.")
        
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()