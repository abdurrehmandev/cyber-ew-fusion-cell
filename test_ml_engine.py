#!/usr/bin/env python3
"""
Test ML Anomaly Detection Engine
"""
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("==================================================")
print("Testing ML Anomaly Detection Engine")
print("==================================================")

# Test sklearn import
try:
    import sklearn
    print(f"✓ scikit-learn version: {sklearn.__version__}")
    SKLEARN_AVAILABLE = True
except ImportError as e:
    print(f"✗ scikit-learn not available: {e}")
    SKLEARN_AVAILABLE = False

# Test numpy import
try:
    import numpy as np
    print(f"✓ numpy version: {np.__version__}")
    NUMPY_AVAILABLE = True
except ImportError as e:
    print(f"✗ numpy not available: {e}")
    NUMPY_AVAILABLE = False

# Test pandas import
try:
    import pandas as pd
    print(f"✓ pandas version: {pd.__version__}")
    PANDAS_AVAILABLE = True
except ImportError as e:
    print(f"✗ pandas not available: {e}")
    PANDAS_AVAILABLE = False

if SKLEARN_AVAILABLE and NUMPY_AVAILABLE and PANDAS_AVAILABLE:
    print("\n✅ All ML dependencies available!")
    
    # Test ML Engine
    try:
        from core.ml_anomaly_detection import MLEngine
        print("✓ ML Engine imported successfully")
        
        # Create and test ML Engine
        ml_engine = MLEngine()
        print("✓ ML Engine created")
        
        # Test with sample data
        sample_data = {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'bytes_sent': 1500,
            'bytes_received': 500,
            'duration': 60,
            'protocol': 'TCP'
        }
        
        # Test feature extraction
        features = ml_engine._extract_features(sample_data)
        print(f"✓ Features extracted: {len(features)} features")
        
        # Test prediction
        if ml_engine.model is not None:
            is_anomaly, score = ml_engine.detect_anomaly(sample_data)
            print(f"✓ Anomaly detection: is_anomaly={is_anomaly}, score={score}")
        else:
            print("ℹ️  ML model needs training data")
            
    except Exception as e:
        print(f"✗ Error testing ML Engine: {e}")
        import traceback
        traceback.print_exc()
else:
    print("\n❌ Missing ML dependencies!")
    print("Install with: pip install scikit-learn pandas numpy")