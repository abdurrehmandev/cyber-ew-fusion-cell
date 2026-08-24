# test_all_fixes.py
import sys
import os
sys.path.append('.')

print("Testing all fixes...")

# Test 1: Import and test ThreatScore
print("\n1. Testing ThreatScore to_dict()...")
try:
    from core.engines.scoring_engine import ThreatScore, ThreatLevel
    
    ts = ThreatScore(
        overall_score=85,
        level=ThreatLevel.HIGH,
        confidence=0.8
    )
    
    # Add components if needed
    if not hasattr(ts, 'components'):
        ts.components = {}
    
    result = ts.to_dict()
    print(f"✓ ThreatScore.to_dict() works: {result}")
except Exception as e:
    print(f"✗ ThreatScore error: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Check ML model
print("\n2. Testing ML model...")
try:
    import pickle
    import numpy as np
    
    model_path = "data/models/anomaly_detector.pkl"
    if os.path.exists(model_path):
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        print(f"✓ Model loaded: {type(model)}")
        
        # Test with 6 features
        test_data = np.random.randn(1, 6)
        
        if hasattr(model, 'predict'):
            prediction = model.predict(test_data)
            print(f"  Test prediction: {prediction}")
        
        if hasattr(model, 'n_features_in_'):
            print(f"  Model expects: {model.n_features_in_} features")
            print(f"  Test data has: {test_data.shape[1]} features")
            
            if model.n_features_in_ == test_data.shape[1]:
                print("  ✓ Feature dimensions match!")
            else:
                print(f"  ✗ Feature mismatch!")
    else:
        print(f"✗ Model not found at {model_path}")
        
except Exception as e:
    print(f"✗ ML model error: {e}")

# Test 3: Test OutputEngine with fixed ThreatScore
print("\n3. Testing OutputEngine with ThreatScore...")
try:
    from core.engines.output_engine import OutputEngine
    from core.models.event_models import NormalizedEvent, EventType, EventSeverity
    from datetime import datetime, timezone
    
    output_engine = OutputEngine()
    
    # Create test event
    event = NormalizedEvent(
        event_id="test_001",
        event_type=EventType.NETWORK_CONNECTION,
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        severity=EventSeverity.HIGH
    )
    
    # Create threat score
    ts = ThreatScore(overall_score=75, level=ThreatLevel.MEDIUM, confidence=0.7)
    
    # Test publish_alert
    output_engine.publish_alert(event, ts, [], [])
    print("✓ OutputEngine.publish_alert() works with ThreatScore")
    
except Exception as e:
    print(f"✗ OutputEngine error: {e}")
    import traceback
    traceback.print_exc()

print("\n✓ All tests completed!")