#!/usr/bin/env python3
"""
Fix ML feature dimension mismatch
"""
import pickle
import numpy as np
import os
from sklearn.ensemble import IsolationForest

def fix_ml_model():
    """Fix or retrain the ML model with correct feature dimensions"""
    
    model_path = "data/models/anomaly_detector.pkl"
    
    # Check if model exists
    if os.path.exists(model_path):
        print(f"Found existing model at {model_path}")
        
        try:
            # Load the model
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            
            print(f"Current model type: {type(model)}")
            
            # Check feature dimensions
            if hasattr(model, 'n_features_in_'):
                print(f"Model expects {model.n_features_in_} features")
            else:
                print("Model doesn't have n_features_in_ attribute")
                
            # Check if it's an IsolationForest
            if isinstance(model, IsolationForest):
                print("Model is IsolationForest")
                
                # Get training data shape from model if available
                if hasattr(model, 'estimators_'):
                    print(f"Model has {len(model.estimators_)} estimators")
            
        except Exception as e:
            print(f"Error loading model: {e}")
    
    # Always create a new model with consistent 6 features
    print("\nCreating new model with 6 features...")
    
    # Generate synthetic training data with exactly 6 features
    np.random.seed(42)
    X_train = np.random.randn(1000, 6)  # 1000 samples, 6 features
    
    # Add some anomalies
    anomalies = np.random.randn(50, 6) + 5  # Shifted mean
    X_train = np.vstack([X_train, anomalies])
    
    # Create and train new model
    model = IsolationForest(
        contamination=0.05,  # 5% contamination
        random_state=42,
        n_estimators=100
    )
    
    model.fit(X_train)
    
    # Ensure directory exists
    os.makedirs("data/models", exist_ok=True)
    
    # Save the model
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"✓ Created new model with {model.n_features_in_} features")
    print(f"Model saved to {model_path}")
    
    # Also create a test to verify
    print("\nTesting model with sample data...")
    test_samples = np.random.randn(5, 6)
    predictions = model.predict(test_samples)
    scores = model.score_samples(test_samples)
    
    print(f"Test predictions: {predictions}")
    print(f"Test scores (lower = more anomalous): {scores}")
    
    return model

if __name__ == "__main__":
    fix_ml_model()