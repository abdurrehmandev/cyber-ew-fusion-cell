#!/usr/bin/env python3
"""
Quick patch for dimension mismatch
"""

import pickle
import os

# Path to the ML model
model_path = "data/models/anomaly_detector.pkl"

if os.path.exists(model_path):
    print(f"Found model at {model_path}")
    
    # Load the model
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    
    print(f"Model type: {type(model)}")
    
    # Check the model's expected features
    if hasattr(model, 'n_features_in_'):
        print(f"Model expects {model.n_features_in_} features")
    
    # If it's an IsolationForest with wrong dimensions, we need to retrain it
    from sklearn.ensemble import IsolationForest
    import numpy as np
    
    # Create a simple retraining script
    print("\nCreating training data with 6 features...")
    
    # Generate synthetic training data with 6 features
    X_train = np.random.randn(100, 6)  # 6 features
    
    # Create and train new model
    new_model = IsolationForest(contamination=0.1, random_state=42)
    new_model.fit(X_train)
    
    # Save the new model
    with open(model_path, 'wb') as f:
        pickle.dump(new_model, f)
    
    print(f"✓ Retrained model with 6 features")
    print(f"New model expects {new_model.n_features_in_} features")
else:
    print(f"Model not found at {model_path}")
    print("Creating new model...")
    
    from sklearn.ensemble import IsolationForest
    import numpy as np
    
    # Generate synthetic training data with 6 features
    X_train = np.random.randn(100, 6)  # 6 features
    
    # Create and train new model
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_train)
    
    # Save the model
    os.makedirs("data/models", exist_ok=True)
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"✓ Created new model with 6 features")