#!/usr/bin/env python3
"""Test all imports"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Testing imports...")

# Test core modules
modules = [
    'core.threat_intel_engine',
    'core.pipeline',
    'core.signature_detection',
    'core.ml_anomaly_detection'
]

for module in modules:
    try:
        __import__(module)
        print(f"✅ {module}")
    except ImportError as e:
        print(f"❌ {module}: {e}")

# Test external dependencies
print("\nTesting external dependencies...")
external = [
    ('sklearn', 'scikit-learn'),
    ('yara', 'yara-python'),
    ('pandas', 'pandas'),
    ('numpy', 'numpy'),
    ('requests', 'requests')
]

for import_name, package_name in external:
    try:
        __import__(import_name)
        print(f"✅ {package_name}")
    except ImportError:
        print(f"❌ {package_name}")