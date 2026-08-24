#!/usr/bin/env python3
"""Working test that finds the right imports"""
import sys
import os
import importlib.util

# Add all possible paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'core'))

print("Testing imports...")

# Method 1: Try to import directly
def try_import(module_name, class_name=None):
    """Try to import a module or class"""
    try:
        if class_name:
            # Try to import class directly
            exec(f"from {module_name} import {class_name}")
            return eval(class_name)
        else:
            # Just import module
            module = __import__(module_name)
            return module
    except ImportError:
        return None

# Try different import paths
paths_to_try = [
    'threat_intel_engine',
    'core.threat_intel_engine',
    '.threat_intel_engine'
]

ThreatIntelEngine = None
for path in paths_to_try:
    try:
        ThreatIntelEngine = try_import(path, 'ThreatIntelEngine')
        if ThreatIntelEngine:
            print(f"✓ Found ThreatIntelEngine at: {path}")
            break
    except:
        pass

if not ThreatIntelEngine:
    print("✗ Could not import ThreatIntelEngine")
    sys.exit(1)

# Test the engine
print("\nTesting threat intel engine...")
engine = ThreatIntelEngine()
print(f"✓ Engine created with {len(engine.feeds)} feeds")

# Update feeds
engine.update_all_feeds()
print(f"✓ Total IOCs: {engine.stats['total_iocs']}")

# Test matching
test_event = {
    'source_ip': '192.168.1.100',
    'destination_ip': '8.8.8.8',
    'timestamp': '2024-01-01T12:00:00Z',
    'details': {}
}

matches = engine.match_event(test_event)
print(f"✓ Matches found: {len(matches)}")

# Now try to find pipeline
print("\nLooking for pipeline...")

# Check what's available
try:
    # List files in core directory
    core_files = os.listdir('core')
    print(f"Files in core: {core_files}")
    
    # Check if pipeline.py exists
    if 'pipeline.py' in core_files:
        print("✓ Found pipeline.py")
        
        # Try to see what's in it
        with open('core/pipeline.py', 'r') as f:
            content = f.read()
            
        # Look for class definitions
        import re
        classes = re.findall(r'class\s+(\w+)', content)
        print(f"Classes in pipeline.py: {classes}")
        
        # Try to import
        try:
            from core.pipeline import CyberEWPipeline
            print("✓ Imported CyberEWPipeline")
            
            # Test it
            pipeline = CyberEWPipeline()
            print("✓ Pipeline created")
            
        except ImportError as e:
            print(f"Import error: {e}")
            
except Exception as e:
    print(f"Error: {e}")

print("\n✅ Test complete!")