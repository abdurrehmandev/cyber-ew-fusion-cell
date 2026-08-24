import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pipeline import CyberEWPipeline

# Create pipeline
pipeline = CyberEWPipeline()

print("Pipeline attributes:")
for attr in dir(pipeline):
    if not attr.startswith('_'):
        print(f"  {attr}")

# Check for threat intel related attributes
print("\nLooking for threat intel attributes:")
for attr in dir(pipeline):
    if not attr.startswith('_') and ('threat' in attr.lower() or 'intel' in attr.lower()):
        print(f"  {attr}: {type(getattr(pipeline, attr))}")