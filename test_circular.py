# Save as: test_circular.py
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

print("Testing for circular imports...")

# Try to import ingest_engine directly
try:
    import core.engines.ingest_engine
    print("✓ ingest_engine imports successfully")
    
    # Now try to import the specific functions
    from core.engines.ingest_engine import IngestEngine
    print("✓ IngestEngine class imports successfully")
    
    # Check what imports ingest_engine is doing
    print("\nChecking ingest_engine imports...")
    import inspect
    source = inspect.getsource(core.engines.ingest_engine)
    lines = source.split('\n')
    
    # Find the import line for validators
    for i, line in enumerate(lines[:30]):
        if 'utils.validators' in line:
            print(f"Line {i+1}: {line.strip()}")
            
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()