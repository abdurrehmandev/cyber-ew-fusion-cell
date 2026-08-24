# Save as: minimal_test.py
import sys
print(f"Python path: {sys.path}")

# Test if we can import from our own project
sys.path.insert(0, r'C:\Users\rehma\Documents\cyber-ew-fusion-cell')

try:
    # Try to import directly
    import utils.validators
    print("✓ Successfully imported utils.validators")
    
    # Test the function
    from utils.validators import validate_ip_address
    print(f"✓ validate_ip_address('192.168.1.1') = {validate_ip_address('192.168.1.1')}")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()