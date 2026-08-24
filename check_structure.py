# File: check_structure.py
import os
from pathlib import Path

print("Checking project structure...\n")

# List of required files
required_files = [
    "utils/__init__.py",
    "utils/validators.py",
    "utils/time_utils.py",
    "utils/helpers.py",
    "utils/security.py",
    "config/settings.yaml",
    "data/inputs/test_events.json",
    "test_simple.py"
]

missing_files = []
for file_path in required_files:
    if not os.path.exists(file_path):
        missing_files.append(file_path)
        print(f"✗ Missing: {file_path}")
    else:
        print(f"✓ Found: {file_path}")

print(f"\nTotal missing files: {len(missing_files)}")

if missing_files:
    print("\nLet me create the missing files...")
    # We'll create them one by one