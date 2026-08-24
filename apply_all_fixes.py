#!/usr/bin/env python3
"""
Apply all fixes at once
"""
import subprocess
import sys
import os

print("=" * 70)
print("APPLYING ALL FIXES TO CYBER-EW FUSION CELL")
print("=" * 70)

# Run fixes in order
fixes = [
    ("Fixing YARA rules", "python fix_yara_rules.py"),
    ("Fixing threat intel engine", "python threat_intel_fix.py"),
    ("Testing YARA compilation", "python test_yara_compile.py"),
    ("Testing threat intel engine", "python test_threat_intel_verification.py")
]

for description, command in fixes:
    print(f"\n{description}...")
    print("-" * 50)
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(f"Stderr: {result.stderr}")
        
        if result.returncode != 0:
            print(f"⚠️  Command failed with return code: {result.returncode}")
    except Exception as e:
        print(f"❌ Error running command: {e}")

print("\n" + "=" * 70)
print("ALL FIXES APPLIED!")
print("=" * 70)
print("\nNext, run the complete system test:")
print("   python test_complete_system.py")
print("\nOr run the final validation:")
print("   python final_working_system.py")