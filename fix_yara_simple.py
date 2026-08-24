#!/usr/bin/env python3
"""
Fix YARA rules - Simple version without Unicode for Windows
"""
import os
from pathlib import Path

print("=" * 60)
print("Fixing YARA Rules")
print("=" * 60)

# Ensure signatures directory exists
Path("data/signatures").mkdir(parents=True, exist_ok=True)

# Create valid YARA rules - SIMPLIFIED
yara_rules_content = """rule Suspicious_Connection {
    meta:
        description = "Detects suspicious network connections"
        severity = "high"
        author = "Cyber-EW Team"
    strings:
        $s1 = "malicious-domain.com" ascii wide
        $s2 = "192.168.1.100" ascii wide
    condition:
        any of them
}

rule Malware_Indicators {
    meta:
        description = "Common malware patterns"
        severity = "high"
    strings:
        $powershell = "powershell -e" ascii wide
        $cmd = "cmd.exe /c" ascii wide
    condition:
        any of them
}
"""

# Save the YARA rules
yara_file = Path("data/signatures/valid_rules.yar")
with open(yara_file, 'w') as f:
    f.write(yara_rules_content)

print("OK Created valid YARA rules at: data/signatures/valid_rules.yar")
print("OK Total rules: 2")

# Also create a basic rules file
basic_rules_content = """rule Basic_Suspicious {
    meta:
        description = "Basic suspicious strings"
        severity = "medium"
    strings:
        $s1 = "malicious-domain.com" ascii wide
        $s2 = "192.168.1.100" ascii wide
    condition:
        any of them
}
"""

basic_file = Path("data/signatures/basic_rules.yar")
with open(basic_file, 'w') as f:
    f.write(basic_rules_content)

print("OK Created basic fallback rules")

print("\n" + "=" * 60)
print("YARA Rules Fix Complete!")
print("=" * 60)