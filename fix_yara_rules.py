#!/usr/bin/env python3
"""
Fix YARA rules - Create valid YARA syntax
"""
import os
from pathlib import Path

print("=" * 60)
print("Fixing YARA Rules")
print("=" * 60)

# Ensure signatures directory exists
Path("data/signatures").mkdir(parents=True, exist_ok=True)

# Create valid YARA rules
yara_rules_content = """/*
Valid YARA rules for Cyber-EW Fusion Cell
Rules follow proper YARA syntax
*/

rule Suspicious_Connection {
    meta:
        description = "Detects suspicious network connections"
        severity = "high"
        author = "Cyber-EW Team"
        date = "2024-01-01"
    strings:
        $s1 = "malicious-domain.com" ascii wide
        $s2 = "192.168.1.100" ascii wide
        $s3 = "cmd.exe /c" ascii wide
    condition:
        any of them
}

rule Potential_Data_Exfiltration {
    meta:
        description = "Detects potential data exfiltration patterns"
        severity = "critical"
        author = "Cyber-EW Team"
        date = "2024-01-01"
    strings:
        $base64_pattern = /[A-Za-z0-9+\/]{40,}={0,2}/
        $hex_dump = /[0-9A-F]{4}:[0-9A-F\s]{20,}/
    condition:
        any of them
}

rule Malware_Indicators {
    meta:
        description = "Common malware strings and patterns"
        severity = "high"
        author = "Cyber-EW Team"
        date = "2024-01-01"
    strings:
        $powershell_encoded = "powershell -e" ascii wide
        $powershell_encoded2 = "powershell -enc" ascii wide
        $tor_domain = ".onion" ascii wide nocase
        $suspicious_url = /https?:\/\/(malware|ransom|botnet|exploit|c2)/ nocase
    condition:
        any of them
}

rule Network_Anomalies {
    meta:
        description = "Network anomaly patterns"
        severity = "medium"
        author = "Cyber-EW Team"
        date = "2024-01-01"
    strings:
        $port_scan = "Port Scan" ascii wide
        $syn_flood = "SYN Flood" ascii wide
        $ddos_pattern = "DDoS" ascii wide
    condition:
        any of them
}

rule File_Malware {
    meta:
        description = "Malware file indicators"
        severity = "critical"
        author = "Cyber-EW Team"
        date = "2024-01-01"
    strings:
        $ransom_note = "READ_ME_FOR_DECRYPT" ascii wide
        $ransom_note2 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide
        $locker_screen = "LOCK_SCREEN" ascii wide
    condition:
        any of them
}

rule System_Compromise {
    meta:
        description = "System compromise indicators"
        severity = "high"
        author = "Cyber-EW Team"
        date = "2024-01-01"
    strings:
        $registry_persistence = "CurrentVersion\\Run" ascii wide
        $schedule_task = "schtasks" ascii wide
        $system_info = "systeminfo" ascii wide
    condition:
        any of them
}

rule Lateral_Movement {
    meta:
        description = "Lateral movement indicators"
        severity = "high"
        author = "Cyber-EW Team"
        date = "2024-01-01"
    strings:
        $psexec = "PsExec" ascii wide
        $wmic = "wmic" ascii wide
        $winrm = "winrm" ascii wide
    condition:
        any of them
}

rule Credential_Access {
    meta:
        description = "Credential access and dumping"
        severity = "critical"
        author = "Cyber-EW Team"
        date = "2024-01-01"
    strings:
        $mimikatz = "mimikatz" ascii wide nocase
        $cred_dump = "credential" ascii wide
        $lsass_dump = "lsass" ascii wide
    condition:
        any of them
}
"""

# Save the YARA rules
yara_file = Path("data/signatures/valid_rules.yar")
with open(yara_file, 'w') as f:
    f.write(yara_rules_content)

print(f"✓ Created valid YARA rules at: {yara_file}")
print(f"✓ Total rules: 8")
print(f"✓ Rule types: Network, File, System, Lateral Movement, Credential Access")

# Also create a basic rules file for fallback
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

print(f"✓ Created basic fallback rules at: {basic_file}")

# Create a test file to verify YARA works
test_yara_script = """
import yara
import os

print("Testing YARA compilation...")
try:
    # Test with basic rules
    rules = yara.compile(filepath='data/signatures/valid_rules.yar')
    print("✅ YARA rules compiled successfully!")
    
    # Test with a sample string
    test_data = "This is a test with malicious-domain.com and powershell -e"
    matches = rules.match(data=test_data)
    
    print(f"✅ Test matches: {len(matches)} rules triggered")
    for match in matches:
        print(f"  - {match.rule}: {match.meta.get('description', 'No description')}")
        
except yara.SyntaxError as e:
    print(f"❌ YARA syntax error: {e}")
except Exception as e:
    print(f"❌ Error: {e}")
"""

test_file = Path("test_yara_compile.py")
with open(test_file, 'w') as f:
    f.write(test_yara_script)

print(f"✓ Created YARA test script at: {test_file}")
print("\nTo test YARA compilation, run: python test_yara_compile.py")

print("\n" + "=" * 60)
print("YARA Rules Fix Complete!")
print("=" * 60)