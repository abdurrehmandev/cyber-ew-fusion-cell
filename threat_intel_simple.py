#!/usr/bin/env python3
"""
Fix Threat Intelligence Engine - Simple version
"""
import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

print("=" * 60)
print("Fixing Threat Intelligence Engine")
print("=" * 60)

# Ensure directories exist
Path("data/threat_intel").mkdir(parents=True, exist_ok=True)

# Create enhanced IOC database
enhanced_iocs = [
    {
        "value": "192.168.1.100",
        "ioc_type": "ip",
        "threat_type": "malware_c2",
        "source": "local_observation",
        "confidence": 0.95,
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "description": "Known malware command and control server",
        "tags": ["malware", "c2", "botnet"]
    },
    {
        "value": "malicious-domain.com",
        "ioc_type": "domain",
        "threat_type": "phishing",
        "source": "threat_feed",
        "confidence": 0.85,
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "description": "Phishing domain",
        "tags": ["phishing", "malicious"]
    }
]

# Save IOCs to file
iocs_file = Path("data/threat_intel/local_iocs.json")
with open(iocs_file, 'w') as f:
    json.dump(enhanced_iocs, f, indent=2)

print("OK Created enhanced IOCs file with 2 indicators")
print("OK File location: data/threat_intel/local_iocs.json")

print("\n" + "=" * 60)
print("THREAT INTEL FIX COMPLETE!")
print("=" * 60)