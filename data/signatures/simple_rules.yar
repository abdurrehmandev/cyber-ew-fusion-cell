rule Suspicious_Domain {
    meta:
        description = "Known malicious domain"
        severity = "high"
    strings:
        $malicious = "malicious-domain.com"
    condition:
        $malicious
}

rule Suspicious_IP {
    meta:
        description = "Known malicious IP address"
        severity = "high"
    strings:
        $malicious_ip = "192.168.1.100"
    condition:
        $malicious_ip
}

rule PowerShell_Encoded {
    meta:
        description = "Encoded PowerShell command"
        severity = "critical"
    strings:
        $ps1 = "powershell -e"
        $ps2 = "powershell -enc"
    condition:
        any of them
}