rule Suspicious_Connection {
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
