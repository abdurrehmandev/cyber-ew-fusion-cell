rule Basic_Suspicious {
    meta:
        description = "Basic suspicious strings"
        severity = "medium"
    strings:
        $s1 = "malicious-domain.com" ascii wide
        $s2 = "192.168.1.100" ascii wide
    condition:
        any of them
}
