/*
 * ATLAS Network Forensics YARA Rules
 * Focused on PCAP-extracted payloads, C2, DDoS artifacts, and malware
 */

rule SYN_Flood_Pattern {
    meta:
        description = "High SYN packet patterns or reflection attack artifacts"
        author = "ATLAS"
        severity = "High"
    strings:
        $syn_flood = { 02 00 00 00 }  // Common in SYN packets (flags)
        $reflection = "SYNACK" nocase
    condition:
        any of them and filesize < 5MB
}

rule C2_Beaconing {
    meta:
        description = "Common C2 beacon patterns (Cobalt Strike, Empire, Sliver, etc.)"
        severity = "High"
    strings:
        $beacon1 = "beacon" nocase
        $beacon2 = "/api/" nocase
        $c2 = "c2" nocase
        $http_post = "POST /" nocase
        $sliver = "sliver" nocase
    condition:
        2 of them
}

rule Data_Exfiltration {
    meta:
        description = "Large base64 or encoded data exfiltration"
        severity = "Medium"
    strings:
        $base64_long = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $base64_long and filesize > 10KB

}

rule Malware_Downloader {
    meta:
        description = "Common malware downloader patterns"
        severity = "High"
    strings:
        $powershell = "powershell" nocase
        $cmd = "cmd.exe" nocase
        $wget = "wget " nocase
        $curl = "curl " nocase
        $exe = ".exe" nocase
    condition:
        2 of them
}

rule Port_Scan_Pattern {
    meta:
        description = "Port scanning behavior in payloads"
        severity = "Medium"
    strings:
        $nmap = "nmap" nocase
        $scan = "scan" nocase
        $port = "port " nocase
    condition:
        any of them
}

rule UDP_Flood_Artifact {
    meta:
        description = "UDP amplification or flood related strings"
        severity = "High"
    strings:
        $udp_flood = "UDP" nocase
        $amplification = "amplification" nocase
        $dns = "DNS" nocase fullword
    condition:
        2 of them
}

/* Add more rules here as you find new IOCs */
