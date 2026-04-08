# analysis/yara_scanner.py
import yara
import os
from pathlib import Path
from scapy.all import rdpcap, TCP, Raw, IP

class YARAScanner:
    def __init__(self):
        self.rules = None
        self.load_rules()

    def load_rules(self):
        """Load or compile YARA rules for network forensics"""
        rules_dir = Path("analysis/yara_rules")
        rules_dir.mkdir(exist_ok=True)

        # Create a default rules file if it doesn't exist
        rules_file = rules_dir / "network_forensics.yar"
        if not rules_file.exists():
            self.create_default_network_rules(rules_file)

        try:
            self.rules = yara.compile(str(rules_file))
            print(" YARA rules loaded successfully")
        except Exception as e:
            print(f"YARA compile error: {e}")
            self.rules = None

    def create_default_network_rules(self, rules_path):
        """Create a strong set of YARA rules for common network attacks & malware"""
        rules_content = '''
/*
 * Recom-Net Network Forensics YARA Rules
 * Focused on PCAP-extracted payloads, C2, DDoS artifacts, and malware
 */

rule SYN_Flood_Pattern {
    meta:
        description = "High SYN packet patterns or reflection attack artifacts"
        author = "Recom-Net"
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
        $exfil = "exfil" nocase
        $upload = "upload" nocase
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
'''
        with open(rules_path, "w") as f:
            f.write(rules_content.strip())
        print(f"Default YARA rules created at {rules_path}")

    def scan_extracted_payload(self, payload_data: bytes, filename: str = "payload"):
        """Scan a single extracted payload (bytes)"""
        if not self.rules or len(payload_data) == 0:
            return []

        try:
            matches = self.rules.match(data=payload_data)
            return [{
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "payload_name": filename
            } for match in matches]
        except:
            return []

    def scan_pcap_for_payloads(self, pcap_path):
        """Extract TCP/HTTP payloads from PCAP and scan with YARA"""
        print(" Extracting payloads from PCAP for YARA scanning...")
        packets = rdpcap(str(pcap_path))
        yara_results = []

        for i, pkt in enumerate(packets):
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw])
                if len(payload) > 50:  # Only scan meaningful payloads
                    matches = self.scan_extracted_payload(payload, f"packet_{i}")
                    if matches:
                        yara_results.extend(matches)

        return yara_results
