import yara
from pathlib import Path
from scapy.all import rdpcap, TCP, Raw
import time
from functools import lru_cache
from typing import List, Dict, Any



class YARAScanner:
    """
    Optimized YARA Scanner with:
    - Singleton pattern (rules compiled only once)
    - Rule caching
    - Efficient payload extraction
    - Performance metrics
    """

    _instance = None
    _rules = None
    _rules_loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._rules_loaded:
            self.load_rules()

    @classmethod
    def load_rules(cls):
        """Load and compile all YARA rules only once"""
        if cls._rules_loaded:
            return

        rules_dir = Path("analysis/yara_rules")
        rules_dir.mkdir(exist_ok=True)

        rule_files = list(rules_dir.glob("*.yar"))
        #print("Current Working Dir:", Path.cwd())    this is used for debugging to know whether there is any
        #print("Looking for rules in:", rules_dir.resolve())    bug in directory parsing. relative path issues.
        #print("Exists?", rules_dir.exists())

        if not rule_files:
            print("No YARA rules found. Creating default rules...")
            cls._create_default_rules(rules_dir / "network_forensics.yar")
            rule_files = list(rules_dir.glob("*.yar"))

        print(f"Loading {len(rule_files)} YARA rule files...")

        start_time = time.time()
        
        try:
            filepaths = {f.stem: str(f) for f in rule_files}
            cls._rules = yara.compile(filepaths=filepaths)
            load_time = time.time() - start_time
            print(f"YARA rules loaded successfully in {load_time:.2f}s ({len(rule_files)} files)")
            cls._rules_loaded = True
        except Exception as e:
            print(f"Failed to compile YARA rules: {e}")
            cls._rules = None

    @staticmethod
    def _create_default_rules(rules_path: Path):
        """Create minimal default rules if none exist"""
        default_rules = '''/*
 * Default Recon-Net YARA Rules
 */

rule Default_Test_Rule {
    meta:
        description = "Default test rule"
        severity = "Low"
    condition:
        filesize > 0
}
'''
        rules_path.write_text(default_rules.strip())
        print(f"Created default rules: {rules_path}")

    def scan_extracted_payload(self, payload_data: bytes, filename: str = "payload") -> List[Dict]:
        """Scan a single payload with all loaded rules"""
        if not self._rules or len(payload_data) < 40:
            return []

        try:
            matches = self._rules.match(data=payload_data)
            return [{
                "rule": match.rule,
                "severity": match.meta.get("severity", "MEDIUM"),
                "description": match.meta.get("description", "No description"),
                "payload_name": filename,
                "matched_strings": [s.identifier for s in match.strings[:5]]  # Limit output
            } for match in matches]
        except Exception:
            return []

    def scan_pcap_for_payloads(self, pcap_path: str, min_payload_size: int = 60) -> List[Dict]:
        """Optimized PCAP scanning with progress feedback"""
        pcap_path = Path(pcap_path)
        print(f"Scanning PCAP: {pcap_path.name} for malicious payloads...")

        start_time = time.time()
        yara_results = []
        payload_count = 0
        match_count = 0

        try:
            packets = rdpcap(str(pcap_path))
            total_packets = len(packets)

            for i, pkt in enumerate(packets):
                if i % 5000 == 0 and i > 0:  # Progress every 5000 packets
                    print(f"   Processed {i:,}/{total_packets:,} packets...")

                if TCP in pkt and Raw in pkt:
                    payload = bytes(pkt[Raw])
                    if len(payload) >= min_payload_size:
                        matches = self.scan_extracted_payload(payload, f"packet_{i}")
                        if matches:
                            yara_results.extend(matches)
                            match_count += len(matches)
                        payload_count += 1

        except Exception as e:
            print(f"Error reading PCAP: {e}")
            return []

        elapsed = time.time() - start_time
        print(f"YARA scan completed in {elapsed:.2f}s")
        print(f"   Payloads scanned : {payload_count:,}")
        print(f"   YARA matches     : {match_count:,}")

        return yara_results


# Optional: Global singleton instance for even faster access
yara_scanner = YARAScanner()