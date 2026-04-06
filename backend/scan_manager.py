# backend/scan_manager.py
from pathlib import Path
import json
from datetime import datetime

# Analysis modules
from analysis.pcap_analyzer import analyze_pcap_basic, analyze_pcap_nfstream, analyze_pcap_full_features
from analysis.zeek_analyzer import run_zeek_analysis
from analysis.hash_generator import generate_hashes
from analysis.attack_detector import detect_attacks
from reports.report_generator import generate_pdf_report

def start_network_scan(file_path: str, investigator: str = "Investigator"):
    file_path = Path(file_path)
    if not file_path.exists():
        return {"error": f"File not found: {file_path}"}

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    print(f"\n=== ATLAS NETWORK FORENSICS SCAN STARTED: {scan_id} ===")
    print(f"File: {file_path.name} ({round(file_path.stat().st_size / (1024*1024), 2)} MB)")

    # Initialize results with proper forensic structure
    results = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "investigator": investigator,
        "tool": "ATLAS Network Forensics Platform",
        "input_file": str(file_path),
        "file_name": file_path.name,
        "file_size_mb": round(file_path.stat().st_size / (1024*1024), 2),
        "file_hash": generate_hashes(file_path),

        "executiveSummary": {
            "isAttack": False,
            "riskLevel": "LOW",
            "totalAttacks": 0,
            "attackTypes": [],
            "affectedIPs": [],
            "affectedPorts": [],
            "protocols": ["TCP", "HTTP"]
        },

        "analysis": {},
        "flow_features": [],
        "detected_attacks": {"attacks": [], "total_detected": 0, "overall_risk_score": 0},
        "yara_matches": [],
        "iocs": [],
        "timeline": [],
        "recommendations": [],
        "affected_ips": [],
        "affected_ports": [],
        "ip_flow_map": {},
        "risk_score": 0
    }

    ext = file_path.suffix.lower()
    if ext in {'.pcap', '.pcapng'}:
        print("→ Running basic Scapy analysis...")
        results["analysis"]["basic"] = analyze_pcap_basic(file_path)

        print("→ Running NFStream flow analysis...")
        results["analysis"]["nfstream"] = analyze_pcap_nfstream(file_path)

        # Zeek with safe fallback
        print("→ Running Zeek analysis...")
        try:
            results["analysis"]["zeek"] = run_zeek_analysis(file_path)
        except Exception as e:
            print(f"⚠️ Zeek skipped: {e}")
            results["analysis"]["zeek"] = {"status": "skipped", "message": str(e)}

        # Full FeatureExtractor analysis
        print("→ Extracting full flow features using FeatureExtractor...")
        try:
            full_features = analyze_pcap_full_features(file_path)
            results["flow_features"] = full_features.get("flow_features", [])
            results["total_flows"] = full_features.get("total_flows", 0)
        except Exception as e:
            print(f"⚠️ Feature extraction failed: {e}")
            results["flow_features"] = []

        # Rule-based attack detection
        print("→ Running rule-based attack detection...")
        attack_results = detect_attacks(results["flow_features"])
        results["detected_attacks"] = attack_results

        # YARA scanning
        print("→ Running YARA scanner on payloads...")
        try:
            from analysis.yara_scanner import YARAScanner
            yara_scanner = YARAScanner()
            yara_matches = yara_scanner.scan_pcap_for_payloads(file_path)
            results["yara_matches"] = yara_matches
        except Exception as e:
            print(f"⚠️ YARA scanning failed: {e}")
            results["yara_matches"] = []

        # ==================== BUILD FORENSIC METADATA ====================
        print("→ Building forensic metadata (Affected IPs + Source→Dest mapping)...")

        affected_ips = set()
        affected_ports = set()
        ip_flow_map = {}   # srcIP → set of destIPs

        for flow in results.get("flow_features", []):
            if isinstance(flow, dict):
                src_ip = flow.get("srcIP")
                dst_ip = flow.get("dstIP")

                if src_ip:
                    affected_ips.add(str(src_ip))
                    if src_ip not in ip_flow_map:
                        ip_flow_map[src_ip] = set()
                    if dst_ip:
                        ip_flow_map[src_ip].add(str(dst_ip))

                if dst_ip:
                    affected_ips.add(str(dst_ip))

                # Ports
                if flow.get("srcPort") is not None:
                    affected_ports.add(str(flow.get("srcPort")))
                if flow.get("dstPort") is not None:
                    affected_ports.add(str(flow.get("dstPort")))

        print(f"   Extracted {len(affected_ips)} unique IPs")

        # Update Executive Summary
        results["executiveSummary"] = {
            "isAttack": len(results["detected_attacks"].get("attacks", [])) > 0 or len(results["yara_matches"]) > 0,
            "riskLevel": "CRITICAL" if results.get("risk_score", 0) >= 75 else "HIGH" if results.get("risk_score", 0) >= 50 else "MEDIUM",
            "totalAttacks": len(results["detected_attacks"].get("attacks", [])) + len(results["yara_matches"]),
            "attackTypes": [a.get("type", "Unknown") for a in results["detected_attacks"].get("attacks", [])],
            "affectedIPs": list(affected_ips)[:20],
            "affectedPorts": list(affected_ports)[:30],
            "protocols": ["TCP", "HTTP"]
        }

        # Root level copies for easy access
        results["affected_ips"] = list(affected_ips)[:20]
        results["affected_ports"] = list(affected_ports)[:30]
        results["ip_flow_map"] = {k: list(v) for k, v in list(ip_flow_map.items())[:12]}

        # Build Timeline
        results["timeline"] = [
            {
                "timestamp": results["timestamp"],
                "eventType": "ANALYSIS_START",
                "description": "Network traffic analysis initiated",
                "severity": "INFO"
            }
        ]

        for attack in results["detected_attacks"].get("attacks", []):
            results["timeline"].append({
                "timestamp": datetime.now().isoformat(),
                "eventType": "ATTACK_DETECTED",
                "description": f"{attack.get('type')} attack detected",
                "severity": attack.get("severity", "MEDIUM")
            })

        results["timeline"].append({
            "timestamp": datetime.now().isoformat(),
            "eventType": "ANALYSIS_COMPLETE",
            "description": f"Analysis completed. Risk Level: {results['executiveSummary']['riskLevel']}",
            "severity": results['executiveSummary']['riskLevel']
        })

        # Recommendations
        results["recommendations"] = [
            {
                "priority": "HIGH",
                "action": "Investigate affected IPs and block suspicious sources",
                "rationale": "Multiple attack patterns detected in traffic"
            }
        ]

        # Final Risk Score
        results["risk_score"] = attack_results.get("overall_risk_score", 0) + (len(results["yara_matches"]) * 15)
        results["executiveSummary"]["riskLevel"] = "CRITICAL" if results["risk_score"] >= 75 else "HIGH" if results["risk_score"] >= 50 else "MEDIUM"

    # ====================== SAVE & REPORT ======================
    output_file = Path("output/scans") / f"{scan_id}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    report_path = generate_pdf_report(scan_id, results)

    print(f"\n✅ SCAN COMPLETED!")
    print(f"   Results JSON → {output_file}")
    print(f"   Forensic PDF  → {report_path}")
    print(f"   Affected IPs   : {len(results.get('affected_ips', []))}")
    print(f"   Detected Attacks: {results['detected_attacks'].get('total_detected', 0)}")
    print(f"   Final Risk Score: {results['risk_score']}/100")

    return results
