# backend/scan_manager.py
from pathlib import Path
import json
from datetime import datetime
from collections import Counter

from analysis.pcap_analyzer import analyze_pcap_basic, analyze_pcap_nfstream, analyze_pcap_full_features
from analysis.zeek_analyzer import run_zeek_analysis
from analysis.hash_generator import generate_hashes
from analysis.attack_detector import detect_attacks
from reports.report_generator import generate_pdf_from_json


def start_network_scan(file_path: str, investigator: str = "Investigator"):
    file_path = Path(file_path)
    if not file_path.exists():
        return {"error": f"File not found: {file_path}"}

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    ext = file_path.suffix.lower()

    print(f"\n=== Recom-Net NETWORK FORENSICS SCAN STARTED: {scan_id} ===")
    print(f"File: {file_path.name} ({round(file_path.stat().st_size / (1024*1024), 2)} MB)")

    # ==================== MAIN RESULTS STRUCTURE ====================
    results = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "investigator": investigator,
        "tool": "Recom-Net Network Forensics Platform",
        "input_file": str(file_path),
        "file_name": file_path.name,
        "file_size_mb": round(file_path.stat().st_size / (1024*1024), 2),
        "file_hash": generate_hashes(file_path),
        "file_type": ext,

        "executiveSummary": {
            "isAttack": False,
            "riskLevel": "LOW",
            "totalAttacks": 0,
            "attackTypes": [],
            "affectedIPs": [],
            "affectedPorts": [],
        },

        "analysis": {},
        "flow_features": [],
        "detected_attacks": {"attacks": [], "total_detected": 0, "overall_risk_score": 0},
        "yara_matches": [],
        "timeline": [],
        "recommendations": [],
        "affected_ips": [],
        "affected_ports": [],
        "risk_score": 0,
        "total_flows": 0
    }

    yara_count = 0

    if ext in {'.pcap', '.pcapng'}:
        print("→ Running core packet analysis...")

        results["analysis"]["basic"] = analyze_pcap_basic(file_path)
        results["analysis"]["nfstream"] = analyze_pcap_nfstream(file_path)

        try:
            results["analysis"]["zeek"] = run_zeek_analysis(file_path)
        except Exception as e:
            results["analysis"]["zeek"] = {"status": "skipped", "message": str(e)}

        # Full Feature Extraction
        try:
            full_features = analyze_pcap_full_features(file_path)
            results["flow_features"] = full_features.get("flow_features", [])
            results["total_flows"] = full_features.get("total_flows", 0)
        except Exception as e:
            print(f" Feature extraction failed: {e}")

        # Rule-based Attack Detection
        attack_results = detect_attacks(results["flow_features"])
        results["detected_attacks"] = attack_results

        # ====================== YARA SCANNING ======================
        print("→ Running YARA scanner on extracted payloads...")
        try:
            from analysis.yara_scanner import YARAScanner
            scanner = YARAScanner()
            results["yara_matches"] = scanner.scan_pcap_for_payloads(file_path)
            yara_count = len(results["yara_matches"])
            print(f"    YARA found {yara_count:,} matches")
        except Exception as e:
            print(f" YARA scanning failed: {e}")
            results["yara_matches"] = []

        # ====================== CLEAN TIMELINE ======================
        timeline = [
            {
                "timestamp": results["timestamp"],
                "eventType": "ANALYSIS_START",
                "description": "Network traffic analysis initiated",
                "severity": "INFO"
            }
        ]

        if yara_count > 0:
            timeline.append({
                "timestamp": datetime.now().isoformat(),
                "eventType": "YARA_MATCH",
                "description": f"YARA scanner detected {yara_count:,} malicious payload matches (possible ransomware/malware)",
                "severity": "CRITICAL"
            })

        # Group attacks to prevent spam
        attack_counter = Counter(a.get("type", "Unknown") for a in results["detected_attacks"].get("attacks", []))
        for attack_type, count in attack_counter.items():
            severity = "CRITICAL" if count > 10 else "HIGH" if count > 3 else "MEDIUM"
            timeline.append({
                "timestamp": datetime.now().isoformat(),
                "eventType": "ATTACK_DETECTED",
                "description": f"{attack_type} detected across {count} flow(s)",
                "severity": severity
            })

        timeline.append({
            "timestamp": datetime.now().isoformat(),
            "eventType": "ANALYSIS_COMPLETE",
            "description": "Analysis completed successfully",
            "severity": "INFO"
        })

        results["timeline"] = timeline

        # Risk Score & Executive Summary
        results["risk_score"] = attack_results.get("overall_risk_score", 0) + (yara_count * 15)

        results["executiveSummary"].update({
            "isAttack": True,
            "riskLevel": "CRITICAL",
            "totalAttacks": len(attack_counter) + (1 if yara_count > 0 else 0),
            "attackTypes": list(attack_counter.keys())
        })

    # ====================== SAVE FILES ======================
    output_file = Path("output/scans") / f"{scan_id}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Generate PDF from saved JSON (decoupled)
    from reports.report_generator import generate_pdf_from_json
    report_path = generate_pdf_from_json(output_file)

    # Final Console Summary
    print(f"\nSCAN COMPLETED SUCCESSFULLY!")
    print(f"   YARA Matches    : {yara_count:,}")
    print(f"   Total Flows     : {results['total_flows']}")
    print(f"   Risk Score      : {results['risk_score']}/100")
    print(f"   JSON Report     → {output_file}")
    print(f"   PDF Report      → {report_path}")

    return results
