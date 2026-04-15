from pathlib import Path
import json
from datetime import datetime
from collections import Counter

# Analysis modules
from analysis.pcap_analyzer import (
    analyze_pcap_basic,
    analyze_pcap_nfstream,
    analyze_pcap_full_features
)
from analysis.zeek_analyzer import run_zeek_analysis
from analysis.hash_generator import generate_hashes
from analysis.attack_detector import detect_attacks
from analysis.yara_scanner import yara_scanner

# Reporting
from reports.report_generator import generate_pdf_from_json


# ====================== HELPER FUNCTIONS ======================

def ms_to_iso(ms):
    """Convert millisecond timestamp to ISO format"""
    if ms is None or ms <= 0:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000).isoformat()
    except:
        return None


def calculate_weighted_risk(attack_score: int, yara_summary: dict) -> int:
    weights = {"CRITICAL": 28, "HIGH": 16, "MEDIUM": 8, "LOW": 3}
    yara_score = sum(weights.get(info.get("severity", "LOW"), 3) * info.get("count", 0)
                     for info in yara_summary.values())
    return min(100, attack_score + yara_score)


def extract_forensic_entities(flow_features):
    src_counter = Counter(f.get("srcIP") or f.get("src_ip") for f in flow_features if f.get("srcIP") or f.get("src_ip"))
    dst_counter = Counter(f.get("dstIP") or f.get("dst_ip") for f in flow_features if f.get("dstIP") or f.get("dst_ip"))
    
    return {
        "likely_attackers": [ip for ip, _ in src_counter.most_common(10)],
        "likely_victims": [ip for ip, _ in dst_counter.most_common(10)],
        "suspicious_sources": [ip for ip, count in src_counter.most_common(5) if count > 100]
    }


def extract_iocs(flow_features):
    ips = set()
    ports = set()
    protocols = set()
    
    for f in flow_features:
        if src := (f.get("srcIP") or f.get("src_ip")): 
            ips.add(src)
        if dst := (f.get("dstIP") or f.get("dst_ip")): 
            ips.add(dst)
        if port := (f.get("dstPort") or f.get("dst_port") or f.get("dstPort")):
            if str(port).isdigit():
                ports.add(int(port))
        if proto := (f.get("application_name") or f.get("application") or f.get("protocol")):
            protocols.add(str(proto))
    
    return {
        "ips": list(ips)[:60],
        "ports": sorted(list(ports))[:50],
        "protocols": list(protocols)
    }


def group_and_filter_yara_matches(raw_matches, noise_threshold=35):
    summary = {}
    noise = {}

    for m in raw_matches:
        rule = m.get("rule", "unknown")
        meta = m.get("meta", {}) or {}
        severity = meta.get("severity", "MEDIUM") if isinstance(meta, dict) else "MEDIUM"

        if rule not in summary:
            summary[rule] = {"count": 0, "severity": severity}
        summary[rule]["count"] += 1

    final_summary = {}
    for rule, data in summary.items():
        if data["count"] > noise_threshold:
            noise[rule] = data["count"]
        else:
            final_summary[rule] = data

    if noise:
        print(f"   🧹 Filtered {len(noise)} noisy rules (threshold: {noise_threshold})")

    return final_summary, noise


def build_evidence(raw_yara_matches):
    """Build evidence section with actual payload samples"""
    evidence = []
    seen_rules = set()
    for m in raw_yara_matches[:40]:
        rule = m.get("rule")
        if rule in seen_rules:
            continue
        seen_rules.add(rule)
        evidence.append({
            "type": "yara_match",
            "rule": rule,
            "severity": m.get("severity", "MEDIUM"),
            "payload_name": m.get("payload_name", "unknown"),
            "matched_strings": m.get("matched_strings", []),
            "description": m.get("description", "")
        })
    return evidence


def build_attack_story(detected_attacks, yara_count, entities):
    story = []
    attackers = entities.get("likely_attackers", [])[:3]
    
    if yara_count > 0:
        story.append(f"YARA scanner detected {yara_count} malicious indicators (possible ransomware/C2) originating from {attackers[0] if attackers else 'suspicious hosts'}.")
    
    counter = Counter(a.get("type", "Unknown") for a in detected_attacks.get("attacks", []))
    for atype, count in counter.most_common():
        story.append(f"{atype} behavior detected across {count} flows targeting internal network.")
    
    return story


# ====================== MAIN SCAN FUNCTION ======================

def start_network_scan(file_path: str, investigator: str = "Investigator"):
    file_path = Path(file_path)
    if not file_path.exists():
        return {"error": f"File not found: {file_path}"}

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    ext = file_path.suffix.lower()

    print(f"\n=== Recon-Net NETWORK FORENSICS SCAN STARTED: {scan_id} ===")
    print(f"File: {file_path.name} ({round(file_path.stat().st_size / (1024*1024), 2):.2f} MB)")

    # Main Results Structure
    results = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "investigator": investigator,
        "tool": "Recon-Net Network Forensics Platform",
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
            "affectedIPs": []
        },

        "analysis": {},
        "flow_features": [],
        "detected_attacks": {"attacks": [], "total_detected": 0, "overall_risk_score": 0},
        "yara_matches": [],
        "yara_summary": {},
        "noise_details": {},
        "entities": {},
        "iocs": {},
        "evidence": [],
        "attack_story": [],
        "timeline": [],
        "recommendations": [],
        "risk_score": 0,
        "total_flows": 0,
        "confidence": 0.85
    }

    yara_count = 0

    if ext in {'.pcap', '.pcapng'}:
        print("→ Running core analysis...")

        results["analysis"]["basic"] = analyze_pcap_basic(file_path)
        results["analysis"]["nfstream"] = analyze_pcap_nfstream(file_path)

        try:
            results["analysis"]["zeek"] = run_zeek_analysis(file_path)
        except Exception as e:
            results["analysis"]["zeek"] = {"status": "failed", "error": str(e)}

        # Structured Flow Features
        try:
            full = analyze_pcap_full_features(file_path)
            results["flow_features"] = full.get("flow_features", [])
            results["total_flows"] = len(results["flow_features"])
        except Exception as e:
            print(f"⚠️ Feature extraction failed: {e}")

        # Attack Detection
        attack_results = detect_attacks(results["flow_features"])
        results["detected_attacks"] = attack_results

        # Entities & IOCs
        results["entities"] = extract_forensic_entities(results["flow_features"])
        results["iocs"] = extract_iocs(results["flow_features"])

        # YARA Scanning with Noise Control
        print("→ Running YARA scanner on payloads...")
        try:
            raw_matches = yara_scanner.scan_pcap_for_payloads(file_path)
            print(f"   Raw matches: {len(raw_matches)}")

            yara_summary, noise = group_and_filter_yara_matches(raw_matches, noise_threshold=35)
            results["yara_matches"] = raw_matches[:60]
            results["yara_summary"] = yara_summary
            results["noise_details"] = noise
            yara_count = len(yara_summary)
        except Exception as e:
            print(f"⚠️ YARA error: {e}")

        # Build Evidence, Story & Timeline
        results["evidence"] = build_evidence(raw_matches)
        results["attack_story"] = build_attack_story(results["detected_attacks"], yara_count, results["entities"])

        # Timeline
        timeline = [{
            "timestamp": results["timestamp"],
            "eventType": "ANALYSIS_START",
            "description": "Network traffic analysis initiated",
            "severity": "INFO"
        }]

        if yara_count > 0:
            timeline.append({
                "timestamp": datetime.now().isoformat(),
                "eventType": "YARA_ALERT",
                "description": f"YARA detected {yara_count} malicious indicators",
                "severity": "CRITICAL"
            })

        for atype, count in Counter(a.get("type", "Unknown") for a in results["detected_attacks"].get("attacks", [])).items():
            severity = "CRITICAL" if count > 10 else "HIGH" if count > 3 else "MEDIUM"
            timeline.append({
                "timestamp": datetime.now().isoformat(),
                "eventType": "ATTACK_DETECTED",
                "description": f"{atype} detected across {count} flow(s)",
                "severity": severity
            })

        timeline.append({
            "timestamp": datetime.now().isoformat(),
            "eventType": "ANALYSIS_COMPLETE",
            "description": "Analysis completed successfully",
            "severity": "INFO"
        })

        results["timeline"] = timeline

        # Final Risk & Summary
        results["risk_score"] = calculate_weighted_risk(
            attack_results.get("overall_risk_score", 0), results["yara_summary"]
        )

        results["executiveSummary"].update({
            "isAttack": True,
            "riskLevel": "CRITICAL" if results["risk_score"] >= 70 else "HIGH",
            "totalAttacks": len(attack_results.get("attacks", [])) + (1 if yara_count > 0 else 0),
            "attackTypes": list(Counter(a.get("type") for a in attack_results.get("attacks", [])).keys()),
            "affectedIPs": results["entities"].get("likely_attackers", [])[:10]
        })

        results["recommendations"] = [
            f"Isolate suspicious IPs: {', '.join(results['entities'].get('likely_attackers', [])[:5])}",
            "Investigate flows with YARA matches for ransomware/C2 activity.",
            "Apply rate limiting on high-volume UDP and long-lived TCP flows."
        ]

    # ====================== SAVE ======================
    output_dir = Path("output/scans")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{scan_id}.json"

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    try:
        report_path = generate_pdf_from_json(output_file)
    except Exception as e:
        report_path = None
        print(f"PDF generation failed: {e}")

    print(f"\n{'='*85}")
    print("✅ SCAN COMPLETED SUCCESSFULLY!")
    print(f"   YARA Unique Rules : {yara_count}")
    print(f"   Total Flows       : {results['total_flows']}")
    print(f"   Risk Score        : {results['risk_score']}/100")
    print(f"   JSON Report       → {output_file}")
    if report_path:
        print(f"   PDF Report        → {report_path}")
    print(f"{'='*85}\n")

    return results