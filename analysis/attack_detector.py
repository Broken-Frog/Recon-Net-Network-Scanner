# analysis/attack_detector.py
def detect_attacks(flow_features):
    """
    Advanced attack detection using parameters from your FeatureExtractor
    Returns list of detected attacks with clear explanations
    """
    attacks = []
    
    for idx, feat in enumerate(flow_features):
        flow_id = f"Flow-{idx}"
        total_pkts = feat.get("totalPackets", 0)
        if total_pkts == 0:
            continue

        # 1. SYN Flood / TCP Reflection Attack
        if (feat.get("synFlagRatio", 0) > 0.75 and 
            feat.get("ackFlagRatio", 0) < 0.25 and 
            feat.get("flowPacketsPerSec", 0) > 50):
            attacks.append({
                "type": "SYN Flood / TCP Reflection",
                "severity": "High",
                "flow": flow_id,
                "parameters": {
                    "synFlagRatio": round(feat["synFlagRatio"], 4),
                    "ackFlagRatio": round(feat["ackFlagRatio"], 4),
                    "flowPacketsPerSec": round(feat["flowPacketsPerSec"], 2),
                    "synFlagCount": feat["synFlagCount"]
                },
                "explanation": f"Very high SYN ratio ({feat['synFlagRatio']:.3f}) with low ACK response. Typical of TCP SYN flood or reflection attack (like your sample amp.TCP.reflection.SYNACK.pcap)."
            })

        # 2. Port Scan
        if (feat.get("flowPacketsPerSec", 0) > 300 and 
            feat.get("smallPacketRatio", 0) > 0.6 and 
            feat.get("totalFwdPackets", 0) > 50):
            attacks.append({
                "type": "Port Scan / Horizontal Scan",
                "severity": "Medium",
                "flow": flow_id,
                "parameters": {
                    "flowPacketsPerSec": round(feat["flowPacketsPerSec"], 1),
                    "smallPacketRatio": round(feat["smallPacketRatio"], 3),
                    "flowAsymmetry": round(feat.get("flowAsymmetry", 0), 3)
                },
                "explanation": "High packet rate with mostly small packets and many different destination ports likely."
            })

        # 3. UDP Flood
        if (feat.get("flowPacketsPerSec", 0) > 800 and 
            feat.get("bwdPacketLengthMean", 0) < 100):
            attacks.append({
                "type": "UDP Flood",
                "severity": "High",
                "flow": flow_id,
                "parameters": {
                    "flowPacketsPerSec": round(feat["flowPacketsPerSec"], 1),
                    "bwdPacketLengthMean": round(feat["bwdPacketLengthMean"], 2)
                },
                "explanation": "Extremely high packet rate with small backward packets — classic UDP amplification/flood."
            })

        # 4. Data Exfiltration / C2
        if (feat.get("totalPayloadBytes", 0) > 50000 and 
            feat.get("flowAsymmetry", 0) > 0.7 and 
            feat.get("downUpRatio", 0) > 5):
            attacks.append({
                "type": "Data Exfiltration",
                "severity": "High",
                "flow": flow_id,
                "parameters": {
                    "totalPayloadBytes": feat["totalPayloadBytes"],
                    "flowAsymmetry": round(feat["flowAsymmetry"], 3),
                    "downUpRatio": round(feat["downUpRatio"], 2)
                },
                "explanation": "Large payload in one direction with high asymmetry — possible data theft or C2 beaconing."
            })

        # 5. Slowloris / Slow DDoS
        if (feat.get("flowIATMean", 0) > 500000 and 
            feat.get("flowDuration", 0) > 30000000 and 
            feat.get("totalPackets", 0) < 100):
            attacks.append({
                "type": "Slowloris / Slow Attack",
                "severity": "Medium",
                "flow": flow_id,
                "parameters": {
                    "flowIATMean": round(feat["flowIATMean"], 0),
                    "flowDuration": round(feat["flowDuration"]/1000000, 1)
                },
                "explanation": "Very long flow duration with large inter-arrival time and few packets — Slow HTTP/DoS pattern."
            })

    # Overall risk score calculation
    severity_map = {"High": 40, "Medium": 20, "Low": 10}
    total_risk = sum(severity_map.get(a["severity"], 10) for a in attacks)
    
    return {
        "attacks": attacks,
        "total_detected": len(attacks),
        "overall_risk_score": min(100, total_risk)
    }
