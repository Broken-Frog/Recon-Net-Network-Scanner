# analysis/flow_feature_analyzer.py
from scapy.all import rdpcap, IP, TCP
from pathlib import Path
from .features_extractor import FeatureExtractor
from tqdm import tqdm

def build_flows_and_extract_features(pcap_path):
    print(" Building flows with packet-level details for FeatureExtractor...")
    pcap_path = Path(pcap_path)
    packets = rdpcap(str(pcap_path))
    
    flows_dict = {}
    all_packets = []

    for pkt in tqdm(packets, desc="Grouping packets into flows"):
        if IP not in pkt:
            continue
            
        srcIP = pkt[IP].src
        dstIP = pkt[IP].dst
        proto = pkt[IP].proto
        srcPort = pkt[TCP].sport if TCP in pkt else 0
        dstPort = pkt[TCP].dport if TCP in pkt else 0
        
        flow_key = (srcIP, dstIP, srcPort, dstPort, proto)
        
        if flow_key not in flows_dict:
            flows_dict[flow_key] = {
                "srcIP": srcIP,
                "dstIP": dstIP,
                "srcPort": srcPort,
                "dstPort": dstPort,
                "startTime": float(pkt.time),
                "endTime": float(pkt.time),
                "packets": []
            }
        
        flow = flows_dict[flow_key]
        flow["endTime"] = max(flow["endTime"], float(pkt.time))
        
        packet_dict = {
            "srcIP": srcIP,
            "dstIP": dstIP,
            "srcPort": srcPort,
            "dstPort": dstPort,
            "length": len(pkt),
            "timestamp": float(pkt.time),
            "tcpFlags": {
                "syn": bool(TCP in pkt and pkt[TCP].flags & 0x02),
                "ack": bool(TCP in pkt and pkt[TCP].flags & 0x10),
                "fin": bool(TCP in pkt and pkt[TCP].flags & 0x01),
                "rst": bool(TCP in pkt and pkt[TCP].flags & 0x04),
                "psh": bool(TCP in pkt and pkt[TCP].flags & 0x08),
                "urg": bool(TCP in pkt and pkt[TCP].flags & 0x20),
            },
            "payloadSize": len(pkt[TCP].payload) if TCP in pkt else 0,
            "headerSize": len(pkt) - len(pkt.payload) if hasattr(pkt, 'payload') else len(pkt),
            "ttl": getattr(pkt[IP], 'ttl', None),
        }
        flow["packets"].append(packet_dict)
        all_packets.append(packet_dict)
    
    flow_list = list(flows_dict.values())
    
    # Run FeatureExtractor
    extractor = FeatureExtractor()
    flow_features = extractor.extract_features(flow_list, all_packets)
    
    # IMPORTANT: Attach srcIP, dstIP, srcPort, dstPort back to each feature
    enriched_flow_features=[]
    for i, feat in enumerate(flow_features):
        if i < len(flow_list):
            feat["srcIP"] = flow_list[i]["srcIP"]
            feat["dstIP"] = flow_list[i]["dstIP"]
            feat["srcPort"] = flow_list[i]["srcPort"]
            feat["dstPort"] = flow_list[i]["dstPort"]
            enriched_flow_features.append(feat)

    return {
        "total_flows": len(flow_list),
        "flow_features": enriched_flow_features,
        "total_packets_processed": len(packets)
    }
