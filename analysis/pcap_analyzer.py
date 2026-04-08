# analysis/pcap_analyzer.py
from scapy.all import rdpcap, IP, TCP, UDP
import nfstream
import pandas as pd
from tqdm import tqdm

# Your original functions (unchanged)
def analyze_pcap_basic(pcap_path):
    print("Reading PCAP with Scapy...")
    packets = rdpcap(str(pcap_path))
   
    flows = {}
    protocols = {}
   
    for pkt in tqdm(packets, desc="Analyzing packets"):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            key = f"{src} -> {dst}"
            flows[key] = flows.get(key, 0) + 1
           
            if TCP in pkt:
                protocols['TCP'] = protocols.get('TCP', 0) + 1
            elif UDP in pkt:
                protocols['UDP'] = protocols.get('UDP', 0) + 1
   
    return {
        "total_packets": len(packets),
        "unique_flows": len(flows),
        "protocols": protocols,
        "top_flows": dict(sorted(flows.items(), key=lambda x: x[1], reverse=True)[:10])
    }


def analyze_pcap_nfstream(pcap_path):
    print("Running NFStream flow analysis...")
    nf = nfstream.NFStreamer(source=str(pcap_path), n_meters=10)
    flow_list = [flow for flow in nf]
    df = pd.DataFrame(flow_list) if flow_list else pd.DataFrame()
   
    return {
        "flow_count": len(flow_list),
        "flows": df.to_dict(orient="records")[:50] if not df.empty else [] 
    }


# ==================== NEW FUNCTION FOR YOUR FEATURE EXTRACTOR ====================
from .flow_feature_analyzer import build_flows_and_extract_features

def analyze_pcap_full_features(pcap_path):
    """Runs your custom FeatureExtractor on the PCAP"""
    print(" Running FULL feature extraction using FeatureExtractor...")
    try:
        return build_flows_and_extract_features(pcap_path)
    except Exception as e:
        print(f" Error in full feature extraction: {e}")
        return {
            "total_flows": 0,
            "flow_features": [],
            "total_packets_processed": 0,
            "error": str(e)
        }
