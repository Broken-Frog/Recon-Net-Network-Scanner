# Recon-Net Network Forensics Analysis Platform

**Recon-Net** is a powerful, open-source network forensics platform designed for investigators, security analysts, and digital forensics professionals.

It allows you to upload PCAP files and automatically performs deep analysis to detect attacks, reconstruct network activity, extract artifacts, and generate court-ready forensic reports.

### Key Features

- **Full PCAP Analysis**: Packet parsing, flow reconstruction, and protocol dissection
- **Advanced Attack Detection**: SYN Flood, UDP Flood, ACK Flood, Port Scan, Slowloris, and more
- **Rich Feature Extraction**: 40+ statistical features per flow using custom FeatureExtractor
- **Zeek Integration**: Generates and parses conn.log, weird.log, packet_filter.log, and more
- **YARA Scanning**: Detects known malware patterns and C2 communication in payloads
- **Threat Intelligence Ready**: Easy integration with VirusTotal and other IOC feeds (upcoming)
- **Professional Reporting**: Generates detailed PDF reports with attack summary, timeline, top IPs, forensic indicators, and recommendations
- **Real-time Dashboard Ready**: Built with modular backend (Firebase integration planned)

### Supported Use Cases

- Incident Response & Investigation
- Malware Traffic Analysis
- DDoS Attack Investigation
- Network Intrusion Detection
- Forensic Evidence Collection

### Tech Stack

- **Backend**: Python 3
- **Packet Analysis**: Scapy, NFStream
- **Deep Forensics**: Zeek (Bro)
- **Feature Engineering**: Custom FeatureExtractor
- **Reporting**: ReportLab (PDF)
- **YARA**: Signature-based detection

### Getting Started

```bash
git clone https://github.com/Broken-Frog/Recon-Net-Network-Scanner.git
cd Recon-Net-Network-Scanner
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py <pcap file>      
