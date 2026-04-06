import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
SCANS_DIR = OUTPUT_DIR / "scans"
REPORTS_DIR = OUTPUT_DIR / "reports"

for d in [OUTPUT_DIR, SCANS_DIR, REPORTS_DIR]:
    d.mkdir(exist_ok=True)

SUPPORTED_FORMATS = {'.pcap', '.pcapng', '.evtx', '.log'}
