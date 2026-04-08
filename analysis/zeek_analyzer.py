# analysis/zeek_analyzer.py
import subprocess
import pandas as pd
from pathlib import Path
from datetime import datetime

def run_zeek_analysis(pcap_path, output_dir=None):
    if output_dir is None:
        output_dir = Path("zeek_output")
    output_dir.mkdir(exist_ok=True, parents=True)

    print(f" Running Zeek analysis on {pcap_path.name}...")

    zeek_bin = "/opt/zeek/bin/zeek"
    pcap_path = Path(pcap_path).resolve()
    try:
        cmd = [
            zeek_bin,
            "-r", str(pcap_path),
            "local"
        ]

        result = subprocess.run(
            cmd,
            cwd=output_dir,
            capture_output=True,
            text=True,
            timeout=180
        )
       # print("Return code:", result.returncode)
       # print("STDOUT:\n", result.stdout)
        #print("STDERR:\n", result.stderr)

        if result.returncode != 0:
            return {
                "status": "error",
                "message": result.stderr
             }
        logs = {}
        # Updated log files based on what Zeek actually generates for your PCAP
        log_files = ["conn.log", "weird.log", "packet_filter.log", "snmp.log", "http.log", "dns.log"]

        print("   Parsing Zeek logs...")
        parsed_count = 0

        for log_name in log_files:
            log_path = output_dir / log_name
            if log_path.exists():
                size = log_path.stat().st_size
                if size > 100:
                    try:
                        df = pd.read_csv(log_path, sep="\t", comment="#", low_memory=False)
                        records = df.to_dict(orient="records")
                        logs[log_name.replace(".log", "")] = records[:400]
                        parsed_count += len(records)
                       # print(f"     ✓ Parsed {log_name} → {len(records)} records")
                    except Exception as e:
                        logs[log_name.replace(".log", "")] = {"error": str(e)}
                else:
                    logs[log_name.replace(".log", "")] = {"status": "too_small"}
            else:
                logs[log_name.replace(".log", "")] = {"status": "missing"}

        if parsed_count == 0:
            print(" Zeek ran but produced no usable logs. Trying broader configuration next time.")
        else:
            print(f" Zeek completed successfully - {parsed_count} total log entries parsed")

        return {
            "status": "success",
            "logs": logs,
            "zeek_output_dir": str(output_dir),
            "total_logs_parsed": parsed_count,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        print(f" Zeek error: {e}")
        return {"status": "error", "message": str(e)}
