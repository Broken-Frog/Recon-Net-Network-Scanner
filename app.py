import streamlit as st
from pathlib import Path
import json
import webbrowser
import subprocess
from backend.scan_manager import start_network_scan

# ====================== PAGE CONFIG ======================
st.set_page_config(
    page_title="Recon-Net | Network Forensics",
    layout="wide",
    page_icon="🛡️"
)

st.title("🛡️ Recon-Net Network Forensics Platform")
st.markdown("### Deep Packet Inspection & Attack Reconstruction")

# ====================== FILE UPLOAD ======================
uploaded_file = st.file_uploader(
    "Upload PCAP / EVTX / LOG / CSV",
    type=['pcap', 'pcapng', 'evtx', 'log', 'csv']
)

if uploaded_file:
    st.success(f"✅ Uploaded: **{uploaded_file.name}**")

    investigator = st.text_input("Investigator Name", value="Investigator")

    if st.button("🚀 Start Forensic Analysis", type="primary", use_container_width=True):
        temp_dir = Path("temp_uploads")
        temp_dir.mkdir(exist_ok=True)
        temp_file = temp_dir / uploaded_file.name

        with open(temp_file, "wb") as f:
            f.write(uploaded_file.getbuffer())

        progress_bar = st.progress(0)
        status_text = st.empty()

        try:
            status_text.text("Running deep forensic analysis...")
            progress_bar.progress(50)

            result = start_network_scan(str(temp_file), investigator=investigator)

            progress_bar.progress(100)
            st.success("✅ Analysis Completed Successfully!")

            scan_id = result['scan_id']

            # Summary Metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Risk Score", f"{result.get('risk_score', 0)}/100")
            with col2:
                st.metric("YARA Matches", len(result.get('yara_matches', [])))
            with col3:
                st.metric("Total Flows", len(result.get('flow_features', [])))
            with col4:
                st.metric("Risk Level", result.get("executiveSummary", {}).get("riskLevel", "LOW"))

            # ====================== ACTION BUTTONS ======================
            col1, col2, col3 = st.columns(3)

            with col1:
                json_path = Path(f"output/scans/{scan_id}.json")
                if json_path.exists():
                    with open(json_path, "rb") as f:
                        st.download_button("📥 Download JSON", f, file_name=f"{scan_id}.json")

            with col2:
                pdf_path = Path(f"output/reports/{scan_id}_Recon-Net_Detailed_Report.pdf")
                if pdf_path.exists():
                    with open(pdf_path, "rb") as f:
                        st.download_button("📥 Download PDF", f, file_name=pdf_path.name)

            with col3:
                if st.button("📊 Open Interactive Report", type="primary", use_container_width=True):
                    try:
                        # Start local HTTP server
                        subprocess.Popen(
                            ["python3", "-m", "http.server", "8503", "--directory", "."],
                            cwd=Path(__file__).parent,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        url = f"http://localhost:8503/report.html?scan={scan_id}"
                        webbrowser.open_new_tab(url)
                        st.success(f"✅ Report opened at http://localhost:8503")
                    except Exception as e:
                        st.error(f"Failed to open report: {e}")

            # Timeline Preview
            if result.get("timeline"):
                st.subheader("Incident Timeline")
                for event in result["timeline"][:8]:
                    st.write(f"**{event.get('timestamp', '')[:19]}** — {event.get('description')}")

        except Exception as e:
            st.error(f"Analysis failed: {e}")

# ====================== PREVIOUS SCANS ======================
st.subheader("📜 Previous Scans")
scans_dir = Path("output/scans")
if scans_dir.exists():
    for file in sorted(scans_dir.glob("*.json"), reverse=True)[:6]:
        try:
            with open(file) as f:
                data = json.load(f)
            col1, col2, col3 = st.columns([3, 2, 2])
            with col1:
                st.write(f"**{data.get('file_name', 'Unknown')}**")
            with col2:
                st.write(data.get('timestamp', '')[:16])
            with col3:
                if st.button("Open Report", key=f"open_{data['scan_id']}"):
                    try:
                        subprocess.Popen(
                            ["python3", "-m", "http.server", "8503", "--directory", "."],
                            cwd=Path(__file__).parent,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        url = f"http://localhost:8503/report.html?scan={data['scan_id']}"
                        webbrowser.open_new_tab(url)
                    except:
                        st.error("Failed to open report")
        except:
            continue
else:
    st.info("No previous scans found.")