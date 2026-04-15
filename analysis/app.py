import streamlit as st
from pathlib import Path
import json
import webbrowser
from backend.scan_manager import start_network_scan

# ====================== PAGE CONFIG ======================
st.set_page_config(
    page_title="Recon-Net | Network Forensics",
    layout="wide",
    page_icon="🛡️"
)

st.markdown("""
<style>
    .stApp { background-color: #0a0a0a; color: #ffffff; }
    .metric-card { background-color: #1f1f2e; padding: 15px; border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Recon-Net Network Forensics Platform")
st.markdown("### Deep Packet Inspection & Attack Reconstruction")

# ====================== FILE UPLOAD ======================
uploaded_file = st.file_uploader(
    "Upload network capture (PCAP, PCAPNG, EVTX, LOG, CSV)",
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
            status_text.text("Analyzing network traffic...")
            progress_bar.progress(40)

            result = start_network_scan(str(temp_file), investigator=investigator)

            progress_bar.progress(100)
            st.success("✅ Analysis Completed Successfully!")

            # Results Summary
            col1, col2, col3, col4 = st.columns(4)
            with col1: st.metric("Risk Score", f"{result.get('risk_score', 0)}/100")
            with col2: st.metric("YARA Matches", len(result.get('yara_matches', [])))
            with col3: st.metric("Total Flows", len(result.get('flow_features', [])))
            with col4: st.metric("Risk Level", result.get("executiveSummary", {}).get("riskLevel", "LOW"))

            scan_id = result['scan_id']

            # ====================== REPORT BUTTONS ======================
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
                   report_html = Path("report.html").absolute()
                   scan_id = result['scan_id']
        
                   if report_html.exists():
            # Open using local HTTP server (most reliable method)
                    try:
                        import subprocess
                # Start a simple HTTP server in the background
                        subprocess.Popen(["python3", "-m", "http.server", "8503", "--directory", "."], 
                                    cwd=Path(__file__).parent, 
                                    stdout=subprocess.DEVNULL, 
                                    stderr=subprocess.DEVNULL)
                
                        url = f"http://localhost:8503/report.html?scan={scan_id}"
                        webbrowser.open_new_tab(url)
                        st.success(f"✅ Report opened at http://localhost:8503")
                    except Exception as e:
                          st.error(f"Failed to start server: {e}")
                else:
                      st.error("report.html not found in root folder!")
            # Timeline Preview
            if result.get("timeline"):
                st.subheader("Incident Timeline")
                for event in result["timeline"][:6]:
                    st.write(f"**{event.get('timestamp','')[:19]}** — {event.get('description')}")

        except Exception as e:
            st.error(f"Analysis failed: {str(e)}")

# ====================== HISTORY SECTION ======================
st.subheader("📜 Previous Scans")
scans_dir = Path("output/scans")
if scans_dir.exists():
    for file in sorted(scans_dir.glob("scan_*.json"), reverse=True)[:8]:
        try:
            with open(file) as f:
                data = json.load(f)
            col1, col2, col3 = st.columns([3, 2, 2])
            with col1:
                st.write(f"**{data.get('file_name')}**")
            with col2:
                st.write(data.get('timestamp', '')[:16])
            with col3:
                if st.button("Open Report", key=f"btn_{data['scan_id']}"):
                    report_html = Path("report.html").absolute()
                    if report_html.exists():
                        file_url = f"file://{report_html}?scan={data['scan_id']}"
                        webbrowser.open_new_tab(file_url)
        except:
            continue

# ====================== SIDEBAR ======================
with st.sidebar:
    st.header("Recon-Net")
    st.caption("Network Forensics Platform")
    st.divider()
    st.write("**Supported Files:** PCAP, EVTX, Logs, CSV")
