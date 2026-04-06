# reports/report_generator.py
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from pathlib import Path
from datetime import datetime

def generate_pdf_report(scan_id, results):
    report_path = Path("output/reports") / f"{scan_id}_ATLAS_Forensic_Report.pdf"
    c = canvas.Canvas(str(report_path), pagesize=A4)
    width, height = A4
    y = height - 70

    # Header
    c.setFont("Helvetica-Bold", 19)
    c.drawString(50, y, "ATLAS NETWORK FORENSICS REPORT")
    y -= 30
    c.setFont("Helvetica", 11)
    c.drawString(50, y, f"Case ID: {scan_id} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 45

    # Attack Summary (same as before - shortened for space)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "ATTACK SUMMARY")
    y -= 25
    # ... (keep your attack table here - I omitted for brevity)

    y -= 30

    # ==================== INCIDENT TIMELINE ====================
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "INCIDENT TIMELINE")
    y -= 28

    c.setFont("Helvetica-Bold", 10)
    c.drawString(60, y, "Time")
    c.drawString(220, y, "Event Type")
    c.drawString(380, y, "Description")
    y -= 16
    c.line(50, y, width - 50, y)

    timeline = results.get("timeline", [])
    c.setFont("Helvetica", 9)
    for event in timeline[:12]:   # Limit to avoid too many pages
        y -= 20
        time_str = event.get("timestamp", "")[11:19] if len(event.get("timestamp", "")) > 10 else event.get("timestamp", "")
        c.drawString(60, y, time_str)
        c.drawString(220, y, event.get("eventType", ""))
        desc = event.get("description", "")[:80]
        c.drawString(380, y, desc)
        if y < 120:
            c.showPage()
            y = height - 70

    y -= 30

    # Flow Statistics + Top IPs + Forensic Indicators (keep as before)
    # ... (you can keep the previous sections)

    # Final Summary
    y -= 20
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "SUMMARY")
    y -= 25
    c.setFont("Helvetica", 12)
    c.drawString(60, y, f"Risk Level: {results.get('executiveSummary', {}).get('riskLevel', 'LOW')}")
    y -= 18
    c.drawString(60, y, f"Total Attacks Detected: {len(results.get('detected_attacks', {}).get('attacks', []))}")

    c.setFont("Helvetica", 8)
    c.drawString(50, 30, f"ATLAS Network Forensics Platform • Detailed Report")

    c.save()
    return report_path
