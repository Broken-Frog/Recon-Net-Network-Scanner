# reports/report_generator.py
import json
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML


def generate_pdf_from_json(json_path: str):
    json_path = Path(json_path)
    if not json_path.exists():
        print(f" JSON not found: {json_path}")
        return None

    with open(json_path, 'r', encoding='utf-8') as f:
        results = json.load(f)

    scan_id = results.get("scan_id", "unknown")

    env = Environment(loader=FileSystemLoader("reports/templates"))
    template = env.get_template("forensic_report.html")

    html_content = template.render(
        results=results,
        scan_id=scan_id,
        generated_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        yara_count=len(results.get("yara_matches", []))
    )

    report_path = Path("output/reports") / f"{scan_id}_Recom-Net_Detailed_Report.pdf"

    HTML(string=html_content).write_pdf(report_path)

   # print(f"Rich PDF with charts generated: {report_path}")
    return str(report_path)
