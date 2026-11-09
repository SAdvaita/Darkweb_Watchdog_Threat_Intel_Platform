import io
from datetime import datetime, timezone


def generate_pdf_report(findings_data: list, metrics: dict) -> bytes:
    """Generate a PDF report using ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("DarkWeb Watchdog — Exposure Report", styles["Title"]))
        story.append(
            Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()} UTC", styles["Normal"])
        )
        story.append(Spacer(1, 12))

        story.append(Paragraph("Summary Metrics", styles["Heading2"]))
        for k, v in metrics.items():
            story.append(Paragraph(f"<b>{k}:</b> {v}", styles["Normal"]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Top Findings", styles["Heading2"]))
        if findings_data:
            data = [["ID", "Title", "Severity", "Score", "Status"]]
            for f in findings_data[:20]:
                data.append(
                    [
                        str(f.get("id", "")),
                        f.get("title", "")[:50],
                        f.get("severity", ""),
                        str(f.get("score", "")),
                        f.get("status", ""),
                    ]
                )
            t = Table(data)
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            story.append(t)

        doc.build(story)
        return buffer.getvalue()
    except Exception as e:
        return f"PDF generation error: {e}".encode()
