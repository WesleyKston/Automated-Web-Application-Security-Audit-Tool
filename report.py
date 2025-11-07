# report.py
# Professional PDF report for ISAA — clean charts, wrapped cells, zebra rows,
# severity coloring, de-duplication, and robust DB compatibility.

import os
import io
import sqlite3
from datetime import datetime

# ReportLab
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
)

# Matplotlib (for charts)
import matplotlib
matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt

DB_PATH = "audit.db"


# ---------- DB helpers ----------

def _column_exists(conn, table, col):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())


def fetch_scan_data(scan_id: int):
    """Returns: scan_dict, findings_rows(list of tuples)."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Try to read flexible scan fields (handle both schemas)
    # Prefer: id, target, status, score, created_at
    cols = ["id", "target", "status", "score"]
    has_created_at = _column_exists(conn, "scans", "created_at")
    if has_created_at:
        cols.append("created_at")

    cur.execute(f"SELECT {', '.join(cols)} FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise ValueError(f"Scan {scan_id} not found")

    scan = {
        "id": row[0],
        "target": row[1],
        "status": row[2],
        "score": row[3] if row[3] is not None else 0,
        "created_at": row[4] if has_created_at else None,
    }

    # Findings schema order we saw in your code:
    # page, type, parameter, evidence, severity, owasp_mapping, recommendation
    cur.execute("""
        SELECT page, type, parameter, evidence, severity, owasp_mapping, recommendation
        FROM findings WHERE scan_id=?;
    """, (scan_id,))
    findings = cur.fetchall()

    conn.close()
    return scan, findings


# ---------- Charts ----------

def _severity_counts(findings):
    order = ["Low", "Medium", "High"]
    counts = {k: 0 for k in order}
    for f in findings:
        sev = (f[4] or "").strip().title()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Low"] += 1  # fallback
    return order, [counts[o] for o in order]


def make_charts(findings):
    """Returns tuple of (pie_png_path, bar_png_path)."""
    order, counts = _severity_counts(findings)

    # PIE
    fig = plt.figure(figsize=(3.8, 3.8), dpi=150)
    plt.pie(
        counts,
        labels=order,
        autopct=lambda p: f"{int(round(p))}%" if p > 0 else "",
        startangle=90,
        colors=["#22C55E", "#FACC15", "#EF4444"],
        wedgeprops=dict(edgecolor="white", linewidth=1),
        textprops=dict(fontsize=8),
    )
    plt.title("Severity Distribution", fontsize=10, pad=8)
    pie_path = "report_pie.png"
    fig.savefig(pie_path, bbox_inches="tight")
    plt.close(fig)

    # BAR
    fig = plt.figure(figsize=(4.2, 3.2), dpi=150)
    plt.bar(order, counts)
    plt.title("Severity Count", fontsize=10, pad=8)
    plt.ylabel("Count", fontsize=9)
    plt.xticks(fontsize=9)
    plt.yticks(fontsize=9)
    bar_path = "report_bar.png"
    fig.savefig(bar_path, bbox_inches="tight")
    plt.close(fig)

    return pie_path, bar_path


# ---------- Building blocks ----------

def _styles():
    ss = getSampleStyleSheet()
    # Avoid name collisions by using unique names
    ss.add(ParagraphStyle(name="H1_ISAA", parent=ss["Title"], fontSize=18, spaceAfter=8))
    ss.add(ParagraphStyle(name="H2_ISAA", parent=ss["Heading2"], fontSize=12, spaceBefore=6, spaceAfter=6))
    ss.add(ParagraphStyle(name="Cell", parent=ss["BodyText"], fontSize=8, leading=10))
    ss.add(ParagraphStyle(name="CellBold", parent=ss["BodyText"], fontSize=8, leading=10, textColor=colors.black))
    ss.add(ParagraphStyle(name="Tiny", parent=ss["BodyText"], fontSize=7))
    return ss


def _sev_color(sev: str):
    s = (sev or "").strip().lower()
    if s == "high":
        return colors.Color(1, 0.4, 0.4)  # soft red
    if s == "medium":
        return colors.Color(0.98, 0.8, 0.3)  # amber
    return colors.Color(0.5, 0.85, 0.5)  # green


def _dedupe_findings(findings):
    """De-duplicate by (page, type, parameter, severity, owasp, recommendation)."""
    seen = set()
    out = []
    for f in findings:
        key = (f[0] or "", f[1] or "", f[2] or "", f[4] or "", f[5] or "", f[6] or "")
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _sort_findings(findings):
    sev_rank = {"High": 0, "Medium": 1, "Low": 2}
    def key(f):
        sev = (f[4] or "").title()
        return (sev_rank.get(sev, 2), (f[1] or ""), (f[2] or ""))
    return sorted(findings, key=key)


def _wrap(text, style):
    return Paragraph((text or "-").replace("&", "&amp;"), style)


def build_summary_table(scan, styles):
    created = scan["created_at"] or datetime.now().strftime("%Y-%m-%d %H:%M")
    data = [
        ["Target", scan["target"]],
        ["Status", scan["status"]],
        ["Score", f'{int(scan["score"])} / 100'],
        ["Generated", created],
    ]
    t = Table(data, colWidths=[70, 440])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def build_charts_block(pie_path, bar_path):
    # Place charts in a 2-col table so they stay on the same page and aligned
    pie_img = Image(pie_path, width=2.8*inch, height=2.8*inch)
    bar_img = Image(bar_path, width=3.2*inch, height=2.4*inch)
    tbl = Table([[pie_img, bar_img]], colWidths=[3.1*inch, 3.1*inch])
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


def build_findings_table(findings, styles):
    # De-duplicate, sort, and wrap
    findings = _sort_findings(_dedupe_findings(findings))

    header = ["Page", "Type", "Parameter", "Severity", "OWASP", "Recommendation"]
    data = [header]
    for f in findings:
        page, typ, param, _, sev, owasp, rec = f
        data.append([
            _wrap(page, styles["Cell"]),
            _wrap(typ, styles["Cell"]),
            _wrap(param, styles["Cell"]),
            _wrap(sev, styles["Cell"]),
            _wrap(owasp, styles["Cell"]),
            _wrap(rec, styles["Cell"]),
        ])

    col_widths = [140, 80, 90, 55, 50, 145]
    t = Table(data, colWidths=col_widths, repeatRows=1)
    base = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf0ff")),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]

    # zebra striping and severity coloring
    for i in range(1, len(data)):
        # zebra (even rows)
        if i % 2 == 0:
            base.append(("BACKGROUND", (0, i), (-1, i), colors.whitesmoke))
        # severity color in column 3
        sev_text = findings[i-1][4] or ""
        base.append(("BACKGROUND", (3, i), (3, i), _sev_color(sev_text)))
        base.append(("TEXTCOLOR", (3, i), (3, i), colors.black))

    t.setStyle(TableStyle(base))
    return t


# ---------- PDF Builder ----------

def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(A4[0] - 36, 18, f"ISAA | Page {doc.page}")
    canvas.restoreState()


def generate_report(scan_id: int, output_path: str = "report.pdf"):
    scan, findings = fetch_scan_data(scan_id)
    pie, bar = make_charts(findings)

    styles = _styles()
    story = []

    # Title
    story.append(Paragraph("Security Audit & Analysis Report", styles["H1_ISAA"]))
    story.append(Spacer(1, 6))

    # Summary
    story.append(build_summary_table(scan, styles))
    story.append(Spacer(1, 10))

    # Charts (kept tight to avoid pushing to next page)
    story.append(Paragraph("Severity Overview", styles["H2_ISAA"]))
    story.append(build_charts_block(pie, bar))
    story.append(Spacer(1, 6))

    # Findings
    story.append(Paragraph("Detailed Findings", styles["H2_ISAA"]))
    story.append(build_findings_table(findings, styles))

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=28,
    )
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)

    # cleanup images
    for p in (pie, bar):
        try:
            os.remove(p)
        except Exception:
            pass

    print(f"✅ Report generated: {output_path}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python report.py <scan_id>")
    else:
        generate_report(int(sys.argv[1]), "report.pdf")
