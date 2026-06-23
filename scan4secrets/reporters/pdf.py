"""PDF reporter using fpdf2 (UTF-8 safe)."""

from pathlib import Path
from typing import List
from collections import Counter

from fpdf import FPDF

from scan4secrets.engine.findings import Finding


def _safe(s: str) -> str:
    # fpdf2 core fonts are Latin-1; map anything outside it to "?"
    return s.encode("latin-1", "replace").decode("latin-1")


def write(findings: List[Finding], path: Path, *, unsafe_show: bool = False):
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _safe("scan4secrets report"), ln=1)
    pdf.set_font("Helvetica", "", 10)
    counts = Counter(f.severity for f in findings)
    pdf.cell(0, 6, _safe(
        f"Total findings: {len(findings)}  |  "
        + "  ".join(f"{s}: {counts.get(s, 0)}" for s in ("critical","high","medium","low","info"))
    ), ln=1)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 9)
    cols = [("severity", 18), ("rule_id", 50), ("verified", 18), ("file", 110), ("line", 14), ("secret_redacted", 60)]
    for name, w in cols:
        pdf.cell(w, 6, _safe(name), border=1)
    pdf.ln(6)

    pdf.set_font("Helvetica", "", 8)
    for f in findings:
        row = f.to_dict(unsafe=unsafe_show)
        vals = [
            row.get("severity", ""),
            row.get("rule_id", ""),
            "YES" if f.verified is True else ("no" if f.verified is False else "-"),
            row.get("file", "")[-55:],
            str(row.get("line", "")),
            (row.get("secret") if unsafe_show else row.get("secret_redacted", "")) or "",
        ]
        for (_, w), v in zip(cols, vals):
            pdf.cell(w, 5, _safe(str(v))[:int(w/1.6)], border=1)
        pdf.ln(5)

    pdf.output(str(path))
