"""
Boundry.AI — PDF Incident Report Generator
============================================
Converts a markdown incident report into a professionally branded PDF
suitable for client delivery, board presentations, and cyber insurance claims.

Usage:
    from pdf_generator import generate_report_pdf
    pdf_bytes = generate_report_pdf(report_id, created_at, threat_count, event_count, content_md)
"""
import re
from datetime import datetime
from fpdf import FPDF


# ── Colour palette ────────────────────────────────────────────────────────────
DARK       = (13,  13,  13)    # #0D0D0D  near-black background
GREEN      = (0,  180,  50)    # #00B432  print-safe Boundry green
TEXT_DARK  = (20,  20,  20)    # #141414  body text
TEXT_MID   = (90,  90,  90)    # #5A5A5A  secondary text
WHITE      = (255, 255, 255)
LIGHT_BG   = (248, 248, 248)   # #F8F8F8  alternating table rows
BORDER     = (210, 210, 210)   # #D2D2D2  table borders
RED        = (220,  50,  50)   # #DC3232  critical/high severity
AMBER      = (200, 130,   0)   # #C88200  medium severity


class BoundryPDF(FPDF):
    """Custom FPDF subclass with Boundry.AI header and footer on every page."""

    def __init__(self, report_id, created_at):
        super().__init__()
        self.report_id  = report_id
        self.created_at = created_at
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(left=15, top=18, right=15)

    def header(self):
        # Dark top bar
        self.set_fill_color(*DARK)
        self.rect(0, 0, 210, 13, "F")
        # Brand name in green
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*GREEN)
        self.set_xy(12, 3)
        self.cell(80, 7, "BOUNDRY.AI  —  CYBERSECURITY HQ", ln=False)
        # Report ref + confidential in white
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*WHITE)
        self.set_xy(0, 3)
        self.cell(198, 7, f"INCIDENT REPORT #{self.report_id}   |   CONFIDENTIAL", align="R")
        self.set_y(16)

    def footer(self):
        self.set_y(-13)
        self.set_fill_color(*DARK)
        self.rect(0, self.get_y(), 210, 13, "F")
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*TEXT_MID)
        self.set_xy(12, self.get_y() + 3)
        self.cell(100, 7, f"Generated: {self.created_at}", ln=False)
        self.set_text_color(*WHITE)
        self.set_xy(0, self.get_y())
        self.cell(198, 7, f"Page {self.page_no()}", align="R")


# ── Markdown parser ───────────────────────────────────────────────────────────

def _strip_md(text: str) -> str:
    """Remove common markdown syntax from a line for plain-text rendering."""
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)   # bold
    text = re.sub(r"\*(.+?)\*",     r"\1", text)    # italic
    text = re.sub(r"`(.+?)`",       r"\1", text)    # inline code
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)  # links
    return text.strip()


def _severity_colour(line: str):
    """Return an RGB tuple hinting at severity from the text."""
    upper = line.upper()
    if "CRITICAL" in upper:
        return RED
    if "HIGH" in upper:
        return RED
    if "MEDIUM" in upper:
        return AMBER
    return GREEN


def _parse_table(rows: list[str]) -> tuple[list[str], list[list[str]]]:
    """
    Parse a markdown table block into headers + data rows.
    Skips the separator row (---|---).
    """
    headers = []
    data    = []
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        if all(re.match(r"^[-:]+$", c) for c in cells if c):
            continue   # separator row
        if not headers:
            headers = cells
        else:
            data.append(cells)
    return headers, data


# ── PDF rendering helpers ─────────────────────────────────────────────────────

def _render_cover(pdf: BoundryPDF, threat_count: int, event_count: int, created_at: str, simulated: bool = False):
    """Render a branded cover page."""
    pdf.add_page()

    # Large dark hero block
    pdf.set_fill_color(*DARK)
    pdf.rect(0, 13, 210, 80, "F")

    # ASCII-style logo text
    pdf.set_font("Courier", "B", 22)
    pdf.set_text_color(*GREEN)
    pdf.set_xy(0, 28)
    pdf.cell(210, 12, "BOUNDRY.AI", align="C")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(0, 44)
    pdf.cell(210, 8, "C Y B E R S E C U R I T Y   H Q", align="C")

    # Green separator line
    pdf.set_draw_color(*GREEN)
    pdf.set_line_width(0.8)
    pdf.line(40, 55, 170, 55)

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(0, 60)
    pdf.cell(210, 10, "INCIDENT REPORT", align="C")

    if simulated:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*AMBER)
        pdf.set_xy(0, 68)
        pdf.cell(210, 7, "TRAINING EXERCISE — SIMULATED ATTACK DATA (NOT A LIVE INCIDENT)", align="C")
    else:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*GREEN)
        pdf.set_xy(0, 68)
        pdf.cell(210, 7, "LIVE INCIDENT — OBSERVED SECURITY EVENTS", align="C")

    # Stats row
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*TEXT_MID)
    pdf.set_xy(0, 73)
    pdf.cell(210, 8, f"Report #{pdf.report_id}   |   {created_at}", align="C")

    # Threat summary boxes
    y = 100
    for label, value, colour in [
        ("THREATS DETECTED", str(threat_count), RED if threat_count else GREEN),
        ("EVENTS ANALYSED",  str(event_count),  TEXT_MID),
    ]:
        x = 30 + (75 if label == "EVENTS ANALYSED" else 0)
        pdf.set_fill_color(*DARK)
        pdf.set_draw_color(*colour)
        pdf.set_line_width(0.5)
        pdf.rect(x, y, 65, 28, "DF")
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(*colour)
        pdf.set_xy(x, y + 3)
        pdf.cell(65, 14, value, align="C")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*TEXT_MID)
        pdf.set_xy(x, y + 16)
        pdf.cell(65, 8, label, align="C")

    # Confidential notice
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*TEXT_MID)
    pdf.set_xy(0, 140)
    pdf.cell(210, 8, "CONFIDENTIAL  —  FOR AUTHORISED RECIPIENTS ONLY", align="C")

    # Description
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*TEXT_MID)
    pdf.set_xy(30, 152)
    pdf.multi_cell(150, 5,
        "This report was generated by the Boundry.AI automated security monitoring "
        "system. It contains sensitive information about detected threats, attack "
        "patterns, and recommended remediation steps. Do not distribute without "
        "authorisation from Boundry.AI.",
        align="C")


def _render_section_header(pdf: BoundryPDF, title: str):
    """Render a ## section header with green left bar."""
    pdf.ln(4)
    # Green left accent bar
    pdf.set_fill_color(*GREEN)
    pdf.rect(pdf.get_x(), pdf.get_y(), 3, 8, "F")
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*DARK)
    pdf.set_x(pdf.get_x() + 5)
    pdf.cell(0, 8, title.upper(), ln=True)
    # Thin underline
    pdf.set_draw_color(*BORDER)
    pdf.set_line_width(0.3)
    y = pdf.get_y()
    pdf.line(15, y, 195, y)
    pdf.ln(2)


def _render_subsection_header(pdf: BoundryPDF, title: str):
    """Render a ### subsection header."""
    pdf.ln(2)
    colour = _severity_colour(title)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*colour)
    pdf.cell(0, 7, _strip_md(title), ln=True)
    pdf.set_text_color(*TEXT_DARK)


def _render_bullet(pdf: BoundryPDF, text: str, indent: int = 0):
    """Render a bullet point, preserving bold markers."""
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*TEXT_DARK)
    x = pdf.get_x() + (indent * 5)
    pdf.set_x(x + 4)
    # Bullet dot
    pdf.set_fill_color(*GREEN)
    pdf.circle(x + 1, pdf.get_y() + 2.5, 0.8, "F")
    # Handle bold prefix like **Immediate (0-24 hours)**
    bold_match = re.match(r"\*\*(.+?)\*\*[:\s]*(.*)", text)
    if bold_match:
        label, rest = bold_match.group(1), bold_match.group(2)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, label + (":" if rest else ""), ln=True if not rest else False)
        if rest:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_x(x + 4)
            pdf.multi_cell(0, 5, _strip_md(rest))
    else:
        pdf.multi_cell(0, 5, _strip_md(text))


def _render_table(pdf: BoundryPDF, headers: list[str], rows: list[list[str]]):
    """Render a markdown table as a formatted PDF table."""
    if not headers:
        return

    pdf.ln(2)
    col_w   = min(55, (180) // max(len(headers), 1))
    row_h   = 6
    table_w = col_w * len(headers)
    x_start = pdf.get_x()

    # Header row
    pdf.set_fill_color(*DARK)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 8)
    for h in headers:
        pdf.cell(col_w, row_h + 1, h[:20], border=0, fill=True, align="C")
    pdf.ln()

    # Data rows with alternating background
    pdf.set_font("Helvetica", "", 8)
    for i, row in enumerate(rows):
        if pdf.get_y() > 260:
            pdf.add_page()
        bg = LIGHT_BG if i % 2 == 0 else WHITE
        pdf.set_fill_color(*bg)
        pdf.set_text_color(*TEXT_DARK)
        # Pad or trim row to header length
        row = (row + [""] * len(headers))[:len(headers)]
        for cell in row:
            pdf.cell(col_w, row_h, _strip_md(str(cell))[:30], border=0, fill=True)
        pdf.ln()

    # Bottom border
    pdf.set_draw_color(*BORDER)
    pdf.set_line_width(0.2)
    pdf.line(x_start, pdf.get_y(), x_start + table_w, pdf.get_y())
    pdf.ln(3)


def _render_body_text(pdf: BoundryPDF, text: str):
    """Render a paragraph of body text."""
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*TEXT_DARK)
    text = _strip_md(text)
    if text:
        pdf.multi_cell(0, 5, text)
        pdf.ln(1)


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_report_pdf(
    report_id:    int,
    created_at:   str,
    threat_count: int,
    event_count:  int,
    content_md:   str,
    simulated:    bool = False,
) -> bytes:
    """
    Convert a markdown incident report into a branded Boundry.AI PDF.

    Args:
        report_id:    Report database ID (shown in header).
        created_at:   Report creation timestamp string.
        threat_count: Number of threats detected (shown on cover).
        event_count:  Number of events analysed (shown on cover).
        content_md:   Full markdown report content from the AI.

    Returns:
        PDF file as bytes — ready to stream as a download.
    """
    pdf = BoundryPDF(report_id=report_id, created_at=str(created_at)[:16])
    _render_cover(pdf, threat_count, event_count, str(created_at)[:16], simulated=simulated)

    # ── Parse and render markdown ─────────────────────────────────────────────
    pdf.add_page()

    lines       = content_md.splitlines()
    i           = 0
    table_buf   = []
    in_table    = False

    while i < len(lines):
        line = lines[i]

        # Table detection
        if "|" in line and line.strip().startswith("|"):
            if not in_table:
                in_table  = True
                table_buf = []
            table_buf.append(line)
            i += 1
            continue
        elif in_table:
            headers, rows = _parse_table(table_buf)
            _render_table(pdf, headers, rows)
            in_table  = False
            table_buf = []
            # Don't increment — re-process current line

        stripped = line.strip()

        # Section headers
        if stripped.startswith("## "):
            _render_section_header(pdf, stripped[3:])

        elif stripped.startswith("### "):
            _render_subsection_header(pdf, stripped[4:])

        # Horizontal rule
        elif re.match(r"^[-─]{3,}$", stripped):
            pdf.set_draw_color(*BORDER)
            pdf.set_line_width(0.3)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(3)

        # Bullet points (-, *, •)
        elif re.match(r"^[-*•]\s+", stripped):
            text = re.sub(r"^[-*•]\s+", "", stripped)
            _render_bullet(pdf, text, indent=0)

        elif re.match(r"^\s{2,}[-*•]\s+", line):
            text = re.sub(r"^\s+[-*•]\s+", "", line)
            _render_bullet(pdf, text, indent=1)

        # Numbered list
        elif re.match(r"^\d+\.\s+", stripped):
            text = re.sub(r"^\d+\.\s+", "", stripped)
            _render_bullet(pdf, text, indent=0)

        # Blockquote / note
        elif stripped.startswith(">"):
            pdf.set_fill_color(*LIGHT_BG)
            pdf.set_draw_color(*GREEN)
            pdf.set_line_width(0.8)
            note = _strip_md(stripped.lstrip("> ").strip())
            x, y = pdf.get_x(), pdf.get_y()
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(*TEXT_MID)
            pdf.set_x(x + 5)
            pdf.multi_cell(0, 5, note)
            pdf.line(x + 1, y, x + 1, pdf.get_y())
            pdf.ln(1)

        # Blank line
        elif not stripped:
            pdf.ln(1)

        # Regular paragraph text
        else:
            _render_body_text(pdf, stripped)

        i += 1

    # Flush any trailing table
    if in_table and table_buf:
        headers, rows = _parse_table(table_buf)
        _render_table(pdf, headers, rows)

    return bytes(pdf.output())
