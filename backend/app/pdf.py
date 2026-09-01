"""Render a report / evidence pack (our lightweight markdown) to PDF bytes.

Uses fpdf2 with the built-in core fonts, so there is nothing to install at the
OS level. Text is sanitised to the Latin-1 range the core fonts support.
"""
from __future__ import annotations

import re

from fpdf import FPDF
from fpdf.enums import XPos, YPos

_REPLACE = {
    "—": "-", "–": "-", "•": "-", "→": "->", "←": "<-", "“": '"', "”": '"',
    "‘": "'", "’": "'", "…": "...", "≥": ">=", "≤": "<=", "×": "x", "✓": "[ok]",
    "✗": "[x]", "⚑": "*", "·": "-", "⛨": "", "◑": "",
}
_EMPH = re.compile(r"[*`_]{1,2}")


def _san(text: str) -> str:
    for k, v in _REPLACE.items():
        text = text.replace(k, v)
    text = _EMPH.sub("", text)
    return text.encode("latin-1", "replace").decode("latin-1")


def _table_block(lines: list[str], start: int) -> tuple[list[list[str]], int]:
    rows, i = [], start
    while i < len(lines) and lines[i].strip().startswith("|"):
        cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
        if not re.match(r"^[-:\s]+$", "".join(cells)):  # skip the --- separator row
            rows.append(cells)
        i += 1
    return rows, i


def render(title: str, markdown: str) -> bytes:
    pdf = FPDF(format="A4")
    pdf.set_title(title[:120])
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    lines = markdown.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        if line.strip().startswith("|"):
            rows, i = _table_block(lines, i)
            if rows:
                pdf.set_font("Helvetica", size=8)
                with pdf.table(width=pdf.epw, line_height=5, first_row_as_headings=True) as table:
                    for r in rows:
                        row = table.row()
                        for cell in r:
                            row.cell(_san(cell))
                pdf.ln(2)
            continue

        # Always return the cursor to the left margin so consecutive blocks
        # (e.g. two bullets) don't start with zero available width.
        nx, ny = XPos.LMARGIN, YPos.NEXT

        stripped = line.strip()
        if stripped.startswith("### "):
            pdf.set_font("Helvetica", "B", 11); pdf.multi_cell(0, 6, _san(stripped[4:]), new_x=nx, new_y=ny); pdf.ln(1)
        elif stripped.startswith("## "):
            pdf.set_font("Helvetica", "B", 13); pdf.multi_cell(0, 7, _san(stripped[3:]), new_x=nx, new_y=ny); pdf.ln(1)
        elif stripped.startswith("# "):
            pdf.set_font("Helvetica", "B", 16); pdf.multi_cell(0, 9, _san(stripped[2:]), new_x=nx, new_y=ny); pdf.ln(2)
        elif stripped.startswith(">"):
            pdf.set_font("Helvetica", "I", 9); pdf.set_text_color(90)
            pdf.multi_cell(0, 5, _san(stripped.lstrip("> ")), new_x=nx, new_y=ny); pdf.set_text_color(0); pdf.ln(1)
        elif stripped.startswith(("- ", "* ")):
            pdf.set_font("Helvetica", size=10); pdf.multi_cell(0, 5, "  - " + _san(stripped[2:]), new_x=nx, new_y=ny)
        elif stripped == "":
            pdf.ln(2)
        else:
            pdf.set_font("Helvetica", size=10); pdf.multi_cell(0, 5, _san(stripped), new_x=nx, new_y=ny)
        i += 1

    return bytes(pdf.output())
