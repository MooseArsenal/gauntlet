"""Render a report / evidence pack (our lightweight markdown) to PDF bytes.

Uses fpdf2 with the built-in core fonts, so there is nothing to install at the
OS level. Text is sanitised to the Latin-1 range the core fonts support.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from .config import BRAND_ACCENT, BRAND_NAME

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


def _accent_rgb() -> tuple[int, int, int]:
    try:
        r, g, b = (int(x) for x in BRAND_ACCENT.split(",")[:3])
        return r, g, b
    except (ValueError, TypeError):
        return 217, 72, 15


class _BrandedPDF(FPDF):
    """A4 report with a branded header rule and a footer carrying the brand
    name, an export timestamp, and page numbers — a consistent, white-labelable
    template for every exported document."""

    def __init__(self, brand: str, accent: tuple[int, int, int] | None = None, footer: str = "") -> None:
        super().__init__(format="A4")
        self._brand = brand
        self._accent = accent
        self._footer = footer
        self._stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def header(self) -> None:
        # The banner strip from the console, in print: ink bar, mono caps.
        self.set_fill_color(21, 25, 28)
        self.rect(0, 0, self.w, 7, style="F")
        self.set_y(1.6)
        self.set_font("Courier", "B", 7)
        self.set_text_color(238, 240, 238)
        self.cell(self.epw / 2, 4, _san(f"EXERCISE CONTROL - {self._brand.upper()}"), align="L")
        self.cell(self.epw / 2, 4, "FACILITATED EXERCISE - NO PRODUCTION ACCESS", align="R",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_y(11)
        # Signal-colour tick, then a hard ink rule: the page reads as a document.
        r, g, b = self._accent or _accent_rgb()
        self.set_fill_color(r, g, b)
        self.rect(self.l_margin, self.get_y(), 3, 3, style="F")
        self.set_draw_color(21, 25, 28)
        self.set_line_width(0.6)
        self.line(self.l_margin, self.get_y() + 5, self.w - self.r_margin, self.get_y() + 5)
        self.set_text_color(0)
        self.set_y(self.get_y() + 9)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_draw_color(21, 25, 28)
        self.set_line_width(0.3)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.set_y(-10)
        self.set_font("Courier", "", 7)
        self.set_text_color(91, 100, 105)
        self.cell(0, 5, _san(f"{self._brand} - generated {self._stamp}" + (f" - {self._footer}" if self._footer else "")), align="L")
        self.cell(0, 5, f"Page {self.page_no()}/{{nb}}", align="R")
        self.set_text_color(0)


def render(title: str, markdown: str, brand: str | None = None, accent: tuple[int, int, int] | None = None,
           footer: str = "") -> bytes:
    pdf = _BrandedPDF(brand or BRAND_NAME, accent, footer)
    pdf.set_title(title[:120])
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
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
