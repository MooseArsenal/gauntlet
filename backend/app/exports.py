"""Additional export formats (F1): CSV, JSON, and DOCX.

The product already renders reports and compliance evidence to Markdown and PDF.
These add the formats stakeholders actually ask for downstream:

* **CSV** timeline — drop the record straight into a spreadsheet or SIEM import.
* **JSON** timeline — a structured, machine-readable session export (integrations,
  archival, external analysis).
* **DOCX** — an editable document, so a GRC lead can adapt a report in Word.

All are pure transforms over data the caller already owns; the API layer handles
tenant scoping and audit.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime

from . import models


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


# --------------------------------------------------------------------------- #
# timeline exports
# --------------------------------------------------------------------------- #
_CSV_COLUMNS = ("seq", "at", "game_clock", "kind", "ref", "payload", "hash")


def timeline_csv(events: list[models.TimelineEvent]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUMNS)
    for e in sorted(events, key=lambda x: x.seq):
        writer.writerow([
            e.seq,
            _iso(e.at),
            e.game_clock or "",
            e.kind,
            e.ref or "",
            json.dumps(e.payload, separators=(",", ":"), sort_keys=True),
            e.hash,
        ])
    return buf.getvalue()


def timeline_json(session: models.Session, scenario: models.Scenario,
                  events: list[models.TimelineEvent],
                  observations: list[models.Observation]) -> dict:
    """A structured, self-describing session export."""
    return {
        "session": {
            "id": session.id,
            "name": session.name,
            "status": session.status,
            "mode": session.mode,
            "created_at": _iso(session.created_at),
            "completed_at": _iso(session.completed_at),
        },
        "scenario": {
            "id": scenario.id,
            "name": scenario.name,
            "threat_actor": scenario.threat_actor,
        },
        "timeline": [
            {
                "seq": e.seq,
                "at": _iso(e.at),
                "game_clock": e.game_clock,
                "kind": e.kind,
                "ref": e.ref,
                "payload": e.payload,
                "prev_hash": e.prev_hash,
                "hash": e.hash,
            }
            for e in sorted(events, key=lambda x: x.seq)
        ],
        "observations": [
            {
                "objective_code": o.objective_code,
                "rating": o.rating,
                "note": o.note,
                "timeline_seq": o.timeline_seq,
                "created_at": _iso(o.created_at),
            }
            for o in observations
        ],
    }


# --------------------------------------------------------------------------- #
# DOCX (from our lightweight Markdown)
# --------------------------------------------------------------------------- #
_EMPH = re.compile(r"[*`_]{1,2}")


def _clean(text: str) -> str:
    return _EMPH.sub("", text)


def markdown_to_docx(title: str, markdown: str) -> bytes:
    """Render the same lightweight Markdown the PDF path uses into a .docx.

    Supports headings (#/##/###), bullets, blockquotes, and pipe tables — the
    subset our reports and evidence packs actually emit.
    """
    from docx import Document
    from docx.shared import Pt

    doc = Document()
    doc.core_properties.title = title[:120]
    doc.add_heading(title, level=0)

    lines = markdown.split("\n")
    i = 0
    while i < len(lines):
        raw = lines[i].rstrip()
        stripped = raw.strip()

        if stripped.startswith("|"):
            rows, i = _collect_table(lines, i)
            if rows:
                _add_table(doc, rows)
            continue

        if stripped.startswith("### "):
            doc.add_heading(_clean(stripped[4:]), level=3)
        elif stripped.startswith("## "):
            doc.add_heading(_clean(stripped[3:]), level=2)
        elif stripped.startswith("# "):
            doc.add_heading(_clean(stripped[2:]), level=1)
        elif stripped.startswith(">"):
            p = doc.add_paragraph(_clean(stripped.lstrip("> ")))
            p.style = doc.styles["Quote"] if "Quote" in doc.styles else p.style
        elif stripped.startswith(("- ", "* ")):
            doc.add_paragraph(_clean(stripped[2:]), style="List Bullet")
        elif stripped == "":
            pass
        else:
            para = doc.add_paragraph(_clean(stripped))
            for run in para.runs:
                run.font.size = Pt(10)
        i += 1

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _collect_table(lines: list[str], start: int) -> tuple[list[list[str]], int]:
    rows, i = [], start
    while i < len(lines) and lines[i].strip().startswith("|"):
        cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
        if not re.match(r"^[-:\s]+$", "".join(cells)):  # skip the |---| separator
            rows.append(cells)
        i += 1
    return rows, i


def _add_table(doc, rows: list[list[str]]) -> None:
    cols = max(len(r) for r in rows)
    table = doc.add_table(rows=0, cols=cols)
    table.style = "Light Grid Accent 1" if "Light Grid Accent 1" in [s.name for s in doc.styles] else "Table Grid"
    for r in rows:
        cells = table.add_row().cells
        for idx in range(cols):
            cells[idx].text = _clean(r[idx]) if idx < len(r) else ""
