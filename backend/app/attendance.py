"""Attendance and individual certificates, calendar invites, the board pack (P6).

- **Attendance**: once the exercise certificate is issued, every person who
  joined by code can receive their own one-page certificate — name, cell,
  hours of participation, decisions answered — carrying the exercise serial
  and an attendee code derived by HMAC from the serial and the join row, so a
  third party can check it through the public verify endpoint without an
  account. Training-credit friendly; contains no scenario content.
- **Calendar invites**: an iCalendar file for a scheduled exercise or a
  planned session, with the join link in the description.
- **Board pack**: the certificate figures and the executive report in one
  PDF, for the people who own the consequences.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from fpdf.enums import XPos, YPos
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .config import BRAND_NAME
from .decisions import participant_scores
from .keys import certificate_key
from .pdf import _BrandedPDF, _accent_rgb, _san


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def attendee_code(serial: str, join_id: int, user_id: int) -> str:
    mac = hmac.new(certificate_key(), f"attendance:{serial}:{join_id}:{user_id}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"AT-{mac[:10].upper()}"


def hours(session: models.Session) -> float | None:
    if not session.started_at:
        return None
    end = _aware(session.completed_at) or datetime.now(timezone.utc)
    h = (end - _aware(session.started_at)).total_seconds() / 3600
    return round(max(h, 0.25), 2)


def record(db: Session, session: models.Session, cert: models.Certificate, join: models.SessionJoin) -> dict:
    user = db.get(models.User, join.user_id)
    scores = {r["user_id"]: r for r in participant_scores(db, session)}
    mine = scores.get(join.user_id, {})
    return {
        "join_id": join.id, "user_id": join.user_id, "display_name": join.display_name or (user.name if user else "") or (user.email if user else ""),
        "email": user.email if user else "", "cell": join.cell, "joined_at": join.joined_at,
        "exercise": session.name, "scenario": cert.payload.get("scenario"), "organization": cert.payload.get("organization"),
        "completed_at": cert.payload.get("completed_at"), "hours": hours(session),
        "responses": mine.get("responses", 0), "mean_score": mine.get("mean_score"),
        "serial": cert.serial, "attendee_code": attendee_code(cert.serial, join.id, join.user_id),
    }


def public_record(rec: dict) -> dict:
    """What a verifier sees about a person: no email, no scores."""
    return {k: rec[k] for k in ("display_name", "cell", "exercise", "organization", "completed_at", "hours", "responses", "serial", "attendee_code")}


def verify_attendee(db: Session, session: models.Session, cert: models.Certificate, code: str) -> dict | None:
    code = (code or "").strip().upper()
    for j in db.execute(select(models.SessionJoin).where(models.SessionJoin.session_id == session.id)).scalars():
        if hmac.compare_digest(attendee_code(cert.serial, j.id, j.user_id), code):
            return record(db, session, cert, j)
    return None


def render_attendance_pdf(rec: dict, verify_path: str, brand: str | None = None) -> bytes:
    pdf = _BrandedPDF(brand or BRAND_NAME)
    pdf.set_title(f"Attendance {rec['attendee_code']}")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=False)
    pdf.add_page()
    ink, grey = (21, 25, 28), (91, 100, 105)
    r, g, b = _accent_rgb()
    pdf.set_font("Courier", "B", 8); pdf.set_text_color(*grey)
    pdf.cell(0, 5, "CERTIFICATE OF PARTICIPATION", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)
    pdf.set_font("Helvetica", "", 11); pdf.set_text_color(*ink)
    pdf.cell(0, 6, "This certifies that", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "B", 24)
    pdf.multi_cell(0, 11, _san(rec["display_name"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    when = rec.get("completed_at") or ""
    try:
        when = datetime.fromisoformat(when).strftime("%d %B %Y")
    except (TypeError, ValueError):
        when = when[:10]
    pdf.multi_cell(0, 6, _san(
        f"took part in the facilitated cyber exercise \"{rec['exercise']}\" ({rec.get('scenario') or ''}) "
        f"run by {rec.get('organization') or ''} on {when}, in the {rec['cell'].replace('_cell', '').replace('_', ' ')} cell."),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)
    tiles = [("HOURS OF PARTICIPATION", f"{rec['hours']:g}" if rec.get("hours") is not None else "n/a"),
             ("DECISIONS ANSWERED", str(rec.get("responses", 0))),
             ("EXERCISE CERTIFICATE", rec["serial"])]
    x0, y0 = pdf.l_margin, pdf.get_y()
    w = (pdf.epw - 2 * 4) / 3
    for i, (label, value) in enumerate(tiles):
        x = x0 + i * (w + 4)
        pdf.set_draw_color(*ink); pdf.set_line_width(0.5); pdf.rect(x, y0, w, 24)
        pdf.set_fill_color(r, g, b); pdf.rect(x, y0, 3, 3, style="F")
        pdf.set_xy(x + 3, y0 + 4); pdf.set_font("Helvetica", "B", 14 if len(value) < 12 else 10); pdf.set_text_color(*ink)
        pdf.cell(w - 6, 9, _san(value))
        pdf.set_xy(x + 3, y0 + 15); pdf.set_font("Courier", "", 6.5); pdf.set_text_color(*grey)
        pdf.cell(w - 6, 5, label)
    pdf.set_y(y0 + 32)
    pdf.set_font("Helvetica", "", 9); pdf.set_text_color(*ink)
    pdf.multi_cell(0, 5, _san(
        "Participation is recorded on the exercise's signed timeline. Hours are wall-clock time between the "
        "exercise starting and completing. This certificate names the person and the exercise and carries no "
        "scenario content; it may be presented for continuing-education credit at the discretion of the awarding body."),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)
    pdf.set_font("Courier", "", 8)
    for k, v in (("Attendee code", rec["attendee_code"]), ("Exercise serial", rec["serial"]), ("Verify", verify_path)):
        pdf.cell(36, 5, _san(k)); pdf.multi_cell(pdf.epw - 36, 5, _san(v), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    return bytes(pdf.output())


# --------------------------------------------------------------------------- #
# calendar invites
# --------------------------------------------------------------------------- #
def _ics_dt(dt: datetime) -> str:
    return _aware(dt).astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _ics_escape(text: str) -> str:
    return str(text or "").replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def ics(uid: str, title: str, start: datetime, hours_: float, description: str, location: str = "") -> str:
    end = _aware(start) + timedelta(hours=hours_ or 2)
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", f"PRODID:-//{BRAND_NAME}//Exercise Control//EN", "METHOD:PUBLISH",
             "BEGIN:VEVENT", f"UID:{uid}", f"DTSTAMP:{_ics_dt(datetime.now(timezone.utc))}",
             f"DTSTART:{_ics_dt(start)}", f"DTEND:{_ics_dt(end)}", f"SUMMARY:{_ics_escape(title)}",
             f"DESCRIPTION:{_ics_escape(description)}"]
    if location:
        lines.append(f"LOCATION:{_ics_escape(location)}")
    lines += ["BEGIN:VALARM", "TRIGGER:-PT30M", "ACTION:DISPLAY", f"DESCRIPTION:{_ics_escape(title)}", "END:VALARM",
              "END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(lines) + "\r\n"


# --------------------------------------------------------------------------- #
# board pack
# --------------------------------------------------------------------------- #
def board_pack_markdown(cert: models.Certificate, executive_md: str, verify_path: str) -> str:
    p = cert.payload
    pct = lambda v: "n/a" if v is None else f"{int(v * 100 + 0.5)}%"  # noqa: E731
    imp = p.get("impact") or {}
    head = [f"# Board pack — {p.get('exercise', '')}", "",
            f"_{p.get('organization', '')} · {p.get('scenario', '')} · {p.get('environment', '')} · certificate {cert.serial}_", "",
            "> An exercise record, not a compliance attestation. The figures were frozen and signed when the certificate "
            f"was issued; verify at {verify_path}", "",
            "## The number", "", "| | |", "|---|---|",
            f"| Detection rate | **{pct(p.get('detection_rate'))}** |",
            f"| Mean time to detect | **{p.get('mean_time_to_detect_min') if p.get('mean_time_to_detect_min') is not None else 'n/a'} min** |",
            f"| Objectives met | **{pct((p.get('objectives') or {}).get('met_rate'))}** |",
            f"| Techniques exercised | **{len(p.get('techniques_exercised') or [])}** |",
            f"| Participants | **{p.get('participants', 0)}** |"]
    if imp:
        from .impact import money
        head.append(f"| Estimated impact of the path taken | **{money(imp.get('cost', 0))}"
                    + (f", {imp.get('downtime_hours')} h downtime" if imp.get("downtime_hours") is not None else "") + "** |")
    head += ["", "---", ""]
    body = executive_md.split("\n", 1)[1] if executive_md.startswith("#") else executive_md
    return "\n".join(head) + body
