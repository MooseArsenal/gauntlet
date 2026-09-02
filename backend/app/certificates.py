"""Exercise certificates (M1): the number, signed.

A tabletop's output is usually a slide deck nobody can check. A certificate
freezes what one completed exercise actually produced — detection rate, mean
time-to-detect, objectives met, techniques exercised, the signed head of the
tamper-evident timeline — and signs it, so an auditor, insurer or board member
can verify the figures against the serial without an account and without
seeing a word of the scenario.

The payload carries counts and identifiers only: organisation and scenario
names, the environment's name and sector, the cells that played. No inject
narrative, no observations, no personal data.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

from fpdf.enums import XPos, YPos

from . import models
from .engine.reporting import _metrics
from .keys import certificate_key
from .pdf import _BrandedPDF, _accent_rgb, _san
from .config import BRAND_NAME
from .timeline import verify_chain

_RATING_WEIGHT = {"met": 1.0, "partial": 0.5, "missed": 0.0}


def new_serial() -> str:
    """GC-YYYY-XXXXXXXX: readable, unguessable (40 bits of randomness)."""
    year = datetime.now(timezone.utc).year
    return f"GC-{year}-{secrets.token_hex(4).upper()}"


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_of(payload: dict) -> str:
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def sign(serial: str, digest: str, key: bytes | None = None) -> str:
    key = key or certificate_key()
    return hmac.new(key, f"certificate:{serial}:{digest}".encode("utf-8"), hashlib.sha256).hexdigest()


def _objectives(scenario: models.Scenario, observations) -> dict:
    by_obj: dict[str, list[str]] = {}
    for o in observations:
        if o.rating in _RATING_WEIGHT:
            by_obj.setdefault(o.objective_code, []).append(o.rating)
    met = partial = missed = 0
    for obj in scenario.objectives:
        ratings = by_obj.get(obj.code, [])
        if not ratings:
            continue
        if "missed" in ratings:
            missed += 1
        elif "partial" in ratings:
            partial += 1
        else:
            met += 1
    total = len(scenario.objectives)
    assessed = met + partial + missed
    return {"total": total, "assessed": assessed, "met": met, "partial": partial, "missed": missed,
            "met_rate": round((met + 0.5 * partial) / assessed, 3) if assessed else None}


def _telemetry_block(session: models.Session) -> dict | None:
    """Observed detections (M4), only when real alerts were recorded."""
    from . import telemetry
    cmp = telemetry.compare(session)
    if not cmp["alerts"]:
        return None
    return {"alerts": cmp["alerts"], "observed_rate": cmp["observed_rate"],
            "model_agreement": cmp["model_agreement"], **cmp["counts"]}


def _decisions_block(session: models.Session) -> dict | None:
    """Participant decisions (P1), only when anyone answered a card."""
    from .decisions import summary
    d = summary(list(session.events))
    return d if d["responses"] else None


def build_payload(org: models.Organization, session: models.Session, scenario: models.Scenario,
                  environment: models.Environment, participants: int) -> dict:
    events = list(session.events)
    m = _metrics(events)
    red = [e for e in events if e.kind == "red_action"]
    red_detected = sum(1 for e in red if e.payload.get("detected"))
    adjudicated = m["adjudications"] + len(red)
    detected = m["detected"] + red_detected
    techniques = sorted(set(m["techniques_exercised"]) | {
        t for e in red for t in (e.payload.get("techniques") or [])})
    gaps = sorted(set(m["coverage_gaps"]) | {
        t for e in red if not e.payload.get("detected") for t in (e.payload.get("techniques") or [])})
    started = session.started_at or session.created_at
    return {
        "version": 1,
        "organization": org.name,
        "exercise": session.name,
        "scenario": scenario.name,
        "exercise_type": scenario.exercise_type,
        "threat_actor": scenario.threat_actor or "",
        "environment": environment.name,
        "sector": environment.sector or "",
        "cells": [c.get("name") or c.get("key") for c in (scenario.cells or [])],
        "participants": participants,
        "started_at": started.isoformat() if started else None,
        "completed_at": session.completed_at.isoformat() if session.completed_at else None,
        "injects": m["injects"],
        "decisions": m["decisions"],
        "adversary_actions": adjudicated,
        "detected": detected,
        "missed": adjudicated - detected,
        "detection_rate": round(detected / adjudicated, 3) if adjudicated else None,
        "mean_time_to_detect_min": m["mttd"],
        "techniques_exercised": techniques,
        "coverage_gaps": gaps,
        "objectives": _objectives(scenario, list(session.observations)),
        "telemetry": _telemetry_block(session),
        "participant_decisions": _decisions_block(session),
        "impact": (__import__("app.impact", fromlist=["summary"]).summary(events, session.state)["totals"] or None),
        "timeline_events": len(events),
        "timeline_head": {"seq": session.head_seq, "hash": session.head_hash},
        "chain_verified": verify_chain(events, session),
    }


def issue(org, session, scenario, environment, participants: int, issued_by: str) -> models.Certificate:
    payload = build_payload(org, session, scenario, environment, participants)
    serial = new_serial()
    digest = digest_of(payload)
    return models.Certificate(org_id=org.id, session_id=session.id, serial=serial,
                              issued_by=issued_by, payload=payload, digest=digest,
                              signature=sign(serial, digest))


def check(cert: models.Certificate) -> tuple[bool, str]:
    """Recompute the digest from the stored payload and the signature from the
    serial + digest. Any edit to the numbers, or a forged row, fails."""
    if cert.revoked_at is not None:
        return False, "revoked"
    if digest_of(cert.payload) != cert.digest:
        return False, "payload does not match its digest"
    if not hmac.compare_digest(sign(cert.serial, cert.digest), cert.signature):
        return False, "signature does not verify"
    return True, "ok"


def public_record(cert: models.Certificate) -> dict:
    """What a verifier sees: the signed numbers, never the session."""
    p = cert.payload
    return {k: p.get(k) for k in (
        "organization", "exercise", "scenario", "exercise_type", "environment", "sector", "cells",
        "participants", "started_at", "completed_at", "injects", "adversary_actions", "detected",
        "missed", "detection_rate", "mean_time_to_detect_min", "techniques_exercised",
        "objectives", "telemetry", "participant_decisions", "impact", "timeline_events", "timeline_head", "chain_verified")}


# --------------------------------------------------------------------------- #
# The one-page PDF
# --------------------------------------------------------------------------- #
def _pct(v) -> str:
    return "n/a" if v is None else f"{int(v * 100 + 0.5)}%"  # half-up, like the console


def _date(iso: str | None) -> str:
    if not iso:
        return "n/a"
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %Y")
    except ValueError:
        return iso[:10]


def render_pdf(cert: models.Certificate, verify_path: str, brand: str | None = None) -> bytes:
    p = cert.payload
    pdf = _BrandedPDF(brand or BRAND_NAME)
    pdf.set_title(f"Exercise certificate {cert.serial}")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=False)
    pdf.add_page()
    ink = (21, 25, 28)
    grey = (91, 100, 105)
    r, g, b = _accent_rgb()

    pdf.set_font("Courier", "B", 8); pdf.set_text_color(*grey)
    pdf.cell(0, 5, "EXERCISE CERTIFICATE", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "B", 22); pdf.set_text_color(*ink)
    pdf.multi_cell(0, 10, _san(p.get("organization", "")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(0, 6, _san(
        f"completed the facilitated cyber exercise \"{p.get('exercise', '')}\" "
        f"({p.get('scenario', '')}) on {_date(p.get('completed_at'))}."),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Four ink-boxed figures: the number is the product.
    tiles = [
        ("DETECTION RATE", _pct(p.get("detection_rate"))),
        ("MEAN TIME TO DETECT",
         "n/a" if p.get("mean_time_to_detect_min") is None else f"{p['mean_time_to_detect_min']} min"),
        ("OBJECTIVES MET", _pct((p.get("objectives") or {}).get("met_rate"))),
        ("TECHNIQUES EXERCISED", str(len(p.get("techniques_exercised") or []))),
    ]
    x0, y0 = pdf.l_margin, pdf.get_y()
    w = (pdf.epw - 3 * 4) / 4
    for i, (label, value) in enumerate(tiles):
        x = x0 + i * (w + 4)
        pdf.set_draw_color(*ink); pdf.set_line_width(0.5)
        pdf.rect(x, y0, w, 24)
        pdf.set_fill_color(r, g, b); pdf.rect(x, y0, 3, 3, style="F")
        pdf.set_xy(x + 3, y0 + 4); pdf.set_font("Helvetica", "B", 16); pdf.set_text_color(*ink)
        pdf.cell(w - 6, 9, _san(value))
        pdf.set_xy(x + 3, y0 + 15); pdf.set_font("Courier", "", 6.5); pdf.set_text_color(*grey)
        pdf.cell(w - 6, 5, label)
    pdf.set_y(y0 + 30)

    # The record
    pdf.set_font("Courier", "B", 8); pdf.set_text_color(*grey)
    pdf.cell(0, 5, "THE RECORD", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*ink); pdf.set_line_width(0.6)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y()); pdf.ln(2)
    obj = p.get("objectives") or {}
    rows = [
        ("Environment under test", f"{p.get('environment', '')} ({p.get('sector', '') or 'n/a'})"),
        ("Threat modelled", p.get("threat_actor") or "n/a"),
        ("Exercise type", p.get("exercise_type") or "n/a"),
        ("Cells", ", ".join(p.get("cells") or []) or "n/a"),
        ("Participants joined by code", str(p.get("participants", 0))),
        ("Injects delivered", str(p.get("injects", 0))),
        ("Adversary actions adjudicated", f"{p.get('adversary_actions', 0)} ({p.get('detected', 0)} detected, {p.get('missed', 0)} missed)"),
        ("Objectives", f"{obj.get('met', 0)} met, {obj.get('partial', 0)} partial, {obj.get('missed', 0)} not met, of {obj.get('total', 0)} ({obj.get('assessed', 0)} assessed)"),
        ("ATT&CK techniques exercised", ", ".join(p.get("techniques_exercised") or []) or "none"),
        ("Undetected techniques", ", ".join(p.get("coverage_gaps") or []) or "none"),
        ("Timeline", f"{p.get('timeline_events', 0)} signed events; chain "
                     + ("verified intact at issue" if p.get("chain_verified") else "NOT verified")),
        ("Timeline head", f"#{(p.get('timeline_head') or {}).get('seq')} {(p.get('timeline_head') or {}).get('hash') or ''}"),
    ]
    for k, v in rows:
        pdf.set_font("Helvetica", "B", 9); pdf.set_text_color(*ink)
        pdf.cell(58, 6, _san(k))
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(pdf.epw - 58, 6, _san(v), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Attestation block
    pdf.set_font("Courier", "B", 8); pdf.set_text_color(*grey)
    pdf.cell(0, 5, "ATTESTATION", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y()); pdf.ln(2)
    pdf.set_font("Helvetica", "", 9); pdf.set_text_color(*ink)
    pdf.multi_cell(0, 5, _san(
        "The figures above were computed from the exercise's append-only, hash-chained timeline "
        "and the evaluators' ratings at the moment of issue, then frozen and signed. They describe "
        "one facilitated exercise against a modelled environment; they are an exercise record, "
        "not a compliance attestation and not a measure of production security."),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    pdf.set_font("Courier", "", 8)
    for k, v in (("Serial", cert.serial),
                 ("Issued", cert.issued_at.strftime("%Y-%m-%d %H:%M UTC") if cert.issued_at else ""),
                 ("Issued by", cert.issued_by or ""),
                 ("Digest (SHA-256)", cert.digest),
                 ("Signature (HMAC-SHA-256)", cert.signature),
                 ("Verify", verify_path)):
        pdf.cell(44, 5, _san(k)); pdf.multi_cell(pdf.epw - 44, 5, _san(v), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    return bytes(pdf.output())
