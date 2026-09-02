"""Real inject delivery (P2): the phishing inject lands in the inbox.

The preview renderer (``authoring.delivery``) shows what an inject would look
like as an email, a chat message or an alert. This module sends it: over
SMTP to the people who joined the addressed cells (plus any extra addresses
the facilitator names), and to a Slack or Teams channel through an incoming
webhook. Every sender is operator-configured by environment variable — a
request can name recipients, never a server — and every send passes the
air-gap guard, so an air-gapped deployment refuses fail-closed and records
that it did. Deliveries are timeline events (``kind="delivery"``) the
participants never see.

Configuration::

    GAUNTLET_SMTP_HOST / GAUNTLET_SMTP_PORT (587) / GAUNTLET_SMTP_USER /
    GAUNTLET_SMTP_PASSWORD / GAUNTLET_SMTP_FROM / GAUNTLET_SMTP_STARTTLS (1)
    GAUNTLET_SLACK_WEBHOOK   (incoming webhook URL)
    GAUNTLET_TEAMS_WEBHOOK   (incoming webhook URL)
    GAUNTLET_NOTIFY_WEBHOOK  (generic JSON webhook, already used for reminders)
"""
from __future__ import annotations

import os
import re
import smtplib
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import egress, models
from .authoring import delivery as preview
from .engine import visibility
from .timeline import append_event

CHANNELS = ("email", "slack", "teams", "webhook")
MAX_RECIPIENTS = 200
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def configured() -> dict[str, bool]:
    """Which senders the operator has configured."""
    return {
        "email": bool(_env("GAUNTLET_SMTP_HOST")),
        "slack": bool(_env("GAUNTLET_SLACK_WEBHOOK")),
        "teams": bool(_env("GAUNTLET_TEAMS_WEBHOOK")),
        "webhook": bool(_env("GAUNTLET_NOTIFY_WEBHOOK")),
    }


# --------------------------------------------------------------------------- #
# content
# --------------------------------------------------------------------------- #
def inject_message(inject, session: models.Session, base_url: str, include_link: bool) -> dict:
    """Subject + plain-text body for one inject, channel-flavoured."""
    d = preview.render(inject)
    lines = [d["headline"], ""]
    for k, v in d["fields"].items():
        lines.append(f"{k}: {v}")
    lines += ["", d["body"] or ""]
    if d["expected_actions"]:
        lines += ["", "Consider:"] + [f"- {a}" for a in d["expected_actions"]]
    if include_link:
        lines += ["", f"Answer in the exercise: {base_url}/participant.html?session={session.id}"]
    lines += ["", f"[{session.name} — facilitated exercise; no production access; all actions are simulated]"]
    subject = d["fields"].get("Subject") or d["fields"].get("Rule") or d["headline"]
    return {"subject": f"[Exercise] {subject}", "text": "\n".join(lines), "channel": d["channel"]}


def invite_message(session: models.Session, base_url: str, message: str = "") -> dict:
    code = session.join_code or ""
    lines = [f"You are invited to the exercise \"{session.name}\".", ""]
    if message:
        lines += [message, ""]
    lines += [f"Join code: {code}", f"Join here: {base_url}/join.html", "",
              "Pick your cell when you join. This is a facilitated exercise: no production access; all actions are simulated."]
    return {"subject": f"[Exercise] Join code for {session.name}", "text": "\n".join(lines)}


# --------------------------------------------------------------------------- #
# senders (each returns an error string, or "" on success)
# --------------------------------------------------------------------------- #
def send_email(recipients: list[str], subject: str, text: str) -> str:
    host = _env("GAUNTLET_SMTP_HOST")
    if not host:
        return "SMTP is not configured"
    if not recipients:
        return "no recipients"
    try:
        egress.guard("smtp delivery")
        msg = EmailMessage()
        msg["From"] = _env("GAUNTLET_SMTP_FROM", "exercise-control@localhost")
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg.set_content(text)
        port = int(_env("GAUNTLET_SMTP_PORT", "587") or "587")
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if _env("GAUNTLET_SMTP_STARTTLS", "1") not in ("0", "false", "False"):
                smtp.starttls()
            user, pw = _env("GAUNTLET_SMTP_USER"), _env("GAUNTLET_SMTP_PASSWORD")
            if user:
                smtp.login(user, pw)
            smtp.send_message(msg)
        return ""
    except Exception as e:  # noqa: BLE001 - delivery is best-effort and recorded
        return str(e)[:200]


def _post(url: str, payload: dict, purpose: str) -> str:
    if not url:
        return f"{purpose} is not configured"
    try:
        import httpx

        egress.guard(purpose)
        r = httpx.post(url, json=payload, timeout=8.0)
        return "" if r.status_code < 300 else f"HTTP {r.status_code}"
    except Exception as e:  # noqa: BLE001
        return str(e)[:200]


def send_slack(subject: str, text: str) -> str:
    return _post(_env("GAUNTLET_SLACK_WEBHOOK"), {"text": f"*{subject}*\n{text}"}, "slack delivery")


def send_teams(subject: str, text: str) -> str:
    return _post(_env("GAUNTLET_TEAMS_WEBHOOK"),
                 {"@type": "MessageCard", "@context": "https://schema.org/extensions",
                  "summary": subject, "title": subject, "text": text.replace("\n", "<br>")}, "teams delivery")


def send_webhook(payload: dict) -> str:
    return _post(_env("GAUNTLET_NOTIFY_WEBHOOK"), payload, "webhook delivery")


# --------------------------------------------------------------------------- #
# recipients + orchestration
# --------------------------------------------------------------------------- #
def cell_recipients(db: Session, session: models.Session, cells: list[str]) -> list[str]:
    """Email addresses of the people who joined the named cells."""
    rows = db.execute(
        select(models.User.email).join(models.SessionJoin, models.SessionJoin.user_id == models.User.id)
        .where(models.SessionJoin.session_id == session.id, models.SessionJoin.cell.in_(cells),
               models.User.is_active.is_(True))
    ).all()
    return sorted({r[0].lower() for r in rows})


def valid_emails(values) -> list[str]:
    out = []
    for v in values or []:
        v = str(v).strip().lower()
        if _EMAIL.match(v):
            out.append(v)
    return sorted(set(out))[:MAX_RECIPIENTS]


def deliver_inject(db: Session, session: models.Session, scenario: models.Scenario, inject, *, channels: list[str],
                   cells: list[str], extra_emails: list[str], base_url: str, include_link: bool, actor: str) -> dict:
    """Send one inject over the chosen channels and record the outcome."""
    cells = [c for c in cells if visibility.is_control_cell(scenario, c)
             or visibility.inject_visible_to(inject.visible_to or [], c)]
    msg = inject_message(inject, session, base_url, include_link)
    recipients = sorted(set(cell_recipients(db, session, cells)) | set(valid_emails(extra_emails)))[:MAX_RECIPIENTS]
    results = {}
    for ch in channels:
        if ch == "email":
            results["email"] = {"ok": False, "error": "no recipients", "recipients": 0} if not recipients else \
                {"ok": (err := send_email(recipients, msg["subject"], msg["text"])) == "", "error": err, "recipients": len(recipients)}
        elif ch == "slack":
            err = send_slack(msg["subject"], msg["text"]); results["slack"] = {"ok": err == "", "error": err}
        elif ch == "teams":
            err = send_teams(msg["subject"], msg["text"]); results["teams"] = {"ok": err == "", "error": err}
        elif ch == "webhook":
            err = send_webhook({"type": "inject", "session_id": session.id, "inject_code": inject.code,
                                "subject": msg["subject"], "text": msg["text"], "cells": cells})
            results["webhook"] = {"ok": err == "", "error": err}
    payload = {"inject_code": inject.code, "channels": results, "cells": cells, "recipients": len(recipients),
               "delivered": any(r["ok"] for r in results.values()), "by": actor}
    append_event(db, session.id, kind="delivery", ref=inject.code, game_clock=inject.clock or "", payload=payload)
    return payload


def send_invites(db: Session, session: models.Session, *, channels: list[str], cells: list[str], extra_emails: list[str],
                 base_url: str, message: str, actor: str) -> dict:
    msg = invite_message(session, base_url, message)
    recipients = sorted(set(cell_recipients(db, session, cells) if cells else []) | set(valid_emails(extra_emails)))[:MAX_RECIPIENTS]
    results = {}
    for ch in channels:
        if ch == "email":
            results["email"] = {"ok": False, "error": "no recipients", "recipients": 0} if not recipients else \
                {"ok": (err := send_email(recipients, msg["subject"], msg["text"])) == "", "error": err, "recipients": len(recipients)}
        elif ch == "slack":
            err = send_slack(msg["subject"], msg["text"]); results["slack"] = {"ok": err == "", "error": err}
        elif ch == "teams":
            err = send_teams(msg["subject"], msg["text"]); results["teams"] = {"ok": err == "", "error": err}
        elif ch == "webhook":
            err = send_webhook({"type": "invite", "session_id": session.id, "join_code": session.join_code,
                                "subject": msg["subject"], "text": msg["text"]})
            results["webhook"] = {"ok": err == "", "error": err}
    payload = {"invite": True, "channels": results, "recipients": len(recipients),
               "delivered": any(r["ok"] for r in results.values()), "by": actor}
    append_event(db, session.id, kind="delivery", ref="invite", payload=payload)
    return payload
