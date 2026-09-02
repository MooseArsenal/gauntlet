"""Evidence attachments (P3): a file, bound into the signed chain.

A screenshot of the SIEM, the ticket export, a photo of the whiteboard —
today they live in a chat thread nobody can find. Here the bytes are stored
with the session and their SHA-256, name, size and type are written as an
``evidence`` event on the hash-chained timeline. The record proves the file
was attached at that moment; verify() recomputes every stored file's digest
against its event, so a swapped file fails the same way an edited event does.

Uploads arrive as base64 JSON (no multipart dependency), capped by
``GAUNTLET_MAX_EVIDENCE_BYTES`` (default 3 MiB, under the request cap) and
``MAX_PER_SESSION``. Staff only; participants never see evidence events.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import models
from .timeline import append_event

MAX_BYTES = int(os.environ.get("GAUNTLET_MAX_EVIDENCE_BYTES", str(3 * 1024 * 1024)))
MAX_PER_SESSION = int(os.environ.get("GAUNTLET_MAX_EVIDENCE_PER_SESSION", "50"))
ALLOWED_TYPES = {
    "image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain", "text/csv",
    "application/json", "text/markdown", "application/zip",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "message/rfc822", "application/octet-stream",
}
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ ()\-]+")


def safe_name(name: str) -> str:
    """Basename only, printable characters only, never empty."""
    base = re.split(r"[\\/]+", (name or "").strip())[-1]
    base = _SAFE_NAME.sub("_", base)[:120].strip(" ._")
    return base or "evidence"


def decode(content_b64: str) -> bytes:
    try:
        raw = base64.b64decode(content_b64 or "", validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(422, "content must be base64")
    if not raw:
        raise HTTPException(422, "empty file")
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, f"evidence is capped at {MAX_BYTES} bytes")
    return raw


def attach(db: Session, session: models.Session, user: models.User, *, filename: str, content_type: str,
           content_b64: str, note: str, about_seq: int | None) -> models.Attachment:
    count = db.execute(select(func.count()).select_from(models.Attachment)
                       .where(models.Attachment.session_id == session.id)).scalar_one()
    if count >= MAX_PER_SESSION:
        raise HTTPException(status.HTTP_409_CONFLICT, f"this exercise already holds {MAX_PER_SESSION} attachments")
    ctype = (content_type or "application/octet-stream").split(";")[0].strip().lower()
    if ctype not in ALLOWED_TYPES:
        raise HTTPException(422, f"unsupported content type '{ctype}'")
    raw = decode(content_b64)
    if about_seq is not None and not any(e.seq == about_seq for e in session.events):
        raise HTTPException(404, f"no timeline event #{about_seq}")
    digest = hashlib.sha256(raw).hexdigest()
    att = models.Attachment(org_id=session.org_id, session_id=session.id, about_seq=about_seq,
                            filename=safe_name(filename), content_type=ctype, size=len(raw), sha256=digest,
                            note=(note or "")[:4000], uploaded_by=user.email, data=raw)
    db.add(att)
    db.flush()
    ev = append_event(db, session.id, kind="evidence", ref=f"ATT-{att.id}", payload={
        "attachment_id": att.id, "filename": att.filename, "content_type": ctype, "size": len(raw),
        "sha256": digest, "note": att.note, "about_seq": about_seq, "by": user.email})
    att.event_seq = ev.seq
    return att


def verify(db: Session, session: models.Session) -> dict:
    """Every evidence event must still match a stored file with the same digest."""
    events = [e for e in session.events if e.kind == "evidence"]
    problems = []
    for e in events:
        p = e.payload or {}
        att = db.get(models.Attachment, p.get("attachment_id"))
        if att is None or att.session_id != session.id:
            problems.append(f"#{e.seq}: file missing")
        elif hashlib.sha256(att.data).hexdigest() != p.get("sha256"):
            problems.append(f"#{e.seq}: {att.filename} does not match its recorded digest")
    return {"attachments": len(events), "valid": not problems, "problems": problems}


def summary(att: models.Attachment) -> dict:
    return {"id": att.id, "event_seq": att.event_seq, "about_seq": att.about_seq, "filename": att.filename,
            "content_type": att.content_type, "size": att.size, "sha256": att.sha256, "note": att.note,
            "uploaded_by": att.uploaded_by, "created_at": att.created_at}
