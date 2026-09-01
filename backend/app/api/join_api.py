"""Join-code lobby (D4) — large-group onboarding.

A facilitator generates a short join code for a session; participants enter it
(no session browsing), pick their cell, and land in the matching fog-of-war
view. Everyone is still an authenticated org member — the code is convenience,
not a new trust boundary — so joins stay tenant-scoped and RBAC-gated.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import get_current_user, require_facilitator, scope_or_404

router = APIRouter(tags=["join"])

# Unambiguous alphabet — no 0/O/1/I/L to keep codes easy to read aloud.
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _new_code(db: Session) -> str:
    for _ in range(20):
        code = "".join(secrets.choice(_ALPHABET) for _ in range(6))
        exists = db.execute(
            select(models.Session.id).where(models.Session.join_code == code)
        ).first()
        if not exists:
            return code
    raise HTTPException(500, "could not allocate a join code")  # pragma: no cover


@router.post("/api/sessions/{session_id}/join-code", response_model=schemas.JoinCodeOut)
def make_join_code(session_id: int,
                   user: models.User = Depends(require_facilitator),
                   db: Session = Depends(get_db)):
    """Generate (or rotate) the session's join code."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    s.join_code = _new_code(db)
    db.commit()
    return schemas.JoinCodeOut(join_code=s.join_code)


@router.get("/api/sessions/{session_id}/lobby", response_model=list[schemas.LobbyMember])
def lobby(session_id: int,
          user: models.User = Depends(get_current_user),
          db: Session = Depends(get_db)):
    """Who has joined this session."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    rows = db.execute(
        select(models.SessionJoin)
        .where(models.SessionJoin.session_id == s.id)
        .order_by(models.SessionJoin.joined_at)
    ).scalars().all()
    return [schemas.LobbyMember.model_validate(r) for r in rows]


@router.post("/api/join", response_model=schemas.JoinOut)
def join(payload: schemas.JoinIn,
         user: models.User = Depends(get_current_user),
         db: Session = Depends(get_db)):
    """Join a session by its code — org-scoped, upserting this user's lobby row."""
    code = (payload.code or "").strip().upper()
    s = db.execute(
        select(models.Session).where(
            models.Session.join_code == code,
            models.Session.org_id == user.org_id,
        )
    ).scalars().first()
    if s is None:
        raise HTTPException(404, "no session with that join code")

    existing = db.execute(
        select(models.SessionJoin).where(
            models.SessionJoin.session_id == s.id,
            models.SessionJoin.user_id == user.id,
        )
    ).scalars().first()
    name = (payload.display_name or "").strip() or user.email
    if existing:
        existing.cell = payload.cell
        existing.display_name = name
    else:
        db.add(models.SessionJoin(org_id=user.org_id, session_id=s.id, user_id=user.id,
                                  display_name=name, cell=payload.cell))
    db.commit()
    return schemas.JoinOut(session_id=s.id, name=s.name, cell=payload.cell, status=s.status)
