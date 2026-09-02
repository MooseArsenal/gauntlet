"""Evidence attachments (P3)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, evidence, models, schemas, ws
from ..database import get_db
from ..security import require_evaluator, scope_or_404
from .sessions import ACTIVE, require_status

router = APIRouter(prefix="/api/sessions", tags=["evidence"])


@router.post("/{session_id}/evidence", status_code=201)
def upload(session_id: int, payload: schemas.EvidenceIn, request: Request,
           user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    """Attach a file to the exercise record; its digest lands on the chain."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    require_status(s, *ACTIVE, "complete")  # evidence is often gathered after the room empties
    att = evidence.attach(db, s, user, filename=payload.filename, content_type=payload.content_type,
                          content_b64=payload.content, note=payload.note, about_seq=payload.about_seq)
    audit.record(db, "evidence.attach", request=request, user=user,
                 detail={"session_id": s.id, "attachment_id": att.id, "sha256": att.sha256, "size": att.size}, commit=False)
    db.commit()
    db.refresh(att)
    ws.manager.notify(s.id)
    return evidence.summary(att)


@router.get("/{session_id}/evidence")
def list_evidence(session_id: int, user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    rows = db.execute(select(models.Attachment).where(models.Attachment.session_id == s.id)
                      .order_by(models.Attachment.id)).scalars().all()
    ev = evidence.verify(db, s)
    return {"session_id": s.id, "attachments": [evidence.summary(a) for a in rows],
            "valid": ev["valid"], "problems": ev["problems"]}


@router.get("/{session_id}/evidence/{attachment_id}")
def download(session_id: int, attachment_id: int, request: Request,
             user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    att = db.get(models.Attachment, attachment_id)
    if att is None or att.session_id != s.id:
        raise HTTPException(404, "attachment not found")
    audit.record(db, "evidence.download", request=request, user=user,
                 detail={"session_id": s.id, "attachment_id": att.id})
    return Response(content=att.data, media_type=att.content_type,
                    headers={"Content-Disposition": f'attachment; filename="{att.filename}"',
                             "X-Content-Type-Options": "nosniff", "X-Evidence-SHA256": att.sha256})
