"""Real inject delivery and invitations (P2)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, delivery, models, schemas, ws
from ..database import get_db
from ..security import require_facilitator, require_staff, scope_or_404
from .sessions import ACTIVE, require_status

router = APIRouter(tags=["delivery"])


def _base(request: Request) -> str:
    return f"{request.base_url.scheme}://{request.base_url.netloc}"


@router.get("/api/delivery/channels")
def channels(user: models.User = Depends(require_staff)):
    """Which senders this deployment has configured (never the secrets)."""
    return {"channels": delivery.configured(), "airgapped": __import__("app.config", fromlist=["AIRGAPPED"]).AIRGAPPED}


@router.post("/api/sessions/{session_id}/deliver")
def deliver(session_id: int, payload: schemas.DeliverIn, request: Request,
            user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    """Send an inject (default: the current one) to the people who joined the
    addressed cells and/or a team channel. Recorded on the timeline either way."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    require_status(s, *ACTIVE)
    scenario = db.get(models.Scenario, s.scenario_id)
    code = payload.inject_code or s.current_inject_code
    if not code:
        raise HTTPException(409, "no inject is live")
    inject = db.execute(select(models.Inject).where(
        models.Inject.scenario_id == scenario.id, models.Inject.code == code)).scalar_one_or_none()
    if inject is None:
        raise HTTPException(404, f"no inject '{code}'")
    chans = [c for c in payload.channels if c in delivery.CHANNELS]
    if not chans:
        raise HTTPException(422, f"choose at least one channel of {list(delivery.CHANNELS)}")
    out = delivery.deliver_inject(db, s, scenario, inject, channels=chans, cells=payload.cells or ["blue_cell"],
                                  extra_emails=payload.extra_emails, base_url=_base(request),
                                  include_link=payload.include_link, actor=user.email)
    audit.record(db, "inject.deliver", request=request, user=user,
                 detail={"session_id": s.id, "inject": code, "channels": chans, "delivered": out["delivered"]}, commit=False)
    db.commit()
    ws.manager.notify(s.id)
    return out


@router.post("/api/sessions/{session_id}/invite")
def invite(session_id: int, payload: schemas.InviteIn, request: Request,
           user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    """Send the join code and link to named addresses and/or a team channel."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    if s.status == "complete":
        raise HTTPException(409, "the exercise is complete")
    if not s.join_code:
        raise HTTPException(409, "issue a join code first")
    chans = [c for c in payload.channels if c in delivery.CHANNELS]
    if not chans:
        raise HTTPException(422, f"choose at least one channel of {list(delivery.CHANNELS)}")
    out = delivery.send_invites(db, s, channels=chans, cells=payload.cells, extra_emails=payload.emails,
                                base_url=_base(request), message=payload.message, actor=user.email)
    audit.record(db, "session.invite", request=request, user=user,
                 detail={"session_id": s.id, "channels": chans, "recipients": out["recipients"], "delivered": out["delivered"]},
                 commit=False)
    db.commit()
    return out
