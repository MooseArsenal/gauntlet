"""Solo learning mode endpoints (S1). Free; any signed-in user."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from .. import branding, models, pdf, schemas, solo
from ..database import get_db
from ..security import get_current_user, scope_or_404

router = APIRouter(prefix="/api/solo", tags=["solo"])


def _run(db: Session, sid: int, user: models.User):
    s = scope_or_404(db.get(models.Session, sid), user)
    solo.require_own(s, user)
    return s, db.get(models.Scenario, s.scenario_id)


@router.get("/scenarios")
def scenarios(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"sides": [{"key": k, "label": v} for k, v in solo.SIDE_LABELS.items()], "scenarios": solo.catalog(db, user)}


@router.get("/runs")
def my_runs(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return solo.runs(db, user)


@router.post("/start", status_code=201)
def start(payload: schemas.SoloStartIn, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    scenario = scope_or_404(db.get(models.Scenario, payload.scenario_id), user)
    if scenario.archived_at is not None:
        raise HTTPException(409, "that scenario is archived")
    s = solo.start(db, user, scenario, payload.side)
    db.commit()
    db.refresh(s)
    return solo.view(db, s, scenario, user)


@router.get("/{sid}")
def get_view(sid: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    s, scenario = _run(db, sid, user)
    return solo.view(db, s, scenario, user)


@router.post("/{sid}/respond")
def respond(sid: int, payload: schemas.SoloRespondIn, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    s, scenario = _run(db, sid, user)
    out = solo.respond(db, s, scenario, user, payload.option, payload.text)
    db.commit()
    db.refresh(s)
    return {**out, "view": solo.view(db, s, scenario, user)}


@router.post("/{sid}/skip")
def skip(sid: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    s, scenario = _run(db, sid, user)
    out = solo.skip(db, s, scenario, user)
    db.commit()
    db.refresh(s)
    return {**out, "view": solo.view(db, s, scenario, user)}


@router.post("/{sid}/move")
def move(sid: int, payload: schemas.SoloMoveIn, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    s, scenario = _run(db, sid, user)
    out = solo.move(db, s, scenario, user, payload.techniques, payload.target, payload.action)
    db.commit()
    db.refresh(s)
    return {**out, "view": solo.view(db, s, scenario, user)}


@router.post("/{sid}/finish")
def finish(sid: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    s, scenario = _run(db, sid, user)
    d = solo.finish(db, s, scenario, reason="You ended the run.")
    db.commit()
    return d


@router.get("/{sid}/debrief")
def get_debrief(sid: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    s, scenario = _run(db, sid, user)
    if s.status != "complete":
        raise HTTPException(409, "the run is still going")
    return solo.debrief(db, s, scenario)


@router.get("/{sid}/debrief.pdf")
def get_debrief_pdf(sid: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    s, scenario = _run(db, sid, user)
    if s.status != "complete":
        raise HTTPException(409, "the run is still going")
    d = solo.debrief(db, s, scenario)
    raw = pdf.render(f"Solo debrief — {scenario.name}", solo.debrief_markdown(d), **branding.pdf_args(db, user.org_id))
    return Response(content=raw, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="solo-debrief-{s.id}.pdf"'})
