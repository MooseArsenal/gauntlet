"""Improvement plan + tracker sync (F4).

Corrective actions from an exercise, optionally pushed to Jira/ServiceNow with
their closure verified back against the ticket. Tenant-scoped; facilitators
manage items and drive the tracker sync.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, models, schemas, tracker
from ..database import get_db
from ..security import require_staff, require_facilitator, scope_or_404

router = APIRouter(tags=["improvements"])


def _get_item(db: Session, item_id: int, user: models.User) -> models.ImprovementItem:
    return scope_or_404(db.get(models.ImprovementItem, item_id), user)


def _validate(severity: str | None, status_: str | None) -> None:
    if severity is not None and severity not in models.IMPROVEMENT_SEVERITIES:
        raise HTTPException(422, f"severity must be one of {list(models.IMPROVEMENT_SEVERITIES)}")
    if status_ is not None and status_ not in models.IMPROVEMENT_STATUSES:
        raise HTTPException(422, f"status must be one of {list(models.IMPROVEMENT_STATUSES)}")


# --------------------------------------------------------------------------- #
# CRUD
# --------------------------------------------------------------------------- #
@router.post("/api/improvements", response_model=schemas.ImprovementOut, status_code=201)
def create_item(payload: schemas.ImprovementCreate,
                user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    _validate(payload.severity, None)
    if payload.session_id is not None:
        scope_or_404(db.get(models.Session, payload.session_id), user)
    item = models.ImprovementItem(
        org_id=user.org_id, session_id=payload.session_id, title=payload.title,
        description=payload.description, severity=payload.severity, source="manual",
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.get("/api/improvements", response_model=list[schemas.ImprovementOut])
def list_items(status: str | None = None, user: models.User = Depends(require_staff),
               db: Session = Depends(get_db)):
    stmt = select(models.ImprovementItem).where(models.ImprovementItem.org_id == user.org_id)
    if status:
        stmt = stmt.where(models.ImprovementItem.status == status)
    return db.execute(stmt.order_by(models.ImprovementItem.id.desc())).scalars().all()


@router.get("/api/sessions/{session_id}/improvements", response_model=list[schemas.ImprovementOut])
def list_for_session(session_id: int, user: models.User = Depends(require_staff),
                     db: Session = Depends(get_db)):
    scope_or_404(db.get(models.Session, session_id), user)
    return db.execute(
        select(models.ImprovementItem)
        .where(models.ImprovementItem.session_id == session_id)
        .order_by(models.ImprovementItem.id.desc())
    ).scalars().all()


@router.patch("/api/improvements/{item_id}", response_model=schemas.ImprovementOut)
def update_item(item_id: int, payload: schemas.ImprovementUpdate,
                user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    item = _get_item(db, item_id, user)
    data = payload.model_dump(exclude_unset=True)
    _validate(data.get("severity"), data.get("status"))
    for k, v in data.items():
        setattr(item, k, v)
    db.commit()
    db.refresh(item)
    return item


# --------------------------------------------------------------------------- #
# auto-generate from a session's gaps
# --------------------------------------------------------------------------- #
@router.post("/api/sessions/{session_id}/improvements/from-gaps",
             response_model=list[schemas.ImprovementOut], status_code=201)
def from_gaps(session_id: int, user: models.User = Depends(require_facilitator),
              db: Session = Depends(get_db)):
    """Create an improvement item for each missed/partial observation."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    created = []
    for obs in s.observations:
        if obs.rating not in ("missed", "partial"):
            continue
        sev = "high" if obs.rating == "missed" else "medium"
        item = models.ImprovementItem(
            org_id=user.org_id, session_id=s.id,
            title=f"Address gap on {obs.objective_code or 'objective'}",
            description=obs.note or "", severity=sev, source="gap",
        )
        db.add(item)
        created.append(item)
    db.flush()
    for item in created:
        db.refresh(item)
    db.commit()
    return created


# --------------------------------------------------------------------------- #
# tracker sync
# --------------------------------------------------------------------------- #
@router.post("/api/improvements/{item_id}/push", response_model=schemas.ImprovementOut)
def push_to_tracker(item_id: int, request: Request,
                    user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    item = _get_item(db, item_id, user)
    if item.external_ref:
        raise HTTPException(status.HTTP_409_CONFLICT, "already pushed to a tracker")
    adapter = tracker.get_adapter()
    try:
        ref, url = adapter.create_issue(item.title, item.description, item.severity)
    except tracker.TrackerError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    item.external_system, item.external_ref, item.external_url = adapter.name, ref, url
    audit.record(db, "improvement.push", request=request, user=user,
                 detail={"item_id": item.id, "system": adapter.name, "ref": ref}, commit=False)
    db.commit()
    db.refresh(item)
    return item


@router.post("/api/improvements/{item_id}/sync", response_model=schemas.TrackerSyncOut)
def sync_from_tracker(item_id: int, user: models.User = Depends(require_facilitator),
                      db: Session = Depends(get_db)):
    """Closure verification: pull the external ticket's status; if it's closed,
    close the local item to match."""
    item = _get_item(db, item_id, user)
    if not item.external_ref:
        raise HTTPException(status.HTTP_409_CONFLICT, "item is not linked to a tracker")
    adapter = tracker.get_adapter()
    try:
        ext = adapter.fetch_status(item.external_ref)
    except tracker.TrackerError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    if ext == "closed":
        item.status = "closed"
    elif ext == "in_progress" and item.status == "open":
        item.status = "in_progress"
    db.commit()
    db.refresh(item)
    return schemas.TrackerSyncOut(id=item.id, external_system=item.external_system,
                                  external_ref=item.external_ref, external_status=ext,
                                  status=item.status)
