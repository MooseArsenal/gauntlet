"""Archive (soft delete) for scenarios, environments and sessions (U-3).

Nothing could be removed before: a mis-click in the wizard was permanent and
every picker grew forever. Archiving hides a record from lists and pickers and
blocks new work on it, while keeping it — and every timeline, report and
audit row that references it — intact. Hard deletion stays where it belongs,
in the retention purge.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, models
from ..database import get_db
from ..security import require_facilitator, scope_or_404

router = APIRouter(tags=["archive"])

_KINDS = {
    "scenarios": models.Scenario,
    "environments": models.Environment,
    "sessions": models.Session,
}


def _set(db: Session, kind: str, item_id: int, user: models.User, request: Request,
         archived: bool) -> dict:
    model = _KINDS[kind]
    obj = scope_or_404(db.get(model, item_id), user)
    if archived and kind == "sessions" and obj.status in ("running", "paused"):
        raise HTTPException(409, "complete the exercise before archiving it")
    obj.archived_at = datetime.now(timezone.utc) if archived else None
    audit.record(db, f"{kind[:-1]}.{'archive' if archived else 'unarchive'}", request=request,
                 user=user, detail={"id": obj.id, "name": obj.name}, commit=False)
    db.commit()
    return {"id": obj.id, "archived_at": obj.archived_at}


for _kind in _KINDS:
    def _make(kind: str):
        @router.post(f"/api/{kind}/{{item_id}}/archive", name=f"archive_{kind}")
        def archive(item_id: int, request: Request,
                    user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
            return _set(db, kind, item_id, user, request, True)

        @router.post(f"/api/{kind}/{{item_id}}/unarchive", name=f"unarchive_{kind}")
        def unarchive(item_id: int, request: Request,
                      user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
            return _set(db, kind, item_id, user, request, False)
    _make(_kind)
