"""Content packs and the intel feed (L5)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from .. import audit, entitlements, models, packs, schemas
from ..database import get_db
from ..security import require_facilitator, require_staff, scope_or_404

router = APIRouter(prefix="/api/packs", tags=["packs"])


@router.get("")
def list_packs(user: models.User = Depends(require_staff), db: Session = Depends(get_db)):
    return [packs.pack_out(p) for p in packs.installed(db, user.org_id)]


@router.post("/inspect")
def inspect(payload: schemas.PackTokenIn, user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    """Verify a pack and describe it — nothing is installed."""
    try:
        manifest, digest = packs.verify(payload.token)
    except packs.PackError as e:
        raise HTTPException(422, str(e))
    out = packs.summary(manifest, digest)
    out["licensed"] = entitlements.has(db, out["feature"])
    return out


@router.post("/install", status_code=201)
def install(payload: schemas.PackInstallIn, request: Request, user: models.User = Depends(require_facilitator),
            db: Session = Depends(get_db)):
    out = packs.install(db, user, payload.token, payload.environment_id)
    audit.record(db, "pack.install", request=request, user=user,
                 detail={"pack": out["pack"]["pack_id"], "version": out["pack"]["version"], "kind": out["pack"]["kind"],
                         "digest": out["pack"]["digest"]}, commit=False)
    db.commit()
    return out


@router.delete("/{pack_id}", status_code=204)
def forget(pack_id: int, request: Request, user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    """Forget the pack record. Scenarios and adversaries it created stay."""
    p = scope_or_404(db.get(models.ContentPack, pack_id), user)
    audit.record(db, "pack.remove", request=request, user=user, detail={"pack": p.pack_id, "version": p.version}, commit=False)
    db.delete(p)
    db.commit()
    return Response(status_code=204)


@router.get("/intel")
def intel(user: models.User = Depends(require_staff), db: Session = Depends(get_db),
          _f: models.User = Depends(entitlements.require_feature("intel_feed"))):
    return packs.feed(db, user.org_id)
