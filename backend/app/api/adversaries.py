"""Custom adversary designer endpoints (A7).

Design your own adversary — real or fictitious — or have the program generate a
coherent random one. Stored per organisation and usable by the scenario
generator exactly like a built-in ATT&CK group.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..authoring import designer
from ..authoring.catalog import THREAT_ACTORS
from ..database import get_db
from ..security import require_staff, require_facilitator, scope_or_404

router = APIRouter(prefix="/api/adversaries", tags=["adversaries"])


def _unique_key(db: Session, org_id: int, name: str) -> str:
    """A slug unique within the org and not colliding with a built-in actor."""
    base = designer.slugify(name)
    taken = set(THREAT_ACTORS)
    taken |= {a.key for a in db.execute(
        select(models.CustomAdversary).where(models.CustomAdversary.org_id == org_id)
    ).scalars()}
    key = base
    i = 2
    while key in taken:
        key = f"{base}_{i}"
        i += 1
    return key


def _out(a: models.CustomAdversary) -> schemas.CustomAdversaryOut:
    return schemas.CustomAdversaryOut.model_validate(a)


@router.get("", response_model=list[schemas.CustomAdversaryOut])
def list_adversaries(user: models.User = Depends(require_staff), db: Session = Depends(get_db)):
    rows = db.execute(
        select(models.CustomAdversary)
        .where(models.CustomAdversary.org_id == user.org_id)
        .order_by(models.CustomAdversary.id.desc())
    ).scalars().all()
    return [_out(a) for a in rows]


@router.post("/random", response_model=schemas.AdversaryDraft)
def generate_random(sector: str | None = None,
                    user: models.User = Depends(require_facilitator)):
    """Compose a coherent, unsaved adversary draft. The proctor reviews/tweaks it
    and POSTs it back to save."""
    return schemas.AdversaryDraft(**designer.random_adversary(sector=sector))


@router.post("", response_model=schemas.CustomAdversaryOut, status_code=201)
def create_adversary(payload: schemas.CustomAdversaryIn,
                     user: models.User = Depends(require_facilitator),
                     db: Session = Depends(get_db)):
    problems = designer.validate_kill_chain(payload.kill_chain)
    if problems:
        raise HTTPException(422, {"kill_chain": problems})

    objectives = [o.model_dump() for o in (payload.objectives or [])]
    if not objectives:
        objectives = [{"title": t, "success_criteria": c}
                      for t, c in designer.default_objectives(payload.kill_chain)]

    adv = models.CustomAdversary(
        org_id=user.org_id,
        key=_unique_key(db, user.org_id, payload.name),
        name=payload.name,
        label=payload.label if getattr(payload, "label", None) else (
            f"{payload.name} — {payload.motivation}-motivated adversary" if payload.motivation
            else payload.name),
        description=payload.description,
        motivation=payload.motivation,
        is_fictitious=payload.is_fictitious,
        sectors=payload.sectors,
        techniques=payload.techniques,
        kill_chain=payload.kill_chain,
        objectives=objectives,
    )
    db.add(adv)
    db.commit()
    db.refresh(adv)
    return _out(adv)


@router.delete("/{adversary_id}", status_code=204)
def delete_adversary(adversary_id: int,
                     user: models.User = Depends(require_facilitator),
                     db: Session = Depends(get_db)):
    adv = scope_or_404(db.get(models.CustomAdversary, adversary_id), user)
    db.delete(adv)
    db.commit()
