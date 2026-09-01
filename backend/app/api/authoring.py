"""Authoring (M2): catalog, threat-actor scenario generation, delivery, editing."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..authoring import delivery, generator
from ..authoring.catalog import INJECT_BANK, SCENARIO_TEMPLATES, THREAT_ACTORS
from ..database import get_db
from ..security import get_current_user, require_facilitator, scope_or_404

router = APIRouter(tags=["authoring"])


def _inject_in_org(db: Session, inject_id: int, user: models.User) -> models.Inject:
    inject = db.get(models.Inject, inject_id)
    if inject is not None:
        scope_or_404(db.get(models.Scenario, inject.scenario_id), user)
    if inject is None:
        raise HTTPException(404, "inject not found")
    return inject


# --------------------------------------------------------------------------- #
# Catalog (read-only; authenticated but not tenant-specific)
# --------------------------------------------------------------------------- #
@router.get("/api/catalog/actors", response_model=list[schemas.ActorOut])
def list_actors(user: models.User = Depends(get_current_user)):
    return [
        schemas.ActorOut(
            key=k, name=a["name"], label=a["label"], description=a["description"],
            kill_chain=a["kill_chain"], objective_count=len(a["objectives"]),
        )
        for k, a in THREAT_ACTORS.items()
    ]


@router.get("/api/catalog/templates", response_model=list[schemas.TemplateOut])
def list_templates(user: models.User = Depends(get_current_user)):
    return [
        schemas.TemplateOut(key=k, name=t["name"], actor=t["actor"], narrative=t["narrative"])
        for k, t in SCENARIO_TEMPLATES.items()
    ]


@router.get("/api/catalog/injects", response_model=list[schemas.InjectBankEntryOut])
def list_inject_bank(
    phase: str | None = None,
    channel: str | None = None,
    user: models.User = Depends(get_current_user),
):
    out = []
    for k, e in INJECT_BANK.items():
        if phase and e["phase"] != phase:
            continue
        if channel and e["channel"] != channel:
            continue
        out.append(schemas.InjectBankEntryOut(
            key=k, phase=e["phase"], channel=e["channel"],
            techniques=e["techniques"], title=e["title"],
        ))
    return out


# --------------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------------- #
@router.post("/api/scenarios/generate", response_model=schemas.ScenarioOut, status_code=201)
def generate_scenario(
    payload: schemas.GenerateRequest,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    env = scope_or_404(db.get(models.Environment, payload.environment_id), user)

    actor_key = payload.actor_key
    if payload.template_key:
        tmpl = SCENARIO_TEMPLATES.get(payload.template_key)
        if not tmpl:
            raise HTTPException(400, f"unknown template '{payload.template_key}'")
        actor_key = tmpl["actor"]
    if not actor_key:
        raise HTTPException(400, "provide either actor_key or template_key")

    try:
        scenario = generator.build_scenario(
            env, actor_key, name=payload.name, template_key=payload.template_key
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    scenario.org_id = user.org_id
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    scenario.injects.sort(key=lambda i: i.sequence)
    return scenario


# --------------------------------------------------------------------------- #
# Delivery
# --------------------------------------------------------------------------- #
@router.get("/api/injects/{inject_id}/delivery", response_model=schemas.DeliveryOut)
def get_delivery(
    inject_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    return delivery.render(_inject_in_org(db, inject_id, user))


# --------------------------------------------------------------------------- #
# Editing — refine a generated draft
# --------------------------------------------------------------------------- #
@router.patch("/api/scenarios/{scenario_id}", response_model=schemas.ScenarioOut)
def update_scenario(
    scenario_id: int,
    payload: schemas.ScenarioUpdate,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    scenario = scope_or_404(db.get(models.Scenario, scenario_id), user)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(scenario, field, value)
    db.commit()
    db.refresh(scenario)
    scenario.injects.sort(key=lambda i: i.sequence)
    return scenario


@router.post("/api/scenarios/{scenario_id}/injects", response_model=schemas.InjectOut, status_code=201)
def add_inject(
    scenario_id: int,
    payload: schemas.InjectIn,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    scope_or_404(db.get(models.Scenario, scenario_id), user)
    inject = models.Inject(scenario_id=scenario_id, **payload.model_dump())
    db.add(inject)
    db.commit()
    db.refresh(inject)
    return inject


@router.patch("/api/injects/{inject_id}", response_model=schemas.InjectOut)
def update_inject(
    inject_id: int,
    payload: schemas.InjectUpdate,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    inject = _inject_in_org(db, inject_id, user)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(inject, field, value)
    db.commit()
    db.refresh(inject)
    return inject


@router.delete("/api/injects/{inject_id}", status_code=204)
def delete_inject(
    inject_id: int, user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)
):
    inject = _inject_in_org(db, inject_id, user)
    db.delete(inject)
    db.commit()
