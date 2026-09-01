"""Authoring (M2): catalog, threat-actor scenario generation, delivery, editing."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from fastapi import Response

from fastapi import Request

from .. import audit, models, scenario_io, schemas
from ..authoring import assist, delivery, generator
from ..authoring import attack_groups
from ..authoring.catalog import INJECT_BANK, SCENARIO_TEMPLATES, THREAT_ACTORS
from ..authoring.generator import _pick_asset
from ..config import MAX_YAML_BYTES
from ..database import get_db
from ..security import get_current_user, require_facilitator, scope_or_404


def _check_size(text: str) -> None:
    if len(text.encode("utf-8")) > MAX_YAML_BYTES:
        raise HTTPException(413, f"scenario YAML exceeds the {MAX_YAML_BYTES}-byte limit")

router = APIRouter(tags=["authoring"])


def _inject_in_org(db: Session, inject_id: int, user: models.User) -> models.Inject:
    inject = db.get(models.Inject, inject_id)
    if inject is not None:
        scope_or_404(db.get(models.Scenario, inject.scenario_id), user)
    if inject is None:
        raise HTTPException(404, "inject not found")
    return inject


@router.post("/api/authoring/assist/inject", response_model=schemas.AssistInjectOut)
def assist_inject(
    payload: schemas.AssistInjectIn,
    request: Request,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    """Draft one inject from a brief (deterministic template by default; a
    guardrailed LLM when configured). Returns a draft only — it is not saved."""
    org = user.organization.name if user.organization else "the organization"
    asset = {"code": "", "name": "an in-scope host"}
    if payload.environment_id is not None:
        env = scope_or_404(db.get(models.Environment, payload.environment_id), user)
        asset = _pick_asset(env, "user")
    try:
        result = assist.generate_inject(
            phase=payload.phase, technique=payload.technique, org=org,
            asset=asset, brief=payload.brief,
        )
    except assist.GuardrailError as exc:
        raise HTTPException(422, str(exc))
    audit.record(db, "authoring.assist", request=request, user=user,
                 detail={"generator": result["generator"], "phase": payload.phase,
                         "technique": payload.technique})
    return schemas.AssistInjectOut(**result)


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


def _attack_group_out(key: str) -> schemas.AttackGroupOut:
    a = THREAT_ACTORS[key]
    return schemas.AttackGroupOut(
        key=key, attack_id=a["attack_id"], name=a["name"], aliases=a["aliases"],
        description=a["description"], sectors=a["sectors"], techniques=a["techniques"],
        kill_chain=a["kill_chain"], objective_count=len(a["objectives"]),
    )


@router.get("/api/catalog/attack-groups", response_model=list[schemas.AttackGroupOut])
def list_attack_groups(
    sector: str | None = None,
    user: models.User = Depends(get_current_user),
):
    """Curated real ATT&CK groups the proctor can emulate. With ``?sector=`` the
    list is narrowed and ranked to the adversaries that target that industry —
    the "what hits an org like mine?" table."""
    return [_attack_group_out(k) for k in attack_groups.recommend(sector)]


@router.get("/api/catalog/attack-groups/random", response_model=schemas.AttackGroupOut)
def random_attack_group(
    sector: str | None = None,
    user: models.User = Depends(get_current_user),
):
    """Pick a random adversary to emulate — optionally biased to a sector.
    Powers the "Surprise me / Random" option in the guided build flow."""
    return _attack_group_out(attack_groups.random_group(sector))


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
        # An explicit actor_key wins — this is the mix-and-match the proctor
        # chose (emulate *this* adversary through *this* attack-type's framing).
        # Only fall back to the template's default actor when none was given.
        actor_key = actor_key or tmpl["actor"]
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
# YAML import / export / validation (M7)
# --------------------------------------------------------------------------- #
@router.post("/api/scenarios/validate", response_model=schemas.ValidationOut)
def validate_scenario_yaml(
    payload: schemas.ValidateRequest, user: models.User = Depends(require_facilitator)
):
    _check_size(payload.yaml)
    try:
        data = scenario_io.load_yaml(payload.yaml)
    except scenario_io.ScenarioError as e:
        return schemas.ValidationOut(errors=e.errors)
    except Exception as e:  # malformed YAML
        return schemas.ValidationOut(errors=[f"YAML parse error: {e}"])
    return schemas.ValidationOut(**scenario_io.validate(data))


@router.post("/api/scenarios/import", response_model=schemas.ScenarioOut, status_code=201)
def import_scenario_yaml(
    payload: schemas.ScenarioImport,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    scope_or_404(db.get(models.Environment, payload.environment_id), user)
    _check_size(payload.yaml)
    try:
        data = scenario_io.load_yaml(payload.yaml)
        scenario = scenario_io.to_models(data, payload.environment_id, user.org_id)
    except scenario_io.ScenarioError as e:
        raise HTTPException(422, {"errors": e.errors})
    except Exception as e:
        raise HTTPException(422, f"YAML parse error: {e}")
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    scenario.injects.sort(key=lambda i: i.sequence)
    return scenario


@router.get("/api/scenarios/{scenario_id}/export")
def export_scenario_yaml(
    scenario_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    scenario = scope_or_404(db.get(models.Scenario, scenario_id), user)
    text = scenario_io.dump_yaml(scenario_io.to_dict(scenario))
    return Response(content=text, media_type="application/x-yaml")


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
