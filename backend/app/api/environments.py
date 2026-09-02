"""Environment intake — the 'feed it what you know' surface."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from .. import audit, intake, models, schemas
from ..authoring import environments as env_library
from ..config import MAX_IMPORT_BYTES
from ..database import get_db
from ..security import require_staff, require_facilitator, scope_or_404

router = APIRouter(prefix="/api/environments", tags=["environments"])


@router.post("", response_model=schemas.EnvironmentOut, status_code=201)
def create_environment(
    payload: schemas.EnvironmentCreate,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    env = models.Environment(org_id=user.org_id, **payload.model_dump())
    db.add(env)
    db.commit()
    db.refresh(env)
    return env


@router.post("/import", response_model=schemas.EnvironmentImportOut, status_code=201)
def import_environment(
    payload: schemas.EnvironmentImportIn,
    request: Request,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    """Map a CMDB / EDR / SIEM / ASM export into an environment — create a new
    one, or merge (append) into an existing one."""
    if len(payload.data.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise HTTPException(413, f"import payload exceeds the {MAX_IMPORT_BYTES}-byte limit")
    try:
        mapped = intake.build_import(payload.source, payload.format, payload.data)
    except intake.IntakeError as exc:
        raise HTTPException(422, str(exc))

    created = payload.environment_id is None
    if created:
        env = models.Environment(org_id=user.org_id,
                                 name=payload.name or f"Imported ({payload.source})")
        db.add(env)
        db.flush()
    else:
        env = scope_or_404(db.get(models.Environment, payload.environment_id), user)

    summary = {}
    for field, items in mapped.items():
        current = list(getattr(env, field) or [])
        setattr(env, field, current + items)
        flag_modified(env, field)
        summary[field] = len(items)

    audit.record(db, "environment.import", request=request, user=user,
                 detail={"source": payload.source, "environment_id": env.id, **summary}, commit=False)
    db.commit()
    db.refresh(env)
    return schemas.EnvironmentImportOut(environment=env, imported=summary, created=created)


@router.get("/templates", response_model=list[schemas.EnvironmentTemplateOut])
def list_environment_templates(user: models.User = Depends(require_staff)):
    """The environment library: complete sector estates a proctor can stamp
    into the organisation and then edit (E1)."""
    return [schemas.EnvironmentTemplateOut(**s) for s in env_library.summaries()]


@router.post("/from-template", response_model=schemas.EnvironmentOut, status_code=201)
def create_from_template(
    payload: schemas.EnvironmentFromTemplateIn,
    request: Request,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    """Create an environment in the caller's organisation from a library template."""
    try:
        env = env_library.build_from_template(payload.key, payload.name)
    except KeyError:
        raise HTTPException(404, f"no environment template '{payload.key}'")
    env.org_id = user.org_id
    # Stamping the same template twice must not produce two identically named
    # environments: suffix the copy so the picker stays unambiguous.
    taken = {n for (n,) in db.execute(
        select(models.Environment.name).where(models.Environment.org_id == user.org_id))}
    base_name, n = env.name, 2
    while env.name in taken:
        env.name = f"{base_name} ({n})"
        n += 1
    db.add(env)
    db.flush()
    audit.record(db, "environment.from_template", request=request, user=user,
                 detail={"template": payload.key, "environment_id": env.id}, commit=False)
    db.commit()
    db.refresh(env)
    return env


@router.get("", response_model=list[schemas.EnvironmentSummary])
def list_environments(
    include_archived: bool = False,
    limit: int = 100, offset: int = 0,
    user: models.User = Depends(require_staff), db: Session = Depends(get_db)
):
    return (
        db.execute(
            select(models.Environment)
            .where(models.Environment.org_id == user.org_id,
                   *([] if include_archived else [models.Environment.archived_at.is_(None)]))
            .order_by(models.Environment.id)
            .limit(max(1, min(limit, 500))).offset(max(0, offset))
        )
        .scalars()
        .all()
    )


@router.get("/{env_id}", response_model=schemas.EnvironmentOut)
def get_environment(
    env_id: int, user: models.User = Depends(require_staff), db: Session = Depends(get_db)
):
    return scope_or_404(db.get(models.Environment, env_id), user)
