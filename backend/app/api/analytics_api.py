"""Longitudinal maturity analytics endpoint (D3)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import analytics, audit, benchmark, models, schemas
from ..database import get_db
from ..entitlements import require_feature
from ..security import require_evaluator, require_role

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/maturity")
def maturity(user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    """Readiness trended across the org's exercises over time."""
    sessions = db.execute(
        select(models.Session).where(models.Session.org_id == user.org_id, models.Session.mode != "solo")
    ).scalars().all()
    return analytics.maturity(list(sessions))


@router.get("/benchmark")
def sector_benchmark(user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    """The org's completed exercises against the library's modelled expectation
    and, when opted in, the k-anonymous cohort of other organisations on this
    instance (M7). Computed locally; nothing leaves the instance."""
    org = db.get(models.Organization, user.org_id)
    return benchmark.compare(db, org)


@router.post("/benchmark/opt-in", response_model=schemas.BenchmarkOptInOut)
def set_benchmark_opt_in(payload: schemas.BenchmarkOptInIn, request: Request,
                         admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db),
                         _feature: models.User = Depends(require_feature("benchmark_cohort"))):
    """Admin: contribute this organisation's figures to the instance cohort (and see it)."""
    org = db.get(models.Organization, admin.org_id)
    org.benchmark_opt_in = bool(payload.opt_in)
    audit.record(db, "benchmark.opt_in", request=request, user=admin, detail={"opt_in": org.benchmark_opt_in}, commit=False)
    db.commit()
    return schemas.BenchmarkOptInOut(opt_in=org.benchmark_opt_in)
