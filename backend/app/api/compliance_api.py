"""Compliance evidence + PDF export (M7 phase 2)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from .. import audit, compliance, models, pdf
from ..database import get_db
from ..security import require_staff, require_evaluator, scope_or_404

router = APIRouter(tags=["compliance"])


def _pdf_response(title: str, markdown: str, filename: str, db: Session | None = None, org_id: int | None = None) -> Response:
    from .. import branding  # L2: white-label
    kw = branding.pdf_args(db, org_id) if db is not None else {}
    return Response(
        content=pdf.render(title, markdown, **kw),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/compliance/frameworks")
def frameworks(user: models.User = Depends(require_staff)):
    return [
        {"key": k, "name": v, "tier": compliance.FRAMEWORK_TIER.get(k, 1)}
        for k, v in compliance.FRAMEWORKS.items()
    ]


def _evidence(db: Session, session_id: int, user: models.User, framework: str | None):
    s = scope_or_404(db.get(models.Session, session_id), user)
    scenario = db.get(models.Scenario, s.scenario_id)
    return s, compliance.build_evidence(scenario, s, list(s.observations), only=framework)


@router.get("/api/sessions/{session_id}/evidence")
def evidence(
    session_id: int,
    framework: str | None = None,
    user: models.User = Depends(require_evaluator),
    db: Session = Depends(get_db),
):
    _, ev = _evidence(db, session_id, user, framework)
    return ev


@router.get("/api/sessions/{session_id}/evidence.pdf")
def evidence_pdf(
    session_id: int,
    request: Request,
    framework: str | None = None,
    user: models.User = Depends(require_evaluator),
    db: Session = Depends(get_db),
):
    s, ev = _evidence(db, session_id, user, framework)
    md = compliance.render_markdown(ev)
    audit.record(db, "evidence.export", request=request, user=user,
                 detail={"session_id": s.id, "framework": framework or "all"})
    return _pdf_response(f"Compliance Evidence — {ev['exercise']['scenario']}",
                         md, f"evidence-session-{s.id}.pdf", db=db, org_id=user.org_id)


@router.get("/api/sessions/{session_id}/reports/{report_id}.pdf")
def report_pdf(
    session_id: int,
    report_id: int,
    request: Request,
    user: models.User = Depends(require_evaluator),
    db: Session = Depends(get_db),
):
    s = scope_or_404(db.get(models.Session, session_id), user)
    report = db.get(models.Report, report_id)
    if not report or report.session_id != s.id:
        raise HTTPException(404, "report not found")
    audit.record(db, "report.export", request=request, user=user,
                 detail={"session_id": s.id, "report_id": report.id, "audience": report.audience})
    return _pdf_response(report.title, report.content, f"report-{report.id}.pdf", db=db, org_id=user.org_id)
