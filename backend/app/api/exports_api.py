"""Timeline and report exports in CSV, JSON, and DOCX (F1).

Complements the existing Markdown/PDF paths. Every endpoint is tenant-scoped and
audited, mirroring the compliance export surface.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from .. import audit, compliance, exports, models
from ..database import get_db
from ..exports import markdown_to_docx
from ..security import require_evaluator, scope_or_404

router = APIRouter(prefix="/api/sessions", tags=["exports"])

_DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _attach(content, media_type: str, filename: str) -> Response:
    return Response(content=content, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _session(db: Session, session_id: int, user: models.User) -> models.Session:
    return scope_or_404(db.get(models.Session, session_id), user)


@router.get("/{session_id}/timeline.csv")
def timeline_csv(session_id: int, request: Request,
                 user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = _session(db, session_id, user)
    audit.record(db, "timeline.export", request=request, user=user,
                 detail={"session_id": s.id, "format": "csv"})
    return _attach(exports.timeline_csv(list(s.events)), "text/csv",
                   f"timeline-session-{s.id}.csv")


@router.get("/{session_id}/timeline.json")
def timeline_json(session_id: int, request: Request,
                  user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = _session(db, session_id, user)
    scenario = db.get(models.Scenario, s.scenario_id)
    audit.record(db, "timeline.export", request=request, user=user,
                 detail={"session_id": s.id, "format": "json"})
    data = exports.timeline_json(s, scenario, list(s.events), list(s.observations))
    return _attach(json.dumps(data, indent=2), "application/json",
                   f"timeline-session-{s.id}.json")


@router.get("/{session_id}/reports/{report_id}.docx")
def report_docx(session_id: int, report_id: int, request: Request,
                user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = _session(db, session_id, user)
    report = db.get(models.Report, report_id)
    if not report or report.session_id != s.id:
        raise HTTPException(404, "report not found")
    audit.record(db, "report.export", request=request, user=user,
                 detail={"session_id": s.id, "report_id": report.id, "format": "docx"})
    return _attach(markdown_to_docx(report.title, report.content), _DOCX_MIME,
                   f"report-{report.id}.docx")


@router.get("/{session_id}/evidence.docx")
def evidence_docx(session_id: int, request: Request, framework: str | None = None,
                  user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = _session(db, session_id, user)
    scenario = db.get(models.Scenario, s.scenario_id)
    ev = compliance.build_evidence(scenario, s, list(s.observations), only=framework)
    md = compliance.render_markdown(ev)
    audit.record(db, "evidence.export", request=request, user=user,
                 detail={"session_id": s.id, "framework": framework or "all", "format": "docx"})
    return _attach(markdown_to_docx(f"Compliance Evidence — {ev['exercise']['scenario']}", md),
                   _DOCX_MIME, f"evidence-session-{s.id}.docx")
