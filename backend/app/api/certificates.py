"""Exercise certificates (M1): issue, fetch, download, and verify without an account."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, certificates, models, schemas
from ..audit import client_ip
from ..database import get_db
from ..security import require_evaluator, require_facilitator, scope_or_404
from ..throttle import throttle

router = APIRouter(tags=["certificates"])

VERIFY_MAX_PER_WINDOW = 60  # per source address, per login window


def _existing(db: Session, session_id: int) -> models.Certificate | None:
    return db.execute(
        select(models.Certificate)
        .where(models.Certificate.session_id == session_id, models.Certificate.revoked_at.is_(None))
        .order_by(models.Certificate.id.desc())
    ).scalars().first()


@router.post("/api/sessions/{session_id}/certificate", response_model=schemas.CertificateOut, status_code=201)
def issue_certificate(
    session_id: int, request: Request,
    user: models.User = Depends(require_facilitator), db: Session = Depends(get_db),
):
    """Issue the certificate for a completed exercise. Idempotent: a session
    has one live certificate; issuing again returns it."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    if s.status != "complete":
        raise HTTPException(409, "a certificate is issued for a completed exercise; complete it first")
    if (cert := _existing(db, s.id)) is not None:
        return cert
    scenario = db.get(models.Scenario, s.scenario_id)
    env = db.get(models.Environment, scenario.environment_id)
    org = db.get(models.Organization, s.org_id)
    participants = db.execute(
        select(func.count()).select_from(models.SessionJoin).where(models.SessionJoin.session_id == s.id)
    ).scalar_one()
    cert = certificates.issue(org, s, scenario, env, participants, user.email)
    db.add(cert)
    db.flush()
    audit.record(db, "certificate.issue", request=request, user=user,
                 detail={"session_id": s.id, "serial": cert.serial}, commit=False)
    db.commit()
    db.refresh(cert)
    return cert


@router.get("/api/sessions/{session_id}/certificate", response_model=schemas.CertificateOut)
def get_certificate(session_id: int, user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    cert = _existing(db, s.id)
    if cert is None:
        raise HTTPException(404, "no certificate issued for this exercise")
    return cert


@router.get("/api/sessions/{session_id}/certificate.pdf")
def certificate_pdf(session_id: int, request: Request,
                    user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    cert = _existing(db, s.id)
    if cert is None:
        raise HTTPException(404, "no certificate issued for this exercise")
    audit.record(db, "certificate.export", request=request, user=user,
                 detail={"session_id": s.id, "serial": cert.serial, "format": "pdf"})
    verify_path = f"{request.base_url.scheme}://{request.base_url.netloc}/verify.html?serial={cert.serial}"
    return Response(content=certificates.render_pdf(cert, verify_path), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="certificate-{cert.serial}.pdf"'})


@router.post("/api/sessions/{session_id}/certificate/revoke", response_model=schemas.CertificateOut)
def revoke_certificate(session_id: int, request: Request,
                       user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    cert = _existing(db, s.id)
    if cert is None:
        raise HTTPException(404, "no certificate issued for this exercise")
    cert.revoked_at = datetime.now(timezone.utc)
    audit.record(db, "certificate.revoke", request=request, user=user,
                 detail={"session_id": s.id, "serial": cert.serial}, commit=False)
    db.commit()
    db.refresh(cert)
    return cert


@router.get("/api/certificates/{serial}/verify", response_model=schemas.CertificateVerifyOut)
def verify_certificate(serial: str, request: Request, db: Session = Depends(get_db)):
    """Public: anyone holding a serial can check that the numbers on the
    certificate are the ones this instance signed. Throttled per address;
    returns the signed record only, never the session."""
    key = f"cert|{client_ip(request)}"
    if throttle.retry_after(key) > 0:
        raise HTTPException(429, "too many verification requests; try again later")
    throttle.record_failure(key, limit=VERIFY_MAX_PER_WINDOW)  # counts lookups, not failures
    serial = serial.strip().upper()[:32]
    cert = db.execute(select(models.Certificate).where(models.Certificate.serial == serial)).scalars().first()
    if cert is None:
        return schemas.CertificateVerifyOut(serial=serial, valid=False, reason="no certificate with this serial")
    ok, reason = certificates.check(cert)
    return schemas.CertificateVerifyOut(serial=cert.serial, valid=ok, reason=reason, issued_at=cert.issued_at,
                                        record=certificates.public_record(cert) if ok else {})
