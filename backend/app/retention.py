"""Data lifecycle (M10): retention purge, portability export, and erasure.

Holding exercise data forever is a liability, not an asset — old sessions and
audit trails are breach surface with diminishing value. These helpers give a
tenant control over its own data:

* **purge** — delete a tenant's *completed* sessions (and their timeline,
  observations, reports) and audit-log entries older than a retention window;
* **export** — a full JSON snapshot of the tenant's data (GDPR portability);
* **erase** — hard-delete a tenant and everything it owns (right to erasure).

All operations are tenant-scoped: they touch only rows belonging to the given
``org_id``. Deletes are ordered child-before-parent so they hold even where the
database (SQLite) does not enforce foreign-key cascades.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _org_session_ids(db: Session, org_id: int) -> list[int]:
    return list(db.execute(
        select(models.Session.id).where(models.Session.org_id == org_id)
    ).scalars())


def _delete_sessions(db: Session, session_ids: list[int]) -> None:
    """Delete sessions and their children (timeline, observations, reports)."""
    if not session_ids:
        return
    # Lobby rows go with the session; improvement items are the org's backlog
    # and outlive the exercise record, so they lose the reference, not the row.
    for row in db.execute(
        select(models.SessionJoin).where(models.SessionJoin.session_id.in_(session_ids))
    ).scalars():
        db.delete(row)
    for item in db.execute(
        select(models.ImprovementItem).where(models.ImprovementItem.session_id.in_(session_ids))
    ).scalars():
        item.session_id = None
    for model in (models.Report, models.Certificate, models.Attachment, models.TimelineEvent, models.Observation):
        for row in db.execute(
            select(model).where(model.session_id.in_(session_ids))
        ).scalars():
            db.delete(row)
    for s in db.execute(
        select(models.Session).where(models.Session.id.in_(session_ids))
    ).scalars():
        db.delete(s)


# --------------------------------------------------------------------------- #
# retention purge
# --------------------------------------------------------------------------- #
def purge_org(db: Session, org_id: int, days: int) -> dict:
    """Delete this org's completed sessions and audit entries older than ``days``.

    Returns counts of what was removed. ``days <= 0`` is a no-op (retention off).
    """
    if days <= 0:
        return {"sessions": 0, "audit_logs": 0}
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Completed sessions past the window. completed_at may be null on older rows;
    # fall back to created_at so nothing lingers indefinitely.
    stale = []
    for s in db.execute(
        select(models.Session).where(
            models.Session.org_id == org_id,
            models.Session.status == "complete",
        )
    ).scalars():
        stamp = s.completed_at or s.created_at
        if stamp is not None and _aware(stamp) < cutoff:
            stale.append(s.id)
    _delete_sessions(db, stale)

    audit_n = 0
    for a in db.execute(
        select(models.AuditLog).where(models.AuditLog.org_id == org_id)
    ).scalars():
        if a.at is not None and _aware(a.at) < cutoff:
            db.delete(a)
            audit_n += 1

    db.flush()
    return {"sessions": len(stale), "audit_logs": audit_n}


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# portability export
# --------------------------------------------------------------------------- #
def export_org(db: Session, org_id: int) -> dict:
    """A JSON-serialisable snapshot of everything the org owns."""
    org = db.get(models.Organization, org_id)
    if org is None:
        return {}

    def rows(model, **where):
        stmt = select(model)
        for col, val in where.items():
            stmt = stmt.where(getattr(model, col) == val)
        return list(db.execute(stmt).scalars())

    env_ids = [e.id for e in rows(models.Environment, org_id=org_id)]
    scn_ids = [s.id for s in rows(models.Scenario, org_id=org_id)]
    ses_ids = _org_session_ids(db, org_id)

    def dump(obj, drop=()):  # a plain dict of an ORM row's columns
        d = {c.name: getattr(obj, c.name) for c in obj.__table__.columns}
        for k in drop:
            d.pop(k, None)
        return _isoformat(d)

    return {
        "organization": dump(org),
        "users": [dump(u, drop=("password_hash", "mfa_secret")) for u in rows(models.User, org_id=org_id)],
        "environments": [dump(e) for e in rows(models.Environment, org_id=org_id)],
        "scenarios": [dump(s) for s in rows(models.Scenario, org_id=org_id)],
        "objectives": [dump(o) for sid in scn_ids for o in rows(models.Objective, scenario_id=sid)],
        "injects": [dump(i) for sid in scn_ids for i in rows(models.Inject, scenario_id=sid)],
        "sessions": [dump(s) for s in rows(models.Session, org_id=org_id)],
        "timeline_events": [dump(t) for sid in ses_ids for t in rows(models.TimelineEvent, session_id=sid)],
        "observations": [dump(o) for sid in ses_ids for o in rows(models.Observation, session_id=sid)],
        "reports": [dump(r) for sid in ses_ids for r in rows(models.Report, session_id=sid)],
        "audit_logs": [dump(a) for a in rows(models.AuditLog, org_id=org_id)],
    }


def _isoformat(d: dict) -> dict:
    return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in d.items()}


# --------------------------------------------------------------------------- #
# erasure
# --------------------------------------------------------------------------- #
def erase_org(db: Session, org_id: int) -> dict:
    """Hard-delete the org and everything it owns. Ordered child-before-parent."""
    counts: dict[str, int] = {}

    scn_ids = [s.id for s in db.execute(
        select(models.Scenario).where(models.Scenario.org_id == org_id)).scalars()]
    user_ids = [u.id for u in db.execute(
        select(models.User).where(models.User.org_id == org_id)).scalars()]
    ses_ids = _org_session_ids(db, org_id)

    counts["sessions"] = len(ses_ids)
    _delete_sessions(db, ses_ids)

    def wipe(model, ids, col="scenario_id"):
        n = 0
        if ids:
            for row in db.execute(select(model).where(getattr(model, col).in_(ids))).scalars():
                db.delete(row)
                n += 1
        return n

    counts["session_joins"] = wipe(models.SessionJoin, [org_id], col="org_id")
    counts["certificates"] = wipe(models.Certificate, [org_id], col="org_id")
    counts["attachments"] = wipe(models.Attachment, [org_id], col="org_id")
    counts["improvement_items"] = wipe(models.ImprovementItem, [org_id], col="org_id")
    counts["custom_adversaries"] = wipe(models.CustomAdversary, [org_id], col="org_id")
    counts["schedules"] = wipe(models.ExerciseSchedule, [org_id], col="org_id")
    counts["injects"] = wipe(models.Inject, scn_ids)
    counts["objectives"] = wipe(models.Objective, scn_ids)
    counts["scenarios"] = wipe(models.Scenario, [org_id], col="org_id")
    counts["environments"] = wipe(models.Environment, [org_id], col="org_id")
    counts["refresh_tokens"] = wipe(models.RefreshToken, user_ids, col="user_id")
    counts["audit_logs"] = wipe(models.AuditLog, [org_id], col="org_id")
    counts["users"] = wipe(models.User, [org_id], col="org_id")

    org = db.get(models.Organization, org_id)
    if org is not None:
        db.delete(org)
    counts["organization"] = 1 if org is not None else 0

    db.flush()
    return counts
