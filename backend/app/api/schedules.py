"""Exercise scheduling & cadence (F3).

Recurring programmes, reminders, and on-demand materialisation of due runs.
Facilitators manage schedules; the run-due and reminders actions are the
pull-based hooks an operator or an external cron calls.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, models, notify, scheduling, schemas
from ..database import get_db
from ..security import require_staff, require_facilitator, scope_or_404

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


def _get(db: Session, schedule_id: int, user: models.User) -> models.ExerciseSchedule:
    return scope_or_404(db.get(models.ExerciseSchedule, schedule_id), user)


@router.post("", response_model=schemas.ScheduleOut, status_code=201)
def create_schedule(payload: schemas.ScheduleCreate, request: Request,
                    user: models.User = Depends(require_facilitator),
                    db: Session = Depends(get_db)):
    if payload.cadence not in models.CADENCES:
        raise HTTPException(422, f"cadence must be one of {list(models.CADENCES)}")
    # The scenario must belong to the caller's org.
    scope_or_404(db.get(models.Scenario, payload.scenario_id), user)
    sched = models.ExerciseSchedule(
        org_id=user.org_id, scenario_id=payload.scenario_id, name=payload.name,
        cadence=payload.cadence, next_run_at=payload.next_run_at,
        reminder_lead_hours=payload.reminder_lead_hours, invitees=payload.invitees,
    )
    db.add(sched)
    db.flush()
    audit.record(db, "schedule.create", request=request, user=user,
                 detail={"schedule_id": sched.id, "cadence": sched.cadence}, commit=False)
    db.commit()
    db.refresh(sched)
    return sched


@router.get("", response_model=list[schemas.ScheduleOut])
def list_schedules(user: models.User = Depends(require_staff), db: Session = Depends(get_db)):
    return db.execute(
        select(models.ExerciseSchedule)
        .where(models.ExerciseSchedule.org_id == user.org_id)
        .order_by(models.ExerciseSchedule.next_run_at)
    ).scalars().all()


@router.get("/reminders", response_model=list[schemas.ReminderOut])
def reminders(send: bool = False, user: models.User = Depends(require_staff),
              db: Session = Depends(get_db)):
    """Reminders whose lead window is open. With ``?send=true``, deliver them
    (record + optional webhook) and mark each as reminded."""
    due = scheduling.pending_reminders(db, user.org_id)
    out = []
    for s in due:
        if send:
            out.append(schemas.ReminderOut(**notify.send_reminder(db, s)))
            scheduling.mark_reminded(s)
        else:
            out.append(schemas.ReminderOut(**notify.reminder_payload(s)))
    if send:
        db.commit()
    return out


@router.post("/run-due", response_model=schemas.RunDueOut)
def run_due(request: Request, admin: models.User = Depends(require_facilitator),
            db: Session = Depends(get_db)):
    """Materialise a session for every schedule that is due now."""
    sessions = scheduling.run_due(db, admin.org_id)
    if sessions:
        audit.record(db, "schedule.run_due", request=request, user=admin,
                     detail={"count": len(sessions)}, commit=False)
    db.commit()
    return schemas.RunDueOut(ran=len(sessions), sessions=sessions)


@router.get("/{schedule_id}", response_model=schemas.ScheduleOut)
def get_schedule(schedule_id: int, user: models.User = Depends(require_staff),
                 db: Session = Depends(get_db)):
    return _get(db, schedule_id, user)


@router.patch("/{schedule_id}", response_model=schemas.ScheduleOut)
def update_schedule(schedule_id: int, payload: schemas.ScheduleUpdate,
                    user: models.User = Depends(require_facilitator),
                    db: Session = Depends(get_db)):
    sched = _get(db, schedule_id, user)
    data = payload.model_dump(exclude_unset=True)
    if "cadence" in data and data["cadence"] not in models.CADENCES:
        raise HTTPException(422, f"cadence must be one of {list(models.CADENCES)}")
    for k, v in data.items():
        setattr(sched, k, v)
    db.commit()
    db.refresh(sched)
    return sched


@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int, user: models.User = Depends(require_facilitator),
                    db: Session = Depends(get_db)):
    sched = _get(db, schedule_id, user)
    db.delete(sched)
    db.commit()
