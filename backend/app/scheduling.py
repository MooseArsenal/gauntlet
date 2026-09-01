"""Exercise scheduling & cadence (F3).

Turns Gauntlet from a run-it-once tool into a **programme**: schedule a scenario
to recur (weekly drills, quarterly tabletops), get a reminder ahead of each run,
and have the session materialise when it comes due.

There is no always-on worker in the zero-infra default, so this is pull-based:
``due_schedules`` / ``run_due`` are invoked by an operator action or an external
cron hitting the API. The cadence maths and the session materialisation live
here so they're unit-testable without a clock daemon.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _add_months(dt: datetime, months: int) -> datetime:
    month_index = dt.month - 1 + months
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    # Clamp the day to the target month's length (e.g. Jan 31 + 1mo -> Feb 28).
    day = min(dt.day, _days_in_month(year, month))
    return dt.replace(year=year, month=month, day=day)


def _days_in_month(year: int, month: int) -> int:
    if month == 12:
        nxt = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        nxt = datetime(year, month + 1, 1, tzinfo=timezone.utc)
    return (nxt - timedelta(days=1)).day


def next_occurrence(after: datetime, cadence: str) -> datetime | None:
    """The run time following ``after`` for a cadence. ``once`` has none."""
    after = _aware(after)
    if cadence == "daily":
        return after + timedelta(days=1)
    if cadence == "weekly":
        return after + timedelta(weeks=1)
    if cadence == "monthly":
        return _add_months(after, 1)
    if cadence == "quarterly":
        return _add_months(after, 3)
    return None  # "once"


def due_schedules(db: Session, org_id: int, now: datetime | None = None) -> list[models.ExerciseSchedule]:
    now = _aware(now or datetime.now(timezone.utc))
    rows = db.execute(
        select(models.ExerciseSchedule).where(
            models.ExerciseSchedule.org_id == org_id,
            models.ExerciseSchedule.enabled.is_(True),
        )
    ).scalars()
    return [s for s in rows if _aware(s.next_run_at) <= now]


def run_schedule(db: Session, schedule: models.ExerciseSchedule,
                 now: datetime | None = None) -> models.Session:
    """Materialise a session from the schedule and advance (or retire) it."""
    now = _aware(now or datetime.now(timezone.utc))
    scenario = db.get(models.Scenario, schedule.scenario_id)
    session = models.Session(
        org_id=schedule.org_id,
        scenario_id=schedule.scenario_id,
        name=f"{schedule.name} — {now.date().isoformat()}",
    )
    db.add(session)

    schedule.last_run_at = now
    nxt = next_occurrence(_aware(schedule.next_run_at), schedule.cadence)
    if nxt is None:
        schedule.enabled = False  # a one-off is done
    else:
        # Skip ahead past any missed windows so we don't fire a backlog at once.
        while nxt <= now:
            nxt = next_occurrence(nxt, schedule.cadence)
        schedule.next_run_at = nxt
    db.flush()
    return session


def run_due(db: Session, org_id: int, now: datetime | None = None) -> list[models.Session]:
    return [run_schedule(db, s, now) for s in due_schedules(db, org_id, now)]


def pending_reminders(db: Session, org_id: int, now: datetime | None = None
                      ) -> list[models.ExerciseSchedule]:
    """Enabled schedules whose reminder window is open and not yet reminded."""
    now = _aware(now or datetime.now(timezone.utc))
    out = []
    for s in db.execute(
        select(models.ExerciseSchedule).where(
            models.ExerciseSchedule.org_id == org_id,
            models.ExerciseSchedule.enabled.is_(True),
        )
    ).scalars():
        run_at = _aware(s.next_run_at)
        window_opens = run_at - timedelta(hours=s.reminder_lead_hours)
        already = s.reminded_for is not None and _aware(s.reminded_for) == run_at
        if window_opens <= now < run_at and not already:
            out.append(s)
    return out


def mark_reminded(schedule: models.ExerciseSchedule) -> None:
    schedule.reminded_for = schedule.next_run_at
