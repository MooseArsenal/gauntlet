"""Reminder / invite delivery (F3).

The zero-infra default has no mail server, so delivery is pluggable and defaults
to **recording** the reminder (it lands in the security audit log and is returned
to the caller). An operator can point ``GAUNTLET_NOTIFY_WEBHOOK`` at their own
endpoint (Slack, Teams, an email relay) to actually push notifications.

Only fires against the single operator-configured URL — it never takes a target
from request data, so it isn't an SSRF vector.
"""
from __future__ import annotations

import os

from sqlalchemy.orm import Session

from . import audit, models


def _webhook_url() -> str:
    return os.environ.get("GAUNTLET_NOTIFY_WEBHOOK", "").strip()


def _post_webhook(payload: dict) -> bool:
    url = _webhook_url()
    if not url:
        return False
    try:
        import httpx

        httpx.post(url, json=payload, timeout=5.0)
        return True
    except Exception:  # noqa: BLE001 - delivery is best-effort; never break the flow
        return False


def reminder_payload(schedule: models.ExerciseSchedule) -> dict:
    return {
        "type": "exercise_reminder",
        "schedule_id": schedule.id,
        "name": schedule.name,
        "scenario_id": schedule.scenario_id,
        "run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "invitees": list(schedule.invitees or []),
    }


def send_reminder(db: Session, schedule: models.ExerciseSchedule) -> dict:
    """Record the reminder (always) and push it to the webhook (if configured)."""
    payload = reminder_payload(schedule)
    delivered = _post_webhook(payload)
    audit.record(db, "schedule.reminder", org_id=schedule.org_id, actor_email="system",
                 detail={"schedule_id": schedule.id, "delivered": delivered,
                         "invitees": len(payload["invitees"])},
                 commit=False)
    return {**payload, "delivered": delivered}
