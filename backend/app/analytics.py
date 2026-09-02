"""Longitudinal maturity analytics (D3).

Trends an org's readiness *across exercises over time* — detection rate, mean
time-to-detect, objectives met, ATT&CK breadth. Answers the recurring tabletop
gripe that "lessons are never formalized / there's no institutional memory": here
the record is computed from the tamper-evident timeline, exercise over exercise.

Pure read-only aggregation over data the org already owns.
"""
from __future__ import annotations

from . import models

_RATING_WEIGHT = {"met": 1.0, "partial": 0.5, "missed": 0.0}


def _scored_events(session: models.Session) -> list[models.TimelineEvent]:
    return [e for e in session.events if e.kind in ("red_action", "adjudication")]


def _session_metrics(session: models.Session) -> dict:
    events = _scored_events(session)
    detected = sum(1 for e in events if e.payload.get("detected"))
    ttds = [e.payload.get("time_to_detect_min") for e in events
            if e.payload.get("detected") and e.payload.get("time_to_detect_min") is not None]
    techniques = {t for e in events for t in (e.payload.get("techniques") or [])}

    rated = [o for o in session.observations if o.rating in _RATING_WEIGHT]
    obj_met = (round(sum(_RATING_WEIGHT[o.rating] for o in rated) / len(rated), 3)
               if rated else None)

    from .decisions import summary as _decisions  # P1
    d = _decisions(session.events)
    return {
        "decision_score": d["mean_score"],
        "decision_latency_sec": d["median_latency_sec"],
        "session_id": session.id,
        "name": session.name,
        "date": session.created_at.isoformat() if session.created_at else None,
        "status": session.status,
        "red_actions": len(events),
        "detection_rate": round(detected / len(events), 3) if events else None,
        "mean_time_to_detect_min": round(sum(ttds) / len(ttds), 1) if ttds else None,
        "objectives_met_rate": obj_met,
        "techniques_covered": len(techniques),
    }


def _avg(values: list) -> float | None:
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 3) if vals else None


def _trend(series: list[dict], key: str) -> float | None:
    """Latest minus earliest non-null value — a simple improvement delta."""
    vals = [s[key] for s in series if s[key] is not None]
    if len(vals) < 2:
        return None
    return round(vals[-1] - vals[0], 3)


def maturity(sessions: list[models.Session]) -> dict:
    """Aggregate maturity across an org's sessions (oldest first)."""
    ordered = sorted(sessions, key=lambda s: (s.created_at or 0))
    series = [_session_metrics(s) for s in ordered]
    # Only exercises that actually produced adjudicated activity count toward trends.
    active = [m for m in series if m["red_actions"]]
    all_techs = {
        t for s in ordered for e in _scored_events(s) for t in (e.payload.get("techniques") or [])
    }
    return {
        "exercises": len(series),
        "exercises_with_activity": len(active),
        "summary": {
            "detection_rate": _avg([m["detection_rate"] for m in active]),
            "mean_time_to_detect_min": _avg([m["mean_time_to_detect_min"] for m in active]),
            "objectives_met_rate": _avg([m["objectives_met_rate"] for m in series]),
            "decision_score": _avg([m["decision_score"] for m in series]),
            "decision_latency_sec": _avg([m["decision_latency_sec"] for m in series]),
            "unique_techniques": len(all_techs),
        },
        "trend": {
            "detection_rate": _trend(active, "detection_rate"),
            "mean_time_to_detect_min": _trend(active, "mean_time_to_detect_min"),
            "objectives_met_rate": _trend(series, "objectives_met_rate"),
            "decision_score": _trend(series, "decision_score"),
        },
        "series": series,
    }
