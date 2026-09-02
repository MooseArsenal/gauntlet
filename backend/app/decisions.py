"""Participant decisions (P1): the room acts, not just watches.

Every inject can carry a decision card — a prompt with scored options, free
text, or both — declared in ``inject.meta["decision"]`` (authored in YAML or
the editor) or derived from the inject's expected actions when nothing is
declared. Participants answer from their own device; the answer lands on the
signed timeline as a ``response`` event with the cell, the option, the score,
and the latency from the moment the inject fired. The proctor sees the tally
live and still makes the ruling; scores roll up per participant, per session,
into analytics, the reports and the certificate.

Spec shape::

    {"prompt": "What does the SOC do first?",
     "options": [{"key": "a", "label": "Isolate the host", "score": 1.0, "note": "..."},
                 {"key": "b", "label": "Wait and monitor", "score": 0.2}],
     "free_text": false, "time_limit_sec": 180}
"""
from __future__ import annotations

from datetime import datetime, timezone
from statistics import median

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .engine import visibility
from .timeline import append_event

MAX_OPTIONS = 8
DEFAULT_PROMPT = "What does your cell do first?"


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def spec_for(inject) -> dict | None:
    """The decision card for an inject: declared, else derived from expected actions."""
    meta = getattr(inject, "meta", None) or {}
    declared = meta.get("decision")
    if isinstance(declared, dict) and (declared.get("options") or declared.get("free_text")):
        options = []
        for i, o in enumerate(list(declared.get("options") or [])[:MAX_OPTIONS]):
            if isinstance(o, str):
                o = {"label": o}
            label = str(o.get("label") or "").strip()
            if not label:
                continue
            try:
                score = max(0.0, min(1.0, float(o.get("score", 1.0))))
            except (TypeError, ValueError):
                score = 1.0
            options.append({"key": str(o.get("key") or chr(97 + i)), "label": label,
                            "score": score, "note": str(o.get("note") or "")})
        return {"prompt": str(declared.get("prompt") or DEFAULT_PROMPT), "options": options,
                "free_text": bool(declared.get("free_text")) or not options,
                "time_limit_sec": declared.get("time_limit_sec"), "derived": False,
                "kind": "comms" if declared.get("kind") == "comms" else "action"}
    actions = [str(a).strip() for a in (getattr(inject, "expected_actions", None) or []) if str(a).strip()]
    if not actions:
        return None
    options = [{"key": chr(97 + i), "label": a, "score": 1.0, "note": ""} for i, a in enumerate(actions[:MAX_OPTIONS - 1])]
    options.append({"key": chr(97 + len(options)), "label": "Wait and monitor", "score": 0.2, "note": "Delay rarely helps."})
    return {"prompt": DEFAULT_PROMPT, "options": options, "free_text": False, "time_limit_sec": None, "derived": True, "kind": "action"}


def public_spec(spec: dict | None) -> dict | None:
    """What a participant sees: never the scores or the proctor's notes."""
    if not spec:
        return None
    return {"prompt": spec["prompt"], "free_text": spec["free_text"], "time_limit_sec": spec.get("time_limit_sec"),
            "kind": spec.get("kind", "action"),
            "options": [{"key": o["key"], "label": o["label"]} for o in spec["options"]]}


def _responses(session, inject_code: str | None = None) -> list:
    return [e for e in session.events if e.kind == "response"
            and (inject_code is None or (e.payload or {}).get("inject_code") == inject_code)]


def _fired_at(session, inject_code: str):
    fired = [e for e in session.events if e.kind == "inject_fired" and e.ref == inject_code]
    return _aware(fired[-1].at) if fired else None


def my_response(session, user_id: int, inject_code: str | None) -> dict | None:
    if not inject_code:
        return None
    for e in reversed(_responses(session, inject_code)):
        if (e.payload or {}).get("user_id") == user_id:
            return e.payload
    return None


def record(db: Session, session: models.Session, scenario: models.Scenario, user: models.User,
           cell: str, display_name: str, inject_code: str | None, option: str | None, text: str) -> models.TimelineEvent:
    code = inject_code or session.current_inject_code
    if not code:
        raise HTTPException(status.HTTP_409_CONFLICT, "no inject is live")
    inject = db.execute(select(models.Inject).where(
        models.Inject.scenario_id == scenario.id, models.Inject.code == code)).scalar_one_or_none()
    if inject is None:
        raise HTTPException(404, f"no inject '{code}'")
    if not visibility.is_control_cell(scenario, cell) and not visibility.inject_visible_to(inject.visible_to or [], cell):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "this inject was not addressed to your cell")
    if _fired_at(session, code) is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "that inject has not fired yet")
    spec = spec_for(inject)
    if spec is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "this inject asks for no decision")
    if my_response(session, user.id, code) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "you have already answered this inject")
    chosen = None
    if option:
        chosen = next((o for o in spec["options"] if o["key"] == option), None)
        if chosen is None:
            raise HTTPException(422, f"unknown option '{option}'")
    text = (text or "").strip()
    if chosen is None and not text:
        raise HTTPException(422, "choose an option or write what you would do")
    if chosen is None and not spec["free_text"]:
        raise HTTPException(422, "this decision needs one of the options")
    if spec.get("kind") == "comms" and not text:
        raise HTTPException(422, "a communications decision needs the statement you would issue")
    now = datetime.now(timezone.utc)
    latency = round((now - _fired_at(session, code)).total_seconds(), 1)
    payload = {"inject_code": code, "cell": cell, "user_id": user.id, "display_name": display_name or user.email,
               "kind": spec.get("kind", "action"),
               "option": chosen["key"] if chosen else None, "label": chosen["label"] if chosen else None,
               "text": text[:4000], "score": chosen["score"] if chosen else None, "latency_sec": latency}
    return append_event(db, session.id, kind="response", ref=code, game_clock=inject.clock or "", payload=payload)


def tally(db: Session, session: models.Session, scenario: models.Scenario, inject_code: str | None) -> dict:
    code = inject_code or session.current_inject_code
    if not code:
        return {"inject_code": None, "spec": None, "responses": 0, "expected": 0, "options": [], "free_text": [], "responders": []}
    inject = db.execute(select(models.Inject).where(
        models.Inject.scenario_id == scenario.id, models.Inject.code == code)).scalar_one_or_none()
    spec = spec_for(inject) if inject else None
    rows = [e.payload for e in _responses(session, code)]
    joined = db.execute(select(models.SessionJoin).where(models.SessionJoin.session_id == session.id)).scalars().all()
    expected = [j for j in joined if inject is None or visibility.is_control_cell(scenario, j.cell)
                or visibility.inject_visible_to(inject.visible_to or [], j.cell)]
    counts = {o["key"]: 0 for o in (spec or {}).get("options", [])}
    for r in rows:
        if r.get("option") in counts:
            counts[r["option"]] += 1
    lat = [r["latency_sec"] for r in rows if r.get("latency_sec") is not None]
    sc = [r["score"] for r in rows if r.get("score") is not None]
    return {
        "inject_code": code, "spec": spec, "responses": len(rows), "expected": len(expected),
        "options": [{**o, "count": counts.get(o["key"], 0)} for o in (spec or {}).get("options", [])],
        "free_text": [{"display_name": r.get("display_name"), "cell": r.get("cell"), "text": r["text"]} for r in rows if r.get("text")],
        "responders": [{"display_name": r.get("display_name"), "cell": r.get("cell"), "option": r.get("option"),
                        "label": r.get("label"), "score": r.get("score"), "latency_sec": r.get("latency_sec")} for r in rows],
        "median_latency_sec": round(median(lat), 1) if lat else None,
        "mean_score": round(sum(sc) / len(sc), 3) if sc else None,
    }


def participant_scores(db: Session, session: models.Session) -> list[dict]:
    """One row per person who answered anything: how many, how well, how fast."""
    per: dict[int, dict] = {}
    for e in _responses(session):
        p = e.payload or {}
        row = per.setdefault(p.get("user_id"), {"user_id": p.get("user_id"), "display_name": p.get("display_name"),
                                                 "cell": p.get("cell"), "responses": 0, "scores": [], "latencies": []})
        row["responses"] += 1
        if p.get("score") is not None:
            row["scores"].append(p["score"])
        if p.get("latency_sec") is not None:
            row["latencies"].append(p["latency_sec"])
    out = []
    for r in per.values():
        out.append({"user_id": r["user_id"], "display_name": r["display_name"], "cell": r["cell"],
                    "responses": r["responses"],
                    "mean_score": round(sum(r["scores"]) / len(r["scores"]), 3) if r["scores"] else None,
                    "median_latency_sec": round(median(r["latencies"]), 1) if r["latencies"] else None})
    return sorted(out, key=lambda r: (-(r["mean_score"] or 0), r["median_latency_sec"] or 1e9))


def summary(events) -> dict:
    """Session-level roll-up for analytics, reports and the certificate."""
    rows = [e.payload or {} for e in events if e.kind == "response"]
    sc = [r["score"] for r in rows if r.get("score") is not None]
    lat = [r["latency_sec"] for r in rows if r.get("latency_sec") is not None]
    return {"responses": len(rows), "responders": len({r.get("user_id") for r in rows}),
            "injects_answered": len({r.get("inject_code") for r in rows}),
            "mean_score": round(sum(sc) / len(sc), 3) if sc else None,
            "median_latency_sec": round(median(lat), 1) if lat else None}
