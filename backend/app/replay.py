"""Session replay (L4): the exercise as a paced narrative, and rewind-to-branch.

Replay reads the signed timeline and folds it into scenes — one per inject
that fired — each carrying what the room answered, what the engine ruled,
what the red cell tried, the branch the proctor took, what it cost, and the
branches that were *not* taken. Nothing is stored: the record is the chain.

Rewind never edits history. It forks a new session from the state the
original had when a chosen scene began, fires that scene again, and notes on
both chains where the fork happened — so a class can replay a decision point
and see the other road without touching the graded run.
"""
from __future__ import annotations

from datetime import timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models, session_ops
from .engine import msel
from .timeline import append_event


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt):
    dt = _aware(dt)
    return dt.isoformat() if dt else None


def build(db: Session, session: models.Session, scenario: models.Scenario) -> dict:
    injects = {i.code: i for i in db.execute(select(models.Inject).where(
        models.Inject.scenario_id == scenario.id)).scalars().all()}
    events = sorted(session.events, key=lambda e: e.seq)
    state = dict(scenario.variables or {})
    scenes: list[dict] = []
    cur: dict | None = None
    started = None
    for e in events:
        p = e.payload or {}
        if e.kind == "status" and p.get("status") == "running" and started is None:
            started = _aware(e.at)
        if e.kind == "inject_fired":
            inj = injects.get(e.ref)
            prev_at = _aware(scenes[-1]["_at"]) if scenes else (started or _aware(e.at))
            cur = {
                "seq": e.seq, "code": e.ref, "title": p.get("title", ""), "channel": p.get("channel", ""),
                "narrative": p.get("narrative", ""), "clock": e.game_clock, "at": _iso(e.at), "_at": e.at,
                "elapsed_sec": max(0, round((_aware(e.at) - prev_at).total_seconds())),
                "visible_to": p.get("visible_to") or [], "techniques": p.get("techniques") or [],
                "expected_actions": p.get("expected_actions") or [],
                "state_before": dict(state), "responses": [], "rulings": [], "red_actions": [], "notes": [],
                "evidence": [], "telemetry": [], "decision": None,
                "branches": [{"label": b.get("label", ""), "when": b.get("when"), "trigger": b.get("trigger"),
                              "goto": b.get("goto"), "taken": False}
                             for b in msel.available_branches(inj, state)] if inj is not None else [],
            }
            scenes.append(cur)
            continue
        if cur is None:
            continue
        if e.kind == "response":
            cur["responses"].append({"display_name": p.get("display_name"), "cell": p.get("cell"),
                                     "label": p.get("label"), "text": p.get("text", ""), "score": p.get("score"),
                                     "latency_sec": p.get("latency_sec")})
        elif e.kind == "adjudication":
            cur["rulings"].append({"action": p.get("description") or "", "techniques": p.get("techniques") or [],
                                   "target": p.get("target_asset") or "", "outcome": p.get("suggested_outcome"),
                                   "probability": p.get("probability"), "detected": p.get("detected"),
                                   "time_to_detect_min": p.get("time_to_detect_min"), "rationale": p.get("rationale") or ""})
        elif e.kind == "red_action":
            cur["red_actions"].append({"action": p.get("action") or "", "techniques": p.get("techniques") or [],
                                       "target": p.get("target_asset") or "", "outcome": p.get("suggested_outcome"),
                                       "detected": p.get("detected")})
        elif e.kind == "note":
            cur["notes"].append(p.get("text") or p.get("note") or "")
        elif e.kind == "evidence":
            cur["evidence"].append(p.get("filename") or p.get("note") or "attachment")
        elif e.kind == "telemetry":
            cur["telemetry"].append({"technique": p.get("technique"), "matched": p.get("matched"),
                                     "latency_sec": p.get("latency_sec")})
        elif e.kind == "decision":
            cur["decision"] = {"label": p.get("label", ""), "goto": p.get("goto"), "when": p.get("when"),
                               "trigger": p.get("trigger"), "note": p.get("note", ""), "impact": p.get("impact"),
                               "at": _iso(e.at)}
            for b in cur["branches"]:
                if b["goto"] == p.get("goto") and (b["label"] == p.get("label") or not b["taken"]):
                    b["taken"] = True
                    break
            state = dict(p.get("state") or state)
        elif e.kind == "status" and p.get("status") == "complete":
            cur["ended"] = True
    for sc in scenes:
        sc.pop("_at", None)
        sc["narrative_line"] = _line(sc)
        sc["alternatives"] = [b for b in sc["branches"] if not b["taken"]]
    ended = next((e for e in events if e.kind == "status" and (e.payload or {}).get("status") == "complete"), None)
    duration = None
    if started and scenes:
        last = _aware(ended.at) if ended else _aware(events[-1].at)
        duration = round((last - started).total_seconds())
    return {"session": {"id": session.id, "name": session.name, "status": session.status, "state": dict(session.state or {})},
            "scenario": {"id": scenario.id, "name": scenario.name, "threat_actor": scenario.threat_actor},
            "started_at": _iso(started) if started else None, "duration_sec": duration,
            "scenes": scenes, "branch_points": sum(1 for s in scenes if len(s["branches"]) > 1),
            "rewound_from": (session.state or {}).get("rewound_from")}


def _line(sc: dict) -> str:
    bits = [f"{sc['clock'] or 'T+?'} — {sc['code']} {sc['title']}".strip()]
    if sc["responses"]:
        sc_ = [r["score"] for r in sc["responses"] if r["score"] is not None]
        bits.append(f"{len(sc['responses'])} answered" + (f", mean score {sum(sc_) / len(sc_):.2f}" if sc_ else ""))
    if sc["rulings"]:
        bits.append("ruled " + ", ".join(str(r["outcome"]) for r in sc["rulings"] if r.get("outcome")))
    if sc["decision"]:
        bits.append(f"the room took '{sc['decision']['label'] or sc['decision']['goto']}' → {sc['decision']['goto']}")
        alt = [b for b in sc["branches"] if not b["taken"]]
        if alt:
            bits.append(f"{len(alt)} other road{'s' if len(alt) > 1 else ''} not taken")
    elif sc.get("ended"):
        bits.append("the exercise ended here")
    return "; ".join(bits) + "."


def scene_at(db: Session, session: models.Session, scenario: models.Scenario, seq: int) -> dict:
    for sc in build(db, session, scenario)["scenes"]:
        if sc["seq"] == seq:
            return sc
    raise HTTPException(404, f"no scene begins at seq {seq}")


def fork(db: Session, source: models.Session, scenario: models.Scenario, seq: int, user: models.User,
         name: str | None = None) -> models.Session:
    """A new running session that begins at the chosen scene with the state the
    original had then. The original is untouched except for a note that it
    was rewound from there."""
    if source.status == "setup":
        raise HTTPException(status.HTTP_409_CONFLICT, "nothing to rewind: the exercise has not started")
    sc = scene_at(db, source, scenario, seq)
    inject = db.execute(select(models.Inject).where(
        models.Inject.scenario_id == scenario.id, models.Inject.code == sc["code"])).scalar_one_or_none()
    if inject is None:
        raise HTTPException(404, f"inject {sc['code']} no longer exists in the scenario")
    s = models.Session(org_id=source.org_id, scenario_id=scenario.id,
                       name=(name or f"{source.name} · rewind at {sc['code']}")[:200],
                       clock_mode=source.clock_mode, mode=source.mode, auto_advance=source.auto_advance,
                       cohort_id=source.cohort_id, status="running", started_at=_now(),
                       auth_scope=list(source.auth_scope or []), authorized_by=source.authorized_by,
                       auth_expires_at=source.auth_expires_at)
    s.state = {**dict(sc["state_before"]), "rewound_from": {"session_id": source.id, "seq": seq, "code": sc["code"]}}
    db.add(s)
    db.flush()
    append_event(db, s.id, kind="status", payload={"status": "running", "rewound_from": {"session_id": source.id, "seq": seq}})
    append_event(db, s.id, kind="note", ref=sc["code"], game_clock=sc["clock"] or "",
                 payload={"text": f"Rewound from exercise #{source.id} at {sc['code']}; state restored to that moment.",
                          "by": user.email})
    session_ops.fire_inject(db, s, inject)
    append_event(db, source.id, kind="note", ref=sc["code"], game_clock=sc["clock"] or "",
                 payload={"text": f"Rewound at {sc['code']} into exercise #{s.id}.", "by": user.email})
    return s


def _now():
    from datetime import datetime
    return datetime.now(timezone.utc)
