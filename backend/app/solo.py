"""Solo learning mode (S1): one person, one side, the engine as the other side.

A free-tier front door. The player picks a side — blue (respond to what the
adversary does), executive (the communications and business decisions) or red
(attack the environment and stay unseen) — and a scenario. The same engine
runs the exercise; an autopilot proctor takes the seat a human facilitator
normally holds:

* Blue / executive: every scene is a decision card. The chosen option picks
  the branch (an authored ``trigger``/``goto`` on the option, else the
  better options take the action-taken road and the poorer ones the timeout
  road), the scene's adversary techniques are adjudicated automatically so
  the scoreboard fills in, and the next scene fires. Silence past the time
  limit is a decision too.
* Red: each move is ruled against the environment's controls. Three
  detections and the defenders evict you; reach a crown jewel undetected and
  you win; the move budget runs out otherwise.

Every run ends in a debrief — a score, what was chosen against what was best,
the authored coaching note for each decision, and what to work on — as a
page and a PDF. Solo runs are flagged ``mode="solo"`` and never count toward
an organisation's readiness figures or the sector benchmark.
"""
from __future__ import annotations

from datetime import datetime, timezone
from statistics import median

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import decisions, engagements, models, session_ops
from .engine import adjudication, msel, visibility
from .timeline import append_event

SIDES = {"blue": "blue_cell", "exec": "exec_cell", "red": "red_cell"}
SIDE_LABELS = {"blue": "Blue team — SOC and incident response", "exec": "Executive — leadership and communications",
               "red": "Red team — the adversary"}
MAX_MOVES = 8
MAX_ALERT = 3
DEFAULT_TIME_LIMIT = 120


def _now():
    return datetime.now(timezone.utc)


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _events(db: Session, s: models.Session) -> list[models.TimelineEvent]:
    """Fresh from the database: the ORM collection can lag within a request."""
    return db.execute(select(models.TimelineEvent).where(models.TimelineEvent.session_id == s.id)
                      .order_by(models.TimelineEvent.seq)).scalars().all()


def solo_state(s: models.Session) -> dict:
    return dict((s.state or {}).get("solo") or {})


def _set_solo(s: models.Session, **changes) -> None:
    st = dict(s.state or {})
    solo = dict(st.get("solo") or {})
    solo.update(changes)
    st["solo"] = solo
    s.state = st


def is_solo(s: models.Session) -> bool:
    return s.mode == "solo"


# --------------------------------------------------------------------------- #
# catalogue
# --------------------------------------------------------------------------- #
def _injects(db: Session, scenario_id: int) -> list[models.Inject]:
    return db.execute(select(models.Inject).where(models.Inject.scenario_id == scenario_id)
                      .order_by(models.Inject.sequence, models.Inject.id)).scalars().all()


def sides_for(scenario: models.Scenario, injects: list[models.Inject]) -> list[str]:
    keys = {c.get("key") for c in (scenario.cells or [])}
    out = []
    if any(decisions.spec_for(i) and (not i.visible_to or visibility.inject_visible_to(i.visible_to, "blue_cell")) for i in injects):
        out.append("blue")
    if "exec_cell" in keys and any(decisions.spec_for(i) and visibility.inject_visible_to(i.visible_to or [], "exec_cell") for i in injects):
        out.append("exec")
    out.append("red")  # any environment with assets can be attacked
    return out


def catalog(db: Session, user: models.User) -> list[dict]:
    scenarios = db.execute(select(models.Scenario).where(
        models.Scenario.org_id == user.org_id, models.Scenario.archived_at.is_(None),
        models.Scenario.exercise_type != "solo").order_by(models.Scenario.id)).scalars().all()
    if not scenarios:
        # A brand-new workspace (a learner who just created an account): give
        # it the bundled library so there is something to play right away.
        from . import seed
        scenarios = seed.provision_library(db, user.org_id)
        db.commit()
    best = {}
    for r in runs(db, user):
        if r["score"] is not None:
            k = (r["scenario_id"], r["side"])
            best[k] = max(best.get(k, 0), r["score"])
    out = []
    for sc in scenarios:
        inj = _injects(db, sc.id)
        if not inj:
            continue
        env = db.get(models.Environment, sc.environment_id)
        n = len(inj)
        out.append({"id": sc.id, "name": sc.name, "threat_actor": sc.threat_actor, "environment": env.name if env else "",
                    "sector": env.sector if env else "", "scenes": n,
                    "difficulty": "short" if n <= 4 else "standard" if n <= 8 else "long",
                    "sides": sides_for(sc, inj),
                    "best": {side: best.get((sc.id, side)) for side in ("blue", "exec", "red")}})
    return out


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
def start(db: Session, user: models.User, scenario: models.Scenario, side: str, difficulty: str = "standard",
          etype: str | None = None) -> models.Session:
    if side not in SIDES:
        raise HTTPException(422, f"side must be one of {list(SIDES)}")
    if difficulty not in engagements.LEVERS:
        raise HTTPException(422, f"difficulty must be one of {list(engagements.LEVERS)}")
    injects = _injects(db, scenario.id)
    if side not in sides_for(scenario, injects):
        raise HTTPException(status.HTTP_409_CONFLICT, f"this scenario has nothing for the {side} side to do")
    first = msel.get_start_inject(injects)
    if not first:
        raise HTTPException(status.HTTP_409_CONFLICT, "the scenario has no starting scene")
    s = models.Session(org_id=user.org_id, scenario_id=scenario.id, name=f"Solo {side}: {scenario.name}"[:200],
                       mode="solo", auto_advance=False, status="running", started_at=_now(),
                       state={**dict(scenario.variables or {}),
                              "solo": {"side": side, "user_id": user.id, "alert": 0, "moves": 0, "started": _now().isoformat(),
                                       "difficulty": difficulty, "type": etype, "foothold": False}})
    db.add(s)
    db.flush()
    db.add(models.SessionJoin(org_id=user.org_id, session_id=s.id, user_id=user.id,
                              display_name=user.name or user.email, cell=SIDES[side]))
    append_event(db, s.id, kind="status", payload={"status": "running", "solo": side})
    session_ops.fire_inject(db, s, first)
    if side != "red":
        _script_adversary(db, s, scenario, first)
    _maybe_finish(db, s, scenario, first)
    db.flush()
    return s


def require_own(s: models.Session, user: models.User) -> None:
    if not is_solo(s):
        raise HTTPException(404, "not a solo run")
    if solo_state(s).get("user_id") != user.id and user.role not in ("admin", "facilitator"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "that is someone else's run")


def _env(db: Session, scenario: models.Scenario) -> models.Environment:
    return db.get(models.Environment, scenario.environment_id)


def _script_adversary(db: Session, s: models.Session, scenario: models.Scenario, inject: models.Inject) -> dict | None:
    """The scene's own techniques, ruled against the environment: the adversary
    the blue player is responding to actually 'moves', so detection figures exist."""
    techs = list(inject.attack_techniques or [])
    if not techs:
        return None
    ruling = adjudication.adjudicate(_env(db, scenario), techs, inject.target_asset or "")
    append_event(db, s.id, kind="adjudication", ref=inject.code, game_clock=inject.clock or "",
                 payload={**ruling, "description": f"Scripted adversary: {inject.title}", "scripted": True})
    return ruling


def _current(db: Session, s: models.Session) -> models.Inject | None:
    return session_ops.current_inject(db, s)


def _terminal(inject: models.Inject, state) -> bool:
    return not msel.available_branches(inject, state)


def _maybe_finish(db: Session, s: models.Session, scenario: models.Scenario, inject: models.Inject) -> bool:
    """A final scene with nothing to decide ends the run at once."""
    if s.status == "running" and _terminal(inject, s.state) and decisions.spec_for(inject) is None:
        finish(db, s, scenario, reason="The story reached its end.")
        return True
    return False


def _declared_option(inject: models.Inject, key: str | None) -> dict:
    for o in ((inject.meta or {}).get("decision") or {}).get("options") or []:
        if isinstance(o, dict) and str(o.get("key") or "") == key:
            return o
    return {}


def _autopilot(db: Session, s: models.Session, scenario: models.Scenario, inject: models.Inject,
               spec: dict | None, chosen: dict | None, timed_out: bool = False) -> models.Inject | None:
    """Pick the branch a facilitator would have picked for this decision."""
    branches = msel.available_branches(inject, s.state)
    if not branches:
        finish(db, s, scenario, reason="The story reached its end.")
        return None
    declared = _declared_option(inject, chosen["key"]) if chosen else {}
    branch = None
    if declared.get("goto") or declared.get("trigger"):
        branch = next((b for b in branches if b.get("goto") == declared.get("goto") or
                       (declared.get("trigger") and b.get("trigger") == declared.get("trigger"))), None)
    timeout = next((b for b in branches if b.get("when") == msel.WHEN_TIMEOUT), None)
    actions = [b for b in branches if b.get("when") == msel.WHEN_ACTION]
    others = [b for b in branches if b.get("when") not in (msel.WHEN_TIMEOUT,)]
    if branch is None:
        score = (chosen or {}).get("score")
        if timed_out or (score is not None and score < 0.5):
            branch = timeout or (others[-1] if others else branches[-1])
        else:
            branch = (actions[0] if actions else (others[0] if others else branches[0]))
    label = branch.get("label") or branch.get("goto")
    why = "no decision before the clock ran out" if timed_out else f"you chose '{(chosen or {}).get('label', 'your own words')}'"
    try:
        nxt = session_ops.advance(db, s, inject, when=branch.get("when", msel.WHEN_PROCTOR),
                                  trigger=branch.get("trigger") or branch.get("label"), goto=branch.get("goto"),
                                  note=f"Autopilot: {why} → {label}")
    except (LookupError, ValueError):
        nxt = session_ops.advance(db, s, inject, when=msel.WHEN_PROCTOR, goto=branch.get("goto"),
                                  note=f"Autopilot: {why} → {label}")
    if solo_state(s).get("side") != "red":
        _script_adversary(db, s, scenario, nxt)
    _maybe_finish(db, s, scenario, nxt)
    return nxt


def respond(db: Session, s: models.Session, scenario: models.Scenario, user: models.User,
            option: str | None, text: str) -> dict:
    if s.status != "running":
        raise HTTPException(status.HTTP_409_CONFLICT, "this run is over")
    side = solo_state(s).get("side")
    if side == "red":
        raise HTTPException(status.HTTP_409_CONFLICT, "the red side makes moves, not decisions")
    inject = _current(db, s)
    spec = decisions.spec_for(inject) if inject else None
    if inject is None or spec is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "nothing to decide right now")
    ev = decisions.record(db, s, scenario, user, SIDES[side], user.name or user.email, inject.code, option, text)
    chosen = next((o for o in spec["options"] if o["key"] == option), None) if option else None
    _autopilot(db, s, scenario, inject, spec, chosen)
    db.flush()
    return {"recorded": ev.payload, "status": s.status}


def skip(db: Session, s: models.Session, scenario: models.Scenario, user: models.User) -> dict:
    """The clock ran out (or the player passed): a scored non-decision."""
    if s.status != "running":
        raise HTTPException(status.HTTP_409_CONFLICT, "this run is over")
    side = solo_state(s).get("side")
    inject = _current(db, s)
    spec = decisions.spec_for(inject) if inject else None
    if inject is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "nothing to skip")
    if spec is not None and decisions.my_response(s, user.id, inject.code) is None:
        append_event(db, s.id, kind="response", ref=inject.code, game_clock=inject.clock or "",
                     payload={"inject_code": inject.code, "cell": SIDES[side], "user_id": user.id,
                              "display_name": user.name or user.email, "kind": spec.get("kind", "action"),
                              "option": None, "label": "No decision in time", "text": "", "score": 0.0,
                              "latency_sec": float(engagements.levers(solo_state(s).get("difficulty", "standard"))["clock"]), "timed_out": True})
    _autopilot(db, s, scenario, inject, spec, None, timed_out=True)
    db.flush()
    return {"status": s.status}


def move(db: Session, s: models.Session, scenario: models.Scenario, user: models.User,
         techniques: list[str], target: str, action: str) -> dict:
    if s.status != "running":
        raise HTTPException(status.HTTP_409_CONFLICT, "this run is over")
    solo = solo_state(s)
    if solo.get("side") != "red":
        raise HTTPException(status.HTTP_409_CONFLICT, "only the red side makes moves")
    if not techniques:
        raise HTTPException(422, "name at least one technique")
    lv = engagements.levers(solo.get("difficulty", "standard"))
    max_alert, max_moves = int(lv["alert"]), int(lv["moves"])
    env = engagements.scaled_environment(_env(db, scenario), solo.get("difficulty", "standard"))
    ruling = adjudication.adjudicate(env, techniques, target)
    moves = int(solo.get("moves") or 0) + 1
    tripped = bool(ruling.get("deception_tripped"))
    alert = int(solo.get("alert") or 0) + (2 if tripped else 1 if ruling["detected"] else 0)
    jewels = set(env.crown_jewels or [])
    foothold = bool(solo.get("foothold")) or (not ruling["detected"] and bool(target) and target not in jewels)
    wants_jewel = bool(target) and target in jewels and not ruling["detected"]
    captured = wants_jewel and (foothold or not lv["foothold"])
    if wants_jewel and not captured:
        ruling = {**ruling, "rationale": ruling.get("rationale", "") +
                  " You have no foothold yet: crown jewels need an unseen move on an outer asset first."}
    append_event(db, s.id, kind="red_action", ref=s.current_inject_code or "",
                 payload={**ruling, "action": action or "solo move", "actor": user.email, "solo": True,
                          "move": moves, "alert": alert, "captured": captured, "foothold": foothold})
    _set_solo(s, moves=moves, alert=alert, captured=captured or bool(solo.get("captured")), foothold=foothold)
    outcome = None
    if captured:
        outcome = f"You reached {target} without being seen. Objective complete."
    elif alert >= max_alert:
        outcome = (f"{max_alert} detections: the defenders traced you and evicted you from the network."
                   if not tripped else "You touched a canary. The defenders were waiting, and evicted you.")
    elif moves >= max_moves:
        outcome = "You ran out of moves before reaching a crown jewel."
    if outcome:
        finish(db, s, scenario, reason=outcome)
    else:
        # the story moves one scene on with each move, when it can
        inject = _current(db, s)
        branches = msel.available_branches(inject, s.state) if inject else []
        pick = next((b for b in branches if b.get("when") != msel.WHEN_TIMEOUT), branches[0] if branches else None)
        if pick:
            try:
                session_ops.advance(db, s, inject, when=pick.get("when", msel.WHEN_PROCTOR),
                                    trigger=pick.get("trigger") or pick.get("label"), goto=pick.get("goto"),
                                    note="Autopilot: the defenders' story moves on")
            except (LookupError, ValueError):
                pass
    db.flush()
    return {"ruling": ruling, "alert": alert, "moves": moves, "max_moves": max_moves, "max_alert": max_alert,
            "captured": captured, "foothold": foothold, "status": s.status, "outcome": outcome}


def finish(db: Session, s: models.Session, scenario: models.Scenario, reason: str = "") -> dict:
    if s.status == "complete":
        return debrief(db, s, scenario)
    s.status = "complete"
    s.completed_at = _now()
    append_event(db, s.id, kind="status", payload={"status": "complete", "reason": reason})
    db.flush()
    d = debrief(db, s, scenario)
    _set_solo(s, score=d["score"], badge=d["badge"], reason=reason, finished=_now().isoformat())
    db.flush()
    return d


# --------------------------------------------------------------------------- #
# what the player sees
# --------------------------------------------------------------------------- #
def _public_inject(i: models.Inject | None) -> dict | None:
    if i is None:
        return None
    return {"code": i.code, "title": i.title, "narrative": i.narrative, "channel": i.channel, "clock": i.clock,
            "expected_actions": list(i.expected_actions or []), "act": i.act, "target_asset": i.target_asset or "",
            "attack_techniques": list(i.attack_techniques or [])}


def view(db: Session, s: models.Session, scenario: models.Scenario, user: models.User) -> dict:
    solo = solo_state(s)
    side = solo.get("side")
    inject = _current(db, s)
    spec = decisions.spec_for(inject) if inject else None
    env = _env(db, scenario)
    events = _events(db, s)
    fired = [e for e in events if e.kind == "inject_fired"]
    feed = []
    for e in events[-12:]:
        p = e.payload or {}
        if e.kind == "inject_fired":
            feed.append({"kind": "scene", "clock": e.game_clock, "text": f"{e.ref} {p.get('title', '')}"})
        elif e.kind == "adjudication" and side != "red":
            feed.append({"kind": "ruling", "clock": e.game_clock,
                         "text": ("Detected" if p.get("detected") else "Missed") + f": {', '.join(p.get('techniques') or [])}"
                                 + (f" on {p['target_asset']}" if p.get("target_asset") else "")})
        elif e.kind == "red_action":
            feed.append({"kind": "move", "clock": e.game_clock,
                         "text": f"{', '.join(p.get('techniques') or [])} → {p.get('target_asset') or '?'}: "
                                 + ("detected" if p.get("detected") else "unseen")})
        elif e.kind == "response":
            feed.append({"kind": "decision", "clock": e.game_clock, "text": f"You: {p.get('label') or p.get('text') or ''}"})
        elif e.kind == "decision":
            feed.append({"kind": "branch", "clock": e.game_clock, "text": p.get("note") or f"→ {p.get('goto')}"})
    total = len(_injects(db, scenario.id))
    fired_at = _aware(fired[-1].at) if fired else None
    difficulty = solo.get("difficulty", "standard")
    lv = engagements.levers(difficulty)
    pub = decisions.public_spec(spec) if (spec and side != "red") else None
    if pub and lv["shuffle"]:
        pub["options"] = engagements.shuffled(pub["options"], f"{s.id}:{inject.code}")
    scene = _public_inject(inject)
    if scene and not lv["hints"]:
        scene["expected_actions"] = []
    out = {
        "id": s.id, "side": side, "side_label": SIDE_LABELS.get(side, side), "status": s.status,
        "scenario": {"id": scenario.id, "name": scenario.name, "threat_actor": scenario.threat_actor,
                     "narrative": scenario.narrative, "rules_of_engagement": scenario.rules_of_engagement},
        "environment": {"name": env.name if env else "", "sector": env.sector if env else ""},
        "difficulty": difficulty, "difficulty_label": engagements.DIFFICULTY_LABELS.get(difficulty, difficulty),
        "type": solo.get("type"), "levers": {"hints": lv["hints"], "zones": lv["zones"], "weight": lv["weight"]},
        "scene": scene, "scene_index": len(fired), "scenes_total": total,
        "decision": pub,
        "time_limit_sec": int(lv["clock"]) if spec and side != "red" else None,
        "scene_started_at": fired_at.isoformat() if fired_at else None,
        "my_response": decisions.my_response(s, user.id, inject.code) if inject else None,
        "terminal": bool(inject and _terminal(inject, s.state)),
        "impact": dict((s.state or {}).get("impact") or {}),
        "feed": feed, "reason": solo.get("reason"), "score": solo.get("score"), "badge": solo.get("badge"),
    }
    if side == "red":
        seen = {t for e in events if e.kind == "red_action" for t in ((e.payload or {}).get("techniques") or [])}
        suggestions = []
        for i in _injects(db, scenario.id):
            for t in i.attack_techniques or []:
                if t not in suggestions:
                    suggestions.append(t)
        out["red"] = {
            "alert": int(solo.get("alert") or 0), "max_alert": int(lv["alert"]),
            "moves": int(solo.get("moves") or 0), "max_moves": int(lv["moves"]), "captured": bool(solo.get("captured")),
            "foothold": bool(solo.get("foothold")), "needs_foothold": bool(lv["foothold"]), "deception_live": bool(lv["deception"]),
            "assets": [{"code": a.get("code"), "name": a.get("name"), "zone": a.get("zone", "") if lv["zones"] else "",
                        "crown_jewel": a.get("code") in set(env.crown_jewels or [])} for a in (env.assets or [])] if env else [],
            "crown_jewels": list(env.crown_jewels or []) if env else [],
            "techniques": suggestions[:16] if lv["hints"] else [], "used": sorted(seen),
            "intel": "The scenario's scenes hint at what this adversary tried. Controls you cannot see cover some assets; "
                     "deception assets may be waiting.",
        }
    return out


# --------------------------------------------------------------------------- #
# debrief
# --------------------------------------------------------------------------- #
def _badge(score: int, side: str) -> str:
    if side == "red":
        return "Ghost" if score >= 85 else "Operator" if score >= 60 else "Noisy neighbour"
    if side == "exec":
        return "Steady hand" if score >= 85 else "Board-ready" if score >= 60 else "Learning the room"
    return "Incident commander" if score >= 85 else "Responder" if score >= 60 else "Trainee"


def debrief(db: Session, s: models.Session, scenario: models.Scenario) -> dict:
    solo = solo_state(s)
    side = solo.get("side")
    env = _env(db, scenario)
    events = _events(db, s)
    injects = {i.code: i for i in _injects(db, scenario.id)}
    started = _aware(s.started_at) or _aware(events[0].at)
    ended = _aware(s.completed_at) or _aware(events[-1].at)
    duration = max(0, round((ended - started).total_seconds()))
    rows, work_on = [], []
    difficulty = solo.get("difficulty", "standard")
    lv = engagements.levers(difficulty)
    if side == "red":
        moves = [e.payload or {} for e in events if e.kind == "red_action"]
        unseen = [m for m in moves if not m.get("detected")]
        captured = any(m.get("captured") for m in moves)
        evicted = int(solo.get("alert") or 0) >= int(lv["alert"])
        base = (100 * len(unseen) / len(moves) * 0.6) if moves else 0
        score = int(round(min(100, max(0, base + (40 if captured else 0) - (10 if evicted else 0)))))
        caught_by = {}
        for m in moves:
            row = {"n": m.get("move"), "techniques": m.get("techniques") or [], "target": m.get("target_asset") or "",
                   "detected": bool(m.get("detected")), "probability": m.get("probability"),
                   "controls": [c.get("name") if isinstance(c, dict) else str(c) for c in (m.get("controls_hit") or [])],
                   "rationale": m.get("rationale") or "", "captured": bool(m.get("captured"))}
            rows.append(row)
            if row["detected"]:
                for c in row["controls"]:
                    caught_by[c] = caught_by.get(c, 0) + 1
        for c, n in sorted(caught_by.items(), key=lambda kv: -kv[1])[:3]:
            work_on.append(f"{c} caught you {n} time{'s' if n > 1 else ''}: pick techniques and assets it does not cover, or go around it.")
        if not captured:
            work_on.append("You never reached a crown jewel: " + ", ".join(env.crown_jewels or []) +
                           ". Plan a path through the zones toward one of them and spend fewer moves on reconnaissance.")
        if moves and len({tuple(m.get("techniques") or []) for m in moves}) == 1:
            work_on.append("Every move used the same technique. Vary the tradecraft; controls that cover one technique rarely cover all.")
        headline = solo.get("reason") or ("Captured" if captured else "Run over")
        summary = {"moves": len(moves), "unseen": len(unseen), "detected": len(moves) - len(unseen),
                   "captured": captured, "evicted": evicted}
    else:
        responses = [e.payload or {} for e in events if e.kind == "response" and (e.payload or {}).get("user_id") == solo.get("user_id")]
        scores, lats = [], []
        for r in responses:
            inj = injects.get(r.get("inject_code"))
            spec = decisions.spec_for(inj) if inj else None
            options = (spec or {}).get("options") or []
            best = max(options, key=lambda o: o["score"]) if options else None
            chosen = next((o for o in options if o["key"] == r.get("option")), None)
            sc = r.get("score")
            if sc is not None:
                scores.append(sc)
            if r.get("latency_sec") is not None:
                lats.append(r["latency_sec"])
            rows.append({"code": r.get("inject_code"), "title": inj.title if inj else "", "prompt": (spec or {}).get("prompt", ""),
                         "chosen": r.get("label") or r.get("text") or "", "score": sc, "latency_sec": r.get("latency_sec"),
                         "timed_out": bool(r.get("timed_out")),
                         "best": best["label"] if best else "", "best_note": (best or {}).get("note", ""),
                         "chosen_note": (chosen or {}).get("note", ""),
                         "verdict": "best" if chosen and best and chosen["key"] == best["key"] else
                                    "good" if sc is not None and sc >= 0.6 else "poor"})
        score = int(round(100 * sum(scores) / len(scores))) if scores else 0
        for row in sorted([r for r in rows if r["verdict"] != "best"], key=lambda r: (r["score"] or 0))[:3]:
            tip = f"The stronger move was '{row['best']}'." + (f" {row['best_note']}" if row["best_note"] else "")
            work_on.append(f"{row['code']} {row['title']}: you chose '{row['chosen']}'. {tip}")
        if lats and median(lats) > 90:
            work_on.append(f"Median time to decide was {median(lats):.0f} s. In a real incident the first fifteen minutes are the ones that matter; practise deciding with less certainty.")
        impact = {k: (round(v * lv["impact"]) if isinstance(v, (int, float)) else v) for k, v in dict((s.state or {}).get("impact") or {}).items()}
        if impact.get("cost"):
            work_on.append(f"The path you took cost about ${impact['cost']:,.0f}" + (f" and {impact.get('downtime_hours')} h of downtime" if impact.get("downtime_hours") else "") + ". Earlier containment usually cuts both.")
        headline = solo.get("reason") or "Run complete"
        summary = {"decisions": len(rows), "best": sum(1 for r in rows if r["verdict"] == "best"),
                   "timed_out": sum(1 for r in rows if r["timed_out"]),
                   "median_latency_sec": round(median(lats), 1) if lats else None, "impact": impact}
    raw = score
    score = int(min(100, round(raw * lv["weight"])))
    badge = _badge(score, side)
    techniques = sorted({t for e in events if e.kind in ("adjudication", "red_action") for t in ((e.payload or {}).get("techniques") or [])})
    return {"id": s.id, "side": side, "side_label": SIDE_LABELS.get(side, side), "scenario": scenario.name,
            "threat_actor": scenario.threat_actor, "environment": env.name if env else "", "status": s.status,
            "started_at": started.isoformat() if started else None, "duration_sec": duration, "score": score, "badge": badge,
            "raw_score": raw, "difficulty": difficulty, "difficulty_label": engagements.DIFFICULTY_LABELS.get(difficulty, difficulty),
            "type": solo.get("type"), "weight": lv["weight"],
            "headline": headline, "summary": summary, "rows": rows, "work_on": work_on[:4], "techniques": techniques,
            "objectives": [{"code": o.code, "title": o.title} for o in scenario.objectives]}


def debrief_markdown(d: dict) -> str:
    lines = [f"# Solo debrief — {d['scenario']}", "",
             f"**Side:** {d['side_label']}  ", f"**Difficulty:** {d['difficulty']}  ",
             f"**Score:** {d['score']} / 100 — {d['badge']}  ",
             f"**Result:** {d['headline']}  ", f"**Duration:** {d['duration_sec'] // 60} min {d['duration_sec'] % 60} s  ", ""]
    if d["side"] == "red":
        lines += ["| # | Techniques | Target | Outcome | Why |", "|---|---|---|---|---|"]
        for r in d["rows"]:
            lines.append(f"| {r['n']} | {', '.join(r['techniques'])} | {r['target']} | {'DETECTED' if r['detected'] else 'unseen'}"
                         f"{' — captured' if r['captured'] else ''} | {r['rationale'][:160]} |")
    else:
        lines += ["| Scene | You chose | Best choice | Score | Time |", "|---|---|---|---|---|"]
        for r in d["rows"]:
            lines.append(f"| {r['code']} {r['title']} | {r['chosen']} | {r['best']} | "
                         f"{'' if r['score'] is None else int(round(r['score'] * 100))} | {'' if r['latency_sec'] is None else str(r['latency_sec']) + ' s'} |")
        notes = [r for r in d["rows"] if r["verdict"] != "best" and (r["best_note"] or r["chosen_note"])]
        if notes:
            lines += ["", "## What the authors wanted you to see", ""]
            for r in notes:
                lines.append(f"- **{r['code']}** — {r['best_note'] or r['chosen_note']}")
    lines += ["", "## Work on", ""] + [f"- {w}" for w in d["work_on"]] or ["- Nothing stands out. Try the other side."]
    if d["techniques"]:
        lines += ["", f"**Techniques in play:** {', '.join(d['techniques'])}"]
    lines += ["", "_A solo run is practice. It is not counted in any organisation's readiness figures._"]
    return "\n".join(lines)


def runs(db: Session, user: models.User) -> list[dict]:
    rows = db.execute(
        select(models.Session).join(models.SessionJoin, models.SessionJoin.session_id == models.Session.id)
        .where(models.SessionJoin.user_id == user.id, models.Session.mode == "solo", models.Session.archived_at.is_(None))
        .order_by(models.Session.id.desc())).scalars().all()
    out = []
    for s in rows:
        solo = solo_state(s)
        if solo.get("user_id") != user.id:
            continue
        sc = db.get(models.Scenario, s.scenario_id)
        out.append({"id": s.id, "scenario_id": s.scenario_id, "scenario": sc.name if sc else "", "side": solo.get("side"),
                    "difficulty": solo.get("difficulty", "standard"), "type": solo.get("type"),
                    "status": s.status, "score": solo.get("score"), "badge": solo.get("badge"),
                    "started_at": _aware(s.started_at).isoformat() if s.started_at else None})
    return out
