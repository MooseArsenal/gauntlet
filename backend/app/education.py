"""Education edition (L4): cohorts, gradebook, anonymous grading.

A cohort is a class. The instructor (a facilitator) creates it and gets a
short code; students enrol with the code — creating their own participant
account if they have none — and receive a stable alias ("S-07"). Any session
the instructor attaches to the cohort is a classroom run: one call seats every
student into a participant cell (round-robin across cells when the scenario
has several), and every decision they make lands on that session's signed
timeline as it does for any participant. The gradebook is derived from those
decision events — score, latency, coverage — per student, per session, across
the cohort; with anonymous grading on, the room and the gradebook see aliases
until the instructor chooses to reveal names.

Students are participants: they never count as seats, never see the console,
and only ever see the sessions they were seated in.
"""
from __future__ import annotations

import csv
import io
import secrets
from datetime import datetime, timezone
from statistics import median

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import decisions, models
from .engine import visibility
from .membership import scenario_cell_keys

_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
MAX_MEMBERS = 500


def new_code(db: Session) -> str:
    for _ in range(20):
        code = "".join(secrets.choice(_ALPHABET) for _ in range(7))
        if not db.execute(select(models.Cohort.id).where(models.Cohort.code == code)).first():
            return code
    raise HTTPException(500, "could not allocate a cohort code")  # pragma: no cover


def by_code(db: Session, code: str) -> models.Cohort:
    c = db.execute(select(models.Cohort).where(models.Cohort.code == (code or "").strip().upper())).scalar_one_or_none()
    if c is None or c.archived_at is not None:
        raise HTTPException(404, "no cohort with that code")
    if not c.open:
        raise HTTPException(status.HTTP_409_CONFLICT, "that cohort is closed to new students")
    return c


def members(db: Session, cohort: models.Cohort) -> list[tuple[models.CohortMember, models.User]]:
    return db.execute(
        select(models.CohortMember, models.User)
        .join(models.User, models.User.id == models.CohortMember.user_id)
        .where(models.CohortMember.cohort_id == cohort.id)
        .order_by(models.CohortMember.id)
    ).all()


def sessions(db: Session, cohort: models.Cohort) -> list[models.Session]:
    return db.execute(
        select(models.Session).where(models.Session.cohort_id == cohort.id, models.Session.archived_at.is_(None))
        .order_by(models.Session.id)
    ).scalars().all()


def create(db: Session, user: models.User, name: str, anonymous: bool) -> models.Cohort:
    c = models.Cohort(org_id=user.org_id, name=name.strip() or "Class", code=new_code(db),
                      instructor_user_id=user.id, anonymous=anonymous)
    db.add(c)
    db.flush()
    return c


def add_member(db: Session, cohort: models.Cohort, user: models.User) -> models.CohortMember:
    if user.org_id != cohort.org_id:
        raise HTTPException(404, "no cohort with that code")
    row = db.execute(select(models.CohortMember).where(
        models.CohortMember.cohort_id == cohort.id, models.CohortMember.user_id == user.id)).scalar_one_or_none()
    if row is not None:
        return row
    n = db.execute(select(func.count(models.CohortMember.id)).where(models.CohortMember.cohort_id == cohort.id)).scalar() or 0
    if n >= MAX_MEMBERS:
        raise HTTPException(status.HTTP_409_CONFLICT, f"this cohort already has {MAX_MEMBERS} students")
    row = models.CohortMember(cohort_id=cohort.id, user_id=user.id, alias=f"S-{n + 1:02d}")
    db.add(row)
    db.flush()
    return row


def display_name_for(cohort: models.Cohort, member: models.CohortMember, user: models.User) -> str:
    return member.alias if cohort.anonymous else (user.name or user.email)


def participant_cells(scenario: models.Scenario) -> list[str]:
    return [k for k in scenario_cell_keys(scenario) if not visibility.is_control_cell(scenario, k)]


def seat_all(db: Session, cohort: models.Cohort, session: models.Session, cell: str = "auto") -> dict:
    """Seat every student in the session: one join row each, aliases as display
    names when grading is anonymous. ``cell`` names a participant cell, or
    ``auto`` to deal students round-robin across the scenario's participant cells."""
    scenario = db.get(models.Scenario, session.scenario_id)
    cells = participant_cells(scenario)
    if not cells:
        raise HTTPException(status.HTTP_409_CONFLICT, "the scenario has no participant cell to seat students in")
    if cell != "auto":
        if cell not in cells:
            raise HTTPException(422, f"'{cell}' is not a participant cell of this scenario; choose one of {cells}")
        cells = [cell]
    seated, counts = 0, {k: 0 for k in cells}
    for i, (m, u) in enumerate(members(db, cohort)):
        if not u.is_active:
            continue
        target = cells[i % len(cells)]
        row = db.execute(select(models.SessionJoin).where(
            models.SessionJoin.session_id == session.id, models.SessionJoin.user_id == u.id)).scalar_one_or_none()
        name = display_name_for(cohort, m, u)
        if row is None:
            db.add(models.SessionJoin(org_id=cohort.org_id, session_id=session.id, user_id=u.id, display_name=name, cell=target))
        else:
            row.cell, row.display_name = target, name
        counts[target] += 1
        seated += 1
    db.flush()
    return {"seated": seated, "cells": counts}


def _possible(db: Session, session: models.Session) -> int:
    """How many fired injects carried a decision card."""
    codes = {e.ref for e in session.events if e.kind == "inject_fired"}
    if not codes:
        return 0
    injects = db.execute(select(models.Inject).where(
        models.Inject.scenario_id == session.scenario_id, models.Inject.code.in_(codes))).scalars().all()
    return sum(1 for i in injects if decisions.spec_for(i) is not None)


def gradebook(db: Session, cohort: models.Cohort, reveal: bool = False) -> dict:
    """Students × sessions. Each cell: answered/possible, mean score (0–1),
    median latency; a row total; a session average. Names only when grading is
    not anonymous, or the instructor reveals."""
    show_names = reveal or not cohort.anonymous
    runs = sessions(db, cohort)
    per_session: dict[int, dict[int, dict]] = {}
    possible: dict[int, int] = {}
    for s in runs:
        per_session[s.id] = {r["user_id"]: r for r in decisions.participant_scores(db, s)}
        possible[s.id] = _possible(db, s)
    rows = []
    for m, u in members(db, cohort):
        cells, scores, lats, answered, total_possible = [], [], [], 0, 0
        for s in runs:
            r = per_session[s.id].get(u.id)
            total_possible += possible[s.id]
            if r is None:
                cells.append({"session_id": s.id, "answered": 0, "possible": possible[s.id], "mean_score": None, "median_latency_sec": None})
                continue
            answered += r["responses"]
            if r["mean_score"] is not None:
                scores.append(r["mean_score"])
            if r["median_latency_sec"] is not None:
                lats.append(r["median_latency_sec"])
            cells.append({"session_id": s.id, "answered": r["responses"], "possible": possible[s.id],
                          "mean_score": r["mean_score"], "median_latency_sec": r["median_latency_sec"]})
        rows.append({
            "user_id": u.id, "alias": m.alias,
            "name": (u.name or u.email) if show_names else m.alias,
            "email": u.email if show_names else "",
            "active": u.is_active, "sessions": cells,
            "answered": answered, "possible": total_possible,
            "mean_score": round(sum(scores) / len(scores), 3) if scores else None,
            "grade": round(100 * sum(scores) / len(scores)) if scores else None,
            "median_latency_sec": round(median(lats), 1) if lats else None,
        })
    sess_out = []
    for s in runs:
        sc = [r["mean_score"] for r in per_session[s.id].values() if r["mean_score"] is not None]
        sess_out.append({"id": s.id, "name": s.name, "status": s.status, "possible": possible[s.id],
                         "responders": len(per_session[s.id]),
                         "mean_score": round(sum(sc) / len(sc), 3) if sc else None})
    graded = [r["mean_score"] for r in rows if r["mean_score"] is not None]
    return {"cohort": {"id": cohort.id, "name": cohort.name, "code": cohort.code, "anonymous": cohort.anonymous,
                       "open": cohort.open, "revealed": show_names},
            "sessions": sess_out, "students": rows,
            "class_mean_score": round(sum(graded) / len(graded), 3) if graded else None}


def gradebook_csv(book: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    head = ["alias", "name", "email", "grade", "mean_score", "median_latency_sec", "answered", "possible"]
    for s in book["sessions"]:
        head += [f"{s['name']} score", f"{s['name']} answered"]
    w.writerow(head)
    for r in book["students"]:
        row = [r["alias"], _safe(r["name"]), _safe(r["email"]), r["grade"], r["mean_score"], r["median_latency_sec"], r["answered"], r["possible"]]
        for c in r["sessions"]:
            row += [c["mean_score"], f"{c['answered']}/{c['possible']}"]
        w.writerow(row)
    return buf.getvalue()


def _safe(v) -> str:
    """Neutralise spreadsheet formula injection in exported text."""
    s = str(v if v is not None else "")
    return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def my_view(db: Session, user: models.User) -> list[dict]:
    """A student's own standing: each cohort they are in, their alias, and their
    rows only — never a classmate's."""
    out = []
    rows = db.execute(
        select(models.CohortMember, models.Cohort)
        .join(models.Cohort, models.Cohort.id == models.CohortMember.cohort_id)
        .where(models.CohortMember.user_id == user.id, models.Cohort.archived_at.is_(None))
        .order_by(models.Cohort.id.desc())
    ).all()
    for m, c in rows:
        book = gradebook(db, c, reveal=False)
        mine = next((r for r in book["students"] if r["user_id"] == user.id), None)
        out.append({"cohort": {"id": c.id, "name": c.name, "anonymous": c.anonymous}, "alias": m.alias,
                    "sessions": book["sessions"], "me": mine, "class_mean_score": book["class_mean_score"]})
    return out


def now() -> datetime:
    return datetime.now(timezone.utc)
