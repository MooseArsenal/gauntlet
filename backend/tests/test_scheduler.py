"""Auto-advance timer logic (M6). Timing is exercised by driving the fire
callback directly, so the tests stay deterministic."""
from app import models, scheduler, session_ops
from app.database import SessionLocal, create_all


def test_parse_duration_minutes():
    assert session_ops.parse_duration_minutes("PT10M") == 10
    assert session_ops.parse_duration_minutes("PT30S") == 0.5
    assert session_ops.parse_duration_minutes("PT1M30S") == 1.5
    assert session_ops.parse_duration_minutes("garbage") == 0.0


def _running_session(db, slug):
    org = models.Organization(name="S", slug=slug)
    db.add(org)
    db.flush()
    env = models.Environment(org_id=org.id, name="e")
    db.add(env)
    db.flush()
    scn = models.Scenario(org_id=org.id, environment_id=env.id, name="s")
    scn.injects = [
        models.Inject(code="INJ-01", sequence=1, is_start=True, title="one",
                      branches=[{"when": "timeout", "after": "PT10M", "goto": "INJ-02"},
                                {"when": "proctor_choice", "goto": "INJ-02"}]),
        models.Inject(code="INJ-02", sequence=2, title="two", branches=[]),
    ]
    db.add(scn)
    db.flush()
    s = models.Session(org_id=org.id, scenario_id=scn.id, name="run",
                       status="running", auto_advance=True, current_inject_code="INJ-01")
    db.add(s)
    db.commit()
    return s


def test_fire_auto_advances_on_timeout():
    create_all()
    db = SessionLocal()
    try:
        s = _running_session(db, "sched-a")
        sid = s.id
    finally:
        db.close()

    scheduler._fire(sid, "INJ-01")  # simulate the timer elapsing

    db = SessionLocal()
    try:
        assert db.get(models.Session, sid).current_inject_code == "INJ-02"
    finally:
        db.close()


def test_fire_is_noop_if_proctor_already_moved():
    create_all()
    db = SessionLocal()
    try:
        s = _running_session(db, "sched-b")
        s.current_inject_code = "INJ-02"  # a proctor already advanced
        db.commit()
        sid = s.id
    finally:
        db.close()

    scheduler._fire(sid, "INJ-01")  # stale timer for the old inject

    db = SessionLocal()
    try:
        assert db.get(models.Session, sid).current_inject_code == "INJ-02"
    finally:
        db.close()
