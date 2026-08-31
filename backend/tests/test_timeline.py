"""The HMAC-signed timeline must detect tampering (M5)."""
from app import models
from app.database import SessionLocal, create_all
from app.timeline import append_event, verify_chain


def _make_session(db):
    org = models.Organization(name="TL", slug="tl-timeline")
    db.add(org)
    db.flush()
    env = models.Environment(org_id=org.id, name="e")
    db.add(env)
    db.flush()
    scn = models.Scenario(org_id=org.id, environment_id=env.id, name="s")
    db.add(scn)
    db.flush()
    sess = models.Session(org_id=org.id, scenario_id=scn.id, name="x")
    db.add(sess)
    db.flush()
    return sess


def test_chain_valid_then_detects_tamper():
    create_all()
    db = SessionLocal()
    try:
        sess = _make_session(db)
        append_event(db, sess.id, kind="status", payload={"status": "running"})
        append_event(db, sess.id, kind="note", payload={"text": "hello"})
        db.commit()

        assert verify_chain(list(sess.events)) is True

        # Editing a recorded event breaks the chain.
        sess.events[0].payload = {"status": "tampered"}
        db.commit()
        reloaded = db.get(models.Session, sess.id)
        assert verify_chain(list(reloaded.events)) is False
    finally:
        db.close()
