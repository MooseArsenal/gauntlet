"""U-7: console files revalidate on every load, and the demo seed offers a
choice of scenarios, not one worked example."""
from fastapi.testclient import TestClient

from app.main import app


def test_console_files_always_revalidate():
    with TestClient(app) as c:
        for path in ("/", "/index.html", "/app.js", "/styles.css", "/wizard.html"):
            r = c.get(path)
            assert r.status_code == 200, path
            assert r.headers["cache-control"] == "no-cache, must-revalidate", path
            assert "etag" in r.headers, path
        assert c.get("/api/health").headers["cache-control"] == "no-store"


def test_demo_seed_offers_several_scenarios_across_environments():
    """The suite boots with GAUNTLET_SEED=1, so the demo org is already there."""
    from sqlalchemy import select

    from app import models
    from app.database import SessionLocal
    with TestClient(app):
        db = SessionLocal()
        try:
            org = db.execute(select(models.Organization).where(models.Organization.slug == "demo")).scalar_one()
            scns = db.execute(select(models.Scenario).where(models.Scenario.org_id == org.id)).scalars().all()
            names = {s.name for s in scns}
            assert "Operation Frostbite — Ransomware Tabletop" in names
            assert "Operation Nightshade — Healthcare Espionage Tabletop" in names
            assert "Clearwater ICS/OT — CTEP Tabletop" in names
            assert len({s.environment_id for s in scns}) >= 3
            assert all(s.injects for s in scns)
        finally:
            db.close()
