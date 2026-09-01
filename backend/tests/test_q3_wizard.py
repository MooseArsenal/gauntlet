"""Q3 — guided wizards are static on-ramps over the existing API.

These smoke tests assert the wizard's page and assets are served; the flows
themselves drive endpoints already covered by their own suites (catalog
templates, scenario generate, sessions start, reports, exports).
"""
from fastapi.testclient import TestClient

from app.main import app


def test_wizard_page_is_served():
    with TestClient(app) as client:
        r = client.get("/wizard.html")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]


def test_wizard_assets_served():
    with TestClient(app) as client:
        for path in ("/wizard.js", "/wizard.css"):
            r = client.get(path)
            assert r.status_code == 200, path
