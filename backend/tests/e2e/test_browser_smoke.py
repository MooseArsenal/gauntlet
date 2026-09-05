"""Browser smoke (F-8): the console really renders and runs an exercise.

Boots the app on a free port with the seeded demo, drives headless Chromium
through sign-in → pick the seeded scenario → start → first inject visible →
adjudicate → complete. Skips cleanly when Playwright or Chromium is absent so
the unit suite never depends on a browser.
"""
import glob
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import pytest

pw = pytest.importorskip("playwright.sync_api")


def _wait_until(pred, seconds: float) -> None:
    """Poll a Python predicate; the console's CSP forbids Playwright's string eval."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if pred():
                return
        except Exception:  # noqa: BLE001 - element not ready yet
            pass
        time.sleep(0.2)
    raise AssertionError("condition not met in time")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server():
    port = _free_port()
    tmp = tempfile.mkdtemp(prefix="gauntlet-e2e-")
    env = {**os.environ, "GAUNTLET_DB_URL": f"sqlite:///{tmp}/e2e.db", "GAUNTLET_SEED": "1",
           "GAUNTLET_USE_ALEMBIC": "0", "GAUNTLET_AUTH_OPTIONAL": "0",
           "GAUNTLET_SECRET_KEY": "e2e-secret-key-at-least-32-bytes-long-0000"}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                             "--port", str(port)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            urllib.request.urlopen(base + "/api/health", timeout=1)
            break
        except Exception:
            time.sleep(0.5)
    else:
        proc.kill()
        pytest.fail("app did not start")
    yield base
    proc.terminate()
    proc.wait(timeout=10)


def test_console_runs_an_exercise_end_to_end(server):
    with pw.sync_playwright() as p:
        browser = None
        candidates = [None, os.environ.get("GAUNTLET_E2E_CHROMIUM")] + sorted(
            glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"), reverse=True)
        last = None
        for exe in candidates:
            if exe == "" or (exe is not None and not os.path.exists(exe)):
                continue
            try:
                browser = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
                break
            except Exception as exc:  # no matching browser here
                last = exc
        if browser is None:
            pytest.skip(f"chromium unavailable: {last}")
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(server + "/")
        page.wait_for_selector("#doorRun", timeout=15000)
        page.click("#doorRun")  # S1: the doors come before sign-in
        page.fill("#loginEmail", "admin@demo.gauntlet")
        page.fill("#loginPassword", "gauntlet-admin")
        page.click("#btnLogin")
        page.wait_for_selector("#setupForm:not([hidden])", timeout=15000)
        assert page.locator("#scenarioSel option").count() >= 1
        page.fill("#sessInput", "e2e run")
        page.click("#btnStart")
        page.wait_for_selector("#console:not([hidden])", timeout=15000)
        _wait_until(lambda: page.locator("#injTitle").inner_text().strip() not in ("", "—"), 15)
        assert page.locator("#injCode").text_content().strip().startswith("INJ")
        # rule on an action, then complete
        page.fill("#adjTech", "T1003")
        page.fill("#adjAsset", "SRV-01")
        page.click("#btnAdjudicate")
        page.wait_for_selector("#rulingOut:not([hidden])", timeout=10000)
        assert page.locator("#rulingOut .verdict").count() == 1
        browser.close()
        assert not errors, errors
