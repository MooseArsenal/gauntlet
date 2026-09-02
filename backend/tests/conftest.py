"""Test bootstrap: throwaway DB, fast schema path, and auth conveniences."""
import os
import tempfile

_tmpdir = tempfile.mkdtemp(prefix="gauntlet-test-")
os.environ["GAUNTLET_DB_URL"] = f"sqlite:///{_tmpdir}/test.db"
os.environ["GAUNTLET_SEED"] = "1"
# Fast schema (create_all) instead of Alembic for the throwaway test DB.
os.environ["GAUNTLET_USE_ALEMBIC"] = "0"
# Existing domain tests run unauthenticated as the seeded default admin; the
# dedicated auth tests flip this off per-request to exercise the real flow.
os.environ["GAUNTLET_AUTH_OPTIONAL"] = "1"
os.environ["GAUNTLET_SECRET_KEY"] = "test-secret-key-at-least-32-bytes-long-000"

import pytest


@pytest.fixture(autouse=True)
def _fresh_registration_window():
    """Registration is throttled per source address (S-11). Every test registers
    its own organisation from the same test client address, so clear that
    window between tests; the throttle test exercises it within one test."""
    from app.throttle import throttle
    with throttle._lock:
        for store in (throttle._fails, throttle._locked_until):
            for k in [k for k in store if k.startswith("reg|")]:
                store.pop(k, None)
    yield
