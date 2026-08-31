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
