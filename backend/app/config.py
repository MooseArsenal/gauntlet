"""Runtime configuration.

Zero-infrastructure by default: a local SQLite file so the whole product runs
with nothing but Python. Override with the ``GAUNTLET_*`` environment variables
to point at Postgres or relocate the database.
"""
from __future__ import annotations

import os
from pathlib import Path

# Repo-root/gauntlet/backend/app/config.py -> gauntlet/backend
BACKEND_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BACKEND_DIR.parent / "web"

DB_URL = os.environ.get(
    "GAUNTLET_DB_URL",
    f"sqlite:///{BACKEND_DIR / 'gauntlet.db'}",
)

# When true, a worked example (finance ransomware tabletop) is loaded on an
# empty database so a fresh checkout has something to run immediately.
SEED_ON_START = os.environ.get("GAUNTLET_SEED", "1") not in ("0", "false", "False")


def _flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default) not in ("0", "false", "False", "")


# Schema management. In real deployments Alembic migrations are the source of
# truth (run on startup). Tests set GAUNTLET_USE_ALEMBIC=0 to use the fast
# create_all path against a throwaway database.
USE_ALEMBIC = _flag("GAUNTLET_USE_ALEMBIC", "1")

# --- Security -------------------------------------------------------------- #
# Secret used to sign the tamper-evident timeline (HMAC) and auth tokens (JWT).
# MUST be overridden in production — the default is intentionally obvious.
SECRET_KEY = os.environ.get("GAUNTLET_SECRET_KEY", "dev-insecure-change-me")
TIMELINE_KEY = os.environ.get("GAUNTLET_TIMELINE_KEY", SECRET_KEY).encode("utf-8")

# Auth token lifetime, in minutes.
TOKEN_TTL_MIN = int(os.environ.get("GAUNTLET_TOKEN_TTL_MIN", "720"))

# Real seconds per game-minute for auto-advance timers. The default is
# compressed for demos; set to 60 for wall-clock real-time exercises.
SECONDS_PER_GAME_MINUTE = float(os.environ.get("GAUNTLET_SECONDS_PER_MIN", "3"))

# Test/dev convenience ONLY: when true, unauthenticated requests resolve to the
# seeded default organisation's admin, so the product is usable without login.
# Never enable in production — it disables access control.
AUTH_OPTIONAL = _flag("GAUNTLET_AUTH_OPTIONAL", "0")

SECRET_IS_DEFAULT = SECRET_KEY == "dev-insecure-change-me"

# Comma-separated allowed CORS origins. Defaults to "*" for local dev; set an
# explicit list in production (e.g. "https://gauntlet.example.com").
CORS_ORIGINS = [o.strip() for o in os.environ.get("GAUNTLET_CORS_ORIGINS", "*").split(",") if o.strip()]

APP_TITLE = "Gauntlet"
APP_TAGLINE = "Security exercise design & proctoring"
