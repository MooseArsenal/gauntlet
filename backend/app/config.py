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

# Access-token lifetime (short) and refresh-token lifetime (M9). TOKEN_TTL_MIN is
# kept as a back-compat alias for the access TTL.
ACCESS_TTL_MIN = int(os.environ.get("GAUNTLET_ACCESS_TTL_MIN",
                                    os.environ.get("GAUNTLET_TOKEN_TTL_MIN", "30")))
TOKEN_TTL_MIN = ACCESS_TTL_MIN
REFRESH_TTL_DAYS = int(os.environ.get("GAUNTLET_REFRESH_TTL_DAYS", "30"))

# Password policy (M9).
PASSWORD_MIN_LEN = int(os.environ.get("GAUNTLET_PASSWORD_MIN_LEN", "10"))

# Short-lived WebSocket connection ticket TTL, seconds (M9).
WS_TICKET_TTL_SEC = int(os.environ.get("GAUNTLET_WS_TICKET_TTL_SEC", "30"))

# TOTP MFA issuer label shown in authenticator apps.
MFA_ISSUER = os.environ.get("GAUNTLET_MFA_ISSUER", "Gauntlet")

# OIDC SSO (M9) — enabled when an issuer + client id are configured.
OIDC_ISSUER = os.environ.get("GAUNTLET_OIDC_ISSUER", "")
OIDC_CLIENT_ID = os.environ.get("GAUNTLET_OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("GAUNTLET_OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.environ.get("GAUNTLET_OIDC_REDIRECT_URI", "")
OIDC_ENABLED = bool(OIDC_ISSUER and OIDC_CLIENT_ID)

# Real seconds per game-minute for auto-advance timers. The default is
# compressed for demos; set to 60 for wall-clock real-time exercises.
SECONDS_PER_GAME_MINUTE = float(os.environ.get("GAUNTLET_SECONDS_PER_MIN", "3"))

# Test/dev convenience ONLY: when true, unauthenticated requests resolve to the
# seeded default organisation's admin, so the product is usable without login.
# Never enable in production — it disables access control.
AUTH_OPTIONAL = _flag("GAUNTLET_AUTH_OPTIONAL", "0")

SECRET_IS_DEFAULT = SECRET_KEY == "dev-insecure-change-me"

# Deployment posture. In "prod", insecure defaults are refused at startup.
ENV = os.environ.get("GAUNTLET_ENV", "dev").lower()
IS_PROD = ENV in ("prod", "production")

# Comma-separated allowed CORS origins. Defaults to "*" for local dev; set an
# explicit list in production (e.g. "https://gauntlet.example.com").
CORS_ORIGINS = [o.strip() for o in os.environ.get("GAUNTLET_CORS_ORIGINS", "*").split(",") if o.strip()]

# Trust X-Forwarded-For for the client IP (only enable behind a trusted proxy).
TRUST_PROXY = _flag("GAUNTLET_TRUST_PROXY", "0")

# Air-gapped mode (D2). When on, every outbound network call (OIDC discovery,
# LLM authoring assist, tracker push, range adapter, webhook notify) is refused
# fail-closed — a hard guarantee the deployment makes no egress. The deterministic
# core (scenario generation, adjudication, scoring, reports) needs no network, so
# the product remains fully functional offline. Surfaced at /api/health.
AIRGAPPED = _flag("GAUNTLET_AIRGAPPED", "0")

# Login throttling / lockout.
LOGIN_MAX_ATTEMPTS = int(os.environ.get("GAUNTLET_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SEC = int(os.environ.get("GAUNTLET_LOGIN_WINDOW_SEC", "300"))
LOGIN_LOCKOUT_SEC = int(os.environ.get("GAUNTLET_LOGIN_LOCKOUT_SEC", "900"))

# Scenario-import safety caps (a huge scenario must not DoS validation).
MAX_YAML_BYTES = int(os.environ.get("GAUNTLET_MAX_YAML_BYTES", str(256 * 1024)))
MAX_INJECTS = int(os.environ.get("GAUNTLET_MAX_INJECTS", "1000"))
# Bulk environment-intake (F6) payload cap — CSV/JSON of assets can be larger
# than a scenario but must still be bounded.
MAX_IMPORT_BYTES = int(os.environ.get("GAUNTLET_MAX_IMPORT_BYTES", str(2 * 1024 * 1024)))
# Absolute request-body cap — a defence-in-depth backstop against oversized
# JSON on any endpoint (individual fields are otherwise schema-unbounded).
MAX_REQUEST_BYTES = int(os.environ.get("GAUNTLET_MAX_REQUEST_BYTES", str(4 * 1024 * 1024)))
# Live-inject authorization grants must stay time-boxed (minutes).
MAX_AUTHORIZATION_TTL_MIN = int(os.environ.get("GAUNTLET_MAX_AUTH_TTL_MIN", "1440"))

# --- Data protection (M10) ------------------------------------------------- #
# Encrypt sensitive environment fields at rest. Enabled by GAUNTLET_ENCRYPT_AT_REST
# (derives a key from the master) or by supplying an explicit rotatable keyring in
# GAUNTLET_DATA_KEYS ("v2:<b64>,v1:<b64>"). See app/keys.py and app/crypto.py.
ENCRYPT_AT_REST = _flag("GAUNTLET_ENCRYPT_AT_REST", "0")

# Retention window (days) for a tenant's completed sessions and audit log. 0
# disables automatic purging. Exposed via the admin retention endpoint.
RETENTION_DAYS = int(os.environ.get("GAUNTLET_RETENTION_DAYS", "0"))

# Enable Postgres row-level security (defence in depth behind app-level scoping).
# No-op on SQLite. See migrations and app/rls.py.
RLS_ENABLED = _flag("GAUNTLET_RLS_ENABLED", "0")

# --- Issue-tracker sync (F4) ----------------------------------------------- #
# Improvement-plan items push to Jira or ServiceNow when configured; otherwise a
# built-in simulation adapter is used (records intent, no external calls).
JIRA_URL = os.environ.get("GAUNTLET_JIRA_URL", "").rstrip("/")
JIRA_USER = os.environ.get("GAUNTLET_JIRA_USER", "")
JIRA_TOKEN = os.environ.get("GAUNTLET_JIRA_TOKEN", "")
JIRA_PROJECT = os.environ.get("GAUNTLET_JIRA_PROJECT", "")
SERVICENOW_URL = os.environ.get("GAUNTLET_SERVICENOW_URL", "").rstrip("/")
SERVICENOW_USER = os.environ.get("GAUNTLET_SERVICENOW_USER", "")
SERVICENOW_PASSWORD = os.environ.get("GAUNTLET_SERVICENOW_PASSWORD", "")

# --- Cyber-range adapter (F7) ---------------------------------------------- #
# Which range executes live/technical injects: simulation (default, no network),
# caldera, or atomic. Real adapters only touch their one configured base URL, and
# only against a target whose host is on the allow-list.
RANGE_ADAPTER = os.environ.get("GAUNTLET_RANGE_ADAPTER", "simulation").lower()
RANGE_ALLOWLIST = [h.strip().lower() for h in
                   os.environ.get("GAUNTLET_RANGE_ALLOWLIST", "").split(",") if h.strip()]
CALDERA_URL = os.environ.get("GAUNTLET_CALDERA_URL", "").rstrip("/")
CALDERA_API_KEY = os.environ.get("GAUNTLET_CALDERA_API_KEY", "")
ATOMIC_URL = os.environ.get("GAUNTLET_ATOMIC_URL", "").rstrip("/")
ATOMIC_TOKEN = os.environ.get("GAUNTLET_ATOMIC_TOKEN", "")

APP_TITLE = "Gauntlet"
APP_TAGLINE = "Security exercise design & proctoring"

# --- Branding (F1) --------------------------------------------------------- #
# Shown in exported PDF headers/footers. Override for white-labelled output.
BRAND_NAME = os.environ.get("GAUNTLET_BRAND_NAME", "Gauntlet")
# Accent colour for the header rule, as "R,G,B" (0-255). Default is a slate blue.
BRAND_ACCENT = os.environ.get("GAUNTLET_BRAND_ACCENT", "37,99,235")


def startup_problems() -> list[str]:
    """Insecure configuration that must be fixed before a production start."""
    problems = []
    if IS_PROD:
        if SECRET_IS_DEFAULT:
            problems.append("GAUNTLET_SECRET_KEY is the insecure default")
        if len(SECRET_KEY) < 32:
            problems.append("GAUNTLET_SECRET_KEY is shorter than 32 characters")
        if "*" in CORS_ORIGINS:
            problems.append("GAUNTLET_CORS_ORIGINS is '*' (wildcard) in production")
        if AUTH_OPTIONAL:
            problems.append("GAUNTLET_AUTH_OPTIONAL is enabled (auth bypass) in production")
    return problems


def validate_config() -> None:
    """Fail fast on insecure production configuration."""
    problems = startup_problems()
    if problems:
        raise RuntimeError(
            "Refusing to start with insecure production config:\n  - "
            + "\n  - ".join(problems)
        )
