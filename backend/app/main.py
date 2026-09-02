"""Gauntlet API + facilitator console host."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import asyncio

from . import __version__, ws
from .api import (
    admin, adversaries, analytics_api, archive, attack_api, audit_api, auth, authoring, compliance_api,
    environments, exports_api, improvements, join_api, live, members, multicell, program, purple,
    reports,
    scenarios, schedules, sessions,
)
from .config import (
    AIRGAPPED, APP_TAGLINE, APP_TITLE, CORS_ORIGINS, MAX_REQUEST_BYTES, SEED_ON_START,
    USE_ALEMBIC, WEB_DIR, validate_config,
)
from .body_limit import BodySizeLimitMiddleware
from .database import SessionLocal, create_all
from .security_headers import SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail fast on insecure production configuration.
    validate_config()
    # Bind the running loop so sync handlers / timer threads can push WS updates.
    ws.manager.bind_loop(asyncio.get_running_loop())
    # Alembic migrations are the schema authority in real deployments; tests set
    # GAUNTLET_USE_ALEMBIC=0 to use the fast create_all path.
    if USE_ALEMBIC:
        from .migrate import run_migrations

        run_migrations()
    else:
        create_all()
    if SEED_ON_START:
        db = SessionLocal()
        try:
            from .seed import seed_if_empty

            seed_if_empty(db)
        finally:
            db.close()
    # Install Postgres row-level-security policies (defence in depth). No-op on
    # SQLite or when GAUNTLET_RLS_ENABLED is off.
    from .database import engine
    from .rls import install_policies

    install_policies(engine)
    # Timers do not survive a restart; rebuild them from the persisted due times (F-5).
    from . import scheduler

    scheduler.rearm_all()
    yield


app = FastAPI(
    title=APP_TITLE,
    description=f"{APP_TAGLINE}. Tabletop-first reference implementation.",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Outermost: the body cap counts bytes as they stream in, so a chunked upload
# without a Content-Length is stopped at the limit too (S-7).
app.add_middleware(BodySizeLimitMiddleware, max_bytes=lambda: MAX_REQUEST_BYTES)


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok", "app": APP_TITLE, "version": __version__, "airgapped": AIRGAPPED}


app.include_router(auth.router)
app.include_router(environments.router)
app.include_router(scenarios.router)
app.include_router(sessions.router)
app.include_router(reports.router)
app.include_router(authoring.router)
app.include_router(adversaries.router)
app.include_router(attack_api.router)
app.include_router(analytics_api.router)
app.include_router(join_api.router)
app.include_router(multicell.router)
app.include_router(live.router)
app.include_router(program.router)
app.include_router(compliance_api.router)
app.include_router(exports_api.router)
app.include_router(schedules.router)
app.include_router(improvements.router)
app.include_router(purple.router)
app.include_router(audit_api.router)
app.include_router(admin.router)
app.include_router(members.router)
app.include_router(archive.router)
app.include_router(ws.router)

# Facilitator console (served last so it never shadows the API routes).
if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="console")
