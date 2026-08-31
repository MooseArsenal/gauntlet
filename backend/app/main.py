"""Gauntlet API + facilitator console host."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import asyncio

from . import __version__, ws
from .api import (
    auth, authoring, environments, live, multicell, program, reports, scenarios, sessions,
)
from .config import APP_TAGLINE, APP_TITLE, CORS_ORIGINS, SEED_ON_START, USE_ALEMBIC, WEB_DIR
from .database import SessionLocal, create_all


@asynccontextmanager
async def lifespan(_: FastAPI):
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
    yield


app = FastAPI(
    title=APP_TITLE,
    description=f"{APP_TAGLINE}. Tabletop-first reference implementation.",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok", "app": APP_TITLE, "version": __version__}


app.include_router(auth.router)
app.include_router(environments.router)
app.include_router(scenarios.router)
app.include_router(sessions.router)
app.include_router(reports.router)
app.include_router(authoring.router)
app.include_router(multicell.router)
app.include_router(live.router)
app.include_router(program.router)
app.include_router(ws.router)

# Facilitator console (served last so it never shadows the API routes).
if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="console")
