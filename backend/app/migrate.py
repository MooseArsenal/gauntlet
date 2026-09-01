"""Run Alembic migrations programmatically on startup."""
from __future__ import annotations

from alembic import command
from alembic.config import Config

from .config import BACKEND_DIR, DB_URL


def _config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", DB_URL)
    return cfg


def run_migrations() -> None:
    """Upgrade the database to the latest revision."""
    command.upgrade(_config(), "head")
