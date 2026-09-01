"""Postgres row-level security (M10) — defence in depth under app-level scoping.

Every query already goes through :func:`app.security.scope_or_404` and an
``org_id`` filter, so a tenant cannot reach another's rows through the API. RLS
adds a **second, database-enforced** wall: even a bug that forgot the ``org_id``
filter — or a raw query run under the app's DB account — returns nothing for the
wrong tenant, because the policy is evaluated by Postgres itself.

It binds to a per-connection setting: each authenticated request sets
``gauntlet.org`` to the caller's org (see :func:`set_tenant`, called from
``get_current_user``), and the policies below restrict every tenant table to
rows whose ``org_id`` matches it.

SQLite has no RLS; everything here is a no-op there, so the default zero-infra
setup is unaffected. Enable with ``GAUNTLET_RLS_ENABLED=1`` on Postgres.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .config import RLS_ENABLED

# Tenant tables keyed directly by org_id. Child tables (injects, timeline_events,
# …) inherit isolation through their parents plus the app's own scoping.
_TENANT_TABLES = ("users", "environments", "scenarios", "sessions", "audit_logs")


def _is_postgres(bind) -> bool:
    return bind.dialect.name == "postgresql"


def active(bind) -> bool:
    return RLS_ENABLED and _is_postgres(bind)


def set_tenant(db: Session, org_id: int) -> None:
    """Bind the current connection to a tenant for the rest of the request.

    ``set_config(..., true)`` is transaction-local, so it cannot leak to another
    request that later reuses the pooled connection. No-op off Postgres/RLS.
    """
    if not RLS_ENABLED:
        return
    bind = db.get_bind()
    if not _is_postgres(bind):
        return
    db.execute(text("SELECT set_config('gauntlet.org', :org, true)"), {"org": str(org_id)})


def install_policies(engine: Engine) -> None:
    """Enable RLS and install per-tenant policies. Idempotent; Postgres-only."""
    if not active(engine):
        return
    with engine.begin() as conn:
        for table in _TENANT_TABLES:
            conn.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            conn.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
            conn.execute(text(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}"))
            # current_setting(..., true) returns NULL when unset (e.g. an
            # unauthenticated bootstrap query) — the USING clause then matches no
            # rows, which is the safe default.
            conn.execute(text(
                f"CREATE POLICY {table}_tenant_isolation ON {table} "
                f"USING (org_id = NULLIF(current_setting('gauntlet.org', true), '')::int)"
            ))
