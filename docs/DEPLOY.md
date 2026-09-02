# Deploying Gauntlet

Gauntlet is one Python process serving the API and the console, plus a
database. The container image and compose file in this repository are the
supported way to run it outside development.

## Quick start (Docker Compose, Postgres)

```bash
cp .env.example .env
# set GAUNTLET_SECRET_KEY (openssl rand -hex 32) and POSTGRES_PASSWORD in .env
docker compose up -d --build
docker compose logs -f app        # wait for "Application startup complete"
```

Open `http://<host>:8000/`, register the first organisation, then add members
from the **Members** page. Put a TLS-terminating reverse proxy (Caddy, nginx,
Traefik) in front and keep `GAUNTLET_TRUST_PROXY=1` so lockouts and audit
entries see real client addresses.

## Air-gapped

Build the image on a connected machine, `docker save` it, move it across, and
set `GAUNTLET_AIRGAPPED=1` in `.env`. Every outbound call site (SSO discovery,
LLM assist, tracker sync, range adapters, reminder webhooks) then fails closed
and the console shows the AIR-GAPPED badge. See `docs/AIRGAPPED.md`.

## One worker per container

Login throttling, WebSocket tickets, OIDC login state and real-time timers are
kept in process memory. The image therefore runs **one** uvicorn worker.
Scale by running more containers behind a proxy with sticky sessions, or
move that state to a shared store first (the four modules have tiny
interfaces: `throttle.py`, `ws_ticket.py`, `oidc.py` state, `scheduler.py`).

## Production checklist

- [ ] `GAUNTLET_ENV=production` — HSTS on, insecure defaults refused at boot.
- [ ] `GAUNTLET_SECRET_KEY` is 32+ random bytes and stored in a secret manager, not the compose file.
- [ ] Postgres, not SQLite, for anything beyond a single facilitator.
- [ ] `GAUNTLET_SEED=0` — the demo organisation and its account do not exist.
- [ ] TLS at the proxy; `GAUNTLET_TRUST_PROXY=1`; proxy overwrites `X-Forwarded-For`.
- [ ] `GAUNTLET_CORS_ORIGINS` empty (the console is same-origin) or an explicit list — the wildcard default is refused in production.
- [ ] `GAUNTLET_ENCRYPT_AT_REST=1` with an explicit `GAUNTLET_DATA_KEYS` keyring if environments hold real asset inventories.
- [ ] `GAUNTLET_RETENTION_DAYS` set to the policy value; purge is admin-initiated.
- [ ] Backups of the Postgres volume; the timeline's signed heads make restores verifiable.
- [ ] OIDC configured with a redirect URI on the public hostname; the provider must send `email_verified`.

## Upgrading

Migrations run on startup (`GAUNTLET_USE_ALEMBIC=1` in the image). Pull the new
image, `docker compose up -d`, and the schema moves forward. Downgrades are
defined for every revision but are not exercised in CI.

## Reproducible installs

`backend/requirements.lock.txt` pins the complete transitive set the image
installs (`pip install --no-deps`). Regenerate it in a clean virtualenv when
`requirements.txt` changes; the header of the file gives the command.
