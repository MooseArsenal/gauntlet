# Gauntlet — single-process image. Timers, login throttling, WebSocket tickets
# and OIDC state live in process memory, so run ONE worker per container and
# scale by adding containers behind a sticky proxy (or move that state to a
# shared store first). See docs/DEPLOY.md.
FROM python:3.12-slim AS base
ARG GAUNTLET_VERSION=dev
ARG GAUNTLET_REVISION=unknown
LABEL org.opencontainers.image.title="Gauntlet" \
      org.opencontainers.image.description="Exercise control: environment-grounded cyber tabletop and purple-team engine" \
      org.opencontainers.image.version="${GAUNTLET_VERSION}" \
      org.opencontainers.image.revision="${GAUNTLET_REVISION}" \
      org.opencontainers.image.source="https://github.com/Moose11b/gauntlet" \
      org.opencontainers.image.licenses="See LICENSE"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --create-home --uid 10001 gauntlet
WORKDIR /srv/gauntlet

COPY backend/requirements.lock.txt /tmp/requirements.lock.txt
RUN pip install --no-deps -r /tmp/requirements.lock.txt

COPY --chown=gauntlet:gauntlet backend/ /srv/gauntlet/backend/
COPY --chown=gauntlet:gauntlet web/ /srv/gauntlet/web/
COPY --chown=gauntlet:gauntlet scenarios/ /srv/gauntlet/scenarios/

USER gauntlet
WORKDIR /srv/gauntlet/backend
ENV GAUNTLET_ENV=production GAUNTLET_USE_ALEMBIC=1 GAUNTLET_SEED=0 \
    GAUNTLET_CORS_ORIGINS="" \
    GAUNTLET_DB_URL=sqlite:////srv/gauntlet/data/gauntlet.db
VOLUME ["/srv/gauntlet/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status==200 else 1)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]
