#!/usr/bin/env bash
# Nightly reset for the public demo (docs/DEMO.md).
#
# Drops the Postgres database and lets the app rebuild it on start: migrations
# run, then the worked example, the library and the demo account are seeded
# again (GAUNTLET_SEED=1). Every account visitors created, every solo run and
# every exercise from the day before is gone. That is the point: the demo is
# clean every morning and never accumulates strangers' data.
#
#   /opt/gauntlet/tools/demo_reset.sh            # from cron, see docs/DEMO.md
#   DEMO_DIR=/srv/gauntlet tools/demo_reset.sh   # if the checkout lives elsewhere
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/opt/gauntlet}"
cd "$DEMO_DIR"

log() { printf '%s demo-reset: %s\n' "$(date -u +%FT%TZ)" "$*"; }

log "stopping the app"
docker compose stop app >/dev/null

log "dropping and recreating the database"
docker compose exec -T db psql -v ON_ERROR_STOP=1 -U gauntlet -d postgres \
  -c "DROP DATABASE IF EXISTS gauntlet WITH (FORCE);" \
  -c "CREATE DATABASE gauntlet OWNER gauntlet;" >/dev/null

log "starting the app (migrations + seed run on boot)"
docker compose start app >/dev/null

# Wait for the health endpoint so a failed seed shows up in the cron mail.
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    log "healthy"
    exit 0
  fi
  sleep 2
done
log "the app did not come back within 60 s; check: docker compose logs app"
exit 1
