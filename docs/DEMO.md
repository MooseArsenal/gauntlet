# The public demo

How `try.moosearsenal.com` is run: one small VM, the compose file from this
repository, Caddy for TLS, and a cron job that wipes the database every
night. The demo exists so a visitor can walk the four doors, run the seeded
exercise and play a solo engagement without installing anything. It holds no
real data and keeps nothing for longer than a day.

## What it is, and is not

- **Seeded.** `GAUNTLET_SEED=1` loads *Operation Frostbite*, the library and
  the demo admin on every fresh database. The demo password is whatever
  `GAUNTLET_DEMO_PASSWORD` says; production refuses to start without one.
- **Reset nightly.** `tools/demo_reset.sh` drops the database at 04:00 UTC and
  the app rebuilds it on start. Accounts visitors created, their solo runs and
  anything they typed are gone by morning. Say so on the landing page and in
  the privacy policy; do not use the demo for a customer's real exercise.
- **Community tier, no licence.** Paid features answer with a plain `402`, the
  same as any unlicensed deployment. That is what a visitor should see.
- **Not air-gapped.** The demo sends real email (solo sign-up confirmation,
  inject delivery to the visitor's own address) through the Workspace SMTP
  relay, so `GAUNTLET_AIRGAPPED` stays `0`.

## The VM

One machine is enough: 2 vCPU, 4 GB RAM, 40 GB disk, Ubuntu 24.04, at
Hetzner, DigitalOcean or similar. Docker Engine with the compose plugin from
Docker's own apt repository (the distribution packages lag).

```bash
# as root on the fresh VM
apt-get update && apt-get install -y ca-certificates curl ufw
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable
```

DNS: an `A` record `try` pointing at the VM's address (and `AAAA` if it has
one). Cloudflare proxied or DNS-only both work; if proxied, set the SSL mode to
*Full (strict)* so Cloudflare talks TLS to Caddy.

## The app

```bash
git clone https://github.com/MooseArsenal/gauntlet.git /opt/gauntlet
cd /opt/gauntlet
git checkout v0.4.0            # pin a release; move it deliberately
cp .env.example .env
```

Set these in `.env` (everything else keeps its default):

```
GAUNTLET_ENV=production
GAUNTLET_SECRET_KEY=<openssl rand -hex 32>
POSTGRES_PASSWORD=<openssl rand -hex 16>
GAUNTLET_SEED=1
GAUNTLET_DEMO_PASSWORD=<a strong password you will publish on the landing page>
GAUNTLET_CORS_ORIGINS=https://try.moosearsenal.com
GAUNTLET_TRUST_PROXY=1
GAUNTLET_REGISTER_MAX_PER_WINDOW=5

GAUNTLET_SMTP_HOST=smtp.gmail.com
GAUNTLET_SMTP_PORT=587
GAUNTLET_SMTP_USER=noreply@moosearsenal.com
GAUNTLET_SMTP_PASSWORD=<the app password for noreply@>
GAUNTLET_SMTP_FROM=noreply@moosearsenal.com
GAUNTLET_SMTP_STARTTLS=1
```

Bind the app to the loopback interface only, so the only way in is through
Caddy. Compose reads `docker-compose.override.yml` automatically:

```yaml
# /opt/gauntlet/docker-compose.override.yml
services:
  app:
    ports: !override
      - "127.0.0.1:8000:8000"
```

Then:

```bash
docker compose up -d --build
docker compose logs -f app       # until "Application startup complete"
curl -s http://127.0.0.1:8000/api/health
```

## Caddy in front

Caddy obtains and renews the certificate itself and forwards the client
address, which the app honours because `GAUNTLET_TRUST_PROXY=1`.

```bash
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy
```

```
# /etc/caddy/Caddyfile
try.moosearsenal.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8000

    # The app sets its own CSP, HSTS and the rest; Caddy only hides itself.
    header -Server

    # WebSocket upgrades pass through reverse_proxy unchanged.
    log {
        output file /var/log/caddy/try.log {
            roll_size 20mb
            roll_keep 5
        }
    }
}
```

```bash
systemctl reload caddy
curl -sI https://try.moosearsenal.com/api/health | head -1
```

## The nightly reset

`tools/demo_reset.sh` stops the app, drops and recreates the database, starts
the app again and waits for `/api/health`. Migrations and the seed run on
boot. Install it as root's cron job; cron mails the output only when the
script fails.

```
# crontab -e   (root)
MAILTO=security@moosearsenal.com
0 4 * * * /opt/gauntlet/tools/demo_reset.sh >/dev/null 2>&1 || /opt/gauntlet/tools/demo_reset.sh
```

Run it once by hand after the first deploy to be sure it works:

```bash
/opt/gauntlet/tools/demo_reset.sh
```

A reset takes about twenty seconds. Anyone signed in at 04:00 UTC gets
"user not found" on their next request and signs in again; the landing page
should say the demo resets at that hour.

## Hardening notes

The production checks in `docs/DEPLOY.md` all apply. What is specific to a
demo that strangers use:

- **Open registration is the feature.** The Learn door creates an account
  and a workspace per visitor. The per-address registration cap
  (`GAUNTLET_REGISTER_MAX_PER_WINDOW`, five per window) and login lockouts
  are in the app; sign-up confirmation by email keeps bots from filling the
  database between resets. The nightly reset is the backstop.
- **Publish the demo credentials, nowhere else.** The console does not
  advertise the seeded account in production (the sign-in page only shows the
  hint outside production), so the landing page states them. Rotate
  `GAUNTLET_DEMO_PASSWORD` if the demo organisation is ever vandalised; the
  next reset applies it.
- **Mail from the demo goes to whoever a visitor names.** Inject delivery
  and invites accept addresses from the facilitator. On the demo that is any
  visitor signed in as the demo admin. The `[Exercise]` subject prefix and the
  "simulated" footer are on every message; keep the SMTP account's daily
  sending limit low (Workspace's default is fine) and watch the DMARC reports
  at security@.
- **No secrets in the checkout.** `.env` holds the only secrets and is
  ignored by git. Do not put a licence on the demo: Community is the point.
- **Interactive API docs are off** (`GAUNTLET_DOCS` defaults to off in
  production). Turn them on only for a session and off again.
- **Updates.** `git fetch --tags && git checkout vX.Y.Z && docker compose up -d --build`,
  then run the reset script so the schema is rebuilt from the new migrations.
  Unattended upgrades for the OS; Watchtower is unnecessary with a pinned tag.
- **What to monitor.** `docker compose ps`, the cron mail, and Caddy's
  certificate renewal (`journalctl -u caddy`). There is nothing to back up.

## Checklist before announcing

- [ ] `https://try.moosearsenal.com/api/health` answers `{"status":"ok", …}`
- [ ] The four doors open; the seeded exercise starts and issues a certificate; `/verify.html` verifies it
- [ ] A solo run on each side plays through to a debrief and its PDF
- [ ] A free account created through the Learn door receives its confirmation email
- [ ] An inject delivered to your own address arrives from noreply@ in the inbox, not spam
- [ ] The reset script has run once by hand and the cron entry is installed
- [ ] The landing page states the demo credentials, the nightly reset, and links the terms and privacy pages
