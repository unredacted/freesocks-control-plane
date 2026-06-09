# Beta deploy: beta.freesocks.org (Caddy + docker compose)

Stand up the full beta stack on one host with docker compose: the self-hosted
Convex backend plus a Caddy tier that terminates TLS, serves the built SPA, and
reverse-proxies the API to the backend. App-layer encryption (CDN-blinding) ships
**dark** for beta (plaintext over TLS, dual-mode); see §10 to turn it on later.

```
beta.freesocks.org ─▶ Caddy (auto Let's Encrypt TLS + security headers)
                        ├─ /api/*, /healthz ─▶ backend:3211  (Convex HTTP actions, compose network)
                        └─ everything else  ─▶ built SPA (/srv/dist), SPA-fallback to index.html
   backend :3210 (deploy/sync) + dashboard :6791 bind to 127.0.0.1 only (never public)
```

Files: `docker-compose.beta.yml`, `Caddyfile`, `docker/web.Dockerfile`,
`.env.beta.example`.

## 0. Prerequisites

- A host with Docker + docker compose v2, ports **80 + 443** open to the internet.
- DNS: an **A (and AAAA) record for `beta.freesocks.org` pointing at the host's
  public IP**. Caddy needs this resolvable before it can get a cert.
- The repo checked out on the host (it is the SPA build context). For the
  `convex deploy` / `convex env set` steps you also need **Bun** on the host
  (`curl -fsSL https://bun.sh/install | bash`), or run those from a workstation
  over an SSH tunnel to `127.0.0.1:3210`.
- A real **Remnawave panel** (base URL + API token) if you want issuance to mint
  real keys. Beta has no dev mock; with no backend instance, get-account returns
  "no active instances" (see §7).

## 1. Infra env

```sh
cp .env.beta.example .env.beta
$EDITOR .env.beta
```

Set at least `SITE_ADDRESS=beta.freesocks.org`, `ACME_EMAIL`, a real
`INSTANCE_SECRET` (`openssl rand -hex 32`), and `CONVEX_SITE_ORIGIN=https://beta.freesocks.org`.
This file is the container infra config only; the app secrets are set on the
deployment in §3.

## 2. Bring up the stack

```sh
docker compose -f docker-compose.beta.yml --env-file .env.beta up -d --build
```

This builds the SPA (in `docker/web.Dockerfile`), starts the backend, and starts
Caddy. Caddy will obtain the TLS cert on first request to the domain (watch
`docker compose -f docker-compose.beta.yml logs -f web`). The backend's data lives
in the `data` volume; the LE cert lives in `caddy_data` (both persist across
restarts).

## 3. Set the deployment (app) secrets

These are set on the Convex deployment, separate from the infra env. Point the
CLI at the local backend and generate an admin key:

```sh
# Generate a deploy/admin key from the running backend (copy the printed key).
docker compose -f docker-compose.beta.yml --env-file .env.beta exec backend ./generate_admin_key.sh

export CONVEX_SELF_HOSTED_URL=http://127.0.0.1:3210
export CONVEX_SELF_HOSTED_ADMIN_KEY='<paste the admin key>'
```

Then set the application env (run on the host with Bun, or over the tunnel):

```sh
# Signing keys + salts (generate fresh, 32 bytes each).
bunx convex env set SESSION_SIGNING_KEY        "$(openssl rand -hex 32)"
bunx convex env set ADMIN_SESSION_SIGNING_KEY  "$(openssl rand -hex 32)"
bunx convex env set IP_HASH_SALT               "$(openssl rand -hex 32)"

# Set ONCE and keep: changing the pepper invalidates every account number.
bunx convex env set ACCOUNT_ID_PEPPER          "$(openssl rand -hex 32)"

# Bootstrap secret: you paste this in the browser in §6, so save the value.
BOOTSTRAP="$(openssl rand -hex 32)"; echo "ADMIN_BOOTSTRAP_SECRET=$BOOTSTRAP"
bunx convex env set ADMIN_BOOTSTRAP_SECRET     "$BOOTSTRAP"

# Cloudflare Turnstile (from the Turnstile dashboard for the beta domain).
bunx convex env set TURNSTILE_SECRET_KEY       '<turnstile secret>'
bunx convex env set TURNSTILE_SITE_KEY         '<turnstile site key>'   # public; echoed to the SPA

# WebAuthn (admin passkeys) bound to the beta domain.
bunx convex env set WEBAUTHN_RP_ID             beta.freesocks.org
bunx convex env set WEBAUTHN_ORIGIN            https://beta.freesocks.org

# Production posture: Secure cookies + trust Caddy's X-Forwarded-For.
bunx convex env set ENVIRONMENT                production
bunx convex env set TRUSTED_PROXY              true
```

`TRUSTED_PROXY=true` is correct here because the Caddyfile **overwrites**
`X-Forwarded-For` with the real client IP (so the free-tier per-IP cap cannot be
spoofed). Do NOT set `DEV_MOCK_BACKEND` (it is dev-only and double-gated off in
production anyway).

Optional, as needed: `WEBHOOK_SIGNING_SECRET` (billing webhook), `FREE_TIER_DAILY_CAP`,
`FREE_TIER_EXPIRY_DAYS`, the `S3_*` mirror block. Full table:
`docs/convex-self-hosting.md §5`.

## 4. Deploy the functions

```sh
bunx convex deploy -y   # uses CONVEX_SELF_HOSTED_URL + _ADMIN_KEY from §3
```

This typechecks + pushes `convex/` (queries, mutations, actions, the HTTP router,
the crons) and applies the schema.

## 5. Seed tiers + settings

```sh
bunx convex run seed:seedCutover '{}'
```

Idempotent: inserts the default-free + member tiers, the app settings, and (if
`REMNAWAVE_*` env is set) the primary Remnawave instance. Adjust tier limits
afterwards in the admin CMS (Tiers).

## 6. Bootstrap the first admin passkey

Open `https://beta.freesocks.org/admin` in a browser. While no passkey exists, the
bootstrap wizard appears: paste the `ADMIN_BOOTSTRAP_SECRET` from §3 and register a
passkey. Bootstrap **locks forever** once any credential exists.

## 7. Add a backend instance (issuance needs one)

In the admin CMS, go to **Backend servers** and add a Remnawave instance (base URL
+ API token; use **Test connection** before saving). Without at least one active
instance of the default-free tier's backend type, get-account returns "No active
remnawave instances". (Alternatively, set `REMNAWAVE_BASE_URL` + `REMNAWAVE_API_TOKEN`
before §5 and `seedCutover` seeds the first instance for you.)

## 8. Verify

```sh
curl -fsS https://beta.freesocks.org/healthz            # -> ok (proxied to :3211)
curl -sI https://beta.freesocks.org | grep -i -E 'content-security-policy|strict-transport'  # headers present
```

In a browser:
- the home page loads over a valid TLS cert;
- `/get-account` issues a key (after §7), and the reveal-once account number shows;
- sign in with that account number works;
- `/admin` is reachable and the passkey login works;
- the session cookie is `Secure` (DevTools, because `ENVIRONMENT=production`).

## 9. Updating / redeploying

```sh
git pull
# SPA changed -> rebuild + restart just the web image:
docker compose -f docker-compose.beta.yml --env-file .env.beta up -d --build web
# Backend functions changed -> redeploy:
bunx convex deploy -y
```

Header-only tweaks (Caddyfile) need no rebuild:

```sh
docker compose -f docker-compose.beta.yml --env-file .env.beta exec web \
  caddy reload --config /etc/caddy/Caddyfile
```

## 10. Turning on app-layer encryption later

1. Generate the keypairs: `node scripts/gen-e2ee-keys.mjs` (prints the Ed25519 +
   ML-DSA manifest keys and the X-Wing server key, public + private halves).
2. Set the private halves on the deployment: `FS_MANIFEST_SK`, `FS_MANIFEST_SK_PQ`,
   `FS_SERVER_HPKE_SK` (+ `POP_REQUIRED` after the client soaks).
3. Pass the public halves as build args to the web image (uncomment the `args` in
   `docker-compose.beta.yml`): `VITE_FS_MANIFEST_PK`, `VITE_FS_MANIFEST_PK_PQ`,
   `VITE_FS_SERVER_HPKE_KID`, `VITE_FS_SERVER_HPKE_PK`, then rebuild the web image.

See `docs/threat-model-cdn-blinding.md`.

## Notes

- **Image pinning.** `docker-compose.beta.yml` pins the Convex backend +
  dashboard to the digests tested in dev. Re-pin (and the `caddy:2-alpine` base in
  `docker/web.Dockerfile`) when you intentionally upgrade.
- **Datastore.** Defaults to single-box SQLite in the `data` volume. Set
  `POSTGRES_URL` in `.env.beta` to move to Postgres. Back up with `bunx convex
  export` regardless.
- **Dashboard.** Reach the admin dashboard over an SSH tunnel, never publicly:
  `ssh -L 6791:127.0.0.1:6791 -L 3210:127.0.0.1:3210 <beta-host>`, then open
  `http://127.0.0.1:6791`.
