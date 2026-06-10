# Beta deploy: beta.freesocks.org (Caddy + docker compose)

Stand up the whole beta stack on one host with `docker compose up`. Everything
runs in the stack: Postgres, the self-hosted Convex backend, a Caddy tier that
terminates TLS + serves the SPA + proxies the API, and two one-shot jobs that
deploy the functions, set the deployment env, and seed. No Bun on the host, no
manual admin-key copy. The only manual step is registering the first admin
passkey (a browser action). App-layer encryption (CDN-blinding) ships **dark** for
beta (plaintext over TLS, dual-mode); see §7 to turn it on later.

```
beta.freesocks.org ─▶ Caddy (auto Let's Encrypt TLS + security headers)
                        ├─ /api/*, /healthz ─▶ backend:3211  (Convex HTTP actions, compose network)
                        └─ everything else  ─▶ built SPA (/srv/dist), SPA-fallback to index.html

  postgres (datastore) ◀─ backend  ·  backend :3210 + dashboard :6791 bind to 127.0.0.1 only
  keygen (one-shot) ─▶ admin key ─▶ deployer (one-shot): convex deploy + env set + seedCutover
```

Files: `docker-compose.beta.yml`, `Caddyfile`, `docker/web.Dockerfile`,
`docker/deploy.Dockerfile`, `.env.beta.example`, `.env.convex.example`.

## 0. Prerequisites

- A host with Docker + docker compose v2, ports **80 + 443** open to the internet.
- DNS: an **A (and AAAA) record for `beta.freesocks.org`** pointing at the host's
  public IP. Caddy needs it resolvable before it can get a cert (the rest of the
  stack comes up regardless).
- The repo checked out on the host (it is the build context). Nothing else: the
  SPA build, function deploy, and seeding all run inside the stack.
- A real **Remnawave panel** (base URL + API token) if you want the subscription
  step to mint real keys. Beta has no dev mock. Account creation never needs a
  backend; only the proxy-subscription step does, and with no backend instance it
  shows "no active instances" (see §4).

## 1. Fill the two env files

```sh
cp .env.beta.example   .env.beta      # infra: Caddy + Convex backend identity + Postgres
cp .env.convex.example .env.convex    # app secrets: signing keys, pepper, Turnstile, WebAuthn
$EDITOR .env.beta .env.convex
```

- `.env.beta`: `SITE_ADDRESS=beta.freesocks.org`, `ACME_EMAIL`, `INSTANCE_SECRET`
  (`openssl rand -hex 32`), `POSTGRES_PASSWORD` (`openssl rand -hex 24`, URL-safe).
- `.env.convex`: fill **every** `CHANGE_ME` (`openssl rand -hex 32` for the keys),
  the Cap captcha keys (`CAP_SITE_KEY` / `CAP_SECRET`, created in the Cap dashboard
  on first boot — see Operations below), and keep `WEBAUTHN_*` / `ENVIRONMENT` /
  `TRUSTED_PROXY` as set. `ACCOUNT_ID_PEPPER` is **set once** (changing it
  invalidates every account number). The `deployer` refuses to run while any
  `CHANGE_ME` remains.

To also seed a Remnawave instance automatically, set `REMNAWAVE_BASE_URL` +
`REMNAWAVE_API_TOKEN` in `.env.convex` (else add it in the CMS in §4).

## 2. Bring up the whole stack

```sh
docker compose -f docker-compose.beta.yml --env-file .env.beta up -d --build
```

This builds the SPA + deployer images, then starts, in order:

1. `postgres` (the datastore) and `backend` (waits for Postgres healthy);
2. `keygen` (one-shot): derives the admin key into a shared volume;
3. `deployer` (one-shot): `convex deploy` (functions + schema) -> `convex env set`
   for every line in `.env.convex` -> `seed:seedCutover` (tiers, settings, and the
   Remnawave instance if `REMNAWAVE_*` is set);
4. `web` (Caddy) and `dashboard`.

Confirm the deploy job succeeded:

```sh
docker compose -f docker-compose.beta.yml --env-file .env.beta logs deployer   # ends with "[deploy] OK"
docker compose -f docker-compose.beta.yml --env-file .env.beta ps              # backend + postgres healthy
```

`keygen` and `deployer` are **one-shot jobs**: they show `Exited (0)` in `ps` when
they succeed (that is normal, not an error). Caddy obtains the TLS cert on the
first request once DNS resolves (`logs web`); the backend `data` + Postgres
`pgdata` + the LE cert in `caddy_data` all persist across restarts.

## 3. Bootstrap the first admin passkey

Open `https://beta.freesocks.org/admin` in a browser. While no passkey exists, the
bootstrap wizard appears: paste the `ADMIN_BOOTSTRAP_SECRET` you set in
`.env.convex`, then register a passkey. Bootstrap **locks forever** once any
credential exists.

## 4. Add a backend instance (the subscription step needs one)

Account creation never needs a proxy instance: `/get-account` mints the account
and reveal-once number with just a Turnstile check, even on a fresh box. The proxy
**subscription** does need an active instance of the account's backend type. If you
did not set `REMNAWAVE_*` in `.env.convex`, add one in the admin CMS: **Backend
servers** -> add a Remnawave instance (base URL + API token; use **Test connection**
before saving). Until then, the "Create subscription" step (on `/get-account` or
`/account`) shows a clean "No proxy server is available right now" notice instead of
a key; the account itself is unaffected.

## 5. Verify

```sh
curl -fsS https://beta.freesocks.org/healthz            # -> ok (proxied to :3211)
curl -sI  https://beta.freesocks.org | grep -i -E 'content-security-policy|strict-transport'
```

In a browser:

- the home page loads over a valid TLS cert;
- `/get-account` step 1 ("Create my account") reveals the account number (after the
  Cap captcha) even with no backend instance; step 2 ("Create subscription") issues
  a key after §4;
- signing in with that account number works;
- `/admin` passkey login works;
- the session cookie is `Secure` (DevTools), because `ENVIRONMENT=production`.

## 6. Updating / redeploying

```sh
git pull
docker compose -f docker-compose.beta.yml --env-file .env.beta up -d --build
```

That rebuilds the SPA + deployer images and re-runs `keygen` + `deployer`, which
re-deploys the functions, re-applies `.env.convex`, and re-seeds (all idempotent).
Header-only Caddyfile tweaks need no rebuild:

```sh
docker compose -f docker-compose.beta.yml --env-file .env.beta exec web \
  caddy reload --config /etc/caddy/Caddyfile
```

## 7. Turning on app-layer encryption later

1. Generate the keypairs: `node scripts/gen-e2ee-keys.mjs` (prints the Ed25519 +
   ML-DSA manifest keys and the X-Wing server key, public + private halves).
2. Add the private halves to `.env.convex` (`FS_MANIFEST_SK`, `FS_MANIFEST_SK_PQ`,
   `FS_SERVER_HPKE_SK`; `POP_REQUIRED` after the client soaks) so the deployer sets
   them.
3. Pass the public halves as build args to the web image (uncomment the `args` in
   `docker-compose.beta.yml`): `VITE_FS_MANIFEST_PK`, `VITE_FS_MANIFEST_PK_PQ`,
   `VITE_FS_SERVER_HPKE_KID`, `VITE_FS_SERVER_HPKE_PK`, then re-run §6.

See `docs/threat-model-cdn-blinding.md`.

## Notes

- **Image pinning.** `docker-compose.beta.yml` pins the Convex backend + dashboard
  (and `keygen`, which reuses the backend image) to the digests tested in dev.
  Re-pin those + the `caddy:2-alpine` / `oven/bun` / `postgres:18` bases when you
  intentionally upgrade.
- **Datastore.** The stack runs **Postgres 18** (the `postgres` service). Set
  `POSTGRES_PASSWORD` in `.env.beta`; the backend connects with `POSTGRES_URL` (no
  db name) and uses the database named after `INSTANCE_NAME` with hyphens replaced
  by underscores, which is why `POSTGRES_DB` is `freesocks_beta` and must stay in
  sync with `INSTANCE_NAME`. SSL on the link is disabled via `DO_NOT_REQUIRE_SSL`
  (private compose network). The backend `data` volume still holds file/module/
  search storage (until S3). Postgres data is the `pgdata` volume; PG18's image
  volume is `/var/lib/postgresql`, not the pre-18 `/data` path. Back up with
  `bunx convex export` and/or `pg_dump`.
- **Client IP.** `TRUSTED_PROXY=true` is safe because Caddy (no `trusted_proxies`)
  overwrites `X-Forwarded-For` with the real client IP, so the free-tier per-IP cap
  cannot be spoofed. `CF_FRONTED` is left UNSET in this topology: there is no Cloudflare
  edge in front, so a client-supplied `cf-connecting-ip` would be spoofable — the backend
  ignores that header unless `CF_FRONTED=true`, and Caddy strips it upstream anyway.
- **Dashboard.** Reach it over an SSH tunnel, never publicly:
  `ssh -L 6791:127.0.0.1:6791 -L 3210:127.0.0.1:3210 <beta-host>`, then open
  `http://127.0.0.1:6791`.

## Operations (A3/A4)

### Captcha (Cap) first-run

The `cap` service runs the self-hosted [Cap](https://trycap.dev) captcha. On first
boot, tunnel to it and create a site key:

```
ssh -L 3000:127.0.0.1:3000 <beta-host>   # if you expose it locally; else exec in
docker compose -f docker-compose.beta.yml exec cap sh   # then browse its dashboard
```

Log in with `CAP_ADMIN_KEY`, create a site key, and put the **site key** +
**secret** into `.env.convex` as `CAP_SITE_KEY` / `CAP_SECRET` (the backend reads
them; `CAP_API_ENDPOINT=http://cap:3000`, `CAP_PUBLIC_ENDPOINT=/cap`). Re-run the
deployer (`docker compose ... up -d`) so the env applies.

### Health & monitoring

- **`/healthz`** — liveness only (process up). Used by the compose healthchecks.
- **`/readyz`** — deep readiness: does a real datastore round-trip and returns
  **503** if Postgres is unreachable. **Point your external uptime monitor at
  `https://<host>/readyz`** and alert on non-200. This is the launch alerting
  baseline; pair it with Convex log streaming (below) for error-rate alerts.
- **Error visibility.** Stream the backend's logs off-box and alert on the rate
  of `issuance failed` / `create failed` lines and 5xx envelopes. Minimal setup:
  `docker compose -f docker-compose.beta.yml logs -f backend | <log shipper>`,
  or a sidecar that tails and POSTs to a webhook. The audit log
  (admin CMS → Audit log) is the pull-based record of lifecycle events.

### Backups & restore

The `backup` service `pg_dump`s the datastore every `BACKUP_INTERVAL_SECONDS`
and (when `BACKUP_S3_*` is set) uploads offsite, pruning to `BACKUP_RETENTION`
local copies. **Configure offsite storage before launch** — accounts are
anonymous, so a lost datastore is unrecoverable. Also back up the **secret set**
(the `bunx convex env` values, especially `ACCOUNT_ID_PEPPER` — losing it
invalidates every account number).

Restore a dump:

```
# copy the chosen dump to the host, then:
gunzip -c freesocks-freesocks_beta-<ts>.sql.gz \
  | docker compose -f docker-compose.beta.yml exec -T postgres \
      psql -U convex -d freesocks_beta
```

Run a **restore drill** before launch (restore into a scratch DB and diff row
counts) and periodically after.

### Rollback (A4)

Deploys are idempotent and the contract changes are kept additive (backend-first
is safe). To roll back:

1. **Backend/functions:** check out the previous good tag and re-run the deployer
   (`docker compose -f docker-compose.beta.yml up -d --build deployer`), or in CI
   re-tag the previous good commit (`git tag -f vX … && git push -f --tags`), or
   `git revert` the bad commit and tag. `convex deploy` replaces the function set.
2. **SPA:** rebuild the `web` image from the previous tag
   (`docker compose ... up -d --build web`) — it bakes the SPA from that checkout.
3. **Schema:** Convex applies schema on deploy; a rollback that drops a field
   only affects new writes. Restore from a backup only if data was corrupted.

### Incident runbook (quick reference)

- **Backend down / `/readyz` 503:** check `docker compose ps`, `logs backend`,
  `logs postgres`; restart `backend`; if Postgres is the cause, see below.
- **Postgres disk full:** prune old WAL/backups, grow the volume, restart. The
  `backup` service keeps only `BACKUP_RETENTION` local copies; offsite is durable.
- **Cert expiry:** Caddy auto-renews; if it fails, check `logs web`, that `:80`
  is reachable (ACME HTTP-01), and `ACME_EMAIL` is set.
- **Cap (captcha) outage:** `/get-account` + login fail closed. Check `logs cap`
  / `logs valkey`; restart. As a temporary measure an operator can loosen the
  `freetier.create` / `account-login.*` limits in the admin CMS, but the captcha
  is a primary anti-abuse control — restore it promptly.
