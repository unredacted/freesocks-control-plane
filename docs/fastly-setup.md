# Fastly Compute deploy target

**Status: scaffolded, not yet production-deployed.** Every piece of the runtime
adapter typechecks against the Workers/Node toolchain and the design is sound, but
nothing in this repo has been published to a real Fastly Compute service yet. Treat
the first deploy as a beta — expect to iron out a few package-resolution or
global-shim differences. If you're the first to run it through, file the rough
edges back to this doc.

## When to choose Fastly over Cloudflare Workers

The Cloudflare Workers target is the recommended path: it bundles D1, KV, Email
Sending, and cron triggers in one platform, and it's the target this repo's CI
runs against on every PR. Fastly Compute is here for the cases where Workers isn't
acceptable — regulated workloads that need Fastly's compliance posture, customers
already invested in Fastly's edge network, or anyone who wants to keep their data
plane and identity plane on different vendors.

The trade-off is operational complexity. Fastly Compute has no built-in SQL
database, no built-in cron, and no Cloudflare Email Sending. Pieces those services
provide on Workers have to be wired up separately on Fastly.

## What you'll set up

| Capability | Workers                                         | Fastly                                             |
| ---------- | ----------------------------------------------- | -------------------------------------------------- |
| Database   | Cloudflare D1 (binding)                         | Turso libSQL (HTTP)                                |
| KV         | Workers KV (binding)                            | Fastly KV Store (binding)                          |
| Secrets    | `wrangler secret`                               | Fastly Secret Store + Config Store                 |
| Email      | `SEND_EMAIL` binding (Cloudflare Email Sending) | Resend or AWS SES                                  |
| Cron       | `wrangler triggers` (native)                    | External scheduler → `/api/internal/cron/run-task` |
| Static SPA | `[assets]` Workers Static Assets                | Separate Fastly service or any static host         |

## Prerequisites

- A Fastly account with Compute services enabled.
- `fastly` CLI installed: `brew install fastly/tap/fastly` or download from
  <https://github.com/fastly/cli/releases>.
- A Turso account (or any libSQL-compatible HTTP database). Sign up at
  <https://turso.tech>; the free tier covers a small FreeSocks deployment.
- A Resend account (or AWS SES credentials) for email.
- An HTTP-capable scheduler to drive cron (see below).

## Step 1 — Provision Turso

1. Create a database: `turso db create freesocks-control-plane`.
2. Apply the migrations using a libSQL client that understands SQLite migrations:
   ```bash
   # apply every migration file in order, starting at 0000_init.sql
   turso db shell freesocks-control-plane < src/server/db/migrations/0000_init.sql
   # repeat for 0001_seed_tiers.sql, 0002_…, through the latest
   ```
   This repo's migrations are SQLite-compatible — the same files the Cloudflare D1
   target uses. The `wrangler d1 migrations apply` command isn't usable here
   because it talks D1's REST API; pipe the SQL through `turso db shell` instead.
3. Record the database URL and auth token:
   ```bash
   turso db show --url freesocks-control-plane            # → libsql://...
   turso db tokens create freesocks-control-plane         # → eyJ...
   ```

## Step 2 — Create the Fastly service

```bash
fastly compute init                # creates the service shell
cp fastly.toml.example fastly.toml # populate from the template
# Edit fastly.toml to fill every <PLACEHOLDER> with real values
```

The template declares:

- Three KV Stores (`FS_SESSIONS_KV`, `FS_CACHE_KV`, `FS_RATELIMIT_KV`) — same
  binding names as the Workers target, so service code is identical.
- A Config Store (`fs_config`) for non-secret runtime config.
- A Secret Store (`fs_secrets`) for credentials.
- Backends for every external host the worker calls: Remnawave, Authentik,
  CiviCRM, Turso, Turnstile, Resend. Add an entry per S3 mirror if you enable
  mirroring.

## Step 3 — Provision KV / Config / Secret stores

```bash
# KV stores
fastly kv-store create --name=FS_SESSIONS_KV
fastly kv-store create --name=FS_CACHE_KV
fastly kv-store create --name=FS_RATELIMIT_KV

# Config store + secret store
fastly config-store create --name=fs_config
fastly secret-store create --name=fs_secrets

# Populate the secret store (each invocation prompts for the value)
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=REMNAWAVE_API_TOKEN
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=AUTHENTIK_CLIENT_SECRET
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=CIVICRM_API_KEY
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=RESEND_API_KEY
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=SESSION_SIGNING_KEY
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=ADMIN_SESSION_SIGNING_KEY
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=ADMIN_BOOTSTRAP_SECRET
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=IP_HASH_SALT
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=TURNSTILE_SECRET_KEY
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=CRON_TRIGGER_SECRET
fastly secret-store-entry create --store-id=$SECRET_STORE_ID --name=TURSO_AUTH_TOKEN
```

Generate strong values for the signing keys, bootstrap secret, IP salt, and cron
trigger secret. `openssl rand -hex 32` is fine for any of them.

Populate the Config Store from `fastly.toml`'s `local_server.config_stores.fs_config.contents`
section using `fastly config-store-entry create` — same shape as the Secret Store
commands but without prompting for the value.

## Step 4 — Build and publish

```bash
bun install
bun run build:fastly      # → bin/main.wasm
fastly compute publish    # uploads bin/main.wasm + fastly.toml, activates service
```

The first publish prints the service URL. Bind it to `app.freesocks.org` (or
whatever public hostname you're using) via the Fastly domains UI.

## Step 5 — Wire the SPA

The Fastly entry **does not bundle the SPA**. Two patterns work:

1. **Same Fastly service**, separate Compute or VCL config that serves the static
   `dist/client` bundle. Use Fastly's
   [compute-js-static-publisher](https://github.com/fastly/compute-js-static-publisher)
   for a same-service setup.
2. **Different host entirely** — Cloudflare Pages, GitHub Pages, S3+CDN. Set the
   SPA's API base URL to point at the Fastly compute service.

The Hono router only ever sees `/api/*` paths on Fastly; the SPA host is responsible
for proxying or routing those.

## Step 6 — Wire the cron trigger

Fastly Compute has no native cron. The cron dispatcher is exposed via
`POST /api/internal/cron/run-task?task=<name>` with a `Bearer` header carrying
`CRON_TRIGGER_SECRET`. Pick any HTTP-capable scheduler and point it at this endpoint
on the cadence below.

| Task                    | Cadence            | Purpose                                                 |
| ----------------------- | ------------------ | ------------------------------------------------------- |
| `reconcile-memberships` | every 5 min        | Poll CiviCRM, apply tier changes, run tier propagation  |
| `grace-sweep`           | every 10 min       | Transition grace-period users + run Outline healthcheck |
| `cleanup-expired-free`  | daily at 03:00 UTC | Remove free-tier users past their expiry                |

Schedulers that work well:

- **GitHub Actions** with a `schedule` workflow: free, public-internet
  triggers, runs on GitHub's infrastructure. Good for `cleanup-expired-free` at
  daily cadence; rate limits make the 5-min jobs marginal.
- **A separate Cloudflare Worker** with native cron triggers that just `curl`s
  the Fastly endpoint. Belt-and-suspenders if you're hedging vendors but want
  reliable cron.
- **cron-job.org** or similar SaaS — free for low cadences, paid for sub-minute.
- **A VPS with systemd timers** if you have a machine that's always on.

Example GitHub Actions workflow:

```yaml
# .github/workflows/cron-trigger.yml
name: Cron triggers
on:
  schedule:
    - cron: '*/5 * * * *' # reconcile-memberships
    - cron: '*/10 * * * *' # grace-sweep
    - cron: '0 3 * * *' # cleanup-expired-free
jobs:
  reconcile:
    if: github.event.schedule == '*/5 * * * *'
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fSs -X POST \
            -H "Authorization: Bearer ${{ secrets.CRON_TRIGGER_SECRET }}" \
            "https://app.freesocks.org/api/internal/cron/run-task?task=reconcile-memberships"
  grace:
    if: github.event.schedule == '*/10 * * * *'
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fSs -X POST \
            -H "Authorization: Bearer ${{ secrets.CRON_TRIGGER_SECRET }}" \
            "https://app.freesocks.org/api/internal/cron/run-task?task=grace-sweep"
  cleanup:
    if: github.event.schedule == '0 3 * * *'
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fSs -X POST \
            -H "Authorization: Bearer ${{ secrets.CRON_TRIGGER_SECRET }}" \
            "https://app.freesocks.org/api/internal/cron/run-task?task=cleanup-expired-free"
```

GitHub Actions `schedule` triggers can be delayed by several minutes under load
(documented in GitHub's docs). If exact cadence matters for your operation, run
the trigger from a paid scheduler.

## Step 7 — Bootstrap the first admin

Same as the Workers target. Generate the bootstrap secret, set it in the Secret
Store, deploy, visit `/admin`, complete passkey registration. Once the first admin
exists, rotate (or unset) `ADMIN_BOOTSTRAP_SECRET` so no further bootstrap is
possible.

## Known limitations on Fastly

- **No `list()` on KV.** Admin diagnostics that enumerate KV keys are not
  available on Fastly. The relevant call paths throw a clear error if reached.
- **`waitUntil` is best-effort.** Background work fires-and-forgets; the runtime
  may cut it off when the request handler returns. Anything that absolutely must
  complete should be driven from cron, not `waitUntil`.
- **`@aws-sdk/client-s3` is heavy.** It works on Fastly's WASM runtime in
  principle, but the bundle size eats into Fastly's WASM limit. If you hit a
  size error, disable S3 mirroring (`S3_MIRRORS_ENABLED=false`) until we
  implement a lightweight signed-fetch alternative. The control plane still
  works without mirrors; you lose the censorship-resistant fallback URL.
- **No native cron.** External trigger required — see step 6.
- **No Cloudflare Email Sending.** Use `EMAIL_PROVIDER=resend` (or `ses`).
- **No Cloudflare-specific request fields.** The `request.cf` object Workers
  exposes (country, ASN, TLS fingerprint) is not present on Fastly. The code
  reads `CF-IPCountry` headers when available, but TLS fingerprint deny-lists
  are Workers-only today.

## Verification

After deploy:

```bash
# Health
curl https://app.freesocks.org/api/healthz   # → 200

# OpenAPI spec is served
curl https://app.freesocks.org/api/openapi.json | jq .info

# Cron dispatcher rejects unauthenticated callers
curl -X POST https://app.freesocks.org/api/internal/cron/run-task?task=grace-sweep
# → 401

# And accepts authenticated ones
curl -X POST \
  -H "Authorization: Bearer $CRON_TRIGGER_SECRET" \
  "https://app.freesocks.org/api/internal/cron/run-task?task=grace-sweep"
# → 200 { "ok": true, "task": "grace-sweep", "durationMs": <n> }
```
