# Self-hosting Convex (FreeSocks Control Plane)

The control plane runs entirely on a **self-hosted Convex backend** (the
`convex/` functions + HTTP router) plus a static Svelte SPA. The previous
Hono/Cloudflare-Workers stack has been removed. See **§6** for the fresh-deploy
cutover runbook and **§7** for the reverse proxy that serves the SPA.

## Prerequisites

- Docker (Compose v2)
- `bun install` installs the `convex` CLI

## 1. Configure the backend

The docker-compose stack lives at the repo root (`docker-compose.yml`, project
name `fcp`). Its config is `.env.docker` (kept separate from `.env` / `.env.local`,
which Vite and the Convex CLI load):

```sh
cp .env.docker.example .env.docker
openssl rand -hex 32          # paste the result into INSTANCE_SECRET in .env.docker
```

## 2. Start the backend + dashboard

```sh
bun run selfhost:up
```

- Backend API → http://127.0.0.1:3210
- HTTP actions → http://127.0.0.1:3211
- Dashboard → http://localhost:6791

Data persists in the `fcp_data` Docker volume (SQLite). Set `POSTGRES_URL` in
`.env.docker` to move to Postgres when single-box write throughput is outgrown.

## 3. Point the CLI at the backend

```sh
bun run selfhost:env          # generates an admin key + writes .env.local for you
```

This writes `.env.local` (gitignored) with `CONVEX_SELF_HOSTED_URL` +
`CONVEX_SELF_HOSTED_ADMIN_KEY` (and the `VITE_CONVEX_*` URLs the SPA uses from P9).

> **Do not** run a bare `convex dev` and pick **"Start without an account (run
> Convex locally)"**: that boots a _separate_ CLI-managed backend (on a
> different port) instead of this docker one, and writes a conflicting
> `CONVEX_DEPLOYMENT` into `.env.local` (you'll then hit
> _"CONVEX_SELF_HOSTED_URL … must not be set when CONVEX_DEPLOYMENT is set"_).
> Always run the step above first; `.env.local` must contain the
> `CONVEX_SELF_HOSTED_*` vars and **no** `CONVEX_DEPLOYMENT`.

## 4. Deploy functions + schema

```sh
bun run convex:dev            # watch mode: pushes convex/ and writes convex/_generated
# one-shot:
bunx convex dev --once
```

For CI / non-interactive deploys: `bun run convex:deploy`.

## 5. Function environment variables

Convex functions read config from **deployment** env vars (separate from the
SPA's build-time `VITE_*`). Set with `bunx convex env set NAME value` (or the
dashboard → Settings → Environment Variables). `bunx convex env list` shows what's set.

**Required for a functioning deploy:**

| Var                                              | Used by                                                                                                                                                                                                                         |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SESSION_SIGNING_KEY`                            | member `fs_session` cookie HMAC: `openssl rand -hex 32`                                                                                                                                                                         |
| `ADMIN_SESSION_SIGNING_KEY`                      | admin `fs_admin_session` cookie HMAC: `openssl rand -hex 32`                                                                                                                                                                    |
| `ADMIN_BOOTSTRAP_SECRET`                         | first-run admin passkey bootstrap gate: `openssl rand -hex 32`                                                                                                                                                                  |
| `IP_HASH_SALT`                                   | HMAC salt for free-tier IP keying + login rate-limit: `openssl rand -hex 32`                                                                                                                                                    |
| `ACCOUNT_ID_PEPPER`                              | keyed-hash pepper for account numbers (a leaked hash column is useless without it): `openssl rand -hex 32`. **Set once before launch; changing it invalidates every account number.**                                           |
| `CAP_API_ENDPOINT`, `CAP_SITE_KEY`, `CAP_SECRET` | self-hosted **Cap** captcha siteverify (free issuance + account login). `CAP_API_ENDPOINT` is the backend-internal Cap URL (e.g. `http://cap:3000`); `CAP_SECRET` is the site key's secret. Replaced Cloudflare Turnstile (W1). |
| `WEBAUTHN_RP_ID`                                 | passkey RP id = the bare domain (e.g. `freesocks.org`)                                                                                                                                                                          |
| `WEBAUTHN_ORIGIN`                                | allowed page origin(s), comma-separated (e.g. `https://app.freesocks.org`)                                                                                                                                                      |

(Backend connection config is no longer required env: it lives per-instance in the
`backendServers` table, managed in the admin CMS. See `REMNAWAVE_*` below for the
optional one-time bootstrap.)

> **Beta compose stack:** the in-stack `deployer` **auto-generates the five
> pure-random secrets** above (`SESSION_SIGNING_KEY`, `ADMIN_SESSION_SIGNING_KEY`,
> `ADMIN_BOOTSTRAP_SECRET`, `IP_HASH_SALT`, `ACCOUNT_ID_PEPPER`) once and persists
> them in the deployment env — leave them as `CHANGE_ME` in `.env.convex` to use
> that. It never regenerates an already-set value. Retrieve the generated
> `ADMIN_BOOTSTRAP_SECRET` (for the first passkey) with
> `bunx convex env get ADMIN_BOOTSTRAP_SECRET`. A standalone `bunx convex deploy`
> (no compose) still needs them set manually.

> **Which file, and applying a change later.** Every var in this section is a Convex
> **deployment** env var and belongs in **`.env.convex`** (the deployer pushes each one
> via `convex env set` on `up`). Compose/build config — ports, `INSTANCE_SECRET`,
> `POSTGRES_PASSWORD`, the `VITE_FS_*` build pins, backup creds — belongs in `.env.beta`
> instead; a deployment var placed there will **not** reach the backend. `.env.convex.example`
> lists every deployment var (optional ones commented). To change one after the first deploy,
> edit `.env.convex` and re-run just the deployer:
>
> ```sh
> docker compose -f docker-compose.beta.yml --env-file .env.beta up -d --no-deps --force-recreate deployer
> docker compose -f docker-compose.beta.yml --env-file .env.beta logs --tail=50 deployer   # look for: env set <KEY>  →  [deploy] OK
> ```
>
> A bare `bunx convex env set` from the host shell fails with _"No CONVEX_DEPLOYMENT set"_ — the
> self-hosted CLI creds (URL + admin key) live in the stack, not your shell, so drive env changes
> through the deployer (or a `docker compose run --rm --no-deps --entrypoint bash deployer` shell
> that exports the admin key from `/keys/admin_key`).

**Optional / feature-gated:**

| Var                                                                         | Default                              | Used by                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------------------------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ENVIRONMENT`                                                               | `production`                         | set to `development` ONLY for local http (drops the cookie `Secure` flag)                                                                                                                                                                                                                                                                                                                                         |
| `WEBAUTHN_RP_NAME`                                                          | `FreeSocks Admin`                    | passkey display name                                                                                                                                                                                                                                                                                                                                                                                              |
| `CAP_PUBLIC_ENDPOINT`                                                       | `/cap`                               | same-origin path the browser Cap widget posts challenges to (Caddy proxies it to the `cap` service); echoed to the SPA via `/api/v1/config` with `CAP_SITE_KEY`                                                                                                                                                                                                                                                   |
| `CAP_DEV_BYPASS`                                                            | unset                                | LOCAL DEV ONLY (requires `ENVIRONMENT=development`): treat every captcha token as valid so the flows work without a Cap server. Double-gated; prod ignores it.                                                                                                                                                                                                                                                    |
| `TRUSTED_PROXY`                                                             | unset                                | set `true` ONLY behind a reverse proxy that overwrites `X-Forwarded-For` (fail-closed client-IP). **Required behind Caddy** — unset here means every anonymous-issuance request fails closed with `freetier.ip_unresolved`.                                                                                                                                                                                       |
| `CF_FRONTED`                                                                | unset                                | set `true` ONLY when a real Cloudflare edge fronts the origin AND the origin rejects direct (non-CF) traffic. Makes the backend trust `cf-connecting-ip`. In the default Caddy-direct topology leave it UNSET — a client-supplied `cf-connecting-ip` is otherwise spoofable. See `docs/threat-model-cdn-blinding.md`.                                                                                             |
| `POP_EXPECTED_HOST`                                                         | unset                                | v2 PoP cross-vhost host check; defaults to `WEBAUTHN_ORIGIN`'s host when unset. Set if the public host differs from the WebAuthn origin.                                                                                                                                                                                                                                                                          |
| `POP_REQUIRED`                                                              | unset                                | CDN-blinding Phase 2: set `true` (after the client soaks) to reject legacy cookie-only sessions and require proof-of-possession. Sessions already bound to a PoP key always enforce it regardless. Watch the admin dashboard's _Session protection_ card (`statusSummary.pop.readyToEnable`) for readiness before flipping. See `docs/threat-model-cdn-blinding.md`.                                              |
| `DEV_MOCK_BACKEND`                                                          | unset                                | LOCAL DEV ONLY: set `true` (requires `ENVIRONMENT=development`) to issue synthetic subscriptions without a real Remnawave/Outline, so the get-account flow works locally. Double-gated; a `production` deployment ignores it. NEVER in prod.                                                                                                                                                                      |
| `REMNAWAVE_BASE_URL`, `REMNAWAVE_API_TOKEN`                                 | none                                 | One-time bootstrap only: `seed:seedCutover` seeds the primary Remnawave instance into `backendServers` from these if set. After cutover, manage instances in the admin CMS ("Backend servers") and remove these. A fresh install can skip them and add every instance in the CMS.                                                                                                                                 |
| `FREE_TIER_DAILY_CAP`                                                       | —                                    | **Removed.** The per-IP/day free-account cap is now the admin-tunable `freetier.create` rate-limit policy (default 3), editable in the admin CMS → Rate limits (no deploy needed).                                                                                                                                                                                                                                |
| `SUBSCRIPTION_RETENTION_DAYS`                                               | `90`                                 | retention for long-`deleted` subscription rows (history only; the backend user is already gone). Other `*_RETENTION_DAYS` knobs: `AUDIT` (180), `WEBHOOK` (90), `TIER_HISTORY` (365), `FREE_GRANT` (30).                                                                                                                                                                                                          |
| `FREE_TIER_EXPIRY_DAYS`                                                     | —                                    | **Removed.** The free-account lifetime is now the admin-tunable `freetier.expiryDays` setting (default 90), editable in the admin CMS → Settings (no deploy). Drives both the issued key's backend expiry and the cleanup sweep.                                                                                                                                                                                  |
| `WEBHOOK_SIGNING_SECRET`                                                    | none                                 | HMAC for `POST /api/webhooks/billing` (the billing seam). **Required once a billing portal posts webhooks**; while unset the endpoint answers a distinct `503 webhook.not_configured` (never a misleading 400). Day-1 paid upgrades use admin-minted membership codes, which don't need this.                                                                                                                     |
| `PUBLIC_BASE_URL`                                                           | none                                 | the deployment's public origin (e.g. `https://beta.freesocks.org`); the backend builds absolute IPN + success/cancel URLs from it. **Required for any self-service billing rail.** See `docs/billing.md`.                                                                                                                                                                                                         |
| `NOWPAYMENTS_API_KEY`, `NOWPAYMENTS_IPN_SECRET`, `NOWPAYMENTS_API_URL`      | API_URL=`https://api.nowpayments.io` | crypto rail. The key creates invoices; the IPN secret verifies callbacks (HMAC-SHA512). **Required once the NOWPayments rail is enabled in Admin → Billing**; while the IPN secret is unset `/api/webhooks/nowpayments` answers `503 billing.not_configured`. See `docs/billing.md` for the USD off-ramp.                                                                                                         |
| `STRIPE_API_KEY`, `STRIPE_WEBHOOK_SECRET`                                   | none                                 | card rail (Phase 2). Required once the Stripe rail is enabled.                                                                                                                                                                                                                                                                                                                                                    |
| `PAYPAL_CLIENT_ID`, `PAYPAL_SECRET`, `PAYPAL_WEBHOOK_ID`, `PAYPAL_API_BASE` | none                                 | PayPal rail (Phase 3). Required once the PayPal rail is enabled. `PAYPAL_API_BASE` = `https://api-m.paypal.com` (live) or the sandbox host.                                                                                                                                                                                                                                                                       |
| `BILLING_PENDING_TTL_HOURS`, `BILLING_ORDER_RETENTION_DAYS`                 | `48`, `365`                          | abandoned-checkout expiry window + terminal-order retention.                                                                                                                                                                                                                                                                                                                                                      |
| `FS_SERVER_HPKE_SK`, `FS_MANIFEST_SK`, `FS_MANIFEST_SK_PQ`                  | none                                 | CDN-blinding sealed channel (user-facing label "HPKE"): the server HPKE private key + the classical/post-quantum manifest signing keys. Generate all of them with `bun scripts/gen-e2ee-keys.mjs` (the printed `VITE_FS_*` public halves bake into the SPA build). Unset = the deployment runs **dark** (plaintext dual-mode over TLS). Full runbook: `docs/secrets.md` §2 + `docs/threat-model-cdn-blinding.md`. |
| `WEBAUTHN_CHALLENGE_RETENTION_DAYS`                                         | `1`                                  | retention (days past `expiresAt`) for consumed/expired passkey challenge rows before the daily sweeps delete them.                                                                                                                                                                                                                                                                                                |
| `MEMBERS_JOIN_URL`, `MEMBERS_ACCOUNT_URL`                                   | none                                 | optional member-portal links surfaced in `/api/v1/config`                                                                                                                                                                                                                                                                                                                                                         |
| `DONATE_URL`, `CONTACT_URL`                                                 | none                                 | optional links surfaced in `/api/v1/config`: the renew/upgrade callouts point lapsed/expiring members at `DONATE_URL` (e.g. `https://unredacted.org/donate`) with `CONTACT_URL` (`https://unredacted.org/contact`) as the secondary CTA                                                                                                                                                                           |
| _(S3 subscription mirrors — see the note below the table)_                  | n/a                                  | **Moved to the DB.** Mirror buckets are configured in the admin CMS (Admin → Storage), not env. No `S3_*` env vars remain.                                                                                                                                                                                                                                                                                        |

The SPA build reads `VITE_CONVEX_SITE_URL` (the public HTTP-actions origin that
`/api` is proxied to). Backend instance connection config (Remnawave `baseUrl` +
`apiToken`, Outline `apiUrl`) lives per-row in the `backendServers` table (admin
CMS, "Backend servers"), never in env. The `REMNAWAVE_*` vars only seed the first
Remnawave instance at cutover. Likewise, **S3 subscription-mirror buckets** live
per-row in the `mirrorProviders` table (admin CMS, "Storage mirrors"), each with
its own `secretAccessKey` (stored server-side, never returned) and optional
preferred country codes. Mirrors are **opt-in + lazy**: a member who can't reach
the normal subscription URL provisions one (country-tiered, capped by the
`mirror.maxPerUser` admin setting in CMS → Settings, default 3); nothing is mirrored
proactively. Country tiering reads `CF-IPCountry` to prefill the picker, so it only
helps when **`CF_FRONTED=true`** (otherwise the member just selects their region) —
the code is transient and never stored. See `docs/threat-model-cdn-blinding.md`.

## 6. Cutover to Convex (P11, start fresh)

No data is migrated (free users churn within the expiry window; there are no OIDC
members to carry). On a fresh backend:

1. **Stand up + deploy**: steps 1 to 4 above, then `bunx convex deploy -y` (CI uses
   `CONVEX_SELF_HOSTED_URL` + `CONVEX_SELF_HOSTED_ADMIN_KEY`).
2. **Set env**: every Required var in §5 (and `ENVIRONMENT` left at `production`
   so cookies are `Secure`; `TRUSTED_PROXY=true` since you're behind the proxy in §7).
3. **Seed tiers + settings** (idempotent):
   ```sh
   bunx convex run seed:seedCutover '{}'
   ```
   Adjust the tier limits afterward in the admin CMS (Tiers) or edit `convex/seed.ts`.
4. **Register Outline servers** (only if using the Outline backend): admin CMS →
   **Backend servers** (the `apiUrl` secret is stored server-side, never echoed back).
5. **Bootstrap the first admin passkey**: open `/admin` in a browser; the wizard
   appears while `passkeyCredentials` is empty. Paste `ADMIN_BOOTSTRAP_SECRET`,
   register a passkey. Bootstrap **locks forever** once any credential exists.
   Sign-in is **usernameless**: the passkey is discoverable, so `/admin` just
   shows a "Sign in with a passkey" button (a username field is a fallback only).
   **Add further admins** from the CMS — **Admins → Invite an admin** mints a
   one-time link (24h) the new person opens on their own device to register their
   passkey; no second bootstrap secret needed.
6. **Issue `fsv1_` service tokens** (if any external callers): admin CMS → API Tokens,
   **or headless** (the zero-touch path for automation such as `ansible-role-freesocks`):
   ```sh
   bunx convex run adminApi:mintAutomationToken \
     '{"scopes":["admin:servers:read","admin:servers:write"]}'
   ```
   This mints a scoped `fsv1_` token attributed to a synthetic, credential-less
   `automation` admin (a valid audit actor that can never sign in — it has no
   passkey). Only `admin:*` scopes are allowed. It uses the same self-hosted admin
   key as `seed:seedCutover`, so no browser/passkey is needed — and the HTTP
   `/api/v1/admin/tokens` route deliberately stays cookie-gated, so a leaked token
   can't mint another token over the public edge.
7. **Verify** (§8), then point DNS at the reverse proxy and decommission the old stack.

## 7. Reverse proxy

Convex does **not** serve your SPA. A reverse proxy terminates TLS, serves the
static `vite build` output, and routes the API surface to the HTTP-actions port.
Example `Caddyfile` (the SPA's `apiClient` calls same-origin `/api/*` + `/healthz`):

```caddy
app.freesocks.org {
    encode gzip

    # Security headers. The captcha (self-hosted Cap) is bundled + served
    # same-origin, so the CSP is pure 'self' — ZERO third-party origins. Inline
    # STYLES are allowed (Svelte style bindings); inline SCRIPTS are not (the FOUC
    # theme logic is the external /theme-init.js). worker-src 'self' covers both
    # the PoP signing worker and Cap's proof-of-work solver worker;
    # 'wasm-unsafe-eval' lets Cap's WASM compile (served same-origin via /cap).
    header {
        Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; worker-src 'self'; child-src 'self' blob:"
        # COOP/CORP isolate the context; COEP require-corp is now ENFORCEABLE
        # (every subresource is same-origin — the Turnstile iframe that blocked it
        # is gone). Permissions-Policy denies features the app never uses.
        Cross-Origin-Opener-Policy "same-origin"
        Cross-Origin-Resource-Policy "same-origin"
        Cross-Origin-Embedder-Policy "require-corp"
        Permissions-Policy "accelerometer=(), browsing-topics=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        Strict-Transport-Security "max-age=31536000"
        Content-Security-Policy-Report-Only "require-trusted-types-for 'script'"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        -Server
    }
    # Integrity-Policy "blocked-destinations=(script)" stays DEFERRED. Every chunk
    # now carries SRI (entry/css in index.html + an import map covering all dynamic
    # chunks), but the enforcing header would block the PoP signing WORKER's module
    # imports (a worker realm doesn't inherit the document import map → no integrity
    # source → blocked → auth breaks). Flip only after an in-browser beta check.

    # API + health/readiness → Convex HTTP actions (:3211)
    @api path /api/* /healthz /readyz
    handle @api {
        reverse_proxy 127.0.0.1:3211 {
            header_up -CF-Connecting-IP   # strip client-spoofable header (A1)
        }
    }
    # Self-hosted Cap captcha (same-origin); strip the /cap prefix to match its routes.
    @cap path /cap/*
    handle @cap {
        uri strip_prefix /cap
        reverse_proxy 127.0.0.1:3000
    }
    # Never serve source maps publicly.
    @maps path *.map
    respond @maps 404
    # Everything else → the built SPA, with history-API fallback to index.html
    handle {
        root * /srv/freesocks/dist
        try_files {path} /index.html
        file_server
    }
}
# Lock the Convex dashboard + the Cap admin dashboard to your network / behind auth.
```

Build the SPA with the public actions origin baked in:
`VITE_CONVEX_SITE_URL=https://app.freesocks.org bun run build` (here `/api` is
same-origin, so the value only matters if you split the actions onto another host).
The build stamps sha384 `integrity` (SRI) on the entry script/style + the theme
script, AND emits an import map with an `integrity` section over every dynamic
chunk (+ a `dist/sri-manifest.json` for the OOB verifier) automatically (the Vite
`sriPlugin`); no operator action is needed.

## 8. Cutover verification checklist

- `GET /healthz` → `{ok:true}` (liveness); `GET /readyz` → 200 with a real DB ping (503 if
  Postgres is down); `GET /api/v1/config` → tiers + the Cap `{apiEndpoint, siteKey}`.
- Anonymous **get-account**: solve the Cap captcha → account created + account number revealed
  once (in the blocking save-it modal) + support ID; 2nd same-IP/day call is capped (429).
- **Account login** with that number → `fs_session` set → `/account` renders; a wrong
  number → generic 401, constant-time.
- **Rotate** → new number revealed once, old number dead.
- **Admin**: bootstrap wizard (zero credentials) → register passkey → authenticate →
  bootstrap locks; edit a tier and confirm it persists.
- **Cron**: a lapsed member moves active→grace→disabled on the schedule.
- **Backup**: `convex export` → `import --replace-all` round-trips into a fresh backend.

## Stop / reset

```sh
bun run selfhost:down                                       # stop containers (keeps fcp_data)
docker compose --env-file .env.docker down -v               # stop + wipe the fcp_data volume
```

## Backups

```sh
bunx convex export --path snapshot.zip
bunx convex import --replace-all snapshot.zip
```

> Pin the `:latest` image tags in `docker-compose.yml` to a specific `:<rev>`
> before any production use.
