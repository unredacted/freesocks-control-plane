# Self-hosting Convex (FreeSocks Control Plane)

The control plane runs entirely on a **self-hosted Convex backend** (the
`convex/` functions + HTTP router) plus a static Svelte SPA. The previous
Hono/Cloudflare-Workers stack has been removed. See **§6** for the fresh-deploy
cutover runbook and **§7** for the reverse proxy that serves the SPA.

## Prerequisites

- Docker (Compose v2)
- `bun install` installs the `convex` CLI

## 1. Configure the backend

```sh
cp self-hosted/.env.example self-hosted/.env
openssl rand -hex 32          # paste the result into INSTANCE_SECRET in self-hosted/.env
```

## 2. Start the backend + dashboard

```sh
bun run selfhost:up
```

- Backend API → http://127.0.0.1:3210
- HTTP actions → http://127.0.0.1:3211
- Dashboard → http://localhost:6791

Data persists in the `data` Docker volume (SQLite). Set `POSTGRES_URL` in
`self-hosted/.env` to move to Postgres when single-box write throughput is
outgrown.

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

| Var                                         | Used by                                                                                                                                                                               |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SESSION_SIGNING_KEY`                       | member `fs_session` cookie HMAC: `openssl rand -hex 32`                                                                                                                               |
| `ADMIN_SESSION_SIGNING_KEY`                 | admin `fs_admin_session` cookie HMAC: `openssl rand -hex 32`                                                                                                                          |
| `ADMIN_BOOTSTRAP_SECRET`                    | first-run admin passkey bootstrap gate: `openssl rand -hex 32`                                                                                                                        |
| `IP_HASH_SALT`                              | HMAC salt for free-tier IP keying + login rate-limit: `openssl rand -hex 32`                                                                                                          |
| `ACCOUNT_ID_PEPPER`                         | keyed-hash pepper for account numbers (a leaked hash column is useless without it): `openssl rand -hex 32`. **Set once before launch; changing it invalidates every account number.** |
| `TURNSTILE_SECRET_KEY`                      | Turnstile siteverify (free issuance + account login)                                                                                                                                  |
| `WEBAUTHN_RP_ID`                            | passkey RP id = the bare domain (e.g. `freesocks.org`)                                                                                                                                |
| `WEBAUTHN_ORIGIN`                           | allowed page origin(s), comma-separated (e.g. `https://app.freesocks.org`)                                                                                                            |
| `REMNAWAVE_BASE_URL`, `REMNAWAVE_API_TOKEN` | Remnawave ("Xray") backend actions                                                                                                                                                    |

**Optional / feature-gated:**

| Var                                                                                                                                   | Default           | Used by                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------ |
| `ENVIRONMENT`                                                                                                                         | `production`      | set to `development` ONLY for local http (drops the cookie `Secure` flag)                        |
| `WEBAUTHN_RP_NAME`                                                                                                                    | `FreeSocks Admin` | passkey display name                                                                             |
| `TURNSTILE_SITE_KEY`                                                                                                                  | none              | echoed to the SPA via `/api/v1/config` so it renders the widget                                  |
| `TRUSTED_PROXY`                                                                                                                       | unset             | set `true` ONLY behind a reverse proxy that overwrites `X-Forwarded-For` (fail-closed client-IP) |
| `FREE_TIER_DAILY_CAP`                                                                                                                 | `1`               | per-IP/day free-key cap                                                                          |
| `FREE_TIER_EXPIRY_DAYS`                                                                                                               | `90`              | free-user cleanup window                                                                         |
| `WEBHOOK_SIGNING_SECRET`                                                                                                              | none              | HMAC for `POST /api/webhooks/billing` (the billing seam)                                         |
| `MEMBERS_JOIN_URL`, `MEMBERS_ACCOUNT_URL`                                                                                             | none              | optional member-portal links surfaced in `/api/v1/config`                                        |
| `S3_MIRRORS_ENABLED`, `S3_PROVIDER_COUNT`, `S3_PROVIDER_<i>_{NAME,ENDPOINT,BUCKET,PUBLIC_URL,REGION,ACCESS_KEY_ID,SECRET_ACCESS_KEY}` | off               | S3 subscription mirrors, one block per mirror; count `0`/unset disables                          |

The SPA build reads `VITE_CONVEX_SITE_URL` (the public HTTP-actions origin that
`/api` is proxied to). Outline server `apiUrl`s live per-row in the
`outlineServers` table (admin CMS), never in env.

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
   Outline Servers (the `apiUrl` secret is stored server-side, never echoed back).
5. **Bootstrap the first admin passkey**: open `/admin` in a browser; the wizard
   appears while `passkeyCredentials` is empty. Paste `ADMIN_BOOTSTRAP_SECRET`,
   register a passkey. Bootstrap **locks forever** once any credential exists.
6. **Issue `fsv1_` service tokens** (if any external callers): admin CMS → API Tokens.
7. **Verify** (§8), then point DNS at the reverse proxy and decommission the old stack.

## 7. Reverse proxy

Convex does **not** serve your SPA. A reverse proxy terminates TLS, serves the
static `vite build` output, and routes the API surface to the HTTP-actions port.
Example `Caddyfile` (the SPA's `apiClient` calls same-origin `/api/*` + `/healthz`):

```caddy
app.freesocks.org {
    encode gzip
    # API + health → Convex HTTP actions (:3211)
    @api path /api/* /healthz
    handle @api {
        reverse_proxy 127.0.0.1:3211
    }
    # Everything else → the built SPA, with history-API fallback to index.html
    handle {
        root * /srv/freesocks/dist
        try_files {path} /index.html
        file_server
    }
}
# Lock the Convex dashboard to your network / behind auth, separately.
```

Build the SPA with the public actions origin baked in:
`VITE_CONVEX_SITE_URL=https://app.freesocks.org bun run build` (here `/api` is
same-origin, so the value only matters if you split the actions onto another host).

## 8. Cutover verification checklist

- `GET /healthz` → `{ok:true}`; `GET /api/v1/config` → tiers + Turnstile site key.
- Anonymous **get-key**: solve Turnstile → key issued + account number revealed once;
  2nd same-IP/day call is capped (`accountIdAvailable:false`).
- **Account login** with that number → `fs_session` set → `/account` renders; a wrong
  number → generic 401, constant-time.
- **Rotate** → new number revealed once, old number dead.
- **Admin**: bootstrap wizard (zero credentials) → register passkey → authenticate →
  bootstrap locks; edit a tier and confirm it persists.
- **Cron**: a lapsed member moves active→grace→disabled on the schedule.
- **Backup**: `convex export` → `import --replace-all` round-trips into a fresh backend.

## Stop / reset

```sh
bun run selfhost:down                                           # stop containers
docker compose -f self-hosted/docker-compose.yml down -v        # stop + wipe the data volume
```

## Backups

```sh
bunx convex export --path snapshot.zip
bunx convex import --replace-all snapshot.zip
```

> Pin the `:latest` image tags in `self-hosted/docker-compose.yml` to a specific
> `:<rev>` before any production use.
