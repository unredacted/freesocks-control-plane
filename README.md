# FreeSocks Control Plane

[FreeSocks](https://freesocks.org) is a service that distributes free, open & uncensored
proxies to people in countries experiencing heavy Internet censorship. This is the
control plane: a **self-hosted [Convex](https://convex.dev) backend + a static Svelte 5
SPA** that hands out subscription URLs from one of two proxy backends,
[Remnawave](https://remna.st) (multi-protocol; shown to users as **"Xray"**) or
[Outline](https://getoutline.org/) (Shadowsocks access keys). It gates anonymous issuance
through a self-hosted [Cap](https://trycap.dev) proof-of-work captcha (no third-party scripts), lets members
sign back in with a self-service **account number**, and provides a passkey-gated admin CMS
for tier, user, backend, token, and runtime-config management.

> **New here?** [`docs/project-inventory.md`](docs/project-inventory.md) is the at-a-glance
> map: every feature (live / deferred), the open to-dos, and a register of intentional
> scaffolding. Read it before removing anything as "dead code".

> **Migration note.** This codebase was fully migrated off its previous Hono/Cloudflare-Workers
> stack. Drizzle/D1, the `PlatformAdapter` + per-platform entrypoints, the `KvStore`
> abstraction, Authentik OIDC, CiviCRM, and the wrangler/Fastly/Fly tooling are all gone.
> The backend is now entirely Convex functions. Trust the source under `convex/` and `src/`
> over any older description.

## Stack

### Backend: self-hosted Convex (`convex/`)

The entire backend is a Convex deployment: queries, mutations, and actions, plus an HTTP
router and native cron jobs. There is no separate web framework or edge worker.

- **[Convex](https://docs.convex.dev) 1.40**: reactive document DB + serverless functions, run **self-hosted** (Docker; SQLite or Postgres). Schema and validators are TypeScript (`v.*`), so there is no SQL and no migration set.
- **HTTP router** (`convex/http.ts`): every public route is an `httpAction`, served on the Convex HTTP-actions port (`:3211`). This is the surface the SPA and API consumers call.
- **Native crons** (`convex/crons.ts`): grace/disable sweep, tombstone sweep, backend healthcheck, free-tier cleanup, session/rate-limit/replay-guard + admin-invite sweeps, HPKE epoch-key rotation, append-only-table retention sweeps, billing pending/gift-reveal sweeps, and S3 mirror refresh.
- **Self-hosted [Cap](https://trycap.dev) captcha** (the `cap` + `valkey` services in the **beta** compose stack, `docker-compose.beta.yml`; the base dev `docker-compose.yml` is backend + dashboard only — local dev uses `CAP_DEV_BYPASS=true`) gates anonymous account creation + login; verified server-side in `convex/lib/captcha.ts`. The widget + its proof-of-work WASM are bundled and served same-origin — no third-party scripts.
- **Proxy backends**: **Remnawave** and **Outline** behind a common action dispatch (`convex/backends.ts` + `convex/lib/backends/*`); per-tier backend selection plus optional end-user choice. See [`docs/backends.md`](docs/backends.md).
- **`@simplewebauthn/server`** for admin passkey auth (a `"use node"` action module).
- **`@aws-sdk/client-s3`** for optional multi-provider subscription mirroring (a `"use node"` action module).
- **TypeScript 6** strict throughout.

### Frontend: Svelte 5 SPA (`src/client/`)

- **Svelte 5** in runes mode (`$state`, `$derived`, `$effect`, `$props`); no SvelteKit, just a custom client-side router on the History API (`src/client/stores/router.svelte.ts`).
- **TanStack Svelte Query 6** for every data fetch and mutation, with a single `QueryClient` and an explicit `queryKeys` registry in `src/client/lib/queries.ts`.
- **A thin cookie-auth `apiClient`** (`src/client/lib/api.ts`, `credentials:'include'`) that calls the Convex HTTP surface and Zod-validates every response. The client does **not** use the Convex reactive client; authenticated data flows over the HTTP actions so the session cookie stays httpOnly.
- **shadcn-svelte** components copied as source into `src/client/components/ui/`, over **bits-ui** headless primitives.
- **Tailwind CSS 4** via `@tailwindcss/vite`; Inter / Inter Tight / JetBrains Mono bundled and self-hosted via `@fontsource/*` (no third-party font CDN).
- **`@simplewebauthn/browser`** for admin passkey ceremonies; **qrcode** for the subscription QR; **svelte-sonner** toasts; **mode-watcher** theming; **`@cap.js/widget`** (bundled) for the captcha.
- **i18n** uses Paraglide/inlang (`messages/*.json` is the authoritative source, compiled to typed messages; `t()` in `src/client/lib/i18n/` shims over them): English + Farsi, Arabic, Russian, Simplified Chinese, with RTL driven off `<html dir>` and a persisted language switcher. The critical user-journey strings are translated; marketing copy + a native-speaker review pass are tracked follow-ups.

### Shared contracts (`src/shared/contracts/`)

Zod schemas the client uses for response parsing and types. Since the server now validates
with Convex `v.*` validators, these are client-side, but they remain the declared shape of
the API surface. Keep the client and the Convex HTTP handlers in agreement.

### Tooling

- **Bun 1.3.14** as the package manager and CLI launcher (`bun.lock` is the only lockfile). The Convex backend runs on Convex's own V8 runtime.
- **Vite 8** builds the SPA (the only build artifact; the backend is `convex/`).
- **Vitest 4** with **`convex-test`** for an in-memory Convex test harness (no backend needed).
- **svelte-check** alongside `tsc -b` in the typecheck pipeline; **ESLint 10** + **Prettier 3**.

## Project layout

```
convex/                            The backend (Convex functions)
├── schema.ts                      defineSchema tables + indexes (no SQL/migrations)
├── http.ts                        httpRouter: every public route as an httpAction
├── crons.ts                       native scheduled jobs
├── seed.ts                        idempotent cutover seed (default tiers + settings)
├── freeTier.ts                    Cap-gated anon account creation + serializable cap
├── account.ts                     getAccountView / regenerate / switchBackend / refresh
├── auth.ts, accountId.ts          account-number login / rotate / mint
├── supportId.ts                   non-secret FS-XXXX-XXXX support handle (mint/lookup)
├── membershipCodes.ts             admin-minted redemption codes; member redeem (single-use)
├── lifecycle.ts                   setMembership seam + grace/disable + cleanup sweeps
├── backends.ts                    proxy-backend dispatch (action)
├── backendServers.ts              generic backend-instance pool (DB half) + healthcheck
├── webauthn.ts                    admin passkey ceremonies + bootstrap ("use node")
├── apiTokens.ts                   fsv1_ token mint/resolve (scoped)
├── webhooks.ts                    generic billing webhook (HMAC + dedupe)
├── storage.ts                     S3 subscription mirrors ("use node")
├── retention.ts                   daily append-only-table retention sweeps
├── health.ts                      /readyz deep readiness (DB ping)
├── subscriptions.ts, tiers.ts, users.ts, admins.ts, appSettings.ts,
│   publicConfig.ts, audit.ts, rateLimits.ts, sessions.ts, adminApi.ts
└── lib/
    ├── http.ts                    error envelope, client-IP, resolveMember/Admin/Bearer (scoped)
    ├── cookies.ts, crypto.ts, accountId.ts, supportId.ts, captcha.ts,
    │   membershipCode.ts, rateLimitPolicy.ts, issuance.ts
    └── backends/{types,registry,remnawave,outline}.ts   pure HTTP backend fns

src/
├── client/                        Svelte 5 SPA (Vite, shadcn-svelte)
│   ├── App.svelte, main.ts        Root: QueryClientProvider, router switch
│   ├── routes/                    Home, GetAccount, Account, Login + admin/*
│   ├── components/                ui/ (shadcn primitives), AppHeader, SubscriptionHero, …
│   ├── lib/                       api.ts (fetch + Zod), queries.ts, query-client.ts, utils.ts
│   └── stores/router.svelte.ts    History-API router
└── shared/contracts/              Zod contracts the client parses responses with

docker-compose.yml                 self-hosted Convex backend + dashboard (compose project "fcp")
.env.docker.example                docker env template (copy to .env.docker)
verifier-extension/                MV3 bundle-verifier scaffold (CDN-blinding Phase 4)
```

## Prerequisites

- **Bun ≥ 1.3** (`brew install oven-sh/bun/bun` or `curl -fsSL https://bun.sh/install | bash`).
- **Docker** (Compose v2) for the self-hosted Convex backend.

## Quick start (local, via Docker)

The self-hosted Convex backend runs from the root `docker-compose.yml` (Compose
project **`fcp`**). Its config lives in **`.env.docker`** (deliberately separate
from `.env` / `.env.local`, which Vite and the Convex CLI load).

```bash
# 1. Docker backend config. Defaults are fine for throwaway local dev; set a real
#    INSTANCE_SECRET (openssl rand -hex 32) for any persistent instance.
cp .env.docker.example .env.docker

# 2. Install deps, then start the backend + dashboard (Docker).
bun install
bun run selfhost:up        # starts fcp-backend-1 + fcp-dashboard-1
bun run selfhost:env       # reads an admin key from the backend -> writes .env.local

# 3. Deploy convex/ and run the SPA together (watch mode).
bun run dev                # `convex dev` (pushes convex/) + `vite` (the SPA)

# 4. Seed default tiers + settings (idempotent).
bunx convex run seed:seedCutover '{}'
```

Then:

- **SPA** → http://localhost:5173 · **Convex dashboard** → http://localhost:6791
- Backend API `:3210`, HTTP actions `:3211`; Vite proxies the SPA's same-origin
  `/api/*` to `:3211` (`vite.config.ts`).

> **The Docker backend is a separate process from `bun run dev`.** `bun run dev`
> only starts the SPA + the Convex CLI watch; the backend is `bun run selfhost:up`
> and must stay running (it now auto-restarts with Docker via `restart:
unless-stopped`, but a `down` removes it). If API calls fail with
> "TypeError: Failed to fetch", the backend is down: `bun run selfhost:up`.

Set Convex **deployment** env vars with `bunx convex env set NAME value` (separate
from the SPA's build-time `VITE_*`); the full required/optional list is in
[`docs/convex-self-hosting.md §5`](docs/convex-self-hosting.md). Reset the backend
to a clean slate with `docker compose --env-file .env.docker down -v` (wipes the
`fcp_data` volume).

To exercise the CDN-blinding sealed channel locally (user-facing label: **"HPKE"**;
code identifiers remain `e2ee`), also generate its keys
(`bun scripts/gen-e2ee-keys.mjs`), `bunx convex env set` the printed `FS_*` secrets,
and append the printed `VITE_FS_*` public vars to `.env.local`. See
[`docs/threat-model-cdn-blinding.md`](docs/threat-model-cdn-blinding.md).

See **[`docs/convex-self-hosting.md`](docs/convex-self-hosting.md)** for the complete
self-hosting walkthrough and the production cutover runbook.

## Deploy

The two halves ship independently to a self-hosted Convex deployment, **deployed
manually** (CI runs checks only — there is no auto-deploy workflow; the beta
docker-compose stack's `deployer` service runs `convex deploy` on `up`):

```bash
# Backend: typecheck + push convex/ functions, schema, HTTP router, crons
CONVEX_SELF_HOSTED_URL=... CONVEX_SELF_HOSTED_ADMIN_KEY=... bunx convex deploy -y

# SPA: static build; a reverse proxy serves dist/ and routes /api -> the actions origin
VITE_CONVEX_SITE_URL=https://app.freesocks.org bun run build
```

Convex does **not** serve the SPA. A reverse proxy (Caddy/nginx/…) terminates TLS, serves
the static `dist/` with history-API fallback, and routes `/api/*` + `/healthz` to the
Convex HTTP-actions origin. The full cutover runbook (stand up, set env, seed, bootstrap the
first admin passkey, reverse-proxy config, verification checklist) is in
**[`docs/convex-self-hosting.md`](docs/convex-self-hosting.md)**.

## Architecture

Highlights:

- **Anonymous flow**: `POST /api/v1/account`, Cap-captcha-gated, no email. Account creation is
  **decoupled from proxy issuance** (so a backend outage can't block sign-up): it mints the
  one-time **account number** (revealed via a blocking save-it modal) + a non-secret **support
  ID** + a member session. The per-(IP, day) cap is a **serializable Convex mutation**
  (`freeTier.claimFreeSlot`, cap from the admin-tunable `freetier.create` policy), so concurrent
  bursts can't over-issue. The proxy key is created separately by the signed-in member.
- **Member flow**: the account number is the only credential. `POST /api/v1/auth/account-login`
  (Cap + strict per-IP/per-(prefix,IP) rate limits + constant-time) sets the signed
  `fs_session` cookie; the member can **rotate** it (`/api/v1/account/account-id/rotate`),
  **regenerate** or **switch backend** for their key, and **redeem a membership code**
  (`/api/v1/account/redeem-code`). There is no OIDC.
- **Entitlements**: `tiers` drive limits; `lifecycle.setMembership` is the single seam that
  sets a user's tier + expiry. Driven by admin edits, **admin-minted redemption codes** a
  member redeems (the day-1 paid path), and the **billing webhook** (`POST /api/webhooks/billing`,
  HMAC-verified + deduped) for the future portal. A cron sweep moves lapsed members
  `active → grace → disabled`.
- **Admin CMS**: passkey-only auth (first-run bootstrap wizard, then WebAuthn), separate
  from member sessions. A landing **dashboard** (health + a shared `GET /admin/status`); tiers
  (CRUD + **duplicate**); users (search by support ID / prefix; disable / **re-enable** /
  reset-traffic / resync / **grant membership**; paginated); **admins** (invite links +
  deactivate/reactivate + per-passkey revoke, under a last-admin guard); API tokens (create /
  reveal-once / revoke); backend servers (CRUD + test-connection); **billing** (per-rail config
  - a readiness check); **storage** mirrors; **rate-limit policies**; **membership codes**; an
    admin-configurable **theme**; settings; and a filterable **audit log**. The Ansible role drives
    a subset over idempotent **by-slug / by-name** routes using an **automation token**.
- **Subscription delivery**: the issuance saga (`convex/lib/issuance.ts`) creates the
  backend user, optionally mirrors the content to N S3 providers
  ([`@aws-sdk/client-s3`](https://www.npmjs.com/package/@aws-sdk/client-s3)), and persists
  the row. Re-issue/switch tombstone the old key with a 24h grace window before the cron
  hard-deletes it.
- **Proxy backends**: Remnawave and Outline run side-by-side behind a single action
  dispatch (`convex/backends.ts`). A tier is bound to one backend; admins can run a
  Remnawave free tier alongside an Outline free tier, or expose backend choice to end users
  via `subscription.user_choice_enabled`. See [`docs/backends.md`](docs/backends.md) and
  [`docs/outline-setup.md`](docs/outline-setup.md).
- **Runtime config**: the `appSettings` table backs admin-toggleable flags (backend
  enable/disable, default backend, user-choice gate, backend labels, Outline scoring
  weights). Defaults are compiled in (`convex/appSettings.ts`).

## API consumers (services, integrations)

### Endpoints (served by `convex/http.ts`)

- **Public / member:** `GET /healthz` (liveness), `GET /readyz` (deep readiness),
  `GET /api/v1/config`, `GET /api/v1/e2ee/keys` (HPKE epoch keys + revocations),
  `POST /api/v1/account` (create), `GET /api/v1/account`,
  `POST /api/v1/auth/account-login`, `POST /api/v1/auth/logout`, `GET /api/v1/me`,
  `POST /api/v1/account/{regenerate,switch-backend,refresh-membership,redeem-code}`,
  `POST /api/v1/account/account-id/rotate`, `POST /api/v1/account/devices/revoke`,
  `GET /api/v1/subscription/content` (sealed raw-config reveal),
  `POST /api/v1/mirror/request` + `GET /api/v1/mirror` (opt-in S3 mirror),
  `POST /api/v1/billing/checkout` + `GET /api/v1/billing/order/*` (self-service membership),
  `POST /api/v1/account/gift-codes/ack` + `GET /api/v1/account/codes` (gift purchases).
- **Admin (cookie or scope-checked token):** `GET|POST|PATCH|DELETE /api/v1/admin/{status,tiers,users,admins,tokens,audit,settings,rate-limits,membership-codes,backend-servers,billing,mirror-providers,theme,verification}/*` — every route enforces a scope on token callers (several features share the broader `admin:settings:*` / `admin:users:*` scopes rather than one scope per feature); the Ansible role's idempotent `by-slug` / `by-name` upserts live under these.
- **Plumbing:** `GET|POST /api/admin/auth/*` (WebAuthn passkey ceremonies + bootstrap),
  `POST /api/webhooks/billing` (generic HMAC inbound), and the processor webhooks
  `POST /api/webhooks/{nowpayments,stripe,paypal}`.

### Authentication paths

Three accepted mechanisms; each `httpAction` resolves identity via `convex/lib/http.ts`:

| Path          | Format                                | Used by                          |
| ------------- | ------------------------------------- | -------------------------------- |
| Member cookie | `Cookie: fs_session=…`                | Web SPA (account-number login)   |
| Admin cookie  | `Cookie: fs_admin_session=…`          | Admin CMS (WebAuthn passkey)     |
| Bearer token  | `Authorization: Bearer fsv1_<random>` | Services, automation, monitoring |

A `fsv1_` token can be a **service** token (acts with its own scopes) or a **user** token
(`subjectType: user`, acts as a specific member). There is **no OIDC / JWT path**.

### Admin-issued API tokens

Admins mint tokens through the admin CMS at `/admin/tokens`. The plaintext is shown **once**
on creation and never recoverable thereafter; only `SHA-256(token)` is stored. Tokens have
a name, an explicit scope set (vocabulary in `src/shared/contracts/scopes.ts`, e.g.
`subscription:read`, `admin:users:write`), optional expiry, debounced last-used tracking,
and soft-revoke.

## Testing

```bash
bun run test         # vitest + convex-test (in-memory; no running backend needed)
bun run typecheck    # tsc -b (client+shared) + tsc on convex/ + svelte-check
bun run lint         # eslint + prettier --check
bun run build        # tsc -b + vite build → static SPA in dist/
```

## Frontend conventions

### Data fetching: TanStack Query only

Every fetch goes through a factory in `src/client/lib/queries.ts` that wraps `createQuery`
or `createInfiniteQuery`, calling the `apiClient` (`src/client/lib/api.ts`), which
Zod-validates the response. Cache keys are exported via the `queryKeys` registry so
mutations can `queryClient.invalidateQueries({ queryKey: queryKeys.X })`. Avoid direct
`fetch()` from components; add a query factory instead. User feedback goes through
`svelte-sonner`. Reference pattern: `Account.svelte`'s regenerate / rotate / refresh
mutations.

### Component conventions

- shadcn-svelte primitives are imported from `@client/components/ui/<name>`; the directory
  barrels re-export named members (`Card`, `CardHeader`, etc.).
- Layout: `AppHeader.svelte` + `App.svelte`'s footer wrap every non-admin route; admin
  routes use `AdminLayout.svelte` with its own sidebar.
- Loading states: `<Skeleton>` placeholders matching the loaded layout, not flat "Loading…"
  text. Destructive confirmations use shadcn-svelte `AlertDialog`, not `window.confirm()`.

### Typography

Inter (body) + Inter Tight (display) + JetBrains Mono (code), bundled and self-hosted via
`@fontsource/*` (imported in `src/client/main.ts`); the page never contacts
`fonts.googleapis.com` / `fonts.gstatic.com` or any third-party host, a deliberate privacy /
censorship-resistance choice. There are **no third-party runtime scripts at all** — the Cap
captcha widget + its proof-of-work WASM + pako are bundled and served same-origin.
Apply `tabular-nums` to counters, file sizes, dates, and any number that re-renders.

The control plane also never persists a client IP anywhere by default (app, Caddy, and Cap
are all configured for it); the end-to-end posture + a downstream-deployer checklist is in
[`docs/privacy.md`](docs/privacy.md).

### Router

`src/client/stores/router.svelte.ts` is a History-API router exposing a reactive
`router.pathname` rune; route resolution is an `{#if}` cascade in `App.svelte`. To add a
route: import the component, add an arm, and link via `<Link href="/foo">`. There is no
file-based routing because SvelteKit is not in the stack.

## License

Same as upstream.
