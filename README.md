# FreeSocks Control Plane

[FreeSocks](https://freesocks.org) is a service that distributes free, open & uncensored
proxies to people in countries experiencing heavy Internet censorship. This is the
control plane: a **self-hosted [Convex](https://convex.dev) backend + a static Svelte 5
SPA** that hands out subscription URLs from one of two proxy backends —
[Remnawave](https://remna.st) (multi-protocol; shown to users as **"Xray"**) or
[Outline](https://getoutline.org/) (Shadowsocks access keys) — gates anonymous issuance
through [Cloudflare Turnstile](https://www.cloudflare.com/products/turnstile/), lets members
sign back in with a self-service **account number**, and provides a passkey-gated admin CMS
for tier, user, backend, token, and runtime-config management.

> **New here?** [`docs/project-inventory.md`](docs/project-inventory.md) is the at-a-glance
> map: every feature (live / deferred), the open to-dos, and a register of intentional
> scaffolding — read it before removing anything as "dead code".

> **Migration note.** This codebase was fully migrated off its previous Hono/Cloudflare-Workers
> stack. Drizzle/D1, the `PlatformAdapter` + per-platform entrypoints, the `KvStore`
> abstraction, Authentik OIDC, CiviCRM, and the wrangler/Fastly/Fly tooling are all gone —
> the backend is now entirely Convex functions. Trust the source under `convex/` and `src/`
> over any older description.

## Stack

### Backend — self-hosted Convex (`convex/`)

The entire backend is a Convex deployment: queries, mutations, and actions, plus an HTTP
router and native cron jobs. There is no separate web framework or edge worker.

- **[Convex](https://docs.convex.dev) 1.40** — reactive document DB + serverless functions, run **self-hosted** (Docker; SQLite or Postgres). Schema and validators are TypeScript (`v.*`), so there is no SQL and no migration set.
- **HTTP router** (`convex/http.ts`) — every public route is an `httpAction`, served on the Convex HTTP-actions port (`:3211`). This is the surface the SPA and API consumers call.
- **Native crons** (`convex/crons.ts`) — grace/disable sweep, tombstone sweep, Outline healthcheck, free-tier cleanup, session/rate-limit sweeps.
- **Proxy backends** — **Remnawave** and **Outline** behind a common action dispatch (`convex/backends.ts` + `convex/lib/backends/*`); per-tier backend selection plus optional end-user choice. See [`docs/backends.md`](docs/backends.md).
- **`@simplewebauthn/server`** for admin passkey auth (a `"use node"` action module).
- **`@aws-sdk/client-s3`** for optional multi-provider subscription mirroring (a `"use node"` action module).
- **TypeScript 6** strict throughout.

### Frontend — Svelte 5 SPA (`src/client/`)

- **Svelte 5** in runes mode (`$state`, `$derived`, `$effect`, `$props`) — no SvelteKit; a custom client-side router on the History API (`src/client/stores/router.svelte.ts`).
- **TanStack Svelte Query 6** for every data fetch and mutation, with a single `QueryClient` and an explicit `queryKeys` registry in `src/client/lib/queries.ts`.
- **A thin cookie-auth `apiClient`** (`src/client/lib/api.ts`, `credentials:'include'`) that calls the Convex HTTP surface and Zod-validates every response. The client does **not** use the Convex reactive client — authenticated data flows over the HTTP actions so the session cookie stays httpOnly.
- **shadcn-svelte** components copied as source into `src/client/components/ui/`, over **bits-ui** headless primitives.
- **Tailwind CSS 4** via `@tailwindcss/vite`; Inter / Inter Tight / JetBrains Mono bundled and self-hosted via `@fontsource/*` (no third-party font CDN).
- **`@simplewebauthn/browser`** for admin passkey ceremonies; **qrcode** for the subscription QR; **svelte-sonner** toasts; **mode-watcher** theming.

### Shared contracts (`src/shared/contracts/`)

Zod schemas the client uses for response parsing and types. Since the server now validates
with Convex `v.*` validators, these are client-side, but they remain the declared shape of
the API surface — keep the client and the Convex HTTP handlers in agreement.

### Tooling

- **Bun 1.3.14** as the package manager and CLI launcher (`bun.lock` is the only lockfile). The Convex backend runs on Convex's own V8 runtime.
- **Vite 8** builds the SPA (the only build artifact — the backend is `convex/`).
- **Vitest 4** with **`convex-test`** for an in-memory Convex test harness (no backend needed).
- **svelte-check** alongside `tsc -b` in the typecheck pipeline; **ESLint 10** + **Prettier 3**.

## Project layout

```
convex/                            The backend (Convex functions)
├── schema.ts                      defineSchema tables + indexes (no SQL/migrations)
├── http.ts                        httpRouter — every public route as an httpAction
├── crons.ts                       native scheduled jobs
├── seed.ts                        idempotent cutover seed (default tiers + settings)
├── freeTier.ts                    Turnstile-gated anon issuance + serializable cap
├── account.ts                     getAccountView / regenerate / switchBackend / refresh
├── auth.ts, accountId.ts          account-number login / rotate / mint
├── lifecycle.ts                   setMembership seam + grace/disable + cleanup sweeps
├── backends.ts                    proxy-backend dispatch (action)
├── outlineServers.ts             Outline server pool (DB half) + healthcheck
├── webauthn.ts                    admin passkey ceremonies + bootstrap ("use node")
├── apiTokens.ts                   fsv1_ token mint/resolve
├── webhooks.ts                    generic billing webhook (HMAC + dedupe)
├── storage.ts                     S3 subscription mirrors ("use node")
├── subscriptions.ts, tiers.ts, users.ts, admins.ts, appSettings.ts,
│   publicConfig.ts, audit.ts, rateLimits.ts, sessions.ts, adminApi.ts
└── lib/
    ├── http.ts                    error envelope, client-IP, resolveMember/Admin/Bearer
    ├── cookies.ts, crypto.ts, accountId.ts, turnstile.ts, issuance.ts
    └── backends/{types,remnawave,outline}.ts   pure HTTP backend fns

src/
├── client/                        Svelte 5 SPA (Vite, shadcn-svelte)
│   ├── App.svelte, main.ts        Root: QueryClientProvider, router switch
│   ├── routes/                    Home, GetKey, Account, Login + admin/*
│   ├── components/                ui/ (shadcn primitives), AppHeader, SubscriptionHero, …
│   ├── lib/                       api.ts (fetch + Zod), queries.ts, query-client.ts, utils.ts
│   └── stores/router.svelte.ts    History-API router
└── shared/contracts/              Zod contracts the client parses responses with

self-hosted/                       docker-compose + .env for the Convex backend + dashboard
```

## Prerequisites

- **Bun ≥ 1.3** (`brew install oven-sh/bun/bun` or `curl -fsSL https://bun.sh/install | bash`).
- **Docker** (Compose v2) for the self-hosted Convex backend.

## Quick start (local)

```bash
bun install
bun run selfhost:up      # start the self-hosted Convex backend + dashboard (Docker)
bun run selfhost:env     # generate an admin key + write .env.local for the CLI
bun run dev              # runs `convex dev` (pushes convex/) + `vite` (the SPA) together
```

`bun run dev` runs Convex in watch mode (pushing `convex/` and regenerating
`convex/_generated`) alongside the Vite SPA dev server. The SPA's same-origin `/api/*`
fetches are proxied by Vite to the Convex HTTP-actions port (`vite.config.ts`).

Set Convex **deployment** env vars with `bunx convex env set NAME value` (these are
separate from the SPA's build-time `VITE_*`). The full required/optional list is in
[`docs/convex-self-hosting.md §5`](docs/convex-self-hosting.md). To seed default tiers +
settings: `bunx convex run seed:seedCutover '{}'`.

See **[`docs/convex-self-hosting.md`](docs/convex-self-hosting.md)** for the complete
self-hosting walkthrough.

## Deploy

The two halves ship independently to a self-hosted Convex deployment. The tag-triggered
`.github/workflows/deploy.yml` does both:

```bash
# Backend — typecheck + push convex/ functions, schema, HTTP router, crons
CONVEX_SELF_HOSTED_URL=... CONVEX_SELF_HOSTED_ADMIN_KEY=... bunx convex deploy -y

# SPA — static build; a reverse proxy serves dist/ and routes /api -> the actions origin
VITE_CONVEX_SITE_URL=https://app.freesocks.org bun run build
```

Convex does **not** serve the SPA — a reverse proxy (Caddy/nginx/…) terminates TLS, serves
the static `dist/` with history-API fallback, and routes `/api/*` + `/healthz` to the
Convex HTTP-actions origin. The full cutover runbook (stand up, set env, seed, bootstrap the
first admin passkey, reverse-proxy config, verification checklist) is in
**[`docs/convex-self-hosting.md`](docs/convex-self-hosting.md)**.

## Architecture

Highlights:

- **Anonymous flow**: `POST /api/v1/subscription` — Turnstile-gated, no email. The
  per-(IP, day) cap is a **serializable Convex mutation** (`freeTier.claimFreeSlot`), so
  concurrent bursts can't over-issue. Each first issuance mints a one-time **account number**
  returned in the response; a per-(IP, day) reissue hands back the existing key.
- **Member flow**: the account number is the only credential. `POST /api/v1/auth/account-login`
  (Turnstile + strict per-prefix/per-IP rate limits + constant-time) sets the signed
  `fs_session` cookie; the member can **rotate** it (`/api/v1/account/account-id/rotate`)
  and **regenerate** or **switch backend** for their key. There is no OIDC.
- **Entitlements**: `tiers` drive limits; `lifecycle.setMembership` is the single seam that
  sets a user's tier + expiry. Today it's driven by admin edits and the **billing webhook**
  (`POST /api/webhooks/billing`, HMAC-verified + deduped) — the future in-house billing
  portal plugs in here. A cron sweep moves lapsed members `active → grace → disabled`.
- **Admin CMS**: passkey-only auth (first-run bootstrap wizard, then WebAuthn), separate
  from member sessions. Tiers, users (search, disable, reset-traffic, resync), API tokens
  (create / reveal-once / revoke), Outline servers (CRUD + test-connection), settings, and
  the audit log.
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

- **Public / member:** `GET /healthz`, `GET /api/v1/config`, `GET|POST /api/v1/subscription`,
  `POST /api/v1/auth/account-login`, `POST /api/v1/auth/logout`, `GET /api/v1/me`,
  `GET /api/v1/account`, `POST /api/v1/account/{regenerate,switch-backend,refresh-membership}`,
  `POST /api/v1/account/account-id/rotate`.
- **Admin (cookie or `admin:*`-scoped token):** `GET|POST|PATCH|DELETE /api/v1/admin/{tiers,users,tokens,audit,settings,outline-servers}/*`.
- **Plumbing:** `GET|POST /api/admin/auth/*` (WebAuthn passkey ceremonies + bootstrap),
  `POST /api/webhooks/billing` (HMAC inbound).

### Authentication paths

Three accepted mechanisms; each `httpAction` resolves identity via `convex/lib/http.ts`:

| Path                | Format                                              | Used by                       |
| ------------------- | --------------------------------------------------- | ----------------------------- |
| Member cookie       | `Cookie: fs_session=…`                              | Web SPA (account-number login) |
| Admin cookie        | `Cookie: fs_admin_session=…`                        | Admin CMS (WebAuthn passkey)   |
| Bearer token        | `Authorization: Bearer fsv1_<random>`               | Services, automation, monitoring |

A `fsv1_` token can be a **service** token (acts with its own scopes) or a **user** token
(`subjectType: user`, acts as a specific member). There is **no OIDC / JWT path**.

### Admin-issued API tokens

Admins mint tokens through the admin CMS at `/admin/tokens`. The plaintext is shown **once**
on creation and never recoverable thereafter — only `SHA-256(token)` is stored. Tokens have
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
`@fontsource/*` (imported in `src/client/main.ts`) — the page never contacts
`fonts.googleapis.com` / `fonts.gstatic.com` or any third-party host, a deliberate privacy /
censorship-resistance choice. The only sanctioned third-party script is Cloudflare Turnstile.
Apply `tabular-nums` to counters, file sizes, dates, and any number that re-renders.

### Router

`src/client/stores/router.svelte.ts` is a History-API router exposing a reactive
`router.pathname` rune; route resolution is an `{#if}` cascade in `App.svelte`. To add a
route: import the component, add an arm, and link via `<Link href="/foo">`. There is no
file-based routing because SvelteKit is not in the stack.

## License

Same as upstream.
