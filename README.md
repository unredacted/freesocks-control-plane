# FreeSocks Control Plane

[FreeSocks](https://freesocks.org) is a service that distributes free, open & uncensored
proxies to people in countries experiencing heavy Internet censorship. This is the
control-plane: a TypeScript app that hands out subscription URLs from one of two proxy
backends — [Remnawave](https://docs.rw) (Shadowsocks/VLESS/Trojan multi-protocol) or
[Outline](https://getoutline.org/) (Shadowsocks access keys) — gates members through
[Authentik](https://goauthentik.io/) OIDC fronting [CiviCRM](https://civicrm.org/)
membership at members.unredacted.org, and provides an admin CMS for tier, user,
backend, and runtime-config management.

> **New here?** [`docs/project-inventory.md`](docs/project-inventory.md) is the at-a-glance
> map: every feature (live / dormant / pending), the open to-dos, and a register of
> intentional scaffolding — read it before removing anything as "dead code".

## Stack

### Backend

- **TypeScript 6.0** strict, target ESNext
- **Hono 4** for HTTP routing with **`@hono/zod-openapi`** generating the spec from route definitions
- **Cloudflare Workers** (primary) with **Workers Static Assets** for the SPA bundle
- **Drizzle ORM** with **D1** (Workers) or **better-sqlite3** (Bun/Node self-host)
- **Workers KV** (Workers) or **SQLite-backed cache** (Bun/Node) — abstracted via a `KvStore` interface
- **Remnawave** and **Outline** proxy backends behind a single `ProxyBackendProvider` interface; per-tier backend selection plus optional end-user choice. See [`docs/backends.md`](docs/backends.md).
- **Cloudflare Email Sending** (default), **Resend**, or **AWS SES** via pluggable provider
- **`@aws-sdk/client-s3`** for multi-provider mirroring
- **`@simplewebauthn/server`** for admin passkey auth
- **`arctic`** + **`jose`** for Authentik OIDC (login + JWT bearer)
- **Zod 4** schemas at every entry, shared with the SPA via `src/shared/contracts/`

### Frontend (SPA in `src/client/`)

- **Svelte 5** in runes mode (`$state`, `$derived`, `$effect`, `$props`) — no SvelteKit; custom client-side router on the History API
- **TanStack Svelte Query 6** for every data fetch and mutation, with a single `QueryClient` mounted at the root and an explicit `queryKeys` registry in `src/client/lib/queries.ts`
- **shadcn-svelte** components, copied as source into `src/client/components/ui/` (Button, Card, Input, Dialog, AlertDialog, Sonner, Tooltip, Checkbox, Select, Skeleton, Collapsible, Badge, Label, Separator)
- **bits-ui** for headless primitives under the shadcn-svelte layer
- **Tailwind CSS 4** via `@tailwindcss/vite`, with Inter / Inter Tight / JetBrains Mono bundled and self-hosted via `@fontsource/*` (no third-party font CDN)
- **`@lucide/svelte`** + **lucide-svelte** for icons
- **svelte-sonner** for toast notifications, mounted globally via `<Toaster />`
- **mode-watcher** for light/dark/system theme syncing, persisted to localStorage
- **runed** for reactive utility runes
- **qrcode** for the QR code on the subscription hero
- **`@simplewebauthn/browser`** for admin passkey ceremonies

### Tooling

- **Bun 1.3.14** as the package manager, test runner driver, and CI runtime. Production runtime on Cloudflare Workers is V8-based — Bun is the dev/build/test layer.
- **Vite 8** with the Cloudflare Vite plugin for SPA + Worker dev/build
- **Vitest 4** with `@cloudflare/vitest-pool-workers` for Miniflare-backed integration tests
- **svelte-check** alongside `tsc -b` in the typecheck pipeline
- **ESLint 10** (minimal flat config — `tsc --strict` + `svelte-check` do the heavy lifting) and **Prettier 3** with `prettier-plugin-svelte`

## Project layout

```
src/
├── client/                       Svelte 5 SPA (Vite, shadcn-svelte)
│   ├── App.svelte                Root: QueryClientProvider, router switch, header/footer
│   ├── main.ts                   mount(App, …)
│   ├── app.d.ts                  Ambient types for Svelte runes + globals
│   ├── routes/                   Page-level components
│   │   ├── Home.svelte, GetKey.svelte, Account.svelte, AuthCallback.svelte
│   │   └── admin/                AdminEntry/Login/Bootstrap/Tiers/Users/Tokens/Audit + modals
│   ├── components/               Shared components
│   │   ├── ui/                   shadcn-svelte components (one folder per primitive)
│   │   ├── AppHeader.svelte, SubscriptionHero.svelte, TierComparison.svelte, etc.
│   │   ├── QrCode.svelte         Canvas-based QR encoder, theme-aware
│   │   └── ThemeToggle.svelte    light/dark/system cycler
│   ├── lib/
│   │   ├── api.ts                apiClient (fetch + Zod parse)
│   │   ├── queries.ts            TanStack Query factories + queryKeys registry
│   │   ├── query-client.ts       QueryClient singleton
│   │   └── utils.ts              cn(), formatBytes(), shadcn type helpers
│   ├── stores/
│   │   └── router.svelte.ts      Tiny History API router (~30 lines)
│   └── styles/globals.css        Tailwind 4 + theme tokens + font setup
├── server/                       Hono backend (platform-agnostic)
│   ├── routes/api/               HTTP route handlers (versioned at /api/v1/*)
│   ├── services/                 Business logic (membership-sync, free-tier, audit, ...)
│   ├── providers/                External integrations (Remnawave, CiviCRM, Authentik, email, S3, ...)
│   ├── platform/                 Cloudflare, Node, and Fastly platform adapters
│   ├── kv/                       KV interface + CF/SQLite implementations
│   ├── db/                       Drizzle schema + migrations
│   ├── lib/                      Shared utilities
│   └── jobs/                     Cron tasks
└── shared/                       Zod contracts shared frontend ↔ backend

src-entries/
├── workers.ts                    Cloudflare Workers entry { fetch, scheduled }
├── node.ts                       @hono/node-server entry
├── bun.ts                        Bun.serve entry
└── fastly.ts                     Fastly Compute entry (scaffolded)
```

## Prerequisites

- **Bun ≥ 1.3** (`brew install oven-sh/bun/bun` or `curl -fsSL https://bun.sh/install | bash`).
  Bun is the only required toolchain — install, scripts, and CI all use it. The production
  _runtime_ on Cloudflare Workers is V8-based (not Bun); Bun is the dev/build/test layer.

## Quick start (local, against Cloudflare Workers runtime)

```bash
bun install
bun run types                    # generates worker-configuration.d.ts from wrangler.dev.toml
cp wrangler.example.toml wrangler.toml   # only needed for production deploy
bun run dev                      # vite + cloudflare worker via Cloudflare Vite plugin
```

The dev server runs the Svelte SPA with HMR and runs the Hono backend in the Cloudflare
Workers runtime through the Cloudflare Vite plugin. D1 and KV are auto-provisioned by
Miniflare locally. TanStack Query DevTools mount automatically in dev (bottom-right
floating button) and tree-shake out of production builds.

Set local secrets in `.dev.vars` (gitignored). See `.dev.vars.example` for the full key list.

## Quick start (self-host on Bun)

For users who want to run the control plane outside of Cloudflare Workers (Fly.io,
Railway, a VPS, on-prem):

```bash
bun install
bun run build:prod               # builds the Svelte SPA into dist/client/
bun run db:migrate:local         # applies migrations against local SQLite
SQLITE_PATH=./data/freesocks.sqlite bun src-entries/bun.ts
```

The Bun entry runs the same Hono app + services on Bun's HTTP server, with `better-sqlite3`
backing D1's role and a SQLite-backed table backing KV. The `PlatformAdapter` interface
(`src/server/platform/interface.ts`) abstracts the runtime so all business logic stays
identical across Cloudflare Workers, Bun, and Node.

A Docker image (`Dockerfile`) is provided for the Bun deploy path; an example Fly.io
config (`fly.toml.example`) shows a working deployment shape.

## Deploy environments

The control plane has three configs, each in its own file:

| Config             | What it's for                                  | Files                                                                        |
| ------------------ | ---------------------------------------------- | ---------------------------------------------------------------------------- |
| **local dev**      | `vite dev` with Miniflare placeholders         | `wrangler.dev.toml` (committed) + `.dev.vars` (gitignored)                   |
| **beta / staging** | live Cloudflare deploy at `beta.freesocks.org` | `wrangler.beta.example.toml` (committed) → `wrangler.beta.toml` (gitignored) |
| **production**     | live Cloudflare deploy at `app.freesocks.org`  | `wrangler.example.toml` (committed) → `wrangler.toml` (gitignored)           |

Build and deploy commands are explicitly env-tagged so there's no doubt which
config is being shipped:

```bash
# Beta / staging
bun run types:beta
bun run db:migrate:beta
bun run build:beta
bun run deploy:beta

# Production
bun run types:prod
bun run db:migrate:prod
bun run build:prod
bun run deploy:prod
```

The Cloudflare Vite plugin embeds the chosen wrangler config into the build
output, so `build:beta` and `build:prod` produce different `dist/` contents —
running `deploy:beta` against a `build:prod` artifact would deploy the wrong
config. Always pair `build:<env>` with `deploy:<env>`.

### First-time production setup

```bash
# 1. Provision Cloudflare bindings
bunx wrangler d1 create freesocks-control-plane
bunx wrangler kv namespace create FS_SESSIONS_KV
bunx wrangler kv namespace create FS_CACHE_KV
bunx wrangler kv namespace create FS_RATELIMIT_KV

# 2. Real prod config
cp wrangler.example.toml wrangler.toml
# Edit: paste IDs, set REMNAWAVE_BASE_URL, AUTHENTIK_*, FREE_TIER_TURNSTILE_SITE_KEY, etc.

# 3. Set secrets directly via wrangler (npm-script stdin forwarding is unreliable)
SECRET=$(openssl rand -hex 32) && echo "$SECRET" && \
  echo -n "$SECRET" | bunx wrangler secret put SESSION_SIGNING_KEY --config wrangler.toml
# ...repeat for ADMIN_SESSION_SIGNING_KEY, ADMIN_BOOTSTRAP_SECRET, IP_HASH_SALT,
# TURNSTILE_SECRET_KEY, REMNAWAVE_API_TOKEN, AUTHENTIK_CLIENT_SECRET, CIVICRM_API_KEY

# 4. Apply schema and ship
bun run db:migrate:prod
bun run build:prod
bun run deploy:prod
```

### First-time beta setup

```bash
# 1. Provision separate beta bindings (do NOT share with prod)
bunx wrangler d1 create freesocks-control-plane-beta
bunx wrangler kv namespace create FS_SESSIONS_KV --env beta
bunx wrangler kv namespace create FS_CACHE_KV --env beta
bunx wrangler kv namespace create FS_RATELIMIT_KV --env beta

# 2. Real beta config
cp wrangler.beta.example.toml wrangler.beta.toml
# Edit: paste IDs, staging Authentik URLs, etc.

# 3. Secrets are per-worker; beta has its own
echo -n "$VALUE" | bunx wrangler secret put SESSION_SIGNING_KEY --config wrangler.beta.toml
# ...repeat the secret list

bun run db:migrate:beta
bun run build:beta
bun run deploy:beta
```

## Deploy targets

The control plane has three deployment paths:

| Target                                 | When to choose                                                                                       | Database            | Cron                                               | Email                    |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------- | -------------------------------------------------- | ------------------------ |
| **Cloudflare Workers** _(recommended)_ | Default. Best edge latency, native bindings, the path this repo's CI runs against.                   | D1                  | native triggers                                    | Cloudflare Email Sending |
| **Bun self-host**                      | Single-vendor concern, full data ownership, container-host friendly (Fly.io, Railway, VPS).          | better-sqlite3 file | `node-cron`                                        | Resend or SES            |
| **Fastly Compute** _(scaffolded)_      | Already invested in Fastly's edge, compliance reasons against Cloudflare. Beta — no CI coverage yet. | Turso (libSQL)      | external scheduler → `/api/internal/cron/run-task` | Resend or SES            |

The codebase abstracts all three via `PlatformAdapter` — business logic is identical
across targets. Switching is a config/DNS change, not a code change.

### Cloudflare Workers

- Recommended for the user-facing path because of edge latency.
- `bun run deploy:prod` / `bun run deploy:beta`.
- Setup: see `wrangler.example.toml` + `wrangler.beta.example.toml`.

### Bun self-host

- Use the provided `Dockerfile`; `fly.toml.example` has a working Fly.io shape.
- Required env vars match the wrangler `[vars]` list; secrets via your platform's secret store.
- `EMAIL_PROVIDER=resend` or `ses` (Cloudflare Email Sending binding is unavailable off-Workers).
- Mount a persistent volume at `/data` for SQLite.

### Fastly Compute

- See [`docs/fastly-setup.md`](docs/fastly-setup.md) for the full walkthrough.
- Turso (or any libSQL-HTTP-compatible) for the database, Fastly KV Store for sessions/cache/rate-limit.
- Fastly has no native cron — drive `/api/internal/cron/run-task` from any HTTP scheduler (GitHub Actions, cron-job.org, a Cloudflare Worker, systemd timer, etc.). The endpoint is gated by `CRON_TRIGGER_SECRET`.
- `bun run build:fastly` produces the WASM bundle; `bun run deploy:fastly` publishes via the Fastly CLI.
- Scaffolded but not yet exercised by a real Fastly deploy. Treat the first deploy as a beta and file rough edges.

## Architecture

Highlights:

- **Anonymous flow**: Turnstile-gated, no email; per-IP daily cap with KV; durable record in
  D1 `free_grants` for abuse analysis.
- **Member flow**: Authentik OIDC (login) → CiviCRM lookup (membership) → tier mapping →
  Remnawave user. Membership is reconciled by a 5-min cron poll plus on-demand check
  with 60s KV cache.
- **Admin CMS**: passkey-only auth, separate from member sessions. Tier CRUD, user
  management (disable, reset traffic, force resync), audit log viewer.
- **Subscription delivery**: Remnawave is source of truth; we mirror to multiple S3
  providers via `@aws-sdk/client-s3` with HEAD-race latency picking; client gets primary
  Remnawave URL plus fallback mirror.
- **Proxy backends**: Remnawave and Outline run side-by-side behind a single
  `ProxyBackendProvider` interface. Tiers are bound to one backend; admins can run a
  Remnawave free tier alongside an Outline free tier, or expose backend choice to end
  users via the `subscription.user_choice_enabled` setting. See
  [`docs/backends.md`](docs/backends.md) for the interface contract and
  [`docs/outline-setup.md`](docs/outline-setup.md) for operator setup.
- **Runtime config**: an `app_settings` table backs admin-toggleable flags (backend
  enable/disable, default backend, user-choice gate, labels, scoring weights). All
  reads are Zod-validated and KV-cached.

## API consumers (mobile, services, integrations)

The HTTP surface is fully API-driven and documented via OpenAPI 3.1.

### Endpoints

- **Documented (versioned):** `/api/v1/me`, `/api/v1/subscription`, `/api/v1/account/*`,
  `/api/v1/admin/{tiers,users,audit,tokens}/*`.
- **Unversioned plumbing (not in spec):** `/api/healthz`, `/api/auth/*` (OAuth ceremonies),
  `/api/admin/auth/*` (WebAuthn ceremonies), `/api/webhooks/*` (HMAC inbound).
- **Spec:** `GET /api/openapi.json`
- **Spec UI:** `GET /api/docs` 302-redirects to `GET /api/openapi.json` (the raw spec; a rendered docs UI was removed to honor the no-external-CDN policy)

### Authentication paths

Three accepted auth mechanisms. They all populate the same Hono context shape:

| Path                | Format                                         | Used by                                                    |
| ------------------- | ---------------------------------------------- | ---------------------------------------------------------- |
| Cookie session      | `Cookie: fs_session=…` or `fs_admin_session=…` | Web SPA                                                    |
| Admin/service token | `Authorization: Bearer fsv1_<random>`          | Mobile push services, automation, monitoring               |
| Authentik OIDC JWT  | `Authorization: Bearer eyJ…`                   | Mobile members (PKCE + redirect to `freesocks://callback`) |

The bearer middleware decides between the second and third by token prefix
(`fsv1_` is unambiguous).

### Admin-issued API tokens

Admins mint tokens through the admin CMS at `/admin/tokens`. The plaintext is
shown **once** on creation and never recoverable thereafter — only `SHA-256(token)`
is stored. Tokens have:

- A name (free-form display label)
- An explicit scope set (e.g. `subscription:read`, `admin:users:write`)
- Optional expiration (none / 30d / 90d / 1y)
- Last-used timestamp tracking (debounced to 5-min granularity)
- Soft-revoke

Service tokens (`subject_type=service`) act with their own scopes. Tokens that
impersonate a specific user (`subject_type=user`) are not user-self-issuable in
v1 — only admins create them.

### Mobile auth flow (Authentik OAuth + PKCE)

1. App opens `ASWebAuthenticationSession` (iOS) / Chrome Custom Tabs (Android)
   to `${AUTHENTIK_ISSUER}/authorize?response_type=code&client_id=…&redirect_uri=freesocks://callback&code_challenge=…&code_challenge_method=S256&scope=openid email profile`.
2. User completes Authentik login.
3. Authentik redirects to `freesocks://callback?code=…&state=…`.
4. App exchanges the code at Authentik's token endpoint (PKCE, no client_secret needed).
5. App stores `access_token` + `refresh_token`. Calls FreeSocks API with
   `Authorization: Bearer <access_token>`.
6. App refreshes silently when `access_token` expires.

Authentik configuration: register `freesocks://callback` as an allowed redirect URI
on the OAuth provider that the web SPA already uses.

## Testing

```bash
bun run test:unit          # plain vitest, fast
bun run test:integration   # @cloudflare/vitest-pool-workers, real Miniflare D1+KV
bun test                   # both projects
bun run typecheck          # tsc -b + svelte-check
bun run lint               # eslint + prettier --check
```

## Frontend conventions

### Data fetching: TanStack Query only

Every fetch goes through a factory in `src/client/lib/queries.ts` that wraps `createQuery`
or `createInfiniteQuery`. Cache keys are exported via the `queryKeys` registry so
mutations can call `queryClient.invalidateQueries({ queryKey: queryKeys.X })`. Avoid
direct `fetch()` from components; add a query factory instead.

Mutations use `createMutation`. The `onSuccess` handler invalidates the relevant keys.
User feedback goes through `svelte-sonner` (`toast.success`, `toast.error`). Reference
pattern: `Account.svelte`'s regenerate and refresh-membership mutations.

### Voice and content policy

Copy must be factual. Do not invent:

- Links to Unredacted pages that have not been confirmed. Confirmed URLs are
  `unredacted.org`, `freesocks.org`, `members.unredacted.org/join`, and
  `members.unredacted.org/account`.
- Specific programs Unredacted runs. FreeSocks is the scope of this repo.
- Pricing numbers. Pricing lives on the Unredacted member portal. Tier feature numbers
  shown in-app come from `src/server/db/migrations/0001_seed_tiers.sql`.
- Marketing flourishes ("Internet freedom is a human right", "Built for the people
  who need it most", etc.).

### Component conventions

- shadcn-svelte primitives are imported from `@client/components/ui/<name>`; the
  directory barrels re-export named members (`Card`, `CardHeader`, etc.).
- Layout: `AppHeader.svelte` + `App.svelte`'s footer wrap every non-admin route. Admin
  routes use `AdminLayout.svelte` with its own sidebar.
- Loading states: `<Skeleton>` placeholders matching the loaded layout, not flat
  "Loading…" text. The page must not reflow when data arrives.
- Confirmations for destructive actions: shadcn-svelte `AlertDialog`, not
  `window.confirm()`.
- Animations: `transition:fly` / `transition:fade` from `svelte/transition` with
  `quintOut` easing, 180–400 ms typical. The CSS-layer `prefers-reduced-motion` rule
  clamps durations to 0.01 ms.

### Typography

Inter (body) + Inter Tight (display, h1/h2) + JetBrains Mono (code). Bundled and
self-hosted via `@fontsource/*` (imported in `src/client/main.ts`) — the page never
contacts `fonts.googleapis.com` / `fonts.gstatic.com` or any third-party host, a
deliberate privacy / censorship-resistance choice. System font fallbacks remain
configured. Apply `tabular-nums` to counters, file sizes, dates, and any number that
re-renders with different digits.

### Router

`src/client/stores/router.svelte.ts` is a History-API router that exposes a reactive
`router.pathname` rune. Route resolution is a `{#if pathname === '/' …}` cascade in
`App.svelte`. To add a route: import the component, add a `{:else if}` arm, and link
to it via `<Link href="/foo">`. There is no file-based routing because SvelteKit is
not in the stack.

## License

Same as upstream.
