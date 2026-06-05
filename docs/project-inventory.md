# Project inventory: features, open work, and code status

**Last reconciled against the code: 2026-06-04** (branch `v2`). This is a map, not a
spec — if it disagrees with the source, trust the source and fix this file. It exists so
a new maintainer (or a future automated pass) can tell at a glance what's **live**, what's
**deliberately dormant or scaffolded**, and what's genuinely **open work** — and, in
particular, so nobody deletes intentional scaffolding while "removing dead code."

Detailed companions, referenced rather than duplicated here:

- [`docs/backends.md`](backends.md) — proxy-backend interface + adding a backend.
- [`docs/outline-setup.md`](outline-setup.md) — registering/operating Outline servers.
- [`docs/account-number-design.md`](account-number-design.md) — account-number feature design + implementation status.
- [`docs/deferred-security-bugs.md`](deferred-security-bugs.md) — audit findings: resolved + still-open.
- [`docs/fastly-setup.md`](fastly-setup.md) — Fastly Compute deployment.

**Status legend**

| Tag             | Meaning                                                                                                      |
| --------------- | ------------------------------------------------------------------------------------------------------------ |
| **Live**        | Wired and active in the default production config.                                                           |
| **Dormant**     | Fully implemented and wired, but off by default behind a flag/setting. Keep it.                              |
| **Pending**     | Foundation built but not yet consumed by any route/UI. Keep it.                                              |
| **Scaffolding** | Deliberately-retained hook/escape-hatch/forward-compat surface with no current caller. **Keep it** — see §3. |

---

## 1. Features

### 1.1 Identity & authentication — three entry paths, unified downstream

- **Authentik OIDC** (members) — `GET /api/auth/{login,callback,logout}`; signed `fs_session`
  cookie **and** Authentik JWT bearer (verified against JWKS with audience/issuer/expiry).
  `src/server/routes/api/auth.ts`, `providers/authentik/{client,jwt}.ts`. **Live.**
- **WebAuthn passkeys** (admins) — one-time bootstrap (gated by `ADMIN_BOOTSTRAP_SECRET`,
  self-closes after the first admin) + register/authenticate; signed `fs_admin_session`
  cookie; per-IP throttle + dummy-challenge anti-enumeration. `routes/api/admin/auth.ts`,
  `providers/webauthn/server.ts`. **Live.**
- **`fsv1_` API tokens** (services) — hashed, scoped (`SCOPE_GROUPS.member|admin`), optional
  expiry, `subjectType: service|user`. `services/api-tokens.ts`, `middleware/bearer-auth.ts`.
  **Live.**
- Global middleware chain (`app.ts`): `requestId → services → logger → sessionOAuth →
sessionPasskey → bearerAuth`. None reject; authorization is **per-route** via
  `requireScope` / `requireScopeIfToken` / `requireAdmin`. **Live.**
- **Account-number login** — opaque 16-digit credential (`services/account-id.ts`).
  **Pending** — foundation only, gated by the `account_id.enabled` app setting (default off).
  See `account-number-design.md` for the done-vs-remaining map.

### 1.2 Free-tier issuance (`services/free-tier.ts`) — **Live**

- Turnstile-gated anonymous key issuance via `POST /api/v1/subscription`.
- **Atomic per-(IP, day) cap**: `free_grants.slot` + `UNIQUE(ip_hash, granted_day_bucket,
slot)`, claimed as `COUNT(...) % cap` with `onConflictDoNothing().returning()` (closes the
  H1 TOCTOU). KV soft-limit is the fast path; D1 is authoritative.
- Reissue path (Flow H): same IP+day returns the existing key with a banner.
- Strict client-IP resolution (`middleware/services.ts`): trust `cf-connecting-ip` on
  Workers; `x-forwarded-for` only when `TRUSTED_PROXY`; refuse issuance on unresolvable IP.
- `cleanup-expired-free` daily cron removes lapsed free users.

### 1.3 Membership & tiers — **Live**

- `services/membership-sync.ts` — cron reconcile (paginated, per-row error-isolated) +
  webhook-driven `reconcileOne`; `active → grace → disabled` lifecycle honoring per-tier
  `expirationDaysAfterMembershipLapse`; KV soft-lock (300s TTL).
- `services/membership-resolver.ts` — request-time CiviCRM lookup (cached, stale-on-error).
- `services/tier-policy.ts` — tier CRUD, membership→tier matching (backend-disambiguated,
  `priority`-ordered), and a propagation queue feeding `jobs/propagate-tier-change.ts`
  (cursor-resumable, lock-wrapped).

### 1.4 Subscription delivery (`services/subscription-delivery.ts`) — **Live**

- Backend-agnostic issue / mirror / teardown. `GET/POST /api/v1/subscription`;
  `/api/v1/account` regenerate + **switch-backend** (24h tombstone overlap). S3 multi-provider
  mirrors; grace-period tombstone sweep (cron piggyback).

### 1.5 Proxy backends (`providers/backend.ts` + `services/backend-registry.ts`)

- **Remnawave** (surfaced to users as **"Xray"**) — `providers/remnawave/*`. **Live, default.**
- **Outline** — `providers/outline/*` + `services/outline-pool.ts` (multi-server scoring) +
  `jobs/outline-healthcheck.ts` + admin server CRUD. **Dormant** (`outline.enabled=false`).
  See `outline-setup.md`.

### 1.6 Admin CMS (`/api/v1/admin/*` + `src/client/routes/admin/*`) — **Live**

- Tiers, Users (search by query/status; disable / reset-traffic / resync; backend shown),
  API tokens (create / reveal-once / revoke), Outline servers (CRUD + test-connection),
  App settings, Audit log (per-action allowlisted payloads).

### 1.7 Platform, runtime & integrations

- 4 entrypoints `src-entries/{workers,node,bun,fastly}.ts` → `PlatformAdapter` seam →
  shared `createApp()`. `KvStore` (Cloudflare / SQLite-table / Fastly) and the `Db` union
  (D1 / better-sqlite3 / libSQL). **Workers/Node/Bun Live; Fastly Pending** (see §2).
- Cron (`jobs/dispatcher.ts`): 3 Workers triggers + 2 piggybacks —
  `*/5` reconcile (+ propagate-tier-changes), `*/10` grace-sweep (+ outline-healthcheck +
  tombstone sweep), `0 3` cleanup-expired-free. Self-host drives these via node-cron /
  `setInterval` with in-process overlap guards; Fastly via `POST /api/internal/cron/run-task`
  (shared-secret `CRON_TRIGGER_SECRET`). Service container is built once per adapter.
- Integrations: **CiviCRM** (membership), **Turnstile** (the only sanctioned third-party
  script), **S3** (subscription mirrors), **email** factory (`cloudflare` / `resend` / `ses`
  / `console`, all selectable). OpenAPI 3.1 at `GET /api/openapi.json`.

### 1.8 Frontend SPA (Svelte 5 runes) — **Live**

- Public: `Home`, `GetKey` (Turnstile + backend chooser when dual-backend on), `Account`
  (OIDC view + regenerate / switch-backend), `AuthCallback`.
- Admin: Entry/Login/Bootstrap/Layout + Tiers/Users/Tokens/OutlineServers/Settings/Audit
  pages + editors/modals. Custom History-API router; all data via TanStack Query + the
  zod-validating `apiClient` (`lib/api.ts`, queries in `lib/queries.ts`).

---

## 2. Open work / to-dos

There are **no `TODO`/`FIXME`/`@deprecated` markers in `src/`** — open work lives here and in
the companion docs. Sizes: S/M/L.

| Item                                                                                                                                                                                                                                                                                    | Size | Where it's tracked                         |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | ------------------------------------------ |
| **Account-number login — stages S4–S13** (issuance wiring, login route, session, OIDC link / rotate / merge, all SPA UI, admin prefix-search, backfill script, e2e tests)                                                                                                               | L    | `account-number-design.md` status block    |
| **Member-signup epic** — the "coming soon" cluster (`AppHeader`, `Home`, `TierComparison`, `MemberImpact`, `Account`); wire the CiviCRM/Authentik join flow and consume `membersJoinUrl`                                                                                                | L    | this file (§3) + inline `coming soon` copy |
| **Bug 15** — Outline WSS `accessUrl` / `ssconf://` create-key contract (latent; needs the fork's real response shape)                                                                                                                                                                   | M    | `deferred-security-bugs.md`                |
| **Outline hardening** — real RTT capture for `scoreServer` (needs a latency column + migration); hard-cutoff disable path                                                                                                                                                               | M    | `deferred-security-bugs.md`                |
| **Fastly Compute finish** — `FastlyKvStore.list()` throws "not implemented"; `waitUntil` best-effort; AWS-SDK WASM size                                                                                                                                                                 | M    | `fastly-setup.md`                          |
| **Lower-priority provider tests** — CiviCRM client, email factory/providers, S3 storage, WebAuthn ceremonies (Remnawave client+backend, webhook HMAC, Authentik JWT verifier are now covered)                                                                                           | M    | this file                                  |
| **Cron lock** — upgrade the KV get/put soft-lock to atomic CAS / a D1 lease (accepted as-is today)                                                                                                                                                                                      | S–M  | `deferred-security-bugs.md` (Bug 8/9)      |
| **CI Drizzle drift check** — `bun run db:generate --check` is **pre-existing red**: this repo hand-writes incremental migrations and does NOT track drizzle-kit snapshots, so `generate` always diffs against an empty baseline. Decide: drop the check, or commit a full snapshot set. | S    | this file                                  |
| **README drift** — README §"Subscription delivery" still mentions S3 "HEAD-race latency picking"; that `pickFastestUrl` path was removed. Reword when next editing the README.                                                                                                          | S    | this file                                  |
| **L2** — Authentik self-provisioning (any user with a valid FreeSocks-audience JWT self-creates a local row)                                                                                                                                                                            | —    | `deferred-security-bugs.md` (accepted)     |

---

## 3. Code status register — scaffolding, escape hatches, dormant & pending

> **Read this before deleting anything as "dead code."** Several symbols have no current
> caller **by design** — they are forward-compat hooks, escape hatches, or feature
> foundations shipping dark. They are intentionally retained. Do not remove them in a
> generic dead-code sweep; if you believe one should go, decide it deliberately and update
> this table.

| Symbol / artifact                                                                                  | Location                                                                                              | Why it has no caller                                                                                                                                                                                                                                       | Disposition                                     |
| -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `RemnawaveClient.getSubscriptionRaw()` + `RawSubscriptionResponse`                                 | `providers/remnawave/{client,types}.ts`                                                               | Escape hatch for a future admin "raw Remnawave panel data" view; returns the full raw subscription payload the common `ProxyBackendProvider` interface intentionally omits.                                                                                | **Keep** (scaffolding)                          |
| `RemnawaveBackend.unsafeRawClient()`                                                               | `providers/remnawave/backend.ts`                                                                      | Documented escape hatch to reach the native client for Remnawave-specific paths that don't fit the backend abstraction.                                                                                                                                    | **Keep** (scaffolding)                          |
| `MembershipSyncService` deps `backends`                                                            | `services/membership-sync.ts`                                                                         | Held for the disable-on-lapse flow that will call `backends.fromSubscription(sub).updateUser(...)`; membership-sync is read-only on the backend side today.                                                                                                | **Keep** (forward-compat)                       |
| `account_id.*` (service, `users.account_id_*` columns, contract fields, `account_id.enabled` flag) | `services/account-id.ts`, `db/schema.ts`, `shared/contracts/*`                                        | Account-number feature foundation; consumed by nothing until stages S4–S13 land. Ships dark.                                                                                                                                                               | **Keep** (pending)                              |
| `PublicConfig.membersJoinUrl`                                                                      | `routes/api/config.ts`, `shared/contracts/auth.ts`                                                    | Emitted by `/api/v1/config` but not yet read by the SPA; reserved for the member-signup join CTA. (`membersAccountUrl` IS consumed.)                                                                                                                       | **Keep** (pending)                              |
| `components/ui/label/`                                                                             | `src/client/components/ui/`                                                                           | Unused shadcn-svelte primitive. shadcn primitives are conventionally kept as a complete kit; a11y labels currently use raw `id`/`for`.                                                                                                                     | **Keep** (kit completeness)                     |
| `kv_table.metadata` column                                                                         | `db/schema.ts`, `kv/sqlite.ts`                                                                        | The KV put-metadata option was removed, so this is now always written `null` (and read back by `list()`). Dropping it needs a column-drop migration; harmless as-is.                                                                                       | **Keep** (vestigial; remove only via migration) |
| Entire **Outline** subsystem                                                                       | `providers/outline/*`, `services/outline-pool.ts`, `jobs/outline-healthcheck.ts`, admin server routes | Fully wired but unreachable until `outline.enabled=true` + a server is registered. Within it: `scoreServer` latency is a hardcoded `0` placeholder (see Outline RTT to-do), and `outline_servers.prometheus_url` is "reserved for future per-key metrics". | **Keep** (dormant)                              |
| `FastlyKvStore.list()`                                                                             | `kv/fastly.ts`                                                                                        | Throws "not implemented" — Fastly KV exposes no list primitive. Fastly is scaffolded, not deployed.                                                                                                                                                        | **Keep** (Fastly is Pending)                    |

---

## How to keep this current

When you flip something Pending→Live, enable a Dormant feature, or intentionally retire a
scaffold, update the relevant row here in the same change — and move security/bug items
into `deferred-security-bugs.md`'s "Recently resolved" section. The companion docs hold the
detail; this file is the index.
