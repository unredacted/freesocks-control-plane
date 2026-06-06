# Project inventory: features, open work, and code status

**Last reconciled against the code: 2026-06-05** (branch `v2`). This is a map, not a
spec — if it disagrees with the source, trust the source and fix this file. It exists so
a new maintainer (or a future automated pass) can tell at a glance what's **live**, what's
**deliberately deferred or scaffolded**, and what's genuinely **open work** — and, in
particular, so nobody deletes intentional scaffolding while "removing dead code."

> **Stack, in one line.** The backend is a **self-hosted Convex deployment** (everything
> under `convex/`: queries/mutations/actions + the `convex/http.ts` HTTP router + the
> `convex/crons.ts` native crons). The frontend is a **static Svelte 5 SPA** (`src/client/`,
> built by Vite) that talks to the Convex HTTP surface through a cookie-auth `apiClient`.
> The previous Hono/Cloudflare-Workers stack — Drizzle/D1, the `PlatformAdapter` +
> `src-entries/*`, `KvStore`, OIDC/Authentik, CiviCRM, wrangler/Fastly — has been removed.

Detailed companions, referenced rather than duplicated here:

- [`docs/convex-self-hosting.md`](convex-self-hosting.md) — self-hosting + fresh-deploy cutover runbook + env checklist.
- [`docs/backends.md`](backends.md) — proxy-backend dispatch (Convex actions) + adding a backend.
- [`docs/outline-setup.md`](outline-setup.md) — registering/operating Outline servers via the admin CMS.
- [`docs/account-number-design.md`](account-number-design.md) — account-number auth design + implementation status.
- [`docs/deferred-security-bugs.md`](deferred-security-bugs.md) — audit findings, re-annotated against the Convex code.

**Status legend**

| Tag             | Meaning                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------ |
| **Live**        | Wired and active in the default config.                                                    |
| **Dormant**     | Fully implemented and wired, but off by default behind a flag/setting. Keep it.            |
| **Deferred**    | Intentionally not built yet; a known follow-up. The seam/hook exists. Keep it.             |
| **Scaffolding** | Deliberately-retained forward-compat surface with no current caller. **Keep it** — see §3. |

---

## 1. Features

### 1.1 Identity & authentication — three schemes, NO OIDC

- **Account number** (members) — a random **32-digit** credential (~106 bits), minted once at
  key issuance (reveal-once), stored only as a peppered keyed hash
  (`HMAC-SHA256(ACCOUNT_ID_PEPPER, number)`), the **only** member identity. `POST /api/v1/auth/account-login` (Turnstile +
  strict per-prefix/per-IP rate limits + constant-time, generic-failure) → signed `fs_session`
  cookie. Rotatable (`POST /api/v1/account/account-id/rotate`). `convex/auth.ts`,
  `convex/accountId.ts`, `convex/lib/accountId.ts`. **Live.** See `account-number-design.md`.
- **WebAuthn passkeys** (admins) — first-run **bootstrap wizard** (gated by
  `ADMIN_BOOTSTRAP_SECRET`, re-checked at options _and_ verify, **locks forever** once any
  credential exists) + authenticate; signed `fs_admin_session` cookie; per-IP throttle +
  anti-enumeration (well-formed options for unknown usernames). `convex/webauthn.ts`
  (`"use node"`) + `convex/admins.ts`. **Live.**
- **`fsv1_` API tokens** (services) — SHA-256-hashed, scoped (`SCOPE_GROUPS.member|admin` in
  `src/shared/contracts/scopes.ts`), optional expiry, `subjectType: service|user`, debounced
  last-used, soft-revoke. `convex/apiTokens.ts`. **Live.**
- Identity resolution is **per-route**, not middleware: each `httpAction` calls
  `resolveMember` / `resolveAdmin` / `resolveBearer` in `convex/lib/http.ts` (signed cookie
  OR `fsv1_` token). **Live.**

### 1.2 Free-tier issuance (`convex/freeTier.ts`) — **Live**

- Turnstile-gated anonymous key issuance via `POST /api/v1/subscription`.
- **Serializable per-(IP, day) cap**: `claimFreeSlot` reads the `freeGrants` for
  `(ipHash, dayBucket)` over the `by_ip_day` index and inserts only if under cap — Convex's
  serializable OCC makes two concurrent claims conflict, so the cap holds exactly (closes the
  H1 over-issuance race **by construction** — see `deferred-security-bugs.md`).
- Reissue path: a same-(IP, day) request with one prior live grant returns the existing key
  (`accountIdAvailable:false`) instead of rejecting.
- The slot is held before any backend HTTP; `releaseFreeSlot` compensates if issuance fails,
  so a transient error doesn't burn the IP's daily allowance.
- Fail-closed client-IP resolution (`convex/lib/http.ts`): trust `cf-connecting-ip`;
  `x-forwarded-for` only when `TRUSTED_PROXY=true`; refuse issuance on an unresolvable IP.
- `cleanup-expired-free` daily cron removes lapsed free users (backend + S3 + local).

### 1.3 Entitlements, tiers & lifecycle (`convex/lifecycle.ts`, `convex/tiers.ts`) — **Live**

- `tiers` are entitlement templates (traffic/device/hwid limits, `backend` discriminator,
  per-tier `expirationDaysAfterMembershipLapse`). Admin CRUD via `convex/adminApi.ts`.
- **`setMembership`** is the single entitlement seam: sets a user's tier + expiry, records
  `tierHistory` + audit, and schedules a durable `pushTierToBackend` (event-driven, **not** a
  cron). Driven today by admin edits and the billing webhook (§1.7).
- `runGraceSweep` cron: `active → grace` for lapsed members, `grace → disabled` past **each
  tier's** grace window (and disables the backend sub so the key stops routing).

### 1.4 Subscription delivery (`convex/lib/issuance.ts`, `convex/account.ts`) — **Live**

- Backend-agnostic issue / mirror / teardown saga. `GET|POST /api/v1/subscription`;
  `/api/v1/account` **regenerate** + **switch-backend** (24h tombstone overlap). Optional S3
  multi-provider mirrors; `tombstone-sweep` cron hard-deletes after the grace window.
- Switch-backend interim: free-tier users switch via the default-free peer tier on the target
  backend; **paid cross-backend switching returns 409** until the billing portal defines tier
  linkage (CiviCRM's linkage is gone). Documented in `convex/account.ts`.

### 1.5 Proxy backends (`convex/backends.ts` + `convex/lib/backends/*`)

- **Remnawave** (surfaced to users as **"Xray"**) — pure HTTP, config from `process.env`
  (`REMNAWAVE_BASE_URL`, `REMNAWAVE_API_TOKEN`). **Live, default.**
- **Outline** — dispatch branches + `convex/lib/backends/outline.ts` (HTTP) +
  `convex/outlineServers.ts` (the DB half: pool selection, key→server resolution,
  `outline-healthcheck` cron) + admin server CRUD. **Dormant** (`outline.enabled=false`).
  See `outline-setup.md`.

### 1.6 Admin CMS (`/api/v1/admin/*` + `src/client/routes/admin/*`) — **Live**

- Tiers; Users (search by query/status/tier; disable / reset-traffic / resync; backend shown);
  API tokens (create / reveal-once / revoke); Outline servers (CRUD + test-connection; the
  `apiUrl` secret is stored server-side and only ever returned as `apiUrlMasked`); App
  settings; Audit log. Backed by `convex/adminApi.ts`.

### 1.7 Integrations & runtime

- **Billing webhook seam** — `POST /api/webhooks/billing` (`convex/webhooks.ts`):
  HMAC-SHA256-verified (`WEBHOOK_SIGNING_SECRET`) + deduped by `eventId` (`webhookEvents`
  table) → maps `{accountId, tierSlug, expiresAtMs?}` onto `lifecycle.setMembership`. The
  single inbound point the **future in-house billing portal** plugs into. **Live (seam ready;
  no portal calling it yet).**
- **Cloudflare Turnstile** (`convex/lib/turnstile.ts`) — gates free issuance + account login.
  The only sanctioned third-party script. **Live.**
- **S3 subscription mirrors** (`convex/storage.ts`, `"use node"`) — N providers from env
  (`S3_MIRRORS_ENABLED`, `S3_PROVIDER_*`); the censorship-resistance hedge. **Dormant**
  (off unless configured).
- **Email subsystem** — **Deferred.** The lifecycle transitions (welcome / grace-warning /
  disabled) fire and audit, but **send nothing**: there is no email provider wired. An
  `emailLog` table + a `templateKey`/`dedupeKey` shape exist as the foundation. See §2.

### 1.8 Scheduled jobs (`convex/crons.ts`) — **Live**

Convex runs these natively (no Workers triggers, no node-cron):

- `grace-sweep` (10 min) — `active→grace→disabled`.
- `tombstone-sweep` (10 min) — hard-delete subscriptions past their 24h regenerate/switch grace.
- `outline-healthcheck` (10 min) — ping active Outline servers; stamp `lastHealthOkAt`.
- `cleanup-expired-free` (daily 03:00 UTC) — delete expired free users.
- `session-sweep` / `rate-limit-sweep` (daily) — drop expired `sessions` / `rateLimits` rows.

### 1.9 Frontend SPA (Svelte 5 runes) — **Live**

- Public: `Home`, `GetKey` (Turnstile + backend chooser when dual-backend on, reveal-once
  account-number panel), `Account` (member view + regenerate / switch-backend / rotate),
  `Login` (account-number sign-in).
- Admin: `AdminEntry`/`AdminLogin`/`AdminBootstrap`/`AdminLayout` + Tiers / Users / Tokens /
  OutlineServers / Settings / Audit pages + editors/modals. Custom History-API router; all
  data via TanStack Query + the zod-validating `apiClient` (`lib/api.ts`, `lib/queries.ts`).

---

## 2. Open work / to-dos

There are **no `TODO`/`FIXME` markers in `convex/` or `src/`** — open work lives here and in
the companion docs. Sizes: S/M/L.

| Item                                                                                                                                                                                                                                                   | Size | Where it's tracked          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---- | --------------------------- |
| **Email subsystem** — welcome / grace-warning / disabled notifications. The lifecycle transitions fire + audit but send nothing; the `emailLog` table is the only foundation. Pick a provider, add a `"use node"` action, wire it into `lifecycle.ts`. | M    | this file (§1.7)            |
| **Billing portal integration** — the webhook seam (`/api/webhooks/billing` → `setMembership`) is ready; the in-house portal that calls it is the future entitlement source.                                                                            | L    | this file (§1.7)            |
| **Paid cross-backend switch** — `account.switchBackend` returns 409 for paid tiers until the billing portal defines cross-backend tier linkage. Needs the portal's tier model.                                                                         | M    | `convex/account.ts`         |
| **Outline WSS `accessUrl` / `ssconf://` contract** (Bug 15, latent) — needs the FreeSocks Outline fork's real WSS create-key response shape before any WSS server is routed to.                                                                        | M    | `deferred-security-bugs.md` |
| **Outline scoring RTT** — `pickCandidatesForIssue` uses a `latency*0` placeholder; real RTT capture would need the healthcheck to record per-server latency. Latent (backend off).                                                                     | M    | `outline-setup.md` + §3     |

---

## 3. Code status register — scaffolding, dormant & deferred

> **Read this before deleting anything as "dead code."** Several symbols have no current
> caller **by design** — forward-compat hooks, feature foundations shipping dark, or
> dormant subsystems. They are intentionally retained. If you believe one should go, decide
> it deliberately and update this table.

| Symbol / artifact                                      | Location                                                                                                                      | Why it has no (full) caller                                                                                                                                             | Disposition                    |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `emailLog` table + `EmailDelivery` shape               | `convex/schema.ts`                                                                                                            | Foundation for the deferred email subsystem; lifecycle transitions fire but nothing sends yet.                                                                          | **Keep** (deferred — §1.7)     |
| `webhooks.ingest` billing seam                         | `convex/webhooks.ts`, `convex/http.ts`                                                                                        | The single inbound point for the future billing portal; HMAC + dedupe + `setMembership` are all live, but no portal calls it today.                                     | **Keep** (seam ready)          |
| Entire **Outline** subsystem                           | `convex/backends.ts` (outline branches), `convex/lib/backends/outline.ts`, `convex/outlineServers.ts`, admin server routes/UI | Fully wired but unreachable until `outline.enabled=true` + a server is registered. Within it: pool scoring uses a `latency*0` placeholder; `prometheusUrl` is reserved. | **Keep** (dormant)             |
| S3 mirroring (`storage.ts`)                            | `convex/storage.ts`, `convex/lib/issuance.ts`                                                                                 | Skipped entirely unless `S3_MIRRORS_ENABLED=true` + providers configured.                                                                                               | **Keep** (dormant)             |
| `appState` table                                       | `convex/schema.ts`                                                                                                            | Generic singleton key/value (e.g. tier-propagation cursors). Forward-compat for cursored sweeps.                                                                        | **Keep** (scaffolding)         |
| `components/ui/label/`, other unused shadcn primitives | `src/client/components/ui/`                                                                                                   | shadcn primitives are kept as a complete kit even when a given primitive has no current import.                                                                         | **Keep** (kit completeness)    |
| `fetchSubscriptionContent` (Remnawave/Outline)         | `convex/backends.ts`, `convex/lib/backends/*`                                                                                 | Only invoked when S3 mirroring is on; part of the backend interface contract regardless.                                                                                | **Keep** (interface + dormant) |

---

## How to keep this current

When you flip something Deferred/Dormant → Live, enable a dormant feature, or intentionally
retire a scaffold, update the relevant row here in the same change — and move security/bug
items into `deferred-security-bugs.md`'s "Recently resolved" section. The companion docs hold
the detail; this file is the index.
