# Project inventory: features, open work, and code status

**Last reconciled against the code: 2026-06-28** (branch `v2`, after the improvement-roadmap
pass: an admin landing **dashboard** with a shared `GET /admin/status` and audit-log filtering,
an admin-configurable **theme system**, **admin/passkey lifecycle** (deactivate/reactivate and
per-passkey revoke, guarded), IaC-friendly **by-slug / by-name CRUD** with declarative
squad↔tier binding and an **automation-token** bootstrap for the Ansible role, per-rail
**billing readiness**, tier **duplicate**, onboarding **skeletons**, a copy sweep, and the
**Paraglide** i18n migration; on top of the earlier launch-readiness pass: Cap captcha, W2
rate-limit policies, W3 support ID, W4 redemption codes, i18n/RTL, and the A1–A4 plus P1/P2
hardening). This is a map, not a spec; if it disagrees with the source, trust the source and fix
this file. It exists so a new maintainer (or a future automated pass) can tell at a glance what's
**live**, what's **deliberately deferred or scaffolded**, and what's genuinely **open work**, and,
in particular, so nobody deletes intentional scaffolding while "removing dead code."

> **Stack, in one line.** The backend is a **self-hosted Convex deployment** (everything
> under `convex/`: queries/mutations/actions + the `convex/http.ts` HTTP router + the
> `convex/crons.ts` native crons). The frontend is a **static Svelte 5 SPA** (`src/client/`,
> built by Vite) that talks to the Convex HTTP surface through a cookie-auth `apiClient`.
> The previous Hono/Cloudflare-Workers stack (Drizzle/D1, the `PlatformAdapter` +
> `src-entries/*`, `KvStore`, OIDC/Authentik, CiviCRM, wrangler/Fastly) has been removed.

Detailed companions, referenced rather than duplicated here:

- [`docs/convex-self-hosting.md`](convex-self-hosting.md): self-hosting + fresh-deploy cutover runbook + env checklist.
- [`docs/backends.md`](backends.md): proxy-backend dispatch (Convex actions) + adding a backend.
- [`docs/outline-setup.md`](outline-setup.md): registering/operating Outline servers via the admin CMS.
- [`docs/account-number-design.md`](account-number-design.md): account-number auth design + implementation status.
- [`docs/deferred-security-bugs.md`](deferred-security-bugs.md): audit findings, re-annotated against the Convex code.

**Status legend**

| Tag             | Meaning                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------ |
| **Live**        | Wired and active in the default config.                                                    |
| **Dormant**     | Fully implemented and wired, but off by default behind a flag/setting. Keep it.            |
| **Deferred**    | Intentionally not built yet; a known follow-up. The seam/hook exists. Keep it.             |
| **Scaffolding** | Deliberately-retained forward-compat surface with no current caller. **Keep it** (see §3). |

---

## 1. Features

### 1.1 Identity & authentication: three schemes, NO OIDC

- **Account number** (members): a random **32-digit** credential (~106 bits), minted once at
  account creation (reveal-once), stored only as a peppered keyed hash
  (`HMAC-SHA256(ACCOUNT_ID_PEPPER, number)`), the **only** member identity. `POST /api/v1/auth/account-login`
  (Cap captcha + strict per-IP + per-(prefix,IP) rate limits + constant-time, generic-failure) → signed `fs_session`
  cookie. Rotatable (`POST /api/v1/account/account-id/rotate`). `convex/auth.ts`,
  `convex/accountId.ts`, `convex/lib/accountId.ts`. **Live.** See `account-number-design.md`.
- **Support ID** (W3): a non-secret `FS-XXXX-XXXX` Crockford-base32 handle minted per user at
  creation (lazily backfilled), uniqueness-checked, NOT a credential (can't log in). The
  human-shareable identifier for support (collision-free, unlike the 4-digit prefix). Shown on
  the Account page; admin user-search resolves it. `convex/supportId.ts`, `convex/lib/supportId.ts`. **Live.**
- **WebAuthn passkeys** (admins): first-run **bootstrap wizard** (gated by
  `ADMIN_BOOTSTRAP_SECRET`, re-checked at options _and_ verify, **locks forever** once any
  credential exists) + authenticate; signed `fs_admin_session` cookie; per-IP throttle +
  anti-enumeration (well-formed options for unknown usernames); **multi-admin invites** + an
  admin **lifecycle** (deactivate/reactivate, per-passkey revoke) under a **last-admin guard**
  (an "effective admin" = active + ≥1 passkey; neither op may drop that count to zero).
  Deactivation is enforced everywhere: `resolveAdmin` re-checks the bound admin's `isActive` on
  **every request** (and the login verify path refuses), so a disabled admin loses access
  immediately rather than at session-TTL. `convex/webauthn.ts` (`"use node"`) + `convex/admins.ts`. **Live.**
- **`fsv1_` API tokens** (services): SHA-256-hashed, scoped (`SCOPE_GROUPS.member|admin` in
  `src/shared/contracts/scopes.ts`, incl. `admin:status:read`), optional expiry,
  `subjectType: service|user`, debounced last-used, soft-revoke. Minted in the CMS **or**
  headlessly for IaC via `bunx convex run adminApi:mintAutomationToken` (a credential-less
  synthetic `automation` admin actor that can never establish a cookie session — the public
  cookie gate is deliberately **not** relaxed). `convex/apiTokens.ts`, `convex/adminApi.ts`. **Live.**
- Identity resolution is **per-route**, not middleware: each `httpAction` calls
  `resolveMember` / `resolveAdmin` / `resolveBearer` in `convex/lib/http.ts` (signed cookie
  OR `fsv1_` token); admin token callers are scope-gated, cookie sessions are full-privilege. **Live.**

### 1.2 Free-tier account creation (`convex/freeTier.ts`): **Live**

- Cap-captcha-gated anonymous account creation via `POST /api/v1/account`
  (`createFreeAccount`): mint user + reveal-once account number + support ID + member session.
  **Decoupled from proxy issuance**, so it never depends on a backend being available; the
  proxy key is created separately by the signed-in member (§1.4).
- **Serializable per-(IP, day) cap**: `claimFreeSlot` reads the `freeGrants` for
  `(ipHash, dayBucket)` over the `by_ip_day` index and inserts only if under cap. Convex's
  serializable OCC makes two concurrent claims conflict, so the cap holds exactly (closes the
  H1 over-issuance race **by construction**; see `deferred-security-bugs.md`).
- Cap reached (same IP, day): `freetier.cap_reached` (429). There is no key to hand back, so
  the visitor signs in with their existing number. `releaseFreeSlot` compensates if the
  mint/session step fails, so a transient error doesn't burn the IP's daily allowance.
- Fail-closed client-IP resolution (`convex/lib/http.ts`): `x-forwarded-for` only when
  `TRUSTED_PROXY=true`; `cf-connecting-ip` only when `CF_FRONTED=true` (a real Cloudflare
  edge in front, else it's client-spoofable); refuse on an unresolvable IP. Caddy also
  strips client-supplied `CF-Connecting-IP` upstream as defense in depth.
- `cleanup-expired-free` daily cron removes lapsed free users (backend + S3 + local).

### 1.3 Entitlements, tiers & lifecycle (`convex/lifecycle.ts`, `convex/tiers.ts`): **Live**

- `tiers` are entitlement templates (traffic/device/hwid limits, `backend` discriminator,
  per-tier `expirationDaysAfterMembershipLapse`). Admin CRUD via `convex/adminApi.ts`.
- **`setMembership`** / `applyMembership` is the single entitlement seam: sets a user's tier +
  expiry (re-activating a lapsed user), records `tierHistory` + audit, and schedules a durable
  `pushTierToBackend` (event-driven, **not** a cron; retries with backoff + audits on final
  failure). Driven by admin edits, **membership-code redemption** (§1.7), and the billing webhook.
- `runGraceSweep` cron: `active → grace` for lapsed members, `grace → disabled` past **each
  tier's** grace window (and disables the backend sub so the key stops routing).

### 1.4 Subscription delivery (`convex/lib/issuance.ts`, `convex/account.ts`): **Live**

- Backend-agnostic issue / mirror / teardown saga, run as a signed-in member action:
  `/api/v1/account` **regenerate** (create-or-replace the proxy key) + **switch-backend** (24h
  tombstone overlap). A missing/empty backend surfaces as a retryable `backend.unavailable`
  (503), mapped in `convex/http.ts`. Optional S3 multi-provider mirrors; `tombstone-sweep`
  cron hard-deletes after the grace window.
- Switch-backend interim: free-tier users switch via the default-free peer tier on the target
  backend; **paid cross-backend switching returns 409** until the billing portal defines tier
  linkage (CiviCRM's linkage is gone). Documented in `convex/account.ts`.

### 1.5 Proxy backends (`convex/backends.ts` + `convex/lib/backends/*`)

- **Generic + instance-based.** Dispatch (`convex/backends.ts`) resolves a backend INSTANCE (a
  `backendServers` row of any type) and calls that type's provider from the registry
  (`convex/lib/backends/registry.ts`). The DB half (pool selection, key→instance resolution, the
  `backend-healthcheck` cron) is generic in `convex/backendServers.ts`; instances are admin-managed
  ("Backend servers" CMS screen). See `backends.md`.
- **Remnawave** (surfaced to users as **"Xray"**): pure HTTP provider. **Live, default.** Instances
  are DB rows; the primary is seeded from `REMNAWAVE_*` env at cutover, then managed in the CMS.
- **Outline**: pure HTTP provider + DB instances. **Dormant** (`outline.enabled=false`). See
  `outline-setup.md`.

### 1.6 Admin CMS (`/api/v1/admin/*` + `src/client/routes/admin/*`): **Live**

- **Dashboard** (the `/admin` landing; replaced the old `→ /admin/tiers` redirect): a health
  strip + users-by-status + per-backend health + a billing mini-panel, all from the shared
  **`GET /api/v1/admin/status`** (`statusSummary`; scope `admin:status:read`; counts + health
  booleans only, never a secret — also consumed by the Ansible post-deploy health gate).
- **Tiers** (CRUD + **Duplicate** — a pre-filled create; the one-default-free-per-backend
  invariant auto-clears on save); **Users** (search by **support ID** or 4-digit prefix;
  status/tier filters; disable / **re-enable** / reset-traffic / resync / **grant-or-extend
  membership**; backend shown; **paginated**); **Admins** (invite links + deactivate/reactivate
  - per-passkey revoke, §1.1); **API tokens** (create / reveal-once / revoke; scope **group**
    toggles); **Backend servers** (CRUD + test-connection; secret `config`/`apiUrl` stored
    server-side, only ever returned masked); **Billing** (per-rail config + a **readiness** check
    that flags enabled-but-misconfigured rails; §1.7); **Storage mirrors** (provider pool, §1.7);
    **Theme** (preset gallery + hue slider + live preview; §1.7); **Rate-limit policies** (W2);
    **Membership codes** (W4); App settings; **Audit log** (filter by action / actor / since).
- **IaC-addressable mutations** (for the Ansible role): idempotent **`PUT …/backend-servers/by-slug/{slug}`** + **`DELETE …/by-slug/{slug}`**, **`PUT …/tiers/by-slug/{slug}`** (also the
  declarative squad↔tier bind — `remnawaveSquadUuid` is a tier field), and **`PUT
…/mirror-providers/by-name/{name}`**. Each is a single keep-secret-on-blank upsert; no
  client-side id resolution. Backed by `convex/adminApi.ts` / `convex/mirrorProviders.ts`.

### 1.7 Integrations & runtime

- **Self-service membership billing** (`convex/billing.ts`, `convex/lib/processors/*`,
  `convex/lib/billingConfig.ts`; `docs/billing.md`): signed-in members buy a fixed-term
  membership via a hosted-redirect rail — **NOWPayments (crypto, Live)**, **Stripe (card)**
  and **PayPal** as phased adapters. `POST /api/v1/billing/checkout` mints an opaque
  `userId`-bound order (no payer PII stored) → processor invoice → `/api/webhooks/<processor>`
  verifies + dedupes + grants exactly once via `applyMembership`. Catalog/toggles in the
  `appSettings` `billing.*` namespace, edited in Admin → Billing. The SPA `UpgradeMembership`
  panel + `/account?order=<ref>` polling complete the loop. **Live (NOWPayments; Stripe/PayPal
  scaffolded behind admin toggles).** The USD off-ramp is a documented ops runbook
  (NOWPayments → USDC → Coinbase/Kraken → ACH).
- **Billing webhook seam** (legacy/ops): `POST /api/webhooks/billing` (`convex/webhooks.ts`),
  HMAC-SHA256-verified (`WEBHOOK_SIGNING_SECRET`) + deduped by `eventId` (`webhookEvents`
  table) → maps `{accountId, tierSlug, expiresAtMs?}` onto `lifecycle.setMembership`. Kept as
  a generic inbound entitlement seam alongside the self-service rails above. **Live.**
- **Self-hosted Cap captcha** (`convex/lib/captcha.ts` + `src/client/components/CapWidget.svelte`):
  proof-of-work CAPTCHA gating free issuance + account login. Replaced Cloudflare Turnstile (W1)
  — the widget is bundled from npm and challenge traffic is same-origin (Caddy `/cap` → the `cap`
  service), so there are now **zero third-party runtime scripts**. **Live.**
- **Membership redemption codes** (W4, `convex/membershipCodes.ts`): admin-minted
  `FSM-XXXX-XXXX-XXXX` bearer codes (stored hashed) a signed-in member redeems
  (`POST /api/v1/account/redeem-code`) to grant/extend a paid tier — the **day-1 upgrade path**,
  no billing portal required. Single-use serializable consume → `applyMembership`; hard
  rate-limited; generic no-oracle failure. **Live.**
- **DB-driven rate-limit policies** (W2, `convex/lib/rateLimitPolicy.ts` + `rateLimits.enforce`):
  every limit (free-tier cap, login, regenerate/switch, redeem, webhook) is an admin-editable
  `{max,windowMs,enabled}` stored under `appSettings.ratelimit.*`, resolved per request with a
  fail-safe fallback to the compiled default. **Live.**
- **Admin-configurable theme** (`convex/lib/themeConfig.ts` + `convex/publicConfig.ts` +
  `src/client/lib/theme.ts`, `theme-init.js`): curated presets (**Emerald** default / Teal /
  Indigo / Classic monochrome) + an optional accent-**hue** override (hue-only, so each preset's
  AA-tuned lightness/chroma ramp is preserved). Resolved server-side (`resolveTheme`,
  bounds-checked, fail-safe), exposed via the public `publicConfig.get`, applied client-side
  through an unlayered `<style>` with a `theme-init.js` localStorage replay (no flash-of-default
  on reload). Edited in Admin → Theme (`PATCH /api/v1/admin/theme`, audited `admin.theme.change`).
  Brand hue stays distinct from the semantic success/health green. **Live (Emerald default).**
- **i18n + RTL** (`messages/*.json` + **Paraglide/inlang**, `src/client/lib/i18n/`):
  `messages/en.json` is the authoritative source, compiled to typed messages
  (`bun run i18n:keys` + `i18n:compile`); `t()` is a thin shim over the compiled `m` (the old
  hand-rolled TS catalogs are gone). Locales en/fa/ar/ru/zh, RTL via `<html dir>`, persisted
  language switcher, Persian/Arabic-Indic digit normalization; non-English locales auto-filled
  (`bun run i18n:translate`). Critical journey strings done; native review is a follow-up.
  **Live (English authoritative; other locales first-pass MT).**
- **S3 subscription mirrors** (`convex/storage.ts` `"use node"` + `convex/mirrorProviders.ts`):
  the censorship-resistance hedge, **opt-in + lazy**. Providers are a DB pool (`mirrorProviders`,
  admin CMS → "Storage mirrors", country-tiered, no env flag — replaced `S3_MIRRORS_ENABLED`/
  `S3_PROVIDER_*`). A config hits S3 ONLY when a member who can't connect requests a mirror
  (`storage.provisionMirror`, capped by `mirror.maxPerUser`, capability-URL'd, country picked from
  `CF-IPCountry` transiently + never stored) — never proactively. The SPA exposes it via the
  understated "trouble connecting?" flow (`MirrorHelp.svelte`), gated on `publicConfig.mirrorsEnabled`.
  See `docs/threat-model-cdn-blinding.md` for the deliberate availability-vs-confidentiality trade.
  **Dormant** (no providers configured yet).
- **Automated backups** (A3, `docker/backup.sh` + the `backup` compose service): scheduled
  `pg_dump` shipped offsite to S3-compatible storage. **Live when `BACKUP_S3_*` is set** (else
  local-only with a loud warning).
- **Email / notifications**: **intentionally absent.** Accounts are anonymous: no contact
  details are collected and the control plane sends nothing. Lifecycle transitions (grace,
  disabled) are recorded to the audit log only. There is no email subsystem, and adding one
  is a non-goal.

### 1.8 Scheduled jobs (`convex/crons.ts`): **Live**

Convex runs these natively (no Workers triggers, no node-cron):

- `grace-sweep` (10 min): `active→grace→disabled` (cursor-drained; backend-disable first).
- `tombstone-sweep` (10 min): hard-delete subscriptions past their 24h regenerate/switch grace.
- `backend-healthcheck` (10 min): ping active backend instances of every type; stamp
  `lastHealthOkAt` + rtt (feeds pool selection).
- `cleanup-expired-free` (daily 03:00 UTC): delete expired free users (per-tier cursor).
- `session-sweep` / `rate-limit-sweep` / `replay-guard-sweep` (daily): drop expired
  `sessions` / `rateLimits` / `replayGuard` rows.
- `epoch-key-rotate` (10 min) / `epoch-key-sweep` (daily): CDN-blinding HPKE epoch keys.
- `retention-audit` / `retention-webhooks` / `retention-tier-history` /
  `retention-free-grants` (daily): bounded deletes of the append-only tables past their
  retention window (P2).

### 1.9 Frontend SPA (Svelte 5 runes): **Live**

- Public: `Home`, `GetAccount` (Cap widget + backend chooser radiogroup when dual-backend on;
  the reveal-once account number is a blocking, checkbox-gated `AccountNumberReveal` modal with
  copy/download/`beforeunload`; per-platform `SetupGuidance` after issuance), `Account` (member
  view + regenerate / switch-backend / rotate / **redeem code** / support-ID display),
  `Login` (account-number sign-in: show/hide, password-manager autofill, digit normalization).
  `Home` + `GetAccount` show loading **skeletons** (no config-gated/auth-state content flash);
  the `Account` page surfaces a calm account-number **recovery** hint (rotate if you didn't save
  it). Localized via `lib/i18n`; a `LanguageSwitcher` in the header.
- Admin (lazy-loaded behind `AdminRouter`): `AdminEntry`/`AdminLogin`/`AdminBootstrap`/`AdminLayout`
  - **Dashboard** / Tiers / Users / **Admins** / Tokens / BackendServers / **Billing** /
    **Storage** mirrors / **RateLimits** / **MembershipCodes** / **Theme** / Settings / Audit
    pages + editors/modals. Custom History-API router; all data via TanStack Query + the
    zod-validating `apiClient` (`lib/api.ts`, `lib/queries.ts`); errors localized via `lib/errors.ts`.

---

## 2. Open work / to-dos

There are **no `TODO`/`FIXME` markers in `convex/` or `src/`**; open work lives here and in
the companion docs. Sizes: S/M/L.

| Item                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Size | Where it's tracked                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | ---------------------------------------- |
| **Self-service billing**: the crypto rail (NOWPayments) is **Live**. **Stripe + PayPal** are **implemented, wired, and unit-tested** (adapters + dispatch + webhook routes + `convex/lib/processors/processors.test.ts`) but stay behind admin toggles **pending a sandbox dry-run** against real Stripe/PayPal test accounts (no adapter-building left). Plus the non-code launch checklist: NOWPayments US-nonprofit ToS confirmation + the USDC→Coinbase/Kraken→ACH off-ramp. Admin → Billing flags enabled-but-misconfigured rails (a client-side **readiness** check); a **live per-processor credential probe** (an actual API ping, beyond readiness) is a deferred follow-up. | M    | `docs/billing.md`, this file (§1.6/§1.7) |
| **Native-speaker translation review** + extracting remaining marketing copy into i18n keys (the non-English locales are a first-pass MT; the critical journey strings are done).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | M    | this file (§1.7), `.claude/plans/`       |
| **`POP_REQUIRED` flip**: operational — flip in beta after the client soaks (boot-warm prerequisite is done), prod launches with it on. PoP **`sid`-binding is DONE** (the public per-session token `fs_pop_sid` is bound into the single-`v1` canonical message; see the threat model Layer 2).                                                                                                                                                                                                                                                                                                                                                                                       | S    | `.claude/plans/`, threat model           |
| **Paid cross-backend switch**: `account.switchBackend` returns 409 for paid tiers until tier linkage across backends is defined. Needs the portal's tier model.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | M    | `convex/account.ts`                      |
| **Outline WSS `accessUrl` / `ssconf://` contract** (Bug 15, latent): needs the FreeSocks Outline fork's real WSS create-key response shape before any WSS server is routed to.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | M    | `deferred-security-bugs.md`              |

---

## 3. Code status register: scaffolding, dormant & deferred

> **Read this before deleting anything as "dead code."** Several symbols have no current
> caller **by design**: forward-compat hooks, feature foundations shipping dark, or
> dormant subsystems. They are intentionally retained. If you believe one should go, decide
> it deliberately and update this table.

| Symbol / artifact                                      | Location                                                                                                                                                              | Why it has no (full) caller                                                                                                                                             | Disposition                    |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `webhooks.ingest` billing seam                         | `convex/webhooks.ts`, `convex/http.ts`                                                                                                                                | The single inbound point for the future billing portal; HMAC + dedupe + `setMembership` are all live, but no portal calls it today.                                     | **Keep** (seam ready)          |
| Entire **Outline** subsystem                           | `convex/backends.ts` (outline branches), `convex/lib/backends/outline.ts`, `convex/backendServers.ts` (generic pool; Outline rows live there), admin server routes/UI | Fully wired but unreachable until `outline.enabled=true` + a server is registered. Within it: pool scoring uses a `latency*0` placeholder; `prometheusUrl` is reserved. | **Keep** (dormant)             |
| S3 mirroring (`storage.ts`)                            | `convex/storage.ts`, `convex/mirrorProviders.ts`, `convex/lib/issuance.ts`                                                                                            | Skipped entirely unless ≥1 active mirror provider is configured (admin CMS → Storage mirrors).                                                                          | **Keep** (dormant)             |
| `appState` table                                       | `convex/schema.ts`                                                                                                                                                    | Generic singleton key/value (e.g. tier-propagation cursors). Forward-compat for cursored sweeps.                                                                        | **Keep** (scaffolding)         |
| `components/ui/label/`, other unused shadcn primitives | `src/client/components/ui/`                                                                                                                                           | shadcn primitives are kept as a complete kit even when a given primitive has no current import.                                                                         | **Keep** (kit completeness)    |
| `fetchSubscriptionContent` (Remnawave/Outline)         | `convex/backends.ts`, `convex/lib/backends/*`                                                                                                                         | Only invoked when S3 mirroring is on; part of the backend interface contract regardless.                                                                                | **Keep** (interface + dormant) |

---

## How to keep this current

When you flip something Deferred/Dormant → Live, enable a dormant feature, or intentionally
retire a scaffold, update the relevant row here in the same change, and move security/bug
items into `deferred-security-bugs.md`'s "Recently resolved" section. The companion docs hold
the detail; this file is the index.
