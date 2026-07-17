# Project inventory: features, open work, and code status

**Updated 2026-07-16 (status page + referrals, branch `v2`).** Landed: the **public
network-status page** (`/status` — per-location online + coarse load bands, an
operator-curated country × connection-mode censorship-availability matrix, and
operator-published incidents, all CMS-editable; §1.7/§1.9); the member **node
surface** (the Access Pass shows the key's node label + location load band and
deep-links to `/status#loc-<code>`; the location picker shows load hints);
and the **referral program** (`FSR-…` share links, paid-conversion-gated
rewards: instant referee bonus + vested referrer bonus + monthly cap; §1.7).
Earlier: the 2026-07-16 locations + node-status + billing-hardening batch
(§1.5/§1.9), and the 2026-07-13 doc reconcile below.

**Updated 2026-07-13 (doc reconcile, branch `v2`).** Landed since the 2026-07-08 note:
**in-app donations** (membership add-on + standalone card funding a shared monthly
free-user bandwidth bonus, with GB-only public impact surfaces — §1.7 / `docs/billing.md`);
the **BTCPay** self-hosted Bitcoin rail (4th rail); **opt-in member passkeys** (§1.1);
the **DB-driven client catalog** gained `easeOfUse` + open-source/license metadata and
install-page links (refresh via operator-run `seed:refreshDefaultClients`); the
**account-number reveal** became a forced download + paste-back verify (§1.9); the
**Xray no-log hardening** admin card (§1.6 / `docs/backends.md`); the **site announcement
banner** (`site.*` settings); **`freeGrants` + `auditLog.ipHash` schema-dropped** (the
no-stored-IP work is complete — `docs/privacy.md`); the legacy `turnstileToken` fallback
removed; **i18n native-review packets** (`bun run i18n:review` → `translation-review/*.md`);
a WCAG pass (zero contrast failures; 44px mobile touch targets); and the Remnawave
update-user contract-safety fixes (pinned in `docs/backends.md`).

**Previous update 2026-07-08 (audit-fix pass, branch `v2`).** A full-pass audit + fixes landed:
(WS1) issuance never mints a squad-less Remnawave key — an unbound connection mode now
falls back across pools (mode → default → any bound) and `switchMode` rejects an unbound
target instead of tombstoning a live key; (WS2) **idle free users are deactivated + RETAINED,
never deleted** — a new `users.status:'inactive'` (login-reactivatable) + `users.freeKeyExpiresAt`
idle marker; the daily cron is now `deactivate-idle-free`, and operator-run `purgeInactiveFree`
is the only removal path; (WS3) `adminApi.statusSummary` reads a maintained `appState`
user-status counter (self-healed by a daily `user-counts-reconcile` cron) instead of an O(users)
scan that 500-ed the /status health-gate; (WS4) the fronted `/api/v1/sub` route sends
`Vary: User-Agent` (+ `private, no-store` for HWID requests); (WS5) `/api/v1/config` +
`/api/v1/e2ee/keys` are per-IP rate-limited; (WS6) removed dead migration-era symbols
(`tiers.list`/`listActive`, `BILLING_PROCESSORS`, `remnawaveNodes.stablePlacement`).

**Last reconciled against the code: 2026-07-13.** The note below is from the earlier
node-placement reconcile and still holds. **2026-07-07** (branch `v2`, after the node-placement
redesign — Phases 1–5a). That redesign replaced the earlier squad-pool "load balancing" (which
balanced nothing in a real fleet: a Remnawave internal squad is a set of inbounds, not a node)
with **issuance-time node placement**. The generic backend layer is now **squad-free** — it
carries an opaque **`placement` handle** (`subscriptions.backendPlacement`); only Remnawave-local
code maps it to a squad UUID. A **connection mode** (renamed from "connection profile"; `evade` /
`privacy`, data-driven with a `deliveryStyle` capability flag) binds a **pool of per-node squads**
(`remnawave.modePlacement.<id>.squads`), and issuance homes each new key to the **least-loaded
node** of that pool by node telemetry (`usersOnline` + optional realtime bandwidth, cached in
`remnawaveNodeStats` by the healthcheck cron); the pick is persisted so tier pushes never re-home
a live key. Remnawave specifics moved behind a namespaced admin surface — **Admin → Remnawave**
(`PATCH /api/v1/admin/remnawave/mode-placements` [`admin:servers:write`],
`GET /api/v1/admin/remnawave/node-stats` [`admin:servers:read`]) — while the generic mode
catalog (labels/description/default) stays at `PATCH /api/v1/admin/connection-modes`
(`admin:settings:write`). A one-time cutover migration copied live subs/users/settings onto
the new fields, after which the old fields (`subscriptions.remnawaveSquadUuid`,
`users.connectionProfileId`, `tiers.remnawaveSquadUuid`, the `remnawaveSquadStats` table) + the
migration itself were **removed** (Phase 5b). See `docs/backends.md` § "Node placement".

Earlier the pre-launch polish pass added: **connection-mode descriptions** — admin-editable
label + description that override the member picker's translated copy per-mode when set; per-
instance **`maxKeys` capacity caps**; the **device-limit enforcement toggle**
(`devices.enforcementEnabled`, default OFF = unlimited-by-default) that gates every
`hwidDeviceLimit` send, plus the **FCP-front HWID fix** — `GET /api/v1/sub/<token>` now
forwards `x-hwid`/`x-device-os`/`x-ver-os`/`x-device-model` so panel device registration +
enforcement work through the front, with app-compatibility gating in the connect UI; the
**privacy-by-default** hardening (explicit Caddy `log … output discard`, `RUST_LOG` request-
line silencing, Cap error-log/geo posture — see `docs/privacy.md`); a **Docker refresh**
(digest re-pins, valkey 8→9, a backup-sidecar healthcheck); and **first-deploy** fixes
(loud `convex env set` failures, the bootstrap secret printed every deploy).
Earlier: the full-audit pass:
the **retryable webhook dedupe claim** (a grant that throws no longer strands the event —
`webhookEvents.status` pending/processed/failed), member **device revocation**
(`POST /api/v1/account/devices/revoke`, Remnawave HWID), WebAuthn-challenge **retention
sweeps**, compose **resource limits**, rate limits on rotate + device-revoke, translated
member error codes, a lazy-loaded Cap widget, per-route titles + back/forward scroll
restoration, a proactive admin auth gate, membership-code pagination, rate-limit
reset-to-default, and URL-persisted admin filters; before that, the improvement-roadmap
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
- [`docs/secrets.md`](secrets.md): every secret/credential — who generates it (deployer auto-gen / `bun run bootstrap` / external), rotation, and blast radius.
- [`docs/billing.md`](billing.md): self-service membership purchases — self-upgrade + **gift codes** — and the USD off-ramp ops.

(Security-audit findings are tracked in the operator's private tracker, not in this repo;
report new issues via [`SECURITY.md`](../SECURITY.md).)

**Status legend**

| Tag             | Meaning                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------ |
| **Live**        | Wired and active in the default config.                                                    |
| **Dormant**     | Fully implemented and wired, but off by default behind a flag/setting. Keep it.            |
| **Deferred**    | Intentionally not built yet; a known follow-up. The seam/hook exists. Keep it.             |
| **Scaffolding** | Deliberately-retained forward-compat surface with no current caller. **Keep it** (see §3). |

---

## 1. Features

### 1.1 Identity & authentication: three schemes (+ opt-in member passkeys), NO OIDC

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
- **Member passkeys (opt-in)**: a member can additionally register WebAuthn passkeys as a
  convenience login (`POST /api/v1/auth/passkey/authenticate/*` also mints the normal
  `fs_session`); the account number remains the ONLY recovery credential, so losing every
  passkey costs nothing. Separate member-scoped tables (`memberPasskeyCredentials` +
  challenge tables with their own retention sweeps) keep the realms isolated from admin
  WebAuthn; RP display name via `WEBAUTHN_RP_NAME_MEMBER`. `convex/memberWebauthn.ts`
  (`"use node"`) + `convex/memberPasskeys.ts`; UI `PasskeyManager.svelte` (Account →
  Security + sign-up). **Live.**
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
  (`createFreeAccount`): mint user + reveal-once account number + support ID + the
  member's own referral code + member session; an optional `referralCode` in the body
  binds the account to its referrer (`referralApplied` in the response; §1.7 referrals).
  **Decoupled from proxy issuance**, so it never depends on a backend being available; the
  proxy key is created separately by the signed-in member (§1.4).
- **Serializable per-(IP, day) cap — no stored IP**: the cap is the ephemeral, serializable
  `freetier.create` rate-limit counter. `createFreeAccount` RESERVES a slot before creating the
  account; Convex's serializable OCC makes two concurrent creates conflict on the bucket row, so the
  cap holds exactly (closes the historical over-issuance race **by construction**,
  proven in `convex/freeTier.test.ts`). The hashed IP lives only in that auto-expiring counter — there is
  **no durable per-IP store** (the old `freeGrants.ipHash` ledger was removed; see `docs/privacy.md`).
- Cap reached (same IP, day): `cap_reached` (`{ ok:false, reason:'cap_reached' }`). There is no key
  to hand back, so the visitor signs in with their existing number. A compensating
  `rateLimits.release` gives the slot back if the mint/session step fails, so a transient error
  doesn't burn the IP's daily allowance.
- Fail-closed client-IP resolution (`convex/lib/http.ts`): `x-forwarded-for` right-anchored to
  the trusted end, taking `chain[len - hops]` where `hops` = `TRUSTED_PROXY_HOPS` (or `1` via the
  legacy `TRUSTED_PROXY=true`); `2`+ when a proxy fronts Caddy (Pangolin / CF Tunnel / ngrok / LB,
  with `CADDY_TRUSTED_PROXIES` set on the `web` service). `cf-connecting-ip` only when
  `CF_FRONTED=true` (a real Cloudflare edge in front, else it's client-spoofable); refuse on an
  unresolvable/too-short chain. Admin self-diagnostic: `GET /api/v1/admin/client-ip`. Caddy also
  strips client-supplied `CF-Connecting-IP` upstream as defense in depth.
- `deactivate-idle-free` daily cron reclaims idle free users' keys (backend + S3) and moves the
  row to `inactive` (RETAINED, login-reactivatable) — never deletes; operator-run `purgeInactiveFree` removes.

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
- **FCP-fronted subscription URL** (`GET /api/v1/sub/<token>`): the evade path hands the client an
  FCP-origin subscription URL (opaque per-sub `subToken`, rotates per key) instead of the backend
  panel URL, so the proxy app fetches config from us — hiding the backend origin, with a short
  User-Agent-keyed TTL cache (`subscriptions.subCache`) fronting the backend. Public/unauthenticated
  (the token is the capability); the SPA builds the URL from its own origin + the sealed `subToken`
  (`subscriptionDisplayUrl`), so no deployment-origin env is needed. Every member UI surface
  (account view + sign-up) fronts uniformly. Privacy members copy via sealed `/api/v1/subscription/content`. See
  `docs/backends.md` + `docs/threat-model-cdn-blinding.md`.
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
    server-side, only ever returned masked); **Remnawave** (per-mode node-placement squad pools —
    write-only UUIDs, with per-mode bound counts — + a read-only per-placement node-load
    table + the **Xray no-log hardening card**: dry-run `logging-status` / apply
    `harden-logging` against every panel config profile; §"Xray logging privacy harden"
    in `docs/backends.md`); **Billing** (per-rail config + a **readiness** check
    that flags enabled-but-misconfigured rails; §1.7); **Storage mirrors** (provider pool, §1.7);
    **Client apps** (the DB-driven recommended-client catalog — `convex/clients.ts`, `AdminClients.svelte`,
    `/admin/clients`; per-client `easeOfUse` (easy/moderate/advanced) + `openSource`/`license`/
    `sourceUrl` metadata and install-page `homepageUrl`s, sorted OSS-first-then-easiest; the
    defaults are re-synced by operator-run `seed:refreshDefaultClients`, which preserves
    `enabled` flags + admin-added rows); **Theme** (preset gallery + hue slider + live preview; §1.7); **Rate-limit policies**
    (W2); **Membership codes** (W4); **Status page** (`/admin/status` — publish/edit/
    resolve/delete incidents, curate the country × connection-mode censorship matrix,
    tune the load-band thresholds; scope `admin:servers:write`, routes
    `/api/v1/admin/status/{page,incidents}`); App settings (incl. the **Verification** panel — `setVerification` /
    `PATCH /api/v1/admin/verification`, surfaced in `E2eeVerifyModal` — and the **site
    chrome** block: the announcement banner + footer source link, `site.*` namespace in
    `convex/lib/siteConfig.ts`, `PATCH /api/v1/admin/site`, rendered by `SiteBanner.svelte`); **Audit log** (filter by action / actor / since).
- **IaC-addressable mutations** (for the Ansible role): idempotent **`PUT …/backend-servers/by-slug/{slug}`** + **`DELETE …/by-slug/{slug}`**, **`PUT …/tiers/by-slug/{slug}`**, and **`PUT
…/mirror-providers/by-name/{name}`**. Each is a single keep-secret-on-blank upsert; no
  client-side id resolution. Backed by `convex/adminApi.ts` / `convex/mirrorProviders.ts`.
  Node placement is bound separately via **`PATCH …/remnawave/mode-placements`**
  (`admin:servers:write`): the role creates one squad per node and binds each connection mode's
  pool there — per mode via full-replace `squadUuids` or the append/detach forms
  `addSquadUuids`/`removeSquadUuids` (so a node deploy adds/removes just itself; UUIDs stay
  write-only, server-side UUID-validated). (The by-slug tier upsert no longer carries a squad
  field — the old tier-level `remnawaveSquadUuid` bind was removed in Phase 5b; node placement
  is per connection mode.)

### 1.7 Integrations & runtime

- **Self-service membership billing** (`convex/billing.ts`, `convex/lib/processors/*`,
  `convex/lib/billingConfig.ts`; `docs/billing.md`): signed-in members buy a fixed-term
  membership via a hosted-redirect rail — **NOWPayments (crypto, Live)**, **BTCPay
  (self-hosted Bitcoin/Lightning; Greenfield invoices, `BTCPay-Sig` HMAC webhook,
  InvoiceSettled-only grant — `convex/lib/processors/btcpay.ts`)**, **Stripe (card)**
  and **PayPal** as phased adapters. `POST /api/v1/billing/checkout` mints an opaque
  `userId`-bound order (no payer PII stored) → processor invoice → `/api/webhooks/<processor>`
  verifies + dedupes + grants exactly once via `applyMembership`. Catalog/toggles in the
  `appSettings` `billing.*` namespace, edited in Admin → Billing. The SPA `UpgradeMembership`
  panel + `/account?order=<ref>` polling complete the loop. **Gift purchases**: the same
  checkout takes `orderKind:'gift'` + a `quantity` (1–50) and mints that many shareable,
  hash-only redemption codes bound to the buyer; the plaintexts reveal once
  (`GiftRevealModal`) and the `billing-gift-reveal-sweep` cron clears any un-acknowledged
  buffer (see `docs/billing.md`). **Code-complete (NOWPayments + BTCPay; Stripe/PayPal
  scaffolded behind admin toggles) but DORMANT by default** — `billingConfig` ships every rail `enabled:false`
  with placeholder prices, so no billing is active until an admin sets keys/prices and enables a
  rail. The USD off-ramp is a documented ops runbook (NOWPayments → USDC → Coinbase/Kraken → ACH).
- **Donations** (`convex/donations.ts`, `convex/lib/donationBonus.ts`; `docs/billing.md` §Donations):
  an optional add-on at membership checkout **and** a standalone give (`kind:'donation'`, no tier),
  on both `/account` and `/get-account` (`DonateCard` + `DonationAmountPicker`, shared amount UI).
  The donation rides the same processor charge; `billingOrders.donationCents` + the
  `billing.order.paid` audit + the admin billing log record how much. A first settled donation
  stamps `users.firstDonatedAt` → a persistent donor badge. Donations in a calendar month
  accumulate into a shared pool (`appState donation:freeBonus`) that raises **every free user's**
  monthly cap by `min(cap, monthDonatedUSD × rate)`, applied fleet-wide via Remnawave
  `bulk/update` (`donations.applyFreeBonus`, scheduled on grant + the hourly
  `donation-bonus-reconcile` cron) and reset to base at the month boundary. Config in
  `billing.donation.*` (Admin → Billing → Donations); DORMANT until billing is enabled + amounts set.
  **Impact dashboards:** a bounded per-month ledger (`appState donation:history`, 24 months,
  upserted by `recordDonation`) + a `freeActive` tally in the daily user-counts reconcile feed
  `publicConfig billing.donation.{freeUsersHelped,history}` (GB/user counts only — dollar totals
  are never public) and the member's own `donatedCentsTotal`/`donationCount` on the account view;
  rendered as dithered charts (`DitherChart.svelte`, hand-rolled Bayer-dither canvas, no chart
  lib) in the account impact panel (`MemberImpact.svelte`) and a home-page impact section.
- **Public network-status page** (`/status` + `GET /api/v1/status`, `convex/statusPage.ts` +
  `convex/lib/statusPage.ts` + `convex/lib/loadBands.ts`): per-location online bits +
  **coarse load bands** (`quiet/busy/crowded` — never raw user counts, the same
  privacy posture as GB-only donations), an operator-curated **censorship-availability
  matrix** (country × connection-mode, `status.censorship` + load thresholds in the
  `status.*` namespace), and **operator-published incidents** (`statusIncidents` table,
  location-scoped, public for 30 days post-resolution). All data reuses the existing
  healthcheck cron signals (`lastHealthOkAt`, `fleetStats`, `remnawaveNodeStats`,
  `keyCount`/`maxKeys`); nothing new is probed. Public + per-IP rate-limited
  (`status.fetch` policy). The member surfaces link in: the Home `NetworkStatus` strip
  links to `/status`, and the Access Pass shows the key's **node label + load band** and
  deep-links to `/status#loc-<code>` (`account.getNodeStatus` gained `load`); the
  location picker shows per-location load hints (`LocationEntry.load` on
  `publicConfig.locations`). **Live.**
- **Referral program** (`convex/referrals.ts` + `convex/lib/{referralCode,referralConfig}.ts`):
  word-of-mouth growth. Every member gets a shareable `FSR-XXXX-XXXX` code
  (`users.referralCode`, lazily backfilled, non-secret); `?ref=` links captured into
  localStorage bind at account creation (`POST /api/v1/account` takes an optional
  `referralCode` — an invalid code never blocks signup; one referrer per referee).
  Rewards fire ONLY on the referee's **first paid-tier grant** (any rail — billing,
  gift/redemption code, admin grant — via the `applyMembership` hook; grants made BY
  referral rewards deliberately don't cascade): the referee gets bonus days instantly,
  the referrer's bonus **vests** after `referral.vestingDays` while the referee stays a
  member, bounded per calendar month (`referral.maxRewardsPerMonth`). Config in the
  `referral.*` namespace (Admin → Billing "Referral program" card,
  `/api/v1/admin/referrals/config`; default ON — needs no external keys); public knobs
  on `publicConfig.referrals`; member card on the Account page
  (`GET /api/v1/account/referrals`, rate-limited `account.referrals`). Audits
  `referral.{bound,converted,rewarded,void}`. **Live.**
- **Billing webhook seam** (legacy/ops): `POST /api/webhooks/billing` (`convex/webhooks.ts`),
  HMAC-SHA256-verified (`WEBHOOK_SIGNING_SECRET`) + deduped by `eventId` (`webhookEvents`
  table) → maps `{accountId, tierSlug, expiresAtMs?}` onto `lifecycle.setMembership`. Kept as
  a generic inbound entitlement seam alongside the self-service rails above. The dedupe row is
  a **status-tracked claim** (`pending → processed | failed`, shared with the processor
  webhooks): a grant that throws leaves the event retryable instead of silently ACKing the
  sender's retry as a duplicate. **Live.**
- **Member device revocation** (`convex/account.ts:revokeDevice` + `convex/backends.ts` +
  `POST /api/v1/account/devices/revoke`): a member frees one HWID slot from the Account page
  (ownership-checked against their own key, confirmation-gated, rate-limited via the
  `account.device-revoke` policy) instead of the nuclear full-key regenerate. Remnawave only
  (Outline has no device concept → typed 409). **Live.**
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
  language switcher, Persian/Arabic-Indic digit normalization. **Translations are human-only
  (policy, 2026-07-15):** the Google-backed `i18n:translate` machine-translate script was
  removed — no third-party services in the translation pipeline (the existing first-pass
  locale fills predate the policy and are being replaced by the native review). New strings
  ship English-fallback in fa/ar/ru/zh until a native reviewer fills them via the review
  packets. Critical journey strings done. `bun run i18n:review`
  (`scripts/i18n-review-packet.ts`) generates the per-locale native-review packets in
  `translation-review/*.md` (English-vs-current tables per namespace, missing keys flagged,
  ICU plurals per variant, reviewer instructions); the human review pass is in progress.
  **Live (English authoritative; other locales first-pass MT pending native review).**
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
  `lastHealthOkAt` + rtt (feeds pool selection); for Remnawave, also refresh the
  `remnawaveNodeStats` node-load cache that feeds issuance-time node placement.
- `deactivate-idle-free` (daily 03:00 UTC): deactivate + RETAIN idle free users (reclaim key →
  `status:'inactive'`; paginated over `by_tier_status_freekey`). Never deletes.
- `user-counts-reconcile` (daily 04:00 UTC): recompute the `appState` user-status counter (self-heal).
- `session-sweep` / `rate-limit-sweep` / `replay-guard-sweep` (daily): drop expired
  `sessions` / `rateLimits` / `replayGuard` rows.
- `epoch-key-rotate` (10 min) / `epoch-key-sweep` (daily): CDN-blinding HPKE epoch keys.
- `admin-invite-sweep` (daily): drop expired admin-invite tokens (multi-admin onboarding).
- `retention-audit` / `retention-webhooks` / `retention-tier-history` /
  `retention-subscriptions` / `retention-billing-orders` /
  `retention-webauthn-auth` / `retention-webauthn-reg` /
  `retention-member-webauthn-auth` / `retention-member-webauthn-reg` (daily): bounded
  deletes of the append-only tables past their retention window (P2; the WebAuthn
  challenge sweeps — admin and member — close the last unswept-table gap).
- `donation-bonus-reconcile` (hourly): re-cap the free fleet's traffic limits from the
  shared donation bandwidth bonus (bulk update ≤500 uuids/chunk; handles the month roll).
- `billing-pending-sweep` (15 min): expire abandoned membership checkouts (never grants).
- `billing-gift-reveal-sweep` (hourly): clear the transient plaintext gift-code reveal from
  paid gift orders the buyer never acknowledged, so plaintext never lingers at rest (the
  codes stay hash-only in `redemptionCodes`).
- `mirror-refresh` (6h): re-fetch + re-upload active subscription mirrors (no-op unless S3
  mirroring is configured).

Every sweep stamps a per-cron heartbeat (`convex/cronHeartbeat.ts`, `cronHeartbeats` table,
stamped at start) surfaced as a freshness panel on the admin dashboard.

### 1.9 Frontend SPA (Svelte 5 runes): **Live**

- Public: `Home`, `GetAccount` (Cap widget + backend chooser radiogroup when dual-backend on;
  the reveal-once account number is a blocking two-step `AccountNumberReveal` modal — the
  save step requires clicking **Download** before Continue, then a verify step hides the
  number and requires pasting the 32 digits back before Done (plus copy + `beforeunload`);
  the per-platform, catalog-driven `ConnectClient` section after issuance), `Account` (member
  view + regenerate / switch-backend / switch-mode / rotate / **redeem code** / support-ID
  display / opt-in passkeys / **referrals card**), `Login` (account-number sign-in: show/hide,
  password-manager autofill, digit normalization; passkey sign-in when one is registered),
  and **`Status`** (the public network-status page: location cards with online + load-band
  badges, the censorship-availability matrix, and incidents — deep-linkable per location
  as `/status#loc-<code>`).
  `Home` + `GetAccount` show loading **skeletons** (no config-gated/auth-state content flash);
  the `Account` page surfaces a calm account-number **recovery** hint (rotate if you didn't save
  it). Localized via `lib/i18n`; a `LanguageSwitcher` in the header.
- **Admin CMS is deliberately English-only** (decision 2026-07-01): operators are
  English-speaking, so the 29 admin `.svelte` files bypass the Paraglide catalog entirely.
  This is an intentional inconsistency with the fully-translated member surface, not an
  oversight — don't file it as an i18n gap, and don't route admin strings through `t()`
  without revisiting the decision here.
- Admin (lazy-loaded behind `AdminRouter`): `AdminEntry`/`AdminLogin`/`AdminBootstrap`/`AdminLayout`
  - **Dashboard** / Tiers / Users / **Admins** / Tokens / BackendServers / **Remnawave** /
    **Clients** / **Billing** / **Storage** mirrors / **RateLimits** / **MembershipCodes** /
    **Theme** / Settings / Audit pages + editors/modals. Custom History-API router; all data via TanStack Query + the
    zod-validating `apiClient` (`lib/api.ts`, `lib/queries.ts`); errors localized via `lib/errors.ts`.

---

## 2. Open work / to-dos

There are **no `TODO`/`FIXME` markers in `convex/` or `src/`**; open work lives here and in
the companion docs. Sizes: S/M/L.

| Item                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Size | Where it's tracked                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | ------------------------------------------------------------------- |
| **Self-service billing**: the crypto rails (NOWPayments, **BTCPay** — self-hosted Bitcoin/Lightning) are **Live**; **Stripe + PayPal** are implemented, wired, unit-tested, and **sandbox-dry-run-verified** (2026-07 operator pass) — enabling them is now just the admin toggle. Remaining is the non-code launch checklist: NOWPayments US-nonprofit ToS confirmation + opening the USDC→Coinbase/Kraken→ACH off-ramp account (the runbook itself is documented in `docs/billing.md`). Admin → Billing flags enabled-but-misconfigured rails (a client-side **readiness** check); a **live per-processor credential probe** (an actual API ping, beyond readiness) is a deferred follow-up.                                  | M    | `docs/billing.md`, this file (§1.6/§1.7)                            |
| **Native-speaker translation review** + extracting remaining marketing copy into i18n keys (the non-English locales are a first-pass MT; the critical journey strings are done).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | M    | this file (§1.7), `.claude/plans/`                                  |
| ~~**`POP_REQUIRED` flip** + **PoP `sid`-binding**~~ — **both DONE**: the flip is live on beta (2026-07-13), and sid-binding shipped 2026-06-28 as the public per-session token (`sessions.popSessionToken`, folded into the canonical PoP message — see `convex/lib/pop.ts` + the threat model). Kept here one release as a tombstone since earlier notes listed them open.                                                                                                                                                                                                                                                                                                                                                     | —    | `docs/threat-model-cdn-blinding.md`                                 |
| **Paid cross-backend switch — portal tier model**: the linkage MECHANISM shipped (`tiers.peerTierId` + `tiers.getPeerTier`; `account.switchBackend` 409s only when NO peer tier is linked, with an actionable message). What remains is the linked-tier model design once a billing portal exists, and actually linking paid peers in the CMS.                                                                                                                                                                                                                                                                                                                                                                                  | M    | `convex/account.ts`                                                 |
| **Outline WSS `accessUrl` / `ssconf://` contract** (latent): needs the FreeSocks Outline fork's real WSS create-key response shape before any WSS server is routed to.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | M    | `docs/outline-setup.md`                                             |
| **Status-page hardening follow-ups** (deferred by design): auto-derived incidents from healthcheck flapping (too noisy — incidents are operator-published only), public uptime %/SLA math (needs durable health history we deliberately don't keep), and automated censorship-matrix probing (needs in-country vantage points).                                                                                                                                                                                                                                                                                                                                                                                                 | M    | `convex/lib/statusPage.ts`                                          |
| **Admin referral drill-down**: referral events are audit-visible today (`referral.*`); a per-user referral view in the CMS is a follow-up if operators want it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | S    | `convex/referrals.ts`                                               |
| **Deferred P2 perf/scale** (from the 2026-07 pre-launch review — its P0/P1 bug fixes + P3 cleanups all landed): (a) retention sweeps drain a single 1000-row page/day — loop pages via an action wrapper (Convex per-mutation write limits rule out an in-mutation loop) once any table sustains >~1000 rows/day; (b) `appSettings.resolved` does a full-table `collect()` on hot paths, though it already filters to `SETTINGS_DEFAULTS` keys (so per-key indexed reads would be a drop-in) — low benefit on a ~dozens-of-rows table, worth it only if that table grows large. (The third item — `statusSummary`'s O(users) scan — shipped in the 2026-07-08 WS3 counters and is no longer open.) Both are fine at beta scale. | M    | this file (`retention.ts` PAGE constant, `appSettings.ts` resolved) |

---

## 3. Code status register: scaffolding, dormant & deferred

> **Read this before deleting anything as "dead code."** Several symbols have no current
> caller **by design**: forward-compat hooks, feature foundations shipping dark, or
> dormant subsystems. They are intentionally retained. If you believe one should go, decide
> it deliberately and update this table.

| Symbol / artifact                                      | Location                                                                                                                                                              | Why it has no (full) caller                                                                                                                                                                                          | Disposition                   |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| `webhooks.ingest` billing seam                         | `convex/webhooks.ts`, `convex/http.ts`                                                                                                                                | The single inbound point for the future billing portal; HMAC + dedupe + `setMembership` are all live, but no portal calls it today.                                                                                  | **Keep** (seam ready)         |
| Entire **Outline** subsystem                           | `convex/backends.ts` (outline branches), `convex/lib/backends/outline.ts`, `convex/backendServers.ts` (generic pool; Outline rows live there), admin server routes/UI | Fully wired but unreachable until `outline.enabled=true` + a server is registered. Within it: `prometheusUrl` is reserved. (Pool scoring now uses real `lastHealthRttMs` — the old `latency*0` placeholder is gone.) | **Keep** (dormant)            |
| S3 mirroring (`storage.ts`)                            | `convex/storage.ts`, `convex/mirrorProviders.ts`, `convex/lib/issuance.ts`                                                                                            | Skipped entirely unless ≥1 active mirror provider is configured (admin CMS → Storage mirrors).                                                                                                                       | **Keep** (dormant)            |
| `appState` table                                       | `convex/schema.ts`                                                                                                                                                    | Generic singleton key/value (issuance lock, the `stats:userCounts` user-status counter, tier-propagation cursors).                                                                                                   | **Keep** (live + scaffolding) |
| `components/ui/label/`, other unused shadcn primitives | `src/client/components/ui/`                                                                                                                                           | shadcn primitives are kept as a complete kit even when a given primitive has no current import.                                                                                                                      | **Keep** (kit completeness)   |
| Dev **mock backend**                                   | `convex/lib/backends/mock.ts`                                                                                                                                         | Short-circuits every dispatch op so the full issuance/account flow works locally with no real instance. Double-gated: `DEV_MOCK_BACKEND=true` AND `ENVIRONMENT=development`.                                         | **Keep** (dev scaffolding)    |
| `fetchSubscriptionContent` (Remnawave/Outline)         | `convex/backends.ts`, `convex/lib/backends/*`                                                                                                                         | **Live** — the FCP-fronted `GET /api/v1/sub/<token>` serves member config through it (also the S3 mirror path). Part of the backend interface contract.                                                              | **Live**                      |

---

## How to keep this current

When you flip something Deferred/Dormant → Live, enable a dormant feature, or intentionally
retire a scaffold, update the relevant row here in the same change, and record resolved
security/bug items in the operator's private audit tracker. The companion docs hold
the detail; this file is the index.
