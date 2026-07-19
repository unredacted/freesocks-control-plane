# Backend abstraction

The control plane talks to N proxy backends through one generic dispatch layer + a provider
registry. This document describes the two core concepts (backend _types_ vs _instances_), how
dispatch works, and what's required to add another backend.

## Two concepts: type vs instance

- A **backend type** is the proxy software the control plane knows how to drive: `remnawave`,
  `outline`, and any future `wireguard` / `3x-ui` / .... The set of types lives in one place,
  `BACKEND_IDS` in `src/shared/contracts/backends.ts`; every `BackendId` union (client zod, server
  TS, the Convex validators) derives from it.
- A **backend instance** is one deployed server of a given type, with its own connection config +
  secret. Instances are rows in the **`backendServers`** table and are managed in the admin CMS
  ("Backend servers"). Remnawave and Outline both have instances; a type can have many.

This split is what makes the system multi-backend: instance _management_ (pool selection at
issuance, key->instance resolution, health, load counters) is fully generic, and only the per-type
wire protocol is pluggable.

## Shape: a generic dispatch + a provider registry

1. **The provider registry** (`convex/lib/backends/registry.ts`). A `BackendProvider` is the set of
   pure operations for one type; `PROVIDERS` maps each `BackendId` to its provider (keying by
   `BackendId` keeps the map exhaustive at compile time):

   ```ts
   interface BackendProvider<C> {
     issue(config, spec) -> IssuedUser
     get(config, backendUserId) -> UserState
     update(config, backendUserId, patch) -> void
     resetTraffic(config, backendUserId) -> void
     remove(config, backendUserId) -> void
     removeDevice?(config, backendUserId, hwid) -> void   // optional: revoke one HWID device
     setStatus?(config, backendUserId, active) -> void    // optional: enable/disable
     fetchContent(config, backendShortId, ua?) -> SubscriptionContent
     health(config) -> { keyCount: number | null, rttMs }
     testConnection(config) -> { ok, keyCount } | { ok:false, error }
   }
   const PROVIDERS: Record<BackendId, BackendProvider> = { remnawave, outline }
   ```

   `config` is the instance's `backendServers.config` (a variant of the schema's discriminated
   `backendServerConfig` union). The shared TS types (`IssueUserSpec`, `IssuedUser`, `UserState`,
   `UpdateUserPatch`, `SubscriptionContent`) live in `convex/lib/backends/types.ts`.

2. **Pure HTTP functions** in `convex/lib/backends/<id>.ts` that take a resolved config and `fetch`.
   No DB access. The provider object in the registry is a thin adapter over them. Reference:
   `convex/lib/backends/remnawave.ts` + `convex/lib/backends/outline.ts`.

3. **The generic instance module** `convex/backendServers.ts` (internal queries/mutations): the
   scored pool pick (`pickCandidatesForIssue`, filtered by backend type), key->instance resolution
   (`resolveKeyServer` via `subscriptions.backendServerId`), `bumpKeyCount`, the per-type
   `healthcheck` action (cron), and `markHealthy`. This is shared by all types.

4. **The dispatch** `convex/backends.ts` (six `internalAction`s). It resolves an instance, then calls
   `PROVIDERS[instance.backend].<op>(instance.config, ...)`. There are no per-backend `if` arms and
   no env-based config.
   - `issueUser({ backend, spec })` dispatches on the tier's backend **type**, picks an active
     instance of that type from the scored pool (random among the top candidates; the CSPRNG pick
     lives in the action, not the query), issues, bumps the instance's key count, and returns the
     chosen `backendServerId` (the saga persists it on the subscription).
   - `getUser` / `updateUser` / `resetUserTraffic` resolve the instance from the subscription row by
     `backendUserId`. The passed `backend` arg is vestigial (the resolved instance is authoritative).
   - `deleteUser` + `fetchSubscriptionContent` also accept a `backendServerId` hint for the points in
     the saga where no subscription row exists yet (issuance compensation + the S3 mirror fetch).

The contract stays permissive about per-type differences: `issueUser` takes a superset `spec` and
each provider applies what it supports (Outline drops `hwidDeviceLimit` / `trafficLimitStrategy` /
the opaque `placement` handle); `updateUser` is a sparse PATCH; `getUser` returns a normalized `UserState`
and the read path is fault-tolerant (an unresolved key returns a sentinel `active/unknown` state
rather than 500-ing `/account`); `fetchSubscriptionContent` lets each type decide what "content" is
and is only called when S3 mirroring is on.

A dev **mock backend** (double-gated: `DEV_MOCK_BACKEND=true` AND `ENVIRONMENT=development`,
`convex/lib/backends/mock.ts`) short-circuits every dispatch op so the full issuance + account flow
works locally without any real instance.

## Where dispatch is called from

Higher-level code never calls `fetch` directly; it runs the dispatch actions:

- **Issuance** goes through `issueNewSubscription` in `convex/lib/issuance.ts`, which calls
  `internal.backends.issueUser` (and, with mirroring on, `fetchSubscriptionContent` +
  `internal.storage.mirrorContent`), then persists the row including `backendServerId`.
- **Tier propagation** (`convex/lifecycle.ts -> pushTierToBackend`) calls
  `internal.backends.updateUser`; the **grace/disable sweep** + admin enable/disable call
  `internal.backends.setUserStatus` (Remnawave's dedicated `/actions/{enable|disable}`), and member
  **device revocation** calls `internal.backends.revokeDevice`.
- **Teardown** (`deleteSubscriptionEverywhere`, used by free-tier cleanup + the tombstone sweep)
  calls `internal.backends.deleteUser`.
- **`/account` reads** call `internal.backends.getUser`.
- **The FCP-fronted subscription URL** (`GET /api/v1/sub/<token>`, `convex/http.ts`) calls
  `internal.backends.fetchSubscriptionContent` to serve the member's config from our own origin
  instead of the backend panel URL. Public + unauthenticated (the opaque per-sub `subToken` is the
  capability), with a short server-side TTL cache on `subscriptions.subCache` keyed by User-Agent
  (Remnawave formats config by UA). It forwards the caller's UA and re-emits the allowlisted
  `subscription-userinfo` / `profile-*` headers `fetchContent` returns (`SubscriptionContent.headers`),
  so the fronted URL is a faithful stand-in. `getAccountView` returns the raw backend URL + the opaque
  `subToken` (both in the sealed reveal-leg); the SPA builds the fronted `<origin>/api/v1/sub/<token>`
  URL client-side (`subscriptionDisplayUrl` in `src/client/lib/utils.ts`), so no deployment-origin env
  is needed and every UI surface fronts uniformly. Privacy members still copy via the sealed
  `/api/v1/subscription/content`. See `docs/threat-model-cdn-blinding.md`.

### The `backend` discriminator: where it lives

- `BACKEND_IDS` (`src/shared/contracts/backends.ts`): the one list of backend types.
- `tiers.backend`: the type a tier issues **against** (what `issueUser` dispatches on). Free tiers
  can come in pairs (one per type, both `isDefaultFree`); the subscription endpoint picks the
  matching default-free tier from the user's choice (or the admin default).
- `subscriptions.backend` + `subscriptions.backendServerId`: the type that **issued** this row and
  the **instance** it lives on. Both stay put even if the tier later moves to a different type
  (existing users keep their backend until they regenerate or switch).

## Instances + config (the admin-managed half)

Each `backendServers` row is `{ backend, name, slug, config, isActive, priority, keyCount,
lastHealthOkAt, lastHealthRttMs }`. `config` is a discriminated union carrying the per-type
connection secret:

- `remnawave`: `{ baseUrl, apiToken }`
- `outline`: `{ apiUrl, websocketEnabled, websocketDomain?, prometheusUrl? }` (the `apiUrl` embeds a
  secret path segment)

Admins add/edit/remove instances + run a pre-save test-connection in the CMS ("Backend servers");
the secret is **never returned** to the SPA (responses mask it: `apiUrlMasked` for Outline,
`apiTokenSet: boolean` for Remnawave). On edit, the secret field is blank and only re-submitted to
rotate it — **Test connection** still works with the field blank: the request carries the instance
`id` and `testBackendConnection` merges the **stored** credentials server-side (typed fields
override stored ones), so secrets never round-trip to the client.

**Pool scoring**: `pickCandidatesForIssue` prefers instances health-checked within ~30 min (else
falls back to all active), then scores `latency_weight * lastHealthRttMs + key_count_weight *
keyCount`, then admin `priority`. Weights are admin-tunable via the `backend.scoring.*` settings.
The `backend-healthcheck` cron pings every active instance through its provider's `health` probe
and stamps `lastHealthOkAt` + rtt (+ key count for types that report one, i.e. Outline). For
Remnawave instances it also refreshes the `remnawaveNodeStats` node-load cache (via the
provider's `getNodeStats`) that feeds issuance-time node placement (see "Node placement").

**Bootstrapping Remnawave from env**: the cutover seed (`seed:seedCutover`) creates the first
Remnawave instance from `REMNAWAVE_BASE_URL` / `REMNAWAVE_API_TOKEN` if they are set, as a one-time
bridge. After that, instances are DB-managed and the env vars can be removed. A fresh install can
skip the env entirely and add every instance in the CMS.

## Adding a backend type

1. **Add the id** to `BACKEND_IDS` in `src/shared/contracts/backends.ts`, the `backendId` literal +
   a `backendServerConfig` variant in `convex/schema.ts`, and the inline `backendId` validators in
   `convex/backends.ts` / `convex/backendServers.ts` / `convex/adminApi.ts` (kept in sync via the
   comment that points back to `BACKEND_IDS`).
2. **Write the pure HTTP functions** at `convex/lib/backends/<id>.ts` (mirror `remnawave.ts`),
   including a `health` + `testConnection`. Custom error classes must NOT capture URLs or secrets
   (see `OutlineApiError` / `RemnawaveApiError`, which record only status + path).
3. **Add a provider + a config type** in `convex/lib/backends/registry.ts` and register it in
   `PROVIDERS` (the `Record<BackendId, ...>` makes a missing provider a compile error).
4. **Add an enable toggle + label** to `SETTINGS_DEFAULTS` in `convex/appSettings.ts`
   (`'<id>.enabled': false` + an entry in `subscription.backend_labels`). Defaulting `enabled` to
   `false` keeps the type dark until an admin turns it on; the free-tier + switch-backend paths
   check `settings['<id>.enabled']` before dispatching.
5. **Surface in the admin UI**: add the type's fields to `BackendServerEditor.svelte` (the type
   select already iterates `BACKEND_IDS`) and add the option to the tier backend `<Select>` in
   `TierEditor.svelte`.
6. **Tests**: unit-test the pure HTTP functions with a stubbed `fetch` (mirror `remnawave.test.ts`),
   and add a `convex-test` case that issues through the dispatch (mirror `backendServers.test.ts`).

Most domain code needs no changes; it already dispatches through `convex/backends.ts`.

## Remnawave API contract (pinned)

The Remnawave provider (`convex/lib/backends/remnawave.ts`) targets these exact routes, verified
against the upstream contract in `remnawave/backend` (`libs/contract/api/{routes,controllers}.ts` +
the NestJS controllers) on the **2.x** line. If you self-host a different panel version, confirm
these still match. The provider tests assert the paths, so a drift here fails CI — this is the guard
that was missing when the `PATCH /api/users/{uuid}` / `/api/hwid-devices` mismatches shipped (they
"passed" only because the tests mocked the wrong paths too).

| Op              | Method + path                                                                                                                         | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| issue           | `POST /api/users`                                                                                                                     | body carries `activeInternalSquads: [placement]` — the generic `placement` handle mapped to a squad UUID (see "Node placement")                                                                                                                                                                                                                                                                                                                                                                               |
| get             | `GET /api/users/{uuid}`                                                                                                               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| update          | `PATCH /api/users`                                                                                                                    | **`uuid` is in the request BODY, not the path** (the route has no path param; the DTO requires `uuid` or `username`). The DTO takes `.optional()` NOT `.nullable()` for `trafficLimitBytes`/`expireAt`/`hwidDeviceLimit`, and refuses past expiry dates — the provider coerces `null` traffic → `0` (the panel's unlimited sentinel), omits a `null` expireAt or `null` hwidDeviceLimit (no clear semantics on update), and clamps a past expireAt to now+5min (FCP's grace sweep governs actual disablement) |
| set status      | `POST /api/users/{uuid}/actions/{enable\|disable}`                                                                                    | dedicated action endpoints, not a `status` field on update. **NOT idempotent panel-side**: enable on an ACTIVE user 400s (`A030 "User already enabled"`), disable on a disabled user 400s (`A029`) — the provider swallows the matching-direction rejection (set-semantics), since the tier push unconditionally re-enables before every update                                                                                                                                                               |
| reset traffic   | `POST /api/users/{uuid}/actions/reset-traffic`                                                                                        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| delete          | `DELETE /api/users/{uuid}`                                                                                                            | a 404 is treated as success (idempotent teardown)                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| list devices    | `GET /api/hwid/devices/{userUuid}`                                                                                                    | the HWID controller is `/api/hwid`; `userUuid` is a **path** param (not `?userUuid=`)                                                                                                                                                                                                                                                                                                                                                                                                                         |
| delete device   | `POST /api/hwid/devices/delete`                                                                                                       | body `{ userUuid, hwid }`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| user usage      | `GET /api/bandwidth-stats/users/{uuid}?start&end`                                                                                     | member usage trend; **aggregate only** — the per-node `series`/`topNodes` are dropped (privacy)                                                                                                                                                                                                                                                                                                                                                                                                               |
| fleet stats     | `GET /api/system/stats` + `GET /api/system/stats/recap`                                                                               | admin dashboard (online / nodes / countries / traffic + panel `version`); cached by the healthcheck cron                                                                                                                                                                                                                                                                                                                                                                                                      |
| node stats      | `GET /api/internal-squads` + `…/{uuid}/accessible-nodes` + `GET /api/nodes` (+ best-effort `GET /api/bandwidth-stats/nodes/realtime`) | per-squad node load (usersOnline / online / realtime bytes) → the issuance-time node-placement picker; cached in `remnawaveNodeStats` by the cron                                                                                                                                                                                                                                                                                                                                                             |
| bulk update     | `POST /api/users/bulk/update`                                                                                                         | body `{ uuids, fields }`, uuids chunked ≤500 per call; used by the donation free-bandwidth re-cap (`donations.applyFreeBonus` — see `docs/billing.md`)                                                                                                                                                                                                                                                                                                                                                        |
| config profiles | `GET /api/config-profiles` + `PATCH /api/config-profiles`                                                                             | the Xray logging privacy harden (see below); PATCH is a **full-replace** of one profile's `config`, so the provider always GET-merges first                                                                                                                                                                                                                                                                                                                                                                   |
| sub content     | the public subscription URL (or `/api/sub/{shortUuid}`)                                                                               | fetched with NO admin token; forwards the client's `user-agent` + HWID headers (see "HWID / device limits" below)                                                                                                                                                                                                                                                                                                                                                                                             |

Most responses are wrapped in `{ response: ... }`; the provider's `unwrap()` tolerates both wrapped
and bare. HWID device metadata is surfaced as `platform` / `deviceModel` / first-seen / last-seen
(mapped from `createdAt` / `updatedAt`); the device `requestIp` and `userAgent` are deliberately
**not** read (metadata minimization). Subscription content is fetched from the panel's public
subscription URL, not an admin API route.

**Token scopes.** The FCP panel token needs, beyond user + HWID management, the **read** scopes
`user-usage:read`, `stats:read`, and `recap:read` for the usage/fleet observability, plus
**node-read** (`nodes:read` / `internal-squads:read`) for the node-placement telemetry
(`getNodeStats`). All the observability additions are read-only, so keep the token
least-privilege — none of them write. If the node-read scope is missing, `getNodeStats`
fail-softs (empty stats) and the placement picker degrades to declaration order — keys still
issue, they just stop favoring the emptier node. Two features DO write beyond user management:
the **config-profiles read+write** scope for the logging harden below, and the **bulk user
update** used by the donation re-cap — grant them only if you use those features.

## Xray logging privacy harden (Config Profiles)

Admin → Remnawave has a fleet-wide **no-log enforcement** card backed by two routes
(`admin:servers:read` / `admin:servers:write`):

- `GET /api/v1/admin/remnawave/logging-status` — dry-run: fetches every config profile and
  reports, per profile, whether the Xray `log` block + `policy.levels."0".statsUserOnline`
  already match the privacy posture (`docs/privacy.md` §5: `access:"none"`, `loglevel:"none"`,
  `dnsLog:false`, `maskAddress:"full"`, `statsUserOnline:false`).
- `POST /api/v1/admin/remnawave/harden-logging` — applies it: for each non-compliant profile the
  provider (`hardenXrayLoggingConfig` in `remnawave.ts`) GETs the profile, merges ONLY the
  `log` + `policy` keys, and PATCHes the full config back. It **refuses a profile with no
  inbounds** (a malformed read must never wipe a config), and the compliance check compares
  **field-by-field, never by JSON string** — the panel stores configs in Postgres `jsonb`,
  which canonically reorders object keys, so a stringify-compare reports false drift forever.
  Applying restarts the affected nodes (Xray reloads config); it is idempotent — re-applying a
  compliant fleet is a no-op.

This covers the panel-config half of the no-log posture; the node-container logging driver and
the Reality/inbound settings remain the province of `ansible-role-freesocks` (see
`docs/privacy.md` §5).

## Testing the Remnawave integration against a real panel

The fast suite (`bun run test`) mocks `fetch`, so it can't catch a wrong endpoint path
or a response-shape drift — it only proves the code matches _our own_ mock. The
**integration test** closes that gap by driving the real provider (`remnawave.ts`)
against a **live Remnawave panel**:

```
bun run test:integration:remnawave     # needs Docker
```

That one command (`scripts/remnawave-integration.sh`) stands up an ephemeral panel
(`docker-compose.remnawave-test.yml`, pinned to the latest Remnawave release + Postgres 18),
bootstraps an admin + mints an API token (`scripts/remnawave-test-bootstrap.mjs`), runs
`convex/lib/backends/remnawave.integration.test.ts` (the full user lifecycle: issue → get →
update → enable/disable → reset-traffic → delete), then tears the panel down. It's excluded
from the fast suite (`vitest.integration.config.ts`; gated on `REMNAWAVE_TEST_URL` +
`REMNAWAVE_TEST_TOKEN`), so it never blocks CI unless explicitly run.

Two Remnawave quirks the harness handles (both bit us / would bite a naive caller):

- **Proxy guard.** The panel's `ProxyCheckMiddleware` rejects any request without
  `X-Forwarded-Proto: https` + `X-Forwarded-For`. A Caddy sidecar injects them —
  mirroring the beta/prod topology (FCP → reverse proxy → panel), so the provider is
  tested **unmodified**. In production the same headers come from the real TLS proxy.
- **Controller names ≠ OpenAPI resource labels.** The HWID controller is `/api/hwid`
  (not `hwid-user-devices`) and the API-tokens controller is `/api/tokens` (not
  `api-tokens`). Trust the NestJS `@Controller()` string, not the `resource` label.
- **Dashboard vs API auth.** Minting a token uses an admin JWT + an
  `X-Remnawave-Client-Type: browser` header; FCP's own runtime token is a ROLE.API
  token that skips that check.

When adding a new backend read/write (§"Adding a backend type"), extend the integration
test so the real contract stays pinned by an executable check, not just a comment.

## Node placement (issuance-time, Remnawave)

FCP's instance pool (`convex/backendServers.ts`) spreads keys across distinct
backend-server rows by score (`latency_weight*rtt + key_count_weight*keyCount`,
admin-tunable) and skips instances at their optional `maxKeys` cap (all-at-capacity
→ the retryable `backend.unavailable`). That's the **generic** capacity layer.

Remnawave adds a second, **Remnawave-local** layer: which **node** a key lands on.
Remnawave has no entry-node balancer — a key's node is decided by which **internal
squad** it's assigned to, and the operator models **one internal squad per node**
(via Ansible). So FCP does one-time, **sticky-per-key node placement** at issuance:
home each new key to the emptiest node.

The generic layer stays backend-agnostic: it carries an opaque **`placement`
handle** (a `string`) end to end (`IssueUserSpec.placement`, persisted as
`subscriptions.backendPlacement`). Only Remnawave-local code interprets it as a
squad UUID (`activeInternalSquads: [placement]`); Outline ignores it. Nothing in
`lib/backends/{types,registry}.ts`, `backends.ts`, `issuance.ts`, or
`subscriptions.ts` mentions "squad".

How a placement is chosen (all Remnawave-local, under `convex/remnawaveNodes.ts` +
`convex/lib/remnawavePlacement.ts`):

- A **connection mode** (`evade` / `privacy`, data-driven — see
  `convex/lib/connectionModes.ts`) binds a **pool** of squad UUIDs, stored in
  `appSettings` under `remnawave.modePlacement.<id>.squads`. Bind it in
  **Admin → Remnawave** (one UUID per line, per mode) or via
  `PATCH /api/v1/admin/remnawave/mode-placements` (scope `admin:servers:write`) —
  the Ansible panel-bootstrap PATCHes this after it creates the per-node squads.
  Per mode the patch composes three ops (applied replace → add → remove):
  `squadUuids` (full replace; `[]` clears), `addSquadUuids` (union, deduped), and
  `removeSquadUuids` — the add/remove forms exist so a node deploy can append or
  detach just ITSELF without knowing the rest of the pool. Replace/add entries are
  UUID-validated server-side; remove accepts any string so pre-validation garbage
  can be purged. Squad UUIDs are **write-only** (never echoed back; audited as a
  `poolBound` boolean + pool size; the response carries `bound` mode ids +
  per-mode `placements[].boundCount`, sizes only).
- At issuance FCP picks the **least-loaded node** of the mode's pool
  (`pickByNodeLoad`): per-squad node load — `usersOnline` (primary) + optional
  realtime bandwidth (secondary; weights `remnawave.nodePlacement.*_weight`, default
  usersOnline-only) — is aggregated from the squad's accessible nodes and cached in
  `remnawaveNodeStats` by the `backend-healthcheck` cron (~10 min). Fresh + online
  squads win (lowest load first); stale / offline / unroutable ones sort last but
  stay selectable; a single-element or empty pool short-circuits.
- The chosen placement is **persisted on the subscription row**
  (`subscriptions.backendPlacement`). A tier push (`lifecycle.pushTierToBackend`)
  re-sends _that_ placement — it never re-picks (`stablePlacement` only fills a row
  that has none, deterministically) — so renewals/downgrades can't thrash a live
  key across nodes. Only **regenerate** / **switch-mode** / **switch-backend**
  re-pick.
- **Multi-panel pairing (2026-07-16):** a mode's pool may span several panels, and
  a squad UUID only exists on its own panel — so issuance resolves the
  **(placement, panel) pair together** (`resolvePlacementTarget`): each pool squad
  is attributed to its panel via its `remnawaveNodeStats` row and the pick pins
  `issueUser` to that instance (`pinServerId`). A squad with no stats row yet
  (bring-up) can't be attributed; the pick then falls back to the historical
  global behavior. The in-place mode switch hard-pins to the key's OWN panel and
  falls back to a re-issue when the target mode has no squad there. **Admin →
  Remnawave** shows a read-only per-placement node-load panel
  (`GET /api/v1/admin/remnawave/node-stats`, scope `admin:servers:read`).
- **Locations (member-facing):** a backend-server row may carry a `location` code
  - display label ("MCI" / "Kansas City, MO"; Admin → Servers or the by-slug
    upsert). One panel manages one location's nodes by convention. Active located
    Remnawave instances are projected publicly as `publicConfig.locations`
    (code/label/online/load-band only); a member may pick one when creating/regenerating a
    key (persisted as `users.preferredLocation`; 'auto' = least-loaded anywhere).
    The filter is **fail-soft**: a stale/offline location never blocks issuance.
- **Member node status:** `GET /api/v1/account/node-status` reports the online
  bit of the squad behind the member's key (refreshed on demand, at most once per
  instance per minute via a serializable stampede guard; instance-health fallback
  for Outline/legacy keys), plus the key's location and the location's coarse
  **load band**. The SPA polls it (~30s) for the hero badge; the Access Pass
  shows the node label + band and deep-links to the public `/status#loc-<code>`.
- **Public status page:** the same healthcheck signals feed `GET /api/v1/status`
  (the `/status` page) — per-location online + coarse load bands
  (`convex/lib/loadBands.ts`: maxKeys utilization when every instance of a
  location is capped, else users-per-online-node against admin-tunable
  `status.loadBusyAt`/`status.loadCrowdedAt` thresholds), plus operator-published
  incidents and the censorship-availability matrix (Admin → Status). Bands only,
  never raw counts — see `docs/privacy.md`.

Operator sizing: one squad per node, add them all to the mode's pool, and FCP fills
the emptiest node at issuance. `maxKeys` on an instance is the generic hard cap for
the multi-panel / Outline case.

## HWID / device limits

Remnawave enforces per-user device limits by **device fingerprint (HWID)**, and
it takes **two** conditions to actually enforce:

1. **Panel:** `HWID_DEVICE_LIMIT_ENABLED=true` on the Remnawave panel (set in the
   panel's own env / the Ansible role — **FCP can neither read nor set it**).
2. **Per-user:** a non-null `hwidDeviceLimit` on the user, which FCP sends only
   when _both_ the tier opts in (`hwidEnabled`) _and_ the deployment-level toggle
   `devices.enforcementEnabled` is on (Admin → Settings → Device limits).

When enforced, a subscription fetched **without** a valid `x-hwid` header is
rejected by the panel with **404**; a fetch **with** `x-hwid` registers/refreshes
that device and counts it against the limit.

**The FCP front forwards HWID headers — only while enforcement is on.** Members
fetch their config from `GET /api/v1/sub/<token>` (the FCP origin), and FCP
fetches the panel server-side. It forwards the client's `x-hwid` /
`x-device-os` / `x-ver-os` / `x-device-model`, and **bypasses the UA cache when
`x-hwid` is present** (each device must reach the panel to register + be
counted). A panel 404 is passed through as 404 (authoritative — not a 502, and
never a stale body). Without this forwarding, enforcement _and_ device
registration would be dead through the front (the device list would always be
empty) — this was a latent gap. **Gate:** forwarding happens only when
`devices.enforcementEnabled` is on — with the toggle off FCP never sends a
panel-side `hwidDeviceLimit`, so forwarding would only register arbitrary
devices with zero enforcement benefit (the headers are then dropped and the
normal UA-cache path applies). The route is also per-token rate-limited
(`subscription.fetch.token`, default 60/min) against UA-rotating cache-bypass
amplification and device-slot stuffing with a leaked/shared token.

**Not every app sends HWID.** Only apps that implement Remnawave device
identification (today **Karing** and **Throne**; tracked per-app as
`clients.hwid`) honor the limit. On a device-limited plan the connect UI splits
apps into "works with your device limit" vs "not recommended", and shows the HWID
hint — **only** when `devices.enforcementEnabled` is on and the member's tier is
device-limited. With the toggle off (the unlimited-by-default posture) the device
UI is neutralized entirely.

**Privacy-mode members** (a connection mode whose `deliveryStyle` is `rawConfig`)
import a static raw config (not a polling URL), so they never send an HWID and
can't honor a device limit — device limits are an `url`-delivery / fronted concept.

The device list + member self-service **revoke** (`POST /api/v1/account/devices/revoke`)
are Remnawave-only; Outline has no device concept and returns a typed 409.

## Subscription formats (Clash, sing-box, base64)

Remnawave emits the subscription in **different formats chosen by the requesting
client's `User-Agent`** (raw v2ray/base64, sing-box JSON, Clash / Clash.Meta YAML).
FCP's fronted URL is **format-agnostic and transparent**: `GET /api/v1/sub/<token>`
forwards the caller's exact `User-Agent` upstream (`http.ts` →
`backends.fetchSubscriptionContent` → `remnawave.ts`), sends no `Accept` / format
override, passes Remnawave's `Content-Type` + body straight back, and caches
per-exact-UA. So a **Clash-family client** (Clash Verge Rev, FlClash, Mihomo Party,
Clash Meta) that imports the fronted URL receives Clash YAML **iff the Remnawave
panel is configured to emit Clash output for that UA** — a **panel / Ansible
subscription-template** concern, _not_ an FCP code change. If Clash clients get
base64 instead of YAML, fix the panel's subscription templates; the FCP front
already does the right thing.

Constraints to know:

- **Clash-family clients are `url`-delivery only.** In a `rawConfig` connection
  mode (privacy) the URL is hidden, the import deep-links are suppressed, and the
  raw-config copy path (`/api/v1/subscription/content`) sends no UA → it always
  returns the base64 default, never Clash. Recommend Clash apps for `url`/evade mode.
- **S3 mirror URLs serve one fixed format** (the base64 default). The mirror
  refresh/provision jobs fetch with no UA (`convex/storage.ts`) and S3 does no UA
  negotiation, so a Clash client pointed at a _mirror_ URL gets base64, not YAML.
  Hand Clash users the primary fronted URL.
- **The per-sub UA cache holds a few buckets** (keyed by exact UA), so a Clash UA
  gets its own bucket and never collapses into another client's format.

The recommended-client catalog marks the Clash-family additions (FlClash, Mihomo
Party) `schemeId: null` (manual paste of the subscription URL) rather than shipping
an unverified one-tap import scheme.

## Sensitive data

Backends need credentials that must never leak:

- Per-instance secrets live in `backendServers.config` (Remnawave `apiToken`, Outline `apiUrl`) and
  are **never returned** to the SPA; admin responses mask them (`apiUrlMasked` / `apiTokenSet`).
- Never write a raw secret into a log line or an audit `payload`. The healthcheck + the
  `OutlineApiError` / `RemnawaveApiError` classes deliberately avoid the config.
- Custom error classes for backend HTTP calls record only status + path, never the URL.
