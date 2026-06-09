# Backend abstraction

The control plane talks to N proxy backends through one generic dispatch layer + a provider
registry. This document describes the two core concepts (backend *types* vs *instances*), how
dispatch works, and what's required to add another backend.

## Two concepts: type vs instance

- A **backend type** is the proxy software the control plane knows how to drive: `remnawave`,
  `outline`, and any future `wireguard` / `3x-ui` / .... The set of types lives in one place,
  `BACKEND_IDS` in `src/shared/contracts/backends.ts`; every `BackendId` union (client zod, server
  TS, the Convex validators) derives from it.
- A **backend instance** is one deployed server of a given type, with its own connection config +
  secret. Instances are rows in the **`backendServers`** table and are managed in the admin CMS
  ("Backend servers"). Remnawave and Outline both have instances; a type can have many.

This split is what makes the system multi-backend: instance *management* (pool selection at
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
`remnawaveSquadUuid`); `updateUser` is a sparse PATCH; `getUser` returns a normalized `UserState`
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
- **Tier propagation** (`convex/lifecycle.ts -> pushTierToBackend`) and the **grace/disable sweep**
  call `internal.backends.updateUser`.
- **Teardown** (`deleteSubscriptionEverywhere`, used by free-tier cleanup + the tombstone sweep)
  calls `internal.backends.deleteUser`.
- **`/account` reads** call `internal.backends.getUser`.

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
rotate it.

**Pool scoring**: `pickCandidatesForIssue` prefers instances health-checked within ~30 min (else
falls back to all active), then scores `latency_weight * lastHealthRttMs + key_count_weight *
keyCount`, then admin `priority`. Weights are admin-tunable via the `backend.scoring.*` settings.
The `backend-healthcheck` cron pings every active instance through its provider's `health` probe
and stamps `lastHealthOkAt` + rtt (+ key count for types that report one, i.e. Outline).

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

## Sensitive data

Backends need credentials that must never leak:

- Per-instance secrets live in `backendServers.config` (Remnawave `apiToken`, Outline `apiUrl`) and
  are **never returned** to the SPA; admin responses mask them (`apiUrlMasked` / `apiTokenSet`).
- Never write a raw secret into a log line or an audit `payload`. The healthcheck + the
  `OutlineApiError` / `RemnawaveApiError` classes deliberately avoid the config.
- Custom error classes for backend HTTP calls record only status + path, never the URL.
