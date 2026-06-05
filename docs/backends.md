# Backend abstraction

The control plane talks to N proxy backends through a single set of Convex actions. This
document describes the operation contract, how dispatch works, and what's required to add a
third backend.

## Shape: a dispatch action + pure HTTP functions

There is no class-based `ProxyBackendProvider` interface anymore. A backend is:

1. **A branch in the dispatch actions** (`convex/backends.ts`) — six `internalAction`s, each
   switching on the `backend` discriminator:

   ```ts
   issueUser({ backend, spec })                         -> IssuedUser
   getUser({ backend, backendUserId })                  -> UserState
   updateUser({ backend, backendUserId, patch })        -> null
   resetUserTraffic({ backend, backendUserId })         -> null
   deleteUser({ backend, backendUserId })               -> null
   fetchSubscriptionContent({ backend, backendShortId, userAgent? }) -> SubscriptionContent
   ```

   The action boundary validates args with `v.*`; the shared TS types
   (`IssueUserSpec`, `IssuedUser`, `UserState`, `UpdateUserPatch`, `SubscriptionContent`)
   live in `convex/lib/backends/types.ts`.

2. **Pure HTTP functions** in `convex/lib/backends/<id>.ts` that take a resolved config and
   do `fetch`. They hold no DB access — they're invoked from inside the dispatch action's V8
   runtime. Reference: `convex/lib/backends/remnawave.ts` (e.g. `remnawaveIssueUser`,
   `remnawaveGetUser`, …) and `convex/lib/backends/outline.ts` (`outlineIssue`,
   `outlineGetState`, …).

3. **Optionally, a DB half** as internal queries/mutations when the backend has its own
   server registry. Outline's lives in `convex/outlineServers.ts` (pool selection, key→server
   resolution, access-key-count bump, healthcheck). The dispatch action does the **read →
   act → write** decomposition: read the server row(s) via the internal query, do the HTTP in
   `lib/backends/outline.ts`, write back (e.g. `bumpAccessKeyCount`).

The contract is intentionally permissive about per-backend differences:

- **`issueUser`** takes a superset `spec`. Backends apply what they support and ignore the
  rest — e.g. `hwidDeviceLimit` / `trafficLimitStrategy` / `remnawaveSquadUuid` are Remnawave
  concepts that Outline drops; `outlineServerId` / `outlineServerPoolIds` are Outline pool
  hints that Remnawave ignores.
- **`updateUser`** is a sparse PATCH. `undefined` means "leave it alone". Backends apply
  whatever fields they understand and no-op the rest (Outline maps `status:'disabled'` to a
  0-byte data limit since it has no native disable, and has no traffic-reset, so
  `resetUserTraffic` is a no-op).
- **`getUser`** returns a normalized `UserState`. Devices a backend doesn't track come back
  empty. The read path is fault-tolerant: an Outline key that can't be resolved to a server
  (e.g. a row mid-write) returns a sentinel `active/unknown` state rather than throwing, so
  `/account` degrades instead of 500-ing.
- **`fetchSubscriptionContent`** lets each backend decide what "subscription content" is.
  Remnawave returns a multi-protocol bag negotiated by User-Agent; Outline returns the plain
  `ss://` access-key URL. It's only called when S3 mirroring is enabled.

## Where dispatch is called from

Higher-level code never calls `fetch` directly — it runs the dispatch actions:

- **Issuance** goes through the saga helper `issueNewSubscription` in
  `convex/lib/issuance.ts`, which calls `internal.backends.issueUser` (and, with mirroring on,
  `fetchSubscriptionContent` + `internal.storage.mirrorContent`), then persists the row.
- **Tier propagation** (`convex/lifecycle.ts → pushTierToBackend`) and the **grace/disable
  sweep** call `internal.backends.updateUser`.
- **Teardown** (`deleteSubscriptionEverywhere` in `convex/lib/issuance.ts`, used by free-tier
  cleanup + the tombstone sweep) calls `internal.backends.deleteUser`.
- **`/account` reads** call `internal.backends.getUser`.

### The `backend` discriminator: two places, two questions

- `tiers.backend` — the backend a tier issues **against**. This is what `issueUser` dispatches
  on. Free tiers can come in pairs (one Remnawave, one Outline, both `isDefaultFree`); the
  subscription endpoint picks the matching default-free tier from the user's choice (or the
  admin default).
- `subscriptions.backend` — the backend that actually **issued** this row. Stays put even if
  the tier later moves to a different backend (tier-backend changes are intentionally not
  propagated — existing users keep their original backend until they regenerate or explicitly
  switch). This is what later reads/updates/deletes dispatch on.

## Adding a new backend

Steps to add a third backend (e.g. `wireguard`, `3xui`, …):

1. **Extend the `BackendId` union** everywhere it's declared:
   - the `backendId` validator in `convex/schema.ts` (`tiers.backend`, `subscriptions.backend`),
   - the `backendId` validator + the dispatch branches in `convex/backends.ts`,
   - the `BackendId` TS type in `convex/lib/backends/types.ts`,
   - the client-side `BackendId` zod enum in `src/shared/contracts/` (so the SPA's response
     parsing accepts it).

   (Convex schema changes apply on the next `convex dev`/`deploy` push — there is no
   migration file.)

2. **Write the pure HTTP functions** at `convex/lib/backends/<id>.ts`. Mirror
   `convex/lib/backends/remnawave.ts`. Implement issue/get/update/delete/fetch as standalone
   functions that take a resolved config and return the shared `lib/backends/types.ts` shapes.
   - Custom error classes must **not** capture URLs or other secrets — see `OutlineApiError`
     in `convex/lib/backends/outline.ts`, which records only the status + path.

3. **Add the dispatch branches** in `convex/backends.ts` — one `if (backend === '<id>')` arm
   per action. Pull config from `process.env` (set via `bunx convex env set`). If the backend
   has multiple physical servers, add a DB-half module like `convex/outlineServers.ts` and do
   the read → act → write split in the dispatch (the random pick / CSPRNG must live in the
   action, not the query).

4. **Add an enable toggle** to `SETTINGS_DEFAULTS` in `convex/appSettings.ts`:

   ```ts
   'wireguard.enabled': false,
   ```

   Defaulting to `false` keeps the new backend dark until an admin turns it on. The free-tier
   and switch-backend paths already check `settings['<backend>.enabled']` before dispatching.

5. **Surface in admin UI**: add the option to the backend `<Select>` in
   `src/client/routes/admin/TierEditor.svelte`, and add a tab/page if the backend has its own
   server registry similar to Outline.

6. **Surface in user UI** (optional): if the backend should be an end-user choice on
   `/get-key`, add an option to the chooser (it degrades gracefully — fewer enabled backends =
   fewer options).

7. **Tests**: unit-test the pure HTTP functions with a mocked `fetch`; add a `convex-test`
   case that issues/reads/updates/deletes through the dispatch action (mirror
   `convex/subscriptions.test.ts` for shape).

Most domain code needs no changes — it already dispatches through `convex/backends.ts`.

## Sensitive data

Backends often need credentials that must never leak:

- Outline's `apiUrl` carries a shared secret in the path segment.
- Future backends may have API keys or signed-URL templates.

Conventions:

- Per-server secrets live on the registry row (e.g. `outlineServers.apiUrl`) and are
  **never returned** to the SPA — admin endpoints return a `apiUrlMasked` form only
  (`maskApiUrl` in `convex/adminApi.ts`). Backend config that's global (Remnawave) lives in
  Convex env vars, never in the DB or a response.
- Never write a raw secret into a log line or audit `payload`. The Outline healthcheck and
  the `OutlineApiError` class both deliberately avoid the `apiUrl`.
- Custom error classes for backend HTTP calls should NOT capture the URL — model them on
  `OutlineApiError`.
