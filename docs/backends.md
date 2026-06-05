# Backend abstraction

The control plane talks to N proxy backends through a single interface. This document
describes the interface contract, how dispatch works, and what's required to add a
third backend.

## Interface

`src/server/providers/backend.ts` declares `ProxyBackendProvider`:

```ts
export type BackendId = 'remnawave' | 'outline';

export interface ProxyBackendProvider {
  readonly id: BackendId;
  issueUser(spec: IssueUserSpec): Promise<IssuedUser>;
  getUser(backendUserId: string): Promise<UserState>;
  updateUser(backendUserId: string, patch: UpdateUserPatch): Promise<void>;
  resetUserTraffic(backendUserId: string): Promise<void>;
  deleteUser(backendUserId: string): Promise<void>;
  fetchSubscriptionContent(backendShortId: string, ua?: string): Promise<SubscriptionContent>;
}
```

Each method is the minimum surface needed by the FreeSocks orchestration layer. The
contract is intentionally permissive about per-backend differences:

- **`issueUser`** takes a superset of fields. Backends apply what they support and
  ignore the rest. Example: `hwidDeviceLimit` is a Remnawave concept; Outline drops it.
- **`updateUser`** is a sparse PATCH. `undefined` means "leave it alone". Backends
  apply whatever fields they understand and silently no-op the rest.
- **`getUser`** returns a normalized `UserState` regardless of backend. Devices that
  the backend doesn't track come back as an empty list.
- **`fetchSubscriptionContent`** lets each backend decide what the "subscription content"
  is. Remnawave returns a multi-protocol bag negotiated by User-Agent; Outline returns
  the plain `ss://` access key URL.

When a feature is fundamentally backend-specific (e.g. WSS-wrapped Shadowsocks on a
non-stock Outline fork), it lives in the adapter implementation, not the interface.

## Dispatch via `BackendRegistry`

Higher-level services never hold a direct reference to a backend client. They
dispatch through `BackendRegistry`
(`src/server/services/backend-registry.ts`), which is mounted on the service
container at `c.var.services.backends`.

The registry exposes three lookup helpers:

```ts
backends.get('outline'); // when the BackendId is already known
backends.fromTier(tier); // for new issuance — tier dictates the backend
backends.fromSubscription(sub); // for reads/updates on an existing sub
```

`fromTier` and `fromSubscription` exist as separate methods because they answer
different questions: a tier's `backend` is the **target** for new issuance, but an
existing subscription's `backend` is **whatever issued it**, which may differ if an
admin has since changed the tier's backend (tier-backend changes are intentionally not
propagated — existing users keep their original backend until they regenerate or
explicitly switch).

### Why two columns

- `tiers.backend` — the backend a tier issues against. Free tiers come in pairs:
  `free-remnawave` and `free-outline`, both `is_default_free=1`. The subscription
  endpoint picks the matching one based on the user's preference (or admin's default).
- `subscriptions.backend` — the backend that actually issued this row. Stays put even
  if the tier later moves to a different backend. This is what reads dispatch on.

The `(civicrm_membership_type_id, backend)` composite unique on `tiers` lets one
CiviCRM membership type map to two tiers — one on each backend — for the
backend-switch flow.

## Adding a new backend

Steps to add a third backend (e.g. `wireguard`, `3xui`, etc.):

1. **Extend `BackendId`** in `src/shared/contracts/admin.ts`:

   ```ts
   export const BackendId = z.enum(['remnawave', 'outline', 'wireguard']);
   ```

   This automatically propagates to every contract that references it
   (`SubscriptionRequest`, `SubscriptionResponse`, `AccountResponse`,
   `TierAdmin`, ...).

2. **Write the adapter** at `src/server/providers/<id>/backend.ts`.
   Reference: `src/server/providers/outline/backend.ts`. The pattern:
   - Implement `ProxyBackendProvider`.
   - If the backend supports multiple physical servers, mirror the
     `OutlineServerPool` pattern with a typed registry table and a
     scoring/health model.
   - Custom errors should not capture URLs or other sensitive fields — see
     `src/server/providers/outline/errors.ts` for the model.

3. **Register the adapter** in `src/server/services/container.ts`:

   ```ts
   providers.set('wireguard', new WireguardBackend({ ... }));
   ```

4. **Add an enable toggle** to `SETTINGS_SCHEMA` in
   `src/server/services/app-settings.ts`:

   ```ts
   'wireguard.enabled': z.boolean(),
   ```

   Defaults to `false` in the migration's `INSERT` so the new backend is dark
   until an admin turns it on.

5. **Update the schema**:
   - Bump the `enum` on `tiers.backend` and `subscriptions.backend` in
     `src/server/db/schema.ts`.
   - Write the matching migration (`ALTER TABLE` for SQLite is limited — see
     `0004_backend_discriminator.sql` for the pattern).

6. **Surface in admin UI**: add the option to the backend `<Select>` in
   `TierEditor.svelte`, and add a tab/page if the new backend has its own server
   registry similar to Outline.

7. **Surface in user UI** (optional): if the backend should be available as an
   end-user choice on `/get-key`, add a third option to the chooser. The chooser
   gracefully degrades — if only two backends are enabled, it stays at two
   options.

8. **Tests**:
   - Unit test the client/adapter directly with mocked `fetch`.
   - Add an integration test that issues, reads, updates, and deletes through the
     registry (mirror `test/integration/admin-tokens.test.ts` for shape).

Most service-level code needs no changes — the registry handles dispatch.

## Sensitive data

Backends often need credentials that must never leak:

- Outline's `apiUrl` carries a shared secret in the path segment.
- Future backends may have API keys or signed-URL templates.

Conventions:

- Sensitive fields live on the backend's registry row (e.g. `outline_servers.api_url`)
  and are returned by admin endpoints in a `*Masked` form (`api_url_masked` →
  `***/access-keys/...`).
- The audit log scrubber in `src/client/routes/admin/AdminAudit.svelte` and the
  server-side log conventions both redact secrets — never write the raw value into a
  log line or audit payload.
- Custom error classes for backend HTTP calls should NOT capture the URL. See
  `OutlineApiError` for the model.
