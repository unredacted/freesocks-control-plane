# Outline backend setup

How to register an Outline server with the control plane and offer it as a backend
option to users. Outline servers are managed entirely through the **admin CMS** (the
**Backend servers** page); their data lives in the generic `backendServers` Convex table, and the
backend itself is a set of Convex actions (`convex/backends.ts` +
`convex/lib/backends/outline.ts`). See [`docs/backends.md`](backends.md) for the dispatch
shape.

## Prerequisites

You need an existing Outline Manager installation. The Outline project documents the
install steps at <https://getoutline.org/get-started/#step-1>. The end state is a host
running `shadowbox` with a management API at a URL that looks like:

```
https://HOST:PORT/<base64-secret>/access-keys
```

That base64-secret in the URL path **is the authentication**. There are no headers,
no API keys; anyone who can construct the URL can call the API. Treat the URL as a
credential. The control plane stores it server-side on the `backendServers` row and
**never returns it** to the SPA: admin reads get a masked form (`apiUrlMasked`,
scheme+host only) instead.

## TLS requirements

The Convex actions runtime does the outbound `fetch` to your Outline host and rejects
untrusted certificates. Stock Outline ships with a self-signed cert by default. Either:

- Front the Outline host with a reverse proxy / CDN that terminates TLS with a
  publicly-trusted certificate, or
- Install a Let's Encrypt (or other publicly-trusted) certificate on the Outline host
  directly. The Outline Manager docs walk through this.

The admin form's **Test connection** button is the fast-feedback check: it runs
`internal.adminApi.testOutlineConnection` (a `GET /access-keys` against the URL you paste)
and surfaces the TLS or auth error. Use it before saving.

## Registering a server

1. Log in to the admin CMS and visit **Backend servers** in the sidebar (pick the Outline type).
2. Click **Add server**.
3. Fill in:
   - **Name**: human-readable, e.g. `EU North`.
   - **Slug**: lowercase, alphanumeric + hyphens, e.g. `eu-north`. Used in audit logs;
     uniqueness is enforced. Immutable once set.
   - **API URL**: the full management URL, including the secret path segment. Stored on the
     server row; never returned to the SPA in full (only `apiUrlMasked` for display). To
     rotate the secret later, edit the server and retype the URL; a blank field leaves the
     stored value unchanged.
   - **WSS-wrapped Shadowsocks**: leave unchecked unless your Outline host runs the
     non-stock FreeSocks fork that supports `websocket: {…}` on `POST /access-keys`.
     Stock Outline servers should keep this off. (See the WSS caveat in
     `deferred-security-bugs.md` (Bug 15) before routing to a WSS server.)
   - **WSS domain**: only used when the above is on; the public hostname that terminates
     the WebSocket TLS.
   - **Prometheus URL**: reserved for future per-key metrics. Leave blank.
   - **Priority**: lower = preferred. The pool draws from the top candidates by score, then
     picks one at random for spread.
   - **Active**: uncheck to mothball a server without deleting its row. Inactive servers
     never receive new keys but existing keys keep working as long as the server is reachable.
4. Click **Test connection**. Confirm "Reachable. Current key count: N" appears.
5. Click **Register server**.

The **backend-healthcheck** cron (every 10 minutes, `convex/crons.ts` →
`internal.backendServers.healthcheck`) pings each active backend instance of every type,
stamps `lastHealthOkAt` + rtt, and refreshes the live access-key count for backends that
report one (Outline does; Remnawave returns `null`, so its locally-tracked estimate is kept).

## How the pool picks a server

New-key issuance calls `internal.backendServers.pickCandidatesForIssue` (in
`convex/backendServers.ts`):

1. Collect active servers (optionally filtered to an `outlineServerPoolIds` allowlist on the
   issue spec).
2. **Prefer servers healthy within the last ~30 minutes** (`lastHealthOkAt` fresh); if none
   qualify, fall back to all active servers, so a transient healthcheck blip can't take the
   whole pool offline.
3. Score each (lower wins): `latency_weight × lastHealthRttMs + key_count_weight × keyCount`.
   `lastHealthRttMs` is the round-trip time the `backend-healthcheck` cron measured on its last
   probe (instances never checked contribute `0`); ties break on admin `priority`. Weights come
   from the `backend.scoring.*` app settings.
4. The dispatch **action** (`convex/backends.ts`) takes the top candidates and picks one at
   **random** via CSPRNG (randomness can't live in a Convex query), then bumps that instance's
   `keyCount`.

Reads/updates/deletes on an existing key resolve the hosting server from the subscription
row via `internal.backendServers.resolveKeyServer` (keyed by `backendUserId`).

## Enabling the Outline backend

Once at least one Outline server is registered:

1. Visit **Settings** in the admin sidebar.
2. Flip **Outline backend enabled** (`outline.enabled`) to `on`.
3. (Optional) Set `subscription.user_choice_enabled` to let end users pick on `/get-account`.
   Default is off; the server picks based on `subscription.default_backend`.
4. (Optional) Edit the user-facing labels under **Backend labels**. Anything you set appears
   in the chooser segment and the "via X" badge on `/account`.

## Creating an Outline tier

A tier is bound to a single backend. To offer Outline as a paid tier:

1. Visit **Tiers** in the admin sidebar.
2. Click **Add tier** (or edit an existing one).
3. Set **Backend** to `outline`.
4. Configure:
   - `monthlyTrafficGb`: the per-key data limit (Outline enforces this server-side via
     `PUT /access-keys/{id}/data-limit`).
   - `deviceLimit`: informational only; Outline doesn't enforce HWID.

The `hwidLimit` and `trafficStrategy` fields disappear from the form when the backend is
Outline because they don't apply.

> **Note on paid backend-switching.** Today `switchBackend` only resolves a cross-backend
> peer for **free-tier** users (via the default-free peer tier on the target backend); paid
> cross-backend switching returns 409 until the future billing portal defines tier linkage
> (`convex/account.ts`).

## Free tier on Outline

To offer a free Outline tier alongside the Remnawave free tier:

1. Create a tier with a distinct slug (e.g. `free-outline`), `isDefaultFree = true`,
   `isActive = true`, `backend = 'outline'`.
2. `tiers.getDefaultFree(backend)` picks the first matching `isDefaultFree && isActive` tier
   for the requested backend.
3. If `subscription.user_choice_enabled` is on, the `/get-account` chooser routes the user's pick
   to the matching default-free tier.

## Operational notes

- **Health**: the **Backend servers** page reflects each server's `lastHealthOkAt` (refreshed
  by the healthcheck cron). A failing server is **not** auto-deactivated; it ages out of the
  30-min "fresh" set in `pickCandidatesForIssue` and is deprioritized, with all-servers
  fallback preserved.
- **Per-key metrics**: `outlineGetState` fetches `/metrics/transfer` on every `/account` read
  for the user's key. If a server returns an error for metrics, the gauge shows 0 bytes used
  and the request still succeeds.
- **Deletion**: regenerate, free-tier cleanup, and admin user-disable all dispatch through
  `internal.backends.deleteUser`, which calls `DELETE /access-keys/{id}` on the hosting
  server. If the server is unreachable, the local subscription row is still tombstoned.
- **Rotating the secret**: edit the server, retype the new `apiUrl`, test connection, save.
  Existing keys keep functioning at the data-plane (Shadowsocks listener) level; only the
  management API URL changes.

## Limits compared to Remnawave

The issue spec accepts a superset of fields. Outline ignores:

- `hwidDeviceLimit` (Outline has no HWID concept)
- `trafficLimitStrategy` (Outline rolls on a server-wide window, not per-user)
- `remnawaveSquadUuid` (a Remnawave-specific concept)
- `expireAt` (Outline has no per-key expiry; the control plane's cleanup cron handles
  free-tier expiry by deleting the key locally and on the Outline server)

Tier propagation (raising a traffic limit) PATCHes Outline keys via the data-limit endpoint
and silently no-ops the rest. Outline also exposes no per-key traffic reset, so
`resetUserTraffic` is a no-op for Outline.
