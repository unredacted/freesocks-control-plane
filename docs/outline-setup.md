# Outline backend setup

How to register an Outline server with the control plane and offer it as a backend
option to users.

## Prerequisites

You need an existing Outline Manager installation. The Outline project documents the
install steps at <https://getoutline.org/get-started/#step-1>. The end state is a host
running `shadowbox` with a management API at a URL that looks like:

```
https://HOST:PORT/<base64-secret>/access-keys
```

That base64-secret in the URL path **is the authentication**. There are no headers,
no API keys — anyone who can construct the URL can call the API. Treat the URL as a
credential.

## TLS requirements

The Workers `fetch` runtime rejects self-signed certificates. Stock Outline ships with
a self-signed cert by default. Either:

- **(Recommended)** Front the Outline host with Cloudflare, terminate TLS at
  Cloudflare's edge, and use a valid Cloudflare-issued cert behind it.
- Install a Let's Encrypt or other publicly-trusted certificate on the Outline host
  directly. The Outline Manager docs walk through this.

The admin form's **Test connection** button is the fast-feedback check: it calls
`GET /access-keys` against the URL you paste and surfaces the TLS or auth error
verbatim. Use it before saving.

## Registering a server

1. Log in to the admin CMS and visit **Outline servers** in the sidebar.
2. Click **Add server**.
3. Fill in:
   - **Name**: human-readable, e.g. `EU North`.
   - **Slug**: lowercase, alphanumeric + hyphens, e.g. `eu-north`. Used in audit logs.
     Immutable once set.
   - **API URL**: the full management URL, including the secret path segment. Stored
     encrypted-at-rest by Cloudflare; never returned to the SPA in full (only a
     masked form for display).
   - **WSS-wrapped Shadowsocks**: leave unchecked unless your Outline host runs the
     non-stock FreeSocks fork that supports `websocket: {…}` on `POST /access-keys`.
     Stock Outline servers should keep this off.
   - **WSS domain**: only used when the above is on; the public hostname that
     terminates the WebSocket TLS.
   - **Prometheus URL**: reserved for future per-key metrics. Leave blank in v1.
   - **Priority**: lower = preferred. The pool picks servers from the top-3 lowest
     scores, randomized for spread.
   - **Active**: uncheck to mothball a server without deleting its row. Inactive
     servers never receive new keys but existing keys keep working as long as the
     server is reachable.
4. Click **Test connection**. Confirm "Reachable. Current key count: N" appears.
5. Click **Register server**.

The server's `lastHealthOkAt` updates immediately, and the **outline-healthcheck**
cron will re-probe it every 10 minutes thereafter.

## Enabling the Outline backend

Once at least one Outline server is registered:

1. Visit **Settings** in the admin sidebar.
2. Flip **Outline backend enabled** to `on`.
3. (Optional) Set `subscription.user_choice_enabled` to let end users pick on
   `/get-key`. Default is off — the server picks based on
   `subscription.default_backend`.
4. (Optional) Edit the user-facing labels under **Backend labels**. Defaults are bare
   provider names; anything you want appears in the chooser segment and the "via X"
   badge on `/account`.

## Creating an Outline tier

A tier is bound to a single backend. To offer Outline as a paid tier:

1. Visit **Tiers** in the admin sidebar.
2. Click **Add tier** (or edit an existing one).
3. Set **Backend** to `outline`.
4. Configure:
   - `monthlyTrafficGb` — the per-key data limit (Outline enforces this server-side
     via `PUT /access-keys/{id}/data-limit`).
   - `deviceLimit` — informational only; Outline doesn't enforce HWID.
   - `civicrmMembershipTypeId` — the CiviCRM membership type that maps to this tier.
     Because the unique index is `(civicrm_membership_type_id, backend)`, the SAME
     CiviCRM type can map to a Remnawave tier AND an Outline tier. Members can then
     switch between them via `/account → Switch backend`.

The `hwidLimit` and `trafficStrategy` fields disappear from the form when the backend
is Outline because they don't apply.

## Free tier on Outline

To offer a free Outline tier alongside the existing Remnawave free tier:

1. Create a tier with `slug = free-outline`, `is_default_free = 1`, `is_active = 1`,
   `backend = 'outline'`.
2. The `(is_default_free, backend)` pair must be unique-ish — `tierPolicy.getDefaultFreeTier(backend)`
   picks the first matching `is_default_free=1 AND is_active=1` tier for the requested
   backend.
3. If `subscription.user_choice_enabled` is on, the `/get-key` chooser routes the
   user's pick to the matching default-free tier.

## Operational notes

- **Health badges**: the **Outline servers** page shows green (healthy in the last
  5 min), amber (5–30 min stale), or red (never reachable / health failed in last
  10+ min). Drives both the admin UI and the issuance pool's scoring.
- **Per-key metrics**: `OutlineBackend.getUser` fetches `/metrics/transfer` on every
  `/account` read for the user's key. If a server returns 500 for metrics, the gauge
  shows 0 bytes used and the request still succeeds.
- **Deletion**: regenerate, free-tier cleanup, and admin user-delete all dispatch
  through `OutlineBackend.deleteUser`, which calls `DELETE /access-keys/{id}` on the
  hosting server. If the server is unreachable, the local subscription row is still
  tombstoned and a periodic reconcile (future work) would handle the orphan cleanup
  on the Outline side.
- **Rotating the secret**: edit the server, paste the new `apiUrl`, test connection,
  save. The old URL stops working as soon as the Outline host rotates its secret.
  Existing keys keep functioning at the data-plane (Shadowsocks listener) level;
  only the management API URL changes.

## Limits compared to Remnawave

The interface accepts a superset of fields. Outline ignores:

- `hwidDeviceLimit` (Outline has no HWID concept)
- `trafficLimitStrategy` (Outline rolls on a server-wide window, not per-user)
- `remnawaveSquadUuid` (Outline-specific concept doesn't apply)
- `expireAt` (Outline has no per-key expiry; the control plane's cleanup cron handles
  free-tier expiry by deleting the key locally and on the Outline server)

Tier propagation (raising a traffic limit) PATCHes Outline keys with `setKeyDataLimit`
and silently no-ops the rest.
