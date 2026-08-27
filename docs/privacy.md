# Privacy defaults: no client IPs at rest, end to end

FreeSocks serves users in censored regions, so the control plane is built to
**never persist a user's IP address** — not in the application, not in the
webserver, not in the captcha. This is the default posture; a fork or a
downstream deployer gets it without extra configuration. This doc is the single
place that describes the whole chain, so nobody has to reverse-engineer it (or
accidentally regress it).

> Scope: the **at-rest / logging** posture across the whole chain — the control
> plane (§1–4) AND the proxy data plane (§5). The data plane necessarily _carries_
> user traffic; §5 is the required node/panel config that stops it from _logging or
> storing_ the client IP. The confidentiality/availability trade-offs of the
> transport itself live in
> [`threat-model-cdn-blinding.md`](threat-model-cdn-blinding.md).

## 1. Application (Convex, `convex/`)

- **No user IP is ever stored — not even hashed.** Every path that needs to
  bucket by IP (the per-(IP,day) free-account cap, login throttle, WebAuthn
  throttle, the fronted-subscription throttle) runs it through `ipHashSubject`
  (`convex/lib/http.ts`): `HMAC-SHA256(IP_HASH_SALT, ip)` — and that digest lives
  **only in an ephemeral, auto-expiring `rateLimits` counter** (swept by a daily
  cron), never in a durable row. It **fails closed** (a missing `IP_HASH_SALT`
  throws rather than using the plaintext IP), and `IP_HASH_SALT` is a
  per-deployment random so even the transient hashes aren't correlatable across
  deployments. The free-account cap IS that ephemeral counter (`freetier.create`);
  there is **no durable per-IP ledger** — the old `freeGrants` table was purged
  live and then dropped from the schema entirely.
- **The audit log stores no IP, hashed or otherwise.** Free-account creation
  records only a coarse, non-identifying `ipCountry` (never the IP, no hash, no raw
  User-Agent), and every audit payload is projected through a fail-closed allowlist
  (`convex/lib/audit.ts`) that drops any unregistered key. The legacy
  `auditLog.ipHash` field was cleared live and then dropped from the schema — the
  shape can no longer carry an IP-derived value at all.
- **`sessions` / `billingOrders` store no IP** (billing orders store no payer PII
  at all).
- **No `console.*` in `convex/` logs an IP, header, or raw request.**
- The admin self-diagnostic `GET /api/v1/admin/client-ip` computes the resolved
  IP **transiently** and returns it `no-store`; it is never persisted or audited.
- The country used to suggest a delivery profile is read transiently from
  `CF-IPCountry` (only when `CF_FRONTED=true`) and **never stored**.
- **Device identification (HWID) is opt-in and panel-side.** When the admin
  enables device-limit enforcement, a proxy app that sends `x-hwid` gets that
  device id forwarded to the Remnawave panel, which keeps its own device rows;
  members can see and revoke those devices from the account page. When
  enforcement is off (the default), no HWID is requested or stored anywhere.
- The FCP-fronted subscription route keeps a **short-lived per-user-agent
  content cache** on the subscription row, so proxy apps with different app
  signatures get the right config format without every app re-hitting the
  panel. It stores the app's User-Agent string next to the cached body,
  bounded to a few entries, and it is deleted with the subscription row — it
  is never exported to the audit log or any other table.
- **Public fleet telemetry is deliberately coarse.** The public `/api/v1/status`
  projection (the `/status` page) exposes per-location online bits and **load
  bands** (`quiet/busy/crowded`) only — never raw online-user counts, per-node
  numbers, or key counts (the same posture as the GB-only donation projection).
  The exact numbers stay server-side.
- **Referral links are a minimal social graph.** The `referrals` table records
  which account invited which (two opaque user ids + reward state) — nothing
  else: no contact details, no IPs, and referral codes are non-secret by design
  (they credit the referrer, grant the holder nothing). Rewards vest only on a
  real paid conversion, so the edge is created by money, not by signup volume.

Client-IP _resolution_ (for those hash buckets) is fail-closed and topology-aware
— see `resolveClientIp` in `convex/lib/http.ts` and the topology matrix in
[`beta-deploy.md`](beta-deploy.md); `TRUSTED_PROXY_HOPS` is the current knob.

## 2. Webserver (Caddy, `Caddyfile`)

- **Access logging is explicitly disabled**, not merely left unconfigured. The
  global options block sets `log default { output discard }` — a null sink — so
  the intent is tamper-evident: a future edit that wants request logging has to
  consciously remove it. (Caddy's own runtime/error log, which does not record
  per-request client IPs, still goes to stderr.)
- Caddy strips a client-supplied `CF-Connecting-IP` before proxying to **both**
  the backend and the Cap service, so a request that reaches Caddy directly can't
  hand a downstream service a spoofed client IP.

## 3. Captcha (Cap, the `cap` + `valkey` services)

- Cap rate-limits on the **compose peer** (Caddy's container), not a real client
  header. Do **not** set `RATELIMIT_IP_HEADER` to a client-supplied header on this
  deployment — that would pull the real client IP into Cap.
- Cap's optional **IP geolocation stays off** (its dashboard default). Leave it off.
- `CAP_DISABLE_ERROR_LOGGING=true` (the compose default) keeps a peer IP from
  surfacing in an error trace.
- `valkey` only holds Cap's short-lived challenge/token state — no client IPs.

## 4. Backend container logging (Convex)

The self-hosted Convex backend logs at `RUST_LOG`. The compose default is
`info,convex-cloud-http=warn`, which **silences the per-request HTTP access line**
(that line logs the immediate peer's socket + request line) while keeping
warnings and errors. Over the compose network the peer is Caddy's container, not
the real client — but quiet-by-default is the posture, and it also cuts log
volume against the rotation cap.

Verify after a deploy:

```sh
docker compose -f docker-compose.stack.yml logs backend | grep 'GET /api'   # → empty
```

If a future Convex version renames that log target, the request lines will
reappear; fall back to `RUST_LOG=warn` (loses info-level operational detail but
guarantees no request lines).

## 5. Proxy data plane (Remnawave panel + Xray nodes)

The nodes carry the actual user traffic, so this is where a client's source IP is
most exposed. This posture lives in the **Remnawave Config Profile** (pushed
fleet-wide) and the `ansible-role-freesocks` node provisioning. It is part of the
privacy guarantee, not optional.

FCP can now **enforce the config-profile half itself**: Admin → Remnawave has a
no-log card that dry-runs a compliance check (`GET
/api/v1/admin/remnawave/logging-status`) and applies exactly the `log` + `policy`
settings below to every profile via the panel API (`POST
/api/v1/admin/remnawave/harden-logging`; safe GET→merge→PATCH, refuses a profile
with no inbounds, key-order-independent check). The node-container logging driver
and the inbound/Reality settings remain Ansible-only. See `docs/backends.md`
§"Xray logging privacy harden".

- **Xray logging OFF.** The Xray access log records `from <client-ip> …` for every
  connection. In the Config Profile's Xray JSON set the `log` block so no client IP
  is ever written:

  ```jsonc
  "log": { "access": "none", "error": "none", "loglevel": "none", "dnsLog": false, "maskAddress": "full" }
  ```

  `access:"none"` stops the per-connection client-IP records; `loglevel:"none"`
  disables the error log; `maskAddress:"full"` masks any IP that would reach a log
  if an operator later raises the level; `dnsLog:false` stops domain→IP lines.

- **Online-IP tracker OFF.** Xray's per-user online stat backs a live client-IP map
  (Remnawave's "IP Management"). Disable it in the Config Profile `policy`:

  ```jsonc
  "policy": { "levels": { "0": { "statsUserOnline": false } } }
  ```

  Trade-off: the panel then shows no online-user counts / drop-connection, and
  FCP's node-placement loses its `usersOnline` signal (it degrades to
  declaration-order — keys still issue).

- **Node host retains nothing.** With `access:"none"` Xray emits no connection
  lines for `docker logs` / journald to capture; as belt-and-suspenders, set the
  node container's logging driver to `none`.
- **Panel logging OFF (defaults).** Keep `IS_HTTP_LOGGING_ENABLED=false` +
  `ENABLE_DEBUG_LOGS=false`. The panel stores no client IP for FCP's flows — the
  `requestIp` it records on an HWID device row is FCP's egress IP (FCP fetches the
  subscription server-side), and FCP strips even that at the Zod boundary
  (`convex/lib/backends/remnawave.ts`).
- **Verify (live):** on a node `docker logs <xray>` shows no connection/IP lines;
  the panel "IP Management" / online view is empty; a client still connects.

## 6. Analytics (optional self-hosted Umami relay)

FCP can report **anonymous pageview counts** to an operator-run
[Umami](https://umami.is) instance. It ships **off** and is configured entirely
in Admin → Settings (the `analytics.*` appSettings namespace). The design is a
**server-side relay**, not the stock Umami integration:

- **No Umami script is ever loaded** (the zero-third-party-scripts posture
  holds). A ~40-line bundled beacon (`src/client/lib/analytics.ts`) POSTs to
  the same-origin `POST /api/v1/telemetry`, and the Convex backend forwards to
  `<umamiUrl>/api/send` (`convex/lib/umami.ts`).
- **Browsers never learn the Umami address.** The public config exposes only
  an `analytics.enabled` boolean; the URL + website id are admin-readable only
  (`GET /api/v1/admin/analytics`). A client can't enumerate the operator's
  analytics infrastructure.
- **What a pageview carries — and only this:** an **allowlist-checked route**
  (`ROUTE_ALLOWLIST` in `convex/lib/umami.ts`; unknown paths bucket to
  `/other`, so a path or title can never embed an identifier), a static
  English title from that same allowlist, the referrer reduced to its
  **origin** (never a full URL — Umami's referrer-path report stays empty by
  design), one of **three coarse screen buckets**, and the SPA's active locale
  (a bare primary subtag). Query strings and fragments are stripped
  client-side AND ignored server-side, so `?ref=` codes can't leak. `/admin`
  navigation is never reported.
- **The beacon is anonymous by construction.** It is a raw `fetch` with
  `credentials: 'omit'` — never `apiClient` (which would attach a PoP
  signature binding the pageview to the member's session) and never
  `navigator.sendBeacon` (which cannot drop cookies same-origin). The relay
  route reads no cookie and resolves no member. The client's User-Agent is
  forwarded transiently (Umami drops UA-less events), CR/LF-stripped, and is
  never logged or audited.
- **The visitor's IP does not leave FCP by default.** `analytics.forwardIp`
  ships off: Umami then sees only the backend's egress IP (no geolocation;
  unique-visitor counts degrade to per-user-agent buckets — accepted). When an
  operator turns it on, the resolved client IP is sent **per request inside the
  event payload** (`payload.ip`, supported since **Umami v2.17.0**) — never in a
  header, and requiring **no Umami instance configuration**, so a shared
  multi-site Umami is unaffected for its other sites (the instance-global
  `CLIENT_IP_HEADER` approach could not offer that). A pre-2.17 Umami simply
  ignores the field. When `payload.ip` is set, Umami ignores proxy geo headers
  and does a local GeoIP lookup, so the result is deterministic regardless of
  what fronts the instance. Umami v2 hashes the IP into a daily-rotating
  session hash and stores derived geo, not a raw IP column — but **verify this
  against your own Umami version**, and make sure Umami's own fronting proxy
  does not access-log request bodies.
- **Location detail is operator-selectable, down to "no city, no IP, ever."**
  With forwarding on, `analytics.geoMode` picks the granularity: **`full`**
  (the default) sends `payload.ip` as above — Umami derives country, region,
  and city, and keeps real per-visitor uniqueness. **`coarse`** never sends the
  IP at all: the relay copies the fronting Cloudflare edge's `cf-ipcountry` +
  `cf-region-code` request headers onto the outbound Umami call (Umami reads
  provider geo headers when `payload.ip` is absent), and the city header is
  **never** sent — city is structurally absent from the operator's Umami, and
  the visitor IP never leaves the backend. Costs: unique-visitor counts
  degrade to per-user-agent buckets (Umami hashes the request IP, which is
  then always the backend's); region requires the free Cloudflare "Add visitor
  location headers" Managed Transform on the zone; and an Umami that is
  itself behind Cloudflare with IP geolocation enabled will overwrite the
  relayed `cf-ipcountry` — disable geolocation on that zone. CF's non-country
  sentinels (`XX` unknown, `T1` Tor) are dropped rather than recorded. The
  inbound geo headers are covered by the same Caddy gate as the IP header:
  with `CADDY_TRUST_CF_HEADER` unset (the default) Caddy strips
  `CF-IPCountry`/`CF-Region-Code`/`CF-IPCity` before the backend, so a client
  can't spoof geo values into the operator's Umami on a deployment that isn't
  genuinely Cloudflare-fronted.
- **The IP the relay forwards is operator-selectable — analytics-only trust.**
  By default it is the fail-closed `resolveClientIp` (the `CF_FRONTED` /
  `TRUSTED_PROXY_HOPS` env trust that also feeds rate limiting — right-anchored
  XFF hop counting handles CDN → tunnel → edge chains generically; tune the hop
  count with the `GET /api/v1/admin/client-ip` diagnostic). For chains where
  XFF doesn't survive, `analytics.ipHeader` names a **single-IP fronting-CDN
  header** to read instead (`cf-connecting-ip`, `fastly-client-ip`, or a custom
  name; `x-forwarded-for` is refused — that's what hop counting is for). This
  trust is **deliberately scoped to the relay** and never feeds
  `resolveClientIp`, so an `admin:settings:write` token cannot widen the
  security-path IP trust; a header the chain doesn't actually set is
  client-spoofable, and the worst case is wrong geo in the operator's own
  Umami. The chosen header name is audited. Note: the stock Caddyfile strips
  `CF-Connecting-IP` before the backend; a genuinely Cloudflare-fronted
  deployment sets `CADDY_TRUST_CF_HEADER=true` on the web service (and must
  lock the origin to CF-only traffic).
- **The audit log never records the Umami URL or website id** —
  `admin.analytics.change` stores booleans plus a truncated hash of the URL
  (`umamiUrlHash`), so a silent repoint of this exfiltration-capable endpoint
  is detectable without the host ever being persisted.
- **Fail-soft + silent:** the relay answers 202 regardless of Umami's outcome,
  bounds the outbound call to 1s, reads no response body, and logs nothing (a
  log line here would carry a UA/IP). A per-IP rate-limit policy
  (`telemetry.send`) caps the outbound amplification. Counts are therefore
  approximate by design — treat Umami numbers as trends, not truth.

## 7. Issue telemetry (member-consented, unlinked)

When a member switches servers or reports a connection problem, the dialog
offers an optional "Include connection details" block (checked by default,
one-click decline). What it does and does not do:

- **What can be sent:** country, city, and network provider (ASN) — never an
  IP. The dialog shows the exact values before sending and every field is
  **member-editable**: the prefill comes from the CDN edge's view of the
  request, which is the VPN exit's network (not the member's) whenever they
  report from inside the tunnel, so members are told to correct it.
- **Unlinked by design:** telemetry rows (`issueReports` table) carry no
  userId, no subscriptionId, and no IP. They answer "what is failing, where,
  on which networks" — never "who". The per-user audit log records only the
  bounded reason enum, exactly as before. City-level geo exists **nowhere else
  in the system** (the analytics relay deliberately never reads `cf-ipcity`);
  here it exists only with the member's consent and the operator's opt-in.
- **Operator gates (`diagnostics.*`, Admin → Telemetry):** a master switch,
  a per-field allowlist (country / city / ASN), and `cloudflareEnabled` —
  geo headers are read only when the operator affirms Cloudflare is in front
  (off-CDN they are client-spoofable). Country/city come from `cf-ipcountry` /
  `cf-ipcity` (the free "Add visitor location headers" Managed Transform);
  ASN needs a Transform Rule that sets the configured header (default
  `x-client-asn`) from `ip.src.asnum`.
- **Bounded:** values are sanitized to narrow shapes (2-letter country,
  numeric ASN, 64-char city), report submissions are rate-limited per member,
  and rows are deleted by a daily sweep after the admin-tunable retention
  window (default 90 days).

## Downstream-deployer checklist

If you deploy or fork FCP, keep the posture:

- [ ] `IP_HASH_SALT` set (the deployer auto-generates it; never blank it).
- [ ] Caddy keeps `log default { output discard }` (don't add a site `log` that
      writes to a file/stdout unless you truly intend to log client IPs).
- [ ] `RUST_LOG` leaves `convex-cloud-http` at `warn` (or use `warn`).
- [ ] Cap: `RATELIMIT_IP_HEADER` unset; IP geolocation off; `CAP_DISABLE_ERROR_LOGGING=true`.
- [ ] Don't add a reverse-proxy access log at any fronting layer (Pangolin / CDN)
      that persists client IPs beyond what you need for abuse handling.
- [ ] If you add a new rate limit or audit event, bucket on `ipHashSubject(ip)`
      (the hash lives only in the ephemeral `rateLimits` counter) and keep the audit
      payload within the allowlist — never persist an IP, hashed or otherwise.
- [ ] Analytics (§6): leave `analytics.forwardIp` off unless you have confirmed
      your Umami version's IP handling AND that Umami's fronting proxy doesn't
      access-log requests; when adding a member-facing SPA route, add it to
      `ROUTE_ALLOWLIST` in `convex/lib/umami.ts` or it reports as `/other`.
- [ ] Nodes (§5): Xray Config Profile has `log.access:"none"` + `loglevel:"none"` +
      `dnsLog:false` (+ `maskAddress:"full"`) and `policy.statsUserOnline:false`;
      node container logging driver `none`. Enforced by `ansible-role-freesocks`;
      verify per §5 on any new node.
