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
docker compose -f docker-compose.beta.yml logs backend | grep 'GET /api'   # → empty
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
- [ ] Nodes (§5): Xray Config Profile has `log.access:"none"` + `loglevel:"none"` +
      `dnsLog:false` (+ `maskAddress:"full"`) and `policy.statsUserOnline:false`;
      node container logging driver `none`. Enforced by `ansible-role-freesocks`;
      verify per §5 on any new node.
