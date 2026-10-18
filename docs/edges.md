# Edges

An **origin** is a place that members reach only through something FCP can replace. The origin
can be a node on a backend FCP knows (a Remnawave node), a whole backend server (an Outline
instance), or an address the operator described by hand. An **edge** is what fronts it: any
frontable proxy. Today an edge is one of two **layers**:

- **L4**: a provider-managed cloud load balancer that forwards a TCP port to the origin. The
  origin terminates its own protocol (REALITY, TLS, plain); the edge is an address.
- **L7**: a CDN front that terminates TLS and HTTP and forwards an HTTP-carried transport
  (WebSocket, HTTP Upgrade, gRPC, XHTTP) to the origin. The edge is a **hostname** under an
  operator-owned zone; the CDN's own certificate and anycast addresses serve it.

Censors block the edge's public address or hostname, not the origin, so the edge is the unit
that gets replaced. What an origin speaks is described per **listener** (a port + protocol /
stream transport / security); the listener decides what the renderer rewrites in a member's
connection and which layers can carry it. Delivery is **edge-required**: a subscription
covered by an origin is served a rendered body or an unavailable response, never the origin
body. This document describes how FCP registers origins, provisions, publishes, rotates and
observes edges, and the contract the node role (Ansible) follows. It is provider-neutral on
purpose: nothing here says which providers, regions, zones, targets or names a given deployment
uses.

Admin surface: **Admin → Edges** (`/admin/edges`) and `/api/v1/admin/edges/*`; probe
telemetry lives under **Admin → Edges → Advanced → Probes** (`/admin/edges/probes`; the former
`/admin/telemetry/probes` redirects there). A backend node's own page is on Servers
(`/admin/servers/...`, see `docs/servers.md`), with its edges embedded. Every request under the
API prefix is HPKE-sealed by verb class (see [Sealing](#sealing)).
How to take one node from the role run to a member connection is the runbook
"Deploy a fronted node" in `docs/servers.md`.

## Supported matrix

What a member's client can reach through an edge, per protocol, stream transport, security,
layer and client format. A **yes** is a claim only because a real connection test proves it:
the release gate `bun run test:integration:edge-connection` (job **Member connects through an
edge**, `docs/client-compatibility.md` "Edge connection") takes a real node through the real
lifecycle, fetches the member's real `/api/v1/sub` body in that format, and the pinned
reference engine (sing-box, or Mihomo for the Clash format) fetches a page through the edge
with it. Everything else says why it is not offered. The table is rendered from
`tests/compat/manifest.ts` (`edgeMatrix`; print it with `bun tests/compat/edgeMatrixTable.ts`)
and pinned to it by `convex/edgeMatrix.test.ts`; the gate refuses a claimed cell it has no case
for.

<!-- edge-matrix:start -->

| Protocol    | Transport    | Security | Layer | sing-box | Mihomo | Outline key | Notes                                                                                              |
| ----------- | ------------ | -------- | ----- | -------- | ------ | ----------- | -------------------------------------------------------------------------------------------------- |
| VLESS       | raw TCP      | REALITY  | L4    | yes      | yes    | n/a         | mode `freedom-reality`                                                                             |
| VLESS       | XHTTP        | REALITY  | L4    | no       | yes    | n/a         | mode `freedom-xhttp`; sing-box has no XHTTP transport (the panel leaves the entry out of its body) |
| VLESS       | raw TCP      | TLS      | L4    | yes      | yes    | n/a         | operator's profile                                                                                 |
| VLESS       | WebSocket    | TLS      | L4    | yes      | yes    | n/a         | operator's profile                                                                                 |
| VLESS       | HTTP Upgrade | TLS      | L4    | yes      | yes    | n/a         | operator's profile                                                                                 |
| VLESS       | gRPC         | TLS      | L4    | yes      | yes    | n/a         | operator's profile                                                                                 |
| VLESS       | XHTTP        | TLS      | L4    | no       | yes    | n/a         | operator's profile; sing-box has no XHTTP transport (the panel leaves the entry out of its body)   |
| Trojan      | raw TCP      | TLS      | L4    | yes      | yes    | n/a         | operator's profile                                                                                 |
| Trojan      | WebSocket    | TLS      | L4    | yes      | yes    | n/a         | operator's profile                                                                                 |
| Shadowsocks | raw TCP      | none     | L4    | yes      | yes    | yes         | operator's profile; Outline key: an Outline server                                                 |
| Hysteria 2  | UDP (QUIC)   | TLS      | L4    | no       | no     | n/a         | UDP: no edge adapter forwards UDP yet (docs/edges.md "UDP"); served direct, never fronted          |
| TUIC        | UDP (QUIC)   | TLS      | L4    | no       | no     | n/a         | UDP: no edge adapter forwards UDP yet (docs/edges.md "UDP"); served direct, never fronted          |
| VLESS       | WebSocket    | TLS      | L7    | yes      | yes    | n/a         | mode `freedom-ws`                                                                                  |
| VLESS       | HTTP Upgrade | TLS      | L7    | yes      | yes    | n/a         | operator's profile                                                                                 |
| VLESS       | gRPC         | TLS      | L7    | yes      | yes    | n/a         | operator's profile                                                                                 |
| VLESS       | XHTTP        | TLS      | L7    | no       | yes    | n/a         | operator's profile; sing-box has no XHTTP transport (the panel leaves the entry out of its body)   |
| Trojan      | WebSocket    | TLS      | L7    | yes      | yes    | n/a         | operator's profile                                                                                 |
| VLESS       | raw TCP      | REALITY  | L7    | no       | no     | n/a         | REALITY terminates on the node: a CDN front would have to terminate it                             |
| VLESS       | XHTTP        | REALITY  | L7    | no       | no     | n/a         | REALITY terminates on the node: a CDN front would have to terminate it                             |
| VLESS       | raw TCP      | TLS      | L7    | no       | no     | n/a         | not an HTTP transport: a CDN front carries HTTP only                                               |
| Trojan      | raw TCP      | TLS      | L7    | no       | no     | n/a         | not an HTTP transport: a CDN front carries HTTP only                                               |
| Shadowsocks | raw TCP      | none     | L7    | no       | no     | no          | not an HTTP transport: a CDN front carries HTTP only                                               |
| Hysteria 2  | UDP (QUIC)   | TLS      | L7    | no       | no     | n/a         | UDP: no edge adapter forwards UDP yet (docs/edges.md "UDP"); served direct, never fronted          |
| TUIC        | UDP (QUIC)   | TLS      | L7    | no       | no     | n/a         | UDP: no edge adapter forwards UDP yet (docs/edges.md "UDP"); served direct, never fronted          |

<!-- edge-matrix:end -->

How the cells are proven:

- **Source.** A _mode_ cell is a transport FCP builds the profile for (a connection mode of
  Servers; the node role enrolls the node). An _operator's profile_ cell is a transport an
  operator wrote into the node's Xray profile; FCP discovers it on the panel node and the
  guided setup fronts it, one edge per transport. The **Outline key** column is an Outline
  server origin (a whole backend server, set up by hand: Outline has no node inventory for
  the guided setup): its member's `ss://` key, rewritten to the edge, connected with the
  reference engine's Shadowsocks, which is what an Outline client speaks.
- **L4** is proven with the UpCloud adapter behind a fake API wiring a real TCP forwarder (one
  address per load balancer); **L7** with the Cloudflare adapter behind a fake API routing a
  real CDN-style front (a proxied record per edge, its Origin Rule's port honoured). The other
  adapters speak the same layer; their wire contracts are pinned by `wireContract.test.ts`.
- **Share links** (v2rayN, v2rayNG, Hiddify, Shadowrocket and the like) are rendered for every
  cell the catalogue lists, and the L4 isolated test link (Try it) is one, imported into the
  engine that speaks it before every tick; no link-list application runs in the gate.
- **gRPC behind a CDN** needs the origin on port 443 (Cloudflare proxies gRPC to 443 only; the
  plan refuses another port as `origin_port_not_carried`) and the zone's gRPC switch on, a
  dashboard-only setting FCP cannot read or flip: with it off the CDN answers 403 and the front
  proof reports `grpc_disabled`.

Outside the matrix altogether:

- **VMess**: no renderer codec; not in the listener catalogue.
- **Xray JSON subscriptions**: the renderer rewrites share links, sing-box JSON and
  Clash/Mihomo YAML; an Xray JSON body is refused (`unsupported_format`), never served with the
  origin in it.
- **Outline keys over WebSocket (WSS dynamic keys)**: an Outline origin is a plain Shadowsocks
  key rewritten by address; there is no WebSocket form to front.
- **sing-box over XHTTP**: sing-box has no XHTTP transport, so the panel leaves an XHTTP entry
  out of a sing-box body and FCP has nothing to render.

A gRPC transport on loopback behind the node's ingress (`lib/backend/ingress.ts`) is reached by
its service name as the route path (`/<serviceName>`, the calls are `/<serviceName>/Tun`), and
only through a route that declares `upstream: "h2c"`: the role must proxy it over HTTP/2
cleartext (Caddy `reverse_proxy h2c://127.0.0.1:<port>`), and a route without the marker is
HTTP/1.1, which no gRPC stream crosses, so the transport stays loopback. No connection mode
declares such a route yet; the bootstrap answer carries the marker for when one does.

### UDP

No edge is offered for a UDP listener (Hysteria 2, TUIC): `udp` is false for every provider in
`EDGE_PROVIDER_CAPABILITIES`, and stays false until an adapter forwards UDP AND a Hysteria 2
connection through a UDP forwarder passes in the gate. Discovery maps both protocols
(`hysteria2/udp/tls`, `tuic/udp/tls`) so the plan says why (`no_udp_provider`), and their
direct Hosts are left alone: they keep serving members direct. On a node whose other
transports are fronted, a direct UDP Host at the origin address would hand members the
origin, so the plan lists it as uncovered and the run hides it only with the operator's
approval (otherwise rehearsal refuses the leak).

What the L4 adapters' providers offer (2026-10-16):

| Adapter  | UDP listener in the provider's API                                      | FCP adapter |
| -------- | ----------------------------------------------------------------------- | ----------- |
| UpCloud  | no: frontends are `tcp` or `http` mode                                  | TCP only    |
| Scaleway | no: its load balancer does not support UDP                              | TCP only    |
| Gcore    | yes: listener protocol `UDP` (with a UDP health monitor, Octavia-style) | TCP only    |
| OVHcloud | yes: Octavia-based, `UDP` listener protocol with a `UDP` pool           | TCP only    |

Gcore and OVHcloud are where UDP fronting would start: a UDP listener and pool plus a UDP
health check in the adapter, then the proof above.

## Model

| Concept          | Table                  | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Provider account | `edgeProviderAccounts` | One cloud or CDN account: write-only credentials, fixed settings (project/region/zone/network, or the DNS zone for an L7 provider), priority, a daily allocation budget, a live-edge cap, `qualified`. An L7 provider whose hostnames' DNS lives elsewhere names a **DNS account**.                                                                                                                                                                              |
| Edge template    | `edgeTemplates`        | Per provider (optionally per account): the full provisioning parameters, validated by the adapter's schema. Provisioning records the template hash; L7 edges also freeze the effective parameters into their intent.                                                                                                                                                                                                                                             |
| Origin           | `relays`               | One ORIGIN behind edges: its `origin` (kind + backend/node or backend server), `originAddress` (what edges dial; never published), `hostMode` (who writes the client-facing backend Hosts), published pool, publication epoch, rotation limits, detector state, quarantine, `probeNode`, the L7 qualification credential.                                                                                                                                        |
| Listener         | `relayListeners`       | One port the origin answers on: `protocol / streamTransport / security` (the catalogue below), server names (REALITY SNIs or certificate names) with retire/drain, an optional REALITY target, HTTP transport parameters, `originTransport` (how an L7 front dials it), a **match rule** (how its template entry is found in a body), the backend transport it maps to, the backend Host FCP owns for it, `source` (role or admin) and a canonical `configHash`. |
| Edge             | `edges`                | One provider resource bound to a LISTENER: its layer, the resource-step ledger, child resources, addresses (IP literals for L4, the hostname for L7), publication state and pool index, health, readiness, front qualification, live snapshot, reachability. L7 edges carry a frozen **provision intent**.                                                                                                                                                       |
| Rotation         | `edgeRotations`        | One provision / publish / replace run: phase, step version, operation claim, per-listener Host plan, previous binding, live event log; its audit trail is assembled on read.                                                                                                                                                                                                                                                                                     |
| Delivery binding | `edgeDeliveryBindings` | The edge-required policy an origin imposes on the subscriptions of its node or backend server, kept apart from the origin row so deleting the origin never silently restores raw delivery.                                                                                                                                                                                                                                                                       |
| Probe target     | `probeTargets`         | An operator-entered public host:port probed alongside the derived targets (edges, origin targets). Operator evidence only.                                                                                                                                                                                                                                                                                                                                       |
| Probe run        | `probeRuns`            | One reachability measurement of one target address from one source.                                                                                                                                                                                                                                                                                                                                                                                              |
| Reachability     | `probeReachability`    | Per target, per country, per source, per address family: the last run's vantage counts and verdict; summarised onto the target's own row.                                                                                                                                                                                                                                                                                                                        |

The supported providers are listed in `src/shared/contracts/edgeProviderIds.ts`; each has an
adapter under `convex/lib/edges/providers/` implementing `EdgeProvider`. Generic code never
branches on a provider id; it reads `EDGE_PROVIDER_CAPABILITIES` (`layer`, `addressKind`,
`l7Transports`, `needsDnsAccount` / `providesDns`, `originPortMode`, `udp`, the async and
health flags) and the adapter's template schema.

### Origins and Host modes

`relays.origin` is one of:

| Kind             | What it is                                   | Subscriptions render?                      | Backend Hosts                                                |
| ---------------- | -------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------ |
| `panel-node`     | a node on a backend FCP knows (node pinning) | yes (pinned node)                          | `fcp` when the backend has Host management, else `none`      |
| `backend-server` | a whole backend server (an Outline instance) | yes (single-key delivery, address rewrite) | `none`                                                       |
| `manual`         | an address the operator described by hand    | no (nothing FCP serves maps to it)         | `none`; the operator wires clients from the `connectionPlan` |

`hostMode` says who writes the client-facing Hosts: `fcp` (FCP creates, flips and deletes
them through a persisted state machine, see **Host ownership**), `operator` (FCP never writes;
the origin's `hostsPlan`, shown by the guided setup and the Listeners tab, says what to create)
or `none` (there is no Host). The
handoff is explicit: `fcp → operator` keeps every Host and marks it `adopted`; `operator →
fcp` needs every listener's Host validated and adopted first (`edge.host_adopt_required`).
One origin per node, one per whole server (`edge.node_already_bound` /
`edge.server_already_bound`); `originAddress` cannot change while edges dial it
(`edge.origin_address_locked`), the origin kind never changes (`edge.origin_kind_locked`), and
an address that is a published edge is refused as an origin (`edge.origin_is_edge`).

### Listener catalogue

A listener speaks one valid combination of three fields (`src/shared/contracts/edgeProtocolIds.ts`):

| protocol             | streamTransport               | security  | notes                                                           |
| -------------------- | ----------------------------- | --------- | --------------------------------------------------------------- |
| `vless`              | `raw`                         | `reality` | REALITY: `realityTarget` + server names required                |
| `vless`              | `raw`                         | `tls`     | server names = the certificate's                                |
| `vless`              | `ws` / `httpupgrade` / `grpc` | `tls`     | L7-frontable (a VLESS proof)                                    |
| `vless`              | `xhttp`                       | `tls`     | L7-frontable where the provider carries it; no sing-box (below) |
| `vless`              | `xhttp`                       | `reality` | L4 only (the node terminates); no sing-box (below)              |
| `trojan`             | `raw` / `ws`                  | `tls`     | `ws` L7-frontable (a Trojan proof); `raw` L4 only               |
| `shadowsocks`        | `raw`                         | `none`    | address/port rewrite only; Outline keys are `ss://`             |
| `hysteria2` / `tuic` | `udp`                         | `tls`     | discovered; no provider forwards UDP (`no_udp_provider`, "UDP") |

Anything else is `invalid_combination`. The catalogue derives `usesSni`, `needsTarget`,
`isHttpTransport`, `usesHostHeader`, `transport` and `l7Proof` (`vless` or `trojan`: which
authenticated request the front proof sends); `convex/lib/edges/protocols.ts`
adds the CODEC table (which subscription formats the renderer can rewrite per combination,
pinned by a test: a combination without a codec for every format it claims never ships).
`vmess` has no codec and is not in the catalogue.

**XHTTP.** An L4 forwarder carries an XHTTP listener like any TCP listener. An L7 front carries
it only when the provider declares `xhttp` in `l7Transports` (Cloudflare does; Fastly's
WebSockets product does not). Xray and Mihomo speak XHTTP (`network: xhttp` + `xhttp-opts`, where
the renderer writes `host`); sing-box has no transport for it, so its codec row covers share
links and Clash bodies, and a sing-box subscription of an edge-required XHTTP listener is
unavailable rather than served with the origin in it. The front
proof speaks `packet-up` (one `GET <path>/<session>` downstream, sequenced `POST
<path>/<session>/<seq>` uploads, every request carrying the `x_padding` Xray's server requires
in its `Referer`), the one mode every CDN passes; a transport declared `stream-up` or
`stream-one` refuses packet-up uploads, so its proof reports `transport_failed` / `mode` and it
stays L4-only. `transportParams.mode` records what the transport declares (`auto` when it declares
nothing). Under REALITY (`vless/xhttp/reality`, the `freedom-xhttp` mode of a backend set up in
Servers) the node terminates and impersonates its family's target, so only an L4 edge can front
it; there is no front proof for it and an L7 provider never carries it.

A deployable transport (Caddy terminates TLS in front of it, as for WebSocket, so Xray listens on
loopback and the listener is registered with the terminator's port and certificate name):

```json
{
  "tag": "VLESS_XHTTP_CDN",
  "listen": "127.0.0.1",
  "port": 8444,
  "protocol": "vless",
  "settings": { "clients": [], "decryption": "none" },
  "streamSettings": {
    "network": "xhttp",
    "security": "none",
    "xhttpSettings": { "path": "/xh", "mode": "packet-up" }
  }
}
```

Caddy proxies `/xh*` to that port (`reverse_proxy 127.0.0.1:8444`). The downstream is a
long-lived response, so nothing in front may buffer it: Caddy streams a `text/event-stream` body
on its own, and needs `flush_interval -1` only when the transport sets `noSSEHeader`. This
template has not been run behind Caddy yet; the proof above was validated against Xray
terminating TLS itself (the front-qualification harness).

**Discovery.** A backend-node origin's listeners can be derived from the node instead of typed:
`backends.listNodeInbounds` (capability `inboundDiscovery`; Remnawave: the node's active config
profile joined with the profile's Xray `inbounds[]` by tag, allowlisted fields only, never
clients, private keys, short ids or certificates; `docs/backends.md`) yields `BackendTransport[]`,
and the pure `mapTransportsToListeners` (`convex/lib/edges/inboundMapping.ts`) turns each into a
registration-shaped listener candidate or an `unsupported` row with a reason from
`INBOUND_UNSUPPORTED_CODES` (`inactive`, `tag`, `protocol`, `transport`, `security`,
`invalid`; worded in `src/client/lib/edgeCodes.ts`). vless / trojan / shadowsocks map, and so do
Hysteria 2 (Xray's `hysteria` inbound) and TUIC, as `udp` + `tls` whatever the stream says (QUIC
is both); tcp or raw → `raw`, ws / httpupgrade / grpc / xhttp (`splithttp`) → themselves (kcp,
quic are `transport`); REALITY
`dest`/`target` + `serverNames` → `realityTarget` + `tlsNames`; TLS `serverName` → `tlsNames`
(none = `needsName`: the operator supplies one before registering); ws / httpupgrade / xhttp
path + host, the xhttp mode and gRPC serviceName → `transportParams`; the transport tag + profile uuids → `panelBinding`
with the default `remark` match rule. Every candidate passes `validateListenerSpec`, and carries
`layers` and `formats`. The listener key is `slug10 + base36(sha256(tag))[0..6]` (the first ten
lowercase alphanumerics of the tag plus six hash digits; at most 16 chars, deterministic, unique
against the origin's existing keys). `originTransport` is never set by the mapper: only the
**origin probe** can say how an L7 front may dial the node. `GET
relays/inbound-candidates?backendServerId=&nodeUuid=` (throttled; the action
`edgeOriginProbe.inboundCandidates` in `convex/edgeOriginProbe.ts`
with the `"use node"` sockets in `edgeOriginProbeOps.ts`, pure rules in
`lib/edges/originProbe.ts`) returns the mapper output with `originTransport` filled where the
probe succeeded and `layers` recomputed: security `none` -> a TCP answer on the port gives
`{scheme: http}` (L7-only); `tls` -> a handshake with SNI = the first name, offering the ALPN a
front would (`h2` alone for gRPC, which an h2-only origin requires; `h2` and `http/1.1` for
XHTTP; `http/1.1` otherwise), `certPublic` = the chain verifies against the system store,
`certNames` = the leaf's names, `acceptsHostHeader: names` unless an HTTP/1.1 request with a
foreign Host header still answers 2xx (`any`; never sent to a gRPC origin). Like the internal
reachability probe it dials public literals only (a name is resolved first, every answer must be
public, the literal is dialled). Without a successful probe the candidate stays L4-only and
carries the probe's reason. For an **enrolled** node the plan reads the node from its intent
(`nodeIntents.enrolledOriginOf`: the origin name plus the ingress), and the Host-header answer
comes from the node's verified ingress, not the probe: the `ingress_verified` evidence recorded at
`machine_ready` with `settings.ingress.hostHeader: 'any'` gives `acceptsHostHeader: any`
(`withVerifiedIngress`).

### Layers

`listenerLayers(listener)` (`convex/lib/edges/layers.ts`) decides which layers can carry a
listener from the **complete** member-to-origin chain, never from the protocol name alone:

| Listener                                                                                                                                                                                      | L4                                   | L7  |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | --- |
| No origin transport declared: raw TCP to the transport                                                                                                                                        | yes                                  |     |
| Origin speaks plaintext HTTP behind the CDN (`originTransport.scheme = http`), HTTP transport                                                                                                 |                                      | yes |
| Origin speaks HTTPS, `vless` or `trojan` HTTP transport, certificate publicly trusted AND every active name covered by a certificate name (RFC 6125) AND the node accepts those names as Host | yes                                  | yes |
| Origin speaks HTTPS, HTTP transport without an authenticated proof (`l7_proof_unsupported`)                                                                                                   | yes                                  |     |
| Origin speaks HTTPS, `reality` / raw `tls` / `none`                                                                                                                                           | yes                                  |     |
| UDP listener                                                                                                                                                                                  | only with a provider declaring `udp` |     |

`hostTargetFor(edge, proto, selectedSni)` is the single source of the Host tuple the backend
Host and the renderer share: L7 → `{ hostname, 443, sni: hostname, host: hostname }`; L4 HTTP
transport → `{ address, port, sni, host: sni }`; L4 `reality` / `tls` → `{ address, port, sni,
host: null }`; `none` security → `{ address, port, sni: null, host: null }`.

### L7 edges

An L7 edge is one hostname `<label>.<zone>` minted deterministically from the edge's
provider-side name (`convex/lib/edges/hostname.ts`). Everything a step, discovery, describe or
destroy needs is **frozen** into `edges.provisionIntent` when the edge is planned. Readiness
has three dimensions: `dns`, `certificate` and `front` (the end-to-end qualification below).

**Front qualification.** Before an L7 edge is published or selected as a standby, FCP opens a
short **authenticated test session** through it (TLS to `hostname:443`, the listener's
transport exactly as deployed, then a VLESS or Trojan request for the origin's qualification
credential fetching a neutral `204` target). A `vless` HTTP-transport `tls` listener is proved
with its VLESS id (`l7Proof: 'vless'`), Trojan over WebSocket with the same account's Trojan
password (`l7Proof: 'trojan'`, stored next to the id as `qualificationTrojanPassword`, never
returned by any read); a credential of the wrong kind is `no_qualification_credential`, every
other combination is `unsupported_protocol` and never L7-fronted.
The result is stored with its **binding** (hostname, listener id + revision, the three
protocol fields, transport parameters, intent hash) and an expiry
(60 minutes, a constant: `EDGE_PLUMBING.l7QualificationTtlMs`); publication re-derives the binding inside the mutation
and refuses `front_unqualified` / `front_qualification_stale`. The reconcile cron re-qualifies
published L7 edges before their qualification expires.

A detector-triggered L7 replacement waits up to 15 minutes for **affected-country evidence**
for the new front (`EDGE_PLUMBING.l7QualifyTimeoutMs`); the reconcile cron renews a proof a
quarter of its lifetime before it lapses (at most six re-proofs a pass); a failed renewal is
retried, and once the proof lapses the front leaves rendering until a proof succeeds. **Importing a front**
(`ImportFrontDialog`, `POST relays/{id}/adopt`) records an existing CDN front against a
listener and publishes it only with a current proof (`front_unqualified` otherwise).
`edge.l7.autoSelect` (default off) governs automatic selection of L7 accounts; manual
provisioning, a guided setup run's chosen account and publishing work regardless.

### Publication

Provisioning and publication are separate. An edge is `unpublished` (a standby), `published`
at a **pool index**, or `draining`. An origin's `publishedEdgeIds` is ordered by pool index and
is ONE origin-wide order for the subscriber PRF, whatever listener each edge serves.
`publicationEpoch` bumps on every change that alters what subscribers should receive (pool,
listener, names, switch) and is part of the cache token of the fronted subscription route.

**Per-listener template edge.** An edge is bound to one listener and can serve only that
listener's protocol and port, so each listener has its own `templateEdgeId`: its lowest-index
published edge. The listener's backend Host (`fcp`), its `hostsPlan` row (`operator`) and its
`connectionPlan` row all derive from that edge; a listener with no published edge is
unavailable. Replacing an edge re-plans **only the listeners whose template edge it is**
(`hostPlan[].listenerKey`), and a direct publish that would make an edge its listener's
template edge under `fcp` is refused (`edge.needs_rotation`): the rotation machine does the
flip.

**Coverage.** The pool exists to give every deployed, enabled, non-retired listener ("coverage
listener") a published edge, so capacity follows the listeners (`convex/lib/edges/poolCapacity.ts`):
`ensurePoolCapacity` raises `desiredPublished` to the coverage-listener count (bound 1..8,
`MAX_DESIRED_PUBLISHED`; the admin create and the listener upsert answer `warnings:
['edge.pool_raised']` when it did) on every origin create, admin listener add and listener
re-enable, and the reconcile cron applies it each tick. A pool that is already FULL while a
listener is uncovered is **expanded** within the cap (`desiredPublished = min(8, published +
uncovered)`, audited `edge.pool_expanded`); it is never shrunk. The cap is enforced where the
operator can act on it rather than clamped silently: a listener body (the create or the CMS
upsert) that would leave more than eight deployed, enabled listeners is refused
(`edge.listener_cap`; a pre-existing excess is not made worse), and `relays.update` refuses
lowering `desiredPublished` below the coverage-listener count (`edge.pool_below_coverage`).
**Reserved allocation**
(`allocatePoolIndex`, `convex/lib/edges/pool.ts`, used by the rotation's `applyPublish`, the
cron's `publishStandby` and both direct publish paths): the free slots are held for uncovered
listeners, so a second edge for an already covered listener is refused (`edge.pool_reserved`,
a `pool_reserved_standby` rotation event) while `freeSlots <= uncoveredListeners`. At the cap
no expansion is possible: attention raises `pool_rebalance` and the operator calls
`POST relays/{id}/rebalance`, which sends ONE duplicate (a published edge that is not its
listener's template edge, highest index first) back to standby (`edge.no_duplicate` when
there is none), bumps the epoch and lets upkeep publish the uncovered listener. Never automatic:
unpublishing changes what members receive.

**Deferred binding and setup ownership.** An origin a guided setup creates is inserted with
`bindingDeferred: true` + `setupOwned: true` (internal arguments of `relays.create`; a request
body never sets them): no delivery binding is written, so the origin keeps serving its raw body,
and there is NO shortcut that binds it when an edge publishes. Only `claimDeliveryBinding`
upserts the binding, bumps its policy version, refreshes the mirrors and clears the flag. Its one
caller is the guided setup run's stage-8 `goLive` mutation, after the activation promotion: a
first protection, `require-edges` (which only starts a run) and a re-protect run all bind
there. A re-protect claims again (a new policy version) and then retires the addresses its new
ones replace. A manual origin never gets a binding. A plain create binds at once; a listener change on a deferred
origin keeps it deferred. While `setupOwned`, reconcile upkeep and the detector's
automatic replacement (veto `setup_owned`) leave the origin alone, whatever the run's state. A rotation start of any kind on an owned origin that does not come from the run itself (`setupRun`) is refused (`edge.setup_owned`): a manual publish, replace or burn would change the endpoint under the run's hides and rehearsal.
`setup-status` warns `binding_deferred` on the publish step (never `members_dark`, which needs
a binding); attention raises `go_live_pending` once an edge is published.

**The publication gate** (`relays.checkPublishable`, shared by `applyPublish`, `publishStandby`,
the direct publish path, adopt-and-publish and the `publish` / `replace` rotation starts, so
nothing can disagree) admits an edge into the pool only when it is active, addressed, on a
deployed + enabled listener, carried by its provider at its layer, **and verified for the
configuration it holds now**: an L7 front needs a current authenticated proof
(`frontQualification`, bound to the listener revision + intent); an **L4 edge needs the
operator's own confirmation** (`edges.verification`, `lib/edges/verification.ts`), taken per
endpoint against `{endpoint, listenerKey, listenerRevision, configHash}` where `configHash`
covers the listener's idempotency hash, the edge's template hash and its addresses / forwarding
ports and, when the origin is an **enrolled** node, the node's REALITY authentication revision
(`panelNodeIntents.authRevision`: the keyed digest of its key pair, short ids and clock bounds).
The digest is folded into the hash, never shown or echoed on its own, so the binding a
confirmation echoes keeps its shape; every builder and checker resolves it the same way
(`lib/edges/verificationContext.ts`). A key, short-id or clock-bound change therefore returns an
enrolled node's L4 endpoints to "needs a test" (no client has proven the new key through them;
attention `retest_needed` with code `reality_key_changed`, the Try it card and the approval card
say so). Unmanaged nodes, whole-server, manual and Outline origins carry no auth component and
behave as before; L7 proofs and the probe `partial` rung are not bound to it. Refusal code
`edge.unverified_endpoint`. The record proves nothing by itself:
`verificationCurrent` compares revision and hash, so a listener revision bump or a
re-addressing returns the endpoint to "needs a test" (attention `retest_needed`) without
anybody clearing anything. One name change is deliberately **not** a revision bump:
**retiring a server name on a REALITY listener** bumps `namesRevision` and the publication
epoch instead (`nameRetireKeepsVerification`, `convex/lib/edges/verification.ts`). On REALITY
the names are an allowlist the node checks; removing one changes neither the path nor the key
material the operator's test proved, and the names that remain are the ones that were already
accepted. Without this, reacting to a blocked name would stop every L4 edge of that listener
rendering until a human retested it. It does not extend to a TLS listener (its names decide
certificate coverage and an L7 proof binds to them), nor to adding or reactivating a name,
which stay revision bumps until something has proven the node accepts the name. The same
condition is applied again **at render time**
(`edgeRender.publishedEdgesOf`): a published L4 edge whose confirmation is no longer current
is ineligible exactly like a stale L7 proof, so nothing is rendered for it until it is
retested; it stays published (nothing unpublishes automatically). Nothing server-side can
promote an L4 edge past the probe ceiling (`partial`, see § Probes, written by the system
from probe evidence and never satisfying the gate): there is no authenticated REALITY client
in this stack, and backend online bits do not identify the path a member used.

Consequences, applied consistently: a **replace** of an L4 edge switches ONLY to an
already-tested spare of the same listener; with none the start is refused
(`edge.no_verified_spare`, not waived by `force`) instead of provisioning a doomed candidate
(the L7 path is unchanged: a listener that can be fronted at L7 with L7 selection allowed keeps
provisioning and proving a new front). A `provision` run that would publish an untested L4
edge ends with it as a **spare** instead (`unverified_standby`, attention `spare_untested`),
never failed and never destroyed; reconcile upkeep skips such a spare and does not provision
another. The detector records the refusal on the origin's suspicion (`lastRotateError`) and
attention raises **`needs_test`** (critical). Importing a live front with `publish: true`
carries the operator's statement `verified: true` (recorded as method `named_connection`);
without it the import is an untested spare.

**The test link** (`POST edges/{id}/test-link`, `convex/edgeTestLinks.ts`, throttled) (`POST edges/{id}/test-link/release {credentialId}` expires the temporary credential behind a link when the card closes or finishes, instead of at its TTL) is the one
verification mechanism for an L4 candidate that is not yet published (setup stage 4b, spares,
retests). It fetches the test credential's OWN subscription body and runs the real renderer with
`published = [this candidate only]` in dry-run: no pool change, no epoch bump, no Host write, no
snapshot, no persisted match rule touched. Before first publication the FCP Host does not exist
in that body, so the builder uses a **test-only matcher**: the intended transport
(`panelBinding.configProfileInboundUuid`) names the enabled backend Hosts on it at
`originAddress:originPort`, whose remarks identify the body's entry; the entry must agree with
the listener's protocol facts (scheme, transport, security); once the direct Host is hidden the
listener's own `<node>-relay-<key>` (or adopted legacy) remark names it instead; an Outline key
is matched whole. A missing or ambiguous match is refused (`edge.test_link_no_match`), never
guessed. The single entry is rendered through a transient whole-body context, so the output is
ONLY the candidate connection (labelled `FCP test <slug> <key>`): no direct entry, no backup, no
auto group. The response carries the binding `POST edges/{id}/verify` must echo (`{edgeId,
endpoint, listenerKey, listenerRevision, configHash, issuedAt}`, the same one
`verification-binding` derives) and records `method: test_link`. L7 edges refuse
(`edge.l7_proof_required`).

**Test credentials** (`convex/edgeTestCredentials.ts`). Remnawave tests reuse the origin's
**qualification credential**, minted on demand through `relayQualification.ensure`: a
**persisted operation** (`relays.qualificationMint`) whose deterministic username is written
BEFORE any backend call, so a crash between `issueUser` and `store` is settled on the next call by
re-finding the user by name (`backends.findUserByUsername`, the version-neutral
`by-username` read; capability `userLookupByUsername`) and adopting it, never by minting a
second one; a user not found waits for the settle rule (2 min + 2 quiet looks,
`credential_unresolved`) before a fresh name is issued; a stored credential is reused only when
its binding `{backendServerId, placement, modeSlug}` equals the request, otherwise it is
replaced and the old user goes through the owed-removal ledger. The credential's own subscription
locator is kept (`relays.qualificationSubscription`) so its body can be fetched. Outline has no
name lookup: a test link mints a **temporary access key** whose `edgeTestCredentials` row is
written before the create (`backendUserId` absent until issuance is observed) and is a durable
obligation the reconcile sweep finishes (expired after 24 h or released when the sheet closes /
the run is cancelled -> `deleteUser` with bounded retries; a delete that keeps failing is
`failed` and raises attention `test_key_cleanup`, retried by hand); a rehearsal on an empty
Outline server has no credential path (`use_manual_setup`).

**Account trust is a separate record.** The first confirmed endpoint of an untrusted L4
account also trusts the account (`edgeProviderAccounts.applyQualification`, with endpoint
evidence `{edgeId, endpoint, accountTestedAt, templateHash, listenerId, listenerRevision}`,
`by: 'admin'`) when the endpoint is evidence for the account **as it is now**: the
credentials passed a test after their last change and the edge's `templateHash` equals the
account's effective template hash (an adopted, template-less edge or one from an older
template verifies its own endpoint only; the confirm response says why in
`accountTrustReason`), unless a manual untrust holds automatic trust off (`autoQualifyHold`,
cleared by a manual trust or a credential change). A trusted account never exempts a NEW
endpoint from its own confirmation. L7 accounts are trusted **automatically**
(`lib/edges/autoQualify.ts`, `by: 'auto'`) when an active edge of the account carries a
current proof for the account's effective template NOW and the account was tested after its
last credential change; when an account it depends on (its DNS account) changed credentials
or settings, the dependents are stamped `dependencyChangedAt` and both the test and the proof
must postdate it (a proof taken through the old dependency never re-trusts the account);
evaluated after every passing proof and by the reconcile sweep. L4 accounts are never
auto-trusted.

### Rendering (what members receive)

Subscriptions are **rendered** by FCP. When the fronted `/api/v1/sub/<token>` route (or the
mirror refresh) fetches a body, it pins the node as before, then, in this order:

1. resolves each listener's **template entry** in the body by its `matchRule`: `remark`
   (the backend Host remark `<node>-relay-<listenerKey>` and any adopted legacy remarks),
   `address` (the entry's host:port equals `originAddress:originPort`) or `whole-body` (a
   single-entry body such as an Outline key). The entry must AGREE with the listener (its
   security / transport parameters) or it is `entry_mismatch`; an unknown scheme is
   `entry_unsupported`; two candidates are `ambiguous_match`. Overlapping rules on one origin
   are refused at registration (`edge.match_rule_overlap`);
2. marks an edge whose listener did not resolve, whose combination has no codec for this
   body format, or whose verification is no longer current (a lapsed L7 proof, an L4
   confirmation gone stale after a listener or address change) **ineligible** (it keeps its
   pool index);
3. assigns primary (+ backup) with a stable PRF keyed on the subscription's `renderKey` over
   the FULL pool order, walking forward past ineligible positions; one server name per emitted
   connection for name-presenting listeners, chosen from the listener's active names (a
   retired name is never selected again). How it is chosen is per listener (`sniPick`): the
   default PRF is a modulus over the stored list, stable when a name is retired but
   reshuffling nearly every subscriber when one is **appended**; `hrw1` is rendezvous hashing
   (`rankSniHrw`), where each name scores independently, so a new name moves only the
   subscribers it wins (about 1 in N+1) and a retired one moves only its holders. A listener
   whose name list is meant to grow should be on `hrw1`. Switching is an explicit operator
   action (`POST listeners/{id}/sni-pick {"version": "hrw1" | null}`): every member of that
   listener gets a different one of the names the node already accepts at their next refresh,
   so it is never a side effect. On `hrw1` a member holds **several names per endpoint**
   (`render.namesPerEndpoint`, default 3; `render.backupNames`, default 1): the top of their
   ranking, one more entry per name with the same address and credentials, labelled
   `<label> 2`, `<label> 3` and placed in the automatic group, so a client fails over by
   itself when one name is blocked. The backup's names avoid the primary's while the list
   allows it. Adding a name changes at most one of a member's names, and only to the new
   one; retiring one replaces only that slot. A family's `maxEntries` cuts the further names
   before it cuts a role, the IPv6 sibling belongs to the first name only, a single-key
   delivery stays one entry, and a listener on the default PRF or an L7 front keeps exactly
   one name. The snapshot persisted on the subscription names edges only, never which names
   a member holds;
4. rewrites: address, port, SNI, HTTP Host header (and Clash `servername`); never the
   credentials or routing (`pbk`, `sid`, `flow`, `path`, `serviceName`, SIP002 userinfo,
   `hy2`/`tuic` auth). Per **client family** (`render.clients.<family>`): auto-capable
   families get one named auto group, link-list families get labelled primary/backup entries.
   The labels are settings (`render.primaryLabel` / `render.backupLabel`, per family too),
   plain by default: `FreeSocks` and `FreeSocks (backup)`, since most members see one entry.
   A link-list app (v2rayNG, Anywhere, anything unrecognized) shows both side by side and never
   switches on its own, so the member page adds one line when the key has a backup: pick the
   backup when the first stops working (`hero.relayBackupHint`).
   An L7 edge renders as ONE entry (its hostname). A backend that hands out a single access
   key (Outline) renders in **single-key** style: one entry, no backup, no auto group;
5. checks every outgoing entry, emitted AND retained, against the origin address
   (`leak_detected`), and persists an **eligibility snapshot** (`subscriptions.lastRender`:
   epoch, family, resolved listeners, primary/backup edge) that the member's connection labels
   and report attribution read: they never reconstruct an assignment without the body.
   Attribution names an edge ONLY from that snapshot (current epoch) and covers unpinned
   whole-server subscriptions (Outline); no snapshot leaves the report at origin level.

**Edge-required delivery.** First the node's **delivery gate**, whatever the binding says: a
body that resolves to an enrolled node that is not live (or an unmanaged node under an open
maintenance hold) is answered `node_gated` even where no origin covers it. Then, a subscription
whose resolved place (the node the body was pinned to, else its backend server) is covered by an
active delivery binding is served the rendered body ONLY when the render produced ≥1 endpoint
and passed the leak check. Otherwise the route answers **HTTP 503 with `Retry-After`** and a
reason, one of `DELIVERY_UNAVAILABLE_CODES` (`src/shared/contracts/edgeCodes.ts`):
`relay_missing`, `relay_disabled`, `render_disabled`, `no_render_key`, `empty_pool`,
`unsupported_format`, `no_match`, `ambiguous_match`, `entry_mismatch`, `leak_detected`,
`node_gated`, `policy_moved` (the place's token moved twice during one request),
`family_disabled` (the client's app family has its render rule off) or `render_failed` (the
format's renderer could not rewrite the body for any other reason). A 503 keeps the client's
last configuration; an empty 200 would wipe it. Each one is counted per reason (§ Operations
safety, attention `delivery_refusals`). The policy is judged AFTER the fetch against the node
the body actually belongs to, so a first fetch without a stored pin and a pin that moved onto an
origin node are both classified correctly. A place no origin covers and whose gate is open passes
the body through. Either way, the last step renames the entries the backend named after a node
(`docs/servers.md` § "A direct node's addresses"); a rendered edge entry keeps its label.

**The cache token** (`epochTokenFor`, `convex/edgeRender.ts`): on a bound place
`<binding policyVersion>[:g<gateToken>]:<publicationEpoch>` (the epoch is -1 when the origin is
missing or disabled or rendering is off); on an unbound place with a managed node
`g<gateToken>`; no node, no token. `gateToken` is
`<gateVersion>:<committed Host count>:<committed edge count>:<hash of the candidate Hosts and
edges, or 0>` (`lib/backend/deliveryGate.ts`), so publishing or releasing a candidate re-keys
every cached body. The route reads the token before deciding and again after rendering,
re-renders once on a move, and answers `policy_moved` on a second move. Only bodies that passed
are cached. Creating an origin therefore takes members on that origin dark until an edge is
published and rendering is on; the setup flow says so.

**Delivery rehearsal** (`convex/edgeRehearsal.ts`, the guided setup's stage before go-live).
Before the binding is claimed, delivery is proven with the real renderer over **cohorts** derived
from authoritative membership (`convex/lib/edges/cohorts.ts`: one representative subscription per
distinct `backendPlacement` among the subscriptions pinned to the node, walked with `paginate`
over every page; a backend-server origin is one cohort of the whole server), never from render
snapshots. Each representative body is fetched FRESH per supported format (links, sing-box,
Clash, through catalogued client user agents) and run through `applyEdgeRender` in dry-run: no
persistence, no snapshot. Every non-dark cohort must yield `serve` in every format; an approved
dark cohort (`darkCohortKeys`) is excluded. An empty backend node is rehearsed from the rehearsal
credential (the qualification user on the node's placement; no usable placement ->
`choose_mode`); an Outline server with members from its real single-key subscriptions. The
result lists `familiesDisabled` (render rules off) and `proofsExpired` (published L7 fronts
whose proof lapsed), the **vector** the go-live mutation compares with `vectorNow`
(`listenerRevisions`, `renderConfigHash`, `publicationEpoch`, `qualificationEvidenceIds`, and for
an enrolled node `activation`: the run id with its machine, config, auth and delivery revisions,
so an old rehearsal never satisfies a new candidate), and
the **observation boundary**: the backend Hosts are listed before and after
(`edgeHostHides.observe`), the run is accepted only when both listings agree (else repeated, 3
attempts, then `listingChanged`), and the FINAL listing is the observation the go-live clock
starts from.

Mirrors follow the same policy: each mirror row records what its object holds (`validated`:
policy version, epoch, edges); creating an origin revalidates the origin's mirrors, replacing
a raw object with a fresh render or, when nothing can render, with an **unavailable stub**
(the URL is already distributed, so the object itself must stop serving the origin). The
account view and the issuance responses hand out ONLY the fronted token URL for a covered key
(`edgeRequired`); an Outline member imports a dynamic access key
`ssconf://<fcp-host>/api/v1/sub/<token>` and follows rotations by re-fetching. Outline over an
edge is **TCP-only** today (no adapter forwards UDP).

## Operations

| Operation                                 | Precondition                                                                                                                                                                                                                                                                                         | Spends budget                      | Writes Hosts                                                                  | Result                                                                                                                                    |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Create origin (admin)                     | origin + listeners in one body                                                                                                                                                                                                                                                                       | no                                 | no                                                                            | origin + listeners created (a slug in use is a `conflict`); the origin's subscriptions become edge-required                               |
| Import edge                               | origin + listener; optionally a provider account + the load balancer picked from its inventory                                                                                                                                                                                                       | no                                 | no                                                                            | edge `active`; managed when imported from an account, observe-only when entered by address (`managed:false`, never destroyed)             |
| Provision edge                            | qualified account (the listener's provider scope when set; any otherwise), template, capacity                                                                                                                                                                                                        | yes                                | no                                                                            | edge `active` + `unpublished` (or published when requested)                                                                               |
| Publish edge                              | active, has an address of its layer, listener deployed + enabled (+ an active name for a name-presenting listener behind L4), and verified for its CURRENT configuration: the operator's per-endpoint confirmation behind L4 (`edge.unverified_endpoint` otherwise), a current front proof behind L7 | no                                 | listener Host only when the edge becomes the listener's template edge (`fcp`) | `published` at the lowest free index; epoch++                                                                                             |
| Verify endpoint (L4)                      | an active, addressed L4 edge; the body echoes the binding `GET edges/{id}/verification-binding` showed (`edge.verification_stale` on any mismatch); an L7 edge refuses (`edge.l7_proof_required`, its proof verifies it)                                                                             | no                                 | no                                                                            | `edges.verification` stamped (`test_link` or `named_connection`); the first confirmed endpoint of an untrusted account trusts the account |
| Replace (rotate / burn)                   | a published target edge; for an L4 target a TESTED spare of its listener (`edge.no_verified_spare` otherwise, not waived by force)                                                                                                                                                                   | unless a compatible standby exists | listener Hosts whose template edge it is (`fcp`)                              | new edge `published` at the SAME index; old `draining` (burn = short drain)                                                               |
| Unpublish / retire name / retire listener | no running rotation, no quarantine; a listener retire needs NO non-destroyed edge on it                                                                                                                                                                                                              | no                                 | no                                                                            | new selections stop; the node keeps accepting through the drain; epoch++ and mirrors refresh                                              |

`hostMode:'operator'` means FCP never writes the Hosts: publishing proceeds without a flip and
replacing a template edge is refused (`edge.hosts_operator_managed`) unless forced.

### Operator endpoints (what the admin section is built on)

All under `/api/v1/admin/edges/`, sealed by verb like every other route; the read-only POSTs
(`setup-status` with a draft, `preflight`) are admitted by the read scope, like `render/preview`.

| Route                                                            | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET setup-status?relay=<slug>` / `POST setup-status {draft}`    | **Origin-scoped** readiness: nine steps (`origin`, `account`, `template`, `relay`, `edge`, `qualification`, `publish`, `rendering`, `automation`), each `done / ready / blocked / skipped` with blockers and warnings as codes, the selected context and `currentStep` (never a token or an address). A draft (origin + listener triples) is judged before the origin exists. Without either, the fleet aggregate plus the origins whose setup can be resumed. Manual origins skip `rendering`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `POST relays/{id}/test-provision`                                | The bootstrap path: ordinary selection excludes unqualified accounts, so a fresh account could never get its first edge. Explicit `{accountId, templateId?, listenerKey}`; the account must be enabled and **tested** but may be unqualified; budgets, capacity and layer compatibility apply; the result is always unpublished. Audited `admin.edge.test_provision`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `POST relays/{id}/preflight`                                     | Dry run of `provision / publish / replace / test-provision`: every guard a real start applies (the FIRST blocker is the code the start would throw), the selection the machine would make, plan-phase refusals that need no adapter, and delivery warnings (`render_disabled`, `members_dark`, ...). Writes nothing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `GET edges/{id}/verification-binding` + `POST edges/{id}/verify` | The L4 endpoint test. The GET returns `{endpoint, listenerKey, listenerRevision, configHash}` (plus whether the gate would pass once confirmed) exactly as the confirmation must echo it; the POST (origin-write scope) recomputes the binding from the live rows and refuses a mismatch (`edge.verification_stale`) rather than stamping a configuration the operator did not see. Records `edges.verification` (`method: test_link` from the isolated test link, `named_connection` for retesting a published address by its `<node>-relay-<key>` connection) and audits `edge.verified` (ids and the listener key only). L7 edges refuse: their authenticated proof is the verification.                                                                                                                                                                                                                                                                                                                                                                  |
| `GET attention`                                                  | Server-ranked list, one action per item: quarantine, needs operator, unsettled Host op, **members dark** (edge-required place with nothing to serve), failed or rolled-back rotation, lapsed front qualification, block suspected, unreachable edge, pool below desired, pool rebalance, account untested or unqualified, account with no daily limit, test key cleanup, direct Host reappeared, go-live pending, restore in progress, maintenance frozen; the operations-safety items (§ Operations safety: fleet brake and cap, stuck rotation, provider API failing, health stale, billable idle, delivery refusals, an app family switched off, a node ready to protect or waiting for approval); plus the three endpoint-verification cards: **needs_test** (critical: the origin is suspected and its automatic replacement has no tested spare), **retest_needed** (a confirmation went stale after a listener or address change) and **spare_untested** (an active unpublished L4 edge never confirmed), each with the one action `verify_endpoint`. |
| `GET relays/{id}/quarantine` + `POST .../quarantine/inspect`     | The resolver view: per listener the previous and the current binding as Host tuples; `inspect` (throttled) fills the live column from the backend and says which one it matches. `resolve-quarantine` records a `reason`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `GET relays/{id}/timeline`                                       | Merged audit rows of the origin, its listeners, its non-destroyed edges and its rotations, newest first, capped.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `GET providers/usage`                                            | Per account: live / max edges, allocations against the daily budget, published / standby / draining; per origin desired against published; totals including what auto-provision would add.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `GET relays/lookup?slug=`                                        | The full admin view of one origin by slug (the per-origin page is addressed by slug).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `POST relays/{id}/listeners/{key}/adopt-host`                    | The `operator` to `fcp` handoff: the named Host must exist, carry the listener's transport and dial a published edge of that listener (`edge.host_adopt_mismatch` otherwise). `hostMode: fcp` is refused until every listener Host is adopted (`edge.host_adopt_required`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `GET maintenance`, `POST maintenance/freeze`, `.../thaw`         | The maintenance switch (see below).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `GET delivery-bindings`, `POST delivery-bindings/{id}/release`   | The edge-required places, including ones whose origin was deleted with `keep-dark`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `GET config`                                                     | Also carries `bounds` and `defaults` per flat key, so the settings forms validate against the server's own limits.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `POST relays/{id}/rebalance`                                     | Coverage at the cap: unpublish ONE duplicate (a published edge that is not its listener's template edge, highest pool index first) back to standby, bump the epoch, refresh mirrors; upkeep then publishes the uncovered listener. Refuses `edge.no_duplicate`, and the usual rotation / quarantine guard. Audited `edge.relay.rebalanced`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `POST automation {on}`                                           | The one automation switch (settings scope): in ONE mutation sets `edge.enabled`, `edge.autoRotate`, `edge.probe.enabled` and `edge.autoProvisionToDesired` to `on`, and `edge.standbyPerListener = 1` when turning on (left as-is when off). Never `render.enabled` or `l7.autoSelect`; touches no origin row (an origin's own `autoRotate` keeps its meaning under the global gate: `cfg.enabled && cfg.autoRotate && relay.autoRotate`). Audited `edge.automation.set` (the boolean only).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `POST setup-runs/plan {backendServerId, nodeUuid}`               | The guided setup's read-only plan for one backend node (`listenerKeys?` as on create; throttled: it lists the node's transports and Hosts): frontable transports, direct Hosts tagged covered / uncovered, compatible accounts with reasons, the fleet-wide rendering consequence, disabled client families, and the `planHash` a run creation must echo. See § "Guided setup runs".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `POST setup-runs`, `GET setup-runs[/{id}]`                       | Create a run (`{backendServerId, nodeUuid, accountId, planHash, approvedHideUuids[], keepDirect?, listenerKeys?}`: `listenerKeys` is the operator's choice of 1 to 8 frontable transports when the node has more, covered by the plan hash; `edge.plan_stale`, `edge.account_incompatible`, `edge.too_many_inbounds`, `edge.setup_run_active`), list runs, poll one (stage, state, the interruption, per-listener verdicts, the `try_it` test links).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `POST setup-runs/{id}/{cancel\|retry\|continue}`                 | The three operator verbs on a run: cancel (before publish deletes the origin `restore-direct`; between publish and go-live, a run parked at `go_live` included, starts the restore workflow with purpose `cancel_setup`; a re-protect run instead drops only its own candidates, disposition `candidates`; after go-live refused), retry (re-enters the current stage under a new generation; `{tryAnotherAddress, edgeId?}` at `try_it` replaces only that line, `{acceptPartial}`, `{accountId}` answer the card's secondary buttons), continue (`{confirmations[]}` forwards each `try_it` tick to `POST edges/{id}/verify`; `{approvedHideUuids[]}` replaces the consent after `review_changed`; `{keepDirect}` finishes unbound).                                                                                                                                                                                                                                                                                                                       |
| `POST relays/{id}/require-edges`                                 | Starts a guided run for a deferred origin (it never binds by itself): the SAME activation policy. Every published L4 edge without a current confirmation comes back as `pending[]` (the node page renders the `try_it` card) instead of a binding; with nothing pending the run starts at the rehearsal and goes live through stage 8. Refuses `edge.not_deferred`, `edge.coverage_incomplete`, `edge.setup_run_active`, `edge.busy`, `edge.quarantined`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `POST relays/{id}/serve-direct`                                  | "Serve this node directly again": the restore workflow with purpose `release_requirement` (binding released before any direct Host is re-enabled; edges and listeners kept). Refuses `edge.quarantined`, `edge.setup_owned`, `edge.restore_in_progress` and `edge.not_edge_required`. See § "Operations safety".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `POST relays/{id}/reprotect`                                     | "Protect again" for a live, bound, enrolled node: a re-protect run (`kind: 'reprotect'`) that keeps the committed delivery until go-live and drops only its candidates on cancel. Refuses `edge.reprotect_not_bound`, `edge.reprotect_not_enrolled`, `edge.reprotect_mixed_accounts`, `edge.reprotect_no_room` and the usual run refusals. See § "Guided setup runs".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `POST edges/{id}/test-link`                                      | The isolated test link for an L4 candidate (throttled: fetches the test credential's body and the backend Hosts): the candidate connection only, plus the binding the confirmation must echo. See § "Publication".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `GET relays/inbound-candidates?backendServerId=&nodeUuid=`       | Discovery with the origin probe applied (throttled): the node's transports as listener candidates, `originTransport` filled where probed, `unsupported` with reasons. Registers nothing. See § "Listener catalogue".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

### Guided setup runs (Autopilot)

`convex/edgeSetupRuns.ts` (table `edgeSetupRuns`) + `convex/edgeSetupPlan.ts`. An operator
protects a backend node by answering two questions (which node, which account), confirming each
new L4 address once from a real client, and pressing Go live; FCP does everything else. ONE
authoritative stage machine, every stage idempotent and re-enterable:

| #   | Stage               | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Members download    |
| --- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| 1   | `prepare`           | registration admitted; account tested, enabled and offered by the plan; `relays.create` with every frontable listener (or the operator's `listenerKeys` choice when the node has more than 8), `deferBinding` + `setupOwned`, `autoRotate: true`, `desiredPublished = max(default, required)` (bound 8). An origin a previous run left owned is reused at its recorded `setupStage` only while its listeners still match what the new plan discovered (same keys, same canonical hash, no extra deployed listener); otherwise `edge.plan_changed` and the operator removes protection first. Switching the account (`retry {accountId}`) is allowed only before anything is published (`edge.account_switch_late`); candidates of the old account are cancelled, never re-labelled.         | raw origin body     |
| 2   | `credential`        | `relayQualification.ensure` for an L7 listener (`qualification`) or an EMPTY backend node (`rehearsal`); an empty Outline server is `use_manual_setup`; a placement problem is `choose_mode`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | unchanged           |
| 3   | `provision`         | per required listener without a live candidate: ONE mutation starts `provision` (`publishOnDone: false`, `requestedAccountId`, `allowUnqualified`) AND records `expect`; a live unpublished edge on the listener is reused. `edge.busy` / `edge.concurrency` wait and poll; `edge.maintenance` asks the operator                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | unchanged           |
| 4   | `verify`            | per standby: outside probes (`trigger: 'qualification'`) + the internal shape run, judged by `partialRungFor` (`partial` is the L4 ceiling); L7 runs the front proof. `unreachable` (or a timeout) asks the operator (`address_unreachable`: try another address, or accept partial)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | unchanged           |
| 4b  | `try_it`            | one isolated **test link** per L4 endpoint lacking a current confirmation (`edgeTestLinks.build`; a published address gets a named-connection retest instead); the card's ticks echo `{edgeId, endpoint, listenerRevision, configHash}` into `edgeVerification.confirm` (`edge.verification_stale` rebuilds the card). Skipped when every listener is L7                                                                                                                                                                                                                                                                                                                                                                                                                                    | unchanged           |
| 5   | `publish`           | per required listener: the node's approval is checked in the same mutation as the start (an enrolled node without one PARKS: `needs_you` `node_not_approved`, nothing published, docs/servers.md "A fronted node's activation"); then a `publish` rotation (`admission: 'setup.complete'`, so a freeze declared meanwhile does not strand admitted work) through the UNCHANGED gate; `pool_full_standby` = `coverage_incomplete`; quarantine = `quarantined`. `keepDirect` finishes `done_unbound` here (never for an enrolled fronted node)                                                                                                                                                                                                                                                | direct AND FCP Host |
| 6   | `hide_direct_hosts` | every L4 confirmation re-checked (stale = back to the card); `edgeHostHides.hide` with the EXACT approved uuids; an uncovered Host the consent did not name = `review_changed` (a new consent bumps `planRevision`); `hide_failed`; pending rows are polled                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | FCP Hosts only      |
| 7   | `rehearse`          | every client family's render rule on (`family_disabled`); `edgeRehearsal.run` (fresh cohort bodies through the real renderer, listing before and after; an enrolled node renders exactly its activation's candidates); expired proofs re-run and the rehearsal repeats (bounded); the version vector (with the activation candidate) + the FINAL Host observation are persisted                                                                                                                                                                                                                                                                                                                                                                                                             | unchanged           |
| 8   | `go_live`           | ONE mutation: no active rotation, no quarantine, origin enabled; the local vector equals the rehearsal's; the observation younger than 60 s; every L7 proof `expiresAt` ahead; every hide row settled and none outstanding; no FCP Host op claimed; every required listener's edge published (in the pool, on a listener whose FCP Host exists), L4 with a current confirmation; `render.enabled` turned on if off (`edge.render.enabled_by_setup`); an enrolled node's candidate promoted in the same mutation (a live node with no activation binds only when every edge fits its committed approval); then `claimDeliveryBinding` and `setupOwned` cleared. A failed check sends the run BACK (7, 6 or the card); a stale candidate blocks the activation and waits for a fresh approval | rendered body       |

Fencing: a rotation the run starts stores `setupRun: {runId, generation}`; `releaseOrigin`
(every terminal transition) schedules `edgeSetupRuns.onRotationTerminal` with THAT stored
generation, and the run acts only while it expects exactly that rotation under exactly that
generation. `retry` and `continue` bump the generation, so an older rotation's callback is a
no-op. The step action is fenced by `stepVersion` like the rotation machine; the reconcile cron
(`setupRunsPass`) re-kicks a run whose step never ran and re-fires a terminal hook that never
landed. `relays.setupOwned` is set at stage 1 and cleared ONLY by stage 8 (or removal): a
failed, cancelled or unbound run leaves the origin owned. Cancel before stage 5 deletes the origin
`restore-direct` (nothing was published; the delete cancels the live rotation, drains the
standbys for the reconcile destroy and removes the credential); at stages 5-7 the published edges
stay and `edgeRestore.start` runs with purpose `cancel_setup`; after go-live there is no cancel.
A **re-protect** run (`kind: 'reprotect'`, `POST relays/{id}/reprotect`, "Protect again" on the
node page) is its own kind for a LIVE node: an enrolled node whose members are already served
through this origin (refused otherwise: `edge.reprotect_not_bound` for an origin not bound yet,
`edge.reprotect_not_enrolled` for a node the role did not enroll; plus the usual
`edge.setup_run_active`, `edge.busy`, `edge.maintenance`, quarantine, restore and a disabled
origin). Its plan is read from the origin's own rows like `require-edges`: the listeners members
are served through (deployed, enabled, with a published template edge; none is
`edge.coverage_incomplete`) and the ONE account of their template edges (missing, disabled or
untested is `edge.account_incompatible`; an origin served through several accounts is
`edge.reprotect_mixed_accounts`). Each new address is published beside what members hold, so
the run first makes room: `desiredPublished` is widened to the published addresses plus one per
transport plus the slots reserved for uncovered listeners, at most `MAX_DESIRED_PUBLISHED`
(beyond it `edge.reprotect_no_room`); the size it found is kept in the plan snapshot
(`reprotect.desiredBefore`). It starts at stage 1 on the existing origin, owns it
(`setupOwned`) while it runs, and never reuses an edge at stage 3: every candidate is a fresh
address with a fresh test link, so a REALITY key change is proven through a new address, not a
named-connection retest of a committed one. Publication follows the node's admission rules
(docs/servers.md "A fronted node's activation"). Members keep the committed delivery until
go-live: the binding, the committed edges and the open gate are never touched before it. At
go-live the new addresses take the old ones' places: every other published edge on a run
transport whose new address is published drains (members move at their next refresh, as after
a Replace) and the pool size goes back to `desiredBefore`. The surviving edges are compacted first
(indexes 0..n-1), so no hole below the restored size admits a publication past it. While any
setup run is working on an origin, the operator's direct pool writes (publish or unpublish by
hand, an import that publishes, a rebalance) are refused with `edge.setup_owned`; an origin a
finished run left owned stays open to them (the `require-edges` recovery). Any ending other than `done` hands
the origin back (`onSetupRunEnded` clears `setupOwned` and gives the room back, so upkeep and
the detector protect the node again); `retry` of a failed one claims it again (and makes room
again) while the origin still binds the node and nothing else owns it. Its cancel
(`cancelReprotect`, one mutation, disposition `candidates`) drops only the run's own new
addresses: an unpublished one is cancelled for the reconcile destroy, a published one (a
candidate the gate keeps from members, or one a committed admission already published) drains
out of the pool unless it is its transport's last served address; never a delete, a restore or
a binding change. It is refused with `edge.busy` while a rotation runs on the origin (nothing
changes; cancel again in a moment).
An ENROLLED node (docs/servers.md "A fronted node's activation"): the run parks at publish
until the node is approved; the approval binds the run (`activationRunId`) and its activation
(`setupRunId`) for good and wakes the run through `wakeForApproval`, fenced by the generation the
approval read (a run past publish returns to the rehearsal); every terminal writer calls
`onSetupRunEnded` with the generation it ends, which blocks the bound activation (a cancel after
the approval parks the node for a fresh one). The provision rotation of a setup run may pick an
L7 account whatever `edge.l7.autoSelect` says: the operator chose it, and its front is proven
before anything publishes.
Vocabularies: `SETUP_RUN_STAGES` / `SETUP_RUN_STATES` / `SETUP_RUN_NEEDS` /
`SETUP_ACCOUNT_REASONS` in `src/shared/contracts/edgeCodes.ts`. Audit:
`edge.setup_run.{started,needs_operator,go_live,finished,cancelled}` and
`edge.render.enabled_by_setup` (slugs, run ids, stage / code words and counts only). The other
subsystems (hides, restore, test links, rehearsal, the credential) are reached only through a
seam the tests replace (`__setStageOpsForTests`).

### Admin section (Admin -> Edges)

Its own lazy chunk under `src/client/routes/admin/edges/`, reached from ONE sidebar leaf
(**Servers -> Edges**, lit on every `/admin/edges/*` path). Inside, a quiet in-page header row
`Nodes | Providers | Advanced` (`components/SectionNav.svelte`) sits at the top of every page.
The section has two faces:

**The simple screens** (`simple/`, plain words: origin -> protected node, edge -> address,
published / standby / draining -> in use / spare / retiring, rotate -> replace address,
qualified -> trusted, quarantine -> paused for safety; `PLAIN_WORDS` in
`src/client/lib/edgeCodes.ts`):

- **Nodes** (`/admin/edges`, `EdgesHome`): one status sentence with a dot ("All 6 nodes
  protected" / "1 node needs you" / "Setting up 1 node"), the **Needs you** rows from
  `attention` (the endpoint test opens the test card in place; go-live calls `require-edges`
  and renders the same card for whatever comes back pending), one row per protected node
  (name, country, one sentence, dot; a live run shows "Setting up, step N of 4" and opens its
  progress; a backend node's row opens its Servers node page), the primary **Protect a node**, and the automatic-protection switch (`POST
automation`; while it is off, a card with the cost and limitation sentences shows once a node is
  live, and the same offer sits on a run's Live card).
  `?protect=1` opens the protect sheet, `?run=<id>` a run's progress.
- **Protect a node** (`ProtectSheet` + `ProtectProgress`): three questions and then the
  progress. Which node (a backend's nodes; already protected ones greyed; the plan from `POST
setup-runs/plan` lists the transports in words, a closed "Not supported yet" disclosure and a
  formats note), which account (compatible accounts as radio cards, incompatible greyed with
  the reason; "Add account" renders `ProviderAccountStepper` in its `compact` mode), review
  (one sentence; the uncovered-hosts statement with the button "Protect and hide N unsupported
  hosts", consent = the exact uuids; the fleet-wide rendering sentence; the quiet alternative
  "Keep those members on the direct address" = `keepDirect`). Progress: four plain stages
  (Creating the address / Checking from outside / Checking it works / Going live, folded from
  the machine's ten by `plainStage`), elapsed, one live line, "You can close this. It keeps
  going.", polled every 3 s. An interruption is one card: the `SETUP_RUN_NEED_COPY` sentence
  and its one button (at most one secondary, `needButtons` in `simple/runWords.ts`); `try_it`
  renders the test card whose ticks echo `{edgeId, endpoint, listenerRevision, configHash}`;
  `review_changed` re-opens the review with the delta; `family_disabled` turns the family's
  render rule on through the config PATCH, then continues.
- **A node's edges** (`NodeEdgesPanel`, no tabs), part of the node's ONE page: a backend node's
  Servers node page embeds it (docs/servers.md "The page") and `/admin/edges/nodes/<slug>`
  redirects there (`nodeHomeOf`, keeping `?test=`); an origin that is not a backend node (manual,
  a whole Outline server) keeps it at that address. The status sentence, "Addresses in use" per
  transport (a reduced pool strip + one plain line per address; a retiring address says
  when it is deleted, from `drainUntil` and the 5-minute reconcile, and offers **Delete now**
  (`DELETE edges/{id}`: the drain ends early, audited `edge.delete` with `drainEndedEarly`;
  members who have not refreshed lose it) and **Keep as a spare** (the operator `reactivate`;
  never for a burned one), both only while no rotation, restore or pause holds the origin),
  the primary **Replace address** (`ReplaceDialog`, which states the drain: the origin's
  `drainMinutes`, or `edge.burnedDrainMinutes` for "Replace now, address is blocked" under
  More), the per-node
  "Replace addresses automatically" switch (origin `autoRotate`, captioned when the global
  switch is off), "Recent activity" (the timeline through `plainAuditActionLabel`), and More: add
  a spare address, **Protect again** (an enrolled node live behind edges: a re-protect run, see
  "Guided setup runs"; the primary action while the node waits to be protected again), Origin
  details, remove protection (`restore-direct`; the restore workflow's phase is shown while it
  runs). `?test=<edgeId>` opens the test card.
- **Providers** (`/admin/edges/providers`): cards (Connected / Problem / Not tested, "3 of 6
  addresses used" from `providers/usage`, and the trust line: "Trusted automatically, checked
  with a real session on <date>" / "Tried with a real session by you on <date>" / "Reached from
  outside. Not yet tried with a real session"); a card opens the account page, whose qualify
  dialog is the **Trust override**.
- **Advanced** (`/admin/edges/advanced`): a plain list of links to the technical pages.

**The technical pages**: **All origins** (`/admin/edges/advanced/origins`, the former
dashboard: fleet tiles, attention list, readiness whose steps link to where each is done
(`setupStepTarget`), origin table, probe chart; **New origin** opens `NewRelayDialog` for a
manual address or a whole Outline server), **Origin details** (`/admin/edges/relays/<slug>`:
overview, edges, listeners, rotations, probes; the quarantine resolver; an origin that is not a
backend node and has no edge yet shows the first-edge card: provision one, where a named, tested
account is allowed before it is trusted and the edge waits unpublished, or import a front), the
per-account page
(`/admin/edges/providers/<id>`), **Templates**, **Probes** (the old `/admin/telemetry/probes`
redirects) and **Settings** (Basics, Advanced sections, maintenance, delivery places). Codes
are never shown bare: `src/shared/contracts/edgeCodes.ts` holds the vocabularies and
`src/client/lib/edgeCodes.ts` the words. Section paths are spelled only in
`src/client/routes/admin/edges/lib/routes.ts`; API paths only in `src/client/lib/edgesApi.ts`.

A backend node is set up only with Autopilot (the protect sheet); the old step-by-step wizard
is gone. Its addresses redirect (`legacyEdgesRedirect`, pinned by a test):
`/admin/edges/setup?relay=<slug>` to that origin's details, `/admin/edges/setup` and
`/admin/edges/advanced/relays` to All origins. One provision dialog (`ProvisionDialog`) covers
both the ordinary provision (FCP picks a trusted account) and the bootstrap provision
(`test-provision`, chosen automatically when the operator names an account), and one import
dialog (`ImportFrontDialog`, with the inventory refresh) imports an existing front.

**One status source.** Every page reads an origin's status from the `attention` response:
`origins[]` (one row per origin, deleting ones included, in slug order: kind, dot, code, the
live setup run and its plain step, published / spare / offline counts, worst health, layers,
whether any item names it, and what members get) and `fleet` (the headline: what matters most,
its count, the total and the protected count). The per-origin Delivery card reads
`setup-status`'s `delivery` (relay scope only), the same judgement plus `degraded` from the
sample render. The judgement lives in `convex/lib/edges/originStatus.ts` (one pure function,
ranked by the server's own attention order); the CMS only words its codes and counts.

Member side: when the key sits behind edges the report dialog also asks which connection the
member was using (optional; the labels the pass shows), and an edge-required single-key
(Outline) subscription is shown as the dynamic access key.

### Host ownership (`hostMode: fcp`)

`convex/hostOps.ts`. Each listener's Host is a persisted state machine
(`relayListeners.host`): `absent → creating → present`, `present → deleting → absent`, with
`unresolved` and `ambiguous` in between. The **intended tuple** (remark, address, port, SNI,
Host header, transport uuid) is persisted BEFORE any backend call; after an uncertain outcome
discovery matches a Host on remark AND transport AND address:port, never remark alone. One match
settles a create; several park the listener as `ambiguous` (needs an operator); an empty
listing right after a timeout is never a licence to create again: the op stays `unresolved`
until a settle floor and two quiet looks passed. A delete is confirmed ONLY by a read-back in
which the uuid is gone. An expired, unsettled op blocks further Host writes for that listener.
A Host the ledger calls `present` is **re-observed against the live listing before it is
accepted**: the uuid listed means present; gone but exactly one Host on the listener's remark
and transport takes its place; several park it `ambiguous`; none makes it `absent` (audited
`relay.host.lost`) and a create runs. `present` is never answered from the database alone, so
a rotation cannot confirm an empty Host plan.
Hosts FCP created are `fcp`-owned and deleted (confirmed) when the listener retires or the
origin is deleted; a Host the operator created and FCP took over is `adopted` and only ever
released. Legacy Hosts adopted from a manual deployment (`legacyHosts`) keep matching the
renderer and are never deleted.

### Direct-Host hides and the restore workflow

Two rules the read-back and the restore apply since the review of PR A2: a uuid found disabled
at a DIFFERENT tuple than the one observed before the write (an administrator repointed or
rebound it meanwhile) is never confirmed (`tupleDrifted`, counted as failed so the run raises
`hide_failed`), and a restore re-enables every Host that is still disabled whatever its tuple
says now (the bit is the one FCP wrote); only a Host an administrator re-enabled is released
without a write. `relays.restore` is a real lock: rotation starts (`edge.restore_in_progress`
in the start blockers), origin updates, adoption, unpublish (even forced), listener writes and
pool writes all refuse while it is set. A completed guided setup stamps its consented dark
cohorts on the origin (`relays.darkCohortKeys`) so the raw-body checks of a later restore skip
them, and a run's `continue {approvedHideUuids}` REPLACES the consent exactly (withdrawing a
Host the ledger already disabled is refused: `edge.consent_withdrawn_hidden`, Remove
protection is the path that re-enables it).

A node that serves members today has backend Hosts pointing at its own address (**direct
Hosts**: enabled, on one of the node's transports, dialling `originAddress`, not an FCP origin
remark, not an adopted legacy Host; `convex/lib/edges/directHosts.ts`). A guided setup hides
them once its edges serve, so that from then on members depend on the edge; a Host is
`covered` when a frontable listener serves its transport and `uncovered` otherwise (the operator
approves hiding an uncovered one by uuid, or its members stay on the direct address).

**The hide ledger** (`edgeHostHides`, `convex/edgeHostHides.ts`) records every write BEFORE it
is made: `intended` (the observed tuple, an `opId`, a 60 s lease) → `setHostDisabled(uuid,
true)` (Remnawave `PATCH /api/hosts {uuid, isDisabled}`, nothing else travels) → `written` →
read-back `isDisabled === true` → `confirmed`. A row that holds an `opId` is **possibly
written** and is settled only by observation: disabled → `confirmed`; gone → `released`; still
enabled → `unresolved`, and only after the settle floor (2 min) AND two quiet looks since the
lease expired is it settled: released inside a restore workflow (nothing was written, nothing
is reversed), retried by the reconcile pass otherwise (six attempts, then `failed` in
`status`, which a setup run surfaces as `hide_failed`). A lease expiry alone never releases or
reverses anything; a disable that lands late is caught by the next look, never undone blindly.
No opposing write is issued while any row of the origin is unsettled. `internal.edgeHostHides`:
`hide {relayId, runId?, approvedUuids, nodeInboundUuids?}` (covered + approved; the rest come
back as `reviewChanged`), `status`, `settle` (reconcile-driven), `observe` (a hashed listing of
the node's direct + FCP Hosts with their disabled bit, for the rehearsal's observation
boundary). Audited `edge.host.hidden` (counts + remarks, never an address).

**Reconcile check for bound guided origins** (`hostOps.reconcileHosts` → `reobserveDirect`):
delivery is fail-closed, so a direct Host re-enabled or added behind FCP's back makes every
render `leak_detected` (503) rather than leak the origin. The pass re-observes the direct Hosts
of every bound origin with hide rows: a covered or previously approved one is **re-hidden**
(audited `edge.host.hidden` with `rehidden`); any other raises attention
`direct_host_reappeared` (critical, `relays.directHostAlert`, cleared when the next pass sees
none). Both are suppressed while a restore workflow runs.

**The restore workflow** (`relays.restore {purpose, phase, ...}`, `convex/edgeRestore.ts`;
one phase per `edge-reconcile` tick, `edgeRestore.step`) is the only way a guided origin stops
depending on its edges, with an explicit purpose: `cancel_setup` (a run cancelled after
publication), `release_requirement` (edge-required delivery switched off, everything kept:
"Serve this node directly again", `POST relays/{id}/serve-direct`) or
`delete_relay` (a `restore-direct` deletion). Phases: (1) `freeze`: no new disable writes; waits
for a running rotation; (2) `settle`: every outstanding hide row confirmed or released by
observation; (3) `verify_fcp_raw` (bound origins only): the RAW backend body of each non-dark
cohort (one representative key per placement pinned to the node, `convex/lib/edges/cohorts.ts`:
the first key of each distinct placement over `subscriptions.by_backend_server_pinned`, a page
of placements per query, driven from the action) carries an FCP entry and no
origin entry, fetched through the same path the sub route uses; (4) `release_binding`: the
delivery binding is released WHILE the origin stays enabled and its edges published, so members
keep the protected entry in raw delivery. **A direct Host is never re-enabled while the origin
is bound**: the renderer would answer `leak_detected` for every member, an outage FCP would
have caused itself (pinned by a test that asserts the ordering inside the backend write);
(5) `restore`: each `confirmed` row is re-observed; still disabled at the observed tuple →
re-enabled through a `restore` row, read-back confirmed; changed or removed by an administrator
→ released untouched (audited `edge.host.restored`); (6) `verify_direct`: the raw bodies carry
the origin entry again; (7) finish by purpose: `cancel_setup` retains the origin (`setupOwned` +
`bindingDeferred`, edges published, attention `go_live_pending`); `release_requirement` retains
everything and sets `bindingDeferred` so `require-edges` can re-apply the activation policy;
`delete_relay` runs the deletion body only now (drain, destroy, remove). An origin with a restore
in progress refuses a second workflow, a new hide and every pool / listener write
(`edge.restore_in_progress`); attention lists it as `restore_in_progress` (info) with its phase
and last error. Audited `edge.relay.restore_started` / `edge.relay.restore_finished`.

`relays.requestDelete` is re-sequenced accordingly: a `restore-direct` delete of an origin that
hid direct Hosts (or that a setup run bound) enters the workflow with purpose `delete_relay`
(response `restore: true`) instead of tearing down at once; `keep-dark` keeps the binding,
never restores a hidden Host and tears down at once, as before; an origin that never hid a Host
and was not bound by a setup run is unchanged.

### The rotation machine

`convex/edgeRotations.ts`. Phases:

```
select → provisioning → verifying → publishing → host_flipping → confirming → finalizing → done
                                                        ↘ rolling_back → rolled_back | quarantined
(failed / cancelled from the early phases)
```

**The recovery contract.** A rotation survives a crash, a lost answer or a killed action at
any point, and never writes twice what it cannot prove:

- **Fencing.** Every DB change is a mutation guarded by the run's `stepVersion`. The `step`
  action does one bounded unit of work and never schedules itself: the recording mutation
  schedules the next step and stamps `nextStepAt`, the action stamps `stepStartedAt`. A step
  scheduled more than 30 s ago that never started, or started more than 10 minutes ago with no
  outcome, is stale: each `edge-reconcile` pass re-kicks it (`rekick` bumps `stepVersion`, so a
  zombie actor's writes are ignored, and schedules a fresh step).
- **Wall clock and errors.** A run past `EDGE_PLUMBING.maxRotationMs` (2 hours), or after 30
  unexpected throws, ends by phase: `select`, `provisioning`, `verifying` fail with nothing to
  undo; `publishing`, `host_flipping` fail into `rolling_back`; `confirming`, `finalizing` and
  a `rolling_back` that cannot converge quarantine. `rolling_back` itself is exempt from the
  wall clock. An unexpected throw is counted and retried after a poll interval (20 s).
- **Cancel.** In `select`, `provisioning` or `verifying` a run is cancelled; in `publishing` or
  `host_flipping` it rolls back; from `confirming` on it is `edge.too_late`; a request during
  `rolling_back` is recorded and never aborts the rollback.
- **Provider steps.** Each create or delete holds an operation claim (60 s lease). A live claim
  answers `edge.op_busy`; an expired claim on a provision or destroy step is never re-run: the
  step goes `unresolved` and to **discovery**, which answers one of four outcomes. `found`: the
  step is done. `confirmed_absent` (two or more quiet looks plus the adapter's settle time):
  the step runs again, at most 3 attempts, then the edge needs an operator and the run fails
  `step_retries_exhausted`. `ambiguous`: the edge needs an operator, the run fails
  `ambiguous_resource`. `unresolved`: keep looking for 30 minutes after the step started, then
  `discovery_timeout`. A provision has its own 20-minute cap (`provision_timeout`). Shared
  external locks use the same lease and are held on a thrown or partial write until discovery
  answers.
- **Hosts.** The Host plan is captured **per listener** from the live listing; when FCP owns the
  Hosts and none exists for the listener yet, the flip CREATES it through the Host state
  machine. The forward write is claimed before it is sent (`forwardWriteAttempted`), so a write
  whose answer was lost is re-observed, never assumed absent. Six failed writes roll back
  (`panel_unreachable`); a planned Host that vanished or was rebound is `hosts_changed` and
  rolls back; an unconverged confirm writes again.
- **Rollback.** The DB half (`applyRollbackBinding`) is idempotent: the new edge back to an
  unpublished standby, the previous edge republished at its pool index, the epoch bumped,
  template edges and mirrors refreshed. The Host half writes back the previous tuple, judged by
  the same diff. With no forward write ever claimed the run is `rolled_back` at once. Six
  failed rollback writes, a vanished or rebound Host, or a backend unreachable past the cap
  **quarantine** the origin.
- **Quarantine** records the rotation, the new edge and `relays.quarantine`, audits
  `edge.quarantined`, refuses every start (`edge.quarantined`) and makes the reconcile leave the
  origin alone (no describe, drop, destroy, requalify or upkeep); attention raises `quarantine`
  (critical) and `billable_idle` lists its edges. Only the operator ends it
  (`resolveQuarantine {keep: current | previous, reason}`, after the inspect view).
- **After a terminal phase.** Every terminal transition releases the origin (`activeRotationId`
  cleared) and calls the setup run's terminal hook with the generation it stored. A failed run
  marks its new edge `failed`; outside a running rotation the reconcile settles unresolved steps
  by discovery and turns failed or cancelled edges into destroy runs (at most 48 attempts, then
  `needs_operator`). Attention `rotation_stuck` (critical) fires after an hour, before the wall
  clock ends the run. A maintenance freeze blocks starts only; steps, re-kicks, rollbacks and
  cancels keep running.

### Reconcile cron (`edge-reconcile`, 5 min)

Re-kicks stale rotations (and stale guided setup runs, re-firing a terminal hook that never
landed); runs the L7 auto-trust sweep; clears a system `partial` rung whose binding no longer
matches the live rows (`edgeVerification.reconcilePartialRungs`: a re-addressed edge or a
changed listener no probe has settled on since); settles edges with unknown outcomes by
discovery; refreshes provider health; renews L7 proofs; re-observes unresolved Host operations
and deletes the FCP-owned Hosts of retired listeners and deleting origins (read-back confirmed);
settles the direct-Host hide ledger and re-observes the direct Hosts of bound guided origins;
drives one phase of each restore workflow; removes expired or released temporary test keys
(`edgeTestCredentials.sweep`, bounded retries, then attention `test_key_cleanup`); turns
drained / failed /
cancelled edges into destroy runs; pool upkeep while `edge.enabled` is on and the maintenance
switch is off (a `setupOwned` origin and an origin in a restore workflow are skipped): first `ensureCapacity` (raise / expand
`desiredPublished` for the deployed listeners), then **listener-aware** upkeep, one listener per
tick: every deployed, enabled listener without a template edge gets its OWN standby published
(`publishStandby` candidates filtered by `edge.listenerId`; a standby of A never counts for B)
or a provision FOR THAT LISTENER (`listenerId` in the start), then the origin-wide fill to
`desiredPublished` once every listener is covered, then spares: the origin-wide
`standbyPerRelay` reserve plus `standbyPerListener` verified standbys per coverage listener
(each the origin's own value, else the fleet's: § Configuration; the automation switch sets
`edge.standbyPerListener` to 1). Finishes origin deletes. At most one automatic start per pass
(`EDGE_PLUMBING.maxReconcileStartsPerTick`; `edge.enabled` is the switch).

**Retention** (separate daily crons, `convex/retention.ts`): `retention-edges` prunes
`destroyed` edges after 30 days, `retention-edge-rotations` terminal rotations after 90, and the
workflow sweeps (`retention-panel-ops`, `-sni-rollouts`, `-edge-setup-runs`,
`-activation-runs`, `-edge-host-hides`, `-port-changes`) terminal rows past 90 days each
(`*_RETENTION_DAYS`, `docs/convex-self-hosting.md`). They never delete a row something still
reads: an op a claim, rollout, port change or rename names; a binding's newest rollout; a node's
newest setup run and one an open activation points at; a node's current activation run, the
committed run of its current approval, and an uncommitted run while any of its candidates (an
edge not destroyed, a Host still on the backend) remains, since it isolates them only while it
exists; the newest hide row of each Host of a live origin, and every row while its restore runs;
a port change whose op is open. Node renames and their aliases are kept (a former name stays
reserved), mirror upload records are deleted when they settle, and the vantage tables keep
their own window.

### Operations safety

What keeps the automatic machinery safe to leave running: the operator hears about problems, a
mass block cannot rotate the whole fleet, provider failures and dark members are visible, and no
read grows with the member count.

**Fleet brake and the fleet's daily cap** (`convex/lib/edges/fleet.ts`). The detector evaluates
every origin first and judges the pass as a whole before any rotation starts. When more than
`edge.detect.fleetBreakerPct` percent (default 30, 100 = never) of the evaluated origins are
suspected, and at least three of them, the brake engages (`appState` `edge:fleetBrake`, audited
`edge.fleet_brake` on each transition): no detector rotation starts anywhere (`fleet_brake`
veto, `edge.fleet_brake` refusal read inside the start mutation), and attention `fleet_brake`
(critical) says so. It releases on the first pass back under the threshold. Detector rotations
across the whole fleet are also capped per UTC day (`edge.detect.fleetRotationsPerDay`, default
12, 0 = none; `edge:fleetRotations`, counted in the mutation that starts one; refusal
`edge.fleet_daily_cap`, attention `fleet_rotation_cap`). Manual rotations are never held.
`edge.detect.allowProbeOnlyAutoRotate` now defaults to **false**: probe evidence alone weighs
in the score but neither suspects nor rotates without member reports, until an operator opts in.

**Provider failures.** Every account-scoped provider call (`edgeProviderOps`: steps, polls,
discovery, describe, inspect, destroy, inventory) counts toward the account's API health
(`edgeProviderAccounts.apiFailures`, `apiFailingSince`, `lastApiError`): a timeout, a network
error, a 5xx, a refused credential (401 / 403), throttling (429) or an answer the adapter cannot
read adds one; a 404 or a 409 the caller handles does not; the first success resets the run.
Three in a row raise attention `account_api_failing` (critical). A live managed edge whose
health was not refreshed for an hour (or 30 polls) shows as `health_stale` on its account. A
`dailyAllocationBudget` of 0 (no daily limit) is refused outside a development deployment
(`ENVIRONMENT=development`); existing rows keep their value until the next edit and show as
`account_budget_unlimited`.
`billable_idle` lists edges that cost money while serving nobody: a quarantined origin's managed
edges, or an edge parked at `needs_operator` whose resources are still present.

**Dark members.** Every refusal the subscription route answers under edge-required delivery
(the 503 with `x-fcp-delivery: <reason>`) is counted per reason in a sharded `appState` counter
(`edge:refusals:<0..7>`, ten-minute buckets, `convex/deliveryRefusals.ts`): codes and counts
only. Attention `delivery_refusals` sums the last hour (`facts.byReason`), critical from 25. A
client family whose render rule is off now answers `family_disabled` (no longer
`render_disabled`), and attention `family_rule_disabled` lists the families while any node is
edge-required. A `rotation_stuck` item (critical) appears for a rotation running over an hour.

**Serve this node directly again** (`POST relays/{id}/serve-direct`, `edgeRestore.serveDirect`):
the restore workflow with purpose `release_requirement`, offered on the origin's Delivery card.
Refused while a quarantine is open (resolve it first), while a guided setup owns the origin
(cancel the run instead) and for a node whose members already get its direct address
(`edge.not_edge_required`). The workflow releases the binding BEFORE any direct Host is
re-enabled; edges and listeners stay, and the node can be protected again later.

**Enrolled nodes that wait on the operator.** FCP never starts a protect run or approves on its
own; it asks. `node_ready_to_protect`: a fronted node at `machine_ready` with no open protect
run (action `protect_node`, the protect sheet with the node preselected).
`node_awaiting_approval`: a node tested and not approved yet, parked after a block, or a protect
run parked at `node_not_approved` (action `open_node`, its Servers page).
`node_mode_disabled`: a live node whose connection mode is turned off, so no member is given it
(action `open_modes`, Admin, Connection modes). The protect review says so first (the plan's
`modesOff`), and so does the node's Servers page (`modeEnabled` on the intent view).

**Approval shape in automatic work.** A replace, or a provision that publishes when done,
outside a guided setup run, picks only a spare or an account whose shape (listener, account,
template) fits the enrolled node's approval; nothing fitting fails the selection with
`outside_approved_shape`, and an automatic start (detector, reconcile) is refused with
`edge.outside_approved_shape` instead of failing every tick. Where the run publishes, the
approval is checked again: out of shape, the paid-for edge stays a standby and a replace leaves
its target served (the finalize drains a target only after a real swap); as a candidate of the
node's running activation it is recorded as one, except for a replace, whose replacement must be
servable at once. Pool upkeep's direct standby publish applies the same approval.

**A burned last name.** When a burn takes a listener's last active name, its FCP-owned Host would
keep handing out the burned one. `hostOps.resyncSni` withdraws it instead: the Host is deleted
through the Host state machine (read-back confirmed, the condition judged again inside the
claim), and the reconcile pass does the same for a Host left on a burned name. Only a Host that
carries one of the listener's own names follows them: an L7 Host carries its edge's hostname and
is never rewritten or withdrawn here. The listener serves nobody until it has a name again; its next
rotation creates the Host afresh. An adopted Host (the operator's) is never deleted.

**A placeholder body is never cached.** A body the node pinner understands that names no node
(the backend's answer for a key whose node serves nothing yet) carries a cache token without a
node, so a node going live could not re-key it; the route answers it `private, no-store` and
never caches it. Unknown body shapes keep caching as before.

**Read limits.** No transaction reads an origin's keys or a whole report window: the cohort walk
(`lib/edges/cohorts.ts`) reads the first key of each DISTINCT placement over the
`subscriptions` indexes that end in `backendPlacement`, one page of placements per query, driven
from the action that needs it (`edgeCohorts.walk*`: the restore workflow, the rehearsal, the
setup plan), and refuses (`edge.cohorts_unbounded`) rather than judge a partial membership; the
detector's report window and the test-key sweep page through their indexes
from the action (one `paginate` per query, as Convex requires).

### Operator alerts

Opt-in (`alerts.*` in `appSettings`, Admin -> Settings -> Operator alerts; `GET /api/v1/admin/alerts`
with the settings read scope, `PATCH` sealed with the write scope, `POST /api/v1/admin/alerts/test`
sends one test). Every five minutes the `alerts-dispatch` cron reads the attention list and
posts the NEW alert-worthy items once, in one notification, to the webhook as ntfy-compatible
JSON:

```json
{
  "topic": "<if set>",
  "title": "Edges: 2 new alerts",
  "message": "quarantine (flip_unconfirmed): 1\nnode_ready_to_protect: 1\n\nOpen Admin, Edges for the details.",
  "priority": 5,
  "tags": ["rotating_light"]
}
```

Alert-worthy: every critical item (quarantine, fleet brake, a provider whose API keeps failing,
a stuck rotation, dark members, a reappeared direct Host, a blocked node with no tested spare, an
ambiguous Host) plus `node_ready_to_protect` and `node_awaiting_approval`. An item is sent once
while it stays on the list at any severity (`appState` `alerts:state` holds the sent ids); one
that clears and comes back alerts again; a failed post records a short code (`network`, `timeout`, the status)
and is retried next tick. **Alerts carry kinds, short codes and counts only**: never a member,
a token, an address, a node or origin name, a provider or a region. The webhook URL must be
https and pass the infra SSRF check (`ALLOW_INTERNAL_BACKENDS=true` admits http in
development); redirects are not followed. The topic and the access token (sent as `Bearer`) are
write-only: the admin view shows whether each is set and the webhook's origin, nothing more.

To poll instead (or as well), read `GET /api/v1/admin/edges/attention` with a read-only API
token (`admin:servers:read`); every item carries `kind`, `severity`, `code` and `action`.

## Server-name families (REALITY)

A REALITY transport accepts an **exact allowlist** of server names (no wildcards) and forwards
every other handshake, and every handshake that fails authentication, to **one target**. So
"any hostname" is not a setting: it is a long, managed list. And a name is only safe to hand out
if the transport's target **genuinely serves it** (TLS 1.3, a certificate valid for that name):
otherwise an active probe presenting the name sees a mismatch and the node stands out. A
**family** is therefore a target plus the names it serves, each checked against that target
before it may be used. More targets means more families, and more transports on other ports (an L4
edge maps its own port to the transport's).

Ships dormant: `edge.sni.enabled` is off. Off, nothing is qualified and no family can be bound.

| Table                   | Holds                                                                                                                                                                                                                                                                                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sniFamilies`           | `slug`, `label`, `target {kind: static, address, port}`, `enabled`, `requireH2`. The **target is immutable**: every name was checked against it, and an allowlist is only safe for the target it was built for. A different target is a new family. `sni-router` (a target on the node that follows the presented name) is a reserved kind. |
| `sniNames`              | `name` (fleet-unique: one family per name), `seq` (monotonic per family, never reused: the order names are taken in), `status`, `qualification`.                                                                                                                                                                                            |
| `sniInboundBindings`    | One family bound to one backend transport: the single authoritative allowlist for it, with its `generation`.                                                                                                                                                                                                                                |
| `sniInboundNameHistory` | Every name a transport has **ever** listed, keyed by transport and name, independent of any binding (it survives unbind and rebind and is never reset). Binding records everything the transport lists at that moment as seen.                                                                                                              |

**Name states.** `active` (usable once it qualifies), `suspended` (it stopped qualifying; it
comes back by itself when it qualifies again), `retired` (an operator took it out), `burned`
(known blocked: never offered again, by any family; an import answers `burned` for it).

**Qualification** (`convex/sniQualifyOps.ts`, cron `sni-qualify` every 5 min, or
`POST sni/qualify`): one TLS handshake per name **against the family's target, never against a
node**, presenting that name. It qualifies on TLS 1.3 with a chain valid for the name; ALPN is
recorded and HTTP/2 required only when the family asks. That is exactly what an unauthenticated
prober presenting the name to a node would be shown, since REALITY forwards it to the target.
The target is operator-supplied, so the dial is guarded like the internal probe: a hostname is
resolved, **every** answer must be public, and the connection goes to a verified literal. At
most two handshakes a second, oldest-checked first, `qualifyPerTick` per run, again after
`requalifyHours`; `suspendAfterFails` consecutive failures suspend a name. Failures are code
words (`q_cert`, `q_tls12`, `q_no_h2`, `q_timeout`, `q_resolve`, `q_private_target`,
`q_unreachable`), never a handshake error string.

**Binding** (`POST sni/families/{slug}/bind {backendSlug, transportTag}`) is refused unless the
transport is REALITY, is on the backend as Servers last read it, has no family yet, and its target
**is** the family's target (`edge.sni.target_mismatch`). From then on the transport's names and
target are no longer edited by hand (`servers.inbound_sni_managed`): they have one author.
Unbinding keeps the names on the backend and on the origins, and keeps the history.

**What goes onto a transport** (`planAllowlist`, `convex/lib/edges/sni/family.ts`). The backend
allowlist is one list with one cap (512; production Xray takes 1024, measured) and three kinds
of tenant: the family's names; names that are not the family's but that an origin still hands
out; and names that were retired but are still inside their drain. The cap is over **all** of
them. The family's share is what is left after the other two and a **headroom of 64** kept free
for the next drain, because retiring one name and adding its replacement needs both on the backend
at once. The family fills its share in `seq` order, so every node on the transport sees the same
choice.

### Rollout and acceptance

A family's names reach members in two separate steps, because they answer two separate
questions.

**1. The backend holds the names** (`POST sni/bindings/{id}/rollout`; `.../plan` shows it first).
The allowlist is planned, previewed against the live backend and written through the server
operations ledger ([servers.md](servers.md) § Editing a config profile), which is the only path
that may edit a managed transport. When the read-back shows the predicted token the rollout is
`panel_confirmed`. **Members are handed nothing by this step.** Rolling out again with nothing
new writes nothing.

**2. Each node accepts them.** A backend read-back says nothing about a node. Measured against a
real node: with the node held off the backend, the backend lists the new name, a plain TLS
handshake with it **completes** (REALITY forwards it to the target), and **no member can connect
with it**. So a TLS probe is never acceptance. Acceptance is a **receipt**:

- `POST sni/rollouts/{id}/test-link {edgeId, sni?}` builds the existing isolated test link
  through one of that node's edges, presenting **one name of the rollout** (a test-only override;
  the name reaches no subscription through it). The edge must already hold a current endpoint
  confirmation, so a failure is unambiguous: it is the name, not the path.
- The operator connects with it and calls `POST sni/receipts/{id}/confirm`. Everything the
  receipt is bound to is derived again from the live rows: the rollout is still the binding's
  latest generation, the profile still has the token that generation wrote, the edge's endpoint
  confirmation is current and unchanged, and the link has not lapsed (one hour). Any difference
  voids it.
- Then the name is handed to **that node's members, and only that node's**: nodes sharing a
  profile progress independently.

**One proof, how much it covers.** A receipt always proves its own name on that node. If the
name is a **witness**, an added name this transport has **never listed before** (per
`sniInboundNameHistory`), a node that authenticates it must be running the generation that
introduced it, so the one receipt activates **every** name of the generation there. A name that
was listed at some point (removed and added again, or present before FCP managed the transport)
is never a witness: a node stuck on an older config could accept it too, so it proves only
itself. Only names that still qualify are activated, whatever was proven.

Activation appends to the listener's names in the rollout's order, moves `namesRevision` and
the publication epoch, and leaves `revision` alone: acceptance was **proven**, so the endpoint
confirmation still describes the path. That is the only way a name is added without a retest.
A listener still on the legacy selection is switched to the growth-stable `hrw1` selection by
its first confirmed receipt; that switch is recorded like an operator's
(`relay.listener.sni_pick`) and bumps the epoch on its own, even when the receipt activated
nothing new, because every member's name changes with it.

A rollout follows its ledger op from **whichever** look settles it (the run's own, the
`backend-reconcile` cron's, an operator's "look again"), so a backend read that fails right after
the write leaves the rollout `writing` only until the next successful look, never for good.

**Removal is the reverse.** A name leaves the origins first, with its drain. The plan **retains**
on the backend every name an origin still hands out or that is still draining, whoever it belongs to
and whatever its family says, and a later rollout drops it once nothing holds it. A burn is
immediate on the origins and restarts nothing.

### When a name leaves

A family name that is **burned**, **retired**, or that **stops qualifying** (suspended) leaves
the origins by itself, with the normal drain (`retireFamilyNames`). Two rules:

- a name that merely stopped qualifying, or that an operator retired, never takes an origin's
  **last** active name with it: an origin with one doubtful name still serves its members, an origin
  with none serves nobody. A **burn** may: a name known blocked is worse than no name;
- an origin that is rotating, restoring, quarantined or being changed by Servers is skipped and
  counted in the result, never forced.

The backend keeps the name until nothing hands it out and its drain is over (§ Rollout and
acceptance), so members who have not refreshed are not cut off.

**The one name of a Host.** A backend Host carries one server name. It is what a member gets who
copies a raw config from the backend (no per-member selection happens there), what the shape
probes present, and what an endpoint shows as its name. `hostSniOf` chooses it: the first active
name, in stored order, that is **not known blocked in any curated country**, else the first
active one. When that name leaves, `hostOps.resyncSni` writes the listener's next choice onto
the Host (address and port unchanged), for an FCP-owned Host that is settled; a Host the
machine is working on, an operator-owned Host and a rotating origin are left alone (a rotation
writes the new tuple by itself).

### Names for the member's country

A name that works almost everywhere can be blocked in one place: a large site that is itself
censored there. So in the **curated countries** (every country on the censored-country list,
§ Configuration, "The censored-country list") "usable" is judged per country.

**Judging.** `POST sni/families/{slug}/names/country {snis, country, state}` records an
operator's judgement (`proven`, `blocked`, or `unknown` to clear it) in `sniNameCountry`, for a
curated country only. The marks are **copied onto every origin listener entry** for that name
(`blockedIn`, `provenIn`), so a render needs no extra reads, and those origins' renders move on
at once. It is a names change, not a material one: no retest. Audit rows carry the country, the
state and a count, never a hostname.

**Selecting** (`countryTier`, `convex/lib/edges/assignment.ts`; only for a listener on `hrw1`):

| The member is             | They are offered                                                                                                                                                              |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| in a curated country      | **Never** a name blocked there. Names proven there first; names nobody has judged there fill the remaining slots. With three or more proven names they hold only proven ones. |
| anywhere else, or unknown | The **universal pool**: names not blocked in **any** curated country.                                                                                                         |
| reading an S3 mirror      | The same universal pool (a mirror has no request to infer anything from, and exists for exactly the people who are blocked), unless they said where they are.                 |

Each tier keeps the rendezvous order, so the stability properties hold inside it. If every name
of an edge is excluded for a member's country, that edge is not assignable **for them** and the
walk moves to the next edge; with none left the existing edge-required behaviour applies.

**Where the member is.** Their own answer first (`subscriptions.sniRegion`, set on the account
page: "Where are you connecting from?", Automatic by default), else the country the CDN reports
for the request (`resolveCountry`: only when the deployment is fronted by it, otherwise it is a
header a client could forge and it is ignored). Either counts only when it is a curated country.

**What is stored.** Only the member's own answer. An inferred country is used for that one
response and kept nowhere: such a body is neither read from nor written to the content cache, is
served `private, no-store`, and a cached body is never handed to a request that infers a curated
country (`convex/lib/edges/sni/country.ts`). A body for the member's own answer caches under that
answer. When no listener has any judged name, caching is exactly as before.

Routes, under `/api/v1/admin/edges/sni/`: `GET|PATCH config` (settings scope),
`GET|POST families`, `GET|PATCH|DELETE families/{slug}`, `POST families/{slug}/names` (a pasted
list, up to 1000 lines, answered with a verdict per line: `added`, `duplicate`, `invalid`,
`in_other_family`, `burned`), `POST families/{slug}/names/{retire|reactivate|burn|recheck}`,
`POST families/{slug}/names/country`,
`POST families/{slug}/bind`, `DELETE bindings/{id}`, `POST qualify`,
`POST bindings/{id}/plan`, `POST bindings/{id}/rollout`, `GET rollouts/{id}`,
`POST rollouts/{id}/test-link`, `POST receipts/{id}/confirm`,
`POST families/{slug}/vantage` and `POST families/{slug}/vantage/apply` (§ Checks from inside a
country). Audit rows (`edge.sni.*`) carry slugs and **counts only, never a hostname**.

### What members' reports say about a name

An outside check cannot tell whether a name is blocked inside a country (FCP is not inside
it), and the operator's judgement needs something to go on. Member reports give a coarse one.

When a report counts for the detector (deduplicated, weight 1), names the edge it is about,
and that edge's listener ranks names per member (`hrw1`), `sniReports.attributeReport`
recomputes the names that member holds on that edge, from the snapshot's edges only, exactly
as the account page rebuilds its labels, and adds `1/K` to each in `sniReportCounts`
(name, country, day, weight: see docs/privacy.md). The country is the member's saved region,
else the one they shared with the report, when curated; else `ZZ`.

`suspectNames` (pure, `convex/lib/edges/sni/health.ts`) then marks a name as a **suspect** in
a curated country when, over `edge.sni.reportWindowDays` (default 14), it gathered at least 3
there **and** at least twice what the family's other reported names average there. Everything
gathering reports alike points at the address or the node, which is the block detector's
business, not the name's. `ZZ` never makes a suspect.

A suspect is a line under the name on the family page and a place in its "Problems" filter,
until the operator records it as blocked there. It never retires a name, never proves one
works, and never changes what anyone is given. Cron `sni-report-sweep` deletes counts older
than the window.

Reports also feed the checks from inside a country (next section): a name reported there at
least as much as the suspect floor (3) is checked from there before other names, and a suspect
is the corroboration a single failing check needs.

### Checks from inside a country (vantage evidence)

Ships dormant: `edge.sni.vantage.enabled` is off and no country is opted in. Off, nothing is
measured, nothing is suggested and nothing is applied.

**The question.** From inside a curated country, does a TLS handshake that presents name N to
one of FCP's own member-facing addresses complete, while the same vantages complete it for the
listener's other names? That isolates the one fact `blockedIn` / `provenIn` record (the censor
there treats this name differently) from the two it must not be confused with: the address is
blocked (the block detector's business, § Probes and the block detector) and the target stopped
serving the name (qualification's). Everything else here follows from keeping those apart.

**Sources** (checked 2026-10-16 against each service's API and probe code):

| Source         | A chosen name against a chosen address, from a country                                                                                                                                                                                                                                                                                                                                                                                                                      | What a vantage reports                                                                                         | Cost and limits                                                                                                                                                                                     |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Globalping     | **Yes.** An `http` measurement, protocol HTTPS, `target` = the address, `request.host` = the name, `HEAD /`. The probe sends the name as SNI and as Host (`servername: request.host`), never rejects a certificate, and reports `tls.authorized` with the reason (`ERR_TLS_CERT_ALTNAME_INVALID`, ...), or a failed test with the connection error. A later measurement can name an earlier one as `locations`, so every name of a batch is tried **from the same probes**. | handshake completed with a certificate valid for the name, completed with a wrong one, reset, timeout, refused | One test per probe result, against the account's hourly limit (`GET /v1/limits`; a token raises the per-address anonymous limit). Only GET / HEAD are allowed; the targets are FCP's own addresses. |
| RIPE Atlas     | **Yes.** `sslcert` with `target` = the address and `hostname` = the name (SNI), on probes pinned by id (`type: probes`), so a batch uses the same probes. Results carry the presented chain (`cert`, PEM; FCP checks the leaf against the name), a TLS `alert`, or `err`. The probe code does not speak TLS 1.3 (RIPE NCC, 2023): a TLS 1.3-only target answers it with a `protocol_version` alert, which counts as "answered", never as working.                           | chain valid / wrong for the name, alert, connection error                                                      | 10 credits per result, doubled for a one-off (20). A probe host earns 15 credits a minute. API key required (`EDGE_PROBE_RIPEATLAS_KEY`). Created `is_public: false` and one-off.                   |
| check-host.net | **No.** `check-http` takes one URL, so the address dialled and the name presented cannot differ; `check-tcp` is a bare connect. It stays an address-level source.                                                                                                                                                                                                                                                                                                           |                                                                                                                |                                                                                                                                                                                                     |
| internal       | **No.** FCP's own host is in no country. Qualification already checks every name against its target from here.                                                                                                                                                                                                                                                                                                                                                              |                                                                                                                |                                                                                                                                                                                                     |

**Vantage-host safety.** The checks run on machines inside censored countries, many of them
volunteers' home connections. These rules are built in, not settings:

- **Ordinary traffic only.** One TLS handshake (Globalping adds `HEAD /`) presenting a name a
  large public site really serves (every name qualified against its target first) to an address
  that country's members already connect to. Nothing names FreeSocks: no FreeSocks hostname,
  header, path, query or description (Atlas gets a generic description, Globalping sends its own
  probe user agent). It is the same handshake every member makes.
- **Only addresses that are already out there.** A published, active L4 edge in front of a
  REALITY listener, or an origin node whose operator opted it into probing (`probeNode`). Never a
  standby or candidate edge, never a fronted origin that did not opt in, never an L7 front (its
  name is the CDN's, not the family's). An address the address-level probes find unreachable
  from that country is skipped: hammering a blocked address from inside teaches nothing about
  names.
- **Low frequency.** A name is checked from a country at most once per
  `edge.sni.vantage.intervalHours` (default 72), **as a control too**: a control is a check like
  any other, so a lone due name waits until another name of its address is due (unless the
  address carries no other name), and the names that waited longest go first. Each 10-minute
  tick starts at most **one** batch (one address, one country, `batchNames` names, default 3),
  within `edge.sni.vantage.hourlyBudget` measurements an hour (default 12; one measurement = one
  name, one source, at most `perCountryLimit` vantages, default 3). Calls to one service inside a
  batch are spaced like the address-level probes (1.5 s apart, `EDGE_PLUMBING.probeSourceSpacingMs`).
- **Opt-in per country.** Nothing runs until the switch is on **and** a country on the
  censored-country list has "Check names from inside" on (Settings, Censored countries). Turning
  it off stops new measurements at once.
- **Each source's rules.** Globalping: own addresses, HEAD, within the rate limit. Atlas:
  non-public one-offs within credits. check-host.net is not used. A maintenance freeze stops new
  measurements like any probe.
- **Gates are checked again when the measurement runs**, not only when it is planned: a switch
  turned off, a country or a source taken out, or a freeze in between settles the queued rows
  (`gate_off`, `gate_country`, `gate_source`, `gate_maintenance`) without dialling anything.

**Residual risk** (accepted by turning a country on; the page says so next to the switch):

- Whoever runs a vantage, which can be the censor, sees the address **and the name**. Globalping
  probes run the measurement on their host's machine; RIPE Atlas shows a non-public measurement
  to the hosts of the probes involved, and non-public measurements may not survive (their removal
  was proposed in 2016 and 2022; a public one can never be made private again). The address
  is already given to every member and to the address-level probes; the pairing with a popular
  name is a stronger hint that the address is a REALITY node than a bare connect.
- The vantage's own network sees a connection shaped like a member's. Where reaching a
  circumvention address carries risk, the host carries a share of it, once per name every few
  days.
- The target site sees one `HEAD /` (Globalping) arriving from the node's address.
- Evidence is about the **name**, not about a member's client: vantages do not use a member's
  TLS fingerprint, so a censor blocking by fingerprint and name together is not seen, and Atlas
  cannot speak TLS 1.3.
- Evidence is pooled per name and country across addresses. A name on several addresses is
  checked on each in turn (the one it was checked on longest ago next), and an address that moved
  is another address; a block that depends on the address as well as the name shows as "mixed"
  and suggests nothing.

**Evidence.** `sniVantageProbes` holds one row per measurement: name, country, source, the
batch it belongs to, the target (edge or origin, address and port) and, per vantage, its network
(ASN) and an **outcome** (`lib/edges/probes/nameCheck.ts`, pure):

| Outcome            | Meaning                                                            | Counts as                      |
| ------------------ | ------------------------------------------------------------------ | ------------------------------ |
| `ok`               | the handshake completed with a certificate valid for the name      | works                          |
| `answered`         | the far end answered (a TLS alert, a response without TLS details) | the path is open; nothing more |
| `cert_mismatch`    | completed, but with a certificate not valid for the name           | interference                   |
| `reset`, `timeout` | the handshake did not complete                                     | interference                   |
| `refused`, `error` | refused before any name was sent, or the probe failed              | nothing                        |

A **batch** is one address, one country and two or more names of that address's listener
(the due names; a lone due name takes another due name of the address as its **control**),
measured from the same vantages. The sources of a batch are **one look**: controls pair within a
source (its vantages), but the newest look is judged with every source together, never by
whichever finished last. For each failing vantage the scorer asks whether that vantage completed a
handshake for another name of the batch: from the **same network** = a `singled` failure (the
path works, this name does not), from another network of the batch = `unpaired` (weaker), no
control got through at all = a `path` failure (the address is the problem, not the name).

`sniVantageEvidence` keeps one row per (name, country): the aggregates over
`edge.sni.vantage.windowDays` (default 14; also the rows' retention) of the measurements taken
while the name was in its **current** family, the newest working check ever (`everOkAt`, kept
past the window as the transition marker) and the current failing streak. When its oldest
measurement leaves the window (`oldestAt`) the sweep aggregates it again, so a suggestion never
outlives what it rests on. Cron `sni-vantage` (10 min) plans, from a starting listener that
rotates every tick (the scan is bounded and must not always stop on the same prefix), and
schedules the sweep (timeouts, retention, re-aggregation). Auto-apply runs only once every source
of a batch has settled.

**Scoring** (`lib/edges/sni/vantage.ts`, pure; `minVantages` 3, `minNetworks` 2):

- **Blocked** is suggested when the newest checks of the name from that country all fail and,
  over that failing streak: name-specific (`singled` + `unpaired`) failures come from at least
  `minVantages` vantages on at least `minNetworks` networks; at least one is `singled`; and it is
  either a **transition** (the name worked from there before), **repeated** (two batches at
  least an hour apart), or **corroborated by member reports** (`suspectNames` has it in that
  country). One check of a name that never worked there, with nothing else, waits for the next.
- **Proven** is suggested when, over the window, `ok` came from at least `minVantages` vantages on
  at least `minNetworks` networks, the newest checks do not fail, and member reports do not single
  the name out there (reports and probes disagreeing suggest nothing).
- Otherwise nothing, with a reason the page words: `no_data`, `not_enough_vantages`,
  `not_enough_networks`, `not_paired`, `needs_repeat`, `no_control` (every name failed: look at
  the address), `mixed`, `reports_disagree`.

**What a suggestion may change.** A suggestion never overrides an operator's mark:

| The mark today                          | Suggestion agrees | Suggestion differs                                               |
| --------------------------------------- | ----------------- | ---------------------------------------------------------------- |
| none                                    | -                 | shown with **Apply**; applied by itself only with `autoApply` on |
| set by an operator (`source: operator`) | "agrees"          | shown as a **conflict**; only the operator changes it            |
| set by checks (`source: probe`)         | "agrees"          | shown with **Apply**; flipped by itself only with `autoApply` on |

**Apply** (`POST sni/families/{slug}/vantage/apply {snis, country}`) records each name's current
suggestion as the operator's own mark (`source: operator`), through the same path as "Works
there" / "Blocked there". `edge.sni.vantage.autoApply` (off) writes `source: probe` marks by
itself, never over an operator's mark, and never a `blocked` that would leave a listener carrying
the name with no name usable from that country (that one stays a suggestion, counted as `held`).
`POST sni/families/{slug}/vantage {snis, country}` checks up to six names now (the same gates and
budget; a name checked from there within the last hour is skipped; a spent budget answers 429).
Audit rows: `edge.sni.vantage.request`, `edge.sni.vantage.batch`, `edge.sni.vantage.apply`,
`edge.sni.vantage.auto_apply`, with slugs, the country, the source and counts, never a hostname
or an address.

**How it meets the report hint.** Member reports and checks are separate evidence and stay
separate on the page: the report line ("members in IR report this name more than the others")
and the checks line ("From IR: failed from 3 vantages on 2 networks while other names got
through"). Reports pick which names are checked first, corroborate a single failing check, and
veto "proven"; checks never create a report suspect.

### The page

Admin -> Edges -> Advanced -> Server names (`/admin/edges/names`, `/admin/edges/names/{slug}`).

- The list: each family in one line (how many names are ready, waiting, failing; whether an
  transport uses it), the switch for `edge.sni.enabled`, and "Add a family" (the target is fixed
  at creation).
- A family: bind it to a REALITY transport (the transports come from the Servers observation),
  add names (the answer says what happened to every kind of line), filter and pick names, then
  check again, retire (confirmed: it states the name drain, `edge.sniDrainMinutes`), bring
  back, burn (typed), or record for a curated country that they work
  or are blocked there.
- Checks from inside countries (the list page): the switch for `edge.sni.vantage.enabled`, the
  countries they run from (read only: changed on Settings, Censored countries), the services,
  "Apply suggestions by themselves", the budget in one
  line, and the residual risk next to the switch. On a family, every name shows one line per
  country it was checked from (what the checks saw, then what they suggest against the mark
  standing today) with **Apply** (or "Use the checks instead" on a conflict); picked names can be
  checked from an opted-in country now, or have the checks' suggestions applied. A block
  suggestion or a conflict also puts the name under "Problems".
- A bound transport: "See what would be written" shows the plan in words, including whether one
  test per node will prove the whole list (a witness) or each name needs its own; "Write to the
  backend" starts the rollout; once the backend has it, each node lists how many names it has proven
  and offers "Test through <address>". The test link is shown once with its name, and "It
  connected" confirms the receipt. The page says plainly that a check from outside cannot
  stand in for that test.

The three facts stay separate in the copy: the target serves a name (checked), a node accepts
it (tested), it works from a country (judged; the checks from inside a country only ever
suggest). Wording is in
`src/client/routes/admin/edges/names/lib/words.ts`; tests pin that every `edge.sni.*` refusal
and every check code the server can record has its own sentence.

## Probes and the block detector

Probe targets are the published edges of
every origin (the only kind the detector reads), origin targets that opted in (`probeNode`) and
operator-entered custom targets; UDP listeners are not probeable (`probe.udp_unsupported`).
The detector's load and node-online signals exist only for a `panel-node` origin; for other
kinds the load score is 0 (`no_load_signal`) and `node_offline` reads the instance health of a
`backend-server` origin. The "manageable Host" veto applies only to `hostMode: operator`; a
`setupOwned` origin (a guided setup in progress) is vetoed `setup_owned` right after the
auto-rotate gates, before any evidence is weighed.

**Verification rungs of an L4 edge** (`lib/edges/verifyRung.ts`, pure): `partial` = provider
health + outside reachability (at least `probe.agreementVantages` distinct vantages reachable,
none `unreachable`) + a protocol-SHAPE check branched by the listener's security: the
internal source runs **`tls-sni`** for a REALITY / TLS listener (a full handshake to the edge
ADDRESS with SNI = one of the listener's active names, the chain verified for that name
against the system store, no HTTP; the name is resolved at execution time by
`probes.runContext`, never stored on the run) and bare `tcp` for a plaintext one
(Shadowsocks, Outline). Outside vantages cannot present an SNI to an IP literal, so they keep
`tcp`; `tls-sni` is never a custom-target choice. This is shape evidence only: a forwarder
aimed straight at the camouflage site presents that site's own certificate and passes
`tls-sni` while every real REALITY session through it would fail, so **`partial` is the
ceiling for L4** and nothing server-side ever writes `verified`. The rung is re-derived after
every probe run on an `edge` target settles (`edgeVerification.refreshPartialRung`, from
`probes.finishRun` / `failRun`) and persisted as `edges.verification { rung: 'partial', by:
'system', method: 'probe' }` against the current binding (audited `edge.verification.rung`,
the word only); `unreachable` clears a `partial` record; a `verified` record is never touched.
The record is informational: `verificationCurrent` answers false for any rung but `verified`,
so it never satisfies the publication gate and attention still lists the edge as
`spare_untested`. `verified` comes only from the operator's per-endpoint confirmation
(§ Publication); `unreachable` = an outside `unreachable` verdict or a failed shape run. L7
edges keep `tls` / `https` by name.

## Configuration

`edge.*` in `appSettings` (Admin → Edges → Advanced → Settings, `/admin/edges/settings`, probe
settings included; `GET/PATCH /api/v1/admin/edges/config`). Ships fully dormant:
`enabled=false`, `autoRotate=false`, `render.enabled=false`, `probe.enabled=false`,
`l7.autoSelect=false`. Probe credentials are write-only (`edge.secret.probe.*`). Defaults and
bounds: `convex/lib/edgeConfig.ts`. Every stored key has a control on the Settings page and
every control a key (pinned by `settings.test.ts`).

**Settings are operator decisions; the machinery is constants.** Timeouts, attempt caps, poll
and claim intervals and per-pass caps are `EDGE_PLUMBING` in `convex/lib/edgeConfig.ts`, not
settings: provision timeout 20 min, discovery timeout 30 min, a rotation's wall clock 2 h, poll
20 s, operation claim 60 s, 8 verification attempts, 6 publish and 6 rollback attempts, 48
destroy attempts, one automatic reconcile start per pass, 2,000 report rows per detector
evaluation, the L7 proof's step timeout 10 s, lifetime 60 min and six re-proofs per pass, the
L7 evidence wait 15 min, and 1.5 s between probe runs on one source. Tests and the
edge-connection gate shorten them through `__setEdgePlumbingForTests`.

**One inheritance rule for the per-origin knobs.** `standbyPerRelay`, `standbyPerListener`,
`cooldownMinutes`, `maxRotationsPerDay` and `drainMinutes` are each the origin's own value when
it set one, else the fleet's (`edge.standbyPerRelay`, `edge.standbyPerListener`,
`edge.cooldownMinutes`, `edge.maxRotationsPerRelayPerDay`, `edge.drainMinutes`), resolved by
`originPolicy` everywhere: the rotation machine (a replaced edge drains for the ORIGIN's drain
time), the reconcile, the detector and the admin view. An origin stores only the values it set,
so a fleet change applies to every origin that did not; the admin view returns the effective
values plus `overrides` (the ones the origin set), and a PATCH with `null` returns a field to
the fleet value (the edit dialog sends that when a value is changed to the fleet's).
`desiredPublishedDefault` seeds an origin's `desiredPublished`, which is pool state (setup and
re-protect runs widen it), bounded 1..8 (`MAX_DESIRED_PUBLISHED`, the coverage cap).

The fleet guards: `detect.fleetBreakerPct` (1..100, default 30) and
`detect.fleetRotationsPerDay` (0..500, default 12); `detect.allowProbeOnlyAutoRotate` defaults
to false (§ Operations safety). The one-call `POST automation {on}` (§ Operator endpoints)
flips the four automation switches together and sets `standbyPerListener` to 1 when turning on;
`render.enabled` and `l7.autoSelect` stay manual.

Server-name settings are `edge.sni.*` (`GET/PATCH /api/v1/admin/edges/sni/config`, defaults and
bounds in `convex/lib/sniConfig.ts`). The checks from inside a country are a nested `vantage`
block in that body, read by their own resolver so the render path never reads them:

| Key (`edge.sni.vantage.*`)                | Default         | Bounds       | Meaning                                                                                   |
| ----------------------------------------- | --------------- | ------------ | ----------------------------------------------------------------------------------------- |
| `enabled`                                 | `false`         |              | the switch (needs `edge.sni.enabled` too)                                                 |
| `sources.globalping`, `sources.ripeatlas` | `true`, `false` |              | services; Atlas also needs `edge.secret.probe.ripeatlas.key` / `EDGE_PROBE_RIPEATLAS_KEY` |
| `intervalHours`                           | 72              | 6..720       | a name is checked from a country again after this long                                    |
| `hourlyBudget`                            | 12              | 0..120       | measurements an hour (one name, one source, one country)                                  |
| `perCountryLimit`                         | 3               | 1..5         | vantages per measurement                                                                  |
| `batchNames`                              | 3               | 2..6         | names per batch, the control included                                                     |
| `windowDays`                              | 14              | 1..60        | the scoring window, and the measurement rows' retention                                   |
| `minVantages`, `minNetworks`              | 3, 2            | 1..20, 1..10 | what a suggestion needs                                                                   |
| `autoApply`                               | `false`         |              | apply suggestions by themselves (never over an operator's mark)                           |

The countries are not a key here: they are the listed countries with "Check names from inside"
on (next section). At the defaults one source spends at most 12 measurements an hour (36 vantage
results); a
family of 40 names in four countries is covered in about 14 hours and then every 72 (a name on several addresses takes one of them per interval); a family
of 500 is covered about once a week unless the budget is raised. Globalping tests count against
the same account limit as the address-level probes.

### The censored-country list

One list, `censorship.countries` in `appSettings` (`convex/lib/censoredCountries.ts`), replaces
five that had drifted apart: `edge.sni.curatedCountries`, `edge.probe.countries`,
`edge.sni.vantage.countries`, `delivery.privacyCountries` and the rows of the status page's
availability matrix (`status.censorship`). Admin -> Settings -> "Censored countries"
(`GET|PUT /api/v1/admin/censored-countries`, `admin:settings:read|write`; PUT replaces the
whole list). Up to 40 entries, in the operator's order, each
`{ code, checkEdges, checkNamesInside }`:

- being on the list makes a country a **curated country** for server names (§ Names for the
  member's country), a choice under "Where are you connecting from?", a row the status page can
  show, and a country where the connection-mode suggestion follows the availability matrix
  (`convex/lib/modeSuggestion.ts`: modes available on the member's backend ranked by that
  country's cell, `available` before `partial`; a listed country without a row gets the
  censorship-recommended mode; elsewhere the default);
- `checkEdges`: edges are probed from there (`EdgeConfig.probe.countries` is filled from these;
  the Edges settings page shows them read only);
- `checkNamesInside`: the checks from inside a country run there (`SniVantageConfig.countries`),
  with the residual risk above stated next to the switch.

While the key has never been written the list is computed **live** from the five old keys (their
union, in the order curated, probe, vantage, privacy, matrix rows; a probe country keeps
`checkEdges`, a vantage country keeps `checkNamesInside` only if it was also curated), so nothing
moves between `convex deploy` and the seed. `seed:seedCensoredCountries` (part of `seedCutover`)
then writes that list once and never overwrites a stored one. The old keys are left in place for
a rollback and no longer read once the list is stored; the edges and server-name PATCH routes no
longer write them. A matrix row of a country that leaves the list stays stored (adding the
country back brings it back) but is not shown on the public page. Audit:
`censorship.countries.update` with the codes added, removed and re-flagged, and the new length.

## Sealing

Every route under `/api/v1/admin/edges/` is sealed by verb (GET reveals, POST seals both legs,
PATCH seals the request, DELETE carries nothing; there is no PUT). Dual-mode plaintext stays
for `fsv1_` callers; `FS_HPKE_ADMIN_REQUIRED=true` refuses plaintext from cookie-session
callers. Config routes need `admin:settings:*`, everything else `admin:servers:*`. No route
here accepts `admin:edges:register`: that scope is the node role's, on the Servers by-name
routes only (see the node role contract).

## Node role contract (Ansible)

**Contract v2: the role bootstraps the machine, FCP does the rest.** The role
(`ansible-role-freesocks`) installs Docker, the node container and, for a front node, Caddy with
its decoy site; FCP owns the backend (the node row, its Host, the profile), the origin name, the
edges and the release to members. The role registers nothing under `/api/v1/admin/edges/`: it
talks only to the Servers routes `/api/v1/admin/servers/{slug}/nodes/by-name/{name}` (`GET`,
`PUT`, `DELETE`, `POST …/bootstrap|applied|wiped`), whose request and answer fields, scopes and
refusals are in `docs/servers.md` "Node registration (contract v2)". One run, in order:

1. Learn the machine's public addresses and the node's management address.
2. `PUT` (enroll the first time with `roleContractVersion: 2`, `mode`, `label?`; afterwards
   report the observations) and read the view (`GET`).
3. `POST …/bootstrap`: the machine configuration (node port and name, the Caddy routes of a
   front node, the origin hostname), `firewall.ports`, and the node secret, which FCP reads from
   the backend per call and never stores.
4. Let every `firewall.ports` port in (TCP), and, for a front node, wait for the origin name to
   resolve, then start Caddy and the node.
5. `POST …/applied {appliedRevision, caddy.certificateReady, nodeStarted, firewall}`: the
   revision must be the current one; the ports confirm this node's waiting port changes
   (`docs/servers.md` "Firewall acknowledgement").
6. Gate on the node's own view (stage, registration code, revisions, retirement), not only on the
   backend row.

`DELETE` asks for a retirement and `POST …/wiped` reports the machine cleaned up. After enrollment
nothing more is the role's job: Autopilot discovers the node's listeners from the backend and its
declared ingress, and publication is admitted only under the node's approval
(`servers.node_not_approved`; setup need `node_not_approved`). Three pieces of the edges side
depend on it:

- **Loopback ingress.** A front node's WebSocket (or gRPC) transport listens on loopback behind
  Caddy. `mapTransportsToListeners` takes `opts.ingress` (`convex/lib/backend/ingress.ts`): a
  mapped loopback transport is discovered as the external TLS listener Caddy exposes (port 443,
  the origin hostname as its certificate name). The Host-header answer comes from the node's
  verified ingress (`ingress_verified` evidence at `machine_ready`), not from the origin probe.
  Without a mapping, loopback stays `loopback`.
- **Go-live.** For an enrolled node, `edgeSetupRuns.goLive` promotes the node's activation run
  inside its own mutation (`nodeActivation.promoteCandidate`): the edges it published are the
  run's candidate resources, filtered from members until then.
- **The origin TLS contract.** Recorded per combination: Fastly with `overrideHost: 'origin'`
  (SNI = Host = the origin name, a public certificate naming it) is supported; Fastly with
  `'hostname'` only when the node's verified ingress accepts any Host header; Cloudflare `full`
  (SNI and Host = the edge hostname, served by Caddy's `fallback_sni` plus a catch-all site) is
  supported. Cloudflare `strict` is admitted only for an origin whose certificate is publicly
  trusted (`certPublic`), and it validates the EDGE hostname, which an enrolled node's
  certificate (the origin name only) does not carry: use `full` for enrolled nodes.

**Contract v1 is retired.** The origin-registering role (`PUT …/relays/by-slug/{slug}`, its
`DELETE` and listener companions, and the `operation_mode=adopt_relay` legacy adoption) is gone:
the PUT answers 404 and registers nothing. Origins the v1 role registered keep their rows
(role-owned listeners, `lastRegisteredAt`) and are managed in the CMS; their role-owned
listeners can be enabled, disabled, have names retired and be retired there, but not edited
(`edge.listener_key_owned`): a change is a new listener under another key.
`GET …/relays/by-slug/{slug}` stays as an admin read of an origin's minimal projection
(`publishedEndpoints`, `connectionPlan`, `hostsPlan`).

**The role's token.** An `fsv1_` token with `admin:edges:register`, minted with a
**registration boundary** (`apiTokens.edgeRegistration`: the backend servers and, optionally,
the node names it may act for), accepted only on the by-name routes
(`servers.registration_boundary` outside the boundary); a boundary-less register token may act
for nothing. `admin:servers:manage` is bounded the same way (backend-write automation never
reaches a node secret on its own); only `admin:servers:write` (the fleet token, and
`admin:servers:read` on a `GET`) is unbounded. Credential rotation = mint a new token with the
same boundary and revoke the old one. The boundary is set at mint: in the CMS (Admin → API
tokens; ticking the scope reveals the backend-server and node-name inputs) or from the control
plane with `adminApi:mintAutomationToken '{"scopes":["admin:edges:register"],
"registerBackendSlugs":["<slug>"],"registerNodeNames":["<node>"]}'`. The mint refuses the
scope without a boundary and a boundary without the scope (`validation`); the audit row
carries counts only. A rename keeps the old name answering and adds the new one to the
boundary (`docs/servers.md` "Renaming a node").

Node pinning understands the origin remark (`convex/lib/nodePinning.ts`).

## Runbooks

**Qualify a provider account.** Add the account and test its credentials, then:

- **L4 (a load-balancer provider): one human tick per endpoint.** Provision a spare on an origin
  from the account (the explicit test-provision path accepts a tested but unqualified
  account); the probes take it to `partial` at most. Fetch `GET edges/{id}/verification-binding`,
  try the address with a real session (the isolated test link, or the named connection for an
  address that is already published), then `POST edges/{id}/verify` echoing the binding you
  were shown. The first confirmed endpoint of the account trusts the account when it was
  provisioned with the account's current template and the credentials were tested after their
  last change (`accountTrustReason` in the response says why not); every NEW endpoint of that
  account still needs its own tick before it can be published or used by an automatic
  replacement, and a listener or address change after the tick puts the endpoint back under
  `retest_needed` and out of every rendered body until retested. The provider page's "Trust this
  account" override trusts the account only; it verifies no endpoint.
- **L7 (a CDN front): automatic on the proof.** Once an active edge of the account carries a
  current authenticated end-to-end proof for the account's effective template (and the account
  was tested after its last credential change), the account is trusted by the auto-trust rule
  (evaluated after every passing proof and by the reconcile sweep; audited
  `edge.provider_account.auto_qualified`). No manual step.

A manual "Remove trust" holds automatic trust off until an operator trusts again or the
credentials change. Editing credentials or settings, or a template change that moves the
account's effective template, clears the qualification (and its evidence).

**Protect a backend node.** Autopilot only: the runbook "Deploy a fronted node" in
`docs/servers.md`, from the role run to a member connection.

**Bootstrap a manual or whole-Outline origin.** All origins → New origin (`?new=1`: a manual
address or a whole Outline server only), then the first-edge card on its Origin details page:
provision an edge or import an existing front, publish it, enable rendering, preview each client
family. Until the first publish with rendering on, members on that origin receive 503.

**Resolve a quarantine / `needs_operator` / an `ambiguous` Host.** Compare the backend's Host with
the recorded bindings, fix by hand if needed, then resolve keeping the binding that matches
what the backend serves; for a Host the backend shows twice for one listener, delete the extra
and resolve.

**Add an L7 account / qualify an L7 front.** Add the account (with its zone), provision a front
on an HTTP-carried listener; FCP proves it end to end (§ L7 edges) and the first passing proof
trusts the account. Each front is proven for its own listener (§ L7 edges).

## Maintenance switch and reset drain

`edgeMaintenance:freeze` separates **admission of new work** from **completion of work in
flight** (`convex/lib/edges/maintenance.ts`). While frozen, nothing new is admitted
(`edge.maintenance`): rotation starts of any kind, registration, imports, direct publishes,
provider account / template writes, probe requests and detector evaluation. Completion paths
keep running: rotation steps and re-kicks, rollback, cancel, unpublish, destroy runs, Host
operations, quarantine / needs_operator resolution, origin delete finalisation, credential
removal. Credential rotation of a provider account also stays admitted (a destroy that must
finish during a drain needs working credentials), as do qualification probes of a rotation
already in flight; every other admin configuration write (qualification flips, account and
template deletes) and every cron, detector or manual probe request is refused. A guided setup
run's stage-5 publish is completion of work admitted before the freeze: its rotation start
carries `admission: 'setup.complete'` (a kind `assertAdmission` admits while frozen, only for a
start that also carries `setupRun`); stages 1 and 3 of a run stay blocked (`maintenance`).
`edgeMaintenance:thaw` lifts it.

`seedEdgesReset` is the one-shot drain that precedes a breaking change to the edge tables:
`freeze` → `status` (read-only, every environment: non-terminal rotations, managed edges not
destroyed (the whole table is walked, never a capped listing), held external locks, quarantined or deleting origins, active or owed qualification
credentials) → finish that work through the ordinary machine until `blockers` is empty →
`bunx convex env set EDGE_RESET_ALLOW wipe-edges` then `wipe '{"confirm":"wipe-edges"}'` (the
opt-in is a deployment env var, set for the reset and **removed afterwards**; `ENVIRONMENT`
cannot be the guard because a beta stack runs `ENVIRONMENT=production` like prod; local
`development` needs none; refuses while any blocker remains, and every destructive batch
re-checks opt-in, confirm word, freeze and blockers itself; deletes `edgeRotations`, `edges`, `relayListeners`, `relays`, `edgeDeliveryBindings`,
`externalLocks`, `relaySamples` and the edge/origin probe rows in bounded pages; turns the
`edge.*` switches off; keeps probe targets, provider accounts, templates, node inventory, marks,
the audit log) → deploy → `thaw`. The deploy entrypoint pushes the schema before it runs any
function, so the drain runs on the OLD code first. All through the deployer container
(`docs/beta-deploy.md` § "One-off functions").

## Local development

The whole setup flow (account, template, origin, provision, qualify, publish, render) can be
walked without cloud credentials. With `ENVIRONMENT=development` and
`DEV_FAKE_EDGE_PROVIDER=true` on the deployment, the provider registry hands out an in-memory
fake in place of one real adapter per layer (`convex/lib/edges/providers/fake.ts`); the fake
keeps the real adapter's template schema so the forms behave as they would in production,
answers with RFC 5737 / RFC 3849 addresses and `*.example` hostnames, records its calls, and
finishes every create instantly (`DEV_FAKE_EDGE_SLOW_MS` delays creates to exercise the async
paths). `seed:seedDevEdges` (the same double gate plus `DEV_MOCK_BACKEND=true`) creates a mock backend server and one tested
but unqualified account per layer, so the first edge goes through the explicit test-provision
path rather than ordinary selection. Nothing about the fake is reachable when either variable
is missing, and it never appears in the provider id lists or the wire contracts.

## Provider accounts: names, test answers and offered regions

**Name.** An account's name is a label for admins (1 to 63 letters, digits, spaces, dots,
dashes and underscores). Edges reference the account by id, so `PATCH …/providers/{id}` with
`name` renames it without touching the provider or the qualification (Rename on the account
page). Names stay unique.

**The provider's answer.** A provider error's message carries the HTTP status and a short
code, never the response body: bodies of provisioning calls echo origins and fronted
hostnames. The exception is the calls an admin makes by hand before anything exists, the
credential test and the account form's listings (`DIAGNOSTIC_STEPS` in
`convex/lib/edges/providers/http.ts`). Those requests carry no origin and no hostname, so
their error keeps `meta.detail`: the provider's answer with address literals and the
credential replaced, capped at 600 characters (a credential under 8 characters cannot be
replaced safely, so the answer is withheld entirely). It is returned by `test-credentials` and
`rotate-credentials` (`detail`), by `discover` (`errorDetails`, per failed list), stored as
`edgeProviderAccounts.lastTestErrorDetail` until the next passing test, and shown folded away
under "Show the provider's answer". It never enters a thrown message, a log line or an audit
row. A new adapter gets this by naming its test and listing steps from that set.

**Offered regions.** A provider's region listing can include regions the account cannot use.
The Gcore adapter keeps only `ACTIVE` regions and, once it knows a project, asks each one for
its load balancers (the credential test's own call, 8 at a time). A region that answers with
a definite refusal (a 4xx other than 401 and 429) is not offered; a timeout or a 5xx says
nothing about the region, so it stays.

## Adding an edge provider

Everything derives from the id tuple in `src/shared/contracts/edgeProviderIds.ts`; every
`Record<EdgeProviderId, …>` fails to compile until the new id has an entry:

1. `src/shared/contracts/edgeProviderIds.ts`: add the id.
2. `convex/lib/edges/accountSettings.ts`: the settings zod schema and its classification;
   `convex/schema.ts`: the credentials and settings union variants.
3. `convex/lib/edges/providers/templates.ts`: the template schema, field descriptors and
   defaults; `providers/capabilities.ts`: the capability row (layer, address kind, transports,
   DNS roles, origin-port mode, `udp`, async and health flags, settle floor).
4. `convex/lib/edges/providers/<id>.ts`: the `EdgeProvider` adapter, registered in
   `providers/registry.ts`, with `<id>.test.ts` on the recording transport.
5. `convex/lib/edges/providers/wireContract.ts`: every endpoint the adapter calls; the table
   below is generated from it. `.github/workflows/edge-providers.yml`: add the id to the matrix.
6. `scripts/node-floor.mjs` when the adapter imports an npm dependency, and `'use node';` as
   the adapter's first statement; `src/client/lib/edgeProviderMeta.ts` for the account form.

## Provider wire contracts

Every HTTP endpoint the edge adapters call, per provider. The table is generated from
`WIRE_CONTRACTS` (`convex/lib/edges/providers/wireContract.ts`) and pinned by
`wireContract.test.ts`, which drives each adapter's whole lifecycle against a recording HTTP
transport and fails when a request is not declared here, when a declared call is never made, or
when this section drifts from the contract. Paths are regular expressions matched against the
request path, with `[^/]+` where an id, a name or a version number goes; `?key` lists the query
keys a call must carry. The Cloudflare rows cover both the Cloudflare edges and the DNS records a
Fastly edge writes into a referenced Cloudflare account. A new provider is not finished until its
lifecycle runs in that test and its rows appear here.

| provider   | method | path                                                                              | purpose                                                                                                           | source                                                                                                                                                                            |
| ---------- | ------ | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| gcore      | GET    | `^/cloud/v1/loadbalancers/[^/]+/[^/]+$`                                           | list load balancers: credential test, region check, discovery by name, inventory                                  | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | POST   | `^/cloud/v1/loadbalancers/[^/]+/[^/]+$`                                           | create the load balancer with its TCP listener, pool and health monitor                                           | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | GET    | `^/cloud/v1/loadbalancers/[^/]+/[^/]+/[^/]+$`                                     | read one load balancer: describe, inspect, delete confirmation                                                    | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | DELETE | `^/cloud/v1/loadbalancers/[^/]+/[^/]+/[^/]+$`                                     | delete the load balancer (answers with a task)                                                                    | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | GET    | `^/cloud/v1/tasks/[^/]+$`                                                         | poll the create or delete task and read the resources it created                                                  | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | GET    | `^/cloud/v1/floatingips/[^/]+/[^/]+$`                                             | list floating IPs (inventory)                                                                                     | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | GET    | `^/cloud/v1/floatingips/[^/]+/[^/]+/[^/]+$`                                       | read a floating IP back after its delete                                                                          | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | DELETE | `^/cloud/v1/floatingips/[^/]+/[^/]+/[^/]+$`                                       | release the floating IP the load balancer held                                                                    | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | GET    | `^/cloud/v1/lbflavors/[^/]+/[^/]+$`                                               | list load balancer flavors (inventory)                                                                            | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | GET    | `^/cloud/v1/projects$`                                                            | account form: the projects the key can see                                                                        | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | GET    | `^/cloud/v1/regions$`                                                             | account form: the regions the key can see                                                                         | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | GET    | `^/cloud/v1/networks/[^/]+/[^/]+$`                                                | account form: private networks for a private VIP                                                                  | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| gcore      | GET    | `^/cloud/v1/subnets/[^/]+/[^/]+$`                                                 | account form: the subnets of those networks                                                                       | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
| upcloud    | GET    | `^/1\.3/account$`                                                                 | credential test                                                                                                   | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | GET    | `^/1\.3/zone$`                                                                    | account form: the zones                                                                                           | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | POST   | `^/1\.3/load-balancer$`                                                           | create the service with its TCP frontend and backend inline                                                       | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | GET    | `^/1\.3/load-balancer$`                                                           | list services: discovery by name and inventory                                                                    | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | GET    | `^/1\.3/load-balancer/plans$`                                                     | list the service plans (inventory)                                                                                | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | GET    | `^/1\.3/load-balancer/(?!plans$)[^/]+$`                                           | read one service: describe, inspect, attachment check                                                             | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | DELETE | `^/1\.3/load-balancer/(?!plans$)[^/]+$`                                           | delete the service (idempotent; re-issued until it answers 404)                                                   | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | POST   | `^/1\.3/load-balancer/[^/]+/ip-addresses$`                                        | delegate the floating IP to the service                                                                           | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | POST   | `^/1\.3/ip_address$`                                                              | allocate the floating IPv4 that is published                                                                      | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | GET    | `^/1\.3/ip_address$`                                                              | list IP addresses: unknown-outcome discovery and inventory                                                        | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| upcloud    | DELETE | `^/1\.3/ip_address/[^/]+$`                                                        | release the floating IP                                                                                           | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs$`                                                        | list load balancers: credential test, discovery by name, inventory                                                | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | POST   | `^/lb/v1/zones/[^/]+/lbs$`                                                        | create the load balancer over the already allocated IPs                                                           | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs/[^/]+$`                                                  | read one load balancer: describe, inspect, delete confirmation                                                    | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | DELETE | `^/lb/v1/zones/[^/]+/lbs/[^/]+$ ?release_ip`                                      | delete the load balancer without releasing its IPs                                                                | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | POST   | `^/lb/v1/zones/[^/]+/ips$`                                                        | allocate a flexible IP (v4, and v6 when the template asks)                                                        | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/ips$`                                                        | list flexible IPs: discovery by tag and inventory                                                                 | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/ips/[^/]+$`                                                  | read a flexible IP back after its release                                                                         | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | DELETE | `^/lb/v1/zones/[^/]+/ips/[^/]+$`                                                  | release a flexible IP                                                                                             | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | POST   | `^/lb/v1/zones/[^/]+/lbs/[^/]+/backends$`                                         | create the TCP backend pointing at the origin                                                                     | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs/[^/]+/backends$`                                         | list backends: discovery by name and inspect                                                                      | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/backends/[^/]+$`                                             | read a backend back after its delete                                                                              | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | DELETE | `^/lb/v1/zones/[^/]+/backends/[^/]+$`                                             | delete the backend                                                                                                | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | POST   | `^/lb/v1/zones/[^/]+/lbs/[^/]+/frontends$`                                        | create the frontend on the edge port                                                                              | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs/[^/]+/frontends$`                                        | list frontends: discovery by name and inspect                                                                     | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/frontends/[^/]+$`                                            | read a frontend back after its delete                                                                             | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | DELETE | `^/lb/v1/zones/[^/]+/frontends/[^/]+$`                                            | delete the frontend                                                                                               | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs/[^/]+/stats$`                                            | backend health for describe and inspect                                                                           | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lb-types$`                                                   | list load balancer types (inventory)                                                                              | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16                                                                           |
| ovh        | GET    | `^/1\.0/auth/time$`                                                               | server clock for the request signature (cached, unsigned)                                                         | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project$`                                                           | account form: the project ids                                                                                     | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+$`                                                     | credential test and the project label in the account form                                                         | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region$`                                              | account form: the regions of the project                                                                          | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/network/private$`                                     | account form: the private networks                                                                                | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/network/private/[^/]+/subnet$`                        | account form: the subnets of a private network                                                                    | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/operation$`                                           | in-flight balancer operations: absence is never confirmed during one                                              | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/operation/[^/]+$`                                     | poll the compound create operation                                                                                | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | POST   | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer$`             | create the balancer with its network, floating IP and listener inline                                             | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer$`             | list balancers: discovery by name and inventory                                                                   | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer/[^/]+$`       | read one balancer: describe, inspect, delete confirmation                                                         | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | DELETE | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer/[^/]+$`       | delete the balancer                                                                                               | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer/[^/]+/stats$` | balancer statistics (inspect)                                                                                     | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/flavor$`                   | list balancer flavors (inventory)                                                                                 | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/floatingip$`                             | find the floating IP the compound create minted, by its description marker                                        | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/floatingip/[^/]+$`                       | read a floating IP back after its delete                                                                          | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | DELETE | `^/1\.0/cloud/project/[^/]+/region/[^/]+/floatingip/[^/]+$`                       | release the floating IP                                                                                           | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/gateway$`                                | find the gateway the compound create minted, by its FCP name                                                      | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/gateway/[^/]+$`                          | read a gateway back after its delete                                                                              | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| ovh        | DELETE | `^/1\.0/cloud/project/[^/]+/region/[^/]+/gateway/[^/]+$`                          | delete the gateway the compound create minted                                                                     | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/user/tokens/verify$`                                                 | credential test: the token is active                                                                              | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones$ ?per_page`                                                    | account form: the zones the token can see                                                                         | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones/[^/]+$`                                                        | credential test: the zone is active and not paused                                                                | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/settings/(ssl\|websockets)$`                             | zone encryption mode and WebSockets setting (recorded, not required)                                              | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | POST   | `^/client/v4/zones/[^/]+/dns_records$`                                            | create the proxied record that IS the edge; also the ACME and traffic records a Fastly edge writes into this zone | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/dns_records$ ?name.exact&per_page`                       | look one name up (unknown-outcome discovery, CAA preflight), including for a Fastly edge                          | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/dns_records$ ?page&per_page&proxied`                     | paged sweep of proxied records for the import inventory                                                           | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/dns_records/[^/]+$`                                      | read the record back: describe, inspect, import inspection, delete confirmation                                   | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | DELETE | `^/client/v4/zones/[^/]+/dns_records/[^/]+$`                                      | delete the record (a Fastly edge deletes its records here too)                                                    | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/rulesets/phases/http_request_origin/entrypoint$`         | read the origin-rules entry point (404 = none yet), and the rule an imported hostname already carries             | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | PUT    | `^/client/v4/zones/[^/]+/rulesets/phases/http_request_origin/entrypoint$`         | bootstrap the entry point with our one origin rule, under the zone lock                                           | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | POST   | `^/client/v4/zones/[^/]+/rulesets/[^/]+/rules$`                                   | add the destination-port origin rule, recovered by its ref                                                        | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | DELETE | `^/client/v4/zones/[^/]+/rulesets/[^/]+/rules/[^/]+$`                             | delete the origin rule                                                                                            | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/ssl/certificate_packs$`                                  | certificate readiness for the minted hostname                                                                     | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| fastly     | POST   | `^/service$`                                                                      | create the VCL service (form encoded)                                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service$ ?page&per_page`                                                       | paged service sweep for the import inventory                                                                      | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/search$ ?name`                                                         | discover the service by its deterministic name (404 = absent)                                                     | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/details$`                                                        | active version: activation discovery, describe, import inspection, drift check                                    | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/domain$`                                                         | every domain a service serves (the import ownership boundary)                                                     | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/service/[^/]+$`                                                                | delete an exclusively owned service                                                                               | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version$`                                                        | the version list: pick the draft, recognise a lost clone by its marker                                            | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/service/[^/]+/version/[^/]+$`                                                  | stamp the clone marker comment on the work version                                                                | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/service/[^/]+/version/[^/]+/clone$`                                            | clone the active version for a shared teardown                                                                    | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/validate$`                                         | validate a version before activating it                                                                           | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/service/[^/]+/version/[^/]+/activate$`                                         | activate the version                                                                                              | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/service/[^/]+/version/[^/]+/deactivate$`                                       | deactivate the active version before deleting the service                                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/service/[^/]+/version/[^/]+/backend$`                                          | create the single origin backend (only fields the WebSocket path honours)                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/backend$`                                          | list backends: inspect and the import ownership check                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/backend/[^/]+$`                                    | discover the backend by name; read it back after a destroy                                                        | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/service/[^/]+/version/[^/]+/snippet$`                                          | install the VCL snippet that hands an Upgrade request to the WebSocket path                                       | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/snippet/[^/]+$`                                    | discover the snippet by name; read it back after a destroy                                                        | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/service/[^/]+/version/[^/]+/domain$`                                           | add the fronted hostname to the draft version                                                                     | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/domain$`                                           | list the version domains: inspect, the import ownership boundary, shared-teardown confirmation                    | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/domain/[^/]+$`                                     | discover the domain by name; read it back after a destroy                                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/domain/[^/]+/check$`                               | DNS readiness of the fronted hostname                                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/service/[^/]+/version/[^/]+/domain/[^/]+$`                                     | remove only our hostname from a shared service                                                                    | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/enabled-products/v1/websockets/services/[^/]+$`                                | enable the WebSockets product on the service (idempotent)                                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/enabled-products/v1/websockets/services/[^/]+$`                                | discover the product state, on import too; read it back after a destroy                                           | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/enabled-products/v1/websockets/services/[^/]+$`                                | disable the product last, after the service is gone                                                               | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/tls/subscriptions$`                                                            | order the certificate for the fronted hostname (JSON:API)                                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tls/subscriptions$ ?filter[tls_domains.id]`                                    | discover the subscription by domain, and the certificate an imported hostname already has; confirm its removal    | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tls/subscriptions/[^/]+$`                                                      | issuance state and (with the include) the managed-DNS challenge                                                   | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/tls/subscriptions/[^/]+$ ?force`                                               | delete the subscription (force, since its domain is enabled)                                                      | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tls/configurations$`                                                           | account form choices, and the CNAME target every fronted hostname points at                                       | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tokens/self$`                                                                  | credential test: the token scope                                                                                  | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/current_customer$`                                                             | credential test: the pricing plan (informational)                                                                 | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |

## Deploy notes

**The cleanup release** tightens the schema (removes values no row holds: the `standby` edge
status, the restore workflow's copy of `darkCohortKeys`, the `wiped` retirement stage and the
`migrate` disposition with `panelMigrations`, the contract-v1 `panelHandoff` table and the
TRANSITIONAL fields of `panelSetups`, `panelNodeIntents` and `panelOwnership`), makes four
origin fields optional overrides, and adds indexes (`panelOps.by_server_kind` and
`by_open_updated`, `sniRollouts.by_phase_updated`, `edgeHostHides.by_state_updated`,
`panelPortChanges.by_state_updated` and `by_op`, `panelNodeRenames.by_op`,
`panelActivationRuns.by_state_updated`) and six daily retention crons. ONE deploy: Convex
validates every stored document on push, so a row still holding a removed value would make the
push fail before anything changes; none did on any deployment when this was written (a
read-only `convex data` count per value). The removed `edge.*` keys (`providerAffinity`,
`settleGraceSeconds` and the plumbing now in `EDGE_PLUMBING`) are no longer read; a stored row of
one is ignored. `backendSetup:migrateContractV2` is gone (`docs/servers.md` "Moving to modes").

**Checks from inside a country** (vantage evidence) add two tables (`sniVantageProbes`,
`sniVantageEvidence`), an index on the existing `sniReportCounts` (`by_country_day`, built by
the backend on push; the family page now reads reports per country with it), cron
`sni-vantage` (10 min) and `edge.sni.vantage.*` settings. Everything
is additive and dormant: with `edge.sni.vantage.enabled` off and no country ticked the cron only
sweeps (nothing to sweep). No migration, no env change (the probe credentials are the existing
`EDGE_PROBE_GLOBALPING_TOKEN` / `EDGE_PROBE_RIPEATLAS_KEY`), and `sniNameCountry.source:
'probe'` was already in the schema. Turning it on is an operator decision per country (§ Checks
from inside a country, "Residual risk").

The `"use node"` actions (provider SDKs, probes, the front qualification) run on the Node
version baked into the self-hosted Convex backend image. The L7 adapters add `cloudflare` (the
official TypeScript SDK, retries off) and `fastly` (the official JavaScript SDK behind a typed
wrapper; it declares `superagent@^6`, which is deprecated along with its `formidable@1`, so
`package.json` overrides `superagent` to the maintained 10.x line and `sdk.test.ts` pins that the
resolved major stays at or above 10); both bundle into the Node action without external packages.
The adapters, the shared DNS client, the registry, the front check's socket layer and the
internal probe start with `'use node';` because every file under `convex/` is a bundler entry
point and the Fastly SDK and the `node:*` imports only bundle for the Node runtime; isolate code
(queries, mutations, the renderer) imports the pure helpers next to them (`capabilities`,
`templates`, `frontCheck/binding`, `frontCheck/vless`) instead, and `bun run convex:bundle-check`
refuses an isolate import of a `"use node"` module in CI. `scripts/node-floor.mjs` derives the highest `engines.node`
floor among those dependencies and `docker/deploy-entrypoint.sh` fails the deploy when the
runtime is below it (`DEPLOY_SKIP_NODE_FLOOR=true` bypasses). The check runs BEFORE the push when
the running deployment already exposes the runtime probe (so incompatible code is never
published first) and again after it; only the first deploy of the guard checks after its own
push. The observed version shows on the admin dashboard.
