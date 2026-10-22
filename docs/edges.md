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

The pages that show live state keep themselves current while the tab is visible
(`src/client/lib/livePoll.ts`): an origin and its lists every 30 s, every 4 s while something runs
on it (a rotation, a setup run, an edge being made or destroyed, a restore). The origin lookup,
the fleet summary and the attention list each remember a stamp per origin (epoch, running and
last rotation, published and spare edges, pause, restore; the status and counts for attention)
and refresh that origin's lists as soon as one moves, so an automatic replacement shorter than a
poll still shows within one summary read. Forms, catalogs and test links never poll. The node
page and the Edges home say "Updated N s ago" with a button that reads them again now.

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
  real CDN-style front (a proxied record per edge, its Origin Rule's port honoured, the
  member's address removed from `CF-Connecting-IP` by its header rule and kept in
  `X-Forwarded-For`, as Cloudflare does). The other adapters speak the same layer; their wire
  contracts are pinned by `wireContract.test.ts`.
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

| Concept           | Table                  | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Provider account  | `edgeProviderAccounts` | One cloud or CDN account: write-only credentials, the account-wide settings (the DNS zone for an L7 provider, the API endpoint where a provider has several), priority, a daily allocation budget, a live-edge cap, a default location. No region: that is a location. An L7 provider whose hostnames' DNS lives elsewhere names a **DNS account**.                                                                                                              |
| Provider location | `edgeLocations`        | One place an account creates edges in: the frozen **placement** (region or zone, project, private network), its `placeKey` (the provider's own region or zone id), trust (`qualified`), optional regional template values, a live-edge limit, a cost note and its inventory. A CDN account has one, `anycast`. § "Provider accounts and locations".                                                                                                              |
| Edge template     | `edgeTemplates`        | Per provider (optionally per account): the full provisioning parameters, validated by the adapter's schema. Provisioning records the template hash; L7 edges also freeze the effective parameters into their intent.                                                                                                                                                                                                                                             |
| Origin            | `relays`               | One ORIGIN behind edges: its `origin` (kind + backend/node or backend server), `originAddress` (what edges dial; never published), `hostMode` (who writes the client-facing backend Hosts), published pool, publication epoch, rotation limits, detector state, quarantine, `probeNode`, the L7 qualification credential.                                                                                                                                        |
| Listener          | `relayListeners`       | One port the origin answers on: `protocol / streamTransport / security` (the catalogue below), server names (REALITY SNIs or certificate names) with retire/drain, an optional REALITY target, HTTP transport parameters, `originTransport` (how an L7 front dials it), a **match rule** (how its template entry is found in a body), the backend transport it maps to, the backend Host FCP owns for it, `source` (role or admin) and a canonical `configHash`. |
| Edge              | `edges`                | One provider resource bound to a LISTENER and created in one LOCATION (frozen on the row): its layer, the resource-step ledger, child resources, addresses (IP literals for L4, the hostname for L7), publication state and pool index, health, readiness, front qualification, live snapshot, reachability. L7 edges carry a frozen **provision intent**.                                                                                                       |
| Rotation          | `edgeRotations`        | One provision / publish / replace run: phase, step version, operation claim, per-listener Host plan, previous binding, live event log; its audit trail is assembled on read.                                                                                                                                                                                                                                                                                     |
| Delivery binding  | `edgeDeliveryBindings` | The edge-required policy an origin imposes on the subscriptions of its node or backend server, kept apart from the origin row so deleting the origin never silently restores raw delivery.                                                                                                                                                                                                                                                                       |
| Probe target      | `probeTargets`         | An operator-entered public host:port probed alongside the derived targets (edges, origin targets). Operator evidence only.                                                                                                                                                                                                                                                                                                                                       |
| Probe run         | `probeRuns`            | One reachability measurement of one target address from one source.                                                                                                                                                                                                                                                                                                                                                                                              |
| Reachability      | `probeReachability`    | Per target, per country, per source, per address family: the last run's vantage counts and verdict; summarised onto the target's own row.                                                                                                                                                                                                                                                                                                                        |

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
carries the probe's reason. The setup plan asks a target that got no answer again
(`ORIGIN_PROBE_ATTEMPTS`, 3, half a second apart; an address the probe refuses outright is not
asked again), and when it never answers the plan says so: the inbound carries `probeFailed` and
an L7 account that would carry it reads `origin_unreachable` ("Couldn't reach the origin. Try
again", which plans again) instead of `layer_mismatch`, or `origin_not_public` when the probe
refused the address outright (private or none: checking again gives the same answer). A
WebSocket node's transport (§ Layers) is never L4-only: without an answer it has no layer yet,
stays the transport to protect, and every L4 account reads `l4_not_for_websocket`. For an **enrolled** node the plan reads the node from its intent
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
| A **WebSocket node**'s HTTP transport (an enrolled node whose mode is fronted by CDNs only, shape `{transport: 'ws', fronting: 'edge-l7'}`), whatever its certificate covers                  | never (`l4_not_for_websocket`)       | yes |

**WebSocket nodes take no load balancer** (`convex/lib/edges/websocketNode.ts`:
`websocketNodeOf(db, origin)`, `l4BarredFor(listener, websocketNode)`; the rule is
`listenerLayers(listener, {websocketNode})`). A WebSocket node's Caddy terminates TLS for its
origin name, the one name its public certificate covers. Behind a load balancer a member's TLS
would go straight to that Caddy, so the member would have to send the origin name as its server
name: a name in public certificate logs that resolves to the node, where one block of it takes
out every load-balancer address the node has. (An L4 pool member must also be an address, and a
WebSocket node's origin is a name.) So an L4 account or location is not offered and not accepted
for such a listener anywhere: the protect plan (the account and each of its locations read
`l4_not_for_websocket`, alone), `create` and its picks (`checkPicks` / `checkPickOptions` refuse
`edge.l4_not_for_websocket`), Protect again and adding a location (`startReprotect`, the set's
`change` and its `available` list), switching a run's pick (`retry`), a named account, location
or spare at a rotation start, automatic selection (no L4 account is eligible, no L4 spare is a
standby), and publication (`checkPublishable` answers `l4_not_for_websocket`). The set's view
says `websocketNode`, so the node page offers CDN accounts only. An L4 edge or pick such a node
already has (none is expected) is left as it is: never destroyed, never chosen for new work,
never published. A WebSocket node's backup at another provider is a second CDN.

`hostTargetFor(edge, proto, selectedSni)` is the single source of the Host tuple the backend
Host and the renderer share: L7 → `{ hostname, 443, sni: hostname, host: hostname }`; L4 HTTP
transport → `{ address, port, sni, host: sni }`; L4 `reality` / `tls` → `{ address, port, sni,
host: null }`; `none` security → `{ address, port, sni: null, host: null }`.

### L7 edges

An L7 edge is one hostname `<label>.<zone>` minted deterministically from the edge's
provider-side name (`convex/lib/edges/hostname.ts`). Everything a step, discovery, describe or
destroy needs is **frozen** into `edges.provisionIntent` when the edge is planned. Readiness
has three dimensions: `dns`, `certificate` and `front` (the end-to-end qualification below).

**Certificates.** A Cloudflare front's certificate is its zone's own: the edge certificate for
`*.<zone>` that every front of the zone shares (§ "Cloudflare fronts"). A Fastly front's
certificate comes one of two ways, frozen per edge from the account's `certificateScope` (an
intent default, § "Fastly fronts"):

- `wildcard` (the default for a new account): ONE subscription for `*.<zone>` per account and
  zone, ordered by the first edge that needs it and reused by every later one. A front's own
  name never reaches the Certificate Transparency logs (a per-name certificate publishes it
  there before any member uses it, so it can be listed and blocked), and only the first front
  waits for issuance: the wait step looks once and finishes when the certificate is issued.
  The subscription and its ACME record (`_acme-challenge.<zone>`, commented
  `fcp-cert:<customer>:<subscription>`) are recorded on each edge as `shared`, so no edge's
  destroy deletes them. Only an operator removes them, with the zone on the account page, and
  only a subscription an edge of this account ORDERED: the settle that records a shared
  resource the step created also keeps `<kind>:<id>` on the account
  (`orderedSharedResources`), and one discovery found and reused is FCP's to use, never to
  delete (`shared_certificate_not_ours`). The certificate and ACME steps hold the external lock
  `fastly-certificate:<account>:<zone>`, so two rotations never both order it, and the removal
  (`POST providers/{id}/locations/{loc}/shared-certificate/remove`, audited) takes the same lock
  as the account (`externalLocks.holderAccountId`) and recounts the zone's live fronts under it
  (`edge.shared_certificate_in_use` while one uses it, `edge.lock_busy` while a step holds the
  lock), so no rotation starts reusing the certificate between the count and the delete. The
  lock is released when the call ends; one a dead removal left is taken over by the next step
  once it lapses. An account still holding a wildcard it ordered, in any zone, cannot be
  deleted (`edge.shared_certificate_present`), nor can that zone's location (the only record of
  it), so nothing is left at the provider with no credentials to remove it.
  A subscription is reused only when it matches the account's certificate authority and its
  EFFECTIVE TLS configuration (the location's, else the default one, the same one the traffic
  CNAME points at); one ordered another way, or several, is never reused
  (`shared_certificate_ambiguous`). At the challenge name, a record with another customer's
  marker or none is never reused, replaced or deleted (`acme_name_in_use`); our own customer's
  marker for a subscription that no longer exists (a failed one deleted at the provider) is
  stale, and the step replaces it with the new subscription's; so is our own record that no
  longer holds the challenge's current value (edited by hand, or a target the provider moved).
  The subscription's state is kept on the zone's front location
  (`edgeLocations.sharedCertificate`, read by the location checks a credential test runs and by
  the reconcile cron, every pass while it is not issued, while it renews and within a week of
  expiry, every 30 minutes otherwise) and shown with that zone on the account page with its
  expiry and how many fronts use it. A renewal reports what holds it up like a first issuance
  does, and one that is late (the certificate expires within a week, or has:
  `certificate_expiring`) is raised by itself; Certainly's 30-day certificates renew with about
  ten days left, so a week means days overdue. A subscription serves only while it is issued or
  renewing AND its newest certificate's `not_after` is still ahead: one renewing past expiry is
  pending (`certificate_expiring`) to the wait step, discovery and describe alike, so no front
  is ready on an expired certificate. Attention `certificate_waiting` (one per zone) is critical
  once under three days remain. A failed one refuses new fronts in that zone
  (`shared_certificate_failed`), and so does one the account would not order
  (`shared_certificate_ambiguous`), before anything is built for the front; the account's other
  zones are not held back. An account switched back to one certificate per front still shows
  each wildcard it left behind, without raising it, until it is removed.
- `per_host` (an account created before, until it is switched): one subscription per front
  hostname, deleted with the edge.

**What discovery cannot prove is ours.** A resource discovery finds by name but cannot prove
belongs to the edge (a record at the edge's name with another marker, a subscription ordered
another way, a versionless domain on another service) is recorded as a candidate
(`meta.candidate`) so the operator sees it, and it is never planned for destroy or deleted,
also when the operator destroys the parked edge: deleting another account's ACME record would
let its certificate lapse. The operator removes such a resource at the provider by hand.

SNI and the zone still link the fronts of one account either way, so the zone choice matters
more than the certificate. A zone carries the wildcard of one Fastly account only (a second
one finds the first one's ACME record and stops at `acme_name_in_use`), and the challenge name
sits at the zone apex: a zone whose own certificate is validated there by another ACME client
should keep one certificate per front.

**CAA preflight.** The check of a Fastly front location (run by the credential test for every
location, by "Check again" and when a zone is added) resolves the CAA records of that location's
zone over public DNS, walking up the tree the way the certificate authority does
(RFC 8659: the first name with any CAA record decides; for the wildcard, `issuewild` when the
set has one, else `issue`; a critical property with an unknown tag forbids). One certificate per
front is checked from `_fcp-caa-check.<zone>`, a label nothing serves: a zone wildcard answers
for it as it will for a new front's name, and the resolver follows that answer's CNAME as the
CA does (a name with nothing of its own then climbs from its parent). Records that exist and do
not name the account's CA (`certainly.com` for Certainly, `letsencrypt.org` for Let's Encrypt,
`globalsign.com` for GlobalSign) fail the check with `caa_forbids_ca`, and so does a record that
names it with parameters the issuance cannot meet (RFC 8657): an `accounturi` (the provider's
ACME account is not FCP's to name) or a `validationmethods` list without `dns-01` (every
certificate FCP orders uses the managed DNS challenge). No record at all, or a lookup that
fails (`unchecked`), passes; so does a name too deep to walk to the top (more than
`MAX_CAA_WALK` labels, also `unchecked`, never "no records"). The verdict is kept with the
location's check (`edgeLocations.observed`: `caa`, `caaIssuer`, `caaCertificate`, `caaAt`; the
refusal as its `checkError`). The verdict answers for the account's default certificate: while a
zone's last check ended on it, the setup plan (the location's `certificateRefusal`, which keeps
the zone pickable), every pick check, the setup run's first stage, the start guards of a
rotation naming the location, the preflight and the selection refuse that zone with that code
for a front on that certificate, before anything is allocated (`certificateRefusalFor(account,
location, choices)`). A node that chose another certificate there is judged by its own
preflight instead (below, Certificates a node chooses), and only the zone's wildcard refuses it,
when it chose the wildcard. The account's other zones stay usable, and the refusal does not
count toward the account's API health. Fix the records or pick another
CA, then check the zone again. Changing the account's default certificate authority or
certificate scope (its option defaults, see Provider options) marks the account untested
(`retest_required`): a per-name verdict says nothing about `issuewild`. Each zone's
shared-certificate record stays (it proves a wildcard FCP ordered is still at the provider, for
its removal and the delete guards) until the next test reads it again. (The DNS account and the TLS configuration are a location's
placement, never edited: another one is another location, checked on its own.) The lookups are DNS
queries from the backend (`node:dns`, 4 s, two tries); the offline test suite refuses them like
`fetch`, and tests answer through `__setFastlyCaaLookup`.

**What a waiting certificate reports.** The wait step (`await_tls`) reads the subscription with
its authorizations on every look. Fastly's authorization warnings carry a type and free text
that names the records; the text is never read or kept, and the type is mapped by keyword to a
fixed code (`L7_CERTIFICATE_CODES`): a CAA problem is `tls_caa_conflict`, conflicting records at
the challenge name `tls_challenge_conflict`, a failed authorization `tls_authorization_failed`,
any other warning `tls_authorization_warning`, reported only once the wait passed five minutes
(`TLS_WARNING_GRACE_MS`). Fastly documents no vocabulary for the types. FCP also reads the
validation record itself: a zone without the managed-DNS challenge's CNAME, or with another
value there, is `tls_challenge_missing` (a DNS API that does not answer says nothing). The code
is kept on the edge while it lasts (`edges.waiting`), logged once per change on the rotation and
on the guided run waiting on it (its progress line names it), raised as attention
`certificate_waiting`, and a provision that times out while held up ends with that code instead
of `provision_timeout`. A zone's shared certificate is judged the same way and raised on its
location.

**Domains.** A Fastly edge planned now attaches its hostname as a versionless (Domain
Management) domain: its own resource, linked to the service by id, created and deleted without a
service version. The account setting `domainModel` (an intent default: `versionless` for a new
account, and for one that does not name it; `classic` allowed) decides it for new edges and is
frozen into each intent, so an operator whose provider refuses a versionless domain can switch
to classic without a code change (`EDGE_INTENT_FACTS`). An edge planned before keeps its
version-scoped (classic) domain, read, renewed and destroyed as before; the adapter reads which
one an edge has from its ledger (`versionless_domain` or `domain`). Discovery finds a versionless
domain by its exact name and owns it only when it is linked to the edge's own service; DNS
readiness is that link plus the traffic record as the zone holds it now, read back and still
pointing at the CNAME of the front's TLS configuration (no version holds the domain, so there
is no domain check to run); destroy deletes it by id after the certificate and before the
service, on a shared service too (no version workflow). Fastly offers classic domains only to
accounts created before 2025-09-16; its documentation names no service-type limit for
versionless ones (the domain page creates a CDN or a Compute service for one), and the WebSockets
product is enabled per service either way.

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
(the countries snapshotted on the rotation when the detector started it, § "Probes and the
block detector")
for the new front (`EDGE_PLUMBING.l7QualifyTimeoutMs`); the reconcile cron renews a proof a
quarter of its lifetime before it lapses (at most six re-proofs a pass); a failed renewal is
retried, and once the proof lapses the front leaves rendering until a proof succeeds. **Importing a front**
(`ImportFrontDialog`, `POST relays/{id}/adopt`) records an existing CDN front against a
listener and publishes it only with a current proof (`front_unqualified` otherwise).
`edge.l7.autoSelect` (default off) governs automatic selection of L7 accounts on an origin
without a provider set; manual provisioning, a guided setup run's chosen account, publishing
and a pick of the node's provider set (the operator chose it, § "Provider sets") work
regardless.

Each **DNS provider's** account (capability `role: 'dns'`, Cloudflare today) says what it is
for: **DNS only** (the default) or **DNS and fronting** (`edgeProviderAccounts.frontsTraffic`,
chosen in the account form and on the account page; `frontsAllowed` in
`providers/capabilities.ts` reads it, and an edge provider's account always fronts). A DNS-only
account only holds the records FCP writes for L7 fronts (a Fastly edge's certificate challenge
and traffic name, a front node's origin name) and is never a candidate, whoever chooses: the
setup plan does not offer it, a rotation naming it fails `dns_account_not_fronting`, automatic
selection skips it, and a provider-set pick of it is not usable (`setPicksOf`). Nor does a
spare of it go live: `checkPublishable` refuses it (`dns_account_not_fronting`) and standby
selection passes it over. Nor does attention ask to trust it (no `account_unqualified`: it
carries no traffic). Switching an account to DNS only leaves its published edges as they are.
The choice is deliberately separate from `l7.autoSelect`: letting automation pick L7 fronts
must not turn a DNS account into one (§ "Adding a DNS provider", § "Cloudflare fronts"). It
replaced the deployment-wide switch `edge.l7.dnsProvidersFront` (§ "Deploy notes").

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
listener") a published edge, and, on a node with a provider set, what that set requires
(§ "Provider sets"): the **coverage deficit** is how many addresses are still missing
(`setStateOf`, `convex/lib/edges/setState.ts`). Capacity follows it
(`convex/lib/edges/poolCapacity.ts`): `ensurePoolCapacity` raises `desiredPublished` to the
coverage-listener count (the admin create and the listener upsert answer `warnings:
['edge.pool_raised']` when it did) on every origin create, admin listener add and listener
re-enable, and the reconcile cron applies it each tick. A pool whose free slots cannot hold the
deficit is **expanded** within the cap (`desiredPublished = min(16, desired + deficit - free)`,
audited `edge.pool_expanded`); it is never shrunk. The pool cap is 16 (`MAX_DESIRED_PUBLISHED`)
and the listener cap 8 (`MAX_COVERAGE_LISTENERS`); both are enforced where the operator can act
on them rather than clamped silently: a listener body (the create or the CMS upsert) that would
leave more than eight deployed, enabled listeners is refused (`edge.listener_cap`; a
pre-existing excess is not made worse), and `relays.update` refuses lowering
`desiredPublished` below the coverage-listener count, or (with a set) below what is published
plus the deficit (`edge.pool_below_coverage`). The fleet default `desiredPublishedDefault`
stays within 1..8. **Reserved allocation** (`allocatePoolIndex`, `convex/lib/edges/pool.ts`,
used by the rotation's `applyPublish`, the cron's `publishStandby` and both direct publish
paths): an edge that lowers the deficit takes the lowest free index; any other edge only while
the free slots exceed the deficit (`edge.pool_reserved`, a `pool_reserved_standby` rotation
event), so a second copy for A never takes the slot B is waiting for. A shortfall only a cooling
pick could fill is not part of the deficit, so reserved slots never hold healthy work hostage.
At the cap no expansion is possible: attention raises `pool_rebalance` and the operator calls
`POST relays/{id}/rebalance`, which sends ONE **removable** edge back to standby, highest index
first: published, not its listener's template edge, and its removal does not increase the
deficit (`removableUnder`: rebalance exists to make room in a pool that is already short
somewhere, so it cannot ask for a zero deficit after removal). `edge.no_duplicate` when none is
removable. It bumps the epoch and lets upkeep publish what is missing. Never automatic:
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
   the FULL pool order, walking forward past ineligible positions; the backup is the next
   assignable edge away from the primary's failure domain (with `render.preferDistinctProviders`):
   another provider first, then another location (`PublishedEdge.locationKey`, admin-only and
   never rendered; a missing key counts as unknown), else the next one; one server name per emitted
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
`family_disabled` (the client's app family has its render rule off), `render_failed` (the
format's renderer could not rewrite the body for any other reason) or `node_unprotected` (a
freedom-family key at a place no binding covers, while freedom modes are only served through
edges: § "Freedom modes only through edges"). A 503 keeps the client's
last configuration; an empty 200 would wipe it. Each one is counted per reason (§ Operations
safety, attention `delivery_refusals`). The policy is judged AFTER the fetch against the node
the body actually belongs to, so a first fetch without a stored pin and a pin that moved onto an
origin node are both classified correctly. A place no origin covers and whose gate is open passes
the body through. Either way, the last step renames the entries the backend named after a node
(`docs/servers.md` § "A direct node's addresses"); a rendered edge entry keeps its label.

**The cache token** (`epochTokenFor`, `convex/edgeRender.ts`): on a bound place
`<binding policyVersion>[:g<gateToken>]:<publicationEpoch>` (the epoch is -1 when the origin is
missing or disabled or rendering is off); on an unbound place `g<gateToken>` when the node is
managed or its gate is closed (an unmanaged node under an open maintenance hold, so a body cached
before the hold is not served from the cache while it holds), then `:f` (or `f` alone) while
freedom modes are only served through edges; none of these, no token. `gateToken` is
`<gateVersion>:<committed Host count>:<committed edge count>:<hash of the candidate Hosts and
edges, or 0>` (`lib/backend/deliveryGate.ts`), so publishing or releasing a candidate re-keys
every cached body. The route reads the token before deciding and again after rendering,
re-renders once on a move, and answers `policy_moved` on a second move. Only bodies that passed
are cached. Creating an origin therefore takes members on that origin dark until an edge is
published and rendering is on; the setup flow says so.

### Freedom modes only through edges

One switch, `edge.freedom.edgesOnly` (Admin → Edges → Settings, the "Freedom modes only through
edges" card; `GET/POST /api/v1/admin/edges/freedom`). While it is on, a member on a
freedom-family connection mode is never handed a node's own address: the node their key resolves
to serves them only through a delivery binding (whose render hands out edges, never the origin),
and a node no binding covers is withheld from them the way the delivery gate withholds an
enrolled node that is not live (`lib/edges/freedomDelivery.ts`, `convex/freedomDelivery.ts`):

| Path                                                             | What a held key gets at a node no binding covers                                                                                                                                                                                                                                                                                                                        |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| the pinner (`backends.fetchSubscriptionContent`)                 | The pick is made among the nodes an origin with a live edge of the node's layer covers (`freedomDelivery.pinRules` `servable`; an enrolled node at its own mode's layer, any other at the key's) while one is in the body; gated nodes stay excluded and the previous pin is avoided within them. With none in the body the pick is as before and the next row refuses. |
| `/sub`, the raw-config view (`edgeRender.decideForSubscription`) | `node_unprotected` (503 with `Retry-After`; the app keeps its last configuration), counted with the other refusals. Also for a body that names no node.                                                                                                                                                                                                                 |
| a cached body                                                    | Never served: the place's token carries `f` while the switch is on, so an entry cached before it moved does not match.                                                                                                                                                                                                                                                  |
| a mirror                                                         | The unavailable stub (the mirror render reads the same decision); when the switch moves, one full pass renders every mirror again at once (`storage.drainMirrors`, continued until the last key), not the six-hourly sweep's window.                                                                                                                                    |
| the raw backend URL (account view, issue and switch answers)     | Blank, like an edge-required key's (`freedomDelivery.rawUrlWithheld`): the backend's own URL hands out the nodes' addresses.                                                                                                                                                                                                                                            |

A covered place is unchanged: the binding's render hands out edges or refuses, as always. A
front of another layer cannot carry the mode's transport, so the render never hands one out;
the layer is judged for the pick and the attention items. Issuance hands out no address (a new
key's node is chosen at its first fetch, by the pinner), so placement is unchanged.

**Which keys are held.** What a key is handed is decided by its placement (the group the backend
serves it, so the nodes in its body) and the node it resolves to, and either signal is enough: a
mode whose pool holds its placement is freedom-family, or the enrolled node it resolves to serves
a freedom mode. This fails closed toward the rule, the opposite of the country handling's
`memberFamilyOf`. The member's stored (or default) mode is not a signal: a member who never
chose, on a privacy group, would otherwise be cut off by a freedom default, and a key with no
placement has no node to hand out. A key on a backend without connection modes (Outline) is
never held.

**Why a node is withheld** (`FREEDOM_WITHHELD_REASONS`, the attention code):
`withheld_unmanaged` (FCP does not enroll it and no binding covers it), `withheld_unprotected`
(enrolled, no binding), `withheld_no_edge` (a binding covers it, but its origin hands out no live
edge of the mode's layer: `edge-l4` needs an L4 edge, `edge-l7` an L7 front, a mode whose
shape is unknown any live edge), `withheld_direct_mode` (the node's mode is in the freedom family
but its backend sets it up `direct`). While the switch is on, attention lists every withheld node
of a freedom mode's pool (`freedom_node_withheld`, a warning that also alerts: facts name the
backend, the node and the mode, never an address), with the action that fixes the reason:
protect the node, open its origin, or open Connection modes.

A freedom mode's pool on a backend is what FCP knows of it, group by group: the enrolled nodes
serving the mode whose gate is open (in the group the setup made for the mode), the observed
nodes serving a transport of the group, and the nodes active keys of the group are pinned to,
under any name the node had before a rename (one indexed read per pinned name and group, at most
200 pinned names per backend). A key's body carries the nodes of its own group only, so a group is
judged on its own: its keys move to a covered node when one serves the group, and get nothing
when none does, whatever another group of the same mode has. A group with keys and no known node
counts as one with no covered node.

**Saving a freedom mode direct is refused** while the switch is on: a backend setup (or a change
of it) that gives a freedom-family mode the shape `direct` (`servers.freedom_mode_direct:<slug>`;
a mode the backend already carries direct is kept, since its shape cannot change, and its nodes
are withheld), and in Connection modes, turning a freedom mode on, moving a mode into the freedom
family, creating one there, or turning the freedom family on while one of its modes is set up
direct somewhere (409 with the reason). Copy edits and turning a mode off stay allowed.

**The default.** `seedCutover` stores the switch ONCE: on for a deployment with no members (a
fresh one), off for a deployment that already has members (one with no edges serves its freedom
members directly today, and turning it on would cut them off). A stored value is never touched
again. Until the seed has run the switch reads off. It is in neither `SETTINGS_DEFAULTS` nor
`EDGE_KEYS`, so no generic settings write reaches it: only `POST freedom`.

**Turning it on.** The card first shows a read-only preview (`GET freedom/preview`, an action
that pages the member counts, never one transaction over every key): per freedom mode and
backend, its nodes (covered, withheld and why) and its members (on a withheld node; moved to a
covered node of their group at their next refresh; cut off, when no covered node serves their
group); the totals count each key once, however many modes share its group. Turning it
on while any member would stop being handed their node needs `confirm: true` (the dialog sends
it); without it `edge.freedom_confirm_required`, judged again in the mutation by indexed
existence reads. Audited as `edge.freedom.edges_only` (`on`, `confirmed`, `withheldNodes`,
`affected`). Turning it off needs no confirm.

### Asking whether a configuration changed

A member benefits from a rotation only once their app fetches its subscription again, so the
route makes that question cheap (`convex/lib/subscriptionEtag.ts`):

- **The validator.** Every answer carries a weak `ETag`, `W/"fs1-<22 characters>"`: SHA-256
  over the exact bytes served plus what an app applies with them (content type,
  `profile-title`, `profile-update-interval`), cut to 128 bits. `subscription-userinfo` is
  left out: its traffic numbers move on nearly every fetch and would make every poll a 200.
  The tag names the content, not one encoding of it, so a compressing proxy leaves it alone.
- **The 304.** A request whose `If-None-Match` names the tag (RFC 9110 weak comparison: `W/`
  ignored, the quoted tags identical; a list or `*` works; a value that does not parse is
  ignored) gets `304 Not Modified` with no body and the headers the 200 would carry (`ETag`,
  `Cache-Control`, `Vary`, `subscription-userinfo`, `profile-title`,
  `profile-update-interval`). The 304 is decided last, after the pin, the render, the
  refusals, the cache write and the delivery stamp, so it only saves bytes. A refusal (503
  under edge-required delivery, 404, 429, 502, a rejected device) never carries a tag.
- **Revalidation without the backend.** A conditional request whose body is still cached for
  the same User-Agent, the same stored country and the CURRENT cache token, and is at most
  10 minutes old (`SUBSCRIPTION_REVALIDATE_MS`), is answered from that entry with no backend
  fetch and no render. Every rotation, binding or gate change moves the token, so this never
  hides one; only changes outside the token (the backend's own body, the traffic numbers) wait
  at most that long, and a 304 means "keep what you have", which is also what a client does on
  a 503. Unconditional requests keep the 30-second cache. A device-specific (HWID) request and
  a body shaped by an inferred country are never cached, so they always take the full path;
  their 304 only saves bytes.
- **A front's proof bounds every copy.** A rendered body records `validUntil`, the earliest
  proof expiry among the L7 fronts it hands out (null when it holds none). No cached copy is
  served past it (not as a fresh hit, not on revalidation, not as the stale fallback), and a
  proof that lapses while a body is being rendered makes the route render again without that
  front (a lapse after that answers `policy_moved`). The freshness a shared cache is told is
  capped the same way, computed when the response is built: `public, max-age=<seconds left,
at most 30>, must-revalidate` for a body holding fronts, `public, max-age=30` otherwise; a 304
  repeats it, so it never extends a cache's freshness past the proof either.
- **Cache format.** Entries carry `v: 2` and `validUntil`. An entry written before that has no
  expiry metadata and is never served; it is overwritten as members fetch (no migration).

What an app does with it: send `If-None-Match` with the tag it holds; on 304 keep what it has;
on 503 keep what it has and honour `Retry-After`; on 200 apply the new body. The per-token
throttle (`subscription.fetch.token`, 60 a minute) is the polling ceiling.

**The refresh hint.** An edge-rendered body carries FCP's own `profile-update-interval`,
`edge.updateIntervalHours` (whole hours, default 1, 1..24), instead of the backend's own value:
apps that honour it fetch again this often. Bodies FCP does not render
(a direct node, an Outline key) keep the backend's value. Which apps honour it is recorded in
`docs/client-compatibility.md` "Refresh behaviour".

### How fast members move

From the moment a rotation finishes, with the defaults (drain of a replaced edge 24 h, of a
burned edge 2 h, refresh hint 1 h):

| App refreshes                                | Routine rotation                                 | Burn (blocked)                                                                | Members inside the blocking country                                                                                                                                                          |
| -------------------------------------------- | ------------------------------------------------ | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| About every minute (an app that revalidates) | moves within a poll; the drain is not needed     | the same                                                                      | rely on their backup entry until the next poll                                                                                                                                               |
| Hourly (honours the hint)                    | within an hour, far inside the drain             | within about an hour, inside the 2 h drain                                    | an app with an automatic group can fail over to the backup when its health check notices (each app's interval differs); a link-list app needs a refresh or a manual pick of the backup entry |
| Never                                        | keeps the old address 24 h, then only the backup | keeps a dead address (it still works elsewhere for 2 h), then only the backup | backup only; a later rotation of the backup leaves them without a working entry until they refresh by hand                                                                                   |

On top of that come detection (the detector runs every 5 minutes over a 30-minute report
window; probes every 15 minutes, fresh for two intervals) and the rotation itself (an L4 replace
onto a tested spare takes seconds; an L7 replace adds provisioning and up to 15 minutes waiting
for affected-country evidence). The safety net for apps that never refresh is the backup entry
on a different provider (`render.preferDistinctProviders`, `lib/edges/assignment.ts`); it only
exists while the pool has published edges on two providers. With one provider the backup is
another address on the same provider.

The burned drain is twice the hint so an hourly app outside the blocking country never races
the destroy. Saving a drain under two refresh intervals (`edge.drain_below_refresh`), a burned
drain under one interval plus 30 minutes (`edge.burned_drain_below_refresh`), or an origin's own
drain under two intervals answers with a warning (never a refusal); the settings page and the
origin dialog show the same note while typing (`drainWarningCodes`,
`src/shared/contracts/edgeCodes.ts`).

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

**The raw-config view follows the same decision.** The member page's sealed copy of the
configuration (`GET /api/v1/subscription/content`) decides, renders, leak-checks and relabels
through the same helper as the subscription route (`lib/subscriptionDelivery.ts`
`deliverBody`, with `locateMember` for the member's country): a gated node or an edge-required
key is answered `503` `delivery.unavailable` with the same reason (counted in the same refusal
counter), never the panel body. It fetches with no client User-Agent (the panel's default link
format; a browser's could fetch the panel's HTML page), so it equals what `/sub` serves an empty
one; it is neither cached nor stamped as a delivery. The app's config endpoint will use the same
helper.

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

| Route                                                               | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET setup-status?relay=<slug>` / `POST setup-status {draft}`       | **Origin-scoped** readiness: nine steps (`origin`, `account`, `template`, `relay`, `edge`, `qualification`, `publish`, `rendering`, `automation`), each `done / ready / blocked / skipped` with blockers and warnings as codes, the selected context and `currentStep` (never a token or an address). A draft (origin + listener triples) is judged before the origin exists. Without either, the fleet aggregate plus the origins whose setup can be resumed. Manual origins skip `rendering`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `POST relays/{id}/test-provision`                                   | The bootstrap path: ordinary selection excludes unqualified accounts, so a fresh account could never get its first edge. Explicit `{accountId, templateId?, listenerKey}`; the account must be enabled and **tested** but may be unqualified; budgets, capacity and layer compatibility apply; the result is always unpublished. Audited `admin.edge.test_provision`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `POST relays/{id}/preflight`                                        | Dry run of `provision / publish / replace / test-provision`: every guard a real start applies (the FIRST blocker is the code the start would throw), the selection the machine would make, plan-phase refusals that need no adapter, and delivery warnings (`render_disabled`, `members_dark`, ...). Writes nothing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `GET edges/{id}/verification-binding` + `POST edges/{id}/verify`    | The L4 endpoint test. The GET returns `{endpoint, listenerKey, listenerRevision, configHash}` (plus whether the gate would pass once confirmed) exactly as the confirmation must echo it; the POST (origin-write scope) recomputes the binding from the live rows and refuses a mismatch (`edge.verification_stale`) rather than stamping a configuration the operator did not see. Records `edges.verification` (`method: test_link` from the isolated test link, `named_connection` for retesting a published address by its `<node>-relay-<key>` connection) and audits `edge.verified` (ids and the listener key only). L7 edges refuse: their authenticated proof is the verification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `GET attention`                                                     | Server-ranked list, one action per item: quarantine, needs operator, unsettled Host op, **members dark** (edge-required place with nothing to serve), failed or rolled-back rotation, lapsed front qualification, block suspected, unreachable edge, pool below desired, pool rebalance, account untested or unqualified, account with no daily limit, test key cleanup, direct Host reappeared, go-live pending, restore in progress, maintenance frozen; the operations-safety items (§ Operations safety: fleet brake and cap, stuck rotation, provider API failing, health stale, billable idle, delivery refusals, an app family switched off, a node ready to protect or waiting for approval); the checks from each country (§ Checks from each country: a failing probe source, a country where the country-wide guard holds blocks, a new address blocked somewhere); plus the three endpoint-verification cards: **needs_test** (critical: the origin is suspected and its automatic replacement has no tested spare), **retest_needed** (a confirmation went stale after a listener or address change) and **spare_untested** (an active unpublished L4 edge never confirmed), each with the one action `verify_endpoint`. |
| `GET relays/{id}/quarantine` + `POST .../quarantine/inspect`        | The resolver view: per listener the previous and the current binding as Host tuples; `inspect` (throttled) fills the live column from the backend and says which one it matches. `resolve-quarantine` records a `reason`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `GET relays/{id}/timeline`                                          | Merged audit rows of the origin, its listeners, its non-destroyed edges and its rotations, newest first, capped.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `GET providers/usage`                                               | Per account: live / max edges, allocations against the daily budget, published / standby / draining; per origin desired against published; totals including what auto-provision would add.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `GET relays/lookup?slug=`                                           | The full admin view of one origin by slug (the per-origin page is addressed by slug).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `POST relays/{id}/listeners/{key}/adopt-host`                       | The `operator` to `fcp` handoff: the named Host must exist, carry the listener's transport and dial a published edge of that listener (`edge.host_adopt_mismatch` otherwise). `hostMode: fcp` is refused until every listener Host is adopted (`edge.host_adopt_required`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `GET freedom`, `GET freedom/preview`, `POST freedom {on, confirm?}` | Freedom modes only through edges (§ "Freedom modes only through edges"): the switch and when it last changed, the read-only preview of what it closes, and the switch itself (settings scope; `edge.freedom_confirm_required` while members would be affected and `confirm` is not set).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `GET maintenance`, `POST maintenance/freeze`, `.../thaw`            | The maintenance switch (see below).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `GET delivery-bindings`, `POST delivery-bindings/{id}/release`      | The edge-required places, including ones whose origin was deleted with `keep-dark`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `GET config`                                                        | Also carries `bounds` and `defaults` per flat key, so the settings forms validate against the server's own limits.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `POST relays/{id}/rebalance`                                        | Coverage at the cap: unpublish ONE removable edge (not its listener's template edge, its removal does not increase the coverage deficit; highest pool index first) back to standby, bump the epoch, refresh mirrors; upkeep then publishes what is missing. Refuses `edge.no_duplicate`, and the usual rotation / quarantine guard. Audited `edge.relay.rebalanced`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `POST automation {on}`                                              | The one automation switch (settings scope): in ONE mutation sets `edge.enabled`, `edge.autoRotate`, `edge.probe.enabled` and `edge.autoProvisionToDesired` to `on`, and `edge.standbyPerListener = 1` when turning on (left as-is when off). Never `render.enabled` or `l7.autoSelect`; touches no origin row (an origin's own `autoRotate` keeps its meaning under the global gate: `cfg.enabled && cfg.autoRotate && relay.autoRotate`). Audited `edge.automation.set` (the boolean only).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `POST setup-runs/plan {backendServerId, nodeUuid}`                  | The guided setup's read-only plan for one backend node (`listenerKeys?` as on create; throttled: it lists the node's transports and Hosts): frontable transports, direct Hosts tagged covered / uncovered, compatible accounts with reasons, the fleet-wide rendering consequence, disabled client families, and the `planHash` a run creation must echo. See § "Guided setup runs".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `POST setup-runs`, `GET setup-runs[/{id}]`                          | Create a run (`{backendServerId, nodeUuid, accountId, planHash, approvedHideUuids[], keepDirect?, listenerKeys?}`: `listenerKeys` is the operator's choice of 1 to 8 frontable transports when the node has more, covered by the plan hash; `edge.plan_stale`, `edge.account_incompatible`, `edge.too_many_inbounds`, `edge.setup_run_active`), list runs, poll one (stage, state, the interruption, per-listener verdicts, the `try_it` test links).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `POST setup-runs/{id}/{cancel\|retry\|continue}`                    | The three operator verbs on a run: cancel (before publish deletes the origin `restore-direct`; between publish and go-live, a run parked at `go_live` included, starts the restore workflow with purpose `cancel_setup`; a re-protect run instead drops only its own candidates, disposition `candidates`; after go-live refused), retry (re-enters the current stage under a new generation; `{tryAnotherAddress, edgeId?}` at `try_it` replaces only that line, refused as `edge.replacement_cannot_start` with nothing cancelled when no replacement could start, `{checkAgain}` checks the same unreachable address afresh, `{acceptPartial}`, `{accountId}` answer the card's secondary buttons), continue (`{confirmations[]}` forwards each `try_it` tick to `POST edges/{id}/verify`; `{approvedHideUuids[]}` replaces the consent after `review_changed`; `{keepDirect}` finishes unbound).                                                                                                                                                                                                                                                                                                                                  |
| `POST relays/{id}/require-edges`                                    | Starts a guided run for a deferred origin (it never binds by itself): the SAME activation policy. Every published L4 edge without a current confirmation comes back as `pending[]` (the node page renders the `try_it` card) instead of a binding; with nothing pending the run starts at the rehearsal and goes live through stage 8. Refuses `edge.not_deferred`, `edge.coverage_incomplete`, `edge.setup_run_active`, `edge.busy`, `edge.quarantined`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `POST relays/{id}/serve-direct`                                     | "Serve this node directly again": the restore workflow with purpose `release_requirement` (binding released before any direct Host is re-enabled; edges and listeners kept). Refuses `edge.quarantined`, `edge.setup_owned`, `edge.restore_in_progress` and `edge.not_edge_required`. See § "Operations safety".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `POST relays/{id}/reprotect`                                        | "Protect again" for a live, bound, enrolled node: a re-protect run (`kind: 'reprotect'`, `mode` `replace_all` or `add`) that keeps the committed delivery until go-live and drops only its candidates on cancel. Refuses `edge.reprotect_not_bound`, `edge.reprotect_not_enrolled`, `edge.reprotect_no_room` and the usual run refusals. See § "Guided setup runs".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `GET relays/{id}/providers`                                         | The node's provider set (§ "Provider sets"): each pick with its addresses in use and spare, whether it cools and until when, the locations outside the set that hold one of its addresses (`outside`), the transports with no backup at another provider, the deficit, the locations that could be added, and the regions a load balancer account reaches that are no location yet (`regions`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `POST relays/{id}/providers {add?, remove?}`                        | Edit the set: adding a location to a live enrolled node starts an `add` re-protect run (the response names it); elsewhere the set is saved. Removing one drains its addresses, refused (`edge.set_would_uncover`) unless the tested survivors elsewhere still serve every transport and meet the remaining requirement. Refused under a setup run, a rotation, quarantine, a restore or the freeze; at most 6 picks (`edge.set_too_large`). Audited `edge.relay.providers_changed`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `POST edges/{id}/test-link`                                         | The isolated test link for an L4 candidate (throttled: fetches the test credential's body and the backend Hosts): the candidate connection only, plus the binding the confirmation must echo. See § "Publication".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `GET relays/inbound-candidates?backendServerId=&nodeUuid=`          | Discovery with the origin probe applied (throttled): the node's transports as listener candidates, `originTransport` filled where probed, `unsupported` with reasons. Registers nothing. See § "Listener catalogue".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

### Guided setup runs (Autopilot)

`convex/edgeSetupRuns.ts` (table `edgeSetupRuns`) + `convex/edgeSetupPlan.ts`. An operator
protects a backend node by answering two questions (which node, which locations its addresses come from), confirming each
new L4 address once from a real client, and pressing Go live; FCP does everything else. ONE
authoritative stage machine, every stage idempotent and re-enterable:

| #   | Stage               | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Members download    |
| --- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| 1   | `prepare`           | registration admitted; every pick's account tested, enabled and offered by the plan; `relays.create` with every frontable listener (or the operator's `listenerKeys` choice when the node has more than 8), `deferBinding` + `setupOwned`, `autoRotate: true`, `desiredPublished = max(default, required, targets)` (bound 16). An origin a previous run left owned is reused at its recorded `setupStage` only while its listeners still match what the new plan discovered (same keys, same canonical hash, no extra deployed listener); otherwise `edge.plan_changed` and the operator removes protection first. Replacing a pick (`retry {replacePick: {from, to}}`; a one-pick run also takes `{accountId?, locationId?}`) is allowed only before that pick's addresses are published (`edge.pick_switch_late`, `edge.account_switch_late` for a one-pick run); candidates of the old pick are cancelled, never re-labelled. | raw origin body     |
| 2   | `credential`        | `relayQualification.ensure` for an L7 listener (`qualification`) or an EMPTY backend node (`rehearsal`); an empty Outline server is `use_manual_setup`; a placement problem is `choose_mode`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | unchanged           |
| 3   | `provision`         | per target (a listener and a pick) without a live candidate: ONE mutation starts `provision` (`publishOnDone: false`, `requestedLocationId`, `allowUnqualified`) AND records `expect`; a live edge of the listener in that location, not used by another target, is reused. `edge.busy` / `edge.concurrency` wait and poll; `edge.maintenance` asks the operator                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | unchanged           |
| 4   | `verify`            | per standby: outside probes (`trigger: 'qualification'`) + the internal shape run, judged by `partialRungFor` (`partial` is the L4 ceiling); L7 runs the front proof. `unreachable` gets one re-apply and a fresh check first (below); then it (or a timeout) asks the operator (`address_unreachable`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | unchanged           |
| 4b  | `try_it`            | one isolated **test link** per L4 endpoint lacking a current confirmation (`edgeTestLinks.build`; a published address gets a named-connection retest instead); the card's ticks echo `{edgeId, endpoint, listenerRevision, configHash}` into `edgeVerification.confirm` (`edge.verification_stale` rebuilds the card). Skipped when every listener is L7                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | unchanged           |
| 5   | `publish`           | per required listener: the node's approval is checked in the same mutation as the start (an enrolled node without one PARKS: `needs_you` `node_not_approved`, nothing published, docs/servers.md "A fronted node's activation"); then a `publish` rotation (`admission: 'setup.complete'`, so a freeze declared meanwhile does not strand admitted work) through the UNCHANGED gate; `pool_full_standby` = `coverage_incomplete`; quarantine = `quarantined`. `keepDirect` finishes `done_unbound` here (never for an enrolled fronted node)                                                                                                                                                                                                                                                                                                                                                                                      | direct AND FCP Host |
| 6   | `hide_direct_hosts` | every L4 confirmation re-checked (stale = back to the card); `edgeHostHides.hide` with the EXACT approved uuids; an uncovered Host the consent did not name = `review_changed` (a new consent bumps `planRevision`); `hide_failed`; pending rows are polled                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | FCP Hosts only      |
| 7   | `rehearse`          | every client family's render rule on (`family_disabled`); `edgeRehearsal.run` (fresh cohort bodies through the real renderer, listing before and after; an enrolled node renders exactly its activation's candidates); expired proofs re-run and the rehearsal repeats (bounded); the version vector (with the activation candidate) + the FINAL Host observation are persisted                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | unchanged           |
| 8   | `go_live`           | ONE mutation: no active rotation, no quarantine, origin enabled; the local vector equals the rehearsal's; the observation younger than 60 s; every L7 proof `expiresAt` ahead; every hide row settled and none outstanding; no FCP Host op claimed; every required listener's edge published (in the pool, on a listener whose FCP Host exists), L4 with a current confirmation; `render.enabled` turned on if off (`edge.render.enabled_by_setup`); an enrolled node's candidate promoted in the same mutation (a live node with no activation binds only when every edge fits its committed approval); then `claimDeliveryBinding` and `setupOwned` cleared. A failed check sends the run BACK (7, 6 or the card); a stale candidate blocks the activation and waits for a fresh approval                                                                                                                                       | rendered body       |

**An address the outside check finds unreachable** (stage 4). Before the run asks, an L4
address gets ONE retry where its adapter offers `reapply` (Scaleway today): its configuration
is saved again at the provider, unchanged (`edgeProviderOps.reapply`; the run event
`reapplied`), because a provider can accept a change and never apply it (§ "Scaleway
settling"). The entry remembers it (`reappliedEdgeId`), so a new address gets its own once and
the same one never twice. Then the check starts afresh: `recheckSince` makes `rungFor` count
only evidence from the new request on (rollup rows updated since, internal runs requested
since), and the fresh round is requested only once every earlier probe run of the address has
landed (`probesInFlight`), so a late verdict of the first round never counts as fresh. Busy
(`lb_busy`) or an unknown outcome still earns the fresh check; nothing to save
(`not_offered`, `no_frontend`) or a load balancer that will not apply anything
(`lb_unusable`) asks at once. The card (`address_unreachable`) offers **Check again**
(`retry {checkAgain}`: the same fresh check, no new address bought; the run carries on if it
now passes), **Try another address** and, quietly, **Go live anyway**; `blocked_in` offers
Check again as its quiet third choice. `checkAgain` answers only those two cards
(`validation` otherwise). There is no such action on a live edge: the retry belongs to the
moment right after creation, where the run already holds the address and its evidence.

**"Doesn't work" asks first, and keeps what it cannot replace.** On the test card (the run
sheet, and a go-live check's card with a run) "Doesn't work" opens a confirmation that names the
address and its transport and says it is removed at the provider and replaced (`replaceWords`;
"Remove and replace" / "Keep it"); a page whose own path replaces the address (a spare's renew, a
published address's burn) keeps its own dialog instead. The `retry` that follows (and "Try
another address" on `address_unreachable` / `blocked_in`) cancels the old address and, in the
SAME transaction, asks whether the replacement could start now (`assertReplacementCanStart`):
the rotation's own start guards (maintenance, a quarantine, a restore) and its selection for the
entry's pick (the account's daily budget, its live cap, where a cancelled address still counts
until it is destroyed, the location's cap, an account switched off or untested). A refusal throws
`edge.replacement_cannot_start` with the reason, the whole retry rolls back, and the address
stays on the card as it was. A wait the stage rides out (another rotation, the concurrency cap)
is no refusal, and nothing is checked when a protect run would reuse a live address of the same
pick instead. A replacement that starts and then fails at the provider still costs the old
address.

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
stay and `edgeRestore.start` runs with purpose `cancel_setup`, unless the origin never reached
members (`edgeSetupRuns.originEverServed`: no edge ever published, no hide row, no binding
naming it), which is deleted like an earlier cancel so the node is free to protect again;
after go-live there is no cancel. An origin a failed or cancelled run left owned (no run live
on it) is a **leftover**: the protect sheet offers its node again (`nodeCandidates.leftover`,
"Half set up") and the new run resumes it (`plan.existingRelay`) at its recorded stage, at
publish at the latest: the new run's listeners hold no edge until publish (through provision)
takes the origin's own back, so a later stage would wait on addresses it never attached; the
node page offers
**Continue setup** when nothing of it is in use. The node's newest run, when it failed, is
named by the origin status (`failedRunId`, "Open the run" on the node page; the Edges home row
opens its sheet) and by attention `setup_run_failed` (warning; info for a re-protect, whose
members keep what they had; action `open_run`). The sheet's clock counts from the current
attempt (`attemptStartedAt`, set by a retry).
A **re-protect** run (`kind: 'reprotect'`, `POST relays/{id}/reprotect`, "Protect again" on the
node page) is its own kind for a LIVE node: an enrolled node whose members are already served
through this origin (refused otherwise: `edge.reprotect_not_bound` for an origin not bound yet,
`edge.reprotect_not_enrolled` for a node the role did not enroll; plus the usual
`edge.setup_run_active`, `edge.busy`, `edge.maintenance`, quarantine, restore and a disabled
origin). Its plan is read from the origin's own rows like `require-edges`: the listeners members
are served through (deployed, enabled, with a published template edge; none is
`edge.coverage_incomplete`) and its picks, the node's provider set (else the locations its
served edges come from; a missing, disabled or untested one is `edge.account_incompatible`).
Two modes (`POST relays/{id}/reprotect {mode?}`): `replace_all` (the default) provisions fresh
targets over the whole requirement and the old addresses drain at go-live; `add` (a set edit
that adds a location, § "Provider sets") provisions only what the larger set lacks given what
is published, retires nothing, and the set becomes the union at go-live. Each new address is
published beside what members hold, so the run first makes room: `desiredPublished` is widened
to the published addresses plus one per target plus the slots the deficit reserves; the run's
own targets are TEMPORARY room above the cap (beyond it `edge.reprotect_no_room`, which a
supported set never reaches); the size it found is kept in the plan snapshot
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
  formats note), where from (each account's locations as checkboxes, an account carrying
  only some transports says which, an incompatible one greyed with the reason; each change
  plans again with the picks and the summary says the addresses per location, a transport no
  pick carries and the transports with no backup at another provider; one usable location is
  picked for you; "Add a location" renders `LocationPicker` and picks the new one; "Add
  account" renders `ProviderAccountStepper` in its `compact` mode; each location shows its
  grade from every checked country, "IR: works" / "blocked" / "some addresses blocked" / "not
  checked yet", with the age and any mark in its tooltip), review
  (one sentence; the uncovered-hosts statement with the button "Protect and hide N unsupported
  hosts", consent = the exact uuids; the fleet-wide rendering sentence; the quiet alternative
  "Keep those members on the direct address" = `keepDirect`). Progress: four plain stages
  (Creating the address / Checking from outside / Checking it works / Going live, folded from
  the machine's ten by `plainStage`), elapsed, one live line, "You can close this. It keeps
  going.", polled every 3 s. An interruption is one card: the `SETUP_RUN_NEED_COPY` sentence
  and its one button (at most one secondary, `needButtons` in `simple/runWords.ts`); `try_it`
  renders the test card whose ticks echo `{edgeId, endpoint, listenerRevision, configHash}`;
  `review_changed` re-opens the review with the delta; `family_disabled` turns the family's
  render rule on through the config PATCH, then continues. With the checks from each country
  on, each new address shows a chip per checked country ("IR: checking", then what its first
  round found), the checks read every 4 s while the run is live.
- **A node's edges** (`NodeEdgesPanel`, no tabs), part of the node's ONE page: a backend node's
  Servers node page embeds it (docs/servers.md "The page") and `/admin/edges/nodes/<slug>`
  redirects there (`nodeHomeOf`, keeping `?test=`); an origin that is not a backend node (manual,
  a whole Outline server) keeps it at that address. The status sentence, "Addresses in use" per
  transport (a reduced pool strip + one plain line per address; a retiring address says
  when it is deleted, from `drainUntil` and the 5-minute reconcile, and offers **Delete now**
  (`DELETE edges/{id}`: the drain ends early, audited `edge.delete` with `drainEndedEarly`;
  members who have not refreshed lose it) and **Keep as a spare** (the operator `reactivate`;
  never for a burned one), both only while no rotation, restore or pause holds the origin;
  each address in use or spare says what it counts as from every checked country, works /
  blocked since / down / not checked yet, why, and whether that comes from its own checks, its
  location or a mark, with a **Countries** menu: **Mark for a country** and **Check from every
  country now**),
  the primary **Replace address** (`ReplaceDialog`, which states the drain: the origin's
  `drainMinutes`, or `edge.burnedDrainMinutes` for "Replace now, address is blocked" under
  More), the per-node
  "Replace addresses automatically" switch (origin `autoRotate`, captioned when the global
  switch is off), "Where its addresses come from" (`NodeProvidersCard`: each pick with its
  addresses in use and spare, cooling, untrusted; a location outside the set that holds one of
  its addresses; what members miss; Add a location, with the regions an account reaches, and
  Remove, § "Provider sets"; Replace and Add a spare take a "Where" choice), "Recent activity" (the
  timeline through `plainAuditActionLabel`), and More: add
  a spare address, **Protect again** (an enrolled node live behind edges: a re-protect run, see
  "Guided setup runs"; the primary action while the node waits to be protected again), Origin
  details, remove protection (`restore-direct`; the restore workflow's phase is shown while it
  runs). `?test=<edgeId>` opens the test card.
- **Providers** (`/admin/edges/providers`): cards (Connected / Problem / Not tested, "3 of 6
  addresses used" from `providers/usage`, and the trust line: "Trusted automatically, checked
  with a real session on <date>" / "Tried with a real session by you on <date>" / "Reached from
  outside. Not yet tried with a real session"); a card opens the account page, whose
  **Locations** card lists each location with its trust, addresses and cost note (Add location,
  Switch off, Make default, Remove, and the per-location **Trust override**), and its
  **Countries** card grades each location from each checked country (Works, Blocked, Some
  addresses blocked, Not checked yet, with the age), with the location marks (**Mark for a
  country**: Works there, Blocked there, Use the checks) and a conflict line where a mark
  disagrees with the checks; the inventory tab reads one location at a time.
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
redirects; a **Sources** panel says whether each source brings back evidence, a failing one
with its last failure in words; a target's run history is grouped by round, control vantages
labelled "control", and for an edge each round's finding per country) and **Settings** (Basics, Advanced sections, maintenance, delivery places). Codes
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

**Provider health is not reachability.** An edge's `health` is the PROVIDER's own check of
the node behind it (`describe`: a load balancer's backend health check), never whether members
can reach the address: a load balancer can reset every connection while its backend check
passes. The CMS words it as whose check it is ("Provider check passing", "failing",
"partly failing", "No provider check"; `EDGE_HEALTH_LABELS`) and shows reachability from
outside apart, from the probe summary (`outsideReachOf` over `reachability.byCountry`, FCP's
own vantage included: "Reachable from outside", "Unreachable from outside", "Reachable from
some places", "Not checked from outside"): the edge drawer and the origin's edge table as a
second badge, the node page's address line as words.

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
`edgeRestore.step` advances one phase, and each `edge-reconcile` tick chains steps until a phase
must wait: a running rotation, hides still settling, a raw body not there yet, the panel
unreachable) is the only way a guided origin stops
depending on its edges, with an explicit purpose: `cancel_setup` (a run cancelled after
publication), `release_requirement` (edge-required delivery switched off, everything kept:
"Serve this node directly again", `POST relays/{id}/serve-direct`) or
`delete_relay` (a `restore-direct` deletion). Phases: (1) `freeze`: no new disable writes; waits
for a running rotation; an origin never bound that never hid a Host has nothing to restore and
goes straight to (7); (2) `settle`: every outstanding hide row confirmed or released by
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
`delete_relay` runs the deletion body only now (drain, destroy, remove; an edge that was never
published served no member and is not drained). An origin with a restore
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
  answers. A step the provider REFUSED (`StepOutcome` partial with `refused`: what FCP built
  does not compile, Fastly's `version_invalid`) is never retried, since the same draft is
  refused the same way: the run fails on that code at once, the edge (not only the step) needs
  an operator, so its `needs_operator` attention stays raised while its billed resources
  exist, and what was built stays so the operator can read the provider's reason at the
  provider (FCP keeps only the code).
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
advances each restore workflow until a phase must wait; removes expired or released temporary
test keys (`edgeTestCredentials.sweep`, bounded retries, then attention `test_key_cleanup`);
turns drained / failed / cancelled edges into destroy runs and starts their walk in the same
pass: in the provider's kind order, the next resource as soon as the last is confirmed gone (an
async-delete provider's delete is read back at once), stopping at the first still going away,
at most `maxDestroyStepsPerPass` (12) per pass, each pass one destroy attempt; pool upkeep while `edge.enabled` is on and the maintenance
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

**Where the member is** (`convex/lib/memberCountry.ts` `memberWhere`; the privacy rules are
docs/privacy.md §1 "Where a member connects from"). Only a key of a freedom-family mode has a
country; any other key gets the universal pool. Their own answer first (`subscriptions.sniRegion`,
set on the account page: "Where are you connecting from?", Automatic by default; "Somewhere
else" means no country), else, with `delivery.country.detect` on, the country stored as a guess
from earlier requests (this request's CDN country may set or refresh it first, unless the request
came from one of FCP's own exits), else, with detection off, the country the CDN reports for this
request (`resolveCountry`: only when the deployment is fronted by it, otherwise it is a header a
client could forge and it is ignored). Each counts only when it is a curated country, and only
at a place an origin covers (elsewhere nothing is rendered). The subscription route and the
raw-config view locate the member with the same function (`lib/subscriptionDelivery.ts`
`locateMember`), so both read this request's country, may set or refresh the guess, and pick the
same names; the family and the place are judged again at the node the body resolves to.

**What is stored.** The member's own answer, and with detection on the guess, on the subscription
row; a body shaped by either caches under that country, and the cache keeps no body for any other
(`subscriptions.writeContentCache` refuses one). With detection off, the request's country is used
for that one response and kept nowhere: such a body is neither read from nor written to the
content cache, is served `private, no-store`, and a cached body is never handed to a request that
infers a curated country (`convex/lib/edges/sni/country.ts`). When no listener has any judged
name, caching is exactly as before.

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
kinds there is no node signal at all: the load score is 0 (`no_load_signal`) and the online bit
is unknown, so `node_offline` never applies. The "manageable Host" veto applies only to `hostMode: operator`; a
`setupOwned` origin (a guided setup in progress) is vetoed `setup_owned` right after the
auto-rotate gates, before any evidence is weighed, while a run works on it, and `not_live`
once none does (a first protection that stopped short keeps its origin owned). The veto is the
detector's last pass; a run can end between passes (or no pass come, with the origin switched
off or edges frozen), so the origin read reports the setup vetoes as the ownership stands
(`setupVetoNow` in `mapRelayAdmin`): no owner, no setup veto; an owner with no run working,
`not_live`. A re-protect that failed hands its origin back, so its page no longer reads "Owned
by a setup run".

**The countries a detector start answers to.** Every detector start records the countries its
evaluation's evidence named for the target (`edgeRotations.affectedCountries`). The L7
replacement gate and the confirming re-check prove the new front against that snapshot, never
against the origin's live suspicion, which every later pass rewrites: a replacement that takes
longer than one pass (provisioning, the 15-minute evidence wait) is still proven where the
block was seen. A rotation row written before the snapshot existed reads the suspicion as
before. Only a detector start carries one (`validation` otherwise); the rotation view shows it.

### Simulating a block on a test deployment

A beta or local deployment cannot produce real censorship, so the automatic path (detector,
start checks, rotation, burn drain, epoch, members' subscriptions) would otherwise never run
there. **Test block evidence** (`convex/edgeSimulations.ts`, `lib/edges/simulation.ts`) makes
the detector believe one published edge is blocked in one country:

- **Only where the deployment opts in**: `EDGE_SIMULATOR_ALLOW=simulate-blocks`, or
  `ENVIRONMENT=development`. `ENVIRONMENT` alone cannot tell a beta stack from production (both
  run `production`). The value is read on every call: once it is removed (`convex env remove`,
  removing the line from `.env.convex` does not unset it), new test blocks are refused
  (`edge.simulator_disabled`, 403) and the next detector pass ends the live ones (`disabled`).
  Never set it on production. While it is on, every admin page says so
  (`GET /api/v1/admin/status` `testTools.blockSimulator`).
- **What it overlays.** A live test block is laid over a COPY of the detector's inputs right
  before `evaluate`: `reporters` more distinct reporters (default twice
  `detect.minReporters`), counted for its country and attributed to its edge, and its edge
  reading `unreachable` from that country, measured just now. Nothing is written to member
  reports, probe rows or baseline samples. With the shipped detection settings (load
  corroboration on, a cold or quiet baseline) the default scores 0.75 against `suspectAt` 0.6,
  hint `corroborated`, so no detector setting has to change. Every gate still applies:
  `edge.enabled`, `edge.autoRotate`, the origin's own Auto rotate, the fleet brake and caps,
  cooldown, the daily cap, `no_verified_spare`, `outside_approved_shape`, maintenance.
- **One test block, one rotation.** When the detector's decision names an edge with a live
  test block, it starts the rotation through `edgeSimulations.startSimulatedRotation`, which
  re-checks the test block (live, same origin and edge, edge still published, opt-in on),
  starts the rotation through the same `startRotation` every start uses, and marks the test
  block `consumed` with the rotation's id, all in one transaction. A refused start rolls the
  whole transaction back and leaves the test block live (the refusal shows on the suspicion as
  usual). The rotation's reason is `detector:<source>:simulated`; the suspicion and its
  `edge.block_suspected` audit carry `simulated: true`.
- **Starting one** (`POST edges/{id}/simulate-block {country, reporters?, minutes?}`, the
  servers write scope, throttled like a probe request; or Simulate a block (test) in the edge's
  actions menu): only a published edge (`edge.not_published`), with probes on
  (`edge.simulation_needs_probes`), in a country edges are checked from
  (`edge.simulation_country`), one per edge (`edge.simulation_active`), three per deployment
  (`edge.simulation_limit`), for 15 to 360 minutes (default 60). `POST
edges/{id}/simulate-block/end` ends it; `GET relays/{id}/simulations` lists the live and the
  last ended ones. Audited `edge.block_simulation.started` / `.ended` (country, reporters,
  minutes, reason); attention `block_simulated` (warning) while one runs. Ended rows are
  deleted after 30 days.

The runbook that uses it is docs/beta-deploy.md "Walking automatic rotation".

### Checks from each country

Every edge is checked from each censored country edges are checked from, and the evidence is
kept per (edge, country) (`convex/edgeCountry.ts`, pure rules in `lib/edges/country/`).
Switched by `edge.country.enabled` (default off): with it off the probes behave exactly as
before (no controls, no spare rounds, no verdicts, no waits). Members' addresses follow it only
with `delivery.country.steer` on (next section).

- **Rounds and controls.** A ROUND is the runs one request makes for one edge
  (`probeRuns.roundId`): every enabled source, every listener port, every family. Each external
  run also asks the **control countries** (`edge.country.controlCountries`, default `DE US JP`;
  a country on the censored-country list is never one) in the same measurement, one vantage
  each, and FCP's own internal check is one more control. Control results are tagged
  (`control: true`) and reach ONLY the round verdict: never `probeReachability`, the edge's
  summary, the detector, scoring or the verification rung. The round is read once, when its
  last run settles (`finishRun`, `failRun` or the stuck-run sweep).
- **A source that errors is no evidence.** A failed or timed-out run adds nothing, and a probe
  that could not run the test is dropped by the parsers. Per path (family, port), from one
  country: `unknown` with fewer than `minProbes` (3) vantages answering or fewer than
  `minNetworks` (2) networks among them (an ASN or a network name, normalized; a vantage the
  source gave neither for adds no network, whichever service it came from), or with more than a
  third failing while some work;
  `proven` with at least 3 working on 2 networks, a third failing at most, and, where the edge
  presents a name (an L7 front, an L4 edge before a REALITY / TLS listener), FCP's own TLS
  check with the real name passed; `blocked` when every vantage fails with the spread met AND
  at least `minControls` (2) controls reach the edge in the same round; `down` when they fail
  too (broken, not blocked). The worst port decides; the result follows IPv4 (or the name of an
  L7 front), IPv6 beside it is kept apart.
- **The address track** (`edgeCountryEvidence.address`) keeps the newest DECIDED result for
  `windowDays` (14). `unknown` and `down` never override it. Proven to blocked needs
  `blockedRounds` (2) blocked rounds at least 30 minutes apart: the first sets `repeatAt` and
  the probe planner takes that edge first once it is due. Blocked to proven takes one round. A
  never-decided edge whose group is already blocked there is blocked on its first blocked
  round. **Country-wide guard:** a block that would make at least 80 % of the edges checked in
  that country within 2 hours blocked, across at least 2 groups and 3 edges, is held as
  `unknown` (`country_wide`): a censor does not block every provider at once, an outage or a
  probe problem does.
- **The handshake track** (`edgeCountryEvidence.handshake`) reads the checks from inside a
  country: a finished batch in which no name got through (`path`, from at least the name
  checks' `minVantages` on `minNetworks`; a service measures every name of a batch from the
  same probes, so a probe counts once however many names it tried) counts only when PAIRED with a working TCP reading of
  the same address, port, family and country from a round within 60 minutes; an unpaired one
  is recorded (`no_tcp_pairing`) and asks for a round at once. Two paired batches at least an
  hour apart block (one when the group is already blocked there). It clears only when names
  reach the address again from enough vantages, by expiry, or by a mark: a working TCP round
  never clears it (both work while a country blocks every name on the address). With the
  checks on, the name planner takes the addresses of a listener in turn (the one batched there
  longest ago first, a new one before all).
- **Combined, groups, marks.** An edge is blocked in a country if either track is, proven if
  the address track is and the handshake track is not. A GROUP is one provider location
  (`<provider>:<placeKey>`; a CDN front is `<provider>:global`; an adopted edge, or one without
  a recorded location, is its own): blocked with at least two blocked edges, at least half of
  the decided ones and none proven (`countryGroupGrades`). An operator's mark
  (`countryMarks`, edge or group, never expires) wins over every check. What an edge counts as
  per country (its mark, the group's mark, its own result, else the group's block for an edge
  with nothing decided) is copied onto `edges.countryState` (decided entries only, each with
  its `until`; one past it reads as unknown). That `until` is how long the combined state
  itself holds (`edgeCountryEvidence.stateUntil`: a block while any blocking track does, a proof
  while the address proof does), not the earliest track's expiry the worker runs on: an address
  proof lapsing never ends a handshake block that still stands. A group never proves an edge.
- **Expiry.** Cron `edge-country-expiry` (hourly, whether or not probes run) lapses decided
  tracks past their `until`, regrades the groups, rewrites every affected `countryState` and
  deletes rows nothing touched for a whole window.
- **Before use.** A guided setup's stage 4 asks for its address's round itself (even when the
  evidence on record already makes the rung `partial`, as for a reused spare) and waits for it (at most
  `preUseWaitMinutes`, 15; not known never holds it); one that finds the address blocked in a
  checked country while the controls reach it stops at `blocked_in` ("Try another address" or
  "Use it anyway"). A rotation that publishes an L4 address (a replacement, a spare's
  publication) requests a round once and waits the same bound; a DETECTOR replacement whose
  round finds it blocked in one of the countries that triggered it
  (`edgeRotations.affectedCountries`) fails `replacement_blocked`. Spares are checked every
  `standbyRecheckHours` (12), and a spare blocked in fewer checked countries is published
  first. A test block (§ Simulating a block) stays detector-only: the replacement's own round is
  real.
- **Budget and failing sources.** `edge.probe.globalpingTestsPerHour` (default 400) counts the
  vantage points asked of Globalping (`probeRuns.tests`: countries x vantages, plus one per
  control); a round that would pass it runs without Globalping, and the executor asks
  Globalping's `GET /v1/limits` first and does not start a measurement that would not fit
  (`globalping_limit`). A failed run keeps a short class (`probeRuns.error`: `auth`,
  `rate_limited`, `timeout`, `service_error`, ...). A source whose newest three settled runs
  brought back nothing (of its newest 50), with nothing working for six hours, raises attention
  `probe_source_failing` (warning) and shows on `GET probes/sources` and `GET probes/matrix`
  (`sources`).
- **Admin API.** `GET countries` (checked and control countries, grades, every edge's tracks
  per country with its effective state, marks, sources; never an address), `POST countries/marks
{scope: edge | group, ref, country, state: proven | blocked | null}` (a listed country only),
  `POST countries/check {edgeId}` (one manual round, throttled like a probe request). Audited
  `edge.country.state` (slug, country, track, state, reason), `edge.country.mark` and
  `edge.country.check`. The verification rung reads its internal shape runs with their own
  query, so the extra runs never push them out of its window.
- **In the admin.** The node page and the edge drawer (per address, per checked country, with
  "Mark for a country" and "Check from every country now"), the provider account page's
  Countries card (location x country grades, location marks, conflicts), the protect sheet
  (grades per offered location, the new addresses' first rounds) and the Probes page (sources,
  rounds, controls); § Admin section. The overview's `blockedSince` is when the edge's own state
  last turned blocked there (the newest `edge.country.state` audit row of that country, when it
  is a block; the tracks keep only the last confirmation). Every round result, reason and
  failure class has its sentence in `src/client/routes/admin/edges/lib/statusWords.ts`, pinned
  by a test that reads the rules above for the literals they write. Attention: warning
  `country_wide_failure` (fleet, one per checked country where a round within
  `standbyRecheckHours` was held `country_wide`; action: the Probes page) and warning
  `new_edge_blocked_in` (an active address never in use whose round there came back blocked
  while it was never proven there, or whose state is blocked; a held round or a country the
  operator marked does not count).
- **Rollback.** Before deploying a build without these checks, run
  `edgeCountry:purgeForRollback` (it walks the evidence, grades, marks, edges and runs).

| Key (`edge.country.*`) | Default    | Bounds | Meaning                                                   |
| ---------------------- | ---------- | ------ | --------------------------------------------------------- |
| `enabled`              | `false`    |        | the switch                                                |
| `controlCountries`     | `DE US JP` | 1..5   | control countries, one vantage each per run               |
| `minProbes`            | 3          | 2..10  | vantages answering before a country decides anything      |
| `minNetworks`          | 2          | 1..5   | networks among them                                       |
| `minControls`          | 2          | 1..5   | controls that must work for `blocked`                     |
| `blockedRounds`        | 2          | 1..5   | blocked rounds (30 min apart) before proven turns blocked |
| `windowDays`           | 14         | 1..60  | how long a decided result stands                          |
| `standbyRecheckHours`  | 12         | 1..168 | spare check interval                                      |
| `preUseWaitMinutes`    | 15         | 0..60  | the setup run's and a replacement's wait for a round      |

### Delivery by country

With `delivery.country.steer` on (Admin -> Settings, "Where members connect from"; default
off), a freedom-family member's addresses are ordered by their **stored** country: their own
choice, or the stored guess (lib/memberCountry.ts `steeringCountry`). A transient CDN reading
(detection off) never orders anything, nor does any other mode family. One `where` serves both
the names and the edges (`locateMember` / `locateAt`).

- **Tiers** (`lib/edges/assignment.ts`): per edge, from `edges.countryState` (entries past their
  `until` dropped at read): 0 proven there, 1 not known, 2 blocked there. The primary is the
  first assignable edge from the member's seeded pool index whose tier is the best any
  assignable edge has: a member moves only when a tier changes, the modulus spread holds inside
  a tier, and a blocked edge is used only when nothing else is assignable. With fewer proven
  edges than `edge.country.minProvenForExclusive` (default 1), proven and not-known edges share
  the first tier. The backup prefers, in order: not blocked, another provider, the better tier,
  another location, the walk order. Without a country the assignment is byte for byte what it
  was (pinned over a fixed corpus).
- **Caching.** The cache token is unchanged (it also drives the before/after check, the mirror
  barrier and the stale fallback). Entries are keyed by the stored country as before; a change
  of an edge's tier reaches a member within the cache's 30 seconds, or, for an app that asks
  whether its copy changed, within the 10 minutes a held copy may answer it with a 304; a stale
  fallback during a backend outage may carry an older order of still-published edges.
- **Turning it on or off** (`appSettings.setMany` -> `edgeRender.steeringChanged`) moves every
  origin's publication epoch (cached bodies stop matching, members are nudged to refresh) and
  refreshes the mirrors; turning it on starts the detector vetoes' settle clock
  (`delivery:steerSince`).
- **Snapshot.** `subscriptions.lastRender` gains `country` (the stored country the body was
  shaped for) and `primaryTier` / `backupTier` (when steered); a transient reading is written
  nowhere, the snapshot included. Every cached body carries the snapshot of what it holds, and a
  cache hit (fresh, revalidated or stale) records it, so the snapshot always describes the body
  last served, whichever app fetched it; any change of edges, listeners, family, country or tier
  rewrites it. The snapshot's country is one more stored copy: `setStoredCountry` strips it when
  the stored country changes, and `markDelivered` keeps only the plain facts of a snapshot that
  names anything else. The account labels and report attribution replay the snapshot's own
  roles (`endpointsFor`), and attribution reads the names under the snapshot's country.
- **Mirrors** are ordered by the member's own choice only (a public object held by a third
  party is never shaped by a guess), on a freedom-family key, while steering is on. Without a
  choice, a mirror puts edges blocked in ANY listed country last (no member data shapes it: a
  mirror exists for exactly the people who are blocked).
- **The detector.** With steering on, `autoRotateDecision` gains two vetoes, after
  `protocol_level_block` and before the fleet brake, over the evidence countries edges are
  checked from:
  - `country_wide`: every one of them is under the country-wide guard (nothing is decided
    there, so a global replacement would act on an outage);
  - `country_scoped`: every evidence country is either under the guard or routed around: the
    chosen edge is effectively blocked there, and on every delivery path it serves (its
    listener x each body format with a codec x each IPv6 allowance and backup order the enabled
    render rules produce) a DISTINCT edge not blocked there is assignable, and one not blocked
    in any listed country (mirrors without a choice); a path that hands out the backup first
    needs two of each (`steeringAvoids`, built from the assignment's own rules and
    cross-checked against it).

  Only an edge on a listener whose transport only freedom-family modes use (the backend
  setup's modes) can be vetoed: privacy-family members are never steered. The vetoes wait one
  refresh interval (plus the 10-minute revalidation) after steering was turned on, so members
  already hold the steered order. It rotates as today when the evidence names no checked
  country, when the edge is blocked in every checked country (it would only serve members
  outside the list), or when the edge is only not known there. A test block (§ Simulating a
  block) meets the same vetoes.

- **Preview.** `POST render/preview {country}` (and "As a member in" on the preview) renders as
  a member whose stored country that is (a listed one): names chosen for it and, with steering
  on, addresses ordered for it, with the tier each endpoint came from.

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
every control a key (pinned by `settings.test.ts`). `edge.freedom.edgesOnly` is not one of
them: it has its own card and route (§ "Freedom modes only through edges").

**Settings are operator decisions; the machinery is constants.** Timeouts, attempt caps, poll
and claim intervals and per-pass caps are `EDGE_PLUMBING` in `convex/lib/edgeConfig.ts`, not
settings: provision timeout 20 min, discovery timeout 30 min, a rotation's wall clock 2 h, poll
20 s, operation claim 60 s, 8 verification attempts, 6 publish and 6 rollback attempts, 48
destroy passes of at most 12 resources each, one automatic reconcile start per pass, 2,000 report rows per detector
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
`edge.updateIntervalHours` (default 1 h) is the refresh hint of an edge-rendered subscription
and `edge.burnedDrainMinutes` (default 120) the drain of a burned edge; neither has a per-origin
override, and a drain shorter than the hint allows is saved with a warning (§ "How fast members
move").
`desiredPublishedDefault` seeds an origin's `desiredPublished`, which is pool state (setup and
re-protect runs widen it), bounded 1..16 (`MAX_DESIRED_PUBLISHED`); the fleet default stays
within 1..8.

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
then writes that list once and never overwrites a stored one. The union is never truncated: when
the old keys together hold more than 40 countries the seed does not copy it (dropping the tail
would silently stop checks, suggestions and matrix rows), it stays live, and the Settings card asks
the operator to remove the extra countries and save. The edges and server-name PATCH routes no
longer write the old keys, and once the list is stored the same seed deletes the four country
lists among them (`seed:retireLegacyCountryKeys`; `status.censorship` stays, it is the matrix
itself); saving the list retires them too. Their last values are kept in `appState`
`censorship:legacyKeys`, and `seed:restoreLegacyCountryKeys` puts back the ones that are missing:
run it before deploying a build older than the list, which reads only the old keys. A key written
again after it was retired (an older build ran after a restore) is never deleted unseen: the seed
keeps it, the card names it ("changed while an older version ran"), and saving the list retires
it with its newest value backed up. Audited `censorship.legacy_keys.retire` / `.restore` /
`.changed` (key names only). A matrix row of a country that leaves the list stays stored (adding the
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
- **The origin TLS contract.** Recorded per combination: Fastly presents the backend's own
  address as SNI and verifies against it, so that address must be a name the origin's
  certificate covers (`origin_cert_name_uncovered` otherwise; also sent as `ssl_sni_hostname`
  and `ssl_cert_hostname`, on port 443); with `overrideHost: 'origin'` (Host = the origin name too, a public certificate
  naming it) it is supported, with `'hostname'` only when the node's verified ingress accepts
  any Host header; Cloudflare `full`
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

**Walk automatic rotation, or an L7 front, on a test deployment.** docs/beta-deploy.md
"Walking the edges on a test deployment" (test block evidence, § "Simulating a block on a test
deployment").

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
Creating a setup run, `require-edges`, and a `retry` or `continue` that re-enters a stage at or
before `provision` are refused too (`admission: 'setup.start'`), and so is the approval of a
fronted node (`publish`). Each check sits inside the mutation that persists the work, never only
in the action before it, so a freeze and a start cannot race. This is the barrier a migration
of the edge tables deploys under (§ Deploy notes). `edgeMaintenance:thaw` lifts it.

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

## Provider accounts and locations

An account is the **whole provider account**: its credentials and what they reach. Where its
edges are created is a **location** (`edgeLocations`, `convex/edgeLocations.ts`), chosen when a
node is protected, an address is added or one is replaced, and frozen on each edge.
`convex/lib/edges/accountSettings.ts` splits every provider's settings into the account's
(`EDGE_SETTINGS_SCHEMAS`: credential identifiers and intent defaults) and the placement
(`EDGE_PLACEMENT_SCHEMAS`); `accountSettings.test.ts` pins that every key sits in exactly one
classification list. A location holds its frozen placement, `placeKey` (the provider's own
region or zone id) and `placementHash`; `locationKeyOf` (`lib/edges/locations.ts`) is
`<provider>:<placeKey>`, account-agnostic, because two accounts in one region share address
ranges. Only an OVH key's API endpoint still locates every resource of its account (locked
while edges exist); nothing else on an account is locked.

**A CDN's place is a DNS zone.** A Cloudflare location's placement is `{zoneId, zoneName}`, one
of the zones its token reaches; a Fastly location's is `{dnsAccountId, zoneId, zoneName,
tlsConfigurationId?}`: the DNS account its records are written through, one of that account's
zones, and the TLS configuration (absent = the Fastly account's default), which decides which
addresses members reach. Every CDN location keeps `placeKey: anycast`: the zones of one CDN share
its address ranges, so per-country grades, the renderer's backup tier and the provider-set
groups treat them as one place. A zone location is checked with the provider when it is created
(`checkLocation`: readable with the credentials that will use it, active, not paused, its name
unchanged; the encryption mode `off` is refused), on **Check again**, on an inventory pull, and
for every location in use whenever the account is tested or its credentials rotate. What the
check saw (`edgeLocations.observed`: the zone's encryption mode, WebSockets, status) is frozen
into each new edge's intent; a refusal is `edgeLocations.checkError`, and no new edge is planned
there (`location_check_failed`) until a check passes. Each zone is its own pick, so a node may
use several zones of one account, trust is taken per zone, and a detector burn cools only the
burned zone.

**What an account reaches** is its catalog (`edgeProviderCatalog`, one row per account and kind:
zones, regions, projects, TLS configurations), listed by `edgeProviderOps.refreshCatalog`
after a passing credential test or rotation, on `POST providers/{id}/catalog/refresh`
(throttled), and when a picker finds it older than 12 hours (`GET providers/{id}/catalog`).
Cloudflare zones are listed page by page up to 1,000 (`truncated` past that). A provider whose
regions depend on the project (Gcore, OVH) lists them in the project a region pick creates in:
the one every location of the account uses, else the key's first; each region names it
(`facts.project`). A failed listing keeps the last items and records why. The catalog is a menu, never an authority: creating a location asks the
provider again.

**An account is its credentials.** Every provider's account, a load balancer's included, may be
created with credentials (and the identifiers each request needs: a Scaleway access key, an OVH
application key and endpoint) and nothing else: the account form's first location is optional
for all of them, all of it or none of it, and its credential test takes no placement (below).
Such an account has no location until one is picked where a node's addresses are chosen. The
old single-place shape (a zone, or a DNS account, among the settings) still makes its first
location, and a Fastly payload naming only its DNS account takes that account's zone. The
account form sends a load balancer's first location only once its region (or another
value it needs) is chosen: a project, a network or a gateway alone is not sent.

**Picking a region.** A load balancer account's regions that are no location of it yet (its
catalog's `regions`, minus the place keys of every location it has, switched on or not:
`edgeProviderCatalog.regionOffersOf`) are offered where a location is chosen: the protect plan
(`SetupPlanAccount.regions`) and a node's provider card (`GET relays/{id}/providers` `regions`).
An account with no usable location is offered by them and is not `no_location`; a load balancer
account cannot help a WebSocket node, so it offers none there. Picking one creates the location
at that moment, `POST providers/{id}/locations {placement: {<region key>: id, <project key>:
project}, fill: true}` (the region key is Gcore `regionId`, UpCloud and Scaleway `zone`, OVH
`regionName`; the project is the one the region was listed in), then picks it. `fill` completes the placement from what the key reaches
(`lib/edges/placementDefaults.ts`, never replacing a value the request names): a project the
request leaves out is the one every other location of the account uses, else the first the key
lists (Gcore `projectId`, OVH `serviceName`); OVH's private network and subnet are the first listed network
with a subnet serving the region and its first subnet (asked with the project and the region);
Gcore's network stays empty (a public address); a Scaleway Project id stays empty (the key's
default, § "A placement value with a provider default"). A value no default fills is refused
`edge.location_options_needed` (its keys in the error's `missing`), a project listing that
failed with no project to fall back on `edge.location_unchecked`, and a balancer size the
template leaves to the region (the OVH flavor) `edge.template_value_required`: a size is never
guessed. The rest is a location create as below: the provider is asked whether it offers the
region to this key, the region's name becomes the label, no credential test runs again, and the
new location is untrusted until its first tested address. `POST …/locations/options {placement,
defaults: true}` answers what that pick would be (`defaults`, `missing`) with the lists for it:
the "Change options" form (`RegionPicks` then `LocationPicker` with `region`) opens on it, and
opens by itself on either refusal. A CDN's place is a zone, added in the location form.

**Adding one.** `POST providers/{id}/locations/options {placement?}` lists what the stored
credentials can use (regions, projects, networks, subnets, the load balancer flavors of a
region); `POST providers/{id}/locations {placement, regionalParams?, maxLiveEdges?, costNote?}`
asks the provider again before it saves, refuses a place it does not offer
(`edge.location_not_offered`, or `edge.location_unchecked` when the provider could not be asked),
takes the region's name as the label and schedules that location's inventory. The same place
twice is the same location (upsert on account and `placementHash`). `PATCH …/locations/{locId}`
switches one off, sets its limit, cost note, default template or regional values, or makes it the
default; `DELETE` refuses while an edge that is not destroyed lives there, a node's provider set
names it, or an open setup run picked it before creating its first edge (`edge.location_in_use`).
A create, or a change to the location's template or regional values, refuses
(`edge.template_value_required`) when a regional value the provider requires (the OVH flavor id)
would be empty in both the template the location resolves and its own values. An account PATCH that names a placement key is
`edge.placement_on_location` (a zone included: another zone is another location). A CDN
location `POST providers/{id}/locations {placement: {zoneId}}` takes the zone's name from the
catalog; the provider check refuses with `edge.location_not_offered` (the key cannot read the
zone), `edge.location_unusable` (paused, not active, encryption off, renamed, an unknown TLS
configuration) or `edge.location_unchecked`, and a front naming a DNS account that is missing,
switched off or no DNS provider is `edge.dns_account_unusable`. Both kinds of call go through the `admin.edges.provider-call`
throttle when they reach the provider.

**Frozen per edge.** Each edge records `locationId`, `placeKey` and `placement` when it is
planned (`edges.ts insertPlannedEdge`, `relays.ts` adopt). `edgeProviderOps.loadAdapter` builds
the adapter's settings from the account, then the edge's own placement for a call about that
edge (step, poll, discover, describe, inspect including the live refresh, destroy), or the location's for planning
(`planProvision`, `effectiveTemplate`, `inventory`, adoption); a CDN account's call naming no
place acts in its default location. For an existing L7 edge every value its intent froze wins
(`frozenSettingsOf`: zone, DNS account, TLS configuration, certificate authority), so no edit of
a location or an account moves a live front. An imported front's hostname must sit in the picked
location's zone (`edge.hostname_not_in_zone`). A credential test takes no
placement: Gcore and OVH list projects, Scaleway reads its first zone, UpCloud reads the
account. So a describe or a destroy always reaches the region the resource is in, even when the
account has others.

**A placement value with a provider default** (`EDGE_OBSERVED_PLACEMENT`). A Scaleway location
may leave its Project id empty: every create then names the API key's default project. The
credential test reads it from IAM (`GET /iam/v1alpha1/api-keys/{access_key}`,
`default_project_id`) and the account keeps it as the observed `defaultProjectId` (not a
secret); `loadAdapter` gives it to a call whose location names none. A key that may not read it
still passes its test, but a location with neither reads `project_unresolved` (`placeProblemOf`:
the plan, selection and the set judge it so) and is not offered until it names a Project id, so
nothing fails at provisioning; the adapter refuses a create with no project rather than send
it. A Scaleway 400 on an address allocation ends the run at once as `ip_allocation_refused`
(the same arguments would be refused again), with the provider's words (§ "The provider's
answer").

**Scaleway sizes** (`convex/lib/edges/sizeCheck.ts`). Only Scaleway's multi-cloud load
balancer sizes accept a backend server hosted outside Scaleway; the standard ones (LB-S,
LB-GP-M) take Scaleway resources only ("Only certain Load Balancer types (L and XL) allow you
to add non-Scaleway resources as backend servers",
https://www.scaleway.com/en/docs/load-balancer/troubleshooting/configuration/, read
2026-10-21), and would refuse an FCP node's backend after the load balancer is built and
billed. An FCP node always counts as outside Scaleway. The effective size (the template, the
location's regional value, the node's own option) is checked before anything is created and
refused as `size_not_multicloud`: the place's reason in the plan (`sizeProblemOfLocation`, the
protect sheet greys the location), a pick's options (`checkPickOptions`), a set naming it
(`refuseSet`), a rotation naming it (`collectStartBlockers`, so preflight too), and selection
(named: `accountFailure`; automatic: never picked). Which sizes are multi-cloud is the
provider's own answer: the location's last inventory pull keeps each size's
`LbType.multicloud` flag (an older pull: its "(multi-cloud)" label); a location never pulled,
or a size its list does not name, falls back to the documented LB-GP-L and LB-GP-XL, and
anything else is refused. The default template keeps LB-S: set the location's size (or the
node's) to a multi-cloud one.

**Scaleway timings on the wire** (`scalewayTimings`, `convex/lib/edges/providers/scaleway.ts`).
The template and its options keep `600s`-style values; only the encoding sent differs by field.
Six are int64 milliseconds and go out as JSON integers (`5s` is `5000`, converted on the digits
by `durationMs` in `templates.ts`): the health check's `check_delay` and `check_timeout`, the
backend's `timeout_server`, `timeout_connect` and `timeout_tunnel`, and the frontend's
`timeout_client`. The other two, the health check's `transient_check_delay` and the backend's
`timeout_queue`, are protobuf durations and go out as strings in seconds (`0.5s`). The source is
Scaleway's Go SDK (`api/lb/v1/lb_sdk.go`: `marshaler.Duration`, "in milliseconds", against
`scw.Duration`), read 2026-10-22, for the create and update calls alike. `@scaleway/sdk-lb`
types all eight as strings and passes them through unchanged, so a template's `5s` reached the
API as is and the backend create was refused (`invalid value for int64 field milliseconds`)
after the addresses and the load balancer were built. A stored value that is not a whole number
of milliseconds (`1.5ms`) refuses the plan as `template_invalid` before anything is created.

**Scaleway settling** (`convex/lib/edges/providers/scaleway.ts`). Every Scaleway call answers
at once, but the load balancer applies each change afterwards (`pending` back to `ready`), and
a change sent while it is still applying the previous one can be accepted and never applied.
Observed: a frontend created seconds after its backend left a load balancer that the API and the
console showed as ready, with its frontend and a healthy backend, answering every TCP port on
both addresses with a reset for over 15 minutes, on two load balancers; saving the frontend
again unchanged made both answer at once. Scaleway's own Terraform provider waits for the load
balancer to be `ready` before and after every backend and frontend change
(`internal/services/lb`, `waitForLB`, default 15 minutes, read 2026-10-22), and so does the
adapter (`asyncOps: true`):

- the load balancer, backend and frontend steps answer `requested` (opRef
  `settle:<lb id>`) with their resource, and `pollStep` reads the load balancer until it is
  `ready`: then the step is `done` (the load balancer step with its addresses). Still applying
  `SCALEWAY_SETTLE.timeoutMs` (15 minutes) after the step's first request, it stops the run as
  `lb_settle_timeout`; an error, a lock, stopped or being deleted stops it as `lb_unusable`
  (both refusals keep what was built for the operator);
- the backend and frontend steps first wait in place for a `ready` load balancer
  (`SCALEWAY_SETTLE.inStepMs`, 30 s, read every 3 s, well inside the step's claim); still
  busy, the step throws `lb_busy` BEFORE any create, so discovery proves the absence and the
  step runs again;
- discovery answers `found` only once the load balancer has applied the step (`unresolved`
  while it applies), so a create whose answer was lost settles too;
- a create only ever leaves from `runStep`: a poll's claim has no unsettled-operation guard,
  so a create sent from a poll could be sent twice.

`reapply` reads the frontend back and updates it with the fields it holds (its
`timeout_client` comes back as the integer milliseconds it is sent as), waiting in place for a
`ready` load balancer before and after: the guided run's one retry (§ "Guided setup runs").

**Trust is per location.** `qualified`, `qualification`, `qualifiedTemplateHash` and
`autoQualifyHold` live on the location; the account's `qualified` in the admin projection means
any switched-on location is trusted. A new location is trusted by its first tested address (a
Try it tick or a passing L7 proof) or by the Trust override. Editing an account's settings
untrusts every location; a credential rotation that passes its test keeps trust. Because that
test needs no location, a rotation first reads every location still in use (switched on, or with
edges) with the new key, through the adapter's inventory call (a CDN zone: its location check); a
location it cannot read refuses the rotation (`location_unreachable`, naming the location) and
nothing is stored. A zone's own state (paused, not active, encryption off, a renamed zone, CAA)
is recorded and does not hold the rotation up; anything the key itself cannot do there (a TLS
configuration it does not see) refuses it. A CDN zone switched off with no edges is checked
too, and what the new key cannot do there is only recorded on it (no new edge is planned there
until a check passes); the same holds for a DNS account's rotation and the zones only such
fronts write through it. Moving an
account's default template untrusts the locations that fall back to it.

**Regional template values.** A template field whose value differs per region is flagged
`regional` in its descriptor (the Gcore `flavor`, the OVH `flavorId`). A location's
`regionalParams` overlay the template; the effective hash is the hash of the merged parameters,
and an empty overlay keeps the template's own. An edge's `templateHash` is written once, when it
is planned: the L4 tick and the approval shape bind to it.

**Limits and selection.** A new edge is checked against the account's live cap, then the
location's `maxLiveEdges` (`edge.location_capacity`), then the account's daily budget.
Selection ranks the switched-on locations of enabled, tested accounts (trusted unless the start
allows otherwise); a provision run may name `requestedLocationId`, and `requestedAccountId` alone
means that account's default location. A run that cannot use the one it names fails with
`location_not_found`, `no_location`, `location_disabled` or `location_capacity_reached`.

## Provider sets

A node is protected by a SET of picks: locations (§ "Provider accounts and locations") its
addresses come from, at most six (`MAX_PROVIDER_PICKS`), recorded on the origin
(`relays.providerSet`) when a run goes live. A block on one provider's address ranges then
leaves every member a backup elsewhere. An origin without a set (a manual origin, a whole
server, a node from before sets) keeps the old rule: any trusted location.

**The requirement** (pure, `convex/lib/edges/providerSet.ts`), per coverage listener:

- basic coverage: at least one published edge, whatever the set says;
- diversity: published edges in `min(2, G)` **groups**, where G counts the groups among the
  picks that can carry the listener and are not cooling. A group is the provider (one block
  on its ranges takes all its regions), or the location when every carrier of the listener is
  one provider (two regions of one network still beat one);
- every pick that carries a listener holds at least one published edge.
  A pick carries a listener when its provider fronts the listener's layer, protocol and port and
  the listener's provider or account scope names it (`carries`, `setState.ts`); a switched-off
  location or a disabled or untested account carries nothing. A listener whose carriers make
  fewer than two groups is **reduced** (`one_group`): reported in the plan, the review, the run,
  the node's card and an info attention item `reduced_resilience`, never hidden. There is one
  item per remedy, each counting only its own transports, and its code says what fixes it:
  `one_group` when a load balancer can front the transport (a location of another provider,
  its load balancer included, gives the backup), `second_cdn_needed` when only a CDN can (a
  WebSocket node's transport, § Layers, or a plaintext origin's): a second CDN account, at a
  provider other than the one in use, and a zone of it on the node.

  A load-balancer pick is refused for a WebSocket node only when none of its transports may be
  fronted by one (`l4BarredForAll`); a node that also serves a REALITY or raw TLS transport keeps
  the pick, which then carries that transport only.

**The cover**: the fewest new (listener, pick) targets that meet the requirement given what is
published: the listener demand left, plus every pick without an address, minus the targets
that serve both (a maximum b-matching found as a max flow; instances are at most 8 x 6, and a
test checks it against brute force). Targets that cover a listener publish before those that
only cover a pick. The **deficit** is its size; pool admission, sizing and rebalance read it
(§ Publication).

**Setup.** The protect sheet's second step picks the set; the plan is asked again with
`picks` and answers what they make (`set`: targets, reduced, transports no pick carries
(`edge.set_uncovered_listener`), more addresses than one origin publishes
(`edge.set_too_large`), a pick over its account's or location's capacity or budget, summed
over its targets). `planHash` covers the picks. The run creates one address per target: stage 3
reuses a live edge of the same listener AND location, a provision's terminal hook fills the
target of its listener and its requested location (a publish, the target of its edge), and
verification is keyed by each target's edge. `retry {replacePick: {from, to}}` swaps one pick
before its addresses are published (`edge.pick_switch_late` after). Go-live records the set.

**Selection with a set**: the set's usable picks, minus cooling ones for automatic work, ranked
by what they add for the listener: lowers the deficit, a provider not yet published for it, a
location not yet published for it, set order, fewest live edges (`pickLocation`). A set pick
counts as the operator's choice, so automatic work on that node may use its L7 picks
(`edge.l7.autoSelect` still governs origins without a set). Spares: a replace prefers a tested
spare away from the target's provider, then its location, then any (`pickStandby`); upkeep
publishes only spares inside the set and outside a cooling pick, a gap-filling one first. An
operator may name the spare (`rotate`/`burn {spareEdgeId}`, that one or nothing), a location
for a new CDN front (`rotate`/`burn {locationId}`) or for a spare (`provision {locationId,
listenerId, publish: false}`; an untrusted location only for an unpublished spare, its first
tested address trusts it); `preflight` says what Automatic would use.

**Cooling.** When a detector burn finalizes, the burned address's pick cools on that origin for
the origin's cooldown (`relays.cooling`). No automatic path allocates, provisions or publishes
into it meanwhile: selection (`set_picks_cooling` when every carrying pick cools), standby
publish, desired fill and spare replenishment all skip it; its shortfall is not part of the
deficit. Manual work is not held. Attention: info `pick_cooling` with the minutes left.

**Members.** The renderer's backup prefers another provider, then another location
(§ Rendering). The rehearsal checks each (cohort, format) body under the EFFECTIVE delivery rule:
when the body could carry a backup in another group (a subscription, backups on, `maxEntries`
not 1, distinct providers preferred, at least two groups among its listeners) and the backup
sits in the primary's group, the run parks at `resilience_short` (it never loops through
provisioning); otherwise the reason is reported (`single_key`, `backup_disabled`,
`max_entries`, `distinct_off`, `one_group`).

**Editing a set** (`POST relays/{id}/providers`, the node page's card): adding a location to a
live enrolled node starts an `add` re-protect run (new addresses in the added location, tested,
reviewed when the location is a new shape, rehearsed against the whole future pool, committed);
elsewhere the set is saved and the operator adds a spare there and puts it in use. A load
balancer is refused for a WebSocket node (`edge.l4_not_for_websocket`, § Layers). Removing one
is refused unless the SURVIVORS (published, active, addressed edges outside the removed pick
whose verification is current) still serve every transport and meet the requirement the
remaining picks make (`edge.set_would_uncover`); then its addresses drain, its spares are
cancelled, and `desiredPublished` keeps room for the survivors plus what the set still lacks.
The card's **Add a location** also offers the regions a load balancer account reaches that are
no location yet (§ "Provider accounts and locations", "Picking a region").

**Addresses outside the set.** The set changes only when a run goes live (`providerSetAfter`),
so a re-protect that fails leaves the set as it was, and a spare it made in a location the set
never took stays there (a retry reuses it). This is by design: the node's committed delivery
never moved. The view names such locations (`outside`: a location holding one of the origin's
addresses in use or spare, not in its set) and the card lists them under "Also has addresses
at", saying why; adding the location to the set, or deleting the spare, resolves it.

**Re-protect** (§ Guided setup runs): `replace_all` covers the whole requirement fresh; `add`
covers what a larger set lacks. Every enrolled run's activation records a **delivery snapshot**
before its rehearsal (`panelActivationRuns.delivery.edgeIds`: the committed addresses go-live
keeps plus the candidates; for `replace_all`, only the committed ones on transports the run
does not touch). The rehearsal renders exactly it, the commit promotes exactly it
(`servers.delivery_changed` when a kept address stopped serving, and the run rehearses again),
and `resources` stays what the run owns (docs/servers.md "A fronted node's activation").

**Location names.** A location the migration named after its bare region id gets the name its
provider lists for that region (`edgeProviderOps.relabelLocations`, scheduled by `seedCutover`,
touching only such rows; fail-soft).

## Provider accounts: names, test answers and offered regions

**Name.** An account's name is a label for admins (1 to 63 letters, digits, spaces, dots,
dashes and underscores). Edges reference the account by id, so `PATCH …/providers/{id}` with
`name` renames it without touching the provider or the qualification (Rename on the account
page). Names stay unique.

**The provider's answer.** A provider error's message carries the HTTP status and a short
code, never the response body. The provider's own words are kept, made safe
(`redactErrorDetail` in `convex/lib/edges/providers/http.ts`: address literals and every
credential replaced, whitespace collapsed, capped at 600 characters; a credential under 8
characters cannot be replaced safely, so the answer is withheld entirely), in two cases:

- **The calls an admin makes by hand before anything exists**, whatever the answer: the
  credential test and the account form's listings (`DIAGNOSTIC_STEPS`), as the error's
  `meta.detail` (those requests carry no origin and no hostname). It is returned by
  `test-credentials` and `rotate-credentials` (`detail`), by `discover` (`errorDetails`, per
  failed list), stored as `edgeProviderAccounts.lastTestErrorDetail` until the next passing
  test, and shown folded away under "Show the provider's answer". A new adapter gets this by
  naming its test and listing steps from that set.
- **A refusal (any 4xx) of any other call**, on every adapter: the shared HTTP helper
  (`providerFetch`), an SDK error (`toProviderError`: the message and the rest of a JSON body
  the SDK kept, as Scaleway's generic `ScalewayError` does), Fastly's SDK (`toFastlyError`,
  and the validation words of a draft that does not compile) and Cloudflare's
  (`cloudflareError`). Every call redacts its own credential (the Fastly and Cloudflare clients
  pass their token on every call). A refusal of a provisioning call can echo what the request
  carried, so it is never on the error object (no property a log line or `JSON.stringify`
  could show): it is held aside (`withRefusal` / `refusalOf`, a WeakMap entry), and leaves the
  provider action only from a CREATE step (`runStep`, `pollStep`,
  `planProvision`) and only after `scrubNames` replaced every name the edge is known by: its
  resource names, fronted hostname, origin addresses and certificate names, zone, and what its
  ledger recorded under a naming key (matched without regard to case; a capped answer ending
  inside a name loses that fragment too). `toOpsFailure` carries it as
  `EdgeProviderOpsFailure.detail`; a refused outcome (`StepOutcome.detail`, a Scaleway address
  the provider refused, a Fastly draft that does not compile) is scrubbed the same way. Every
  other call (describe, discovery, destroy) drops it. The rotation appends it to the step's
  event ("... The provider answered: ..."; event details keep up to 800 characters), the edge
  keeps it as `failure.detail` (a later failure with no answer of its own, such as
  `step_retries_exhausted`, keeps the last one: `nextFailure`), and a run the refusal ended
  carries it as `need.providerAnswer`. The edge's detail, the "What FCP saw" dialog and the
  run's failure card show it folded away like a test answer.

It never enters a thrown message, a log line or an audit row.

**Live at the provider.** "Refresh live" on an edge (`POST edges/{id}/live/refresh`) runs the
adapter's `inspect`; an SDK adapter answers with class values Convex cannot return (Scaleway's
SDK turns every timestamp into a `Date`), so `edgeProviderOps` passes every `inspect` and
`describe` answer through `jsonSafe` (`convex/lib/edges/jsonSafe.ts`: a `Date` becomes its ISO
string, `undefined` and functions are dropped, a key Convex refuses is dropped, a cycle is
cut). A refresh that fails is shown in the live section itself, in words, until the next try.

**Offered regions.** A provider's region listing can include regions the account cannot use.
The Gcore adapter keeps only `ACTIVE` regions and, once it knows a project, asks each one for
its load balancers (the credential test's own call, 8 at a time). A region that answers with
a definite refusal (a 4xx other than 401 and 429) is not offered; a timeout or a 5xx says
nothing about the region, so it stays.

## Fastly fronts

A Fastly account is an API token with the global scope (on an automation user, with the
WebSockets product entitlement). Each of its front locations names a DNS account and one of
its zones, with an optional TLS configuration, all frozen on each edge planned there; the
certificate authority and `certificateScope` are certificate option defaults, and
`domainModel` an account setting (intent defaults: a change moves new edges only). One edge
is ten steps: the VCL service, its one origin backend, the WebSocket upgrade snippet, the domain
(versionless, or classic when the account says so),
the WebSockets product, the version activation, the certificate (the hostname's own or the
zone's shared wildcard), its ACME record, the wait for issuance and the traffic CNAME
(§ "L7 edges" for certificates, the CAA preflight, waiting codes and domains).

**The origin backend.** The origin must listen on its scheme's own port (443 over TLS, 80
without; `origin_port_unsupported` at plan time otherwise), and the backend carries that `port`
explicitly, with the origin's TLS name as `ssl_cert_hostname` and `ssl_sni_hostname`. The
WebSocket path honours no TLS-name override, though: the front presents and verifies the
backend's own address, so an https origin must be addressed by a name its certificate covers
(never an IP address; `origin_cert_name_uncovered` at plan time otherwise), and that address is
the TLS name sent. Fastly's
WebSockets guide lists only name, address, TLS and Host override as supported, yet the front
dials the backend's `port`, which the API defaults to 80 whatever `use_ssl` says: a backend
without it spoke TLS to port 80 and every front failed its qualification. Inspect reports the
port the provider holds.

**Teardown.** In `FASTLY_DESTROY_ORDER`: traffic record, certificate, ACME record, versionless
domain, version deactivation, service, then the version-scoped children (backend, snippets, a
classic domain) and the WebSockets product. The children are never deleted on their own: with
the edge's own service gone (`ownServiceOf`, never a candidate discovery could not prove) they
are confirmed gone without a call, and otherwise read back on the service's version (a 404 is
gone), so a service deleted under a ledger that never recorded it cannot leave them waiting.

- **Switching domains.** On the account page, Domains, "A new front's name is": its own
  domain linked to the service (versionless, the default) or a domain on the service version
  (classic, only on accounts created before September 2025). Fronts that exist keep theirs;
  like any settings change it untrusts the locations until a test and a proven front.
- **Switching to the wildcard.** On the account page, Certificates, set Certificate to "One
  wildcard for every front" and save the defaults: nodes protected from then on start from it
  (one node can also choose it alone, under its Options when it is protected). Like a settings
  change it untrusts the account's locations, and as a certificate default it marks the account
  untested (`retest_required`): test the account again (each zone's CAA preflight then checks
  `issuewild`), and its next proven front trusts it again. Fronts that exist keep their own
  certificates until they are replaced.
- **CAA.** Allow the account's CA at the zone (or wherever its CAA records sit, up the tree) with
  `issue`, and with `issuewild` for the wildcard: `0 issue "certainly.com"` and
  `0 issuewild "certainly.com"` for Certainly.
- **A failed shared certificate.** Fix what the account page says it waited on, retry the
  subscription at the provider, and the next reconcile pass reads it again.
- **Retiring the wildcard.** Switch the account's default to one certificate per front (and
  any node that chose the wildcard, under its Options) and replace its fronts; once none uses the wildcard, the account page offers "Remove shared certificate"
  (for one FCP ordered only), which deletes it and the ACME record FCP wrote (never another
  customer's record). An account is deleted only after that. A wildcard FCP found and reused is
  removed at the provider by hand, if nothing else uses it. Removal reads the wildcard with the
  account's default certificate authority: one a node ordered under another authority reads as
  `shared_certificate_ambiguous` until the default names that authority again.

## Cloudflare fronts

A Cloudflare account is a DNS provider's account: its API token, and the zones it reaches as
its locations (§ "Provider accounts and locations"). Fronting member traffic through it is a
choice every account makes for itself, **DNS only** (the default) or **DNS and fronting** (§ "L7
edges"); an account from before the choice took the retired switch's value (§ "Deploy notes").
Nothing turns it on by itself: a deployment that never sets an account to DNS and fronting fronts nothing through
Cloudflare. Set it in the account form ("What this account does") or on the account page
(same card, then Change); both are audited (`edge.provider_account.create` carries
`frontsTraffic`, a change is `edge.provider_account.fronting_changed` with how many of the
account's edges exist). Switching an account to DNS and fronting untrusts its locations and
stamps `credentialsChangedAt`, so automatic trust needs a credential test after it (the page
runs one at once: it is what checks the zones for fronting) and then a proven front, as for any
new account; it never touches the records the account holds for other fronts. Switching it back
to DNS only stops new fronts there and keeps its spares from going live; fronts that carry
members are kept until they are replaced or deleted.

**Terms of service.** Cloudflare's Self-Serve Subscription Agreement (the version of
2025-09-12, § 2.2.1 (j)) restricts using its services "to provide a virtual private network or
other similar proxy services" unless Cloudflare permits it in writing, and its service-specific
terms for the CDN describe it as serving web pages and websites, with limits on serving video
or a disproportionate share of large files. Fronting member proxy traffic through a self-serve
account may therefore be outside what those terms allow, and Cloudflare may limit or end the
service for that zone or account. Read the terms that apply to the account (an enterprise
agreement may differ) before choosing DNS and fronting. FCP neither checks nor enforces this.

**Trade-offs.** What differs from a Fastly front, stated for the choice:

- Every Cloudflare zone answers from the same anycast address ranges, so a block of those ranges
  blocks every Cloudflare front at once; blocking them costs a censor much of the web, which some
  do anyway. Fastly and Cloudflare are separate failure domains: for a WebSocket node, which no
  load balancer fronts (§ "Provider sets"), a fronting Cloudflare account is offered by the
  protect sheet beside Fastly, and a set holding both clears `second_cdn_needed`.
- Fronts share the zone's wildcard certificate: a front's own name never reaches Certificate
  Transparency logs, and nothing is ordered per front (Fastly's `wildcard` scope does the same).
  The zone's name does reach them, and the SNI and zone link every front of the zone.
- A Free zone holds 10 Transform Rules and 10 Origin Rules: each front uses one Transform Rule
  (unless it passes the member's address on) and one Origin Rule only when the node's port is not
  the encryption mode's default, so a Free zone carries at most 10 fronts at once, a replacement
  included.
- Cloudflare carries HTTP transports Fastly does not (HTTP Upgrade, gRPC with the zone's
  dashboard-only gRPC switch, XHTTP), and like any CDN it sees every connection's metadata.

**The member's address at a Cloudflare front.** Cloudflare sends the origin `CF-Connecting-IP`
and `X-Forwarded-For` with the member's address on every request. A front that keeps the
member's address from its node (the default: `forwardClientAddress` off, for every account,
template and front) gets a request-header Transform Rule (phase `http_request_late_transform`)
for its own hostname only, never the zone, removing every name in
`CLOUDFLARE_CLIENT_ADDRESS_HEADERS` (`providers/cloudflare.ts`): `cf-connecting-ip`, the one
address header a rule may remove there. What no rule removes at Cloudflare, by its own
documentation (re-read 2026-10-21):

- `X-Forwarded-For`: a rule may remove it, but the proxy adds it back with the member's address
  after every rule phase, managed transforms included, so the rule does not ask;
- `CF-Connecting-IPv6` and `CF-Pseudo-IPv4` (a hash of the member's IPv6 address), sent while
  the zone's Pseudo IPv4 is on (`add_header` or `overwrite_header`), and every other `cf-` or
  `x-cf-` header: rules may not touch them;
- `True-Client-IP` (Enterprise only, through a managed transform), `X-Real-IP` (Cloudflare drops
  it unless a Worker runs) and `Forwarded`: no documented removal, so they stay off the list
  until a front built with one shows it gone in a capture at a node (the Fastly lesson: one name
  a CDN refuses fails every front);
- `CF-IPCountry` (the member's country, not the address: the zone's IP geolocation, zone-wide),
  `CF-Ray` (a request id with the data centre's code), `CF-Visitor` (the scheme) and
  `CDN-Loop`: no address, and no removal either.

So the member's address always reaches a node behind a Cloudflare front, in `X-Forwarded-For` at
least, as `Fastly-WAF-Client-IP` reaches a node behind a Fastly front (§ "Provider options"):
only the node itself keeps it from the proxy, with the role's Caddyfile (in
`ansible-role-freesocks`) removing every address header in each `reverse_proxy` with
`header_up -<name>`, `X-Forwarded-For` and the `CF-` ones included. Keep that layer on every node
a Cloudflare front reaches; a node without it hands the proxy each member's address. The
zone-wide managed transform "Remove visitor IP headers" removes `cf-connecting-ip`, `true-client-ip` and (only for requests
another CDN proxied) `x-forwarded-for` for EVERY hostname of the zone, so FCP never turns it on;
it adds nothing for a front's own request that the header rule does not. A fronting zone's
location check reports Pseudo IPv4 (`pseudo_ipv4_on`) and IP geolocation (`ip_country_header_on`)
and changes neither: they are the operator's other sites' settings too. On (the node's options)
adds no header rule. The rule is created under the zone lock (`cloudflare-zone:<zoneId>`, as the
Origin Rule), found again by its `ref` (the edge name), shown by Inspect with what it removes, and
destroyed before the record; a token that may not edit Transform Rules (or a zone with no rule
left) is refused at once (`header_rule_forbidden`), the run stopping there. An imported front
adopts a rule that names exactly its hostname, and gets none from FCP otherwise.

**Certificates and TLS.** Universal SSL covers the zone apex and its first-level names, which is
where every front is minted, so a front needs no certificate of its own. The location check of
a fronting account's zone (a credential test, "Check again", a new zone) reads the zone's
certificate packs: none for `*.<zone>`, active or on its way, refuses the zone
(`edge_certificate_missing`: Universal SSL switched off, or nothing ordered), one still being
issued is reported (`edge_certificate_pending`), and an Advanced or Total TLS pack for the
wildcard counts as well. The location records the pack's state, type and authority
(`edgeCertificate`, `edgeCertificateType`, `edgeCertificateAuthority`). A new front whose zone's
certificate does not cover it yet waits with that code (`edges.waiting`, attention
`certificate_waiting`, and a provision that times out ends with it), as a Fastly front waits on
its subscription; a certificate the token cannot read is left to the front qualification, which
proves it end to end.

Cloudflare picks the authority for Universal SSL among Let's Encrypt (`letsencrypt.org`), Google
Trust Services (`pki.goog`) and SSL.com (`ssl.com`), and may change it at a renewal without
notice (it cannot be chosen through the API; an Advanced certificate can). The CAA preflight
walks the wildcard's records from the zone up (§ "L7 edges", CAA preflight; `issuewild`, else
`issue`) and refuses the zone (`caa_forbids_ca`, a certificate refusal like Fastly's) only when
records exist and allow none of the three; it records which ones they allow (`caaIssuer`).
Cloudflare adds CAA records for its own authorities to a zone it hosts once the zone has any, but
never to records above the zone (a zone for a subdomain inherits its parent's), which is what the
walk is for. Allow at least one of them with `issuewild`, ideally all three.

The lowest TLS version members may use is a zone-wide setting (`min_tls_version`, 1.0 unless set):
the check records it and reports 1.0 or 1.1 (`min_tls_1.0`, `min_tls_1.1`). Set 1.2 on a zone
used for fronts; a per-hostname minimum needs Advanced Certificate Manager, and FCP sets neither.
Cloudflare speaks TLS 1.2 or 1.3 to the node; that leg is not configurable.

**The origin leg.** The zone's encryption mode decides how the front dials the node (observed,
frozen per edge, § "Node role contract"): Flexible dials a plaintext origin on 80, Full and Full
(strict) an https origin on 443 (another port through an Origin Rule). Full encrypts without
checking the node's certificate. Full (strict) checks it against the FRONT's hostname, which an
enrolled node's certificate (its origin name only) never carries, so enrolled nodes are fronted
under Full: the location check reports it (`zone_ssl_not_strict`) and does not refuse it. This is
where a Cloudflare front falls short of a Fastly one, which verifies the node's certificate
against the name it dials. Closing it needs the front to present the node's own name (an Origin
Rule SNI override, which Cloudflare offers on Enterprise plans only, as it does the Host header
override) or nodes with a certificate for the front's name; neither is built.

**Long-lived WebSockets.** The zone's WebSockets setting must be on (`zone_websockets_off`
otherwise). Cloudflare publishes no idle timeout for a proxied WebSocket (it closes one after a
period without data in either direction; Enterprise can change it), and it restarts servers when
it releases code, which ends open WebSocket connections: members' clients reconnect, so a front
must not be judged blocked by one dropped session. Its documented proxy limits (a 125 s wait for
the origin's first byte, 900 s proxy idle, 400 s client keep-alive) are stated for HTTP; how they
apply to an upgraded connection is not. Argo Smart Routing does not carry WebSockets. The edge
connection gate does not model any of these.

**Lifecycle.** One edge is the proxied record, the Origin Rule when the node's port needs one, and
the header rule. Discovery finds the record by its comment marker and content, and each rule by
its `ref`; readiness is a proxied record plus a certificate covering the name. Qualification,
publication, rotation and the replacement of a blocked front are the generic L7 ones (§ "L7
edges"). Destroy removes the header rule, the Origin Rule, then the record; each delete is
synchronous (a 404 is gone), so the destroy walk ends in the pass it starts. The import inventory
lists the zone's proxied records.

**Token.** A token that fronts needs, on its zones: Zone read, DNS edit, Zone Settings read (the
encryption mode, WebSockets and the settings above), SSL and Certificates read, and edit on
Transform Rules (the header rule) and on Origin Rules (a port override). A DNS-only account needs
Zone read and DNS edit.

## Provider options

Every settable field of every resource FCP creates at a provider is an OPTION, declared once
per provider in `convex/lib/edges/providers/templates.ts` (a zod leaf, plus a descriptor:
label, help in plain words, group, unit, default, the API field it fills, whether it is
shown first for a node, a `when` condition). `providers/options.ts` holds the generic half:
`describeFields` completes a descriptor's bounds, choices and default from the schema,
`wireBody` writes a resource's chosen fields into its request body, and the hash helper. The
admin forms render from the same descriptors (`optionSchemas` on `GET providers`, `schemas`
on `GET templates`) through one component, `OptionFields.svelte`.

**Two kinds, one home each.**

- **Tuning** options configure the resources an edge is built from (a size, a timeout, a
  health check, an IPv6 preference). Their defaults live in **templates**, in the template
  hash as before. The Templates tab edits them.
- **Certificate** options decide a CDN front's certificate (the authority, one wildcard or one
  per front). Their defaults live on the **account** (`edgeProviderAccounts.optionDefaults`),
  outside the template hash, frozen in each front's intent and proven per edge by its front
  proof. An account's defaults only PREFILL: a node protected from it copies them into its
  pick.

**Per node.** Any option can be chosen for one node at one location: the protect sheet's
Options fold on each pick, `relays.providerSet[i].options` once the run goes live
(`edgeSetupRuns.picks[i].options` while it runs). A pick stores only what differs from what
the location builds with anyway, plus the certificate values copied from the account. The
deploy copies the account's certificate defaults into every pick from before options too
(`migrateOptionDefaults`), so a later change of an account's defaults reaches nodes
protected after it, never one that exists (what the account page says). Changing a live node's options is a re-protect (`reprotect {pickOptions}`,
every address replaced, members move at go-live), never an edit of a live edge. A manual
spare or replacement may carry options for that one address (`options` with `locationId`);
automatic work never takes such an address.

**Frozen per edge.** When an edge is planned, `resolveBuildFor` lays the pick's tuning
choices over the template the location resolves (and checks the result against the
provider's rules). The edge records `choices` (the pick's whole set, JSON) and
`baseTemplateHash` (the location's own hash); its `templateHash` is the base hash when the
pick chose no tuning value, else the hash of the template with the tuning choices laid over
it. The certificate is the approval shape's own part instead (`certificateDigest`,
`lib/edges/choices.ts`: the authority and scope, defaults filled in): a review line and a
publication carry it for a provider whose certificate is a node's option, so a re-protect or
a replacement that changes only the authority or the scope returns to `node_not_approved`,
while a pick that merely copied the account's defaults builds under the template's own hash.
A review line approved before options names no certificate and takes the one the node is
built with. So the node's approval shape covers its choices, a tick on such an edge is
still trust evidence for its location (trust compares the location's own hash), and a
template edit is still detected mid-provision against the base hash. Certificate values go
into the L7 intent like the authority always did; `loadAdapter` lays the account's defaults
under them for a new edge and the intent's values over them for an existing one (an intent
without a value reads as what its absence meant: one certificate per front, the default
authority).

**Spares follow their pick.** Selection's standby candidates and `verifiedSpareFor` skip an
edge whose frozen choices (tuning) or frozen certificate differ from what its pick asks for
now (`builtForChoices`, `lib/edges/choices.ts`). A template edit is not a choice: it keeps
the existing rule (it untrusts the locations that fall back to the template).

**Certificates a node chooses.** A pick whose certificate differs from what its location's
check covered (the account's defaults: another authority, the wildcard) is checked against
that zone's CAA records when its plan is made (`edgeProviderOps.certificatePreflight` with
the pick's location, the adapter's `certificatePreflight`): a refusal is a problem of that
pick, before anything is ordered. A zone whose CAA refuses the account's own default stays
refused (the location's `checkError`) until the default or the zone's records change and the
zone is checked again; the account's other zones are not held back. A zone's shared wildcard
is read as a front there that chose it froze it, even where the account defaults to one
certificate per front.

The zone holds ONE shared wildcard, issued by the account's default authority (the account
reads, renews and removes it under that one). A node takes it, or one certificate per front
from any authority; a pick asking for the wildcard from another authority is refused
(`edge.option_invalid`, in words), and so is a wildcard pick while the zone's wildcard is
one the account would not order (`edge.shared_certificate_ambiguous`). A wildcard an edge of
the account ORDERED stays the account's to remove whatever authority it was ordered under
(the default may have changed since): the reconcile read names it (`ambiguous` with its
subscription, shown even on an account that now defaults to one per front) and "Remove shared
certificate" deletes it. One the account did not order, or several, never.

**What a place cannot do.** Some values are valid for a provider but not where an edge is
about to be built (`contextProblems`, `providers/templates.ts`), refused with
`edge.option_invalid` and words when a pick is planned (protect, re-protect, a spare's
options) and again when the edge is built (the rotation fails `option_invalid` before it
allocates anything):

- an HTTP or HTTPS health check (Gcore, OVH) on a node that serves a REALITY transport: a
  REALITY port answers no plain HTTP request, so every member would be marked down;
- record tags (Cloudflare `recordTags`, Fastly `dnsTags`) or a flattened traffic record
  (Fastly `dnsFlatten`) on a Cloudflare zone on the Free plan: Cloudflare offers tags from
  Pro up and per-record flattening on paid zones only. The plan comes from the zone's last
  credential test (`observedSettings.zonePlan`); a zone never tested since is not refused here.

Write rules (on a template or a pick, `WRITE_CHECKS`) also cover Fastly: the lowest backend TLS
version may not be above the highest, and keepalive timings need keepalive on.

**The member's address at a Fastly front.** Fastly sets `Fastly-Client-IP` and adds the
member's address to `X-Forwarded-For` on the incoming request, before any VCL runs (its header
reference). By default (`forwardClientAddress` off, for every account, template and front,
including fronts planned before the option, whose frozen params do not name it) the front's
service version gets three snippets: in `vcl_recv`, on every request, `unset` of every header
in `FASTLY_CLIENT_ADDRESS_HEADERS` (`providers/fastly.ts`), then the WebSocket handoff; in
`vcl_miss` and `vcl_pass`, the same headers removed from the backend request, for a request
that is not handed off. The list, by name:

- Fastly's own: `Fastly-Client-IP` and `X-Forwarded-For`;
- what a client, or a proxy on its side, may send: `True-Client-IP`, `X-Real-IP` and
  `Forwarded`.

The generated VCL is pinned whole by `fastly.test.ts`. On passes them all through (the upgrade
snippet only, as before the option).

**`Fastly-WAF-Client-IP` reaches the node.** Fastly also sends `Fastly-WAF-Client-IP`, with the
member's address, on every request through a front (a capture on a beta node showed it on
every WebSocket upgrade). Fastly documents that header nowhere (its header reference, special
and protected headers, WebSockets passthrough, Fanout and Next-Gen WAF client address pages,
re-read 2026-10-21), and it is protected: VCL that unsets it does not compile (`Variable
req.http.Fastly-WAF-Client-IP cannot be unset`), so no snippet can remove it, on any front.
What keeps it from the node's software is the node: the role's Caddyfile (in
`ansible-role-freesocks`) can drop it in each `reverse_proxy` with
`header_up -Fastly-WAF-Client-IP`, which keeps it from Xray, though Caddy, which keeps no access
log, still receives it. Fastly support is the place to ask for a service-level way to stop it.
Until either is in place, a node behind a Fastly front receives each member's address.

**A list only of names that compiled.** Fastly protects headers it does not document, and one
protected name in a snippet fails the whole version: activation answers `version_invalid` and
no front builds at all. Lists are no proof (Fastly's own and the one the VCL linter Falco
models both leave `Fastly-WAF-Client-IP` out), so a name joins `FASTLY_CLIENT_ADDRESS_HEADERS`
only once it has compiled in an activated version, `unset` on `req` and on `bereq`; every name
above has. `fastly.test.ts` refuses any name on a hard-coded denylist (Fastly's documented
protected headers, `Fastly-FF` among them, plus `Fastly-WAF-Client-IP`) in the list or anywhere
in a generated snippet.

**`version_invalid`.** The draft version did not compile. The run fails on that code at once
(the same draft would be refused again) and keeps what it built: open the front's service at
the provider, where the draft version shows the compile error, then delete the front. FCP keeps
the code only, never the provider's words.

**What VCL cannot reach.** `return(upgrade)` ends VCL in `vcl_recv`, so no later VCL puts a
removed header back on the upgrade path. Fastly's WebSocket path adds headers after the handoff
(`CDN-Loop: Fanout` arrives at the node, and no VCL wrote it), and a protected header such as
`Fastly-WAF-Client-IP` cannot be removed at all: only a capture on the node shows what arrives.

**Fronts built before a change to the list.** FCP never edits a live or spare front's service
(an option's `live` is informational only): a front behaves as its version was built until it
is replaced. Its `ws-upgrade` snippet shows which list it has
(`GET /service/{id}/version/{n}/snippet/ws-upgrade`). To replace one, spares first, so no
replace puts an old spare in use:

- a spare: "Doesn't work" on its test card destroys it and builds a new spare in its place
  (the spare dialog's renew);
- a front still waiting in a go-live run: "Doesn't work" on its line retries that line with a
  new front, or cancel the run (only its new addresses go) and protect again;
- a front in use: Replace address, Where naming its location, so a new front is built; the old
  one drains and is deleted as any replaced address is.

**To verify it on a live front.** The active version's snippets
(`GET /service/{id}/version/{n}/snippet`) list `client-address-miss`, `client-address-pass` and
`ws-upgrade` with the unsets above. Then capture on the node itself, since beta and prod nodes
run Xray with logging off and nothing logs a header: on the node's loopback, where Caddy hands
the decrypted request to the transport's loopback port (8443 here; use the node's),

```
tcpdump -i lo -A 'tcp dst port 8443'
```

while a WebSocket upgrade goes through the front (a member's app, or a tester's). Expect no
header that contains the client's address. Expect `Fastly-SSL`, `Fastly-Edge-Service-Id`,
`CDN-Loop: Fanout`, `Via: 1.1 Caddy` and Caddy's own `X-Forwarded-*`. Two limits:

- Caddy passes every request header through unchanged EXCEPT `X-Forwarded-For`,
  `X-Forwarded-Proto` and `X-Forwarded-Host`, which it sets itself (the role's Caddyfile names
  no `trusted_proxies`): on loopback `X-Forwarded-For` is always the Fastly server Caddy talked
  to. The capture proves every other header; what the front itself sent in `X-Forwarded-For`
  never reaches Xray, and Caddy keeps no access log, but it cannot be read on the node (TLS on
  the wire, replaced on loopback).
- Through a plaintext origin (port 80) the front's request crosses the wire unencrypted:
  `tcpdump -A -s0 -i any 'tcp port 80'` shows what the front sent, `X-Forwarded-For` included.

**A second address after the tick.** A provider may report an address family an L4 edge did
not have when its endpoint was confirmed (a dual-stack load balancer whose IPv6 is only read
from `additional_vips`, as Gcore's is now). `recordDescribe` holds it apart
(`edges.learnedAddresses`): it is not served, not in the confirmation's hash, and the
confirmation of what IS served stands, so the IPv4 keeps rendering. The edge's addresses
line says "new address ... not served until tested" with Test it; the test link carries that
address only, its binding is the configuration that serves it, and its tick moves it into
`addresses` (`edgeVerification.confirm`). A family the provider stops reporting is dropped
from the hold; an edge without a confirmation takes a new address at once, as before.

**The hash rule.** An option added after a provider's first schema is `.optional()`, with
its default declared on the descriptor and applied where it is sent, and an option a
template never set stays UNSENT (the provider's own default), so an existing node's next
replacement sends exactly what it sent before. Two fields that predate options keep their
old wire: Gcore's node timeouts are sent on the listener as they always were (not added to
the pool), and OVH's `timeoutMemberDataMs`, shown before but never sent, stays hidden and
unsent (`nodeIdleTimeoutMs` sends `timeoutMemberData` when chosen). Two UpCloud changes are
corrections, checked against UpCloud's own Go SDK (`upcloud/request/load_balancer.go`,
v8.42.0): attaching a floating IP posts `{address, network_name}`
(`AttachLoadBalancerIPAddressRequest`), and backend properties have no
`health_check_timeout`, so it is no longer sent. A stored template then
parses to exactly the object it did before, so no template hash, location trust or
in-flight provision moves on deploy. `templates.test.ts` pins every provider's empty
template hash. Rules across fields (a check timeout below its interval, IPv4 ranges only)
apply to WRITES only (`validateTemplateWrite`; for a pick, `checkBuiltParams` on the pick
laid over the template its location builds with, never against the compiled defaults, since a
pick may lean on its template's interval or keepalive switch): on the read schema a stored
template that broke one would stop parsing and `resolveTemplateFor` would silently fall back
to another template. A location joining a node by re-protect is refused at once when what it
inherits cannot be built there; options sent with the old single-location selector (no
`picks`) are refused, never dropped.

**Refusals and audit.** `edge.option_unknown` (not an option of the provider),
`edge.option_invalid` (a value or a rule, in words), `edge.option_not_here` (a tuning option
on the account, a certificate one in a template). The plan reports them per pick
(`set.problems[].detail`). `edge.provider_account.options_changed` records which keys
changed, with values for choices, numbers and switches only;
`edge.provider_account.options_migrated` the deploy move; rotation starts carry `optionKeys`.
A change of an account's certificate defaults untrusts its locations like a settings change.

**Migration.** One deploy, optional fields only. `seedCutover` runs
`edgeProviderAccounts.migrateOptionDefaults` (idempotent): a Fastly account's
`certificateAuthority` and `certificateScope` are copied into `optionDefaults` without
touching `credentialsChangedAt` or trust, and every pick from before options gets its
account's certificate copied in. The copy under `settings` STAYS, and every settings write
keeps it in step with `optionDefaults` (`settingsWithOptionCopy`), so a build from before
options still validates and reads the account's certificate. An older client still sending
them under `settings` is translated, and is never a settings change. A new Fastly account
starts from a wildcard (`EDGE_NEW_ACCOUNT_OPTION_DEFAULTS`).

**Rollback.** Before deploying a build from before options, run
`edgeProviderAccounts:purgeOptionsForRollback` with no arguments (it schedules itself
through accounts, relays, edges, rotations and runs, page by page): it removes
`optionDefaults`, pick and run `options`, the edges' `choices`, `baseTemplateHash` and
`learnedAddresses`, and rotations' `requestedOptions`, which the older schema refuses, while
accounts keep the settings copy it reads.

**Kept fixed on purpose.** Each with its reason:

- names, tags and comments FCP finds its resources by (load balancer and backend names,
  ownership tags and record comments): changing one orphans the resource;
- values derived from the node (member address and port, the listener's port and scheme, a
  Fastly backend's port and the origin's TLS name it presents and checks, the linkage ids
  between resources);
- the proxied flag of a DNS record: an unproxied front publishes the origin;
- PROXY protocol, `X-Forwarded-*` insertion at an L4 balancer and access logs: they hand
  members' addresses to nodes or the provider, and a node not expecting a PROXY header breaks
  every connection (a Fastly front strips the member's address by default, see above; passing
  those headers on is its one option here);
- TLS termination, HTTP modes, certificates and HTTP/3 at an L4 balancer: they break the
  end-to-end passthrough;
- balancing methods, stickiness, weights and backup members: one origin per edge, so they
  change nothing (the existing algorithm fields stay, with that said in their help);
- Fastly shielding, caching, request settings, health checks, `between_bytes_timeout`,
  keepalive reuse: the WebSocket path gains nothing from them or ignores them;
- Cloudflare zone-wide settings (encryption mode, minimum TLS, HTTP/3, WebSockets, IPv6, edge
  certificates, Pseudo IPv4, IP geolocation, managed transforms): they change the operator's
  other sites, so FCP observes them only;
- resources FCP does not create (Cloudflare Configuration Rules and per-hostname TLS, UpCloud
  frontend rules, a Scaleway ACL, OVH's v2-only listener fields): a new resource, not a field;
- polling, request timeouts and page sizes: internal safety, deliberately not settings.

Fastly documents only name, address, TLS and Host as WebSocket backend settings, so the help
of its other backend options says their effect is not proven until a beta walk shows it.

### Every provider option

Generated from the option registry and pinned by `providers/optionTable.test.ts`. "Chosen":
where a value can be set (a template or a location's regional value, an account default),
and per node always. "Live change": what the provider's API would take to change it on a
live resource; FCP never applies one (a new edge is built instead).

| provider   | group             | option                                | API field                                        | default        | chosen                         | live change at the provider |
| ---------- | ----------------- | ------------------------------------- | ------------------------------------------------ | -------------- | ------------------------------ | --------------------------- |
| gcore      | Load balancer     | Size                                  | `loadbalancer.flavor`                            | lb1-1-2        | template or location, per node | in place                    |
| gcore      | Load balancer     | IP versions                           | `loadbalancer.vip_ip_family`                     | IPv4 and IPv6  | template, per node             | rebuild                     |
| gcore      | Load balancer     | Address type                          | `loadbalancer.vip_network_id`                    | Public address | template, per node             | rebuild                     |
| gcore      | Load balancer     | Extra tags                            | `loadbalancer.tags`                              | none           | template, per node             | in place                    |
| gcore      | Listener          | Most connections at once              | `listener.connection_limit`                      | 0              | template, per node             | in place                    |
| gcore      | Listener          | Client idle timeout                   | `listener.timeout_client_data`                   | 300000 ms      | template, per node             | in place                    |
| gcore      | Listener          | Allowed client ranges                 | `listener.allowed_cidrs`                         | none           | template, per node             | in place                    |
| gcore      | Listener          | Node connect timeout                  | `listener.timeout_member_connect`                | 5000 ms        | template, per node             | in place                    |
| gcore      | Listener          | Node idle timeout                     | `listener.timeout_member_data`                   | 300000 ms      | template, per node             | in place                    |
| gcore      | Pool              | Balancing method                      | `pool.lb_algorithm`                              | Round robin    | template, per node             | in place                    |
| gcore      | Health check      | Check type                            | `health_monitor.type`                            | TCP            | template, per node             | rebuild                     |
| gcore      | Health check      | Check interval                        | `health_monitor.delay`                           | 10 s           | template, per node             | in place                    |
| gcore      | Health check      | Check timeout                         | `health_monitor.timeout`                         | 5 s            | template, per node             | in place                    |
| gcore      | Health check      | Healthy after                         | `health_monitor.max_retries`                     | 3              | template, per node             | in place                    |
| gcore      | Health check      | Unhealthy after                       | `health_monitor.max_retries_down`                | 3              | template, per node             | in place                    |
| gcore      | Health check      | Check port                            | `member.monitor_port`                            | provider's own | template, per node             | in place                    |
| gcore      | Health check      | HTTP check method                     | `health_monitor.http_method`                     | GET            | template, per node             | in place                    |
| gcore      | Health check      | HTTP check path                       | `health_monitor.url_path`                        | /              | template, per node             | in place                    |
| gcore      | Health check      | Healthy status codes                  | `health_monitor.expected_codes`                  | 200            | template, per node             | in place                    |
| gcore      | Health check      | HTTP check version                    | `health_monitor.http_version`                    | 1.0            | template, per node             | in place                    |
| gcore      | Health check      | HTTP check host name                  | `health_monitor.domain_name`                     | provider's own | template, per node             | in place                    |
| upcloud    | Load balancer     | Plan                                  | `loadbalancer.plan`                              | development    | template, per node             | in place                    |
| upcloud    | Load balancer     | Maintenance day                       | `loadbalancer.maintenance_dow`                   | provider's own | template, per node             | in place                    |
| upcloud    | Load balancer     | Maintenance time (UTC)                | `loadbalancer.maintenance_time`                  | provider's own | template, per node             | in place                    |
| upcloud    | Load balancer     | Labels                                | `loadbalancer.labels`                            | none           | template, per node             | in place                    |
| upcloud    | Frontend          | Client idle timeout                   | `frontend.properties.timeout_client`             | 300 s          | template, per node             | in place                    |
| upcloud    | Backend           | Node idle timeout                     | `backend.properties.timeout_server`              | 300 s          | template, per node             | in place                    |
| upcloud    | Backend           | Tunnel timeout                        | `backend.properties.timeout_tunnel`              | 3600 s         | template, per node             | in place                    |
| upcloud    | Health check      | Check interval                        | `backend.properties.health_check_interval`       | 10 s           | template, per node             | in place                    |
| upcloud    | Health check      | Unhealthy after                       | `backend.properties.health_check_fall`           | 3              | template, per node             | in place                    |
| upcloud    | Health check      | Healthy after                         | `backend.properties.health_check_rise`           | 3              | template, per node             | in place                    |
| upcloud    | Health check      | Close connections on failure          | `backend.properties.health_check_on_down`        | off            | template, per node             | in place                    |
| upcloud    | Member            | Most connections at once              | `member.max_sessions`                            | 1000           | template, per node             | in place                    |
| upcloud    | Address           | Delegate a floating IPv4              | `ip_address.floating`                            | on             | template, per node             | rebuild                     |
| scaleway   | Load balancer     | Size                                  | `loadbalancer.type`                              | LB-S           | template or location, per node | in place                    |
| scaleway   | Load balancer     | Description                           | `loadbalancer.description`                       | origin edge    | template, per node             | in place                    |
| scaleway   | Load balancer     | Extra tags                            | `loadbalancer.tags`                              | none           | template, per node             | in place                    |
| scaleway   | Address           | Also an IPv6 address                  | `ip.is_ipv6`                                     | on             | template, per node             | rebuild                     |
| scaleway   | Address           | Reverse DNS name                      | `ip.reverse`                                     | provider's own | template, per node             | in place                    |
| scaleway   | Frontend          | Client idle timeout                   | `frontend.timeout_client`                        | 600s           | template, per node             | in place                    |
| scaleway   | Frontend          | New connections per second            | `frontend.connection_rate_limit`                 | 0              | template, per node             | in place                    |
| scaleway   | Backend           | Node idle timeout                     | `backend.timeout_server`                         | 600s           | template, per node             | in place                    |
| scaleway   | Backend           | Node connect timeout                  | `backend.timeout_connect`                        | 5s             | template, per node             | in place                    |
| scaleway   | Backend           | Tunnel timeout                        | `backend.timeout_tunnel`                         | 3600s          | template, per node             | in place                    |
| scaleway   | Backend           | Most connections at once              | `backend.max_connections`                        | provider's own | template, per node             | in place                    |
| scaleway   | Backend           | Queue wait limit                      | `backend.timeout_queue`                          | provider's own | template, per node             | in place                    |
| scaleway   | Backend           | Node connect retries                  | `backend.max_retries`                            | provider's own | template, per node             | in place                    |
| scaleway   | Backend           | Balancing method                      | `backend.forward_port_algorithm`                 | Round robin    | template, per node             | in place                    |
| scaleway   | Health check      | Close connections on failure          | `backend.on_marked_down_action`                  | off            | template, per node             | in place                    |
| scaleway   | Health check      | Check interval                        | `backend.health_check.check_delay`               | 5s             | template, per node             | in place                    |
| scaleway   | Health check      | Check timeout                         | `backend.health_check.check_timeout`             | 3s             | template, per node             | in place                    |
| scaleway   | Health check      | Unhealthy after                       | `backend.health_check.check_max_retries`         | 3              | template, per node             | in place                    |
| scaleway   | Health check      | Recheck interval while changing state | `backend.health_check.transient_check_delay`     | 0.5s           | template, per node             | in place                    |
| ovh        | Load balancer     | Size                                  | `loadbalancer.flavorId`                          | provider's own | template or location, per node | in place                    |
| ovh        | Gateway           | Gateway size                          | `gateway.model`                                  | S (200 Mbps)   | template, per node             | in place                    |
| ovh        | Listener          | Client idle timeout                   | `listener.timeoutClientData`                     | 300000 ms      | template, per node             | rebuild                     |
| ovh        | Listener          | Node idle timeout                     | `listener.timeoutMemberData`                     | provider's own | template, per node             | rebuild                     |
| ovh        | Listener          | Allowed client ranges                 | `listener.allowedCidrs`                          | none           | template, per node             | in place                    |
| ovh        | Pool              | Balancing method                      | `pool.algorithm`                                 | Round robin    | template, per node             | in place                    |
| ovh        | Health check      | Check type                            | `health_monitor.monitorType`                     | TCP            | template, per node             | rebuild                     |
| ovh        | Health check      | Check interval                        | `health_monitor.delay`                           | 5 s            | template, per node             | in place                    |
| ovh        | Health check      | Check timeout                         | `health_monitor.timeout`                         | 3 s            | template, per node             | in place                    |
| ovh        | Health check      | Healthy after                         | `health_monitor.maxRetries`                      | 3              | template, per node             | in place                    |
| ovh        | Health check      | Unhealthy after                       | `health_monitor.maxRetriesDown`                  | 3              | template, per node             | in place                    |
| ovh        | Health check      | HTTP check method                     | `health_monitor.httpConfiguration.httpMethod`    | GET            | template, per node             | in place                    |
| ovh        | Health check      | HTTP check path                       | `health_monitor.httpConfiguration.urlPath`       | /              | template, per node             | in place                    |
| ovh        | Health check      | Healthy status codes                  | `health_monitor.httpConfiguration.expectedCodes` | 200            | template, per node             | in place                    |
| ovh        | Health check      | HTTP check version                    | `health_monitor.httpConfiguration.httpVersion`   | 1.0            | template, per node             | in place                    |
| ovh        | Health check      | HTTP check host name                  | `health_monitor.httpConfiguration.domainName`    | provider's own | template, per node             | in place                    |
| cloudflare | Names             | Name length                           |                                                  | 12             | template, per node             | rebuild                     |
| cloudflare | Names             | Name prefix                           |                                                  | provider's own | template, per node             | rebuild                     |
| cloudflare | DNS record        | Record comment prefix                 | `dns_record.comment`                             | fcp            | template, per node             | in place                    |
| cloudflare | DNS record        | Answer addresses                      | `dns_record.settings.ipv4_only`                  | IPv4 and IPv6  | template, per node             | in place                    |
| cloudflare | DNS record        | Record tags                           | `dns_record.tags`                                | provider's own | template, per node             | in place                    |
| cloudflare | Origin rule       | Allow a node port override            | `origin_rule.action_parameters.origin.port`      | on             | template, per node             | in place                    |
| cloudflare | Request           | Pass the member's address to the node | `header_rule.action_parameters.headers`          | off            | template, per node             | rebuild                     |
| fastly     | Names             | Name length                           |                                                  | 12             | template, per node             | rebuild                     |
| fastly     | Names             | Name prefix                           |                                                  | provider's own | template, per node             | rebuild                     |
| fastly     | Service           | Service note                          | `service.comment`                                | origin edge    | template, per node             | new service version         |
| fastly     | Backend           | Host sent to the node                 | `backend.override_host`                          | The front name | template, per node             | new service version         |
| fastly     | Backend           | Prefer IPv6 to the node               | `backend.prefer_ipv6`                            | off            | template, per node             | new service version         |
| fastly     | Backend           | Node connect timeout                  | `backend.connect_timeout`                        | 1000 ms        | template, per node             | new service version         |
| fastly     | Backend           | Upgrade answer timeout                | `backend.first_byte_timeout`                     | 15000 ms       | template, per node             | new service version         |
| fastly     | Backend           | Most connections per Fastly server    | `backend.max_conn`                               | 200            | template, per node             | new service version         |
| fastly     | Backend TLS       | Lowest TLS version to the node        | `backend.min_tls_version`                        | provider's own | template, per node             | new service version         |
| fastly     | Backend TLS       | Highest TLS version to the node       | `backend.max_tls_version`                        | provider's own | template, per node             | new service version         |
| fastly     | Backend TLS       | Ciphers to the node                   | `backend.ssl_ciphers`                            | provider's own | template, per node             | new service version         |
| fastly     | Backend keepalive | TCP keepalive to the node             | `backend.tcp_keepalive_enable`                   | provider's own | template, per node             | new service version         |
| fastly     | Backend keepalive | Keepalive idle time                   | `backend.tcp_keepalive_time`                     | 300 s          | template, per node             | new service version         |
| fastly     | Backend keepalive | Keepalive interval                    | `backend.tcp_keepalive_interval`                 | 10 s           | template, per node             | new service version         |
| fastly     | Backend keepalive | Keepalive probes                      | `backend.tcp_keepalive_probes`                   | 3              | template, per node             | new service version         |
| fastly     | Request           | Pass the member's address to the node | `snippet.content`                                | off            | template, per node             | new service version         |
| fastly     | DNS records       | Record TTL                            | `dns_record.ttl`                                 | 1 s            | template, per node             | in place                    |
| fastly     | DNS records       | Record tags                           | `dns_record.tags`                                | provider's own | template, per node             | in place                    |
| fastly     | DNS records       | Flatten the front name                | `dns_record.settings.flatten_cname`              | off            | template, per node             | in place                    |
| fastly     | Certificate       | Certificate authority                 | `tls_subscription.certificate_authority`         | Certainly      | account default, per node      | rebuild                     |
| fastly     | Certificate       | Certificate                           | `tls_subscription.tls_domains`                   | One per front  | account default, per node      | rebuild                     |

## Adding an edge provider

Everything derives from the id tuple in `src/shared/contracts/edgeProviderIds.ts`; every
`Record<EdgeProviderId, …>` fails to compile until the new id has an entry:

1. `src/shared/contracts/edgeProviderIds.ts`: add the id.
2. `convex/lib/edges/accountSettings.ts`: the account settings zod schema, the placement
   schema (`EDGE_PLACEMENT_SCHEMAS`; empty for a provider not tied to a region) and the
   classification lists; `convex/lib/edges/locations.ts`: the `placeKey` of a placement;
   `convex/schema.ts`: the credentials, settings and `relayEdgePlacement` union variants. The
   credential test must work without a placement.
3. `convex/lib/edges/providers/templates.ts`: the template schema, field descriptors and
   defaults (every settable field of every resource the adapter creates is an option,
   § "Provider options"; options added later follow its hash rule); `providers/capabilities.ts`: the capability row (layer, role, address kind, transports,
   DNS roles, origin-port mode, `udp`, async and health flags, settle floor).
4. `convex/lib/edges/providers/<id>.ts`: the `EdgeProvider` adapter, registered in
   `providers/registry.ts`, with `<id>.test.ts` on the recording transport.
5. `convex/lib/edges/providers/wireContract.ts`: every endpoint the adapter calls; the table
   below is generated from it. `.github/workflows/edge-providers.yml`: add the id to the matrix.
6. `scripts/node-floor.mjs` when the adapter imports an npm dependency, and `'use node';` as
   the adapter's first statement; `src/client/lib/edgeProviderMeta.ts` for the account form.

## Adding a DNS provider

A **DNS provider** holds the records FCP writes for L7 fronts and fronts no member traffic
itself unless its account is set to DNS and fronting (capability `role: 'dns'`, mirrored in
`src/client/lib/edgeProviderMeta.ts`; the admin console lists it under "DNS providers" and the
Fastly form asks for one first; § "L7 edges"). Cloudflare is the only one today. The seam is the `DnsClient` interface in
`convex/lib/edges/providers/dns/types.ts`, which the Fastly adapter uses (through its
`dnsClientFor` factory) instead of any vendor SDK, and which the origin names of front nodes
(`nodeIntentOps.ts`) are written through:

- `createRecord`, `findRecordsByName`, `getRecord`, `deleteRecord` over A, AAAA and CNAME
  records in ONE zone. Every record carries the ownership `comment` marker (at most 100
  characters) that discovery proves ownership with; `findRecordsByName` is one request;
  `deleteRecord` is idempotent (a missing record is a success).
- `listCaa`, the apex CAA records as the zone itself holds them (a front location's CAA
  preflight reads CAA over public DNS instead, since records above the zone decide too).
- `readZone`, the zone as the credentials read it: a front location's check, and the reach
  check a credential rotation runs on every zone other accounts write through this one.
- `zoneId`, `zoneName` and `accountId` (the FCP account the credentials came from), recorded in
  every DNS ledger resource so cleanup acts on the zone the records were written into.

A new DNS provider needs: the id with its credentials and settings schemas (§ "Adding an edge
provider", steps 1 and 2; its placement names the zone, its catalog lists the zones its token
reaches), a `DnsClient` beside `cloudflareDns.ts`
(no transport retries, logging off, errors reduced to an HTTP status and a short code, never a
response body), a credential test that accepts every token kind the provider issues,
`role: 'dns'` and `providesDns: true` in its capability row, and `dnsClientFor` / the origin-name
writer choosing the client by the DNS account's provider instead of assuming Cloudflare. A
provider that can never front would also need the `EdgeProvider` front lifecycle made optional
for it; that split has not been needed yet.

**Cloudflare tokens.** FCP accepts both kinds Cloudflare issues. A user API token verifies at
`/user/tokens/verify`; an account-owned token is unknown there (`1000 Invalid API Token`) and
verifies at `/accounts/{account_id}/tokens/verify`, with the account id taken from the zone the
token reads, else from the account settings (`verifyCloudflareToken` in `cloudflareDns.ts`). A
token both endpoints reject is `token_rejected`; a retryable answer (429, 5xx, a timeout) is
never taken for a rejection. The zone reads, DNS writes and option discovery accept either kind
unchanged.

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

| provider   | method | path                                                                               | purpose                                                                                                                                               | source                                                                                                                                                                                                                                                               |
| ---------- | ------ | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| gcore      | GET    | `^/cloud/v1/loadbalancers/[^/]+/[^/]+$`                                            | list load balancers: credential test, region check, discovery by name, inventory                                                                      | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | POST   | `^/cloud/v1/loadbalancers/[^/]+/[^/]+$`                                            | create the load balancer with its TCP listener, pool and health monitor                                                                               | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | GET    | `^/cloud/v1/loadbalancers/[^/]+/[^/]+/[^/]+$`                                      | read one load balancer: describe, inspect, delete confirmation                                                                                        | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | DELETE | `^/cloud/v1/loadbalancers/[^/]+/[^/]+/[^/]+$`                                      | delete the load balancer (answers with a task)                                                                                                        | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | GET    | `^/cloud/v1/tasks/[^/]+$`                                                          | poll the create or delete task and read the resources it created                                                                                      | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | GET    | `^/cloud/v1/floatingips/[^/]+/[^/]+$`                                              | list floating IPs (inventory)                                                                                                                         | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | GET    | `^/cloud/v1/floatingips/[^/]+/[^/]+/[^/]+$`                                        | read a floating IP back after its delete                                                                                                              | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | DELETE | `^/cloud/v1/floatingips/[^/]+/[^/]+/[^/]+$`                                        | release the floating IP the load balancer held                                                                                                        | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | GET    | `^/cloud/v1/lbflavors/[^/]+/[^/]+$`                                                | list load balancer flavors (inventory, the location form)                                                                                             | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | GET    | `^/cloud/v1/projects$`                                                             | credential test without a location; the projects the key can see (location form)                                                                      | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | GET    | `^/cloud/v1/regions$`                                                              | location form: the regions the key can see                                                                                                            | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | GET    | `^/cloud/v1/networks/[^/]+/[^/]+$`                                                 | location form: private networks for a private VIP                                                                                                     | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| gcore      | GET    | `^/cloud/v1/subnets/[^/]+/[^/]+$`                                                  | location form: the subnets of those networks                                                                                                          | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                                                                                                          |
| upcloud    | GET    | `^/1\.3/account$`                                                                  | credential test                                                                                                                                       | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | GET    | `^/1\.3/zone$`                                                                     | location form: the zones                                                                                                                              | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | POST   | `^/1\.3/load-balancer$`                                                            | create the service with its TCP frontend and backend inline                                                                                           | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | GET    | `^/1\.3/load-balancer$`                                                            | list services: discovery by name and inventory                                                                                                        | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | GET    | `^/1\.3/load-balancer/plans$`                                                      | list the service plans (inventory)                                                                                                                    | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | GET    | `^/1\.3/load-balancer/(?!plans$)[^/]+$`                                            | read one service: describe, inspect, attachment check                                                                                                 | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | DELETE | `^/1\.3/load-balancer/(?!plans$)[^/]+$`                                            | delete the service (idempotent; re-issued until it answers 404)                                                                                       | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | POST   | `^/1\.3/load-balancer/[^/]+/ip-addresses$`                                         | delegate the floating IP to the service                                                                                                               | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | POST   | `^/1\.3/ip_address$`                                                               | allocate the floating IPv4 that is published                                                                                                          | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | GET    | `^/1\.3/ip_address$`                                                               | list IP addresses: unknown-outcome discovery and inventory                                                                                            | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| upcloud    | DELETE | `^/1\.3/ip_address/[^/]+$`                                                         | release the floating IP                                                                                                                               | https://developers.upcloud.com/1.3/ (Managed Load Balancer), 2026-09-16                                                                                                                                                                                              |
| scaleway   | GET    | `^/iam/v1alpha1/api-keys/[^/]+$`                                                   | credential test: the API key's default project (a location with no Project id creates there)                                                          | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs$`                                                         | list load balancers: credential test, discovery by name, inventory                                                                                    | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | POST   | `^/lb/v1/zones/[^/]+/lbs$`                                                         | create the load balancer over the already allocated IPs                                                                                               | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs/[^/]+$`                                                   | read one load balancer: the wait for a ready LB around every change, describe, inspect, delete confirmation                                           | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | DELETE | `^/lb/v1/zones/[^/]+/lbs/[^/]+$ ?release_ip`                                       | delete the load balancer without releasing its IPs                                                                                                    | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | POST   | `^/lb/v1/zones/[^/]+/ips$`                                                         | allocate a flexible IP (v4, and v6 when the template asks)                                                                                            | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/ips$`                                                         | list flexible IPs: discovery by tag and inventory                                                                                                     | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/ips/[^/]+$`                                                   | read a flexible IP back after its release                                                                                                             | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | DELETE | `^/lb/v1/zones/[^/]+/ips/[^/]+$`                                                   | release a flexible IP                                                                                                                                 | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | POST   | `^/lb/v1/zones/[^/]+/lbs/[^/]+/backends$`                                          | create the TCP backend pointing at the origin                                                                                                         | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs/[^/]+/backends$`                                          | list backends: discovery by name and inspect                                                                                                          | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/backends/[^/]+$`                                              | read a backend back after its delete                                                                                                                  | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | DELETE | `^/lb/v1/zones/[^/]+/backends/[^/]+$`                                              | delete the backend                                                                                                                                    | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | POST   | `^/lb/v1/zones/[^/]+/lbs/[^/]+/frontends$`                                         | create the frontend on the edge port                                                                                                                  | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs/[^/]+/frontends$`                                         | list frontends: discovery by name and inspect                                                                                                         | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/frontends/[^/]+$`                                             | read a frontend back: after its delete, and before it is saved again                                                                                  | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | PUT    | `^/lb/v1/zones/[^/]+/frontends/[^/]+$`                                             | save the frontend again with the fields it was read back with (a new address the outside check finds unreachable)                                     | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | DELETE | `^/lb/v1/zones/[^/]+/frontends/[^/]+$`                                             | delete the frontend                                                                                                                                   | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lbs/[^/]+/stats$`                                             | backend health for describe and inspect                                                                                                               | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| scaleway   | GET    | `^/lb/v1/zones/[^/]+/lb-types$`                                                    | list load balancer types (inventory)                                                                                                                  | https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/ via @scaleway/sdk-lb v1, 2026-09-16; https://www.scaleway.com/en/developers/api/iam/ (api-keys), 2026-10-22                                                                                      |
| ovh        | GET    | `^/1\.0/auth/time$`                                                                | server clock for the request signature (cached, unsigned)                                                                                             | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project$`                                                            | credential test without a location; the project ids (location form)                                                                                   | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+$`                                                      | credential test in a location and the project label in the location form                                                                              | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region$`                                               | location form: the regions of the project                                                                                                             | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/network/private$`                                      | location form: the private networks                                                                                                                   | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/network/private/[^/]+/subnet$`                         | location form: the subnets of a private network                                                                                                       | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/operation$`                                            | in-flight balancer operations: absence is never confirmed during one                                                                                  | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/operation/[^/]+$`                                      | poll the compound create operation                                                                                                                    | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | POST   | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer$`              | create the balancer with its network, floating IP and listener inline                                                                                 | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer$`              | list balancers: discovery by name and inventory                                                                                                       | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer/[^/]+$`        | read one balancer: describe, inspect, delete confirmation                                                                                             | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | DELETE | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer/[^/]+$`        | delete the balancer                                                                                                                                   | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/loadbalancer/[^/]+/stats$`  | balancer statistics (inspect)                                                                                                                         | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/loadbalancing/flavor$`                    | list balancer flavors (inventory, the location form)                                                                                                  | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/floatingip$`                              | find the floating IP the compound create minted, by its description marker                                                                            | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/floatingip/[^/]+$`                        | read a floating IP back after its delete                                                                                                              | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | DELETE | `^/1\.0/cloud/project/[^/]+/region/[^/]+/floatingip/[^/]+$`                        | release the floating IP                                                                                                                               | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/gateway$`                                 | find the gateway the compound create minted, by its FCP name                                                                                          | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | GET    | `^/1\.0/cloud/project/[^/]+/region/[^/]+/gateway/[^/]+$`                           | read a gateway back after its delete                                                                                                                  | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| ovh        | DELETE | `^/1\.0/cloud/project/[^/]+/region/[^/]+/gateway/[^/]+$`                           | delete the gateway the compound create minted                                                                                                         | https://api.ovh.com/console/ (/cloud/project/{serviceName}), 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/user/tokens/verify$`                                                  | credential test: the token is active                                                                                                                  | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/accounts/[^/]+/tokens/verify$`                                        | credential test: an account-owned token is active                                                                                                     | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones$ ?page&per_page`                                                | credential test (one page) and the account catalog (paged, up to 1,000): the zones the token reaches                                                  | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones/[^/]+$`                                                         | location check: the zone is readable, active and not paused (also a DNS account's zone read)                                                          | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/settings/(ssl\|websockets)$`                              | location check: zone encryption mode and WebSockets setting (recorded, not required)                                                                  | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/settings/(min_tls_version\|pseudo_ipv4\|ip_geolocation)$` | location check of a fronting account: lowest TLS version, Pseudo IPv4 and IP geolocation (recorded, never changed)                                    | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | POST   | `^/client/v4/zones/[^/]+/dns_records$`                                             | create the proxied record that IS the edge; also the ACME and traffic records a Fastly edge writes into this zone                                     | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/dns_records$ ?name.exact&per_page`                        | look one name up (unknown-outcome discovery, CAA preflight), including for a Fastly edge                                                              | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/dns_records$ ?page&per_page&proxied`                      | paged sweep of proxied records for the import inventory                                                                                               | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/dns_records/[^/]+$`                                       | read the record back: describe, inspect, import inspection, delete confirmation                                                                       | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | DELETE | `^/client/v4/zones/[^/]+/dns_records/[^/]+$`                                       | delete the record (a Fastly edge deletes its records here too)                                                                                        | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/rulesets/phases/http_request_origin/entrypoint$`          | read the origin-rules entry point (404 = none yet), and the rule an imported hostname already carries                                                 | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | PUT    | `^/client/v4/zones/[^/]+/rulesets/phases/http_request_origin/entrypoint$`          | bootstrap the entry point with our one origin rule, under the zone lock                                                                               | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/rulesets/phases/http_request_late_transform/entrypoint$`  | read the request-header Transform Rules entry point (404 = none yet), and the rule an imported hostname already carries                               | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | PUT    | `^/client/v4/zones/[^/]+/rulesets/phases/http_request_late_transform/entrypoint$`  | bootstrap that entry point with our one header rule (the member's address removed for one hostname), under the zone lock                              | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | POST   | `^/client/v4/zones/[^/]+/rulesets/[^/]+/rules$`                                    | add the destination-port origin rule or the hostname's header rule, recovered by its ref                                                              | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | DELETE | `^/client/v4/zones/[^/]+/rulesets/[^/]+/rules/[^/]+$`                              | delete the origin rule or the header rule                                                                                                             | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/ssl/certificate_packs$`                                   | certificate readiness for the minted hostname; a fronting account's location check reads the zone's wildcard                                          | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                                                                                                              |
| fastly     | POST   | `^/service$`                                                                       | create the VCL service (form encoded)                                                                                                                 | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service$ ?page&per_page`                                                        | paged service sweep for the import inventory                                                                                                          | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/search$ ?name`                                                          | discover the service by its deterministic name (404 = absent)                                                                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/details$`                                                         | active version: activation discovery, describe, import inspection, drift check                                                                        | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/domain$`                                                          | every domain a service serves (the import ownership boundary)                                                                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/service/[^/]+$`                                                                 | delete an exclusively owned service                                                                                                                   | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version$`                                                         | the version list: pick the draft, recognise a lost clone by its marker                                                                                | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/service/[^/]+/version/[^/]+$`                                                   | stamp the clone marker comment on the work version                                                                                                    | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/service/[^/]+/version/[^/]+/clone$`                                             | clone the active version for a shared teardown                                                                                                        | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/validate$`                                          | validate a version before activating it                                                                                                               | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/service/[^/]+/version/[^/]+/activate$`                                          | activate the version                                                                                                                                  | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/service/[^/]+/version/[^/]+/deactivate$`                                        | deactivate the active version before deleting the service                                                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/service/[^/]+/version/[^/]+/backend$`                                           | create the single origin backend, its port always sent (the API defaults it to 80) with the TLS name for SNI and verification                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/backend$`                                           | list backends: inspect and the import ownership check                                                                                                 | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/backend/[^/]+$`                                     | discover the backend by name; read it back after a destroy                                                                                            | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/service/[^/]+/version/[^/]+/snippet$`                                           | install the VCL snippet that hands an Upgrade request to the WebSocket path                                                                           | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/snippet/[^/]+$`                                     | discover the snippet by name; read it back after a destroy                                                                                            | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/service/[^/]+/version/[^/]+/domain$`                                            | add the fronted hostname to the draft version (an edge planned before versionless domains)                                                            | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/domain$`                                            | list the version domains: inspect, the import ownership boundary, shared-teardown confirmation                                                        | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/domain/[^/]+$`                                      | discover the domain by name; read it back after a destroy                                                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/domain/[^/]+/check$`                                | DNS readiness of the fronted hostname                                                                                                                 | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/service/[^/]+/version/[^/]+/domain/[^/]+$`                                      | remove only our hostname from a shared service                                                                                                        | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/domain-management/v1/domains$`                                                  | create the fronted hostname as a versionless domain linked to the service                                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/domain-management/v1/domains$ ?fqdn&fqdn_match`                                 | discover the versionless domain by its exact name                                                                                                     | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/domain-management/v1/domains$ ?service_id`                                      | the versionless domains linked to a service: inspect, inventory, import                                                                               | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/domain-management/v1/domains/[^/]+$`                                            | DNS readiness (still linked to the service); read it back after a destroy                                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/domain-management/v1/domains/[^/]+$`                                            | delete the versionless domain, after its certificate                                                                                                  | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/enabled-products/v1/websockets/services/[^/]+$`                                 | enable the WebSockets product on the service (idempotent)                                                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/enabled-products/v1/websockets/services/[^/]+$`                                 | discover the product state, on import too; read it back after a destroy                                                                               | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/enabled-products/v1/websockets/services/[^/]+$`                                 | disable the product last, after the service is gone                                                                                                   | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/tls/subscriptions$`                                                             | order the certificate for the fronted hostname, or once the account's shared wildcard (JSON:API)                                                      | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tls/subscriptions$ ?filter[tls_domains.id]`                                     | discover the subscription by domain (the hostname, or the zone's wildcard), and the certificate an imported hostname already has; confirm its removal | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tls/subscriptions/[^/]+$`                                                       | issuance state, what holds it up (the authorizations), the managed-DNS challenge, and when the shared certificate expires                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/tls/subscriptions/[^/]+$ ?force`                                                | delete the subscription (force, since its domain is enabled)                                                                                          | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tls/configurations$`                                                            | account form choices, and the CNAME target every fronted hostname points at                                                                           | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tokens/self$`                                                                   | credential test: the token scope                                                                                                                      | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/current_customer$`                                                              | credential test: the pricing plan (informational)                                                                                                     | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; Domain Management (versionless domains) and TLS authorizations re-read 2026-10-20; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |

## Deploy notes

**Per-account Cloudflare fronting** adds one optional field (`edgeProviderAccounts.frontsTraffic`):
one deploy, no freeze, no env change. `seedCutover` runs `edgeProviderAccounts:migrateDnsFronting`
(idempotent): every DNS account without the field takes the value the retired deployment-wide
switch `edge.l7.dnsProvidersFront` held (on or off; never set = off), so what fronts and what does
not stays exactly as it was, trust untouched, each audited as
`edge.provider_account.fronting_migrated`; then the switch's row is deleted. The Settings switch is
gone (a config patch naming it is ignored), and every account created from now on stores its
choice. A deployment that never turned the switch on fronts nothing through Cloudflare, before
or after. For an account set to DNS and fronting, after the deploy:

- new fronts get the header rule (§ "Cloudflare fronts"): its token needs edit on Transform Rules,
  or a new front stops at once with `header_rule_forbidden`. Fronts planned before have none and
  send `CF-Connecting-IP` until they are replaced;
- its zones' location checks also check what a front needs: test the account again, and a zone
  without a certificate for its wildcard (`edge_certificate_missing`) or whose CAA records allow
  none of Cloudflare's authorities (`caa_forbids_ca`) takes no new front until it is fixed and
  checked again. Fronts that exist are not touched.

To roll back, run `edgeProviderAccounts:restoreDnsFrontingForRollback` before deploying the older
build: it removes the field from every account (that build's schema refuses it) and writes the
switch back, on when any DNS account was set to DNS and fronting (the older build then lets every
DNS account front), off otherwise.

**Provider accounts** (CDN zones as locations) widen the schema only: an L7 account's zone
keys (Cloudflare `zoneId` / `zoneName`, a Fastly account's `dnsAccountId` and
`tlsConfigurationId`) become optional in its settings and appear on its location's
placement, locations gain `observed`, `observedAt`, `checkError`, `checkErrorDetail` and
`sharedCertificate`, and the `edgeProviderCatalog` table is new. `seedCutover` runs
`edgeL7Locations:migrate`: ONE transaction, idempotent, location ids unchanged. It moves each
L7 account's zone onto its `anycast` location (with the zone facts its last test read), moves
a Fastly account's `*.<zone>` shared certificate onto that location, and strips the legacy
keys; live edges are untouched (their intent froze their zone). Until it has run, a read
fallback serves the legacy keys (`lib/edges/l7Place.ts`), so no maintenance freeze is needed.
Check `edgeL7Locations:status` afterwards: `legacyAccounts` and `locationsWithoutZone` are 0
(`openRuns` is for information). Then test each CDN account again, so every zone records its
own check (the CAA verdict included). To roll back, run
`edgeL7Locations:unmigrate {"confirm":"restore-single-zone-settings"}` first: it puts each
single-zone account's keys, zone facts and shared certificate back on the account and drops
what an older schema refuses (the location check fields, the catalog); an account with a
second zone is reported, and must be cut back to one zone before the older build is deployed.
A rollback past provider options then runs `edgeProviderAccounts:purgeOptionsForRollback`. A
later release drops the legacy keys and the fallback.

**Fastly front VCL back to what compiles.** The previous deploy added `Fastly-WAF-Client-IP`
(with `Fastly-Temp-XFF`, `X-Client-IP`, `Client-IP` and `X-Cluster-Client-IP`) to the headers a
Fastly front removes. Fastly protects `Fastly-WAF-Client-IP`, so every front planned under it
failed to activate (`version_invalid`, after every retry, as `step_retries_exhausted`). This
deploy puts the list back to the five headers fronts activated with before, and a refused step
now fails the run on its own code at once: no schema change, no migration, one deploy. Fronts
built before that deploy carry exactly this list and need no replacing. Delete each front left
by a failed run under it (the run's attention names it), then build again. The member's address
still reaches the node in `Fastly-WAF-Client-IP` (§ "Provider options"): drop it in the node
role's Caddyfile, and ask Fastly support for a service-level way to stop it.

**Provider options** add optional fields only (`edgeProviderAccounts.optionDefaults`, pick and
run `options`, the edges' `choices`, `baseTemplateHash` and `learnedAddresses`, rotations'
`requestedOptions`): one deploy, no freeze. `seedCutover` copies each Fastly account's
certificate into `optionDefaults` and into its nodes' picks, keeping the copy under `settings`
(§ "Provider options", Migration); no template hash moves. Fronts planned after the deploy
keep the member's address from their node (`forwardClientAddress` off); a front activated
before keeps forwarding it until it is replaced: replace such fronts once, and check one as
§ "Provider options" describes. An activation run open across the deploy whose review
has a Fastly line reads as changed once (its line now names the certificate): read the
review again. To roll back, run `edgeProviderAccounts:purgeOptionsForRollback` first.

**Fastly certificates and domains** add optional fields only (`edges.waiting`,
`edgeProviderAccounts.sharedCertificate`, the Fastly settings `certificateScope` and
`domainModel`): one deploy, no migration, no freeze. Existing Fastly accounts keep one certificate per front and existing edges
keep their classic domains; edges planned after the deploy get versionless domains. After it,
test each Fastly account again (the CAA preflight runs only in the test) and switch an account
to the wildcard on its page when wanted (that untrusts its location until a test and a proven
front). The backend's resolver must reach public DNS for the CAA lookups.

**Locations cleanup** narrows what the locations release left optional: account settings hold
no placement keys any more, the moved account fields (`qualified`, `qualifiedTemplateHash`,
`qualification`, `autoQualifyHold`, `inventorySnapshot`, `inventoryAt`) and
`edgeSetupRuns.accountId` are gone, and so is the migration driver
(`seed:migrateEdgeLocations`, `seed:edgeLocationsStatus`; its `appState` marker stays, unread).
An edge of a placed provider (gcore, upcloud, scaleway, ovh) without its own placement is
refused at the provider call (`placement_missing`) instead of reading the account, and a
location's live edges are read by `by_location_status`. Convex validates every stored document
on push, so a row still holding a dropped value makes the push fail before anything changes.
The deploy goes under the maintenance barrier like the locations release, after a read-only
count shows zero for: accounts with a placement key in `settings`, accounts holding a moved
field, setup runs holding `accountId`, and edges of a placed provider without a placement that
are not destroyed or cancelled. Procedure: finish or cancel open setup runs, activations and
rotations; `edgeMaintenance:freeze {reason: 'locations-cleanup'}`; the quiescence counts and the
count above are zero; deploy; thaw. A deployment where the migration never ran (it never had
an account) needs nothing.

**Provider sets** add one optional field (`edgeRotations.requestedSpareEdgeId`, a replace's
named spare); everything else the series needs came with locations. One deploy, no migration,
no freeze. `seedCutover` schedules the location relabel (a read of each provider's region
names for locations still named after a bare region id). The pool cap moves to 16; an origin's
`desiredPublished` above 8 can only come from a set or a re-protect's temporary room.

**Provider locations** add `edgeLocations`, the location fields on `edges`, and the fields the
later releases of the series use (`edgeRotations.requestedLocationId`, `edgeSetupRuns.picks`,
`relays.providerSet` and `relays.cooling`, `panelActivationRuns.delivery`); the account's
placement and trust fields become optional. One deploy, under the maintenance barrier, because
`seedCutover` migrated the rows (`convex/edgeLocationsMigration.ts`, since removed). Six phases, each with its
own predicate, each paged and idempotent:

| Phase     | Work left while                                                                            | What it does                                                                                |
| --------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| locations | an account still holds placement keys with no matching location, or a CDN account has none | creates the location (placement, label, trust, default template, inventory) and the default |
| edges     | an edge with an account and no location                                                    | freezes its account's location onto it (`templateHash` untouched)                           |
| runs      | a setup run with an account and no `picks`, or a listener entry without a location         | fills `picks` and each entry's location                                                     |
| reviews   | a fronted approval entry with an account and no location                                   | adds the location to the stored review (its hash is never recomputed)                       |
| relays    | a node origin with edges and no `providerSet`                                              | the set of its edges' locations                                                             |
| cleanup   | an account still holding moved fields while none of its edges waits for phase 2            | clears them                                                                                 |

An account created after the migration never counts as work left. The marker
`appState edge:locationsMigration` is written only when every predicate is zero, and
`seedCutover` runs the driver while it is absent; an interrupted run resumes at the first phase
with work left. Before its first write the driver checks the barrier itself: with no legacy row
it only writes the marker; otherwise it needs the maintenance freeze (`needs_freeze`, nothing
written) and re-counts open work inside the mutation of its first write (non-terminal rotations
and setup runs, running fronted activations, edges inside a provisioning step;
`not_quiescent`, nothing written). Either answer was logged and the deploy still succeeded:
edges kept working through a fallback, where an edge without its own placement read the
account's (removed by the cleanup release above).

Procedure: finish or cancel every open setup run, activation and rotation; `edgeMaintenance:freeze
{reason: 'locations-migration'}`; check the counts are zero; deploy; `seed:edgeLocationsStatus`
shows every predicate at zero and the marker set (`seed:migrateEdgeLocations` re-runs the driver
after a `not_quiescent`); then thaw. If the migration or the checks fail, stay frozen and fix
forward: members keep being served. Both one-offs run through the deployer container
(`docs/beta-deploy.md` § "One-off functions"). The driver and both one-offs are gone since the
cleanup release above.

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
