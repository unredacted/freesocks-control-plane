# Edges

A **relay** is an ORIGIN that members reach only through something FCP can replace. The origin
can be a node on a panel FCP knows (a Remnawave node), a whole backend server (an Outline
instance), or an address the operator described by hand. An **edge** is what fronts it: any
frontable proxy. Today an edge is one of two **layers**:

- **L4**: a provider-managed cloud load balancer that forwards a TCP port to the origin. The
  origin terminates its own protocol (REALITY, TLS, plain); the edge is an address.
- **L7**: a CDN front that terminates TLS and HTTP and forwards an HTTP-carried transport
  (WebSocket, HTTP Upgrade, gRPC) to the origin. The edge is a **hostname** under an
  operator-owned zone; the CDN's own certificate and anycast addresses serve it.

Censors block the edge's public address or hostname, not the origin, so the edge is the unit
that gets replaced. What an origin speaks is described per **listener** (a port + protocol /
stream transport / security); the listener decides what the renderer rewrites in a member's
connection and which layers can carry it. Delivery is **edge-required**: a subscription
covered by a relay is served a rendered body or an unavailable response, never the origin
body. This document describes how FCP registers origins, provisions, publishes, rotates and
observes edges, and the contract the node role (Ansible) follows. It is provider-neutral on
purpose: nothing here says which providers, regions, zones, targets or names a given deployment
uses.

Admin surface: **Admin → Edges** (`/admin/edges`) and `/api/v1/admin/edges/*`; probe
telemetry lives under **Admin → Telemetry → Probes** (`/admin/telemetry/probes`). Every request
under the API prefix is HPKE-sealed by verb class (see [Sealing](#sealing)).

## Model

| Concept          | Table                  | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Provider account | `edgeProviderAccounts` | One cloud or CDN account: write-only credentials, fixed settings (project/region/zone/network, or the DNS zone for an L7 provider), priority, a daily allocation budget, a live-edge cap, `qualified`. An L7 provider whose hostnames' DNS lives elsewhere names a **DNS account**.                                                                                                                                                                        |
| Edge template    | `edgeTemplates`        | Per provider (optionally per account): the full provisioning parameters, validated by the adapter's schema. Provisioning records the template hash; L7 edges also freeze the effective parameters into their intent.                                                                                                                                                                                                                                       |
| Relay            | `relays`               | One ORIGIN behind edges: its `origin` (kind + panel/node or backend server), `originAddress` (what edges dial; never published), `hostMode` (who writes the client-facing panel Hosts), published pool, publication epoch, rotation limits, detector state, quarantine, `probeNode`, the L7 qualification credential.                                                                                                                                      |
| Listener         | `relayListeners`       | One port the origin answers on: `protocol / streamTransport / security` (the catalogue below), server names (REALITY SNIs or certificate names) with retire/drain, an optional REALITY target, HTTP transport parameters, `originTransport` (how an L7 front dials it), a **match rule** (how its template entry is found in a body), the panel inbound it maps to, the panel Host FCP owns for it, `source` (role or admin) and a canonical `configHash`. |
| Edge             | `edges`                | One provider resource bound to a LISTENER: its layer, the resource-step ledger, child resources, addresses (IP literals for L4, the hostname for L7), publication state and pool index, health, readiness, front qualification, live snapshot, reachability. L7 edges carry a frozen **provision intent**.                                                                                                                                                 |
| Rotation         | `edgeRotations`        | One provision / publish / replace run: phase, step version, operation claim, per-listener Host plan, previous binding, live event log; its audit trail is assembled on read.                                                                                                                                                                                                                                                                               |
| Delivery binding | `edgeDeliveryBindings` | The edge-required policy a relay imposes on the subscriptions of its node or backend server, kept apart from the relay row so deleting the relay never silently restores raw delivery.                                                                                                                                                                                                                                                                     |
| Probe target     | `probeTargets`         | An operator-entered public host:port probed alongside the derived targets (edges, relay origins). Operator evidence only.                                                                                                                                                                                                                                                                                                                                  |
| Probe run        | `probeRuns`            | One reachability measurement of one target address from one source.                                                                                                                                                                                                                                                                                                                                                                                        |
| Reachability     | `probeReachability`    | Per target, per country, per source, per address family: the last run's vantage counts and verdict; summarised onto the target's own row.                                                                                                                                                                                                                                                                                                                  |

The supported providers are listed in `src/shared/contracts/edgeProviderIds.ts`; each has an
adapter under `convex/lib/edges/providers/` implementing `EdgeProvider`. Generic code never
branches on a provider id; it reads `EDGE_PROVIDER_CAPABILITIES` (`layer`, `addressKind`,
`l7Transports`, `needsDnsAccount` / `providesDns`, `originPortMode`, `udp`, the async and
health flags) and the adapter's template schema.

### Origins and Host modes

`relays.origin` is one of:

| Kind             | What it is                                   | Subscriptions render?                      | Panel Hosts                                                  |
| ---------------- | -------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------ |
| `panel-node`     | a node on a panel FCP knows (node pinning)   | yes (pinned node)                          | `fcp` when the backend has Host management, else `none`      |
| `backend-server` | a whole backend server (an Outline instance) | yes (single-key delivery, address rewrite) | `none`                                                       |
| `manual`         | an address the operator described by hand    | no (nothing FCP serves maps to it)         | `none`; the operator wires clients from the `connectionPlan` |

`hostMode` says who writes the client-facing Hosts: `fcp` (FCP creates, flips and deletes
them through a persisted state machine, see **Host ownership**), `operator` (FCP never writes;
the by-slug response carries a `hostsPlan` to apply) or `none` (there is no Host). The
handoff is explicit: `fcp → operator` keeps every Host and marks it `adopted`; `operator →
fcp` needs every listener's Host validated and adopted first (`edge.host_adopt_required`).
One relay per node, one per whole server (`edge.node_already_bound` /
`edge.server_already_bound`); `originAddress` cannot change while edges dial it
(`edge.origin_address_locked`), the origin kind never changes (`edge.origin_kind_locked`), and
an address that is a published edge is refused as an origin (`edge.origin_is_edge`).

### Listener catalogue

A listener speaks one valid combination of three fields (`src/shared/contracts/edgeProtocolIds.ts`):

| protocol             | streamTransport               | security  | notes                                                             |
| -------------------- | ----------------------------- | --------- | ----------------------------------------------------------------- |
| `vless`              | `raw`                         | `reality` | REALITY: `realityTarget` + server names required                  |
| `vless`              | `raw`                         | `tls`     | server names = the certificate's                                  |
| `vless`              | `ws` / `httpupgrade` / `grpc` | `tls`     | L7-frontable (the only authenticated L7 proof)                    |
| `vless`              | `xhttp`                       | `tls`     | L7-frontable where the provider carries it; no sing-box (below)   |
| `trojan`             | `raw` / `ws`                  | `tls`     | L4 only (no L7 proof)                                             |
| `shadowsocks`        | `raw`                         | `none`    | address/port rewrite only; Outline keys are `ss://`               |
| `hysteria2` / `tuic` | `udp`                         | `tls`     | registers, but no provider forwards UDP today (`no_udp_provider`) |

Anything else is `invalid_combination`. The catalogue derives `usesSni`, `needsTarget`,
`isHttpTransport`, `usesHostHeader`, `transport` and `l7Proof`; `convex/lib/edges/protocols.ts`
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
in its `Referer`), the one mode every CDN passes; an inbound declared `stream-up` or
`stream-one` refuses packet-up uploads, so its proof reports `transport_failed` / `mode` and it
stays L4-only. `transportParams.mode` records what the inbound declares (`auto` when it declares
nothing). It is only behind a real certificate: there is no `xhttp` + `reality` combination.

A deployable inbound (Caddy terminates TLS in front of it, as for WebSocket, so Xray listens on
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
on its own, and needs `flush_interval -1` only when the inbound sets `noSSEHeader`. This
template has not been run behind Caddy yet; the proof above was validated against Xray
terminating TLS itself (the front-qualification harness).

**Discovery.** A panel-node relay's listeners can be derived from the node instead of typed:
`backends.listNodeInbounds` (capability `inboundDiscovery`; Remnawave: the node's active config
profile joined with the profile's Xray `inbounds[]` by tag, allowlisted fields only, never
clients, private keys, short ids or certificates; `docs/backends.md`) yields `PanelInbound[]`,
and the pure `mapInboundsToListeners` (`convex/lib/edges/inboundMapping.ts`) turns each into a
registration-shaped listener candidate or an `unsupported` row with a reason from
`INBOUND_UNSUPPORTED_CODES` (`inactive`, `tag`, `protocol`, `transport`, `security`,
`invalid`; worded in `src/client/lib/edgeCodes.ts`). vless / trojan / shadowsocks map; tcp or raw
→ `raw`, ws / httpupgrade / grpc / xhttp (`splithttp`) → themselves (kcp, quic are `transport`); REALITY
`dest`/`target` + `serverNames` → `realityTarget` + `tlsNames`; TLS `serverName` → `tlsNames`
(none = `needsName`: the operator supplies one before registering); ws / httpupgrade / xhttp
path + host, the xhttp mode and gRPC serviceName → `transportParams`; the inbound tag + profile uuids → `panelBinding`
with the default `remark` match rule. Every candidate passes `validateListenerSpec`, and carries
`layers` and `formats`. The listener key is `slug10 + base36(sha256(tag))[0..6]` (the first ten
lowercase alphanumerics of the tag plus six hash digits; at most 16 chars, deterministic, unique
against the relay's existing keys). `originTransport` is never set by the mapper: only the
**origin probe** can say how an L7 front may dial the node. `GET
relays/inbound-candidates?backendServerId=&nodeUuid=` (throttled; `convex/edgeOriginProbe.ts`
with the `"use node"` sockets in `edgeOriginProbeOps.ts`, pure rules in
`lib/edges/originProbe.ts`) returns the mapper output with `originTransport` filled where the
probe succeeded and `layers` recomputed: security `none` -> a TCP answer on the port gives
`{scheme: http}` (L7-only); `tls` -> a handshake with SNI = the first name, `certPublic` = the
chain verifies against the system store, `certNames` = the leaf's names, `acceptsHostHeader:
names` unless a request with a foreign Host header still answers 2xx (`any`). Like the internal
reachability probe it dials public literals only (a name is resolved first, every answer must be
public, the literal is dialled). Without a successful probe the candidate stays L4-only and
carries the probe's reason.

### Layers

`listenerLayers(listener)` (`convex/lib/edges/layers.ts`) decides which layers can carry a
listener from the **complete** member-to-origin chain, never from the protocol name alone:

| Listener                                                                                                                                                                          | L4                                   | L7  |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | --- |
| No origin transport declared: raw TCP to the inbound                                                                                                                              | yes                                  |     |
| Origin speaks plaintext HTTP behind the CDN (`originTransport.scheme = http`), HTTP transport                                                                                     |                                      | yes |
| Origin speaks HTTPS, `vless` HTTP transport, certificate publicly trusted AND every active name covered by a certificate name (RFC 6125) AND the node accepts those names as Host | yes                                  | yes |
| Origin speaks HTTPS, non-vless HTTP transport (no authenticated proof: `l7_proof_unsupported`)                                                                                    | yes                                  |     |
| Origin speaks HTTPS, `reality` / raw `tls` / `none`                                                                                                                               | yes                                  |     |
| UDP listener                                                                                                                                                                      | only with a provider declaring `udp` |     |

`hostTargetFor(edge, proto, selectedSni)` is the single source of the Host tuple the panel
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
transport exactly as deployed, then a VLESS request for the relay's qualification credential
fetching a neutral `204` target). Only a `vless` HTTP-transport `tls` listener has such a proof
(`l7Proof: 'vless'`); every other combination is `unsupported_protocol` and never L7-fronted.
The result is stored with its **binding** (hostname, listener id + revision, the three
protocol fields, transport parameters, intent hash) and an expiry
(`edge.l7.qualificationTtlMinutes`); publication re-derives the binding inside the mutation
and refuses `front_unqualified` / `front_qualification_stale`. The reconcile cron re-qualifies
published L7 edges before their qualification expires.

**Affected-country evidence**, **observed zone facts**, **renewal**, **failed requalification**
and **importing a front** work as before (per listener instead of per slot/profile).
`edge.l7.autoSelect` (default off) governs automatic selection of L7 accounts; manual
provisioning and publishing work regardless.

### Publication

Provisioning and publication are separate. An edge is `unpublished` (a standby), `published`
at a **pool index**, or `draining`. A relay's `publishedEdgeIds` is ordered by pool index and
is ONE relay-wide order for the subscriber PRF, whatever listener each edge serves.
`publicationEpoch` bumps on every change that alters what subscribers should receive (pool,
listener, names, switch) and is part of the cache token of the fronted subscription route.

**Per-listener template edge.** An edge is bound to one listener and can serve only that
listener's protocol and port, so each listener has its own `templateEdgeId`: its lowest-index
published edge. The listener's panel Host (`fcp`), its `hostsPlan` row (`operator`) and its
`connectionPlan` row all derive from that edge; a listener with no published edge is
unavailable. Replacing an edge re-plans **only the listeners whose template edge it is**
(`hostPlan[].listenerKey`), and a direct publish that would make an edge its listener's
template edge under `fcp` is refused (`edge.needs_rotation`): the rotation machine does the
flip.

**Coverage.** The pool exists to give every deployed, enabled, non-retired listener ("coverage
listener") a published edge, so capacity follows the listeners (`convex/lib/edges/poolCapacity.ts`):
`ensurePoolCapacity` raises `desiredPublished` to the coverage-listener count (bound 1..8,
`MAX_DESIRED_PUBLISHED`; the node role's PUT and the admin create answer `warnings:
['edge.pool_raised']` when it did) on every registration, admin listener add and listener
re-enable, and the reconcile cron applies it each tick. A pool that is already FULL while a
listener is uncovered is **expanded** within the cap (`desiredPublished = min(8, published +
uncovered)`, audited `edge.pool_expanded`); it is never shrunk. The cap is enforced where the
operator can act on it rather than clamped silently: a listener body (the role's PUT or the
CMS upsert) that would leave more than eight deployed, enabled listeners is refused
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

**Deferred binding and setup ownership.** A relay a guided setup creates is inserted with
`bindingDeferred: true` + `setupOwned: true` (internal arguments of `relays.create`; a request
body never sets them): no delivery binding is written, so the origin keeps serving its raw body,
and there is NO shortcut that binds it when an edge publishes. Only `claimDeliveryBinding`
(the go-live step; not routed yet) upserts the binding, bumps its policy version, refreshes the
mirrors and clears the flag. A by-slug registration always binds at once; a re-registration of a
deferred relay keeps it deferred. While `setupOwned`, reconcile upkeep and the detector's
automatic replacement (veto `setup_owned`) leave the relay alone, whatever the run's state. A rotation start of any kind on an owned relay that does not come from the run itself (`setupRun`) is refused (`edge.setup_owned`): a manual publish, replace or burn would change the endpoint under the run's hides and rehearsal.
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
ports. Refusal code `edge.unverified_endpoint`. The record proves nothing by itself:
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
in this stack, and panel online bits do not identify the path a member used.

Consequences, applied consistently: a **replace** of an L4 edge switches ONLY to an
already-tested spare of the same listener; with none the start is refused
(`edge.no_verified_spare`, not waived by `force`) instead of provisioning a doomed candidate
(the L7 path is unchanged: a listener that can be fronted at L7 with L7 selection allowed keeps
provisioning and proving a new front). A `provision` run that would publish an untested L4
edge ends with it as a **spare** instead (`unverified_standby`, attention `spare_untested`),
never failed and never destroyed; reconcile upkeep skips such a spare and does not provision
another. The detector records the refusal on the relay's suspicion (`lastRotateError`) and
attention raises **`needs_test`** (critical). Importing a live front with `publish: true`
carries the operator's statement `verified: true` (recorded as method `named_connection`);
without it the import is an untested spare.

**The test link** (`POST edges/{id}/test-link`, `convex/edgeTestLinks.ts`, throttled) (`POST edges/{id}/test-link/release {credentialId}` expires the temporary credential behind a link when the card closes or finishes, instead of at its TTL) is the one
verification mechanism for an L4 candidate that is not yet published (setup stage 4b, spares,
retests). It fetches the test credential's OWN subscription body and runs the real renderer with
`published = [this candidate only]` in dry-run: no pool change, no epoch bump, no Host write, no
snapshot, no persisted match rule touched. Before first publication the FCP Host does not exist
in that body, so the builder uses a **test-only matcher**: the intended inbound
(`panelBinding.configProfileInboundUuid`) names the enabled panel Hosts on it at
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

**Test credentials** (`convex/edgeTestCredentials.ts`). Remnawave tests reuse the relay's
**qualification credential**, minted on demand through `relayQualification.ensure`: a
**persisted operation** (`relays.qualificationMint`) whose deterministic username is written
BEFORE any panel call, so a crash between `issueUser` and `store` is settled on the next call by
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
   (the panel Host remark `<node>-relay-<listenerKey>` and any adopted legacy remarks),
   `address` (the entry's host:port equals `originAddress:originPort`) or `whole-body` (a
   single-entry body such as an Outline key). The entry must AGREE with the listener (its
   security / transport parameters) or it is `entry_mismatch`; an unknown scheme is
   `entry_unsupported`; two candidates are `ambiguous_match`. Overlapping rules on one relay
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
   families get one named auto group, link-list families get labelled Primary/Backup entries.
   An L7 edge renders as ONE entry (its hostname). A backend that hands out a single access
   key (Outline) renders in **single-key** style: one entry, no backup, no auto group;
5. checks every outgoing entry, emitted AND retained, against the origin address
   (`leak_detected`), and persists an **eligibility snapshot** (`subscriptions.lastRender`:
   epoch, family, resolved listeners, primary/backup edge) that the member's connection labels
   and report attribution read: they never reconstruct an assignment without the body.
   Attribution names an edge ONLY from that snapshot (current epoch) and covers unpinned
   whole-server subscriptions (Outline); no snapshot leaves the report at origin level.

**Edge-required delivery.** A subscription whose resolved place (the node the body was pinned
to, else its backend server) is covered by an active delivery binding is served the rendered
body ONLY when the render produced ≥1 endpoint and passed the leak check. Otherwise the route
answers **HTTP 503 with `Retry-After`** and a reason (`unsupported_format`, `no_match`,
`ambiguous_match`, `entry_mismatch`, `empty_pool`, `leak_detected`, `render_disabled`,
`relay_disabled`, `relay_missing`, `no_render_key`); a 503 keeps the client's last
configuration, an empty 200 would wipe it. The policy is judged AFTER the fetch against the
node the body actually belongs to, so a first fetch without a stored pin and a pin that moved
onto a relay node are both classified correctly. Only bodies that passed are cached (the cache
token is `<bindingPolicyVersion>:<epoch>`). A place no relay covers passes the body through.
Registering a relay therefore takes members on that origin dark until an edge is published and
rendering is on; the setup flow and the node role say so.

**Delivery rehearsal** (`convex/edgeRehearsal.ts`, the guided setup's stage before go-live).
Before the binding is claimed, delivery is proven with the real renderer over **cohorts** derived
from authoritative membership (`convex/lib/edges/cohorts.ts`: one representative subscription per
distinct `backendPlacement` among the subscriptions pinned to the node, walked with `paginate`
over every page; a backend-server origin is one cohort of the whole server), never from render
snapshots. Each representative body is fetched FRESH per supported format (links, sing-box,
Clash, through catalogued client user agents) and run through `applyEdgeRender` in dry-run: no
persistence, no snapshot. Every non-dark cohort must yield `serve` in every format; an approved
dark cohort (`darkCohortKeys`) is excluded. An empty panel node is rehearsed from the rehearsal
credential (the qualification user on the node's placement; no usable placement ->
`choose_mode`); an Outline server with members from its real single-key subscriptions. The
result lists `familiesDisabled` (render rules off) and `proofsExpired` (published L7 fronts
whose proof lapsed), the **vector** the go-live mutation compares with `vectorNow`
(`listenerRevisions`, `renderConfigHash`, `publicationEpoch`, `qualificationEvidenceIds`), and
the **observation boundary**: the panel Hosts are listed before and after
(`edgeHostHides.observe`), the run is accepted only when both listings agree (else repeated, 3
attempts, then `listingChanged`), and the FINAL listing is the observation the go-live clock
starts from.

Mirrors follow the same policy: each mirror row records what its object holds (`validated`:
policy version, epoch, edges); registering a relay revalidates the origin's mirrors, replacing
a raw object with a fresh render or, when nothing can render, with an **unavailable stub**
(the URL is already distributed, so the object itself must stop serving the origin). The
account view and the issuance responses hand out ONLY the fronted token URL for a covered key
(`edgeRequired`); an Outline member imports a dynamic access key
`ssconf://<fcp-host>/api/v1/sub/<token>` and follows rotations by re-fetching. Outline over an
edge is **TCP-only** today (no adapter forwards UDP).

## Operations

| Operation                                 | Precondition                                                                                                                                                                                                                                                                                         | Spends budget                      | Writes Hosts                                                                  | Result                                                                                                                                    |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Register relay (role PUT / admin)         | origin + listeners in one body                                                                                                                                                                                                                                                                       | no                                 | no                                                                            | relay + listeners upserted; an identical body changes nothing; the origin's subscriptions become edge-required                            |
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

| Route                                                            | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET setup-status?relay=<slug>` / `POST setup-status {draft}`    | **Relay-scoped** readiness: nine steps (origin, account, template, relay, edge, qualification, publish, rendering, automation), each `done / ready / blocked / skipped` with blockers and warnings as codes, the selected context, `currentStep` and `roleVars` (public values only: never a token or an address). A draft (origin + listener triples) is judged before the relay exists. Without either, the fleet aggregate plus the relays whose setup can be resumed. Manual origins skip `rendering`.                                                                                                                                                                                 |
| `POST relays/{id}/test-provision`                                | The bootstrap path: ordinary selection excludes unqualified accounts, so a fresh account could never get its first edge. Explicit `{accountId, templateId?, listenerKey}`; the account must be enabled and **tested** but may be unqualified; budgets, capacity and layer compatibility apply; the result is always unpublished. Audited `admin.edge.test_provision`.                                                                                                                                                                                                                                                                                                                      |
| `POST relays/{id}/preflight`                                     | Dry run of `provision / publish / replace / test-provision`: every guard a real start applies (the FIRST blocker is the code the start would throw), the selection the machine would make, plan-phase refusals that need no adapter, and delivery warnings (`render_disabled`, `members_dark`, ...). Writes nothing.                                                                                                                                                                                                                                                                                                                                                                       |
| `GET edges/{id}/verification-binding` + `POST edges/{id}/verify` | The L4 endpoint test. The GET returns `{endpoint, listenerKey, listenerRevision, configHash}` (plus whether the gate would pass once confirmed) exactly as the confirmation must echo it; the POST (relay-write scope) recomputes the binding from the live rows and refuses a mismatch (`edge.verification_stale`) rather than stamping a configuration the operator did not see. Records `edges.verification` (`method: test_link` from the isolated test link, `named_connection` for retesting a published address by its `<node>-relay-<key>` connection) and audits `edge.verified` (ids and the listener key only). L7 edges refuse: their authenticated proof is the verification. |
| `GET attention`                                                  | Server-ranked list, one action per item: quarantine, needs operator, unsettled Host op, **members dark** (edge-required place with nothing to serve), failed or rolled-back rotation, lapsed front qualification, block suspected, unreachable edge, pool below desired, account untested or unqualified, drift, maintenance frozen; plus the three endpoint-verification cards: **needs_test** (critical: the relay is suspected and its automatic replacement has no tested spare), **retest_needed** (a confirmation went stale after a listener or address change) and **spare_untested** (an active unpublished L4 edge never confirmed), each with the one action `verify_endpoint`. |
| `GET relays/{id}/quarantine` + `POST .../quarantine/inspect`     | The resolver view: per listener the previous and the current binding as Host tuples; `inspect` (throttled) fills the live column from the panel and says which one it matches. `resolve-quarantine` records a `reason`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `GET relays/{id}/timeline`                                       | Merged audit rows of the relay, its listeners, its non-destroyed edges and its rotations, newest first, capped.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `GET providers/usage`                                            | Per account: live / max edges, allocations against the daily budget, published / standby / draining; per relay desired against published; totals including what auto-provision would add.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `GET relays/lookup?slug=`                                        | The full admin view of one relay by slug (the per-relay page is addressed by slug).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `POST relays/{id}/listeners/{key}/adopt-host`                    | The `operator` to `fcp` handoff: the named Host must exist, carry the listener's inbound and dial a published edge of that listener (`edge.host_adopt_mismatch` otherwise). `hostMode: fcp` is refused until every listener Host is adopted (`edge.host_adopt_required`).                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `GET maintenance`, `POST maintenance/freeze`, `.../thaw`         | The maintenance switch (see below).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `GET delivery-bindings`, `POST delivery-bindings/{id}/release`   | The edge-required places, including ones whose relay was deleted with `keep-dark`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `GET config`                                                     | Also carries `bounds` and `defaults` per flat key, so the settings forms validate against the server's own limits.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `POST relays/{id}/rebalance`                                     | Coverage at the cap: unpublish ONE duplicate (a published edge that is not its listener's template edge, highest pool index first) back to standby, bump the epoch, refresh mirrors; upkeep then publishes the uncovered listener. Refuses `edge.no_duplicate`, and the usual rotation / quarantine guard. Audited `edge.relay.rebalanced`.                                                                                                                                                                                                                                                                                                                                                |
| `POST automation {on}`                                           | The one automation switch (settings scope): in ONE mutation sets `edge.enabled`, `edge.autoRotate`, `edge.probe.enabled` and `edge.autoProvisionToDesired` to `on`, and `edge.standbyPerListener = 1` when turning on (left as-is when off). Never `render.enabled` or `l7.autoSelect`; touches no relay row (a relay's own `autoRotate` keeps its meaning under the global gate: `cfg.enabled && cfg.autoRotate && relay.autoRotate`). Audited `edge.automation.set` (the boolean only).                                                                                                                                                                                                  |
| `POST setup-runs/plan {backendServerId, nodeUuid}`               | The guided setup's read-only plan for one panel node (throttled: it lists the node's inbounds and Hosts): frontable inbounds, direct Hosts tagged covered / uncovered, compatible accounts with reasons, the fleet-wide rendering consequence, disabled client families, and the `planHash` a run creation must echo. See § "Guided setup runs".                                                                                                                                                                                                                                                                                                                                           |
| `POST setup-runs`, `GET setup-runs[/{id}]`                       | Create a run (`{backendServerId, nodeUuid, accountId, planHash, approvedHideUuids[], keepDirect?}`; `edge.plan_stale`, `edge.account_incompatible`, `edge.too_many_inbounds`, `edge.setup_run_active`), list runs, poll one (stage, state, the interruption, per-listener verdicts, the `try_it` test links).                                                                                                                                                                                                                                                                                                                                                                              |
| `POST setup-runs/{id}/{cancel\|retry\|continue}`                 | The three operator verbs on a run: cancel (before publish deletes the relay `restore-direct`; between publish and go-live starts the restore workflow with purpose `cancel_setup`; after go-live refused), retry (re-enters the current stage under a new generation; `{tryAnotherAddress}`, `{acceptPartial}`, `{accountId}` answer the card's secondary buttons), continue (`{confirmations[]}` forwards each `try_it` tick to `POST edges/{id}/verify`; `{approvedHideUuids[]}` replaces the consent after `review_changed`; `{keepDirect}` finishes unbound).                                                                                                                          |
| `POST relays/{id}/require-edges`                                 | The only path besides a run's go-live to a deferred relay's binding: the SAME activation policy. Every published L4 edge without a current confirmation comes back as `pending[]` (the node page renders the `try_it` card) instead of a binding; with nothing pending the run starts at the rehearsal and goes live through stage 8. Refuses `edge.not_deferred`, `edge.coverage_incomplete`, `edge.setup_run_active`, `edge.busy`, `edge.quarantined`.                                                                                                                                                                                                                                   |
| `POST edges/{id}/test-link`                                      | The isolated test link for an L4 candidate (throttled: fetches the test credential's body and the panel Hosts): the candidate connection only, plus the binding the confirmation must echo. See § "Publication".                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `GET relays/inbound-candidates?backendServerId=&nodeUuid=`       | Discovery with the origin probe applied (throttled): the node's inbounds as listener candidates, `originTransport` filled where probed, `unsupported` with reasons. Registers nothing. See § "Listener catalogue".                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

### Guided setup runs (Autopilot)

`convex/edgeSetupRuns.ts` (table `edgeSetupRuns`) + `convex/edgeSetupPlan.ts`. An operator
protects a panel node by answering two questions (which node, which account), confirming each
new L4 address once from a real client, and pressing Go live; FCP does everything else. ONE
authoritative stage machine, every stage idempotent and re-enterable:

| #   | Stage               | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Members download    |
| --- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| 1   | `prepare`           | registration admitted; account tested, enabled and offered by the plan; `relays.create` with every frontable listener, `deferBinding` + `setupOwned`, `autoRotate: true`, `desiredPublished = max(default, required)` (bound 8). A relay a previous run left owned is reused at its recorded `setupStage` only while its listeners still match what the new plan discovered (same keys, same canonical hash, no extra deployed listener); otherwise `edge.plan_changed` and the operator removes protection first. Switching the account (`retry {accountId}`) is allowed only before anything is published (`edge.account_switch_late`); candidates of the old account are cancelled, never re-labelled. | raw origin body     |
| 2   | `credential`        | `relayQualification.ensure` for an L7 listener (`qualification`) or an EMPTY panel node (`rehearsal`); an empty Outline server is `use_manual_setup`; a placement problem is `choose_mode`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | unchanged           |
| 3   | `provision`         | per required listener without a live candidate: ONE mutation starts `provision` (`publishOnDone: false`, `requestedAccountId`, `allowUnqualified`) AND records `expect`; a live unpublished edge on the listener is reused. `edge.busy` / `edge.concurrency` wait and poll; `edge.maintenance` asks the operator                                                                                                                                                                                                                                                                                                                                                                                          | unchanged           |
| 4   | `verify`            | per standby: outside probes (`trigger: 'qualification'`) + the internal shape run, judged by `partialRungFor` (`partial` is the L4 ceiling); L7 runs the front proof. `unreachable` (or a timeout) asks the operator (`address_unreachable`: try another address, or accept partial)                                                                                                                                                                                                                                                                                                                                                                                                                      | unchanged           |
| 4b  | `try_it`            | one isolated **test link** per L4 endpoint lacking a current confirmation (`edgeTestLinks.build`; a published address gets a named-connection retest instead); the card's ticks echo `{edgeId, endpoint, listenerRevision, configHash}` into `edgeVerification.confirm` (`edge.verification_stale` rebuilds the card). Skipped when every listener is L7                                                                                                                                                                                                                                                                                                                                                  | unchanged           |
| 5   | `publish`           | per required listener: `publish` rotation (`admission: 'setup.complete'`, so a freeze declared meanwhile does not strand admitted work) through the UNCHANGED gate; `pool_full_standby` = `coverage_incomplete`; quarantine = `quarantined`. `keepDirect` finishes `done_unbound` here                                                                                                                                                                                                                                                                                                                                                                                                                    | direct AND FCP Host |
| 6   | `hide_direct_hosts` | every L4 confirmation re-checked (stale = back to the card); `edgeHostHides.hide` with the EXACT approved uuids; an uncovered Host the consent did not name = `review_changed` (a new consent bumps `planRevision`); `hide_failed`; pending rows are polled                                                                                                                                                                                                                                                                                                                                                                                                                                               | FCP Hosts only      |
| 7   | `rehearse`          | every client family's render rule on (`family_disabled`); `edgeRehearsal.run` (fresh cohort bodies through the real renderer, listing before and after); expired proofs re-run and the rehearsal repeats (bounded); the version vector + the FINAL Host observation are persisted                                                                                                                                                                                                                                                                                                                                                                                                                         | unchanged           |
| 8   | `go_live`           | ONE mutation: no active rotation, no quarantine, relay enabled; the local vector equals the rehearsal's; the observation younger than 60 s; every L7 proof `expiresAt` ahead; every hide row settled and none outstanding; no FCP Host op claimed; every required listener published by its own edge, L4 with a current confirmation; `render.enabled` turned on if off (`edge.render.enabled_by_setup`); then `claimDeliveryBinding` and `setupOwned` cleared. A failed check sends the run BACK (7, 6 or the card)                                                                                                                                                                                      | rendered body       |

Fencing: a rotation the run starts stores `setupRun: {runId, generation}`; `releaseOrigin`
(every terminal transition) schedules `edgeSetupRuns.onRotationTerminal` with THAT stored
generation, and the run acts only while it expects exactly that rotation under exactly that
generation. `retry` and `continue` bump the generation, so an older rotation's callback is a
no-op. The step action is fenced by `stepVersion` like the rotation machine; the reconcile cron
(`setupRunsPass`) re-kicks a run whose step never ran and re-fires a terminal hook that never
landed. `relays.setupOwned` is set at stage 1 and cleared ONLY by stage 8 (or removal): a
failed, cancelled or unbound run leaves the relay owned. Cancel before stage 5 deletes the relay
`restore-direct` (nothing was published; the delete cancels the live rotation, drains the
standbys for the reconcile destroy and removes the credential); at stages 5-7 the published edges
stay and `edgeRestore.start` runs with purpose `cancel_setup`; after go-live there is no cancel.
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

**The simple screens** (`simple/`, plain words: relay -> protected node, edge -> address,
published / standby / draining -> in use / spare / retiring, rotate -> replace address,
qualified -> trusted, quarantine -> paused for safety; `PLAIN_WORDS` in
`src/client/lib/edgeCodes.ts`):

- **Nodes** (`/admin/edges`, `EdgesHome`): one status sentence with a dot ("All 6 nodes
  protected" / "1 node needs you" / "Setting up 1 node"), the **Needs you** rows from
  `attention` (the endpoint test opens the test card in place; go-live calls `require-edges`
  and renders the same card for whatever comes back pending), one row per protected node
  (name, country, one sentence, dot; a live run shows "Setting up, step N of 4" and opens its
  progress), the primary **Protect a node**, and the automatic-protection switch (`POST
automation`; a first-run card carries the cost and limitation sentences while it is off).
  `?protect=1` opens the protect sheet, `?run=<id>` a run's progress.
- **Protect a node** (`ProtectSheet` + `ProtectProgress`): three questions and then the
  progress. Which node (a panel's nodes; already protected ones greyed; the plan from `POST
setup-runs/plan` lists the inbounds in words, a closed "Not supported yet" disclosure and a
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
- **Node page** (`/admin/edges/nodes/<slug>`, `NodePage`, no tabs): the status sentence,
  "Addresses in use" per inbound (a reduced pool strip + one plain line per address), the
  primary **Replace address** (`ReplaceDialog`; "Replace now, address is blocked" under More),
  the per-node "Replace addresses automatically" switch (relay `autoRotate`, captioned when the
  global switch is off), "Recent activity" (the timeline through `plainAuditActionLabel`), and
  More: add a spare address, remove protection (`restore-direct`; the restore workflow's phase
  is shown while it runs), advanced details. `?test=<edgeId>` opens the test card.
- **Providers** (`/admin/edges/providers`): cards (Connected / Problem / Not tested, "3 of 6
  addresses used" from `providers/usage`, and the trust line: "Trusted automatically, checked
  with a real session on <date>" / "Tried with a real session by you on <date>" / "Reached from
  outside. Not yet tried with a real session"); a card opens the account page, whose qualify
  dialog is the **Trust override**.
- **Advanced** (`/admin/edges/advanced`): a plain list of links to the technical pages.

**The technical pages**, unchanged and at their old addresses: **All relays**
(`/admin/edges/advanced/relays`, the former dashboard: fleet tiles, attention list, readiness
with resume links, relay table, probe chart), **Manual setup** (`/admin/edges/setup?relay=<slug>`,
driven entirely by `setup-status`), the **per-relay page** (`/admin/edges/relays/<slug>`:
overview, edges, listeners, rotations, probes; the quarantine resolver), the per-account page
(`/admin/edges/providers/<id>`), **Templates**, **Probes** (the old `/admin/telemetry/probes`
redirects) and **Settings** (Basics, Advanced sections, maintenance, delivery places). Codes
are never shown bare: `src/shared/contracts/edgeCodes.ts` holds the vocabularies and
`src/client/lib/edgeCodes.ts` the words. Section paths are spelled only in
`src/client/routes/admin/edges/lib/routes.ts`; API paths only in `src/client/lib/edgesApi.ts`.

Member side: when the key sits behind edges the report dialog also asks which connection the
member was using (optional; the labels the pass shows), and an edge-required single-key
(Outline) subscription is shown as the dynamic access key.

### Host ownership (`hostMode: fcp`)

`convex/hostOps.ts`. Each listener's Host is a persisted state machine
(`relayListeners.host`): `absent → creating → present`, `present → deleting → absent`, with
`unresolved` and `ambiguous` in between. The **intended tuple** (remark, address, port, SNI,
Host header, inbound uuid) is persisted BEFORE any panel call; after an uncertain outcome
discovery matches a Host on remark AND inbound AND address:port, never remark alone. One match
settles a create; several park the listener as `ambiguous` (needs an operator); an empty
listing right after a timeout is never a licence to create again: the op stays `unresolved`
until a settle floor and two quiet looks passed. A delete is confirmed ONLY by a read-back in
which the uuid is gone. An expired, unsettled op blocks further Host writes for that listener.
A Host the ledger calls `present` is **re-observed against the live listing before it is
accepted**: the uuid listed means present; gone but exactly one Host on the listener's remark
and inbound takes its place; several park it `ambiguous`; none makes it `absent` (audited
`relay.host.lost`) and a create runs. `present` is never answered from the database alone, so
a rotation cannot confirm an empty Host plan.
Hosts FCP created are `fcp`-owned and deleted (confirmed) when the listener retires or the
relay is deleted; a Host the operator created and FCP took over is `adopted` and only ever
released. Legacy Hosts adopted from a manual deployment (`legacyHosts`) keep matching the
renderer and are never deleted.

### Direct-Host hides and the restore workflow

Two rules the read-back and the restore apply since the review of PR A2: a uuid found disabled
at a DIFFERENT tuple than the one observed before the write (an administrator repointed or
rebound it meanwhile) is never confirmed (`tupleDrifted`, counted as failed so the run raises
`hide_failed`), and a restore re-enables every Host that is still disabled whatever its tuple
says now (the bit is the one FCP wrote); only a Host an administrator re-enabled is released
without a write. `relays.restore` is a real lock: rotation starts (`edge.restore_in_progress`
in the start blockers), relay updates, adoption, unpublish (even forced), listener writes and
pool writes all refuse while it is set. A completed guided setup stamps its consented dark
cohorts on the relay (`relays.darkCohortKeys`) so the raw-body checks of a later restore skip
them, and a run's `continue {approvedHideUuids}` REPLACES the consent exactly (withdrawing a
Host the ledger already disabled is refused: `edge.consent_withdrawn_hidden`, Remove
protection is the path that re-enables it).

A node that serves members today has panel Hosts pointing at its own address (**direct
Hosts**: enabled, on one of the node's inbounds, dialling `originAddress`, not an FCP relay
remark, not an adopted legacy Host; `convex/lib/edges/directHosts.ts`). A guided setup hides
them once its edges serve, so that from then on members depend on the edge; a Host is
`covered` when a frontable listener serves its inbound and `uncovered` otherwise (the operator
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
No opposing write is issued while any row of the relay is unsettled. `internal.edgeHostHides`:
`hide {relayId, runId?, approvedUuids, nodeInboundUuids?}` (covered + approved; the rest come
back as `reviewChanged`), `status`, `settle` (reconcile-driven), `observe` (a hashed listing of
the node's direct + FCP Hosts with their disabled bit, for the rehearsal's observation
boundary). Audited `edge.host.hidden` (counts + remarks, never an address).

**Reconcile check for bound guided relays** (`hostOps.reconcileHosts` → `reobserveDirect`):
delivery is fail-closed, so a direct Host re-enabled or added behind FCP's back makes every
render `leak_detected` (503) rather than leak the origin. The pass re-observes the direct Hosts
of every bound relay with hide rows: a covered or previously approved one is **re-hidden**
(audited `edge.host.hidden` with `rehidden`); any other raises attention
`direct_host_reappeared` (critical, `relays.directHostAlert`, cleared when the next pass sees
none). Both are suppressed while a restore workflow runs.

**The restore workflow** (`relays.restore {purpose, phase, ...}`, `convex/edgeRestore.ts`;
one phase per `edge-reconcile` tick, `edgeRestore.step`) is the only way a guided relay stops
depending on its edges, with an explicit purpose: `cancel_setup` (a run cancelled after
publication), `release_requirement` (edge-required delivery switched off, everything kept) or
`delete_relay` (a `restore-direct` deletion). Phases: (1) `freeze`: no new disable writes; waits
for a running rotation; (2) `settle`: every outstanding hide row confirmed or released by
observation; (3) `verify_fcp_raw` (bound relays only): the RAW panel body of each non-dark
cohort (one representative key per placement pinned to the node, `convex/lib/edges/cohorts.ts`,
walked page by page over `subscriptions.by_backend_server_pinned`) carries an FCP entry and no
origin entry, fetched through the same path the sub route uses; (4) `release_binding`: the
delivery binding is released WHILE the relay stays enabled and its edges published, so members
keep the protected entry in raw delivery. **A direct Host is never re-enabled while the relay
is bound**: the renderer would answer `leak_detected` for every member, an outage FCP would
have caused itself (pinned by a test that asserts the ordering inside the panel write);
(5) `restore`: each `confirmed` row is re-observed; still disabled at the observed tuple →
re-enabled through a `restore` row, read-back confirmed; changed or removed by an administrator
→ released untouched (audited `edge.host.restored`); (6) `verify_direct`: the raw bodies carry
the origin entry again; (7) finish by purpose: `cancel_setup` retains the relay (`setupOwned` +
`bindingDeferred`, edges published, attention `go_live_pending`); `release_requirement` retains
everything and sets `bindingDeferred` so `require-edges` can re-apply the activation policy;
`delete_relay` runs the deletion body only now (drain, destroy, remove). A relay with a restore
in progress refuses a second workflow, a new hide and every pool / listener write
(`edge.restore_in_progress`); attention lists it as `restore_in_progress` (info) with its phase
and last error. Audited `edge.relay.restore_started` / `edge.relay.restore_finished`.

`relays.requestDelete` is re-sequenced accordingly: a `restore-direct` delete of a relay that
hid direct Hosts (or that a setup run bound) enters the workflow with purpose `delete_relay`
(response `restore: true`) instead of tearing down at once; `keep-dark` keeps the binding,
never restores a hidden Host and tears down at once, as before; a role-registered relay that
never hid a Host is unchanged.

### The rotation machine

`convex/edgeRotations.ts`. Phases:

```
select → provisioning → verifying → publishing → host_flipping → confirming → finalizing → done
                                                        ↘ rolling_back → rolled_back | quarantined
(failed / cancelled from the early phases)
```

The recovery contract is unchanged (step version fencing, resource-step ledger, operation
claims, four-outcome discovery, observe-then-write Hosts, shared external locks, leak guard,
quarantine, audit trail; see the sections of the previous release in git history for the
long form). Two things changed: the Host plan is captured, flipped and rolled back **per
listener**, and when FCP owns the Hosts and no Host exists for the listener yet, the flip
CREATES it through the Host state machine instead of waiting for the role.

### Reconcile cron (`edge-reconcile`, 5 min)

Re-kicks stale rotations (and stale guided setup runs, re-firing a terminal hook that never
landed); runs the L7 auto-trust sweep; clears a system `partial` rung whose binding no longer
matches the live rows (`edgeVerification.reconcilePartialRungs`: a re-addressed edge or a
changed listener no probe has settled on since); settles edges with unknown outcomes by
discovery; refreshes provider health; renews L7 proofs; re-observes unresolved Host operations
and deletes the FCP-owned Hosts of retired listeners and deleting relays (read-back confirmed);
settles the direct-Host hide ledger and re-observes the direct Hosts of bound guided relays;
drives one phase of each restore workflow; removes expired or released temporary test keys
(`edgeTestCredentials.sweep`, bounded retries, then attention `test_key_cleanup`); turns
drained / failed /
cancelled edges into destroy runs; pool upkeep while `edge.enabled` is on and the maintenance
switch is off (a `setupOwned` relay and a relay in a restore workflow are skipped): first `ensureCapacity` (raise / expand
`desiredPublished` for the deployed listeners), then **listener-aware** upkeep, one listener per
tick: every deployed, enabled listener without a template edge gets its OWN standby published
(`publishStandby` candidates filtered by `edge.listenerId`; a standby of A never counts for B)
or a provision FOR THAT LISTENER (`listenerId` in the start), then the relay-wide fill to
`desiredPublished` once every listener is covered, then spares: the relay-wide
`standbyPerRelay` reserve (unchanged) plus `standbyPerListener` verified standbys per coverage
listener (relay field, default from `edge.standbyPerListener`; the automation switch sets the
config key to 1). Finishes relay deletes. Daily sweeps prune `destroyed` edges after 30 days
and terminal rotations after 90.

## Server-name families (REALITY)

A REALITY inbound accepts an **exact allowlist** of server names (no wildcards) and forwards
every other handshake, and every handshake that fails authentication, to **one target**. So
"any hostname" is not a setting: it is a long, managed list. And a name is only safe to hand out
if the inbound's target **genuinely serves it** (TLS 1.3, a certificate valid for that name):
otherwise an active probe presenting the name sees a mismatch and the node stands out. A
**family** is therefore a target plus the names it serves, each checked against that target
before it may be used. More targets means more families, and more inbounds on other ports (an L4
edge maps its own port to the inbound's).

Ships dormant: `edge.sni.enabled` is off. Off, nothing is qualified and no family can be bound.

| Table                   | Holds                                                                                                                                                                                                                                                                                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sniFamilies`           | `slug`, `label`, `target {kind: static, address, port}`, `enabled`, `requireH2`. The **target is immutable**: every name was checked against it, and an allowlist is only safe for the target it was built for. A different target is a new family. `sni-router` (a target on the node that follows the presented name) is a reserved kind. |
| `sniNames`              | `name` (fleet-unique: one family per name), `seq` (monotonic per family, never reused: the order names are taken in), `status`, `qualification`.                                                                                                                                                                                            |
| `sniInboundBindings`    | One family bound to one panel inbound: the single authoritative allowlist for it, with its `generation`.                                                                                                                                                                                                                                    |
| `sniInboundNameHistory` | Every name an inbound has **ever** listed, keyed by inbound and name, independent of any binding (it survives unbind and rebind and is never reset). Binding records everything the inbound lists at that moment as seen.                                                                                                                   |

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

**Binding** (`POST sni/families/{slug}/bind {backendSlug, inboundTag}`) is refused unless the
inbound is REALITY, is on the panel as Servers last read it, has no family yet, and its target
**is** the family's target (`edge.sni.target_mismatch`). From then on the inbound's names and
target are no longer edited by hand (`servers.inbound_sni_managed`): they have one author.
Unbinding keeps the names on the panel and on the relays, and keeps the history.

**What goes onto an inbound** (`planAllowlist`, `convex/lib/edges/sni/family.ts`). The panel
allowlist is one list with one cap (512; production Xray takes 1024, measured) and three kinds
of tenant: the family's names; names that are not the family's but that a relay still hands
out; and names that were retired but are still inside their drain. The cap is over **all** of
them. The family's share is what is left after the other two and a **headroom of 64** kept free
for the next drain, because retiring one name and adding its replacement needs both on the panel
at once. The family fills its share in `seq` order, so every node on the inbound sees the same
choice.

### Rollout and acceptance

A family's names reach members in two separate steps, because they answer two separate
questions.

**1. The panel holds the names** (`POST sni/bindings/{id}/rollout`; `.../plan` shows it first).
The allowlist is planned, previewed against the live panel and written through the server
operations ledger ([servers.md](servers.md) § Editing a config profile), which is the only path
that may edit a managed inbound. When the read-back shows the predicted token the rollout is
`panel_confirmed`. **Members are handed nothing by this step.** Rolling out again with nothing
new writes nothing.

**2. Each node accepts them.** A panel read-back says nothing about a node. Measured against a
real node: with the node held off the panel, the panel lists the new name, a plain TLS
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
name is a **witness**, an added name this inbound has **never listed before** (per
`sniInboundNameHistory`), a node that authenticates it must be running the generation that
introduced it, so the one receipt activates **every** name of the generation there. A name that
was listed at some point (removed and added again, or present before FCP managed the inbound)
is never a witness: a node stuck on an older config could accept it too, so it proves only
itself. Only names that still qualify are activated, whatever was proven.

Activation appends to the listener's names in the rollout's order, switches the listener to the
growth-stable `hrw1` selection, moves `namesRevision` and the publication epoch, and leaves
`revision` alone: acceptance was **proven**, so the endpoint confirmation still describes the
path. That is the only way a name is added without a retest.

**Removal is the reverse.** A name leaves the relays first, with its drain. The plan **retains**
on the panel every name a relay still hands out or that is still draining, whoever it belongs to
and whatever its family says, and a later rollout drops it once nothing holds it. A burn is
immediate on the relays and restarts nothing.

### When a name leaves

A family name that is **burned**, **retired**, or that **stops qualifying** (suspended) leaves
the relays by itself, with the normal drain (`retireFamilyNames`). Two rules:

- a name that merely stopped qualifying, or that an operator retired, never takes a relay's
  **last** active name with it: a relay with one doubtful name still serves its members, a relay
  with none serves nobody. A **burn** may: a name known blocked is worse than no name;
- a relay that is rotating, restoring, quarantined or being changed by Servers is skipped and
  counted in the result, never forced.

The panel keeps the name until nothing hands it out and its drain is over (§ Rollout and
acceptance), so members who have not refreshed are not cut off.

**The one name of a Host.** A panel Host carries one server name. It is what a member gets who
copies a raw config from the panel (no per-member selection happens there), what the shape
probes present, and what an endpoint shows as its name. `hostSniOf` chooses it: the first active
name, in stored order, that is **not known blocked in any curated country**, else the first
active one. When that name leaves, `hostOps.resyncSni` writes the listener's next choice onto
the Host (address and port unchanged), for an FCP-owned Host that is settled; a Host the
machine is working on, an operator-owned Host and a rotating relay are left alone (a rotation
writes the new tuple by itself).

### Names for the member's country

A name that works almost everywhere can be blocked in one place: a large site that is itself
censored there. So in the **curated countries** (`edge.sni.curatedCountries`, default
`CN, RU, IR, MM`) "usable" is judged per country.

**Judging.** `POST sni/families/{slug}/names/country {snis, country, state}` records an
operator's judgement (`proven`, `blocked`, or `unknown` to clear it) in `sniNameCountry`, for a
curated country only. The marks are **copied onto every relay listener entry** for that name
(`blockedIn`, `provenIn`), so a render needs no extra reads, and those relays' renders move on
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
`POST rollouts/{id}/test-link`, `POST receipts/{id}/confirm`. Audit rows
(`edge.sni.*`) carry slugs and **counts only, never a hostname**.

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

Not built: probing each name from inside a country through the outside probe sources. The
internal probe cannot stand in for it (it is not in the country), and qualification already
checks every name against its target.

### The page

Admin -> Edges -> Advanced -> Server names (`/admin/edges/names`, `/admin/edges/names/{slug}`).

- The list: each family in one line (how many names are ready, waiting, failing; whether an
  inbound uses it), the switch for `edge.sni.enabled`, and "Add a family" (the target is fixed
  at creation).
- A family: bind it to a REALITY inbound (the inbounds come from the Servers observation),
  add names (the answer says what happened to every kind of line), filter and pick names, then
  check again, retire, bring back, burn (typed), or record for a curated country that they work
  or are blocked there.
- A bound inbound: "See what would be written" shows the plan in words, including whether one
  test per node will prove the whole list (a witness) or each name needs its own; "Write to the
  panel" starts the rollout; once the panel has it, each node lists how many names it has proven
  and offers "Test through <address>". The test link is shown once with its name, and "It
  connected" confirms the receipt. The page says plainly that a check from outside cannot
  stand in for that test.

The three facts stay separate in the copy: the target serves a name (checked), a node accepts
it (tested), it works from a country (judged). Wording is in
`src/client/routes/admin/edges/names/lib/words.ts`; tests pin that every `edge.sni.*` refusal
and every check code the server can record has its own sentence.

## Probes and the block detector

Unchanged in substance from the previous release: probe targets are the published edges of
every relay (the only kind the detector reads), relay origins that opted in (`probeNode`) and
operator-entered custom targets; UDP listeners are not probeable (`probe.udp_unsupported`).
The detector's load and node-online signals exist only for a `panel-node` origin; for other
kinds the load score is 0 (`no_load_signal`) and `node_offline` reads the instance health of a
`backend-server` origin. The "manageable Host" veto applies only to `hostMode: operator`; a
`setupOwned` relay (a guided setup in progress) is vetoed `setup_owned` right after the
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

`edge.*` in `appSettings` (Admin → Edges → Settings, probe settings included;
`GET/PATCH /api/v1/admin/edges/config`). Ships fully dormant: `enabled=false`,
`autoRotate=false`, `render.enabled=false`, `probe.enabled=false`, `l7.autoSelect=false`.
Probe credentials are write-only (`edge.secret.probe.*`). Defaults and bounds:
`convex/lib/edgeConfig.ts`. `providerAffinity` was removed (never read).
`desiredPublishedDefault` and a relay's `desiredPublished` are bounded 1..8
(`MAX_DESIRED_PUBLISHED`, the coverage cap); `standbyPerListener` (0..2, default 0) is the
per-listener spare count the reconcile keeps on top of `standbyPerRelay` (a relay's own
`standbyPerListener` is an override, stored only when set, so a change of the global applies
to every relay that never set one). The one-call
`POST automation {on}` (§ Operator endpoints) flips the four automation switches together and
sets `standbyPerListener` to 1 when turning on; `render.enabled` and `l7.autoSelect` stay
manual.

## Sealing

Every route under `/api/v1/admin/edges/` is sealed by verb (GET reveals, POST seals both legs,
PATCH/PUT seal the request, DELETE carries nothing). Dual-mode plaintext stays for `fsv1_`
callers; `FS_HPKE_ADMIN_REQUIRED=true` refuses plaintext from cookie-session callers. Config
routes need `admin:settings:*`, everything else `admin:servers:*`, and the registration
routes additionally accept **`admin:edges:register`** (see the node role contract).

## Node role contract (Ansible)

The role registers a relay with ONE idempotent body and reads back what to configure. Token:
an `fsv1_` token with `admin:edges:register`, minted with a **registration boundary**
(`apiTokens.edgeRegistration`: the backend servers and, optionally, the node names it may
register for). Such a token may call only the by-slug routes below, and only for origins
inside its boundary (`edge.registration_boundary` otherwise); a boundary-less register token
may register nothing. Credential rotation = mint a new token with the same boundary and revoke
the old one; nothing on the relay row references a token. The boundary is set at mint: in
the CMS (Admin → API tokens; ticking the scope reveals the backend-server and node-name
inputs, and the guided setup's "Mint role token" link presets them) or from the control plane
with `adminApi:mintAutomationToken '{"scopes":["admin:edges:register"],
"registerBackendSlugs":["<slug>"],"registerNodeNames":["<node>"]}'`. The mint refuses the
scope without a boundary and a boundary without the scope (`validation`); the audit row
carries counts only.

1. `PUT /api/v1/admin/edges/relays/by-slug/{slug}` with
   `{ origin, originAddress, locationCode?, label?, listeners[], pruneListeners? }` where
   `origin` is `{ kind:'panel-node', backendSlug, nodeName, nodeUuid? }`,
   `{ kind:'backend-server', backendSlug }` or `{ kind:'manual' }`, and each listener is
   `{ listenerKey, protocol, streamTransport, security, originPort, tlsNames?, realityTarget?,
transportParams?, originTransport?, panelBinding?, matchRule?, deployed? }`. **Idempotent**:
   an identical body changes nothing but `lastRegisteredAt` (no listener revision bump, no
   epoch bump, no mirror refresh, no qualification invalidation). Listeners the body omits are
   retired (`pruneListeners`, default true) ONLY when the role registered them; admin-created
   listeners are never touched (`edge.listener_key_owned` if the body names one). The role can
   add names and retire its own; it can never reactivate an admin-retired name or shorten a
   drain. A rebind or prune under a non-destroyed edge is refused (`edge.listener_in_use`).
   The response is the minimal projection: `relay { slug, hostMode, delivery, enabled,
deleting, publicationEpoch, originAddress, lastRegisteredAt }`, `listeners[]` (with
   `layers` and `excluded` reasons), `publishedEndpoints[]` (role-usable only), `connectionPlan[]`
   (what a client must dial per listener) and `hostsPlan { mode, hosts[] }` (non-empty only
   for `operator`), plus `registration` (what changed).
2. `GET` the same path to poll; `hostsPlan.mode === 'fcp'` means FCP creates and flips the
   panel Hosts itself: the role writes nothing. With `mode === 'operator'` the role applies
   `hostsPlan.hosts[]` verbatim (remark, address, port, sni, host, inbound) with GET-first
   drift replacement. With `mode === 'none'` there is no Host.
3. Teardown: `DELETE …/by-slug/{slug}?disposition=restore-direct|keep-dark` (default
   `restore-direct`: the node is decommissioned, raw delivery of its subscriptions returns);
   `DELETE …/by-slug/{slug}/listeners/{key}` retires one listener.
4. **Legacy adoption** (`operation_mode=adopt_relay` in the role): a node that already sits
   behind a manually run proxy with operator-created Hosts registers with
   `hostModeRequest:'operator'` and `adoption: { edge: { address, port }, hosts: [{ uuid,
remark, inboundUuid, sni? }] }`. FCP records the legacy Hosts on their listeners (never
   deleted; the renderer keeps matching their remarks), imports the proxy as an observe-only
   edge carrying the operator's statement that it already serves (a `named_connection`
   verification: the adoption payload IS that statement) and publishes it at index 0 without
   a flip. The operator then validates and adopts each Host in the CMS and switches
   `hostMode` to `fcp`.

Node pinning understands the relay remark (`convex/lib/nodePinning.ts`).

## Runbooks

**Qualify a provider account.** Add the account and test its credentials, then:

- **L4 (a load-balancer provider): one human tick per endpoint.** Provision a spare on a relay
  from the account (the explicit test-provision path accepts a tested but unqualified
  account); the probes take it to `partial` at most. Fetch `GET edges/{id}/verification-binding`,
  try the address with a real session (the isolated test link, or the named connection for an
  address that is already published), then `POST edges/{id}/verify` echoing the binding you
  were shown. The first confirmed endpoint of the account trusts the account when it was
  provisioned with the account's current template and the credentials were tested after their
  last change (`accountTrustReason` in the response says why not); every NEW endpoint of that
  account still needs its own tick before it can be published or used by an automatic
  replacement, and a listener or address change after the tick puts the endpoint back under
  `retest_needed` and out of every rendered body until retested. The Providers "Mark
  qualified" override trusts the account only; it verifies no endpoint.
- **L7 (a CDN front): automatic on the proof.** Once an active edge of the account carries a
  current authenticated end-to-end proof for the account's effective template (and the account
  was tested after its last credential change), the account is trusted by the auto-trust rule
  (evaluated after every passing proof and by the reconcile sweep; audited
  `edge.provider_account.auto_qualified`). No manual step.

A manual "Mark unqualified" holds automatic trust off until an operator trusts again or the
credentials change. Editing credentials or settings, or a template change that moves the
account's effective template, clears the qualification (and its evidence).

**Bootstrap a relay.** Register it (role or CMS) with its listeners, add a provider account,
provision or import an edge on a listener, publish it, enable rendering, preview each client
family. Until the first publish with rendering on, members on that origin receive 503.

**Resolve a quarantine / `needs_operator` / an `ambiguous` Host.** Compare the panel's Host with
the recorded bindings, fix by hand if needed, then resolve keeping the binding that matches
what the panel serves; for a Host the panel shows twice for one listener, delete the extra
and resolve.

**Add an L7 account / qualify an L7 front.** As in the previous release, per listener.

## Maintenance switch and reset drain

`edgeMaintenance:freeze` separates **admission of new work** from **completion of work in
flight** (`convex/lib/edges/maintenance.ts`). While frozen, nothing new is admitted
(`edge.maintenance`): rotation starts of any kind, registration, imports, direct publishes,
provider account / template writes, probe requests and detector evaluation. Completion paths
keep running: rotation steps and re-kicks, rollback, cancel, unpublish, destroy runs, Host
operations, quarantine / needs_operator resolution, relay delete finalisation, credential
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
destroyed (the whole table is walked, never a capped listing), held external locks, quarantined or deleting relays, active or owed qualification
credentials) → finish that work through the ordinary machine until `blockers` is empty →
`bunx convex env set EDGE_RESET_ALLOW wipe-edges` then `wipe '{"confirm":"wipe-edges"}'` (the
opt-in is a deployment env var, set for the reset and **removed afterwards**; `ENVIRONMENT`
cannot be the guard because a beta stack runs `ENVIRONMENT=production` like prod; local
`development` needs none; refuses while any blocker remains, and every destructive batch
re-checks opt-in, confirm word, freeze and blockers itself; deletes `edgeRotations`, `edges`, `relayListeners`, `relays`, `edgeDeliveryBindings`,
`externalLocks`, `relaySamples` and the edge/relay probe rows in bounded pages; turns the
`edge.*` switches off; keeps probe targets, provider accounts, templates, node inventory, marks,
the audit log) → deploy → `thaw`. The deploy entrypoint pushes the schema before it runs any
function, so the drain runs on the OLD code first. All through the deployer container
(`docs/beta-deploy.md` § "One-off functions").

## Local development

The whole setup flow (account, template, relay, provision, qualify, publish, render) can be
walked without cloud credentials. With `ENVIRONMENT=development` and
`DEV_FAKE_EDGE_PROVIDER=true` on the deployment, the provider registry hands out an in-memory
fake in place of one real adapter per layer (`convex/lib/edges/providers/fake.ts`); the fake
keeps the real adapter's template schema so the forms behave as they would in production,
answers with RFC 5737 / RFC 3849 addresses and `*.example` hostnames, records its calls, and
finishes every create instantly (`DEV_FAKE_EDGE_SLOW_MS` delays creates to exercise the async
paths). `seed:seedDevEdges` (same double gate) creates a mock backend server and one tested
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
