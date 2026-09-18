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
| `trojan`             | `raw` / `ws`                  | `tls`     | L4 only (no L7 proof)                                             |
| `shadowsocks`        | `raw`                         | `none`    | address/port rewrite only; Outline keys are `ss://`               |
| `hysteria2` / `tuic` | `udp`                         | `tls`     | registers, but no provider forwards UDP today (`no_udp_provider`) |

Anything else is `invalid_combination`. The catalogue derives `usesSni`, `needsTarget`,
`isHttpTransport`, `usesHostHeader`, `transport` and `l7Proof`; `convex/lib/edges/protocols.ts`
adds the CODEC table (which subscription formats the renderer can rewrite per combination,
pinned by a test: a combination without a codec for every format it claims never ships).
`vmess` has no codec and is not in the catalogue.

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
2. marks an edge whose listener did not resolve, or whose combination has no codec for this
   body format, **ineligible** (it keeps its pool index);
3. assigns primary (+ backup) with a stable PRF keyed on the subscription's `renderKey` over
   the FULL pool order, walking forward past ineligible positions; one server name per emitted
   connection for name-presenting listeners, chosen from the listener's active names (a
   retired name is never selected again);
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

Mirrors follow the same policy: each mirror row records what its object holds (`validated`:
policy version, epoch, edges); registering a relay revalidates the origin's mirrors, replacing
a raw object with a fresh render or, when nothing can render, with an **unavailable stub**
(the URL is already distributed, so the object itself must stop serving the origin). The
account view and the issuance responses hand out ONLY the fronted token URL for a covered key
(`edgeRequired`); an Outline member imports a dynamic access key
`ssconf://<fcp-host>/api/v1/sub/<token>` and follows rotations by re-fetching. Outline over an
edge is **TCP-only** today (no adapter forwards UDP).

## Operations

| Operation                                 | Precondition                                                                                                                                                  | Spends budget                      | Writes Hosts                                                                  | Result                                                                                                                        |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Register relay (role PUT / admin)         | origin + listeners in one body                                                                                                                                | no                                 | no                                                                            | relay + listeners upserted; an identical body changes nothing; the origin's subscriptions become edge-required                |
| Import edge                               | origin + listener; optionally a provider account + the load balancer picked from its inventory                                                                | no                                 | no                                                                            | edge `active`; managed when imported from an account, observe-only when entered by address (`managed:false`, never destroyed) |
| Provision edge                            | qualified account (the listener's provider scope when set; any otherwise), template, capacity                                                                 | yes                                | no                                                                            | edge `active` + `unpublished` (or published when requested)                                                                   |
| Publish edge                              | active, has an address of its layer, listener deployed + enabled (+ an active name for a name-presenting listener behind L4; a current front proof behind L7) | no                                 | listener Host only when the edge becomes the listener's template edge (`fcp`) | `published` at the lowest free index; epoch++                                                                                 |
| Replace (rotate / burn)                   | a published target edge                                                                                                                                       | unless a compatible standby exists | listener Hosts whose template edge it is (`fcp`)                              | new edge `published` at the SAME index; old `draining` (burn = short drain)                                                   |
| Unpublish / retire name / retire listener | no running rotation, no quarantine; a listener retire needs NO non-destroyed edge on it                                                                       | no                                 | no                                                                            | new selections stop; the node keeps accepting through the drain; epoch++ and mirrors refresh                                  |

`hostMode:'operator'` means FCP never writes the Hosts: publishing proceeds without a flip and
replacing a template edge is refused (`edge.hosts_operator_managed`) unless forced.

### Operator endpoints (what the admin section is built on)

All under `/api/v1/admin/edges/`, sealed by verb like every other route; the read-only POSTs
(`setup-status` with a draft, `preflight`) are admitted by the read scope, like `render/preview`.

| Route                                                          | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET setup-status?relay=<slug>` / `POST setup-status {draft}`  | **Relay-scoped** readiness: nine steps (origin, account, template, relay, edge, qualification, publish, rendering, automation), each `done / ready / blocked / skipped` with blockers and warnings as codes, the selected context, `currentStep` and `roleVars` (public values only: never a token or an address). A draft (origin + listener triples) is judged before the relay exists. Without either, the fleet aggregate plus the relays whose setup can be resumed. Manual origins skip `rendering`. |
| `POST relays/{id}/test-provision`                              | The bootstrap path: ordinary selection excludes unqualified accounts, so a fresh account could never get its first edge. Explicit `{accountId, templateId?, listenerKey}`; the account must be enabled and **tested** but may be unqualified; budgets, capacity and layer compatibility apply; the result is always unpublished. Audited `admin.edge.test_provision`.                                                                                                                                      |
| `POST relays/{id}/preflight`                                   | Dry run of `provision / publish / replace / test-provision`: every guard a real start applies (the FIRST blocker is the code the start would throw), the selection the machine would make, plan-phase refusals that need no adapter, and delivery warnings (`render_disabled`, `members_dark`, ...). Writes nothing.                                                                                                                                                                                       |
| `GET attention`                                                | Server-ranked list, one action per item: quarantine, needs operator, unsettled Host op, **members dark** (edge-required place with nothing to serve), failed or rolled-back rotation, lapsed front qualification, block suspected, unreachable edge, pool below desired, account untested or unqualified, drift, maintenance frozen.                                                                                                                                                                       |
| `GET relays/{id}/quarantine` + `POST .../quarantine/inspect`   | The resolver view: per listener the previous and the current binding as Host tuples; `inspect` (throttled) fills the live column from the panel and says which one it matches. `resolve-quarantine` records a `reason`.                                                                                                                                                                                                                                                                                    |
| `GET relays/{id}/timeline`                                     | Merged audit rows of the relay, its listeners, its non-destroyed edges and its rotations, newest first, capped.                                                                                                                                                                                                                                                                                                                                                                                            |
| `GET providers/usage`                                          | Per account: live / max edges, allocations against the daily budget, published / standby / draining; per relay desired against published; totals including what auto-provision would add.                                                                                                                                                                                                                                                                                                                  |
| `GET relays/lookup?slug=`                                      | The full admin view of one relay by slug (the per-relay page is addressed by slug).                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `POST relays/{id}/listeners/{key}/adopt-host`                  | The `operator` to `fcp` handoff: the named Host must exist, carry the listener's inbound and dial a published edge of that listener (`edge.host_adopt_mismatch` otherwise). `hostMode: fcp` is refused until every listener Host is adopted (`edge.host_adopt_required`).                                                                                                                                                                                                                                  |
| `GET maintenance`, `POST maintenance/freeze`, `.../thaw`       | The maintenance switch (see below).                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `GET delivery-bindings`, `POST delivery-bindings/{id}/release` | The edge-required places, including ones whose relay was deleted with `keep-dark`.                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `GET config`                                                   | Also carries `bounds` and `defaults` per flat key, so the settings forms validate against the server's own limits.                                                                                                                                                                                                                                                                                                                                                                                         |

### Admin section (Admin -> Edges)

Its own lazy chunk under `src/client/routes/admin/edges/`, one nav group: **Overview**
(`/admin/edges`: fleet tiles, attention list, readiness with resume links, relay table, probe
chart), **guided setup** (`/admin/edges/setup?relay=<slug>`, driven entirely by `setup-status`:
the page holds no progress state of its own), **per-relay page**
(`/admin/edges/relays/<slug>`: overview, edges, listeners, rotations, probes; the quarantine
resolver), **Providers** (+ per-account page), **Templates**, **Probes** (moved from Telemetry;
the old path redirects) and **Settings** (Basics, Advanced sections, maintenance). Codes are
never shown bare: `src/shared/contracts/edgeCodes.ts` holds the vocabularies and
`src/client/lib/edgeCodes.ts` the words. Paths are built only in `src/client/lib/edgesApi.ts`.

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
Hosts FCP created are `fcp`-owned and deleted (confirmed) when the listener retires or the
relay is deleted; a Host the operator created and FCP took over is `adopted` and only ever
released. Legacy Hosts adopted from a manual deployment (`legacyHosts`) keep matching the
renderer and are never deleted.

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

Re-kicks stale rotations; settles edges with unknown outcomes by discovery; refreshes provider
health; renews L7 proofs; re-observes unresolved Host operations and deletes the FCP-owned
Hosts of retired listeners and deleting relays (read-back confirmed); turns drained / failed /
cancelled edges into destroy runs; publishes standbys / provisions to `desiredPublished` while
`edge.enabled` is on and the maintenance switch is off; finishes relay deletes. Daily sweeps
prune `destroyed` edges after 30 days and terminal rotations after 90.

## Probes and the block detector

Unchanged in substance from the previous release: probe targets are the published edges of
every relay (the only kind the detector reads), relay origins that opted in (`probeNode`) and
operator-entered custom targets; UDP listeners are not probeable (`probe.udp_unsupported`).
The detector's load and node-online signals exist only for a `panel-node` origin; for other
kinds the load score is 0 (`no_load_signal`) and `node_offline` reads the instance health of a
`backend-server` origin. The "manageable Host" veto applies only to `hostMode: operator`.

## Configuration

`edge.*` in `appSettings` (Admin → Edges → Settings, probe settings included;
`GET/PATCH /api/v1/admin/edges/config`). Ships fully dormant: `enabled=false`,
`autoRotate=false`, `render.enabled=false`, `probe.enabled=false`, `l7.autoSelect=false`.
Probe credentials are write-only (`edge.secret.probe.*`). Defaults and bounds:
`convex/lib/edgeConfig.ts`. `providerAffinity` was removed (never read).

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
the old one; nothing on the relay row references a token.

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
   edge and publishes it at index 0 without a flip. The operator then validates and adopts
   each Host in the CMS and switches `hostMode` to `fcp`.

Node pinning understands the relay remark (`convex/lib/nodePinning.ts`).

## Runbooks

**Qualify a provider account.** Add the account and test its credentials; provision a test
edge on a relay from the account (the explicit test-provision path accepts a tested but
unqualified account); open a real session through the edge and hold it idle; pull the live
view; then "Mark qualified". Editing credentials or settings, or a template change that moves
the account's effective template, clears the qualification.

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
removal. `edgeMaintenance:thaw` lifts it.

`seedEdgesReset` is the one-shot drain that precedes a breaking change to the edge tables:
`freeze` → `status` (read-only, every environment: non-terminal rotations, managed edges not
destroyed, held external locks, quarantined or deleting relays, active or owed qualification
credentials) → finish that work through the ordinary machine until `blockers` is empty →
`wipe '{"confirm":"wipe-edges"}'` (allow-listed environments only; refuses while any blocker
remains; deletes `edgeRotations`, `edges`, `relayListeners`, `relays`, `edgeDeliveryBindings`,
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
| gcore      | GET    | `^/cloud/v1/loadbalancers/[^/]+/[^/]+$`                                           | list load balancers: credential test, discovery by name, inventory                                                | https://api.gcore.com/docs/cloud (Cloud API v1), 2026-09-16                                                                                                                       |
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
