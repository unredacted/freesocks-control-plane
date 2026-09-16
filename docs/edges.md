# Edges

A **relay** is a node that members reach through something FCP can replace. An **edge** is
that something: any frontable proxy. Today an edge is one of two **layers**:

- **L4**: a provider-managed cloud load balancer that forwards a TCP port to the node. The
  node terminates its own protocol (REALITY, TLS, plain); the edge is an address.
- **L7**: a CDN front that terminates TLS and HTTP and forwards an HTTP-carried transport
  (WebSocket, HTTP Upgrade, gRPC) to the node. The edge is a **hostname** under an
  operator-owned zone; the CDN's own certificate and anycast addresses serve it.

Censors block the edge's public address or hostname, not the node, so the edge is the unit
that gets replaced. Edges are protocol-agnostic within their layer: what a slot speaks decides
what the renderer rewrites in a member's connection and which layers can carry the slot
([Layers](#layers)). This document describes how FCP provisions, publishes, rotates and
observes edges, and the contract the node role (Ansible) follows. It is provider-neutral on
purpose: nothing here says which providers, regions, zones, targets or names a given deployment
uses.

Admin surface: **Admin → Edges** (`/admin/edges`) and `/api/v1/admin/edges/*`; probe
telemetry lives under **Admin → Telemetry → Probes** (`/admin/telemetry/probes`, its own nav
entry beside User reports). Every request
under the API prefix is HPKE-sealed by verb class (see [Sealing](#sealing)).

## Model

| Concept          | Table                  | Meaning                                                                                                                                                                                                                                                                                                                        |
| ---------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Provider account | `edgeProviderAccounts` | One cloud or CDN account: write-only credentials, fixed settings (project/region/zone/network, or the DNS zone for an L7 provider), priority, a daily allocation budget, a live-edge cap, `qualified`. An L7 provider whose hostnames' DNS lives elsewhere names a **DNS account** (another account whose provider hosts DNS). |
| Edge template    | `edgeTemplates`        | Per provider (optionally per account): the full provisioning parameters, validated by the adapter's schema. Provisioning records the template hash; L7 edges also freeze the effective parameters into their intent.                                                                                                           |
| Protocol profile | `protocolProfiles`     | What a slot's inbound speaks (`reality` / `tls` / `plain` / `ws` / `httpupgrade` / `grpc`) plus what the renderer needs: server names (REALITY SNIs or certificate names; none for `plain`) and, for REALITY, the impersonated target. Optionally scoped to one provider's network.                                            |
| Relay            | `relays`               | One node behind edges: its origin address (what edges dial), published pool, publication epoch, rotation limits, detector state, quarantine, `probeNode`, the L7 qualification credential.                                                                                                                                     |
| Slot             | `relaySlots`           | One inbound on the relay (port + panel inbound uuid) deployed by the role for one protocol profile, with ONE template Host (remark `<node>-relay-<slotKey>`) and, for an inbound an L7 front can dial, its **origin transport** (scheme, certificate trust and names, Host policy).                                            |
| Edge             | `edges`                | One provider resource bound to a relay slot: its layer, the resource-step ledger, child resources, addresses (IP literals for L4, the hostname for L7), publication state and pool index, health, readiness, front qualification, live snapshot, reachability. L7 edges carry a frozen **provision intent**.                   |
| Rotation         | `edgeRotations`        | One provision / publish / replace run: phase, step version, operation claim, Host plan, previous binding, live event log; its audit trail is assembled on read.                                                                                                                                                                |
| Probe target     | `probeTargets`         | An operator-entered public host:port probed alongside the derived targets (edges, relay nodes); private, loopback and link-local literals are refused. Operator evidence only.                                                                                                                                                 |
| Probe run        | `probeRuns`            | One reachability measurement of one target address (edge, relay node or custom) from one source.                                                                                                                                                                                                                               |
| Reachability     | `probeReachability`    | Per target, per country, per source, per address family: the last run's vantage counts and verdict; summarised onto the target's own row.                                                                                                                                                                                      |

The supported providers are listed in `src/shared/contracts/edgeProviderIds.ts`; each has an
adapter under `convex/lib/edges/providers/` implementing `EdgeProvider`. Generic code never
branches on a provider id; it reads `EDGE_PROVIDER_CAPABILITIES` (`layer`, `addressKind`,
`l7Transports`, `needsDnsAccount` / `providesDns`, `originPortMode`, the async and health flags)
and the adapter's template schema.

### Layers

`slotLayers(slot, profile)` (`convex/lib/edges/layers.ts`) decides which layers can carry a
slot from the **complete** member-to-node chain, never from the protocol name alone:

| Slot                                                                                                                                                                                                    | L4  | L7  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | --- |
| Legacy slot (no origin transport declared): raw TCP to the inbound                                                                                                                                      | yes |     |
| Origin speaks plaintext HTTP behind the CDN (`originTransport.scheme = http`), HTTP transport profile                                                                                                   |     | yes |
| Origin speaks HTTPS, HTTP transport profile, certificate publicly trusted AND every active server name covered by a certificate name (RFC 6125 wildcard rules) AND the node accepts those names as Host | yes | yes |
| Origin speaks HTTPS, profile is `reality` / `tls` / `plain`                                                                                                                                             | yes |     |

Public trust and name coverage are separate requirements: an L4 forwarder cannot add the TLS
the CDN terminated, and a member's TLS session to the node must validate the name the renderer
emits. A provider carries a protocol when `protocolCarriedBy(provider, protocol)`: L4 carries
any TCP protocol, an L7 provider only the HTTP transports it declares. Publication
(`checkPublishable`), selection, import and the detector's replacement choice all refuse a
layer the slot cannot use (`layer_mismatch`, `protocol_not_carried`, `no_compatible_layer`).

`hostTargetFor(edge, protocol, selectedSni)` is the single source of the Host tuple the panel
template Host and the renderer share: L7 → `{ hostname, 443, sni: hostname, host: hostname }`;
L4 HTTP transport → `{ address, port, sni, host: sni }`; L4 `reality` / `tls` → `{ address, port,
sni, host: null }`; `plain` → `{ address, port, sni: null, host: null }`.

### L7 edges

An L7 edge is one hostname `<label>.<zone>` minted deterministically from the edge's
provider-side name (`convex/lib/edges/hostname.ts`: a hash-derived label of 8 to 16 characters,
optional prefix, always a single first-level label under the zone because the CDN's default
certificate covers only that level). Everything a step, discovery, describe or destroy needs
is **frozen** into `edges.provisionIntent` when the edge is planned (hostname, zone, DNS
account, TLS configuration, certificate authority, origin transport, origin port, the zone's
encryption mode and the effective template parameters), so an account or template edit never
moves an existing edge and cleanup uses the original intent.

Readiness has three dimensions: `dns` (the record exists and is proxied / the domain check
passes), `certificate` (the CDN certificate covers the hostname / the managed certificate is
issued) and `front` (the end-to-end qualification below). DNS existence is not origin health;
L7 providers report `memberHealth:false` and publication waits for the qualification.

**Front qualification.** Before an L7 edge is published or selected as a standby, FCP opens a
short **authenticated test session** through it: TLS to `hostname:443` with SNI = hostname and a
valid chain, the slot's transport exactly as the template Host describes (RFC 6455 handshake
with the accept key verified; HTTP Upgrade with the template's token; gRPC `POST
/<serviceName>/Tun` with length-prefixed `Hunk` frames), then a VLESS request for the relay's
qualification credential (a panel account FCP mints on the relay's placement, so the proof
travels a member's path) fetching `http://www.gstatic.com/generate_204` through the tunnel and
requiring the `204`. Anything else fails with a code: `front_error` (a CDN-generated answer such
as `403` or `52x`), `grpc_<status>` (trailers without a tunnel response), `auth_failed`,
`egress_failed`, `timeout_<step>`. The result is stored with its **binding** (hostname, slot and
profile revisions, protocol, transport parameters, intent hash) and an expiry
(`edge.l7.qualificationTtlMinutes`); publication re-derives the binding inside the mutation
and refuses `front_unqualified` / `front_qualification_stale`. The reconcile cron re-qualifies
published L7 edges whose qualification expired. `POST …/{edgeId}/qualify` runs it on demand.

**Affected-country evidence.** A detector-triggered L7 replacement additionally needs, during
`verifying`, probes of the new hostname from every country in the detector's evidence:
`reachable` everywhere → proceed; any `unreachable` → `replacement_blocked` (counted against
`edge.l7.maxSameProviderReplacementsPerDay`, because a new hostname on the same provider is
not a new frontend address); timeout, no enabled source or `mixed` / `unknown` →
`qualification_inconclusive`. An unknown result never counts as success. `confirming` repeats
the probe set once and rolls back on `unreachable`. A manual publish may pass
`forceGeoEvidence` to skip only this gate (audited); it never bypasses the transport proof,
the TLS chain, ownership, layer compatibility or the configuration binding.

**Gate.** `edge.l7.autoSelect` (default off) governs automatic selection of L7 accounts
(detector replacements, auto-provision, auto-publish). It stays off until the node role
registers `originTransport` and the HTTP-transport profiles and a qualification run has passed;
manual provisioning and publishing work regardless.

### Publication

Provisioning and publication are separate. An edge is `unpublished` (a standby: paid for, not
rendered), `published` at a **pool index**, or `draining` (still serving old subscribers,
scheduled for destruction after the drain). A relay's `publishedEdgeIds` is ordered by pool
index; index 0 is the "primary slot" whose IPv4 the template Host points at. `publicationEpoch`
bumps on every change that alters what subscribers should receive (pool, slot, profile, switch),
and is the cache token of the fronted subscription route.

### Rendering (what members receive)

Subscriptions are **rendered** by FCP, not rewritten on the panel. The panel keeps exactly one
template Host per slot. When the fronted `/api/v1/sub/<token>` route (or the mirror refresh)
fetches a body, it pins the node as before (a single-node body pins to that node; Clash/Mihomo
bodies pin by proxy name like the others), then replaces the node's template entries with the
subscriber's assigned endpoints. The node the pin chose, the render and the stored epoch token
share one value, and the subscription records the `publicationEpoch` it was rendered against
(`lastRenderedEpoch`, also stamped by the mirror refresh):

- assignment is a stable PRF keyed on the subscription's `renderKey` (random, never exposed):
  primary = pool index `h mod publishedCount` over the full pool order, walking forward past an
  edge that is not currently assignable so only that edge's subscribers move; backup = the next
  assignable edge in pool order (a different provider when `render.preferDistinctProviders` is
  on). An edge is assignable only with an address the family's `ipv6Mode` can emit;
- for a `reality` or `tls` profile, one server name per emitted connection, chosen from the
  profile's active set; a retired name is never selected again (it stays accepted by the node
  through its drain, and when `drainUntil` passes the epoch bumps and mirrors refresh). With no
  active name left the edge is not assignable. A `plain` profile has no server names: only
  address and port are rewritten and the template's own parameters are kept; a `tls` profile
  sets the Clash `servername` even when the template omitted it;
- IPv4 entries by default, plus IPv6 literals as separate bracketed entries when the edge has one
  (`render.ipv6Mode`, per family). An **L7 edge renders as ONE entry** whose hostname is the
  address, the SNI and the HTTP Host header (no IPv6 sibling; `ipv6Mode` does not apply to it);
- for the HTTP transports (`ws`, `httpupgrade`, `grpc`) the Host header is rewritten alongside
  the SNI (`host=` in links, `transport.headers.Host` / `transport.host` in sing-box,
  `ws-opts.headers.Host` in Clash) while the path and the gRPC service name are never touched;
  behind an L4 edge the Host header is the selected server name;
- per **client family** (sing-box, Mihomo, plain link-list clients…): auto-capable families get
  one named auto group (`urltest` / `url-test`), link-list families get labelled Primary/Backup
  entries; each family has an admin-editable rule (`render.clients.<family>`). Rendered labels
  and the auto-group name are de-duplicated against the template's own tags; a change to any
  `render.*` setting bumps every enabled relay's epoch and refreshes mirrors.

Rendering is fail-open for an **unknown** body shape only: it passes through unchanged. It is off
until `render.enabled` is set; preview any family per relay from the admin page. When an enabled
relay's eligible pool is **empty** (every edge unpublished or draining, or the profile disabled)
the template entries are **dropped** regardless of the family rule's flags, and every reference
to the dropped tag (rules, `route.final`, group defaults, detours) is pruned structurally rather
than the original body being served: the template Host still carries the former index-0
address, which an explicit unpublish must stop distributing. Unpublish, drop-from-pool, slot
retire and profile changes all bump the epoch and schedule a mirror refresh.

## Operations

| Operation                                | Precondition                                                                               | Spends budget                      | Writes Hosts                                  | Result                                                                                                                                                                 |
| ---------------------------------------- | ------------------------------------------------------------------------------------------ | ---------------------------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Import edge                              | origin + slot; optionally a provider account + the load balancer picked from its inventory | no                                 | no                                            | edge `active`; managed when imported from an account (FCP describes, rotates and destroys it), observe-only when entered by address (`managed:false`, never destroyed) |
| Provision edge                           | qualified account (the profile's provider when scoped; any otherwise), template, capacity  | yes                                | no                                            | edge `active` + `unpublished` (or published when requested)                                                                                                            |
| Publish edge                             | active, has IPv4, slot deployed (+ enabled profile with an active SNI for `reality`)       | no                                 | template Host only when taking index 0        | `published` at the lowest free index; epoch++                                                                                                                          |
| Replace (rotate / burn)                  | a published target edge                                                                    | unless a compatible standby exists | template Host only if the target held index 0 | new edge `published` at the SAME index; old `draining` (burn = short drain)                                                                                            |
| Unpublish / retire server name / profile | no running rotation, no quarantine                                                         | no                                 | no                                            | new selections stop; the node keeps accepting through the drain; epoch++ and mirrors refresh                                                                           |

`hostManaged:false` on a relay means FCP never writes the template Host: publishing at index 0
proceeds without a flip and replacing index 0 is refused (`edge.hosts_unmanaged`).

### The rotation machine

`convex/edgeRotations.ts`. Phases:

```
select → provisioning → verifying → publishing → host_flipping → confirming → finalizing → done
                                                        ↘ rolling_back → rolled_back | quarantined
(failed / cancelled from the early phases)
```

Recovery contract:

- **Step version.** Every mutation that advances a rotation carries the version it read; a stale
  actor's write is ignored. The `step` action does one bounded unit of work per invocation and
  never schedules itself: the mutation that records the outcome schedules the next step
  (mutation scheduling is transactional). Each step stamps `stepStartedAt`; the reconcile cron
  re-kicks a rotation whose step went stale (scheduled but never started, or started and never
  settled) and the re-kick bumps `stepVersion`, fencing the stale actor. Control flow reads
  persisted row fields (`viaStandby`, `createdEdgeId`, `hostPlanCaptured`,
  `forwardWriteAttempted`, `slotId`), never the bounded `events[]` log, which is display-only.
  A run is capped by `edge.maxRotationMinutes` (default 120) and by a step-error budget: past
  either, `publishing`/`host_flipping` roll back and `confirming`/`finalizing`/`rolling_back`
  quarantine. Cancel during `rolling_back` is recorded and audited but not acted on until the
  rollback settles.
- **Resource-step ledger.** `planProvision` yields the ordered steps; every child resource an
  adapter creates is recorded on the edge before anything else happens, including on partial
  failures. Destroy walks the ledger ordered by resource kind (load balancer, then floating IP,
  then gateway, then network), `present → delete_requested → confirmed_gone`. A provider without
  an async-delete confirmation is confirmed by re-issuing its idempotent delete, never by
  assuming the delete landed; an async-delete provider that reports the resource `still_present`
  (the delete never landed) gets the delete re-issued, as does one whose confirmation stays
  `unresolved` for several passes. An unknown resource kind is never assumed gone: it stays
  `unresolved` and parks the edge as `needs_operator`.
- **Operation claims.** Every external write (a provider step, a Host PATCH) is bracketed by a
  claim with an expiry. An expired, unsettled claim blocks any further allocating or destroying
  call until the outcome is re-observed.
- **Four-outcome discovery.** After an unknown outcome the adapter reports `found` (adopt the
  resource), `confirmed_absent` (safe to run the step again), `unresolved` (keep waiting, up to
  `discoveryTimeoutMinutes`) or `ambiguous` (candidates whose ownership cannot be proven: an
  operator decides; nothing is destroyed automatically). The count of consecutive unresolved
  looks is kept on the step (`discoverAttempts`), and `confirmed_absent` additionally needs a
  per-provider settle time since the step started (`discoverySettleMs`), so a slow compound
  create is never re-run 40 seconds after the request. A forward-write timeout (`timedOut`) is
  not a quiet look.
- **Observe-then-write Hosts.** The flip captures its plan from the live Host list first. A planned
  Host that later disappears or changes inbound is `hosts_changed`: the run rolls back the
  **complete previous binding** (edge, slot, profile, pool index, Host tuple) and never
  "converges" on a different Host. The flip writes the **full tuple** `{ address, port, sni,
host }` from `hostTargetFor`, so an L7 → L4 or L4 → L7 transition never leaves a stale CDN
  hostname in the SNI or Host header; `null` means "clear". Plans captured at snapshot version
  2 also record the previous SNI and Host and roll them back; a legacy plan (no snapshot
  version) rolls back address and port only, because its historical SNI/Host are unknown, not
  null, and operator configuration is never cleared on a guess.
- **Shared external resources.** A provider write that touches something several edges share
  (a zone's origin ruleset, a CDN service's version chain) is bracketed by an `externalLocks`
  claim keyed on that resource, not only by the edge's own op claim. An expired, unsettled lock
  blocks further writes until the holder re-observes the outcome.
- **Leak guard.** A template Host that points at the origin itself is never planned or
  written: the flip fails (`host_leaks_origin`) and rolls back until an operator repairs it.
- **Quarantine.** A rollback that cannot converge parks the relay in `quarantine`. Nothing
  bypasses it (no rotation, no delete, no automatic action) until an operator, having checked
  the panel by hand, resolves it keeping either the previous binding (the rollback's DB half
  already applied) or the current one (the new edge is republished at the saved pool index,
  after a publishability check, and the previous edge drains). The same guard (`edge.quarantined`
  / `edge.rotation_running`) refuses every direct pool or edge write while a rotation is
  running or the relay is quarantined: publish, unpublish, import-and-publish, delete edge,
  retry destroy, resolve `needs_operator`, publish standby. A restore that finds an unexpected
  occupant at the saved index evicts and unpublishes it with an audit row rather than silently
  overwriting. Toggling `hostManaged` is refused during a rotation; a replace that finds it off
  mid-flip rolls back (`hosts_unmanaged`) instead of reporting convergence.
- **Audit trail.** Every audit row a rotation produces carries its `rotationId` (the operator's
  request, publish/unpublish, flips, the outcome, quarantine and its resolution) and its id is
  kept in a bounded list on the rotation row, so the rotation detail (`GET …/rotations/{id}`,
  the CMS drawer) is complete for old rotations too and merges them with the live event log.

Live progress: the rotation row carries `events[]` (bounded) and the admin route
`GET /api/v1/admin/edges/rotations/{id}` returns steps + weighted percent; the CMS polls it every
2 s while the run is not terminal.

### Reconcile cron (`edge-reconcile`, 5 min)

Re-kicks stale rotations; settles edges with unknown outcomes by discovery; refreshes provider
health (a published edge the provider reports gone on **two consecutive** passes is dropped
from the pool, the epoch bumped and mirrors refreshed in one mutation, with an `edge.drift`
audit; a single 404, which a narrowed credential can also produce, does nothing); turns
drained / failed / cancelled edges into destroy runs (the attempt cap parks an edge as
`needs_operator`; reaching `destroyed` clears the stored live snapshot); publishes standbys
into free pool indexes (`autoPublishStandby`, through the same start guards as a manual
publish) or provisions up to `desiredPublished` / `standbyPerRelay` (`autoProvisionToDesired`,
off by default) — both only while `edge.enabled` is on; finishes relay deletes (the relay's
pool drains for `drainMinutes` unless the delete is forced). A standby-only provision is
finalized even if its slot is not publishable at that moment. Daily sweeps prune `destroyed`
edges (with their probe rollups, which never cascade) after 30 days and terminal rotations after 90 (`retention-edges`,
`retention-edge-rotations`).

## Probes and the block detector

### Probes (`edge-probe`, 5 min tick, `probe.*`)

FCP asks measurement services to open TCP connections to **its own addresses** from the
configured countries. Targets are the published edges of every relay (the only kind the detector
reads), relay nodes that opted in (`probeNode`, a direct-block signal) and operator-entered custom
host:port pairs (`probeTargets`); each is addressed as `<kind>:<id>`. Everything lives under
**Telemetry → Probes**: a time chart of outcomes (failing vantages by country), the matrix, run
history per target, "probe now" for any selection of targets, target management, the settings
and a probe audit feed. No member data is involved (see
`docs/privacy.md`). Sources:

- **Globalping** via the official SDK (TCP ping, per-country probe selection, eyeball vs
  datacenter tags; an optional token raises the rate limit);
- **check-host.net** (keyless TCP checks; `Accept: application/json` is required; kept to a few
  requests per minute);
- **RIPE Atlas** (optional, needs a key + credits);
- the **internal** connect check from FCP's own host, which distinguishes "down for everyone"
  from "blocked in a country" and is never a country signal.

Verdicts need agreement: within a source, `unreachable` requires `probe.agreementVantages`
(minimum 2) distinct failing networks and no success; the failing network identifiers are
persisted on the reachability row, so the cross-source check counts real networks. A network is
an ASN (RIPE Atlas reads its probes' ASNs from the probe registry; a probe id is not a network)
or a network name; vantages that identify neither collapse into ONE `<source>:unknown` bucket, so
a source can never fabricate agreement out of anonymous vantages. `reachable`
needs one residential success or two datacenter successes. A probe-side error (a vantage that
could not run, an unparsed answer) is neither; a TLS alert means the peer answered and counts as
reachable, as for the internal check. Every listener port of an edge is probed and rolled up per
(country, source, address family, port); sources agree per port, then the ports roll up per
country: any `unreachable` port makes the country unreachable (a blocked listener blocks that
slot), `mixed` passes through next, `reachable` needs every port with a verdict to be reachable,
else `unknown`. Runs are budgeted per hour (`probe.hourlyBudget`) on every path alike — cron,
"probe now" and detector-triggered: the requesting mutation counts the hour's runs (any trigger,
any state) and reserves its round atomically, refuses with `probe.budget_exhausted` when nothing
fits, and otherwise truncates a batch to whole targets in request order (duplicates collapse; the
rest come back in `skipped` as `<key>: probe.budget_exhausted`). A batch is staggered per source
by `probe.sourceSpacingMs` so no service sees a burst; the spacing shrinks so the batch's last run
is scheduled no further out than one probe interval (a lone request clamps each delay to that
span). A run records `scheduledAt`, and the stuck-run timeout (10 min) counts from there — or from
`startedAt` once it runs — never from the request, so a staggered run is not timed out before its
executor fires. Suspected origins are probed at `suspectedIntervalMinutes`. A target's summary
carries only verdicts from currently enabled sources; each country row has its own freshness, and
a country older than two probe intervals drops out of the detector's evidence even if another
country was just refreshed. A dual-stack edge is probed per address family and rolled up per
family: the country verdict follows the IPv4 path (what every member receives) and the IPv6 path
is reported alongside as `v6Verdict`. IPv6 probing follows `render.ipv6Mode` for edges (a family
members are never handed says nothing about them) and the separate `probe.ipv6` knob for relay
nodes and custom targets; a target with only a v6 address is probed over v6 either way. A target
with no listener port (an edge whose slots were retired, a relay with nothing deployed) is not
probeable at all and is skipped with `probe.no_listeners`: probing a guessed port would record
its silence as a block.

A target may also be a **hostname** rather than a literal: an L7 edge's fronted name, a relay
origin or a custom target entered as a name. A run then records three independent things -
`addressKind` (`ip` / `name`), `probeProtocol` (`tcp` / `tls` / `https`) and `requestedFamily`
(4 / 6 / `any`) - while `ipVersion` is the OBSERVED family and is absent for a name (the
vantage's own resolver decides). Rollups key on `ipVersion ?? 'name'`, and a target that has both
kinds of row reports the by-name path alongside the verdict as `nameVerdict`. Defaults: an L7
edge is probed with `tls` (a real handshake with SNI = the hostname, so a certificate or
handshake failure IS unreachable), while relay origins and custom targets keep the bare `tcp`
connect (a hostname does not imply HTTPS, and a REALITY or plaintext origin must not look blocked
for failing a handshake); a custom target can opt into `tls` or `https`. Per source: Globalping
`ping`/TCP vs an `http` measurement, check-host `check-tcp` vs `check-http`, RIPE Atlas `sslcert`
with the name as `hostname`, and the internal probe per protocol. Custom name targets must be
dotted (a single label would resolve through the control plane's own search domains) and the
internal probe resolves a name first, refusing it unless every answer is a public literal. Stored
error strings never carry a hostname. RIPE Atlas measurements are created private with a
non-identifying description. Settled runs are kept two weeks (`retention-edge-probes`, daily).

### Attribution

A member issue report is attributed server-side to the relay behind the key's pinned node
(`relaySlug`). The **edge** is set only when the member said which connection failed and that
choice resolves to exactly one edge under their own assignment (`connectionChoice`,
`relayEdgeId`); it is never inferred from the primary. Each member contributes at most one
detector weight per window via a time-independent peppered dedupe mark (`EDGE_MARK_PEPPER`,
falling back to `IP_HASH_SALT`; with neither set a report is stored with weight 0 and no edge
attribution); the telemetry row stays unlinked. `refreshNotObserved` marks a key whose last
rendered `publicationEpoch` is older than the relay's current one (older keys fall back to the
last-rotation timestamp): such a report is still on the OLD pool, so it gets no edge attribution
(it would otherwise land on the healthy replacement).

### Detector (`edge-block-detector`, 5 min, `detect.*`)

Per relay: attributed reports in the window (deduplicated), the node's live user count against
its own **time-of-day** baseline (the same hour on previous days; samples taken while suspected,
rotating, in cooldown, with the node offline, with stale node stats or on an incomplete window
are not added to the baseline), and probe
verdicts per edge. Probe evidence is a **transition**, judged per listener port before the ports roll up: a
country that reached a port before and now finds that same port `unreachable` with agreement
scores that edge at 1.0; a port that has never been reached from that country is not evidence,
however long another port's reachable history is (`wasReachable` on the summary). That reachable
history is read over ALL of the target's rows, whatever their source and however old: disabling a
source, or letting its rows age out, must not erase the fact that the country once reached the
edge and so disarm the transition marker. The signal is the last SUCCESS (`lastOkAt`), not the
last fully-`reachable` verdict, so a country that only ever saw a degraded (`mixed`) path still
counts as having reached the edge. A fresh probe verdict alone can reach suspicion when
`allowProbeOnlyAutoRotate` is on. Relay-level evidence can only **hint** (the dashboard strip and
the relay badge). An **automatic rotation** needs, in order: `edge.enabled`, `edge.autoRotate`,
the relay's `autoRotate`, a suspected state, a COMPLETE report window (the window is aggregated
page by page up to `detect.maxReportRowsPerEval`; past that cap it is marked incomplete, the
suspicion and its hint still show but the veto is `evidence_incomplete` and nothing rotates on a
truncated count), edge-level evidence (probes, or members naming the
connection with enough share, counted after the per-member dedupe), the relay node being online
(`node_offline`), the edge not being an outage (internal probe and provider health say the edge
itself is up), the block not affecting every published edge alike (`protocol_level_block`:
rotating an address cannot help), no quarantine, no running rotation, cooldown and daily cap not
reached, and a manageable Host when the target holds index 0. The resulting rotation is a
**burn** (short drain). Every refusal is recorded on the relay as the veto so the operator sees
why nothing happened.

### Adopting an existing front

Importing what already fronts a node ("Import edge") records the provider resource's real
identity (record id / service id and version / domains / TLS subscription) so discovery and
destroy never depend on a generated name. For a shared resource (a service or subscription that
also serves other hostnames) the edge is **shared**: FCP publishes and rotates it but deletes
only the owned children (its domain, its DNS records) through a persisted per-service version
workflow (clone → remove domain → validate → activate → confirm, serialized per service; a
lost clone is re-found by its marker or parked as `needs_operator`; the active version is
re-read before every activation and a drift parks the edge). Exclusivity is re-checked before
any destructive step. A record whose content is not the relay's origin, or a service the
account does not own, is refused.

## Configuration

`edge.*` in `appSettings` (Admin → Edges → the config tab, and the probe settings under
Telemetry → Probes; both `GET/PATCH /api/v1/admin/edges/config`). Ships fully dormant: `enabled=false`, `autoRotate=false`,
`render.enabled=false`, `probe.enabled=false`, `l7.autoSelect=false`. Probe credentials are write-only
(`edge.secret.probe.*`, env fallback `EDGE_PROBE_GLOBALPING_TOKEN` /
`EDGE_PROBE_RIPEATLAS_KEY`). Defaults and bounds: `convex/lib/edgeConfig.ts`. The L7 knobs are
`edge.l7.autoSelect`, `edge.l7.maxSameProviderReplacementsPerDay`, `edge.l7.qualifyTimeoutMinutes`,
`edge.l7.qualifyStepTimeoutMs` and `edge.l7.qualificationTtlMinutes`; `edge.probe.ipv6` decides
whether relay and custom targets are probed over IPv6; `edge.detect.maxReportRowsPerEval` caps the
report rows one detector evaluation reads (past it the window is incomplete and nothing rotates).

## Sealing

Every route under `/api/v1/admin/edges/` carries credentials, addresses, provider handles or
live LB data, so the whole prefix is sealed by verb in `src/shared/crypto/envelope.ts`: GET
reveals the response to the caller's ephemeral key, POST seals the request AND reveals the
response (the response ephemeral rides inside the sealed body), PATCH/PUT seal the request,
DELETE carries nothing. Dual-mode (plaintext accepted) stays for `fsv1_` IaC callers, as for
backend servers; `FS_HPKE_ADMIN_REQUIRED=true` additionally refuses plaintext from cookie-session
(passkey CMS) callers on these routes (`hpke.sealed_required`) while bearer callers, who cannot
seal, keep dual-mode. The caller class follows the credential that would authenticate the
request, exactly as `resolveAdmin` does: the admin cookie is tried first, and only when it does
not authenticate (absent, stale, malformed, inactive admin, failed proof of possession) is the
bearer the caller. A passkey session therefore cannot downgrade itself to plaintext by adding any
bearer header, bogus or a real low-privilege token, while a valid token is never refused for a
dead browser cookie riding along. A malformed percent escape in a path is a `400 validation` on every verb.
Provider-API-calling POSTs (credential test, discover, inventory / live / node refresh, render
preview, credential rotation) and manual probes are rate-limited per actor
(`admin.edges.provider-call`, `admin.edges.probe`). Read-only POSTs (render preview, template
validate) need only `admin:servers:read`; seeding default templates is an explicit
`POST templates/ensure-defaults` rather than a side effect of GET. `convex/httpEdges.test.ts` pins the policy and a seal-both round trip.

## Node role contract (Ansible)

The role deploys, per relay node and per slot (one per protocol profile the node serves), one
inbound and one
template Host, and registers both with FCP using an `fsv1_` token with `admin:servers:write`.
The L7 additions below are a **release dependency** for L7 automatic selection: `edge.l7.autoSelect`
stays off until the role registers them and a qualification run has passed.

1. `PUT /api/v1/admin/edges/relays/by-slug/{hostname}` with
   `{ backendServerSlug, nodeHostname, originAddress, locationCode?, modeSlugs? }`
   (idempotent). Only those fields are honored on an update: the role can never set or flip the
   operator-owned knobs (`autoRotate`, `hostManaged`, `enabled`, `probeNode`, `desiredPublished`,
   cooldown / drain / daily-cap limits, provider preference); a create always starts with
   `autoRotate:false`. A PUT on a relay that is being deleted is refused (`edge.deleting`), and
   re-parenting to another `backendServerSlug` is refused while the relay has non-destroyed
   edges (`edge.relay_reparent_locked`). The response carries `publishedEndpoints`. One origin
   per (backend server, node) is enforced (`edge.node_already_bound`), and `originAddress`
   cannot change while the origin has live edges (`edge.origin_address_locked`): edges carry
   the address in their listener members, so a moved node means draining or destroying its
   edges first (or registering a new origin).
2. `PUT /api/v1/admin/edges/relays/by-slug/{hostname}/slots/{slotKey}` with
   `{ profileSlug, inboundTag, configProfileUuid, configProfileInboundUuid, originPort,
originTransport? }` per inbound; the profile (by slug) carries the protocol. For an inbound
   an L7 front may dial, `originTransport = { scheme: 'http' | 'https', certPublic, certNames[],
acceptsHostHeader: 'any' | 'names' }` declares how the CDN reaches it (plaintext origins are
   L7-only; an `https` origin behind the WebSocket CDN path needs a publicly trusted
   certificate on port 443). Changing the inbound uuid or the profile re-binds the slot (the
   template Host must be recreated).
3. Poll `GET /api/v1/admin/edges/relays/by-slug/{hostname}` until `publishedEndpoints[0]`
   exists, then create ONE template Host per slot: remark `<hostname>-relay-<slotKey>`, address =
   `publishedEndpoints[0].hostname` for an L7 edge or its index-0 IPv4 for an L4 edge, port =
   its port, SNI = `publishedEndpoints[0].sni` (the hostname for L7, the first active server
   name otherwise), HTTP Host header = `publishedEndpoints[0].hostHeader` when not null,
   `overrideSniFromAddress:false`. `publishedEndpoints` lists role-usable edges only (an
   address, a deployed slot, an enabled profile, a current front qualification for L7): a
   published edge that is not usable is omitted so the role keeps waiting instead of configuring
   a dud.
4. Re-runs read FCP state first and never rewrite an FCP-owned Host address; server names are
   removed from the node only after their `drainUntil`.
5. Teardown: `DELETE /api/v1/admin/edges/relays/by-slug/{hostname}`, then Host cleanup by the
   `<hostname>-relay-*` remark pattern.

Node pinning understands the relay remark (`convex/lib/nodePinning.ts`), so a node's relay
templates pin with the node like its other Hosts.

## Runbooks

**Qualify a provider account.** Add the account and test its credentials; provision a test edge
on a relay (unpublished); open an authenticated REALITY session through the edge with a real
client and hold it idle for several minutes; pull the live view; then "Mark qualified" (the
effective template's hash is recorded server-side). Editing the account's credentials or
settings through the ordinary update clears the qualification; so does any template change that
moves the account's **effective** template: the parameters of the template it names or falls
back to, a new or switched default in its scope, or the removal of the template it used (the
effective template hash is compared before and after every template write; audited as
`edge.provider_account.qualified` with `qualified:false`). An account may name only an unscoped
template or one scoped to itself as its default. A routine
secret rotation goes through **Rotate credentials** (`POST …/providers/{id}/rotate-credentials`):
the new credentials are tested first, nothing that locates resources may change, and the
qualification is kept (audited as `edge.provider_account.credentials_rotated`, booleans only).
Only the settings that locate resources (project, region, zone, network) are locked while any
non-destroyed edge references the account: destroy those edges first, or add a second account.
Non-locating identifiers that some providers pair with the secret can change at any time. Switching the
account's default template also clears the qualification. An account-scoped profile
provisions and publishes edges from that account only. A slot's inbound, profile or origin port
cannot change while non-destroyed edges use the slot (register a new slot key instead).

**Bootstrap a relay.** Add the provider account (its existing load balancers are inventoried
automatically; "Refresh" re-pulls), register the relay from the panel node picker (or via the
role), then "Import edge": pick the load balancer that already fronts the node from the account's
inventory (its addresses fill in; it becomes a managed edge) and publish it at index 0. Provision
a second edge (published at index 1), enable rendering, preview each client family, then rotate
index 1 and index 0 while watching the progress view. A load balancer FCP must never touch can be
recorded by address instead (observe-only).

**Resolve a quarantine.** Compare the panel's template Host with the two bindings the rotation
recorded, fix the Host by hand if needed, then resolve keeping the binding that matches what the
panel serves. Nothing else on that origin runs until then.

**An edge is `needs_operator`.** Discovery could not prove what exists at the provider (an
ambiguous or timed-out resource). Check the provider console; then either "Destroy" (trust the
ledger and delete), "Reactivate" (the resource is fine) or "Forget" (you cleaned up by hand).

**Add a DNS-hosting (proxying CDN) account.** Create an API token scoped to the one zone the
edges will live in with: Zone DNS Edit, Zone Read, Zone Settings Read, SSL and Certificates Read
(certificate readiness) and Origin Rules Edit (only when origin ports other than the zone
mode's default are needed; ten origin rules on the free plan). The zone must be active, not
paused, with WebSockets on; its encryption mode (`flexible` / `full` / `strict`) is recorded
and checked against each slot's origin transport at plan time (`flexible` = plaintext origin
on port 80, `full` / `strict` = HTTPS origin on 443; `strict` needs a publicly trusted origin
certificate). gRPC has no API toggle FCP can read: enable it on the zone by hand before a gRPC
profile is published (the front qualification catches the CDN's `403` otherwise), and note
that gRPC requires origin port 443 (no port override). The hostname is one first-level label
under the zone apex, which the CDN's default certificate covers. Rate limit: 1,200 API
requests per five minutes per user, shared with the dashboard.

**Add a service-CDN account (hostnames' DNS in a DNS-hosting account).** The token needs the
`global` scope on a dedicated automation user (service-scoped tokens cannot create services or
manage TLS subscriptions; the 1,000 writes per hour limit is per user) and the account needs the
WebSockets product entitlement (a paid plan) and, for `globalsign`, a paid plan too (free
accounts get two managed-certificate domains from `certainly` / `lets-encrypt`). Pick the
DNS-hosting account whose zone will carry the hostnames; FCP writes the ACME validation CNAME
and, once the certificate is issued, the traffic CNAME into it, so that account's zone is
locked while any such edge exists and editing its credentials clears the qualification of every
account that depends on it. The WebSocket path honours only the backend's name, address, TLS
flag and Host override, so a slot behind it must declare `originTransport` as `https` with a
publicly trusted certificate on port 443 or `http` on port 80. A CAA record on the zone must
permit the chosen certificate authority (checked before issuance).

**Qualify an L7 front.** Mint the relay's qualification credential (`POST
…/relays/{id}/qualification-credential`, or the button in the relay drawer: a capped panel
account on the relay's placement, deactivated again on revoke or relay delete), register the
slot with its `originTransport` and the HTTP-transport profile, provision an edge (unpublished),
then "Qualify now" on it (or wait for the `verifying` phase): the authenticated session must
reach the tunnel target and return `204`.
Publish only after the qualification is current. Keep `edge.l7.autoSelect` off until the node
role registers the L7 fields on every relay that should take part in automatic replacement.

## Adding an edge provider

Everything derives from the id tuple in `src/shared/contracts/edgeProviderIds.ts`; every
`Record<EdgeProviderId, …>` fails to compile until the new id has an entry:

1. `src/shared/contracts/edgeProviderIds.ts`: add the id.
2. `convex/lib/edges/accountSettings.ts`: the settings zod schema and its classification into
   locating settings, credential identifiers and intent defaults (`accountSettings.test.ts` pins
   that every key is exactly one of them); `convex/schema.ts`: the credentials and settings
   union variants (`edgeProviderIds.test.ts` pins them).
3. `convex/lib/edges/providers/templates.ts`: the template schema, field descriptors and
   defaults; `providers/capabilities.ts`: the capability row (layer, address kind, transports,
   DNS roles, origin-port mode, async and health flags, settle floor); `capabilities.test.ts`
   cross-checks each flag against the adapter.
4. `convex/lib/edges/providers/<id>.ts`: the `EdgeProvider` adapter (official SDK behind a typed
   wrapper when one exists, else `providerFetch`; body-free errors; deterministic resource
   names; four-outcome discovery; destroy confirmed by read-back), registered in
   `providers/registry.ts`, with `<id>.test.ts` on the recording transport.
5. `convex/lib/edges/providers/wireContract.ts`: every endpoint the adapter calls, with a
   source; `wireContract.test.ts` drives the lifecycle and refuses undeclared or dead entries;
   the table below is generated from it. `.github/workflows/edge-providers.yml`: add the id to
   the matrix.
6. `scripts/node-floor.mjs` when the adapter imports an npm dependency; `src/client/lib/
edgeProviderMeta.ts` and `EdgeProvidersPanel.svelte` for the account form.

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
| cloudflare | GET    | `^/client/v4/zones/[^/]+/dns_records/[^/]+$`                                      | read the record back: describe, inspect, delete confirmation                                                      | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | DELETE | `^/client/v4/zones/[^/]+/dns_records/[^/]+$`                                      | delete the record (a Fastly edge deletes its records here too)                                                    | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/rulesets/phases/http_request_origin/entrypoint$`         | read the origin-rules entry point (404 = none yet)                                                                | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | PUT    | `^/client/v4/zones/[^/]+/rulesets/phases/http_request_origin/entrypoint$`         | bootstrap the entry point with our one origin rule, under the zone lock                                           | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | POST   | `^/client/v4/zones/[^/]+/rulesets/[^/]+/rules$`                                   | add the destination-port origin rule, recovered by its ref                                                        | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | DELETE | `^/client/v4/zones/[^/]+/rulesets/[^/]+/rules/[^/]+$`                             | delete the origin rule                                                                                            | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| cloudflare | GET    | `^/client/v4/zones/[^/]+/ssl/certificate_packs$`                                  | certificate readiness for the minted hostname                                                                     | https://developers.cloudflare.com/api/ via cloudflare@7.1.0, 2026-09-16                                                                                                           |
| fastly     | POST   | `^/service$`                                                                      | create the VCL service (form encoded)                                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service$ ?page&per_page`                                                       | paged service sweep for the import inventory                                                                      | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/search$ ?name`                                                         | discover the service by its deterministic name (404 = absent)                                                     | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/details$`                                                        | active version: activation discovery, describe, drift check                                                       | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
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
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/domain$`                                           | list the version domains: inspect and shared-teardown confirmation                                                | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/domain/[^/]+$`                                     | discover the domain by name; read it back after a destroy                                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/service/[^/]+/version/[^/]+/domain/[^/]+/check$`                               | DNS readiness of the fronted hostname                                                                             | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/service/[^/]+/version/[^/]+/domain/[^/]+$`                                     | remove only our hostname from a shared service                                                                    | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | PUT    | `^/enabled-products/v1/websockets/services/[^/]+$`                                | enable the WebSockets product on the service (idempotent)                                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/enabled-products/v1/websockets/services/[^/]+$`                                | discover the product state; read it back after a destroy                                                          | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/enabled-products/v1/websockets/services/[^/]+$`                                | disable the product last, after the service is gone                                                               | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | POST   | `^/tls/subscriptions$`                                                            | order the certificate for the fronted hostname (JSON:API)                                                         | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tls/subscriptions$ ?filter[tls_domains.id]`                                    | discover the subscription by domain; confirm its removal                                                          | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tls/subscriptions/[^/]+$`                                                      | issuance state and (with the include) the managed-DNS challenge                                                   | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | DELETE | `^/tls/subscriptions/[^/]+$ ?force`                                               | delete the subscription (force, since its domain is enabled)                                                      | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tls/configurations$`                                                           | account form choices, and the CNAME target every fronted hostname points at                                       | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/tokens/self$`                                                                  | credential test: the token scope                                                                                  | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |
| fastly     | GET    | `^/current_customer$`                                                             | credential test: the pricing plan (informational)                                                                 | https://www.fastly.com/documentation/reference/api/ via fastly@16.1.0, 2026-09-16; the DNS records this adapter writes are Cloudflare API calls and are listed under `cloudflare` |

## Deploy notes

The `"use node"` actions (provider SDKs, probes, the front qualification) run on the Node
version baked into the self-hosted Convex backend image. The L7 adapters add `cloudflare` (the
official TypeScript SDK, retries off) and `fastly` (the official JavaScript SDK behind a typed
wrapper; it pulls in `superagent`); both bundle into the Node action without external packages. `scripts/node-floor.mjs` derives the highest `engines.node`
floor among those dependencies and `docker/deploy-entrypoint.sh` fails the deploy when the
runtime is below it (`DEPLOY_SKIP_NODE_FLOOR=true` bypasses). The check runs BEFORE the push when
the running deployment already exposes the runtime probe (so incompatible code is never
published first) and again after it; only the first deploy of the guard checks after its own
push. The observed version shows on the admin dashboard.
