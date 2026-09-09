# Edges

A **relay** is a node whose protocols need an L4 forwarder in front of it (REALITY first;
any TCP inbound the node terminates itself works the same way). An **edge** is that
forwarder: a provider-managed cloud load balancer that forwards a port to the node. Censors
block the edge's public address, not the node, so the edge is the unit that gets replaced.
Edges are protocol-agnostic; what a slot speaks decides only what the renderer rewrites in a
member's connection. This document describes how FCP provisions, publishes, rotates and
observes edges, and the contract the node role (Ansible) follows. It is provider-neutral on
purpose: nothing here says which providers, regions, targets or names a given deployment uses.

Admin surface: **Admin → Edges** (`/admin/edges`) and `/api/v1/admin/edges/*`; probe
telemetry lives under **Admin → Telemetry → Probes** (`/admin/telemetry/probes`, its own nav
entry beside User reports). Every request
under the API prefix is HPKE-sealed by verb class (see [Sealing](#sealing)).

## Model

| Concept          | Table                  | Meaning                                                                                                                                                                                                                                             |
| ---------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Provider account | `edgeProviderAccounts` | One cloud account: write-only credentials, fixed settings (project/region/zone/network), priority, a daily allocation budget, a live-edge cap, `qualified`.                                                                                         |
| Edge template    | `edgeTemplates`        | Per provider (optionally per account): the full provisioning parameters, validated by the adapter's schema. Provisioning records the template hash.                                                                                                 |
| Protocol profile | `protocolProfiles`     | What a slot's inbound speaks (`reality` / `tls` / `plain`) plus what the renderer needs: server names (REALITY SNIs or certificate names; none for `plain`) and, for REALITY, the impersonated target. Optionally scoped to one provider's network. |
| Relay            | `relays`               | One node behind edges: its origin address (what edges dial), published pool, publication epoch, rotation limits, detector state, quarantine, `probeNode`.                                                                                           |
| Slot             | `relaySlots`           | One inbound on the relay (port + panel inbound uuid) deployed by the role for one protocol profile, with ONE template Host (remark `<node>-relay-<slotKey>`).                                                                                       |
| Edge             | `edges`                | One provider load balancer bound to a relay slot: the resource-step ledger, child resources, addresses, publication state and pool index, health, live snapshot, reachability.                                                                      |
| Rotation         | `edgeRotations`        | One provision / publish / replace run: phase, step version, operation claim, Host plan, previous binding, live event log; its audit trail is assembled on read.                                                                                     |
| Probe target     | `probeTargets`         | An operator-entered public host:port probed alongside the derived targets (edges, relay nodes); private, loopback and link-local literals are refused. Operator evidence only.                                                                      |
| Probe run        | `probeRuns`            | One reachability measurement of one target address (edge, relay node or custom) from one source.                                                                                                                                                    |
| Reachability     | `probeReachability`    | Per target, per country, per source, per address family: the last run's vantage counts and verdict; summarised onto the target's own row.                                                                                                           |

The supported providers are listed in `src/shared/contracts/edgeProviderIds.ts`; each has an
adapter under `convex/lib/edges/providers/` implementing `EdgeProvider`. Generic code never
branches on a provider id; it reads `EDGE_PROVIDER_CAPABILITIES` and the adapter's template schema.

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
  (`render.ipv6Mode`, per family);
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
  **complete previous binding** (edge, slot, profile, pool index, Host address) and never
  "converges" on a different Host.
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
edges after 30 days and terminal rotations after 90 (`retention-edges`,
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
persisted on the reachability row, so the cross-source check counts real networks. `reachable`
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
is reported alongside as `v6Verdict`. RIPE Atlas measurements are created private with a
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
rotating, in cooldown or with the node offline are not added to the baseline), and probe
verdicts per edge. Probe evidence is a **transition**: a country that was reachable from that
edge and is now `unreachable` with agreement scores that edge at 1.0; a country that was never
reachable from it is not evidence. A fresh probe verdict alone can reach suspicion when
`allowProbeOnlyAutoRotate` is on. Relay-level evidence can only **hint** (the dashboard strip and
the relay badge). An **automatic rotation** needs, in order: `edge.enabled`, `edge.autoRotate`,
the relay's `autoRotate`, a suspected state, edge-level evidence (probes, or members naming the
connection with enough share, counted after the per-member dedupe), the relay node being online
(`node_offline`), the edge not being an outage (internal probe and provider health say the edge
itself is up), the block not affecting every published edge alike (`protocol_level_block`:
rotating an address cannot help), no quarantine, no running rotation, cooldown and daily cap not
reached, and a manageable Host when the target holds index 0. The resulting rotation is a
**burn** (short drain). Every refusal is recorded on the relay as the veto so the operator sees
why nothing happened.

## Configuration

`edge.*` in `appSettings` (Admin → Edges → the config tab, and the probe settings under
Telemetry → Probes; both `GET/PATCH /api/v1/admin/edges/config`). Ships fully dormant: `enabled=false`, `autoRotate=false`,
`render.enabled=false`, `probe.enabled=false`. Probe credentials are write-only
(`edge.secret.probe.*`, env fallback `EDGE_PROBE_GLOBALPING_TOKEN` /
`EDGE_PROBE_RIPEATLAS_KEY`). Defaults and bounds: `convex/lib/edgeConfig.ts`.

## Sealing

Every route under `/api/v1/admin/edges/` carries credentials, addresses, provider handles or
live LB data, so the whole prefix is sealed by verb in `src/shared/crypto/envelope.ts`: GET
reveals the response to the caller's ephemeral key, POST seals the request AND reveals the
response (the response ephemeral rides inside the sealed body), PATCH/PUT seal the request,
DELETE carries nothing. Dual-mode (plaintext accepted) stays for `fsv1_` IaC callers, as for
backend servers; `FS_E2EE_ADMIN_REQUIRED=true` additionally refuses plaintext from cookie-session
(passkey CMS) callers on these routes (`e2ee.sealed_required`) while bearer callers, who cannot
seal, keep dual-mode. A malformed percent escape in a path is a `400 validation` on every verb.
Provider-API-calling POSTs (credential test, discover, inventory / live / node refresh, render
preview, credential rotation) and manual probes are rate-limited per actor
(`admin.edges.provider-call`, `admin.edges.probe`). Read-only POSTs (render preview, template
validate) need only `admin:servers:read`; seeding default templates is an explicit
`POST templates/ensure-defaults` rather than a side effect of GET. `convex/httpEdges.test.ts` pins the policy and a seal-both round trip.

## Node role contract (Ansible)

The role deploys, per relay node and per slot (one per protocol profile the node serves), one
inbound and one
template Host, and registers both with FCP using an `fsv1_` token with `admin:servers:write`:

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
   `{ profileSlug, inboundTag, configProfileUuid, configProfileInboundUuid, originPort }`
   per inbound; the profile (by slug) carries the protocol. Changing the inbound uuid or the
   profile re-binds the slot (the template Host must be recreated).
3. Poll `GET /api/v1/admin/edges/relays/by-slug/{hostname}` until `publishedEndpoints[0]`
   exists, then create ONE template Host per slot: remark `<hostname>-relay-<slotKey>`, address =
   the index-0 IPv4, port = its port, SNI = the first active server name,
   `overrideSniFromAddress:false`.
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
settings through the ordinary update clears the qualification; so does changing the parameters
of a template the account was qualified with, names as its default, or falls back to as the
provider default (audited as `edge.provider_account.qualified` with `qualified:false`). A routine
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

## Deploy notes

The `"use node"` actions (provider SDKs, probes) run on the Node version baked into the
self-hosted Convex backend image. `scripts/node-floor.mjs` derives the highest `engines.node`
floor among those dependencies and `docker/deploy-entrypoint.sh` fails the deploy when the
runtime is below it (`DEPLOY_SKIP_NODE_FLOOR=true` bypasses). The check runs BEFORE the push when
the running deployment already exposes the runtime probe (so incompatible code is never
published first) and again after it; only the first deploy of the guard checks after its own
push. The observed version shows on the admin dashboard.
