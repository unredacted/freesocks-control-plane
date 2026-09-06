# Relay edges

Freedom Mode REALITY nodes are reached through an external TCP edge: a cloud load balancer
that forwards `:443` to the node. Censors block the edge's public address, not the node, so
the edge is the unit that gets replaced. This document describes how FCP provisions,
publishes, rotates and observes those edges, and the contract the node role (Ansible)
follows. It is provider-neutral on purpose: nothing here says which providers, regions,
targets or names a given deployment uses.

Admin surface: **Admin → Relay edges** (`/admin/relays`) and `/api/v1/admin/relay/*`.
Every request under that prefix is HPKE-sealed by verb class (see [Sealing](#sealing)).

## Model

| Concept            | Table                     | Meaning                                                                                                                                                      |
| ------------------ | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Provider account   | `relayProviderAccounts`   | One cloud account: write-only credentials, fixed settings (project/region/zone/network), priority, a daily allocation budget, a live-edge cap, `qualified`.  |
| Edge template      | `relayEdgeTemplates`      | Per provider (optionally per account): the full provisioning parameters, validated by the adapter's schema. Provisioning records the template hash.          |
| Camouflage profile | `relayCamouflageProfiles` | Provider-scoped REALITY target (address:port) + the approved server names (`active` / `retired` with a drain window).                                        |
| Origin             | `relayOrigins`            | One REALITY node behind edges: its published pool, publication epoch, rotation limits, detector state, quarantine.                                           |
| Slot               | `relayOriginSlots`        | One origin inbound (port + panel inbound uuid) deployed by the role for one profile, with ONE template Host (remark `<node>-relay-<slotKey>`).               |
| Edge               | `relayEdges`              | One provider load balancer: the resource-step ledger, the child resources, addresses, publication state and pool index, health, live snapshot, reachability. |
| Rotation           | `relayRotations`          | One provision / publish / replace run: phase, step version, operation claim, Host plan, previous binding, live event log.                                    |
| Probe run          | `relayProbeRuns`          | One reachability measurement of one edge address from one source.                                                                                            |
| Reachability       | `relayEdgeReachability`   | Per edge, per country, per source: the last run's vantage counts and verdict.                                                                                |

The supported providers are listed in `src/shared/contracts/edgeProviderIds.ts`; each has an
adapter under `convex/lib/relays/providers/` implementing `EdgeProvider`. Generic code never
branches on a provider id; it reads `EDGE_PROVIDER_CAPABILITIES` and the adapter's template schema.

### Publication

Provisioning and publication are separate. An edge is `unpublished` (a standby: paid for, not
rendered), `published` at a **pool index**, or `draining` (still serving old subscribers,
scheduled for destruction after the drain). An origin's `publishedEdgeIds` is ordered by pool
index; index 0 is the "primary slot" whose IPv4 the template Host points at. `publicationEpoch`
bumps on every change that alters what subscribers should receive (pool, slot, profile, switch),
and is the cache token of the fronted subscription route.

### Rendering (what members receive)

Subscriptions are **rendered** by FCP, not rewritten on the panel. The panel keeps exactly one
template Host per slot. When the fronted `/api/v1/sub/<token>` route (or the mirror refresh)
fetches a body, it pins the node as before, then replaces the node's template entries with the
subscriber's assigned endpoints:

- assignment is a stable PRF keyed on the subscription's `renderKey` (random, never exposed):
  primary = pool index `h mod publishedCount`, backup = the next edge in pool order (a different
  provider when `render.preferDistinctProviders` is on);
- one server name per emitted connection, chosen from the slot profile's active set; a retired
  name stops being selected but stays accepted by the node through its drain;
- IPv4 entries by default, plus IPv6 literals as separate bracketed entries when the edge has one
  (`render.ipv6Mode`, per family);
- per **client family** (sing-box, Mihomo, plain link-list clients…): auto-capable families get
  one named auto group (`urltest` / `url-test`), link-list families get labelled Primary/Backup
  entries; each family has an admin-editable rule (`render.clients.<family>`).

Rendering is fail-open: an unknown body shape passes through unchanged. It is off until
`render.enabled` is set; preview any family per origin from the admin page.

## Operations

| Operation                                | Precondition                                                  | Spends budget                      | Writes Hosts                                  | Result                                                                      |
| ---------------------------------------- | ------------------------------------------------------------- | ---------------------------------- | --------------------------------------------- | --------------------------------------------------------------------------- |
| Adopt edge                               | origin + slot                                                 | no                                 | no                                            | edge `active`, observe-only (`managed:false`, never destroyed)              |
| Provision edge                           | qualified account of the slot's provider, template, capacity  | yes                                | no                                            | edge `active` + `unpublished` (or published when requested)                 |
| Publish edge                             | active, has IPv4, slot deployed, profile enabled + active SNI | no                                 | template Host only when taking index 0        | `published` at the lowest free index; epoch++                               |
| Replace (rotate / burn)                  | a published target edge                                       | unless a compatible standby exists | template Host only if the target held index 0 | new edge `published` at the SAME index; old `draining` (burn = short drain) |
| Unpublish / retire server name / profile | —                                                             | no                                 | no                                            | new selections stop; the node keeps accepting through the drain             |

`hostManaged:false` on an origin means FCP never writes the template Host: publishing at index 0
proceeds without a flip and replacing index 0 is refused (`relay.hosts_unmanaged`).

### The rotation machine

`convex/relayRotations.ts`. Phases:

```
select → provisioning → verifying → publishing → host_flipping → confirming → finalizing → done
                                                        ↘ rolling_back → rolled_back | quarantined
(failed / cancelled from the early phases)
```

Recovery contract:

- **Step version.** Every mutation that advances a rotation carries the version it read; a stale
  actor's write is ignored. The `step` action does one bounded unit of work per invocation and
  never schedules itself: the mutation that records the outcome schedules the next step
  (mutation scheduling is transactional). The reconcile cron re-kicks a rotation whose next step
  went stale (a crashed action).
- **Resource-step ledger.** `planProvision` yields the ordered steps; every child resource an
  adapter creates is recorded on the edge before anything else happens, including on partial
  failures. Destroy walks the ledger in reverse (`present → delete_requested → confirmed_gone`);
  a provider without an async-delete confirmation is confirmed by re-issuing its idempotent
  delete, never by assuming the delete landed.
- **Operation claims.** Every external write (a provider step, a Host PATCH) is bracketed by a
  claim with an expiry. An expired, unsettled claim blocks any further allocating or destroying
  call until the outcome is re-observed.
- **Four-outcome discovery.** After an unknown outcome the adapter reports `found` (adopt the
  resource), `confirmed_absent` (safe to run the step again), `unresolved` (keep waiting, up to
  `discoveryTimeoutMinutes`) or `ambiguous` (candidates whose ownership cannot be proven: an
  operator decides; nothing is destroyed automatically). The count of consecutive unresolved
  looks is kept on the step (`discoverAttempts`), so adapters that want two quiet looks before
  `confirmed_absent` get them even though each pass settles its claim.
- **Observe-then-write Hosts.** The flip captures its plan from the live Host list first. A planned
  Host that later disappears or changes inbound is `hosts_changed`: the run rolls back the
  **complete previous binding** (edge, slot, profile, pool index, Host address) and never
  "converges" on a different Host.
- **Quarantine.** A rollback that cannot converge parks the origin in `quarantine`. Nothing
  bypasses it (no rotation, no delete, no automatic action) until an operator, having checked
  the panel by hand, resolves it keeping either the previous or the current binding.

Live progress: the rotation row carries `events[]` (bounded) and the admin route
`GET /api/v1/admin/relay/rotations/{id}` returns steps + weighted percent; the CMS polls it every
2 s while the run is not terminal.

### Reconcile cron (`relay-edge-reconcile`, 5 min)

Re-kicks stale rotations; settles edges with unknown outcomes by discovery; refreshes provider
health (a published edge the provider no longer has is dropped from the pool with a
`relay.drift` audit); turns drained / failed / cancelled edges into destroy runs (the attempt
cap parks an edge as `needs_operator`); publishes standbys into free pool indexes
(`autoPublishStandby`) or provisions up to `desiredPublished` / `standbyPerRelay`
(`autoProvisionToDesired`, off by default); finishes origin deletes.

## Probes and the block detector

### Probes (`relay-probe`, 5 min tick, `probe.*`)

FCP asks measurement services to open TCP connections to **its own edge addresses** from the
configured countries. No member data is involved (see `docs/privacy.md`). Sources:

- **Globalping** via the official SDK (TCP ping, per-country probe selection, eyeball vs
  datacenter tags; an optional token raises the rate limit);
- **check-host.net** (keyless TCP checks; `Accept: application/json` is required; kept to a few
  requests per minute);
- **RIPE Atlas** (optional, needs a key + credits);
- the **internal** connect check from FCP's own host, which distinguishes "down for everyone"
  from "blocked in a country" and is never a country signal.

Verdicts need agreement: within a source, `unreachable` requires `probe.agreementVantages`
distinct failing networks and no success; across sources, a second source or a second network.
`reachable` needs one residential success or two datacenter successes. Runs are budgeted per hour;
suspected origins are probed at `suspectedIntervalMinutes`. A dual-stack edge is probed per
address family and rolled up per family: the country verdict follows the IPv4 path (what every
member receives) and the IPv6 path is reported alongside as `v6Verdict`. Settled runs are kept
two weeks (`retention-relay-probes`, daily).

### Attribution

A member issue report is attributed server-side to the origin behind the key's pinned node
(`relaySlug`). The **edge** is set only when the member said which connection failed and that
choice resolves to exactly one edge under their own assignment (`connectionChoice`,
`relayEdgeId`); it is never inferred from the primary. Each member contributes at most one
detector weight per window via a peppered dedupe mark (`RELAY_MARK_PEPPER`, falling back to
`IP_HASH_SALT`); the telemetry row stays unlinked. `refreshNotObserved` marks a key that has not
fetched content since the origin's last rotation.

### Detector (`relay-block-detector`, 5 min, `detect.*`)

Per origin: attributed reports in the window (deduplicated), the node's live user count against
its own baseline, and probe verdicts. Origin-level evidence can only **hint** (the dashboard
strip and the origin badge). An **automatic rotation** needs, in order: `relay.enabled`,
`relay.autoRotate`, the origin's `autoRotate`, a suspected state, edge-level evidence (probes,
or members naming the connection with enough share, counted after the per-member dedupe), the
edge not being an outage (internal
probe and provider health say the edge itself is up), no quarantine, no running rotation,
cooldown and daily cap not reached, and a manageable Host when the target holds index 0. The
resulting rotation is a **burn** (short drain). Every refusal is recorded on the origin as the
veto so the operator sees why nothing happened.

## Configuration

`relay.*` in `appSettings` (Admin → Relay edges → the config tab; `GET/PATCH
/api/v1/admin/relay/config`). Ships fully dormant: `enabled=false`, `autoRotate=false`,
`render.enabled=false`, `probe.enabled=false`. Probe credentials are write-only
(`relay.secret.probe.*`, env fallback `RELAY_PROBE_GLOBALPING_TOKEN` /
`RELAY_PROBE_RIPEATLAS_KEY`). Defaults and bounds: `convex/lib/relayConfig.ts`.

## Sealing

Every route under `/api/v1/admin/relay/` carries credentials, addresses, provider handles or
live LB data, so the whole prefix is sealed by verb in `src/shared/crypto/envelope.ts`: GET
reveals the response to the caller's ephemeral key, POST seals the request AND reveals the
response (the response ephemeral rides inside the sealed body), PATCH/PUT seal the request,
DELETE carries nothing. Dual-mode (plaintext accepted) stays for `fsv1_` IaC callers, as for
backend servers. `convex/httpRelays.test.ts` pins the policy and a seal-both round trip.

## Node role contract (Ansible)

The role deploys, per relay node and per camouflage profile, one origin inbound and one
template Host, and registers both with FCP using an `fsv1_` token with `admin:servers:write`:

1. `PUT /api/v1/admin/relay/relays/by-slug/{hostname}` with
   `{ backendServerSlug, nodeHostname, originAddress, locationCode?, modeSlugs? }`
   (idempotent; never flips `autoRotate`). The response carries `publishedEndpoints`. One origin
   per (backend server, node) is enforced (`relay.node_already_bound`), and `originAddress`
   cannot change while the origin has live edges (`relay.origin_address_locked`): edges carry
   the address in their listener members, so a moved node means draining or destroying its
   edges first (or registering a new origin).
2. `PUT /api/v1/admin/relay/relays/by-slug/{hostname}/slots/{slotKey}` with
   `{ profileSlug, inboundTag, configProfileUuid, configProfileInboundUuid, originPort }`
   per inbound. Changing the inbound uuid re-binds the slot (the template Host must be recreated).
3. Poll `GET /api/v1/admin/relay/relays/by-slug/{hostname}` until `publishedEndpoints[0]`
   exists, then create ONE template Host per slot: remark `<hostname>-relay-<slotKey>`, address =
   the index-0 IPv4, port = its port, SNI = the first active server name,
   `overrideSniFromAddress:false`.
4. Re-runs read FCP state first and never rewrite an FCP-owned Host address; server names are
   removed from the node only after their `drainUntil`.
5. Teardown: `DELETE /api/v1/admin/relay/relays/by-slug/{hostname}`, then Host cleanup by the
   `<hostname>-relay-*` remark pattern.

Node pinning understands the relay remark (`convex/lib/nodePinning.ts`), so a node's relay
templates pin with the node like its other Hosts.

## Runbooks

**Qualify a provider account.** Add the account and test its credentials; provision a test edge
on an origin (unpublished); open an authenticated REALITY session through the edge with a real
client and hold it idle for several minutes; pull the live view; then "Mark qualified". Changing
the account's credentials or settings clears the qualification; so does changing the parameters
of a template the account was qualified with or uses as its default (audited as
`relay.provider_account.qualified` with `qualified:false`).

**Bootstrap an origin.** Register via the role (or create it here), adopt the hand-made edge at
index 0 (publish), provision a second edge (published at index 1), enable rendering, preview each
client family, then rotate index 1 and index 0 while watching the progress view.

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
