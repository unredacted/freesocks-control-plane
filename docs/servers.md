# Server management

Admin -> Servers shows, and will later manage, what lives on a proxy panel: its **nodes**, the
**config profiles** and **inbounds** they run, the **Hosts** members are handed and the
**squads** that grant them. It is built the way [edges](edges.md) is: a pure library
(`convex/lib/panel/`), isolate queries and mutations that are the only writers of their tables,
one bounded provider call per action, one HTTP prefix with a dispatcher, contracts in
`src/shared/contracts/servers.ts`.

**It ships dormant.** Reading a panel and changing it are separate switches, both off. Today
the writes cover **Hosts**, **internal squads** and two typed edits of a **config profile**
(REALITY server names and target); node writes follow.

Backends: a type takes part when its provider implements `observePanel` and declares the
`panelObservation` capability (`convex/lib/backends/capabilities.ts`). Remnawave 3.x does;
Outline has nothing to observe and answers `servers.unsupported_backend`.

## Switches

`servers.manage.*` rows in `appSettings` (`convex/lib/serverConfig.ts`), both **off** by default:

| Key                      | Off (default)                                               | On                                                                          |
| ------------------------ | ----------------------------------------------------------- | --------------------------------------------------------------------------- |
| `servers.manage.observe` | FCP makes no additional panel call.                         | Each capable panel is read at the tail of the backend healthcheck (10 min). |
| `servers.manage.enabled` | Every management write refuses (`servers.manage_disabled`). | Writes are accepted, subject to the gates under § Writes.                   |

Turning either off never hands ownership of anything back to another writer.

## Observation

`convex/panelObserve.ts` is the only writer of the cache tables. One look is five kinds of
read: `GET /api/nodes`, `GET /api/hosts`, `GET /api/internal-squads`, `GET /api/config-profiles`
and then **each profile by uuid** (the list row is never trusted to be complete). It runs in its
own best-effort slot of the healthcheck, like fleet stats: a failing look keeps the last
snapshot, stores the code word `servers.observe_failed` on `panelObserveState` (never the
panel's text) and **never marks the instance unhealthy**. `POST {slug}/refresh` does the same
look on demand and reports a failure to the caller as `502 backend.panel_read_failed`.

| Table               | One row per    | Holds                                                                                                  |
| ------------------- | -------------- | ------------------------------------------------------------------------------------------------------ |
| `panelNodes`        | node           | name, address, port, country, online, disabled, users online, profile uuid, served inbounds, tags      |
| `panelProfiles`     | config profile | name, the inbound projection, `shapeHash`, `changeToken` + `digestKeyId`, `tokenChangedAt`             |
| `panelHosts`        | Host           | remark, address, port, SNI, Host header, path, ALPN, fingerprint, flags, inbound binding, pinned nodes |
| `panelSquads`       | internal squad | name, inbound uuids, member count                                                                      |
| `panelObserveState` | instance       | when it was last looked at, whether that worked, a code word, counts                                   |

A row the panel stopped listing is deleted. These tables are kept apart from
`backendNodeInventory` (the edges node picker and block detector) so neither writer can clobber
the other.

### Nothing secret is read into FCP's database

A config profile holds the REALITY **private key**, the **short ids**, the **client list** and
certificate material. None of it is stored, returned or logged:

- An inbound is the same **allowlist projection** discovery uses (`projectXrayInbound`): tag,
  protocol, port, transport, security, server names, target, paths. The panel's derived
  `rawInbound` (the complete inbound JSON) is stripped at the schema boundary.
- Every config-profile call is made `sensitive` ([backends.md](backends.md) § Sensitive data):
  an error is status and path only.
- The raw config exists only inside `observeConfigProfile`, which returns the projection plus
  three digests (`convex/lib/panel/digest.ts`):

| Digest              | Over                                                             | Answers                                                                                              |
| ------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `shapeHash`         | the **redacted** config, SHA-256                                 | "Does this profile look different?" Safe to show. Blind to a change that touches only secrets.       |
| `changeToken`       | the **complete** config, keyed HMAC                              | "Did anything change?", a key or short-id rotation included. What a write will be conditioned on.    |
| `realityAuthDigest` | key pair, short ids, client version and clock bounds, keyed HMAC | "Would a client that connected yesterday still connect?" Server names and target are not part of it. |

The REALITY **public** key is derived from the private one and _is_ shown: it is public by
nature (every share link carries it). A stored `publicKey` that does not belong to the private
key is flagged (`realityPublicKeyMismatch`): clients holding it cannot connect.

The panel normalises a config on write (it trims each server name and clears
`settings.clients`; it neither lowercases nor de-duplicates). `normalizeForToken` applies exactly
that, so a token computed from what FCP sends equals the token of what the panel stores.

**The digest key** is derived, with a fixed label, from `ACCOUNT_ID_PEPPER`: the one deployment
secret that is set once and never rotated ([secrets.md](secrets.md)). It must be stable because
the authentication digest is meant to join an operator's endpoint confirmation, and a key that
rotated would stale every confirmation at once. `digestKeyId` names the key without revealing
it; a token made with a different key (a database restored onto a new deployment) is a new
baseline, never a "change".

`tokenChangedAt` records that a profile's token moved between two looks. _Who_ moved it is a
question for the operations ledger that comes with the write routes, not for this cache.

## What a node does with a profile (measured)

`bun run test:integration:remnawave-node` (needs Docker) stands up the test panel **plus a real
panel-managed node** (`remnawave/node:3.4.1`), a TLS 1.3 target that serves any name, and a
client that is the node image's own Xray, then opens **authenticated REALITY sessions** through
the node (`convex/lib/backends/remnawave.node-integration.test.ts`,
`docker-compose.remnawave-node-test.yml`). Two networks separate panel-to-node from
client-to-node traffic, so the node can be cut off from the panel while clients still reach it.
Every write route that touches a profile is designed around what this run shows:

| Question                                                        | Measured                                                                                                                                                                                                                         |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Does a server name work as soon as the **panel** stores it?     | **No.** With the node held off the panel: the panel lists the name, a plain TLS 1.3 handshake with that name **completes** (REALITY forwards an unauthenticated handshake to the target), and **no member can connect with it**. |
| So what does a TLS probe of a node prove?                       | That the target answers for that name. **Never** that the node accepts it. Only an authenticated session proves acceptance.                                                                                                      |
| An unlisted name                                                | Falls through to the target; the client's own REALITY verification fails.                                                                                                                                                        |
| When does the held-back name start working?                     | About 4 s after the node can reach the panel again: the panel re-delivers the profile on reconnect.                                                                                                                              |
| How long until a **connected** node serves a changed name list? | 1 to 3 s from the `PATCH` (the `PATCH` itself answers in 10 to 20 ms: application is asynchronous).                                                                                                                              |
| How many server names does production Xray take on one inbound? | 64, 256, 512 and **1024** all work: first, middle and last name authenticate, a name beyond the list does not.                                                                                                                   |
| Is `xrayUptime` evidence that Xray (re)started?                 | **No.** It read `0` or `2` on every read, before and after every change.                                                                                                                                                         |
| Is `isConnected` evidence that a node applied a change?         | **No.** It stayed `true` for a node that was cut off (only `isConnecting` flipped). `lastStatusChange` moves on each application, but it is the panel's own clock about the panel's own view.                                    |

One harness detail worth knowing when building on it: current Xray refuses to proxy to private
addresses, so the test's data network deliberately uses a non-private subnet; the REALITY
handshake succeeds on a private one but nothing comes back through the tunnel.

## Writes: the operations ledger

A write to a panel goes wrong in ways a request/response call hides: the answer is lost while
the panel did the work, a gateway answers an error while upstream commits, the panel queues
node work behind a write and answers before it runs. `convex/panelLedger.ts` (the only writer of
`panelOps` and `panelClaims`) and the pure rules in `convex/lib/panel/ops.ts` exist for that.

**Gates**, checked in the claiming transaction: `servers.manage.enabled` is on
(`servers.manage_disabled`), the backend type can be managed, and the node role has reported its
**handoff** for this instance (`servers.handoff_missing`, see § The node role). A write needs the
scope **`admin:servers:manage`**. That is deliberately not `admin:servers:write`: the node
role's token holds that one and must not gain the power to change a panel here. (A signed-in
admin is not scope-limited; scopes confine tokens.)

**One op, one attempt.** A `request*` mutation validates against what FCP knows and inserts the
op **and all its claims** in one transaction, before anything is sent; a claimed key refuses the
whole op. `run` then looks first, records the one attempt (`markSent` refuses a second), sends
it, and looks again. Three facts are recorded separately and never folded into one flag:

| Fact          | Values                                               | Meaning                                                                                                                                                                                                                |
| ------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `request`     | `rejected_pre_mutation`, `acknowledged`, `uncertain` | What happened to the HTTP exchange. **Only** "never sent", 401 and 403 prove nothing changed. Every 5xx, every other status and every timeout is `uncertain` (measured: the panel answers an invalid config with 500). |
| `panelState`  | `observed`, `unobserved`                             | Whether the intended result was **seen** on a read made afterwards. A delete needs two consecutive reads without the object.                                                                                           |
| `asyncEffect` | `none`, `pending`, `complete`                        | Whether node work the panel queued behind the write has run.                                                                                                                                                           |

**Claims are released only when** the request was provably rejected before any change, or the
result was observed **and** the queued work is done. There is no timed release, no re-send, no
re-assert and no "abandon": stable reads of the old state do not prove a delayed attempt is
finished, and releasing early is how a late write overwrites a newer one. While an attempt's
outcome is unknown, another write to the same item is refused (`servers.op_uncertain`). With one
outstanding attempt whose intended result differs from the state before, seeing the result
means that attempt landed and is over.

**Creates are never repeated.** The panel enforces no uniqueness on Hosts (an identical create
is a second Host, measured). A create reserves an identity (Host: remark + inbound + address +
port; squad: name) and looks for it **before** sending: one match is adopted and nothing is
sent, several are refused (`servers.duplicate_object`). After a lost answer the same look
settles it.

**What queues node work.** Changing a squad's inbounds, and deleting a squad, make the panel
re-apply the affected config profiles to their nodes; creating or renaming a squad and every
Host write do not. The first kind also claims those **profiles and nodes** and holds the claims
until each node's `lastStatusChange` has moved past its value read just before the call. A node
the panel cannot reach stays pending (the panel delivers on reconnect, measured). Reading the
changed squad row never releases those claims. `isConnected` and `xrayUptime` are not read:
neither says anything about application (measured).

**Recovery of an unknown outcome.** If the result is never seen, the op stays fenced until a
recorded recovery: an operator attests to **each** of: the credentials that attempt used are
revoked (not merely replaced), nothing in flight can still execute it, and the panel's queued
and stalled jobs have finished or were cancelled; a fresh read is taken first and may simply
settle the op. "The panel was restarted" is not a condition: queued work survives a restart.

**Interruption.** `panel-reconcile` (every 5 min) never sends anything. An op that never
recorded an attempt sent nothing and is released (`servers.never_sent`); one that recorded an
attempt but no outcome becomes `uncertain`; everything open is looked at again.

**Other workflows** call `assertNoPanelClaim` and refuse while a key is claimed. An op's own
follow-up work passes the same guard by **ownership**, never by a bypass flag: every required
key must have a claim row held by that op at that generation, so a missing claim fails.

### Editing a config profile

The panel takes a profile's config **wholesale** and offers **no conditional update** (measured:
stale preconditions are ignored). An edit is therefore a read-modify-write, in two calls:

1. `POST {slug}/profiles/{uuid}/preview {ops}` reads the live profile, applies the edit in
   memory and answers the non-secret before/after, the nodes the panel will re-apply it to, the
   relays whose listeners are bound to the touched inbounds, and two tokens: the profile as it
   is, and as it would be. It writes nothing.
2. `POST {slug}/profiles/{uuid}/apply` takes that answer back verbatim. The write is
   conditioned on the profile **still having the previewed token**: FCP re-reads immediately
   before the `PATCH`, and a profile someone else changed in between is refused
   (`servers.profile_changed`) with nothing sent. The result is confirmed by reading the
   profile back: its token must equal the predicted one, which means the edit landed **and
   nothing else moved**, key material included.

The edit itself is `convex/lib/panel/patchOps.ts`: a **closed set** of operations
(`setRealityServerNames`, `setRealityTarget`), no raw JSON. It refuses a config that is not an
object, an empty `inbounds` (writing that back would strip the nodes), a missing or duplicated
tag, a non-REALITY inbound. Everything it does not name is carried over by reference, the
private key and short ids included; they exist only inside the provider call. It never changes
an inbound's tag, protocol or position, because the panel keeps an inbound's uuid only while
tag and protocol hold (measured) and listener bindings, Hosts and squads hang off that uuid. A
uuid that moved anyway is flagged (`servers.inbound_uuid_changed`). Port changes and new
inbounds are not offered yet: they need the node's firewall to be ready first.

The residual race is stated plainly: between FCP's last read and its `PATCH`, another writer's
change would be overwritten and cannot be detected afterwards. That is why every FCP writer of
a profile takes the same claim, why the node role may not `PATCH` a managed profile, and why a
token that moves without an FCP op is recorded (`tokenChangedAt`).

**Claims.** One edit claims the profile, every enabled node on it and every affected relay
together, and holds them until each node's `lastStatusChange` has moved (the `PATCH` answers in
tens of milliseconds while application is asynchronous, measured). Rotations, restores,
registrations and listener edits on a claimed relay refuse with `edge.panel_op_running`
(`assertNoRelayPanelClaim`). A relay that is rotating, restoring, quarantined or mid-setup is
left alone instead: the edit is refused.

**The relay listeners follow, under the op's own claims** (ownership with exact coverage, in
the same transaction that records the observation):

- a new **target** is written to the bound listeners and their `revision` moves, so every L4
  endpoint confirmation on them is due a retest;
- new **server names are not activated** on any listener. The panel listing a name does not
  mean a node accepts it (measured), so a name reaches members only through a path that proves
  acceptance per node;
- a name a bound listener still hands out, or that is still inside its drain, **may not be
  removed** (`servers.name_in_use`): retire it on the relay first.

### An edit made somewhere else

The panel has no conditional update, so an edit that lands between FCP's read and its write is
overwritten, and one made at any other time is simply there. FCP cannot prevent either; it can
notice. Every look compares each profile's keyed token with the last one. When it moved, and
**no change made from FCP expected that token** (the `expectedToken` of the instance's recent
profile ops), the profile is flagged `foreignEditAt`: the panel UI, the node role, another tool.
The token covers the complete config, so this catches what no redacted view shows, such as a
short id or a private key.

The flag is a warning at the top of the Servers page and stays, across looks, until an operator
says they have seen it (`POST {slug}/profiles/{uuid}/acknowledge`, audited as
`servers.profile.foreign_edit_seen` with the profile name only). It changes nothing by itself:
what to do about an edit is a judgement. A token made with another digest key is a new
baseline, never a flag, and so is the logging harden, which is FCP's own edit outside the
ledger and re-reads the panel as a baseline when it changed something.

### Node writes

FCP writes the panel **row** of a node: its name, address, port, country, the profile it runs
and which of that profile's inbounds it serves. It never installs a node and never asks the
panel for a node's secret; that stays the node role's job, against the panel directly.

| Action                           | What is sent                                                                                                                                              | When it is done                                                                                                                                                                   |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Create                           | One `POST`. Never a second one: a lost answer is looked up by name and adopted.                                                                           | The row is seen.                                                                                                                                                                  |
| Rename, country                  | One `PATCH`.                                                                                                                                              | The row shows the fields. The panel queues no node work for these.                                                                                                                |
| Address, port, profile, inbounds | One `PATCH`. Profile and inbounds travel together.                                                                                                        | The row shows the fields **and** the node's `lastStatusChange` has moved since the call.                                                                                          |
| Enable, disable                  | The action, only when the node is not already in that state (`servers.already`): a repeat makes the panel queue work for nothing.                         | Enable waits for the node's clock like an address change. Disable is done when the row says so.                                                                                   |
| Restart                          | The action with `forceRestart: true` (a node otherwise skips a restart when its config hashes match). Refused on a node that is off (`servers.node_off`). | Only when `lastStatusChange` moves. The panel answers 202 on queue insertion, the row names nothing that changed, and `xrayUptime` and `isConnected` are not evidence (measured). |
| Stop and remove                  | `DELETE`, and only on a node that is **already off** (`servers.node_still_on`). Disable it first, as its own op.                                          | The uuid is absent on two looks.                                                                                                                                                  |
| Remove from panel                | `DELETE ...?removeOnly=1`, on a node in any state.                                                                                                        | The uuid is absent on two looks. **The node process may still be running and serving**: the panel removes its row before it tries to stop Xray.                                   |

While an op that restarts a node is open it holds `node:<uuid>`, so a second lifecycle change
to the same node is refused (`servers.op_running`) rather than queued behind it.

| Refusal                          | When                                                                                                                                                                        |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `servers.node_relay_origin`      | A relay stands in front of this node: its address, port, profile and inbounds are what the relay forwards to, and it is not disabled or removed here. A restart is allowed. |
| `servers.node_rename_referenced` | The node's **name** is an identifier: relays, delivery requirements and members pinned to a node refer to it. Renaming a referenced node is not offered in this version.    |
| `servers.node_name_taken`        | As named. Node names are how a lost create is found again.                                                                                                                  |
| `servers.unknown_inbound`        | An inbound that is not part of the profile being assigned.                                                                                                                  |

### What is refused

| Refusal                                                 | When                                                                                                                          |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `servers.host_edge_owned`                               | The Host is a relay listener's Host, an adopted legacy Host, or in the direct-Host hide ledger. It is changed from its relay. |
| `servers.relay_remark`                                  | Creating or renaming to `<node>-relay[-key]`: remarks the edges machinery owns.                                               |
| `servers.unknown_inbound`                               | The inbound is not on this panel as last read.                                                                                |
| `servers.squad_in_placement`                            | Deleting, or emptying, a squad members are issued into (a connection mode's pool).                                            |
| `servers.squad_has_members`, `servers.squad_name_taken` | As named.                                                                                                                     |
| `servers.tombstoned`                                    | Recreating something that was removed on purpose, by any identity it ever had. `restore: true` says it is wanted back.        |

Ownership is durable (`panelOwnership`): a settled create is `owned`, a settled delete leaves a
`tombstoned` row keeping every identity the object had. It is independent of both switches and
of FCP being reachable.

### The node role

One contract: the role bootstraps the **machine** of a NEW node and reports (below, "Node
lifecycle"); FCP writes the backend and releases to members. Nothing the role sends is a write
to the backend, and FCP never waits on the role for anything on it. A backend that already has
nodes is **adopted** (below), never re-bootstrapped: the role is not run for an existing
machine.

Not built yet: the firewall acknowledgement (FCP publishing the ports an edit needs and the role
confirming them). Nothing FCP writes today opens a port: the typed profile edits change names
and targets only.

## Setting up a backend

`convex/panelSetup.ts`. One durable workflow per backend server (`panelSetups`), started from
Admin -> Servers ("Set up this backend") with names, shapes and family slugs only: never a
secret. Each step is idempotent and re-enterable; an interrupted attempt is resumed by the
`panel-bootstrap-sweep` cron once its lease has expired.

**Modes.** A backend is set up for a list of modes (`PanelSetupInput.modes`, pre-filled from
`DEFAULT_MODE_SETUP`; editable, a table, not a fixed set). Each names the connection mode it
feeds (`slug`, which must exist in the catalog), the group on the backend (`name`, 2 to 20 plain
characters; the transport tag is that name upper-cased), a **shape** and, for REALITY transports,
the **server-name family** whose target and names the transport carries:

| Mode (default)    | Shape                       | Transport                                           | Members reach it        |
| ----------------- | --------------------------- | --------------------------------------------------- | ----------------------- |
| `privacy-reality` | `reality` / `direct`        | VLESS + REALITY on 443                              | at the node's addresses |
| `freedom-reality` | `reality` / `edge-l4`       | VLESS + REALITY on 443                              | through an L4 edge      |
| `freedom-xhttp`   | `xhttp-reality` / `edge-l4` | VLESS over XHTTP under REALITY on 443 (no sing-box) | through an L4 edge      |
| `freedom-ws`      | `ws` / `edge-l7`            | VLESS over WebSocket on loopback behind Caddy       | through an L7 edge      |

Every REALITY transport listens on 443: a node serves ONE mode, so they never collide. A mode
named by a node is the only thing the role needs to know about it (`node_mode`); the machine
shape (Caddy or not, ingress, what an edge dials) follows from the mode's shape.

| Step       | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| observe    | A fresh look at the backend; everything below reads the cache.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| families   | Every REALITY mode's family must exist, be on, and have a usable (qualified, active) name today: `servers.family_missing`, `servers.family_empty`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| profile    | The profile by name: adopted when compatible (`lib/panel/profileCompat.ts`: per mode the transport found under the mode's tag or a tag an earlier setup gave it, checked for protocol, network, security, listen, port, path, names, target and a usable key; keys and short ids never touched; an adopted tag is kept, since a backend keys transports by tag), otherwise created from the template (`lib/panel/profileTemplate.ts`: one transport per mode, born with the privacy posture, each REALITY transport with its family's target and usable names and its own key pair generated inside the claimed attempt). `servers.profile_incompatible:<tag>:<field>`. |
| bind       | Each REALITY transport is bound to its family (`sniFamilies.bind`): the family is the one authoritative allowlist from then on, and later name changes are rollouts (docs/edges.md). An adopted transport forwarding elsewhere than the family's target is `servers.family_target_mismatch`.                                                                                                                                                                                                                                                                                                                                                                            |
| groups     | Each mode's group, found under its name, or under a name an earlier setup gave the same mode (`FreeSocks-Reality` → `Privacy-Reality`, `FreeSocks-Relay` → `Freedom-Reality`, `FreeSocks-Fronted`/`FreeSocks-Fastly` → `Freedom-WebSocket`) and **renamed in place** through the ledger (its id and every member assignment survive; audited `servers.setup.group_renamed`), else created; carrying the mode's transport.                                                                                                                                                                                                                                               |
| placements | Each group into its mode's pool (`addSquadUuids`). A mode that does not exist is recorded `skipped` and blocks activation of its nodes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| templates  | The four subscription templates (`lib/panel/subscriptionTemplates/`, YAML byte-exact) reconciled on drift; a refused write (401/403) blocks activation unless the live template already matches.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

A ready row that still records a blocker (a drifted or refused template, a skipped placement, an
unbound family, drifted privacy) is re-run on the next request so the blocker can clear. The
setup row also carries the backend-wide **delivery gate version** (below).

### Adopting a backend

A backend that already has nodes or addresses is never quietly set up: `start` refuses with
`servers.adopt_required` until the request carries `adopt: true` (the sheet's typed
confirmation). Adopting means FCP becomes the backend's writer as it is: the profile is adopted
under its existing tags, groups an earlier setup named are renamed in place, and nothing a
member holds changes. The setup row records `adopted`.

**Adopting a node** (`POST {slug}/nodes/adopt {nodeUuid, mode, externallyFronted?}`,
`panelIntents.adoptNode`): a backend node that already serves members becomes an enrolled node
that is **live at once**: its row must run the mode's transport; its addresses (a direct node's,
by remark or address) become its committed set; evidence and approval are synthesized as
`adopted`. A fronted node whose edge FCP does not run yet (an earlier tool made it) is
`externallyFronted`: it needs no standbys and no origin name until Edges protects it, one node at
a time, through the normal flow. The role is never run for an adopted machine.

## Node lifecycle

The bootstrap contract v2 (`convex/panelIntents.ts`, `panelActivation.ts`, `panelRetirement.ts`):
the node role bootstraps the **machine** and reports; FCP owns the machine settings, the panel
row, the direct Host, the origin DNS record and the release to members. Nothing about a node
reaches a member before its **delivery commit**.

```
registered → bootstrap_available → machine_applied → machine_ready → candidates_verified
          → awaiting_approval → activating → live
```

| Stage                 | Evidence (each row bound to the revisions it was taken for)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `registered`          | The intent exists; the node row is created or brought in line through the ledger; a direct node's Host is created **disabled**; a front node's origin record is written (obligations, below).                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `bootstrap_available` | `POST …/bootstrap` served the machine configuration and the panel's node secret. The secret is read from the panel on the call and returned to the caller; FCP never persists, audits or logs it (the machine holds it in its compose file).                                                                                                                                                                                                                                                                                                                                                                                    |
| `machine_applied`     | The role reported `appliedRevision == machineRevision`. Idempotent; a lower revision is `servers.revision_stale` (run the role again), a higher one `servers.revision_unknown`; a report never regresses a stage.                                                                                                                                                                                                                                                                                                                                                                                                               |
| `machine_ready`       | The node op that applied the current profile and inbound is done by its own ledger evidence, the node is online, the profile token has not moved; a front node's origin name resolves to the intended addresses, presents a publicly valid certificate naming it, proxies the WebSocket path and answers a foreign Host header.                                                                                                                                                                                                                                                                                                 |
| `candidates_verified` | Direct: the isolated **direct test link** (the node's own test credential, the inbound's live parameters) confirmed against a **binding** recomputed from live rows: endpoint, machine, config and authentication revisions, the parameters tested, the credential. A moved endpoint refuses (`servers.confirmation_stale`). Fronted: every listener of the open Autopilot run (the one waiting at publish for this approval) has a live, verified standby (L7 proof; L4 confirmation); recorded as `standbys_verified` evidence at approval, refused as `servers.standbys_missing` / `servers.standbys_unverified` until then. |
| `awaiting_approval`   | The review card hashes the delivery **shape** (purpose, ingress, profile revision, listeners, provider account + template, subscription templates, the Host tuple), never individual addresses.                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `activating`          | Approval creates one run with an **immutable candidate snapshot** (`panelActivationRuns`); older runs are superseded. A direct run enables the Host as a **candidate resource**, rehearses the panel's real bodies in every client family (`lib/panel/rehearsal.ts`), and commits. A failed rehearsal disables the Host again and releases nothing. A run that blocks or fails **parks** the node at `awaiting_approval` with no current run (`staged` again unless it was live): the next approval supersedes it and starts a fresh run.                                                                                       |
| `live`                | `panelActivation.commit`: one mutation that re-validates the approval, the evidence, the rehearsal and open obligations, then **promotes the snapshot** (`intent.approved`, the committed resources), opens the gate, bumps the gate version. A fronted node's Autopilot go-live calls the same promotion inside its own mutation; no independent go-live exists while an activation is unapproved, blocked or superseded.                                                                                                                                                                                                      |

Three revision sets: `desired` (what the next review approves), `committed` (`intent.approved`,
what members are served; moves only at a commit) and, per run, the candidate. `patchSettings`
classifies a change (`lib/panel/activation.ts` `classifyChange`): one that only adds a path is
prepared beside the committed one; one that rewrites the running path (a port or path rewrite, a
re-address, a profile edit) is applied in place and needs an explicit **maintenance transition**,
which closes the node (`unavailable`) until it is verified and approved again. The previous
configuration is not claimed to remain served in that case.

**Observed drift** is the same transition without anyone asking for it. When a reconcile finds
the REALITY material moved, or the profile token moved by somebody else's edit
(`foreignEditAt`), under evidence already taken, or a direct node's endpoint moved under one of
its addresses (`panelIntents.observeRevisions`), the invalidated evidence goes, running
activations are superseded, and a live node closes under a maintenance transition (reason
`drift`, audited as `servers.node.drift`) until it is re-verified and approved again; the
existing addresses are brought to the new endpoint meanwhile (a name that arrived is a new
address, a name that left is removed). A token FCP's own ledger moved (a family rollout, a
hardening) is not drift: evidence and approval are re-stamped to the new revision, since what
members hold still works, and a run in flight is superseded for a fresh approval. A lost DNS
answer is settled by discovery on the next run (an absent record confirms a delete and fails a
create, so the ladder never waits forever), and a record FCP owns for an address family no
longer desired is withdrawn. Every resumed workflow re-reads `servers.manage.enabled` before a
provider write outside the ledger (the profile create, the subscription templates, origin DNS)
and parks while it is off.

**A shared change** (a typed profile edit through `requestProfilePatch`; never a rollout, whose
names reach members by per-node receipts) is applied in place under every node running the
touched transports, so the maintenance transition comes BEFORE the write is admitted
(`panelIntents.closeForSharedChange`): every affected enrolled node closes under one transition
(reason `profile`; it reopens only through its own re-verification and commit), and every
affected node FCP does not manage needs a treatment from the operator, `hold` (closed by name in
`panelMaintenanceHolds` until an admin releases it: nothing re-verifies an unmanaged node) or
`acknowledge` (it changes in place). "No intent means open" never bypasses this. Audited as
`servers.profile.transition` / `servers.profile.transition_released` (counts only).

**The delivery gate** (`lib/panel/deliveryGate.ts`, enforced in `edgeRender.deliveryPolicyFor`,
the pinner's exclusion list, the subscription route, the mirror refresh): closed for an enrolled
node that is not live, under maintenance or retiring, open for an unmanaged node. Every render
carries the gate version; the route and the mirror refresh re-read it after rendering and never
attach content rendered under an older policy to a newer token. **Publication** is admitted by
`edgeRotations` only under a node's committed approval or as a candidate of its one activating
run (`servers.node_not_approved` otherwise), for manual, reconcile and setup publishes alike.

**Authorization decision.** A staged node serves a shared inbound: an existing credential could
authenticate on it if someone learned its address. That is accepted (REALITY keys are per inbound
by design); what approval gates is exposure. Panel subscription URLs are not a member-facing
surface; the direct Host is enabled only during the run's rehearsal and disabled again on failure.

### Node registration (contract v2)

Routes on `{slug}/nodes/by-name/{name}`, scope `admin:servers:write` or `admin:edges:register`
confined to the token's registration boundary (backend servers and, optionally, node names):

| Route              | What                                                                                                                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PUT`              | Enroll (`mode`, `label`; taken once) or report observations (`management`, `publicIps`, `capabilities`; every run). The role never sends FCP-owned settings.                                |
| `GET`              | The node's own view: stage, disposition, revisions, the origin name, the retirement.                                                                                                        |
| `POST …/bootstrap` | The machine configuration (node port, the Caddy routes of a front node, the origin hostname) and the node secret. `SEAL_BOTH`; bearer callers get plaintext over TLS as on every IaC route. |
| `POST …/applied`   | `{appliedRevision, caddy.certificateReady, nodeStarted}`.                                                                                                                                   |
| `DELETE`           | A retirement request (below).                                                                                                                                                               |
| `POST …/wiped`     | The role's acknowledgement that the machine is cleaned up (`ready_to_wipe → retired`).                                                                                                      |

Refusals: `servers.panel_not_set_up`, `servers.contract_version`, `servers.node_exists_unowned`
(a panel node or Host of that name no intent owns: an admin adopts first), `servers.tombstoned`
(an admin restores), `servers.purpose_change_needs_admin`, `servers.node_retiring`,
`servers.registration_boundary`.

A shared change (a profile edit, `POST {slug}/profiles/{uuid}/apply`) takes an `unmanaged`
treatment (`hold` | `acknowledge`) whenever nodes FCP does not manage run the touched transports
(`servers.unmanaged_nodes_affected` otherwise); `GET {slug}/nodes/intents` lists the open holds
and `POST {slug}/holds/{id}/release` ends one. `POST {slug}/nodes/adopt` adopts a node (above).

Admin routes on `{slug}/nodes/intents/{id}`: `GET review`, `POST test-link`, `POST confirm`,
`POST approve {reviewHash}`, `POST settings {patch, maintenance}`, `POST maintenance` (finish),
`POST retire [{disposition}]`.

### Origin names

A front node's origin name is `<label>.<zone>` in the Cloudflare zone chosen at setup (or an
explicit hostname the admin sets). Records are **obligations** (`panelObligations`, kind
`dns.record`) persisted before the call with the account, zone, marker
`fcp-origin:<slug>:<name>` and expected content; an uncertain answer is discovered by name and
marker before anything is sent again; a record FCP did not write, or a CNAME at the name, is
`servers.origin_name_taken`, never replaced; FCP's own record with other content is replaced.
Cleanup uses the obligation's own account and zone. `created` and `resolves` are distinct.

### Obligations

External side effects of every workflow are rows persisted before the call. A superseded
generation never releases an unresolved one; a lease expiry resumes discovery of the same
attempt; settlement reconciles the result against what is wanted now (`lib/panel/obligations.ts`:
reuse, retain, delete), so a late create generation B still needs is adopted, an update never
authorises a delete, and a shared object is never disposable.

### Retirement and migration

`DELETE …/by-name/{name}` only records the request. Whenever the node was ever live or anything
of it is still out there, the retirement is `needs_admin`; the admin chooses `keep-dark` (its
members get the edge-required unavailable answer) or `migrate` (refused in this version with
`servers.migration_not_built`). Never `restore-direct`. The ladder: `draining` (the relay
deleted keep-dark, credentials released, the direct Host deleted, DNS withdrawn) →
`panel_removed` (the row removed with `removeOnly`, the name tombstoned) → `ready_to_wipe` →
the role's `wiped` ack → `retired`.

## Admin surface

`/api/v1/admin/servers/*` (`convex/httpServers.ts`), sealed by verb class like the edges
surface (`src/shared/crypto/envelope.ts`): the responses carry node and Host addresses.
`{slug}` is the backend server's slug.

| Route                                                                                                            | Scope                              | What                                                                                                           |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `GET summary`                                                                                                    | `admin:servers:read`               | Every instance: observable or not, last look, counts, the switches.                                            |
| `GET {slug}/tree`                                                                                                | `admin:servers:read`               | One instance as a tree, from the cache (no panel call).                                                        |
| `POST {slug}/refresh`                                                                                            | `admin:servers:read`               | Look now, then return the tree. Rate-limited (`admin.servers.panel-read`): the one route that reaches a panel. |
| `POST {slug}/placements/validate`                                                                                | `admin:servers:read`               | Check the squad pools in mode placements against the squads the panel has.                                     |
| `GET config`, `PATCH config`                                                                                     | `admin:settings:*`                 | The switches. Audited as `servers.config.update {changedKeys}`.                                                |
| `POST {slug}/hosts`, `PATCH` / `DELETE {slug}/hosts/{uuid}`, `POST {slug}/hosts/reorder`                         | `admin:servers:manage`             | Host writes. Answer the op. Rate-limited (`admin.servers.panel-write`).                                        |
| `POST {slug}/squads`, `PATCH` / `DELETE {slug}/squads/{uuid}`                                                    | `admin:servers:manage`             | Squad writes.                                                                                                  |
| `POST {slug}/nodes`, `PATCH` / `DELETE {slug}/nodes/{uuid}`, `POST {slug}/nodes/{uuid}/enable\|disable\|restart` | `admin:servers:manage`             | Node writes. `DELETE ...?removeOnly=1` is "remove from panel".                                                 |
| `POST {slug}/profiles/{uuid}/preview`                                                                            | `admin:servers:read`               | What a typed profile edit would do. Writes nothing.                                                            |
| `POST {slug}/profiles/{uuid}/acknowledge`                                                                        | `admin:servers:manage`             | An operator has seen that the profile was edited elsewhere.                                                    |
| `POST {slug}/profiles/{uuid}/apply`                                                                              | `admin:servers:manage`             | Apply a previewed edit, conditioned on the previewed token.                                                    |
| `GET {slug}/ops`                                                                                                 | `admin:servers:read`               | The last 50 ops of an instance.                                                                                |
| `POST {slug}/ops/{id}/observe`                                                                                   | `admin:servers:read`               | Look at the panel again for an open op. Changes nothing on the panel.                                          |
| `POST {slug}/ops/{id}/recover`                                                                                   | `admin:servers:manage`             | The attested recovery of an unknown outcome.                                                                   |
| `PUT {slug}/handoff`                                                                                             | `admin:servers:write` or `:manage` | The node role's handoff report.                                                                                |

**The tree** is node -> the profile it runs -> the inbounds it **serves** -> the Hosts members
get for each inbound (a Host pinned to nodes appears under those only) and the squads that
grant it. What hangs off no node is returned as `unattached`: a profile no node runs, a Host on
an inbound no node serves. That is usually a leftover worth noticing.

**Placement validation** answers in counts and squad names, never the pasted uuids (a pool is
write-only over HTTP). `unknownHere` is a count to look into, not a verdict: several instances
can share a backend type, and a uuid missing on this panel may live on another.
`withoutInbounds` names squads that would issue keys connecting to nothing.

### The page

Admin -> Servers -> Nodes and inbounds, built like the simple Edges screens: one status
sentence, a "Needs you" list only when something is broken, one row per node, and the
leftovers as quiet one-line notes (an inbound nobody uses on three nodes is one line, not six).
The two switches (regular reading, changes from here) sit in the footer.

`/admin/servers/nodes/{uuid}` is one node: its sentence, the profile it runs, its own notes,
and its inbounds with the addresses members get for each. With changes allowed and the role's
handoff in place the header carries Edit, Restart or Turn on, and a More menu with Turn off,
**Stop and remove** (offered only once the node is off) and **Remove from the panel only**
(says the process may keep running); both removes are typed. On an inbound: add, change or
remove an address; edit a REALITY inbound's names and target as write -> preview -> apply,
typed when more than one node restarts. The home lists squads (add, rename, change inbounds,
remove) and Recent changes ("Look again" on an open one, "Settle by hand" on an unknown
outcome, asking for each recovery condition by name).

The page hides what the server would refuse anyway; the server is what decides. All wording is
in `src/client/routes/admin/servers/lib/words.ts`, and tests pin the sentences and that every
`servers.*` refusal the server can answer has its own.

## Adding an observed backend

1. Implement `observePanel(config, digestKey)` on the provider and return `PanelObservation`
   (`convex/lib/backends/types.ts`). Reduce anything secret-bearing **inside** the provider.
2. Set `panelObservation: true` for the type in `capabilities.ts` (the consistency test pins the
   flag to the method).
3. Add a redaction test in the style of `remnawave.observe.test.ts`, and a live step to the
   backend's integration test.
