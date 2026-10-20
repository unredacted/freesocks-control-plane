# Server management

Admin -> Servers shows and manages what lives on a proxy backend: its **nodes**, the
**config profiles** and **transports** they run, the **Hosts** members are handed and the
**mode groups** that grant them. It is built the way [edges](edges.md) is: a pure library
(`convex/lib/backend/`), isolate queries and mutations that are the only writers of their tables,
one bounded provider call per action, one HTTP prefix with a dispatcher, contracts in
`src/shared/contracts/servers.ts`.

**Request bodies are the contract's words.** Every write route parses its body with the shared
zod write schema (`AddressWrite`, `AddressPatch`, `ModeGroupWrite`, `ModeGroupPatch`,
`ProfilePatchPreviewRequest`, `ProfilePatchApply`, `PortChangeAcknowledge`, `DirectTestConfirm`,
`NodeRegistration`, …)
and maps it onto the internal mutations' stored names at the HTTP boundary (`transportUuid` →
`inboundUuid`, `transportTag` → `inboundTag`). A field the API renamed (`inboundUuid`,
`inboundUuids`, `inboundTag`, also inside `ops[]` and `binding`) is refused by name with a 400
BEFORE parsing (`convex/lib/legacyFields.ts`), because a zod object would otherwise drop it
silently. Responses are mapped back the same way (the profile preview answers `transportUuids`
and `changes[].transportTag`; the direct test link answers `binding.transportUuid`).

**It ships dormant.** Reading a backend and changing it are separate switches, both off. Today
the writes cover **Hosts**, **internal mode groups**, **nodes** and four typed edits of a
**config profile** (REALITY server names and target, a transport's port, a transport added from
a template).

Backends: a type takes part when its provider implements `observePanel` and declares the
`panelObservation` capability (`convex/lib/backends/capabilities.ts`). Remnawave 3.x does;
Outline has nothing to observe and answers `servers.unsupported_backend`.

## Switches

`servers.manage.*` rows in `appSettings` (`convex/lib/serverConfig.ts`), both **off** by default:

| Key                      | Off (default)                                               | On                                                                            |
| ------------------------ | ----------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `servers.manage.observe` | FCP makes no additional backend call.                       | Each capable backend is read at the tail of the backend healthcheck (10 min). |
| `servers.manage.enabled` | Every management write refuses (`servers.manage_disabled`). | Writes are accepted, subject to the gates under § Writes.                     |

Turning either off never hands ownership of anything back to another writer.

## Observation

`convex/backendObserve.ts` is the only writer of the cache tables. One look is five kinds of
read: `GET /api/nodes`, `GET /api/hosts`, `GET /api/internal-squads`, `GET /api/config-profiles`
and then **each profile by uuid** (the list row is never trusted to be complete). It runs in its
own best-effort slot of the healthcheck, like fleet stats: a failing look keeps the last
snapshot, stores the code word `servers.observe_failed` on `panelObserveState` (never the
backend's text) and **never marks the instance unhealthy**. `POST {slug}/refresh` does the same
look on demand and reports a failure to the caller as `502 backend.panel_read_failed`.

| Table               | One row per         | Holds                                                                                                    |
| ------------------- | ------------------- | -------------------------------------------------------------------------------------------------------- |
| `panelNodes`        | node                | name, address, port, country, online, disabled, users online, profile uuid, served transports, tags      |
| `panelProfiles`     | config profile      | name, the transport projection, `shapeHash`, `changeToken` + `digestKeyId`, `tokenChangedAt`             |
| `panelHosts`        | Host                | remark, address, port, SNI, Host header, path, ALPN, fingerprint, flags, transport binding, pinned nodes |
| `panelSquads`       | internal mode group | name, transport uuids, member count                                                                      |
| `panelObserveState` | instance            | when it was last looked at, whether that worked, a code word, counts                                     |

A row the backend stopped listing is deleted. These tables are kept apart from
`backendNodeInventory` (the edges node picker and block detector) so neither writer can clobber
the other.

### Nothing secret is read into FCP's database

A config profile holds the REALITY **private key**, the **short ids**, the **client list** and
certificate material. None of it is stored, returned or logged:

- A transport is the same **allowlist projection** discovery uses (`projectXrayTransport`): tag,
  protocol, port, transport, security, server names, target, paths. The backend's derived
  `rawInbound` (the complete transport JSON) is stripped at the schema boundary.
- Every config-profile call is made `sensitive` ([backends.md](backends.md) § Sensitive data):
  an error is status and path only.
- The raw config exists only inside `observeConfigProfile`, which returns the projection plus
  three digests (`convex/lib/backend/digest.ts`):

| Digest              | Over                                                             | Answers                                                                                              |
| ------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `shapeHash`         | the **redacted** config, SHA-256                                 | "Does this profile look different?" Safe to show. Blind to a change that touches only secrets.       |
| `changeToken`       | the **complete** config, keyed HMAC                              | "Did anything change?", a key or short-id rotation included. What a write will be conditioned on.    |
| `realityAuthDigest` | key pair, short ids, client version and clock bounds, keyed HMAC | "Would a client that connected yesterday still connect?" Server names and target are not part of it. |

The REALITY **public** key is derived from the private one and _is_ shown: it is public by
nature (every share link carries it). A stored `publicKey` that does not belong to the private
key is flagged (`realityPublicKeyMismatch`): clients holding it cannot connect.

The backend normalises a config on write (it trims each server name and clears
`settings.clients`; it neither lowercases nor de-duplicates). `normalizeForToken` applies exactly
that, so a token computed from what FCP sends equals the token of what the backend stores.

**The digest key** is derived, with a fixed label, from `ACCOUNT_ID_PEPPER`: the one deployment
secret that is set once and never rotated ([secrets.md](secrets.md)). It must be stable because
the authentication digest is meant to join an operator's endpoint confirmation, and a key that
rotated would stale every confirmation at once. `digestKeyId` names the key without revealing
it; a token made with a different key (a database restored onto a new deployment) is a new
baseline, never a "change".

`tokenChangedAt` records that a profile's token moved between two looks. _Who_ moved it is a
question for the operations ledger that comes with the write routes, not for this cache.

## What a node does with a profile (measured)

`bun run test:integration:remnawave-node` (needs Docker) stands up the test backend **plus a real
backend-managed node** (`remnawave/node:3.4.1`), a TLS 1.3 target that serves any name, and a
client that is the node image's own Xray, then opens **authenticated REALITY sessions** through
the node (`convex/lib/backends/remnawave.node-integration.test.ts`,
`docker-compose.remnawave-node-test.yml`). Two networks separate backend-to-node from
client-to-node traffic, so the node can be cut off from the backend while clients still reach it.
Every write route that touches a profile is designed around what this run shows:

| Question                                                          | Measured                                                                                                                                                                                                                             |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Does a server name work as soon as the **backend** stores it?     | **No.** With the node held off the backend: the backend lists the name, a plain TLS 1.3 handshake with that name **completes** (REALITY forwards an unauthenticated handshake to the target), and **no member can connect with it**. |
| So what does a TLS probe of a node prove?                         | That the target answers for that name. **Never** that the node accepts it. Only an authenticated session proves acceptance.                                                                                                          |
| An unlisted name                                                  | Falls through to the target; the client's own REALITY verification fails.                                                                                                                                                            |
| When does the held-back name start working?                       | About 4 s after the node can reach the backend again: the backend re-delivers the profile on reconnect.                                                                                                                              |
| How long until a **connected** node serves a changed name list?   | 1 to 3 s from the `PATCH` (the `PATCH` itself answers in 10 to 20 ms: application is asynchronous).                                                                                                                                  |
| How many server names does production Xray take on one transport? | 64, 256, 512 and **1024** all work: first, middle and last name authenticate, a name beyond the list does not.                                                                                                                       |
| Is `xrayUptime` evidence that Xray (re)started?                   | **No.** It read `0` or `2` on every read, before and after every change.                                                                                                                                                             |
| Is `isConnected` evidence that a node applied a change?           | **No.** It stayed `true` for a node that was cut off (only `isConnecting` flipped). `lastStatusChange` moves on each application, but it is the backend's own clock about the backend's own view.                                    |
| A transport moved to a port the node's firewall drops             | It serves nobody: the old port is gone seconds after the `PATCH`, the new one is dropped. Let in, the same client connects about 1 s later with nothing else changed. The transport keeps its uuid.                                  |
| A transport added to the profile                                  | The node re-applies the profile and keeps exactly its own transports: nothing listens on the new one until a node is assigned to it.                                                                                                 |

One harness detail worth knowing when building on it: current Xray refuses to proxy to private
addresses, so the test's data network deliberately uses a non-private subnet; the REALITY
handshake succeeds on a private one but nothing comes back through the tunnel.

## Writes: the operations ledger

A write to a backend goes wrong in ways a request/response call hides: the answer is lost while
the backend did the work, a gateway answers an error while upstream commits, the backend queues
node work behind a write and answers before it runs. `convex/backendLedger.ts` (the only writer of
`panelOps` and `panelClaims`) and the pure rules in `convex/lib/backend/ops.ts` exist for that.

**Gates**, checked in the claiming transaction: `servers.manage.enabled` is on
(`servers.manage_disabled`), the backend type can be managed, and FCP has set this backend up or
adopted it (`servers.not_set_up`, see § Setting up a backend). A write needs the
scope **`admin:servers:manage`**. That is deliberately not `admin:servers:write`: the node
role's token holds that one and must not gain the power to change a backend here. (A signed-in
admin is not scope-limited; scopes confine tokens.)

**One op, one attempt.** A `request*` mutation validates against what FCP knows and inserts the
op **and all its claims** in one transaction, before anything is sent; a claimed key refuses the
whole op. `run` then looks first, records the one attempt (`markSent` refuses a second), sends
it, and looks again. Three facts are recorded separately and never folded into one flag:

| Fact          | Values                                               | Meaning                                                                                                                                                                                                                  |
| ------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `request`     | `rejected_pre_mutation`, `acknowledged`, `uncertain` | What happened to the HTTP exchange. **Only** "never sent", 401 and 403 prove nothing changed. Every 5xx, every other status and every timeout is `uncertain` (measured: the backend answers an invalid config with 500). |
| `panelState`  | `observed`, `unobserved`                             | Whether the intended result was **seen** on a read made afterwards. A delete needs two consecutive reads without the object.                                                                                             |
| `asyncEffect` | `none`, `pending`, `complete`                        | Whether node work the backend queued behind the write has run.                                                                                                                                                           |

**Claims are released only when** the request was provably rejected before any change, or the
result was observed **and** the queued work is done. There is no timed release, no re-send, no
re-assert and no "abandon": stable reads of the old state do not prove a delayed attempt is
finished, and releasing early is how a late write overwrites a newer one. While an attempt's
outcome is unknown, another write to the same item is refused (`servers.op_uncertain`). With one
outstanding attempt whose intended result differs from the state before, seeing the result
means that attempt landed and is over.

**Creates are never repeated.** The backend enforces no uniqueness on Hosts (an identical create
is a second Host, measured). A create reserves an identity (Host: remark + transport + address +
port; mode group: name) and looks for it **before** sending: one match is adopted and nothing is
sent, several are refused (`servers.duplicate_object`). After a lost answer the same look
settles it.

**Who a write is by.** Each settled op is audited as `servers.<kind>.<verb>`: by the admin who
asked, or, when no admin did, as `system` with the FCP run that made it as the actor id
(`<kind>:<id>`: `node:<intent>` for a node's own address reconcile, `retirement:<id>`,
`activation:<run>`). An activation's writes are by the admin who approved it. Admin, Recent
changes and the audit log fold identical neighbours into one line ("Tried 40 times, never
sent"); an open op keeps its own line.

**Writes outside the ledger.** Edges change Hosts they own straight through the provider (an
origin's Host, a rotation's repoint, a hide). Each such write re-reads the instance's Hosts into
the cache right after, when Servers observes the instance, so "Addresses members get" follows
the flip at once instead of at the next read.

**What queues node work.** Changing a mode group's transports, and deleting a mode group, make the backend
re-apply the affected config profiles to their nodes; creating or renaming a mode group and every
Host write do not. The first kind also claims those **profiles and nodes** and holds the claims
until each node's `lastStatusChange` has moved past its value read just before the call. A node
the backend cannot reach stays pending (the backend delivers on reconnect, measured). Reading the
changed mode group row never releases those claims. `isConnected` and `xrayUptime` are not read:
neither says anything about application (measured).

**Recovery of an unknown outcome.** If the result is never seen, the op stays fenced until a
recorded recovery: an operator attests to **each** of: the credentials that attempt used are
revoked (not merely replaced), nothing in flight can still execute it, and the backend's queued
and stalled jobs have finished or were cancelled; a fresh read is taken first and may simply
settle the op. "The backend was restarted" is not a condition: queued work survives a restart.

**Interruption.** `backend-reconcile` (every 5 min) never sends an attempt again. An op that
never recorded an attempt sent nothing and is released (`servers.never_sent`); one that recorded
an attempt but no outcome becomes `uncertain`; everything open is looked at again. The same pass
admits a staged port change whose nodes all confirmed (§ Firewall acknowledgement), which sends
its ONE attempt, and resumes a parked node rename (§ Renaming a node).

**Other workflows** call `assertNoPanelClaim` and refuse while a key is claimed. An op's own
follow-up work passes the same guard by **ownership**, never by a bypass flag: every required
key must have a claim row held by that op at that generation, so a missing claim fails.

### Editing a config profile

The backend takes a profile's config **wholesale** and offers **no conditional update** (measured:
stale preconditions are ignored). An edit is therefore a read-modify-write, in two calls:

1. `POST {slug}/profiles/{uuid}/preview {ops}` reads the live profile, applies the edit in
   memory and answers the non-secret before/after, the nodes the backend will re-apply it to, the
   origins whose listeners are bound to the touched transports, and two tokens: the profile as it
   is, and as it would be. It writes nothing.
2. `POST {slug}/profiles/{uuid}/apply` takes that answer back verbatim. The write is
   conditioned on the profile **still having the previewed token**: FCP re-reads immediately
   before the `PATCH`, and a profile someone else changed in between is refused
   (`servers.profile_changed`) with nothing sent. The result is confirmed by reading the
   profile back: its token must equal the predicted one, which means the edit landed **and
   nothing else moved**, key material included.

The edit itself is `convex/lib/backend/patchOps.ts`: a **closed set** of operations
(`setRealityServerNames`, `setRealityTarget`, `setInboundPort`, `addInboundFromTemplate`), no raw
JSON. It refuses a config that is not an object, an empty `inbounds` (writing that back would
strip the nodes), a missing or duplicated tag, a non-REALITY transport for a names or target
edit. Everything it does not name is carried over by reference, the private key and short ids
included; they exist only inside the provider call. It never changes a transport's tag, protocol
or position, because the backend keeps a transport's uuid only while tag and protocol hold
(measured, a port change included) and listener bindings, Hosts and mode groups hang off that
uuid; a new transport is appended. A uuid that moved anyway is flagged
(`servers.inbound_uuid_changed`). A port change and a new transport are each made on their own
(one op per edit).

- **`setInboundPort`** moves one transport to another port. Every node serving it listens there
  seconds after the write, so it is **staged** until each of those nodes has confirmed its
  firewall lets the port in (§ Firewall acknowledgement); the apply route refuses it
  (`servers.port_change_staged`). The backend checks neither the range nor collisions (measured:
  it stores 70000, and two transports on one port), so FCP refuses a port out of range, a port a
  node on the transport already uses for another of its transports or for its own API
  (`servers.port_taken`; the node's API port as FCP will set it and its own proxy's public port
  count too), a loopback transport (`servers.port_loopback`: it sits behind the
  node's own proxy, whose route to it is a node setting), a port range (`servers.port_not_single`)
  and a transport an origin forwards to (`servers.port_edge_bound`: the edges dial its port).
- **`addInboundFromTemplate`** adds a transport built exactly as setup builds a mode's
  (`lib/backend/profileTemplate.ts`: REALITY, XHTTP under REALITY, or a loopback WebSocket), with
  the tag and port asked for. A REALITY template names a server-name family; the preview answers
  it with the family's target and the names usable today (a family that is turned off gives none:
  `servers.family_missing`), and the apply takes that back verbatim. Its **key pair is made inside the claimed attempt** and never stored, logged or
  returned, so no preview can predict the token the profile will have: the preview answers
  `expectedToken: null`, and the attempt records the token it computed from its own fresh read
  immediately before the `PATCH` (`markSent`), which is what the look then settles on and what
  tells the observer the edit was FCP's. A tag another transport of the backend has is refused
  (`servers.tag_taken`; the backend answers 409). **No node serves a new transport** until it is
  assigned to it (measured: the backend re-applies the profile to its nodes, and each keeps
  exactly its own transports), so the add opens no port and closes no node. Setting the backend
  up again with a mode whose group name gives this tag adopts it (§ Setting up a backend).

The residual race is stated plainly: between FCP's last read and its `PATCH`, another writer's
change would be overwritten and cannot be detected afterwards. That is why every FCP writer of
a profile takes the same claim, why the node role may not `PATCH` a managed profile, and why a
token that moves without an FCP op is recorded (`tokenChangedAt`).

**Claims.** One edit claims the profile, every enabled node on it and every affected origin
together, and holds them until each node's `lastStatusChange` has moved (the `PATCH` answers in
tens of milliseconds while application is asynchronous, measured). Rotations, restores and
admin listener writes (`applyRegistration`) on a claimed origin refuse with `edge.panel_op_running`
(`assertNoRelayPanelClaim`). An origin that is rotating, restoring, quarantined or mid-setup is
left alone instead: the edit is refused.

**The origin listeners follow, under the op's own claims** (ownership with exact coverage, in
the same transaction that records the observation):

- a new **target** is written to the bound listeners and their `revision` moves, so every L4
  endpoint confirmation on them is due a retest;
- new **server names are not activated** on any listener. The backend listing a name does not
  mean a node accepts it (measured), so a name reaches members only through a path that proves
  acceptance per node;
- a name a bound listener still hands out, or that is still inside its drain, **may not be
  removed** (`servers.name_in_use`): retire it on the origin first.

### An edit made somewhere else

The backend has no conditional update, so an edit that lands between FCP's read and its write is
overwritten, and one made at any other time is simply there. FCP cannot prevent either; it can
notice. Every look compares each profile's keyed token with the last one. When it moved, and
**no change made from FCP expected that token** (the `expectedToken` of the instance's recent
profile ops), the profile is flagged `foreignEditAt`: the backend UI, the node role, another tool.
The token covers the complete config, so this catches what no redacted view shows, such as a
short id or a private key.

The flag is a warning at the top of the Servers page and stays, across looks, until an operator
says they have seen it (`POST {slug}/profiles/{uuid}/acknowledge`, audited as
`servers.profile.foreign_edit_seen` with the profile name only). It changes nothing by itself:
what to do about an edit is a judgement. A token made with another digest key is a new
baseline, never a flag, and so is the logging harden, which is FCP's own edit outside the
ledger and re-reads the backend as a baseline when it changed something.

### Node writes

FCP writes the backend **row** of a node: its name, address, port, country, the profile it runs
and which of that profile's transports it serves. It never installs a node and never asks the
backend for a node's secret; that stays the node role's job, against the backend directly.

| Action                             | What is sent                                                                                                                                              | When it is done                                                                                                                                                                     |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Create                             | One `POST`. Never a second one: a lost answer is looked up by name and adopted.                                                                           | The row is seen.                                                                                                                                                                    |
| Country                            | One `PATCH`.                                                                                                                                              | The row shows the fields. The backend queues no node work for this.                                                                                                                 |
| Rename                             | A workflow of its own (§ Renaming a node): one `PATCH` of the row, then the Host remarks FCP wrote, each its own op.                                      | Every reference moved; the backend queues no node work for any of it.                                                                                                               |
| Address, port, profile, transports | One `PATCH`. Profile and transports travel together.                                                                                                      | The row shows the fields **and** the node's `lastStatusChange` has moved since the call.                                                                                            |
| Enable, disable                    | The action, only when the node is not already in that state (`servers.already`): a repeat makes the backend queue work for nothing.                       | Enable waits for the node's clock like an address change. Disable is done when the row says so.                                                                                     |
| Restart                            | The action with `forceRestart: true` (a node otherwise skips a restart when its config hashes match). Refused on a node that is off (`servers.node_off`). | Only when `lastStatusChange` moves. The backend answers 202 on queue insertion, the row names nothing that changed, and `xrayUptime` and `isConnected` are not evidence (measured). |
| Stop and remove                    | `DELETE`, and only on a node that is **already off** (`servers.node_still_on`). Disable it first, as its own op.                                          | The uuid is absent on two looks.                                                                                                                                                    |
| Remove from backend                | `DELETE ...?removeOnly=1`, on a node in any state.                                                                                                        | The uuid is absent on two looks. **The node process may still be running and serving**: the backend removes its row before it tries to stop Xray.                                   |

While an op that restarts a node is open it holds `node:<uuid>`, so a second lifecycle change
to the same node is refused (`servers.op_running`) rather than queued behind it.

| Refusal                        | When                                                                                                                                                                             |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `servers.node_relay_origin`    | An origin stands in front of this node: its address, port, profile and transports are what the origin forwards to, and it is not disabled or removed here. A restart is allowed. |
| `servers.node_rename_separate` | A name is changed only by a rename (§ Renaming a node): `PATCH` refuses it, because the name is an identifier origins, delivery requirements, pins and the node role refer to.   |
| `servers.node_name_taken`      | As named. Node names are how a lost create is found again.                                                                                                                       |
| `servers.unknown_inbound`      | A transport that is not part of the profile being assigned.                                                                                                                      |

### A direct node's addresses

A direct node gets one address (a backend Host) per server name its transport lists, and FCP
writes each with the remark `<node> | <server name>` (`lib/backend/hostRemark.ts`). The backend
caps a remark at 40 characters, so a pair that does not fit carries a 7-character tag derived from
the server name instead (`<node> | <tag>`); the address itself carries the full name in its `sni`.
FCP finds its own addresses by the uuids it recorded, and the remark only has to be unique per node.

The backend names every entry of a subscription body after its Host's remark, and the remark is
how FCP reads which node an entry belongs to: node pinning (`lib/nodePinning.ts`
`splitPanelRemark`, which also reads the older role-written `<node>-reality`, `<node>-ws[-<hash>]`
and an origin's `<node>-relay-<key>`) keeps each member on one node's entries, and the edge
render matches the entries it replaces by it. A `|` remark is FCP's only when what follows the
separator is the server name the entry itself serves (a link's `sni`, sing-box
`tls.server_name`, Clash `servername`) or that name's tag; an operator's own Host remark such as
`Region | VLESS` is never read as a node.

**Members never see these remarks.** After pinning and rendering, every body a member receives
(the fronted subscription route, the sealed configuration copy, every mirror upload) renames each
entry that names a node (`lib/memberEntryNames.ts`):

| Entries left | Name in the member's app                              |
| ------------ | ----------------------------------------------------- |
| One          | `<site name> · <place>`                               |
| Several      | `<site name> · <place> · <code>`, one per server name |

- `<site name>` is `subscription.siteName` (default `FreeSocks`), `<place>` the backend's
  member-facing location label up to its first comma (left out when unset), `<code>` four
  characters derived from the server name alone. A code is the same on every refresh, under a
  node rename, and whatever other entries come or go. Only while two server names in one body
  share a code do both carry their six-character code instead (each still from its own name);
  a name that is still not unique gets a ` (2)`.
- References follow the rename: sing-box selector/urltest members, `default`, `route.final`,
  rule `outbound`s and `detour`s; Clash proxy-group members and rule targets. Covered formats are
  link lists (base64-wrapped or not), sing-box JSON, Clash / Mihomo YAML and Xray JSON config
  lists; a body none of them reads is served as it is (like the pinner, the step never emits a
  broken config).
- Entries that name no node keep their names: an edge's rendered entries (their labels are
  `edge.render.*`, docs/edges.md), the backend's placeholders, groups.
- `subscription.entryNames` (default on, Admin → Settings → "Names in members' apps") turns it
  off. Turning it off, or changing the site name, reaches a member at their next refresh past the
  content cache, and every mirror at its next sweep.

### Renaming a node

A node's name is an identifier well beyond the backend row: origins and their delivery
bindings, the node role's routes and token boundary, members' pins, holds, port requirements and
the remarks of the Hosts FCP writes all carry it. `POST {slug}/nodes/{uuid}/rename {name}` starts
a resumable workflow (`convex/backendNodeRenames.ts`, `panelNodeRenames`), one step at a time,
every backend write through the ledger:

1. **The backend row.** One node op renames the row. In the transaction that SEES the new name
   (`applyLook` → `bridgeNodeRename`, `lib/backend/nodeRename.ts`), every FCP row keyed by the name
   moves with it: the enrolled node (`name`, the old one kept in `formerNames`), the origins in
   front of it (`nodeName`), their listeners' remarks (`matchRule`, the Host's intended remark;
   the old remark kept in `formerRemarks`, which the renderer still matches), the delivery
   binding (its `policyVersion` moves, so nothing rendered under the old name is served under the
   new one), guided setup runs, holds, port requirements, ownership (`lookup` gains the new name),
   the read caches, and the node role's token boundary (gains the new name, keeps the old, but only
   for a token bounded to this backend alone: a boundary pairs every backend with every name, so a
   token spanning several backends would also reach another backend's node of the new name; such
   a token keeps acting for the node under its old name, through the alias). The old name becomes
   an alias (`panelNodeAliases`), and every earlier alias of the node is pointed straight at the
   new name, so any former name resolves in one step however often the node was renamed.
2. **The Host remarks.** The backend's Host listing is READ, and every Host whose remark is one of
   FCP's forms for the old name (a direct node's `<node> | <name>`, rebuilt from the Host's own
   server name; an origin listener's `<node>-relay[-<key>]`) is re-remarked in place, one op at a
   time. Nothing else about a Host changes and none is created or deleted, so nothing a member
   holds stops working, and a remark FCP's records missed is still found. A remark write the
   backend refuses before any change is not sent again on its own: the rename holds at this step
   (`servers.rename_host_refused`, the node page names the address, its old remark still matched)
   until an operator fixes what refused it and retries (`POST {slug}/renames/{id}/retry`).
3. **Members' pins.** The backend's subscriptions are walked a page at a time and a pin (or the
   node a key is kept off) under the old name moves to the new one.

While it runs, the node's origins are fenced (`relays.renaming`: rotations, restores, setup runs
and admin listener writes answer `edge.panel_op_running`), no new origin or
guided setup run is admitted for the node under either name (`edge.panel_op_running`), its
retirement is refused (`servers.node_rename_running`, by the role and by an admin), and the node's
own reconcile waits; it is reconciled under the new name when the rename finishes. A step whose write
has an unknown outcome parks, and `backend-reconcile` resumes it once a look settled the write
(or a recorded recovery and a fresh read decided it). A write refused before any change ends the
rename with nothing moved.

**The old name keeps answering.** A lookup by a name that is no longer current resolves through
the alias: the node's origin and delivery binding (`relayForBackendNode`, `deliveryBindingFor`),
its gate (`nodeGateFor`), the role's `…/nodes/by-name/{old name}` routes (an enroll under it
reports observations for the same node), and the pin exclusion of gated nodes (a body whose Hosts
still carry the old remark). A former name stays reserved: no node may take it. The origin DNS
record's marker keeps the name the node was enrolled with, so FCP's own record never reads as
somebody else's.

Refused before anything is sent: a name a node has or had, or that another running rename is
giving its node (`servers.node_name_taken`, checked again right before the backend write), or one
removed on purpose (`servers.tombstoned`); a node retiring, with its own work in flight, or
already being renamed (`servers.node_rename_running`); an origin in front of it that is rotating,
restoring, quarantined or mid-setup, whose Hosts the operator writes or adopted
(`servers.node_rename_foreign_hosts`: those remarks are theirs), for which the name is not a DNS
label (`servers.node_name_origin`: origins keep it as one) or would make a Host remark longer
than the backend allows (`servers.node_name_too_long`). Audited as
`servers.node.rename_started`, `servers.node.renamed`, `servers.node.rename_failed`,
`servers.node.rename_retried` (the two names only).

On a body that carries several nodes, the pin is a rendezvous hash over node names, so members of
a renamed node may be pinned anew there; each lands on a node that serves. With one node per mode
group (the usual topology) nothing moves.

### What is refused

| Refusal                                                 | When                                                                                                                             |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `servers.host_edge_owned`                               | The Host is an origin listener's Host, an adopted legacy Host, or in the direct-Host hide ledger. It is changed from its origin. |
| `servers.relay_remark`                                  | Creating or renaming to `<node>-relay[-key]`: remarks the edges machinery owns.                                                  |
| `servers.unknown_inbound`                               | The transport is not on this backend as last read.                                                                               |
| `servers.squad_in_placement`                            | Deleting, or emptying, a mode group members are issued into (a connection mode's pool).                                          |
| `servers.squad_has_members`, `servers.squad_name_taken` | As named.                                                                                                                        |
| `servers.tombstoned`                                    | Recreating something that was removed on purpose, by any identity it ever had. `restore: true` says it is wanted back.           |

Ownership is durable (`panelOwnership`): a settled create is `owned`, a settled delete leaves a
`tombstoned` row keeping every identity the object had. It is independent of both switches and
of FCP being reachable.

### The node role

One contract: the role bootstraps the **machine** of a NEW node and reports (below, "Node
lifecycle"); FCP writes the backend and releases to members. Nothing the role sends is a write
to the backend, and FCP never waits on the role for anything on it. A backend that already has
nodes is **adopted** (below), never re-bootstrapped: the role is not run for an existing
machine.

The one thing FCP waits on the role for is a **firewall**: a port change is not sent until the
role (or, for a node no role runs, an admin) has confirmed the new port is let in (§ Firewall
acknowledgement).

### Firewall acknowledgement

A node must not be told to listen on a port its firewall drops (it would serve nobody, measured
on a real node with the port dropped), and members must not be given a port before it is
reachable. `convex/backendPortChanges.ts` (the only writer of `panelPortChanges` and
`panelPortRequirements`) stages a port change instead of sending it:

1. **Stage.** `POST {slug}/profiles/{uuid}/port-change` takes what the preview answered (the
   preview of a port change lists the nodes and who confirms each, and the addresses on the
   transport FCP does not own: those keep the port they name, since a forwarder in front of a
   node may map it, so they are listed and never moved). It records the edit and **one
   requirement per node serving the transport**: an enrolled node the role runs is confirmed by
   the role (`role`); a node FCP does not manage, or an adopted one (no role runs its machine),
   by an admin (`operator`). Nothing is claimed and nothing is sent: members keep the old port.
   Nodes FCP does not manage need the usual treatment (`unmanaged: hold | acknowledge`), and one
   port change per profile is open at a time (`servers.port_change_waiting`).
2. **Confirm.** The role reads the pending port in its node's view and reports it in its applied
   report (below); an admin confirms an `operator` node by name (`POST {slug}/port-changes/{id}/
acknowledge {nodeNames}`, refused for a `role` node: `servers.firewall_role_confirms`). Each
   confirmation is audited (`servers.port_change.confirmed`, `by: role | operator`).
3. **Apply.** The last confirmation admits the edit through the ledger in ONE transaction with
   the change (`admit`, then `run`): the claim is owned by that change (`portChangeId`; a port
   op without it is refused), every refusal of the claim is checked BEFORE the maintenance
   transition (so a change that is not admitted leaves no node closed and no hold behind), the
   transition closes every node on the transport before the write (§ A shared change), and the
   one attempt is sent and looked at like every profile edit. Admission re-reads who serves the
   transport: a node that started serving it since staging gets a requirement of its own and the
   change keeps waiting (`servers.firewall_unconfirmed`); a node that stopped serving it (turned
   off, removed, moved) is no longer waited for. A busy profile (`servers.op_running`,
   `servers.op_uncertain`) or the switch turned off leaves it waiting; the `backend-reconcile`
   sweep looks at every waiting change again and sends what is ready. Any other refusal ends it
   as `refused` with the code. A profile edited between the preview and the send is refused with
   nothing sent (`servers.profile_changed`), as for every profile edit. The transport a change
   names must be the one its tag names on the profile as last read (`servers.unknown_inbound`
   otherwise, for every profile edit): the backend is edited by tag, the nodes are found by uuid.
4. **Settle.** Once the moved transport is SEEN, the setup row's record of the mode's transport
   follows (the review and the node's addresses read their port from it) and every enrolled node
   on it is reconciled at once, so its own addresses move to the new port while it is still
   closed (a reconcile already running is fenced by a new generation and runs again); it comes
   back through its own verification (the direct test link dials the new port) and approval. A
   transport whose uuid moved anyway (`servers.inbound_uuid_changed`) is not bridged: nothing is
   re-pointed at the old uuid. The change's outcome is its op's (`applying`, `applied` only once
   the edit was SEEN, `refused`), or `recovered` when a recorded recovery settled it: that says
   nothing about whether the port moved, and the page says so.

`POST {slug}/port-changes/{id}/cancel` withdraws a change that still waits (nothing was sent; a
node that already opened the port keeps it open). `GET {slug}/port-changes` lists the open ones
and the last few settled; the Servers page shows them as "Port changes", with each node's wait
in words.

#### What the node role does (contract v2, firewall)

The role repository implements this; FCP only describes it.

- **Read the ports.** The node's view (`GET {slug}/nodes/by-name/{name}`) and the bootstrap
  answer carry `firewall.ports: [{port, protocol: 'tcp', reason}]`: every port the node's
  firewall must let in. `serving`: a transport the node serves listens there (loopback ones
  excepted), or its own proxy's public port (a WebSocket node's Caddy). `pending`: a staged
  change waits for this node; it stays listed after the role confirmed it, until the change is
  sent and settled, cancelled or refused. The node's API port (`node.port`, the backend's channel
  to the node) is the role's own business and is not listed.
- **Open them.** On every run, let every listed port in (TCP, from anywhere) before reporting.
  The role MAY close a port it opened for FCP earlier that is no longer listed; it never closes
  SSH or the node API port on that basis.
- **Report them.** `POST …/applied` gains `firewall: {ports: [{port, protocol: 'tcp'}]}`: the
  ports the firewall lets in for FCP after this run. FCP confirms every pending requirement of
  THIS node whose port is listed. The report's `appliedRevision` must be the node's current
  `machineRevision`, as for every applied report (an older one is refused
  `servers.revision_stale`, a newer one `servers.revision_unknown`, before anything is
  confirmed); a run that only opened a port reports the same revision again, which is
  idempotent. A report without `firewall`
  confirms nothing, so a role that predates this keeps a port change waiting (the Servers page
  says which node), and nothing else changes for it.
- **Gate on it.** A `pending` port in the view means a change waits for this node: run the role
  again after opening it if the report was missed.
- **A renamed node.** The by-name routes answer under the old name too, and the token boundary
  gains the new one; the view's `name` is the current one. Switch the inventory's node name to it
  when convenient.

## Setting up a backend

`convex/backendSetup.ts`. One durable workflow per backend server (`panelSetups`), started from
Admin -> Servers ("Set up this backend") with names, shapes and family slugs only: never a
secret. Each step is idempotent and re-enterable; an interrupted attempt is resumed by the
`backend-bootstrap-sweep` cron once its lease has expired.

**Modes.** A backend is set up for a list of modes (`BackendSetupInput.modes`, pre-filled from
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

| Step       | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| observe    | A fresh look at the backend; everything below reads the cache.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| families   | Every REALITY mode's family must exist, be on, and have a usable (qualified, active) name today: `servers.family_missing`, `servers.family_empty`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| profile    | The profile by name: adopted when compatible (`lib/backend/profileCompat.ts`: per mode the transport found under the mode's tag or a tag an earlier setup gave it, checked for protocol, network, security, listen, port, path, names, target and a usable key; keys and short ids never touched; an adopted tag is kept, since a backend keys transports by tag), otherwise created from the template (`lib/backend/profileTemplate.ts`: one transport per mode, born with the privacy posture, each REALITY transport with its family's target and usable names and its own key pair generated inside the claimed attempt). `servers.profile_incompatible:<tag>:<field>`. |
| bind       | Each REALITY transport is bound to its family (`sniFamilies.bind`, by the transport's own uuid, since a tag is unique per profile and not per backend): the family is the one authoritative allowlist from then on, and later name changes are rollouts (docs/edges.md). An adopted transport forwarding elsewhere than the family's target is `servers.family_target_mismatch`; one already bound to a DIFFERENT family is `servers.family_bound_elsewhere:<slug>` (that family's rollouts own its names, so an admin unbinds it or the mode names that family).                                                                                                           |
| groups     | Each mode's group, found under its name, or under a name an earlier setup gave the same mode (`FreeSocks-Reality` → `Privacy-Reality`, `FreeSocks-Relay` → `Freedom-Reality`, `FreeSocks-Fronted`/`FreeSocks-Fastly` → `Freedom-WebSocket`) and **renamed in place** through the ledger (its id and every member assignment survive; audited `servers.setup.group_renamed`), else created; carrying EXACTLY the mode's transport (a transport an earlier release left in the group is removed: a mode grants one way in).                                                                                                                                                   |
| placements | Each group into its mode's pool (`addSquadUuids`). A mode that does not exist is recorded `skipped` and blocks activation of its nodes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| templates  | The four subscription templates (`lib/backend/subscriptionTemplates/`, YAML byte-exact) reconciled on drift; a refused write (401/403) blocks activation unless the live template already matches. Kept current afterwards by the sweep ("Templates after setup").                                                                                                                                                                                                                                                                                                                                                                                                          |

A ready row that still records a blocker (a drifted or refused template, a skipped placement, an
unbound family, drifted privacy) is re-run on the next request so the blocker can clear. The
setup row also carries the backend-wide **delivery gate version** (below).

**Templates after setup.** FCP owns the subscription templates, so a release that changes one
must reach every backend already set up, and a change made on the backend (an edit, an upgrade
that resets one) must be put back. The `backend-bootstrap-sweep` cron (every 5 minutes,
`backendSetup.resyncTemplates`) runs the templates step alone on each ready backend whose
recorded templates are not all `matched` at the hash of what FCP ships now, and on every ready
backend whose live templates were last looked at an hour ago or more (`templatesCheckedAt`).
After a deploy that changed a template, that is one re-sync per backend; each run writes only
the templates that differ. It holds the setup's lease meanwhile (a setup request answers
`servers.setup_running`), the row stays ready, and nothing else of the setup runs. Server
changes switched off: nothing is written, and the switch is read again before every write. A
refused or failed write is recorded as during setup and tried again on every sweep;
`servers.setup.templates_installed` is audited when something was written or the outcome moved.
Before writing, the claim records a template FCP now ships differently under its new hash, not
matched: the review hash (`awaiting_approval`, below) moves and activation holds
(`servers.template_drifted`) until the outcome is recorded, so no node is approved or goes live
against the old template while the write is in flight. A node approved but not yet live parks
until it is approved again (`servers.review_stale`); live nodes are untouched. Members get the
new body on their app's next subscription refresh.

### Changing a backend's setup

Once FCP writes a backend, a new setup request is a **change** of its setup, never a fresh
setup. FCP writes a backend when its setup row has been ready (`readyAt`, stamped on the first
ready; a ready row older than the field counts too) or an admin adopted it (`fcpWrites` in
`convex/backendSetup.ts`; the view says `established`). Its nodes and addresses then are FCP's
own (enrolled, added from Servers) or are handled one node at a time (Adopt as an enrolled node,
holds), and no setup step touches a node or an address, so a change asks for no adoption. A row
that never got to ready proves nothing: what is on the backend may be anybody's, and
`servers.adopt_required` still applies.

Admin -> Servers -> Nodes shows **Backend setup** (the modes, the generation, the zone for
origin names) with **Change setup** while the backend is ready. The sheet opens filled in with
the current setup and says what the change does before it runs (a confirmation). What may
change (`checkChange`), anything else refused before a write:

| Change                         | What happens                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The zone for origin names only | Recorded **in place** at a new generation; the row stays ready and nothing runs, since no setup step reads it: no backend read or write, no node touched. A WebSocket node enrolled while there was no zone (blocked on `servers.origin_hostname_missing`) takes its managed name (below). Audited `servers.setup.changed`.                                                                                                                                                                                                                                                                                                                                                                                     |
| A mode added                   | The setup **runs again** at a new generation. The new mode's transport must already be in the profile (Add a transport, on a node's page), checked against the last look at the backend (`servers.setup_transport_missing:<tag>:<field>`) and again by the run. Every mode already set up keeps what was found for it while the run looks again, and is found as it is: no profile, group, binding or placement write for it (a placement already so is not rewritten or audited). The new mode gets its group and placement. Until the run is done no node can enroll or be approved; delivery to members is untouched (the gate reads its own version, and edges keep dialing a front node by the same name). |
| Nothing (modes reordered)      | Nothing: the same generation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

Refused, because nodes and members rely on them: another profile name
(`servers.setup_profile_kept`); a mode removed, or a mode's group name, shape, family, PROXY
protocol, WebSocket path or port changed (`servers.setup_mode_kept:<slug>`; add a new mode
instead); another zone, or none, while any node that is not retired has a managed origin name in
the current one (`servers.origin_zone_in_use`). Another account holding the SAME zone is always
fine: every name stays, and FCP finds its records again by name and marker.

### Adopting a backend

A backend that already has nodes or addresses, and that FCP does not write yet (above), is never
quietly set up: `start` refuses with `servers.adopt_required` until the request carries
`adopt: true` (the sheet's typed confirmation). Adopting means FCP becomes the backend's writer
as it is: the profile is adopted under its existing tags, groups an earlier setup named are
renamed in place, and nothing a member holds changes. The setup row records `adopted`; a change
of the setup later never sets it.

**Adopting a node** (`POST {slug}/nodes/adopt {nodeUuid, mode, externallyFronted?}`,
`nodeIntents.adoptNode`): a backend node that already serves members becomes an enrolled node
that is **live at once**: its row must run the mode's transport; its addresses (a direct node's,
by remark or address) become its committed set; evidence and approval are synthesized as
`adopted`. A fronted node whose edge FCP does not run yet (an earlier tool made it) is
`externallyFronted`: it needs no standbys and no origin name until Edges protects it, one node at
a time, through the normal flow. The role is never run for an adopted machine, which is also why
its retirement is closed by an admin rather than by a report (below).

### Moving to modes

The release that introduced modes carried a one-shot mutation, `backendSetup:migrateContractV2`,
that cleared the rows of the shape before it (the v1 handoff rows, v1 reservations on
`panelOwnership`, and `panelSetups` / `panelNodeIntents` rows without modes). No deployment holds
such rows any more, so the mutation and the TRANSITIONAL schema fields that accepted them are
gone. A deployment that still holds them (one that skipped that release) must deploy a release
that has the migration and run it first: Convex validates every stored document on each push, so
this schema refuses those rows.

## Node lifecycle

The bootstrap contract v2 (`convex/nodeIntents.ts`, `nodeActivation.ts`, `nodeRetirement.ts`):
the node role bootstraps the **machine** and reports; FCP owns the machine settings, the backend
row, the direct Host, the origin DNS record and the release to members. Nothing about a node
reaches a member before its **delivery commit**.

```
registered → bootstrap_available → machine_applied → machine_ready → candidates_verified
          → awaiting_approval → activating → live
```

| Stage                 | Evidence (each row bound to the revisions it was taken for)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `registered`          | The intent exists; the node row is created or brought in line through the ledger; a direct node's Host is created **disabled**; a front node's origin record is written (obligations, below).                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `bootstrap_available` | `POST …/bootstrap` served the machine configuration and the backend's node secret. The secret is read from the backend on the call and returned to the caller; FCP never persists, audits or logs it (the machine holds it in its compose file).                                                                                                                                                                                                                                                                                                                                                                                  |
| `machine_applied`     | The role reported `appliedRevision == machineRevision`. Idempotent; a lower revision is `servers.revision_stale` (run the role again), a higher one `servers.revision_unknown`; a report never regresses a stage.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `machine_ready`       | The node op that applied the current profile and transport is done by its own ledger evidence, the node is online, the profile token has not moved; a front node's origin name resolves to the intended addresses, presents a publicly valid certificate naming it, proxies the WebSocket path and answers a foreign Host header.                                                                                                                                                                                                                                                                                                 |
| `candidates_verified` | Direct: the isolated **direct test link** (the node's own test credential, the transport's live parameters) confirmed against a **binding** recomputed from live rows: endpoint, machine, config and authentication revisions, the parameters tested, the credential. A moved endpoint refuses (`servers.confirmation_stale`). Fronted: every listener of the open Autopilot run (the one waiting at publish for this approval) has a live, verified standby (L7 proof; L4 confirmation); recorded as `standbys_verified` evidence at approval, refused as `servers.standbys_missing` / `servers.standbys_unverified` until then. |
| `awaiting_approval`   | The review card hashes the delivery **shape** (mode, ingress, profile revision, every listener with its provider account, location + template, subscription templates, the Host tuple), never individual addresses.                                                                                                                                                                                                                                                                                                                                                                                                               |
| `activating`          | Approval creates one run with an **immutable candidate snapshot** (`panelActivationRuns`); older runs are superseded. A direct run enables the addresses as **candidate resources**, rehearses the backend's real bodies in every client family (`lib/backend/rehearsal.ts`), and commits. The rehearsal reads EVERY address the run would commit, each with the server name it is there to serve (links `sni`, sing-box `tls.server_name`, Clash `servername`) and the expected REALITY key: one entry proves nothing about the others, and the detail records `<family>:<name>:absent                                           | key | sni`. A failed rehearsal disables the Host again and releases nothing. A run that blocks or fails **parks** the node at `awaiting_approval` with no current run (`staged` again unless it was live): the next approval supersedes it and starts a fresh run. |
| `live`                | `nodeActivation.commit`: one mutation that re-validates the approval, the evidence, the rehearsal and open obligations, then **promotes the snapshot** (`intent.approved`, the committed resources), opens the gate, bumps the gate version. A fronted node's Autopilot go-live calls the same promotion inside its own mutation; no independent go-live exists while an activation is unapproved, blocked or superseded.                                                                                                                                                                                                         |

Three revision sets: `desired` (what the next review approves), `committed` (`intent.approved`,
what members are served; moves only at a commit) and, per run, the candidate. `patchSettings`
classifies a change (`lib/backend/activation.ts` `classifyChange`): one that only adds a path is
prepared beside the committed one; one that rewrites the running path (a port or path rewrite, a
re-address, a profile edit) is applied in place and needs an explicit **maintenance transition**,
which closes the node (`unavailable`) until it is verified and approved again. The previous
configuration is not claimed to remain served in that case.

**Observed drift** is the same transition without anyone asking for it. When a reconcile finds
the REALITY material moved, or the profile token moved by somebody else's edit
(`foreignEditAt`), under evidence already taken, or a direct node's endpoint moved under one of
its addresses (`nodeIntents.observeRevisions`), the invalidated evidence goes, running
activations are superseded, and a live node closes under a maintenance transition (reason
`drift`, audited as `servers.node.drift`) until it is re-verified and approved again; the
existing addresses are brought to the new endpoint meanwhile (a name that arrived is a new
address, a name that left is removed). A name a family ROLLOUT added to a live node is neither
drift nor a delivery change: the committed addresses keep serving (the node stays `live`, the
gate stays open), the new address is created disabled as a candidate, and the node's own
verification is dropped so it asks for the isolated tick and a fresh approval, which then commits
the whole set. A token FCP's own ledger moved (a family rollout, a
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
(`nodeIntents.closeForSharedChange`): every affected enrolled node closes under one transition
(reason `profile`; it reopens only through its own re-verification and commit), and every
affected node FCP does not manage needs a treatment from the operator, `hold` (closed by name in
`panelMaintenanceHolds` until an admin releases it: nothing re-verifies an unmanaged node) or
`acknowledge` (it changes in place). "No intent means open" never bypasses this. Audited as
`servers.profile.transition` / `servers.profile.transition_released` (counts only).

**The delivery gate** (`lib/backend/deliveryGate.ts`, enforced in `edgeRender.deliveryPolicyFor`,
the pinner's exclusion list, the subscription route, the mirror refresh): closed for an enrolled
node that is not live, under maintenance or retiring; open for an unmanaged node unless an open
maintenance hold names it. Its
**candidate set** is every resource of every activation run that never committed (running,
blocked, under review, superseded, failed), minus what the committed set holds: a superseded or
blocked run's candidate stays isolated until a later commit takes it over. Every render carries
the gate token (`<gate version>:<committed Host count>:<committed edge count>:<hash of the
candidate set>`; the full cache token is in `docs/edges.md` "Rendering"); the route and the
mirror refresh re-read it after rendering and never attach content rendered under an older
policy to a newer token. **Publication** is admitted by `edgeRotations` only under a node's
committed approval or as a candidate of its one activating run (below), for manual, reconcile
and setup publishes alike.

### A fronted node's activation

A node behind edges is taken live by its guided setup run (docs/edges.md "Guided setup runs")
and its approval, all in one place, the protect sheet: **Start** (from the ready node), **Try
it** (one tick per new L4 address; an L7 front is proven by its own session) and **Approve
go-live** (the review card, `NodeApprovalCard`; the Servers node page shows the same card as a
mirror). FCP never starts a run by itself.

- **Planned from the intent.** An enrolled node's plan and transport discovery read the node from
  its intent (`nodeIntents.enrolledOriginOf`): the origin FCP gives the role (the origin name of a
  WebSocket node, else its public address; never the management address) and the declared ingress,
  so a loopback WebSocket behind Caddy is frontable at L7. Whether the ingress answers a foreign
  Host header is taken from what `machine_ready` verified (`ingress_verified`), not re-derived by
  the origin probe. A Host dialling the node's public address counts as direct when the origin is
  a name. Enrollment refreshes the backend node list as soon as it creates the node, so the node
  can be protected at once.
- **Try it on an enrolled node.** No Host exists on a fronted node's transport before its first
  publication, so the L4 test link is built from the transport's live REALITY parameters and the
  origin's own credential (as the direct test link is), then rendered for the candidate edge. The
  origin's credential is minted in the node's own mode, so its body carries this node's transport.
- **Parked at publish, never failed.** The run's publish step checks the node's approval in the
  same transaction as the publish start (`edgeRotations.publicationApproval`). Without one the run
  waits (`needs_you`, `node_not_approved`, the detail is the node's stage, event `publish_held`)
  with nothing published; a refusal the start itself reports for the node's own reasons parks the
  same way.
- **Ownership is stable; the generation is an attempt fence.** The approval binds the activation
  run (`setupRunId`) and the setup run (`activationRunId`) to each other; neither changes when the
  run is retried or resumed (those bump the setup run's generation). A newer approval of the same
  node supersedes the old activation run and rebinds the open setup run.
- **The approval wakes exactly that run.** `approve` (fronted) is allowed from `machine_ready`,
  `candidates_verified`, `awaiting_approval` and, for a re-approval, `live`, when every listener
  of the open setup run has a verified standby whose L4 tick is still current: an L4 tick binds to
  the node's REALITY authentication revision too (docs/edges.md "Publication"), so a key, short-id
  or clock-bound change since the ticks refuses `servers.standbys_unverified` (the review card
  says the key moved) until each address is tried again with the new key. On a live node the same
  change is drift and closes it under maintenance first, as before. It records
  `standbys_verified`, seeds the new run's
  candidates with those standbys (minus anything already committed) and schedules
  `edgeSetupRuns.wakeForApproval {setupRunId, activationRunId, generation}`. The wake acts only
  while the setup run is still at that generation, waiting for this approval, bound to this
  activation, and the activation is the node's current one; it re-enters the run (a new
  generation). A run past its publish goes back to the rehearsal with the old rehearsal dropped,
  and the rehearsal vector names the activation candidate: a new approval is never satisfied by an
  old rehearsal.
- **A stale candidate parks for a fresh approval.** Go-live promotes the run's snapshot in its own
  mutation (`promoteCandidate`, which compares the machine, config, authentication AND delivery
  revisions); on `servers.review_stale`, `servers.standbys_unverified` or `servers.revision_moved`
  the activation is blocked (`blockActivation`: the node parks at `awaiting_approval`, a live node
  keeping its committed delivery) and the setup run waits at `node_not_approved` for the next
  approval. Every terminal writer of a setup run (a failure, a cancel, an unbound finish) calls
  `onSetupRunEnded` with the generation it ends, read before any increment: the bound activation is
  blocked only when both links agree, it is still the node's current run, and the generation is
  the run's current one, so a late hook of an older attempt or another run does nothing.
- **Candidates are isolated, rehearsals render them.** `edgeRender.publishedEdgesOf` takes a
  required selection context: `member` (the subscription route, mirrors, previews) drops every
  candidate edge; `activation` (internal, the setup run's rehearsal only) selects exactly that
  activation run's candidates, after checking it is the node's current, running one, and writes
  nothing (no binding, cache, mirror, pin or render snapshot). A live node's replacement therefore
  rehearses on the edges its commit promotes while members keep the committed ones; after the
  commit the replacement joins what members get.
- **Admission compares the publication with the approval** (`nodeActivation.publicationAdmission`,
  the publish pre-check and the rotation start gate): `candidate` when the node's running
  activation approved this listener with this account, location and template; `committed` when
  the node is live with no activation running, its revisions are the committed ones and the
  publication fits the committed review (a replacement ADDRESS in the same location reuses the
  approval); refused otherwise (another account, location, template, listener or revision needs
  a review; maintenance and retirement refuse). `publicationFits` needs one approved entry equal
  on all four; an entry that names an account but no location never fits (it fails closed). The review lists every required listener
  with its account, location and template (`shape.listeners`; the card names the location),
  never one representative edge. With a provider set the shape is the union of what members
  are served from (every published address, not only the template edge) and the run's targets,
  one entry per (listener, account, location, template). Approving a fronted node is refused
  while edges are frozen (docs/edges.md "Maintenance switch and reset drain").
- **The delivery snapshot.** Before its rehearsal, an enrolled setup run records on its
  activation what members will get after the commit (`delivery.edgeIds`: the committed
  addresses go-live keeps plus the candidates; a `replace_all` keeps only those on transports
  it does not touch). The rehearsal renders exactly that set (an `add` run rehearses every
  cohort against its real future pool), and the commit promotes exactly it into
  `approved.committed.edgeIds`, refusing `servers.delivery_changed` when a kept address stopped
  serving (the run rehearses a new snapshot). `resources` is left as the run's own: the gate and
  cancel keep reading it. A run without a snapshot (a direct node, an older row) commits as
  before. A re-protect of a live node within its approved shape reaches
  go-live and binds without a new approval; outside it, it parks for the review.
- **Protect again from the node page.** A live node is protected again by its own run kind
  (`POST /api/v1/admin/edges/relays/{id}/reprotect`, a `reprotect` setup run, docs/edges.md
  "Guided setup runs"): new candidate addresses on the listeners members are served through, a
  test link for each, then the admission above (no new approval within the approved shape; the
  review card otherwise). Members keep what they have until go-live: the committed edges, the
  binding and the open gate, and a candidate reaches them only when go-live commits it. At
  go-live the new addresses take the old ones' places (the old ones drain, as after a Replace).
  Cancel drops only the run's new addresses (an unpublished one is destroyed, a published one
  drains; the bound activation is blocked as for any cancel). A failure leaves the node live and
  hands the origin back to upkeep and the detector; retry claims it again. One run has one
  provider account: a node served through several is refused (`edge.reprotect_mixed_accounts`).
- **Candidate Hosts on a live node.** A direct node's body reaches members as the backend serves
  it, so an address a candidate would enable cannot be kept out of it; a fronted listener without
  a committed template edge would get a new Host or a moved Host pointer. Either needs the gate
  closed first: the review shows `servers.maintenance_required` and approval refuses it until
  the node is closed for maintenance (`POST …/maintenance {start: true}`, then Finish
  maintenance and a fresh activation with the gate closed).
- **Keep members on the direct address** does not exist for an enrolled fronted node: refused as
  `edge.keep_direct_enrolled` when a run is created and when it resumes (the plan reports
  `enrolled`, and the sheet hides the choice). Removing protection stays the restore workflow's job.
- **The mirror barrier.** An S3 mirror upload takes real time and the delivery token can move
  while it is in flight, which a check before the upload cannot see. Every upload (a first mirror
  as well as a refresh) opens a `mirrorUploads` obligation with the token its body was rendered
  under BEFORE the object is written, and settles it only when the token read after a successful
  upload is unchanged. An open obligation past its in-flight grace is repaired by the
  `mirror-barrier-repair` cron (`storage.repairMirrorUploads`, every 5 min): the subscription's
  mirror is re-rendered and re-uploaded under the current policy (the unavailable stub when its
  place is gated or edge-required with nothing to render), or a copy no subscription references
  is withdrawn. Rows hold a subscription id, the object path, provider names and the token.

**Authorization decision.** A staged node serves a shared transport: an existing credential could
authenticate on it if someone learned its address. That is accepted (REALITY keys are per transport
by design); what approval gates is exposure. Backend subscription URLs are not a member-facing
surface; the direct Host is enabled only during the run's rehearsal and disabled again on failure.

### Node registration (contract v2)

Routes on `{slug}/nodes/by-name/{name}` (`convex/httpServers.ts`; a former name resolves through
the rename aliases). Scopes (`scopeFor`, `lib/adminHttp.ts` `registrationBoundaryOf`): a `GET`
takes `admin:servers:read`, `admin:servers:write`, `admin:edges:register` or
`admin:servers:manage`; every other verb `admin:servers:write`, `admin:edges:register` or
`admin:servers:manage`. Only `admin:servers:write` (and `admin:servers:read` on a `GET`) is
unbounded. `admin:edges:register` and `admin:servers:manage` are confined to the token's
registration boundary (backend servers and, optionally, node names; none = nothing), so
backend-write automation never reaches a node's secret (`bootstrap`) on its own; outside the
boundary the answer is 403 `servers.registration_boundary`. Only `bootstrap` is throttled
(`admin.servers.panel-write`). Nothing under `/api/v1/admin/edges/` accepts
`admin:edges:register`.

| Route              | What                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PUT`              | Enroll or report observations (`NodeRegistration`): `{roleContractVersion: 2, mode, label?, machineName?, observed: {management: {address, port}, publicIps: {v4?, v6?}, capabilities: {caddy, ipv6}}}`. `mode` and `label` are taken once; observations every run. `machineName` is the machine's own name (the role sends its inventory host name), shown to operators next to the node and matched by the Nodes filter; it is never member-facing (the node name stays in address remarks and subscription bodies), never part of the desired hash, kept when a run omits it, and ignored when it is not a plain host name. The role never sends FCP-owned settings. Answers the view. |
| `GET`              | The node's own view (`NodeRoleView`): `name` (the current one), `mode {slug, name, shape}`, `registration {state, code, generation}`, `stage`, `delivery`, `machineRevision`, `appliedRevision`, `node {uuid, port}`, `origin {hostname, dns}`, `retirement`, `firewall.ports`, `updatedAt`.                                                                                                                                                                                                                                                                                                                                                                                              |
| `POST …/bootstrap` | The machine configuration and the node secret: `machineRevision`, `secretKey` (read from the backend per call, never stored, logged or audited), `node {port, name, mode}`, `ingress {hostname, externalPort, routes[{path, port, upstream?: 'h2c'}]}` or null (`upstream: 'h2c'` for a gRPC transport, proxied over HTTP/2 cleartext), `origin {hostname, dns}`, `firewall.ports`. `SEAL_BOTH`; bearer callers get plaintext over TLS as on every IaC route.                                                                                                                                                                                                                             |
| `POST …/applied`   | `NodeAppliedReport`: `{appliedRevision, caddy?: {certificateReady}, nodeStarted, firewall?: {ports: [{port, protocol: 'tcp'}]}}` (at most 64 ports). `appliedRevision` must equal the current `machineRevision`; the same revision again is idempotent. The listed ports confirm this node's waiting port requirements (§ Firewall acknowledgement).                                                                                                                                                                                                                                                                                                                                      |
| `DELETE`           | A retirement request (below). Answers the view.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `POST …/wiped`     | The role's acknowledgement that the machine is cleaned up (`ready_to_wipe → retired`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

`firewall.ports` entries are `{port, protocol: 'tcp', reason: 'serving' | 'pending'}`
(`lib/backend/portRequirements.ts`): `serving` = the non-loopback ports of the transports the
node serves (its mode's transport before the backend node exists) plus the ingress external
port; `pending` = a staged change's port, listed until that change ends. The node API port is
never listed.

Refusals. `PUT`: `servers.manage_disabled`, `servers.contract_version`,
`servers.panel_not_set_up`, `servers.mode_unknown`, `servers.node_retiring`,
`servers.mode_change_needs_admin`, `servers.node_exists_unowned` (a backend node or Host of that
name no intent owns: an admin adopts first), `servers.tombstoned` (an admin restores),
`servers.origin_label_invalid`, `validation`. `bootstrap`: `servers.node_retiring`,
`servers.unsupported_backend`. `applied`: `servers.revision_stale` (the configuration moved on:
run the role again), `servers.revision_unknown`. Every verb: `servers.registration_boundary`.

A shared change (a profile edit, `POST {slug}/profiles/{uuid}/apply`) takes an `unmanaged`
treatment (`hold` | `acknowledge`) whenever nodes FCP does not manage run the touched transports
(`servers.unmanaged_nodes_affected` otherwise); `GET {slug}/nodes/intents` lists the open holds
and `POST {slug}/holds/{id}/release` ends one. `POST {slug}/nodes/adopt` adopts a node (above).

Admin routes on `{slug}/nodes/intents/{id}`: `GET review`, `POST test-link`, `POST confirm`,
`POST approve {reviewHash}`, `POST settings {patch, maintenance}`, `POST maintenance {start:
true}` (close the node for maintenance) and `POST maintenance` (finish),
`POST retire [{disposition}]`, `POST wiped` (an ADOPTED node's machine confirmed gone by an
admin, since no role runs it; the role's own `POST {slug}/nodes/by-name/{name}/wiped` does this
for a machine FCP bootstrapped).

### Origin names

A front node's origin name is `<label>.<zone>` in the Cloudflare zone chosen at setup (or an
explicit hostname the admin sets). A backend set up without a zone gets one with **Change
setup** (Admin -> Servers -> Nodes, Backend setup): pick a Cloudflare DNS account whose zone
holds the names. It is recorded in place, touching no node ("Changing a backend's setup"); every
WebSocket node enrolled from then on gets a managed name, and one enrolled before, blocked on
`servers.origin_hostname_missing`, takes its managed name at once
(`nodeIntents.nameWaitingFrontNodes`: a new machine revision for the role to apply, then the
usual reconcile; a node with a hostname of its own, an adopted one, a retiring one and one that
was ever live are left alone). The zone stays while any node has a name in it: another account
holding the same zone may replace the account, another zone may not.

Records are **obligations** (`backendObligations`, kind `dns.record`) persisted before the call
with the account, zone, marker `fcp-origin:<slug>:<name>` and expected content; an uncertain
answer is discovered by name and marker before anything is sent again; a record FCP did not
write, or a CNAME at the name, is `servers.origin_name_taken`, never replaced; FCP's own record
with other content is replaced. Cleanup uses the obligation's own account and zone. `created`
and `resolves` are distinct.

### Obligations

External side effects of every workflow are rows persisted before the call
(`backendObligations`). An outstanding row blocks its identity whatever generation owns it
(`blocksIdentity` in `lib/backend/obligations.ts`); a superseded generation never releases an
unresolved one; a lease expiry resumes discovery of the same attempt, and the owning workflow
settles a late result by that discovery against what it wants now (the origin DNS record above,
by name and marker), never by rule.

### Retirement

`DELETE …/by-name/{name}` only records the request. Whenever the node was ever live or anything
of it is still out there, the retirement is `needs_admin`; the admin decides `keep-dark` (its
members get the edge-required unavailable answer). An admin's own retire (the node page's header
More menu, "Retire node…", a typed-name confirm) IS that decision: it starts the ladder keep-dark
at once (`nodeRetirement.startIfPlain`), audited with the admin. Either way the gate closes the
moment the retirement is recorded: members lose the node at once. Moving the members to another node is not
offered: a `migrate` disposition is refused with `servers.migration_not_built`. Never
`restore-direct`. The ladder: `draining` (the origin deleted keep-dark, credentials released,
the direct Host deleted, DNS withdrawn) → `panel_removed` (the row removed with `removeOnly`, the
name tombstoned) → `ready_to_wipe` → `retired` (events `wiped`, `retired`). The last step is the role's `wiped` ack for a machine FCP bootstrapped, or an
admin's confirmation that the machine is gone for an ADOPTED node, whose machine no role runs
("The machine is gone" on the node, `POST {slug}/nodes/intents/{id}/wiped`, audited with
`confirmedBy: admin`). Without either the ladder would sit at `ready_to_wipe` forever.

The sweep (`backend-bootstrap-sweep`, every 5 minutes) pushes `draining` along and records where
it stopped (`panelRetirements.step`: `origin`, `credentials`, `addresses`, `dns`, `panel_row`)
and why (`code`); a wait it meets again on the next pass is one event, not one per pass. The
intents list projects `retirement {stage, code, step, requestedBy, requestedAt, since}` and the
node page words it as steps (`retirementSteps`): the one it is on and why it waits there. A
retiring node whose panel row is already gone stays listed on Servers (and its page stays
reachable) until it is retired.

## Deploy a fronted node

From an empty machine to a member connecting through an edge, for an L4 mode
(`freedom-reality`, `freedom-xhttp`) or an L7 one (`freedom-ws`). Every switch below ships off.

1. **Switches, once per deployment.**
   - `servers.manage.observe` and `servers.manage.enabled` on (§ Switches).
   - The connection mode members are issued into enabled (Admin → Connection modes;
     `freedom-ws` ships enabled, `freedom-reality` and `freedom-xhttp` ship disabled).
   - For a REALITY mode, server names on (`edge.sni.enabled`) and a family with qualified,
     active names (`docs/edges.md` "Server-name families").
   - Edge rendering (`edge.render.enabled`) may stay off: the first go-live turns it on
     (audited `edge.render.enabled_by_setup`), and the protect plan says so first.
2. **The backend is set up for the mode** (§ Setting up a backend): Servers → Backends, "Set up
   this backend", with the mode's family and, for a front node, the origin DNS account and zone
   (§ Origin names). A backend already set up without them gets them with Change setup on
   Servers → Nodes (§ Changing a backend's setup); a mode it lacks is added there too, once its
   transport is in the profile.
3. **A provider account for the edge**: added and its credentials tested (in the protect
   sheet's account step, or on the provider pages under Edges → Advanced), with a daily
   allocation budget (0, no limit, is refused outside development). An L4 account is trusted by
   its first ticked endpoint, an L7 account by its first passing front proof.
4. **The role's token**: an `admin:edges:register` token bounded to the backend (and,
   optionally, the node name), minted in Admin → API tokens or with
   `adminApi:mintAutomationToken` (`docs/edges.md` "Node role contract"), or the fleet token
   (`admin:servers:write`).
5. **Run the role** with the node's name and `node_mode` (§ Node registration). It enrolls,
   fetches the bootstrap, lets every `firewall.ports` port in, waits for a front node's origin
   name to resolve, starts Caddy (front node) and the node, and reports `applied` with the
   ports it opened. The node reaches `machine_ready` once its applied revision is current and
   the evidence in § Node lifecycle holds; its page (Servers → Nodes) words each step and what
   it waits for.
6. **Protect it**: "Protect this node" on the node's page (also offered on the Edges home and as
   attention `node_ready_to_protect`). The protect sheet preselects the node and a sole
   compatible account; Start. The Autopilot run (`docs/edges.md` "Guided setup runs") creates
   the origin and provisions one edge per transport (at most 8: a node with more asks which).
7. **Try it** (L4): each new address shows a test link and a QR code. Import it into a client,
   connect, and tick "Works" per address; "Doesn't work" replaces just that address. An L7
   front is proven by FCP itself, with no tick.
8. **Approve go-live**: the run parks at publish, waiting for the node's approval
   (`node_not_approved`). The approval card (in the sheet and on the node page) shows the
   review; type the node's name and approve. The run hides the direct Hosts the plan named,
   rehearses delivery for every cohort and format, and goes live in one mutation: the
   activation commits, the gate opens, the delivery binding is claimed.
9. **A member connects**: a key issued into the mode is pinned to the node, and its
   subscription is the fronted URL (`/api/v1/sub/<token>`), whose body names only the edge,
   never the origin. The client imports it and connects through the edge.
10. **Afterwards**, as needed: automatic protection (`POST automation {on}`, offered on the
    run's Live card), probes and operator alerts (`docs/edges.md` "Operations safety").
    "Protect again" on the node's page replaces every address of a live node; "Serve this node
    directly again" ends edge-required delivery and gives members the direct address.

## Admin surface

`/api/v1/admin/servers/*` (`convex/httpServers.ts`), sealed by verb class like the edges
surface (`src/shared/crypto/envelope.ts`): the responses carry node and Host addresses.
`{slug}` is the backend server's slug.

| Route                                                                                                            | Scope                  | What                                                                                                                                                             |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET summary`                                                                                                    | `admin:servers:read`   | Every instance: observable or not, last look, counts, the switches.                                                                                              |
| `GET {slug}/tree`                                                                                                | `admin:servers:read`   | One instance as a tree, from the cache (no backend call).                                                                                                        |
| `POST {slug}/refresh`                                                                                            | `admin:servers:read`   | Look now, then return the tree. Rate-limited (`admin.servers.panel-read`, shared with the profile preview and op observe, the other reads that reach a backend). |
| `POST {slug}/placements/validate`                                                                                | `admin:servers:read`   | Check the mode group pools in mode placements against the mode groups the backend has.                                                                           |
| `GET {slug}/setup`, `POST {slug}/setup`                                                                          | read / manage          | The backend's setup workflow (§ Setting up a backend): its view, and start / resume / adopt.                                                                     |
| `GET config`, `PATCH config`                                                                                     | `admin:settings:*`     | The switches. Audited as `servers.config.update {changedKeys}`.                                                                                                  |
| `POST {slug}/addresses`, `PATCH` / `DELETE {slug}/addresses/{uuid}`, `POST {slug}/addresses/reorder`             | `admin:servers:manage` | Address writes. Answer the op. Rate-limited (`admin.servers.panel-write`).                                                                                       |
| `POST {slug}/modeGroups`, `PATCH` / `DELETE {slug}/modeGroups/{uuid}`                                            | `admin:servers:manage` | Mode group writes.                                                                                                                                               |
| `POST {slug}/nodes`, `PATCH` / `DELETE {slug}/nodes/{uuid}`, `POST {slug}/nodes/{uuid}/enable\|disable\|restart` | `admin:servers:manage` | Node writes. `DELETE ...?removeOnly=1` is "remove from backend".                                                                                                 |
| `POST {slug}/nodes/{uuid}/rename`, `GET {slug}/renames`                                                          | manage / read          | Rename a node (§ Renaming a node), and the recent renames with the step each is at.                                                                              |
| `POST {slug}/profiles/{uuid}/preview`                                                                            | `admin:servers:read`   | What a typed profile edit would do. Writes nothing.                                                                                                              |
| `POST {slug}/profiles/{uuid}/acknowledge`                                                                        | `admin:servers:manage` | An operator has seen that the profile was edited elsewhere.                                                                                                      |
| `POST {slug}/profiles/{uuid}/apply`                                                                              | `admin:servers:manage` | Apply a previewed edit, conditioned on the previewed token. A port change is refused here: it is staged.                                                         |
| `POST {slug}/profiles/{uuid}/port-change`                                                                        | `admin:servers:manage` | Stage a previewed port change until every node's firewall lets the port in (§ Firewall acknowledgement).                                                         |
| `GET {slug}/port-changes`                                                                                        | `admin:servers:read`   | The open port changes, each node's wait, and the last few settled.                                                                                               |
| `POST {slug}/port-changes/{id}/acknowledge`, `POST {slug}/port-changes/{id}/cancel`                              | `admin:servers:manage` | An admin confirms nodes no role reports for; withdraw a change that still waits.                                                                                 |
| `GET {slug}/ops`                                                                                                 | `admin:servers:read`   | The last 50 ops of an instance.                                                                                                                                  |
| `POST {slug}/ops/{id}/observe`                                                                                   | `admin:servers:read`   | Look at the backend again for an open op. Changes nothing on the backend.                                                                                        |
| `POST {slug}/ops/{id}/recover`                                                                                   | `admin:servers:manage` | The attested recovery of an unknown outcome.                                                                                                                     |

**The tree** is node -> the profile it runs -> the transports it **serves** -> the Hosts members
get for each transport (a Host pinned to nodes appears under those only) and the mode groups that
grant it. What hangs off no node is returned as `unattached`: a profile no node runs, a Host on
a transport no node serves. That is usually a leftover worth noticing.

**Placement validation** answers in counts and mode group names, never the pasted uuids (a pool is
write-only over HTTP). `unknownHere` is a count to look into, not a verdict: several instances
can share a backend type, and a uuid missing on this backend may live on another.
`withoutTransports` names mode groups that would issue keys connecting to nothing.

### The page

Admin -> **Servers** is ONE sidebar leaf (the Servers group has five: Servers, Connection
modes, Edges, Storage mirrors, Status page) with three tabs, its paths spelled only in
`src/client/routes/admin/servers/lib/routes.ts`:

| Tab        | Path                      | What                                                                                                                                    |
| ---------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Backends   | `/admin/servers/backends` | The backend servers keys are issued on (add, edit, remove; a link to each Remnawave server's nodes) and the node logging privacy check. |
| Nodes      | `/admin/servers`          | The default tab, below.                                                                                                                 |
| Mode pools | `/admin/servers/pools`    | Which mode groups each connection mode issues new keys into (write-only uuids), and the node load per placement.                        |

The old addresses redirect (`legacyServersRedirect`, pinned by a test): `/admin/backend-servers`
to Backends and `/admin/remnawave` to Mode pools.

**Nodes** is built like the simple Edges screens: one status sentence, a "Needs you" list only
when something is broken, one row per node, and the leftovers as quiet one-line notes (a
transport nobody uses on three nodes is one line, not six). **Backend setup** says how a ready
backend is set up (its modes, the generation, the zone for origin names) and, with changes from
here allowed, carries **Change setup** ("Changing a backend's setup"). The two switches (regular
reading, changes from here) sit in the footer.

**Add a node** (with changes allowed and the backend set up) writes one node row by hand: name,
where the backend reaches it, country, the profile it runs and the transports it serves. The
dialog says first that the node role is the normal way a node arrives (it enrolls the machine;
FCP writes the row, the addresses and the approval) and that this is for a machine the role does
not run. Before anything is sent it shows the placement check: the mode groups that list each
chosen transport, and what `placements/validate` says about every mode's pool (an empty pool, a
mode group this backend does not have, a mode group with no transport). The create is the
ledger's node create (`POST {slug}/nodes`, sent once).

`/admin/servers/nodes/{uuid}` is the node's ONE page: its sentence, the profile it runs, its own
notes, its activation (an enrolled node), its **edges** when an origin protects it, and its
transports with the addresses members get for each. The edges panel is the Edges section's
(`edges/simple/NodeEdgesPanel.svelte`, loaded lazily): the origin's status from the server's one
projection (docs/edges.md "Admin section"), Go live or Replace address, More (a spare address,
**Protect again**, Origin details, Remove protection), the test card (`?test=<edgeId>`), the
addresses in use, the per-node automatic switch and recent activity. `/admin/edges/nodes/<slug>`
redirects here for a backend node. **Protect again** (an enrolled node live behind edges) starts
a re-protect run ("A fronted node's activation") and opens its progress in the protect sheet; it
is the primary action while the node waits to be protected again.

With changes allowed and the backend set up the node header carries Edit, Restart or Turn on,
and a More menu with Turn off, **Stop and remove** (offered only once the node is off) and
**Remove from the backend only** (says the process may keep running); both removes are typed.
An enrolled node adds **Retire node…** after a separator (typed; it says members lose the node at
once), offered even with changes off; its steps then show under "On its way to members" (see
"Retirement").
On a transport: add, change or remove an address; edit a REALITY transport's names and target as
write -> preview -> apply, typed when more than one node restarts; **Change port** (write ->
preview -> stage: the nodes and who confirms each, then "Port changes" lists what waits on whom)
and, under the profile, **Add a transport** from a template. The Nodes tab lists mode groups
(add, rename, change transports, remove) and Recent changes ("Look again" on an open one,
"Settle by hand" on an unknown outcome, asking for each recovery condition by name).

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
