# Server management

Admin -> Servers shows, and will later manage, what lives on a proxy panel: its **nodes**, the
**config profiles** and **inbounds** they run, the **Hosts** members are handed and the
**squads** that grant them. It is built the way [edges](edges.md) is: a pure library
(`convex/lib/panel/`), isolate queries and mutations that are the only writers of their tables,
one bounded provider call per action, one HTTP prefix with a dispatcher, contracts in
`src/shared/contracts/servers.ts`.

**Today it is read-only toward the panel.** FCP reads and shows what exists. Writes come later,
each behind its own switch, and none ships enabled.

Backends: a type takes part when its provider implements `observePanel` and declares the
`panelObservation` capability (`convex/lib/backends/capabilities.ts`). Remnawave 3.x does;
Outline has nothing to observe and answers `servers.unsupported_backend`.

## Switches

`servers.manage.*` rows in `appSettings` (`convex/lib/serverConfig.ts`), both **off** by default:

| Key                      | Off (default)                                               | On                                                                          |
| ------------------------ | ----------------------------------------------------------- | --------------------------------------------------------------------------- |
| `servers.manage.observe` | FCP makes no additional panel call.                         | Each capable panel is read at the tail of the backend healthcheck (10 min). |
| `servers.manage.enabled` | Every management write refuses (`servers.manage_disabled`). | Reserved for the write routes. No write route exists yet.                   |

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

## Admin surface

`/api/v1/admin/servers/*` (`convex/httpServers.ts`), sealed by verb class like the edges
surface (`src/shared/crypto/envelope.ts`): the responses carry node and Host addresses.
`{slug}` is the backend server's slug.

| Route                             | Scope                | What                                                                                                           |
| --------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------------- |
| `GET summary`                     | `admin:servers:read` | Every instance: observable or not, last look, counts, the switches.                                            |
| `GET {slug}/tree`                 | `admin:servers:read` | One instance as a tree, from the cache (no panel call).                                                        |
| `POST {slug}/refresh`             | `admin:servers:read` | Look now, then return the tree. Rate-limited (`admin.servers.panel-read`): the one route that reaches a panel. |
| `POST {slug}/placements/validate` | `admin:servers:read` | Check the squad pools in mode placements against the squads the panel has.                                     |
| `GET config`, `PATCH config`      | `admin:settings:*`   | The switches. Audited as `servers.config.update {changedKeys}`.                                                |

**The tree** is node -> the profile it runs -> the inbounds it **serves** -> the Hosts members
get for each inbound (a Host pinned to nodes appears under those only) and the squads that
grant it. What hangs off no node is returned as `unattached`: a profile no node runs, a Host on
an inbound no node serves. That is usually a leftover worth noticing.

**Placement validation** answers in counts and squad names, never the pasted uuids (a pool is
write-only over HTTP). `unknownHere` is a count to look into, not a verdict: several instances
can share a backend type, and a uuid missing on this panel may live on another.
`withoutInbounds` names squads that would issue keys connecting to nothing.

## Adding an observed backend

1. Implement `observePanel(config, digestKey)` on the provider and return `PanelObservation`
   (`convex/lib/backends/types.ts`). Reduce anything secret-bearing **inside** the provider.
2. Set `panelObservation: true` for the type in `capabilities.ts` (the consistency test pins the
   flag to the method).
3. Add a redaction test in the style of `remnawave.observe.test.ts`, and a live step to the
   backend's integration test.
