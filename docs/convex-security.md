# Convex security and isolation

What self-hosted Convex does and does not isolate, what FCP adds on top, and
the tests that keep it that way. Read this before adding a Convex function, an
HTTP route, a runtime dependency or a compose service.

## What Convex gives us, and what it does not

Self-hosted Convex has few security knobs, and FCP uses every one that applies:

- **Function visibility.** Public functions are callable by anyone who can reach
  the deploy port (`:3210`), with no auth and no rate limit. Internal functions
  are reachable only from FCP's own code (and from the admin key).
- **Validators.** `args` validators on every function, `returns` on the public
  one, and schema validation on every document write.
- **Log redaction and telemetry.** `REDACT_LOGS_TO_CLIENT=true` (error details
  never reach API clients), `DISABLE_BEACON=true`, and a `RUST_LOG` that keeps
  request URIs out of the backend log ([`privacy.md`](privacy.md) §4).

What it does **not** give a self-hosted deployment:

- **No scoped or read-only admin keys.** Every admin key is derived from
  `INSTANCE_SECRET` and has full control: it can read every table, read and set
  every env var, read logs and run any internal function, bypassing FCP's audit
  log. A key cannot be revoked on its own; rotating `INSTANCE_SECRET` revokes
  them all. (Convex's scoped deploy keys are cloud-only.) The dashboard holds
  the same power, which is why it stays behind an SSH tunnel.
- **No per-function secrets.** Every function, V8 or `"use node"`, can read every
  deployment env var.
- **No sandbox for `"use node"`.** Node actions run in the backend container
  with the same env and the same `ctx.run*` reach as everything else.
- **Env vars live in the database.** Convex stores deployment env vars in its
  own tables in the same Postgres database, so a `pg_dump` contains every secret
  (`SESSION_SIGNING_KEY`, `ACCOUNT_ID_PEPPER`, the HPKE and manifest keys). The
  age encryption of backups and the owner-only snapshot directory
  ([`beta-deploy.md`](beta-deploy.md), "Backups & restore" and "Exports stay
  outside the checkout") are the real controls. It is also why encrypting
  individual fields in the database would not help: the key would sit in the
  same dump.

So the rest is FCP's job, and the sections below are how it does it.

## The raw surface: one public function

`publicConfig.get` is the only public function. Everything else is
`internalQuery` / `internalMutation` / `internalAction`, reachable only through
the HTTP router, where auth, scopes, proof of possession and rate limits live.

- `convex/publicSurface.test.ts` fails the build when any other file imports a
  public builder (`query`, `mutation`, `action`, or the `*Generic` ones), and
  when any loaded module registers a second public function.
- `publicConfig.get` declares its return shape (`convex/lib/publicConfigReturns.ts`).
  Convex rejects any field not listed there, so a new public field has to be
  added on purpose, in that file and in `PublicConfig`
  (`src/shared/contracts/auth.ts`). The same test keeps the two key sets equal.

There is no `convex/auth.config.ts`, so Convex's JWT identity path is off and
`ctx.auth` is never consulted.

## The HTTP router is the perimeter

Each route resolves its caller itself, through `resolveMember` /
`resolveAdmin` (`convex/lib/http.ts`). `convex/routeAuth.test.ts` checks, for
every route in `http.ts`:

1. it calls a resolver, or is in `PUBLIC_ROUTES` with what gates it instead (a
   probe, the public bootstrap, a credential ceremony, a signed webhook);
2. every `resolveAdmin` call passes a scope, and `resolveMember` without a scope
   (any member token passes) is limited to `MEMBER_ANY_TOKEN`;
3. the edges and servers sections register only through their `wrap`, which
   resolves the admin with a per-verb scope;
4. at runtime, an anonymous request to every non-public route is refused.

Adding a public route means adding it to `PUBLIC_ROUTES` with its reason.

Row-level-security wrappers (convex-helpers `wrapDatabaseReader`) do not fit
this design: they key off `ctx.auth` inside queries, and FCP deliberately keeps
identity at the HTTP layer and passes explicit ids to internal functions.

## Arguments

All functions declare `args`. `v.any()` is allowed only where something else
validates the value, and `convex/anyArgs.test.ts` lists every one with what
that is. When a value lands in a typed schema field unchanged, use that field's
validator instead (for example `lib/edges/reachabilityValidators.ts`, shared by
`schema.ts` and `edges.patchEdge`).

## Runtime dependencies

Because any function can read every secret, every npm package bundled into the
backend is part of the trust boundary. `convex/runtimeDeps.test.ts` computes
that set from source (every non-test file under `convex/` plus the local files
they import, `src/shared` included) and requires each package to be listed with
a reason. Before adding one, prefer a small hand-written client over an SDK, as
the Gandi DNS adapter does.

## Outbound URLs

`checkInfraUrl` (`convex/lib/urlSafety.ts`) refuses loopback, link-local and
metadata addresses, Docker's host aliases, and this stack's own compose service
names. Fetches run inside the backend container, where `postgres`, `valkey`,
`backend` (the deploy API) and the rest resolve to private peers.
`convex/lib/urlSafety.test.ts` keeps the name list in step with both compose
files, so a new service must be added there.

## The containers

`docker-compose.stack.yml` (its header has the same notes):

| Service            | Networks                            | Hardening                                                         |
| ------------------ | ----------------------------------- | ----------------------------------------------------------------- |
| backend            | edge, data, checks, ops, epoch_keys | uid 10001, read-only root, no capabilities                        |
| postgres           | data (internal)                     | only the capabilities its entrypoint needs                        |
| valkey             | cache (internal)                    | only the capabilities its entrypoint needs                        |
| cap                | edge, cache                         | no capabilities                                                   |
| web (Caddy)        | edge                                | read-only root, only `NET_BIND_SERVICE`                           |
| dashboard          | edge                                | read-only root, no capabilities                                   |
| edge-client-check  | checks                              | read-only root, no capabilities                                   |
| hpke-epoch-store   | epoch_keys (internal)               | read-only root, no capabilities                                   |
| backup             | data, backup_egress                 | only `DAC_READ_SEARCH` (reads the signing key), read-only DB role |
| deployer           | ops, epoch_keys                     | no capabilities                                                   |
| keygen, data-perms | none                                | no network                                                        |
| db-roles           | data                                | no capabilities                                                   |

Every service also runs with `no-new-privileges`. Docker cannot filter by port,
so anything that shares a network with `backend` can reach `:3210`; the layout
keeps Caddy, the client-check sidecar and the data stores off the networks they
do not need. `convex/deployPins.test.ts` holds all of this in place, plus the
privacy defaults and the Caddy request-body cap (1 MB, above the largest route
limit; Convex buffers a whole HTTP-action body before a handler can refuse it).

**Running the backend as non-root.** Upstream ships its binaries owner-only
executable as root. `docker/convex-node/Dockerfile` makes them world-executable,
and the one-shot `data-perms` service hands the data volume to uid 10001 before
the backend starts (idempotent; it touches only files not already owned by that
uid).

**Backups as a read-only role.** The one-shot `db-roles` service creates or
refreshes `fcp_backup` with `pg_read_all_data` (`docker/db-roles.sh`); the backup
sidecar dumps as that role and never holds the superuser password. Its password
is `BACKUP_DB_PASSWORD` in the infra env file, generated by
`bun scripts/bootstrap-secrets.mjs`. Restores still run as the superuser.

**The admin key file** that `keygen` writes for the deployer is owner-only
(mode 600).
