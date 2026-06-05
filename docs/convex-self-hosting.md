# Self-hosting Convex (FreeSocks Control Plane)

The migration target runs on a **self-hosted Convex backend**. This is the
parallel stack stood up in phase **P1** of the migration
(`.claude/plans/how-hard-or-feasible-harmonic-dahl.md` lives outside the repo;
ask the maintainer). The existing Hono app keeps running until cutover (P11).

## Prerequisites

- Docker (Compose v2)
- `bun install` — installs the `convex` CLI

## 1. Configure the backend

```sh
cp self-hosted/.env.example self-hosted/.env
openssl rand -hex 32          # paste the result into INSTANCE_SECRET in self-hosted/.env
```

## 2. Start the backend + dashboard

```sh
bun run selfhost:up
```

- Backend API  → http://127.0.0.1:3210
- HTTP actions → http://127.0.0.1:3211
- Dashboard    → http://localhost:6791

Data persists in the `data` Docker volume (SQLite). Set `POSTGRES_URL` in
`self-hosted/.env` to move to Postgres when single-box write throughput is
outgrown.

## 3. Generate an admin key and point the CLI at it

```sh
bun run selfhost:admin-key    # prints an admin key
```

Create `.env.local` (gitignored) in the repo root:

```sh
CONVEX_SELF_HOSTED_URL=http://127.0.0.1:3210
CONVEX_SELF_HOSTED_ADMIN_KEY=<the key from the previous step>
```

## 4. Deploy functions + schema

```sh
bun run convex:dev            # watch mode: pushes convex/ and writes convex/_generated
# one-shot:
bunx convex dev --once
```

For CI / non-interactive deploys: `bun run convex:deploy`.

## Stop / reset

```sh
bun run selfhost:down                                           # stop containers
docker compose -f self-hosted/docker-compose.yml down -v        # stop + wipe the data volume
```

## Backups

```sh
bunx convex export --path snapshot.zip
bunx convex import --replace-all snapshot.zip
```

> Pin the `:latest` image tags in `self-hosted/docker-compose.yml` to a specific
> `:<rev>` before any production use.
