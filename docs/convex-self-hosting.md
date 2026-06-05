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

## 3. Point the CLI at the backend

```sh
bun run selfhost:env          # generates an admin key + writes .env.local for you
```

This writes `.env.local` (gitignored) with `CONVEX_SELF_HOSTED_URL` +
`CONVEX_SELF_HOSTED_ADMIN_KEY` (and the `VITE_CONVEX_*` URLs the SPA uses from P9).

> **Do not** run a bare `convex dev` and pick **"Start without an account (run
> Convex locally)"** — that boots a *separate* CLI-managed backend (on a
> different port) instead of this docker one, and writes a conflicting
> `CONVEX_DEPLOYMENT` into `.env.local` (you'll then hit
> *"CONVEX_SELF_HOSTED_URL … must not be set when CONVEX_DEPLOYMENT is set"*).
> Always run the step above first; `.env.local` must contain the
> `CONVEX_SELF_HOSTED_*` vars and **no** `CONVEX_DEPLOYMENT`.

## 4. Deploy functions + schema

```sh
bun run convex:dev            # watch mode: pushes convex/ and writes convex/_generated
# one-shot:
bunx convex dev --once
```

For CI / non-interactive deploys: `bun run convex:deploy`.

## 5. Function environment variables

Convex functions read config from **deployment** env vars (separate from the
SPA's `.env.local`). Set them with `npx convex env set NAME value` (or in the
dashboard → Settings → Environment Variables). Accumulated so far:

| Var | Used by |
| --- | --- |
| `REMNAWAVE_BASE_URL`, `REMNAWAVE_API_TOKEN` | Remnawave backend actions (P4a) |
| `S3_PROVIDER_COUNT`, `S3_PROVIDER_<i>_{NAME,ENDPOINT,BUCKET,PUBLIC_URL,REGION,ACCESS_KEY_ID,SECRET_ACCESS_KEY}` | S3 mirror Node action (P4c) — one block per mirror; `count=0` disables mirroring |

Outline server `apiUrl`s live per-row in the `outlineServers` table, not env.
Later phases add session-signing, Turnstile, and admin-bootstrap secrets.

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
