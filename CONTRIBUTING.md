# Contributing to FreeSocks Control Plane

Thanks for helping build censorship-circumvention infrastructure. Contributions of all
kinds are welcome — code, docs, translations, and testing from inside censored networks
are all valuable.

## Toolchain

**Bun only.** `bun.lock` is the only lockfile — do not use npm or yarn.

- [Bun](https://bun.sh) ≥ 1.3 (package manager + CLI launcher)
- Docker (Compose v2) for the self-hosted Convex backend

## Local setup

```bash
cp .env.docker.example .env.docker   # local defaults are fine for throwaway dev
bun install
bun run selfhost:up                  # Convex backend + dashboard (Docker)
bun run selfhost:env                 # writes an admin key to .env.local
bun run dev                          # convex dev (pushes convex/) + the Vite SPA
bunx convex run seed:seedCutover '{}'  # seed default tiers + settings (idempotent)
```

The SPA is at http://localhost:5173. The full walkthrough (env vars, admin bootstrap,
production cutover) is in [`docs/convex-self-hosting.md`](docs/convex-self-hosting.md),
and [`docs/project-inventory.md`](docs/project-inventory.md) maps every feature before
you go digging.

## Checks

Every change must pass all four (CI runs the same set):

```bash
bun run test         # vitest + convex-test (in-memory; no running backend needed)
bun run typecheck    # tsc -b (client+shared) + tsc on convex/ + svelte-check
bun run lint         # eslint + prettier --check   (bun run format fixes style)
bun run build        # tsc -b + vite build
```

New behavior needs tests — the existing suites in `convex/*.test.ts` show the patterns
(`convex-test` for domain logic, route-level tests in `convex/http.test.ts`, pure adapter
tests with a stubbed `fetch`).

## Conventions that matter most

- **Contracts are the API shape.** The zod schemas in `src/shared/contracts/` are the
  declared surface the SPA parses against; the server's Convex `v.*` validators must
  agree. Change the contract, not an ad-hoc shape.
- **All client fetching goes through TanStack Query + `apiClient`**
  (`src/client/lib/api.ts`); register new queries in `src/client/lib/queries.ts`. No
  direct `fetch()` from components.
- **Never log or persist secrets** — API keys, the member account-number plaintext (only
  the 4-digit prefix), Outline `apiUrl`s, or client IPs. Backend error types deliberately
  avoid capturing URLs; keep it that way.
- **No third-party runtime dependencies in the SPA.** No external `<script>`, font, or
  CDN — everything is bundled and served same-origin (a censorship-resistance
  requirement, enforced by the CSP).
- **Convex channel invariant:** `publicConfig.get` is the only public `api.*` function;
  every other query/mutation stays `internal*`.
- **i18n:** user-facing strings live in `messages/<locale>.json` (Paraglide); add the
  key to `en.json` and the other locales. Native-speaker corrections for fa/ar/ru/zh are
  especially welcome.
- Generated code in `convex/_generated/` is committed; regenerate with
  `bun run convex:codegen` after schema/function changes.

## Pull requests

Keep PRs focused and describe what changed and why. If a change affects the security
posture or privacy guarantees (anything in `docs/privacy.md` or the threat-model docs),
call that out explicitly. For vulnerabilities, use the private channel in
[`SECURITY.md`](SECURITY.md) instead of a public PR or issue.
