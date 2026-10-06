# Contributing to FreeSocks Control Plane

Thanks for helping. Code, docs, translations and testing from inside censored networks are all
useful. This page covers how to set up, what every change must pass, and the rules that matter
most in this codebase.

## Set up

Follow [Run it locally](README.md#run-it-locally) in the README. You need Bun and Docker. Use
Bun only: `bun.lock` is the only lockfile, so don't use npm or yarn.

[docs/project-inventory.md](docs/project-inventory.md) lists every feature and its status. Read
it before deleting anything that looks unused: some of it is there on purpose.

## Before you open a pull request

Run all of these. CI runs the same set on every pull request.

```bash
bun run test
bun run typecheck
bun run convex:bundle-check
bun run lint                  # `bun run format` fixes formatting
bun run build
```

New behavior needs tests. The existing `convex/*.test.ts` files show the patterns: backend logic
runs in an in-memory Convex (`convex-test`), API routes are tested in `convex/http.test.ts`, and
proxy-server and payment adapters are tested with a fake `fetch`.

If you change how FCP talks to proxy servers or how keys reach apps, also run the Docker suites
(`bun run test:integration:remnawave`, `bun run test:compat`).

## Rules that matter most

### Privacy and secrets

- **Never log or store secrets or identifying data.** That includes API keys, Outline server
  URLs (they contain a secret), visitor IP addresses, and account numbers. For an account
  number, only the first 4 digits may appear anywhere.
- Errors from proxy servers and edge providers must not carry URLs or response bodies, since
  those can contain secrets. Payment adapters may keep a short, truncated response body in
  server-side errors so operators can see why a payment failed, but never a URL, key or
  payer detail. The existing adapters show both patterns.
- A new audit-log action needs an entry in `AUDIT_PAYLOAD_ALLOWLIST` (`convex/lib/audit.ts`),
  which decides which fields get recorded.
- If your change touches anything promised in [docs/privacy.md](docs/privacy.md) or the threat
  model docs, say so clearly in the pull request.

### The website

- **Nothing from other sites.** No external script, font, stylesheet or CDN. Everything is
  bundled and served from the same server, and the browser's security policy blocks anything
  else. This keeps third parties from seeing who visits.
- **Fetch data only through TanStack Query.** Add a query to `src/client/lib/queries.ts` that
  calls `apiClient` (`src/client/lib/api.ts`), which checks every response against its contract.
  Don't call `fetch()` from a component. After a change, refresh the cache with
  `queryClient.invalidateQueries({ queryKey: queryKeys.X })`.
- **Words go in `messages/en.json`.** Every string people see is a translation key. Add new keys
  to English only; the other languages fall back to English until a native speaker translates
  them. Machine translation isn't used. Native-speaker fixes for Persian, Arabic, Russian and
  Chinese are very welcome (`bun run i18n:review` produces review sheets).
- **No em-dashes in text people see.** Use a comma, colon or full stop.
- **Adding a page:** add a branch for its path in `src/client/App.svelte` and link to it with
  `<Link href="/path">`. There's no file-based routing. If the page is public, also add its path
  to `ROUTE_ALLOWLIST` in `convex/lib/umami.ts`, or analytics will count it as `/other`.
- **Components:** ready-made UI pieces live in `src/client/components/ui/` (shadcn-svelte). Show
  `<Skeleton>` placeholders while loading rather than "Loading…" text. Confirm destructive
  actions with `AlertDialog`, never `window.confirm()`. Use `tabular-nums` for numbers that
  change.
- The admin console is English only, on purpose.

### The backend

- **API shapes live in `src/shared/contracts/`.** The website checks responses against these
  schemas, and the backend's own validators must agree with them. Change the contract rather
  than returning an ad-hoc shape.
- **Keep backend functions internal.** `publicConfig.get` is the only public Convex function.
  Every other query and mutation must be `internal*`, because public ones can be called
  directly by anyone who can reach the backend.
- **Every file in `convex/` is built separately.** A file that imports a Node-only package needs
  `"use node"` at the top. `bun run convex:bundle-check` catches mistakes here.
- **Don't read whole large tables.** One backend call can read at most about 32,000 documents.
  For tables that grow with users (users, sessions, subscriptions, the audit log, and so on),
  read through an index, in pages, or from a maintained counter. Never `collect()` them whole.
- After changing the schema or adding a function, run `bun run convex:codegen` and commit the
  updated `convex/_generated/`.

## Pull requests

Keep each pull request focused, and say what changed and why. Report security problems
privately as described in [SECURITY.md](SECURITY.md), not in a public pull request or issue.

## License

This project is licensed under [AGPL-3.0-or-later](LICENSE). By contributing, you agree that
your contributions are licensed under the same terms.
