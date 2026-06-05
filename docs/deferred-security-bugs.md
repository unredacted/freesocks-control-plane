# Deferred items from the security + bugs audit pass

A three-agent audit (security, major bugs, account-number-design) ran on
2026-05-17. The most consequential findings — three Critical security issues,
four High security issues, and six Critical/High bugs — were fixed in the same
pass. This document tracks the remaining items that were triaged as either
**deferred-by-design** (they need a cohesive follow-up rather than a one-shot
fix) or **lower priority** (real but not load-bearing for the imminent prod
push).

The audit itself is fresh in the conversation history; this file is the
durable record for the next maintainer who picks any of these up.

## Why these aren't fixed yet

The audit cycle landed during the lead-up to a production deploy. Cherry-picking
the obvious P0/P1 issues kept the change set focused; the items below either
need design discussion, cross-feature coordination, or have a real fix that's
larger than the rest of the audit pass justified.

## Recently resolved

Fixed in the 2026-06 straggler-cleanup pass (detailed sections below retained for
history):

- **M1** (PRNG → CSPRNG), **M2** (cookie separator), **M3** (audit-payload scrub),
  **M4** (admin-auth enumeration + per-IP throttle).
- **H1** (free-tier race) — now an ATOMIC cap via a `free_grants.slot` column +
  `UNIQUE(ip_hash, granted_day_bucket, slot)` (migration `0009`), claimed with
  `slot = COUNT(...) % cap` + `onConflictDoNothing().returning()`. Loss is detected
  by an empty returned array — the portable signal across the D1/better-sqlite3/libSQL
  driver union, which can't read affected-rows uniformly. The slot is claimed before
  any backend work, so a lost race rolls back only a bare user row. (Supersedes the
  Durable-Object / D1-stored-proc options floated in the H1 section below.)
- **Bug 5** (per-tier grace), **Bug 10** (tier_history ordering), **Bug 11**
  (cleanupExpired join), **Bug 14** (Remnawave squad clear).
- **Bug 6** (dual-backend tier disambiguation) — `applyMembership` now passes the
  user's active `sub.backend` to `findForMembership`. Latent (single backend) but correct.
- **Bug 8** (propagate overlap) — `propagateTierChanges` is now wrapped in a
  best-effort KV lock. **Bug 9** — reconcile lock TTL raised 60s→300s to cover
  worst-case pagination. NB: both locks are still KV get/put, NOT atomic CAS — a rare
  cross-isolate overlap remains possible and is accepted as harmless (applyMembership /
  propagate PATCHes are idempotent; self-host also has the in-process `runGuarded`). A
  true CAS/lease primitive remains a nice-to-have.
- **Bug 13** (idempotency_keys dead table) — dropped in migration `0010` along with the
  dead `SubscriptionRequest.idempotencyKey` field.
- Outline (latent, backend disabled): `accessKeyCount` is now incremented on issue.

**Still open / deferred:** **Bug 15** (Outline WSS `accessUrl`, latent — needs the
fork's response contract); remaining Outline-hardening — scoring **RTT capture** (needs
a new latency column + migration) and a **hard-cutoff disable** path — both latent while
Outline is disabled; **L2** (Authentik self-provisioning, accepted). **Test gaps still
open:** CiviCRM client, email factory/providers, S3 storage, WebAuthn ceremonies
(Remnawave client + backend, webhook HMAC, and the Authentik JWT verifier are now
covered).

## Security — deferred

### H1. Free-tier rate-limit race

**Location** `src/server/services/rate-limit.ts:54-65`, `src/server/services/free-tier.ts:64-95`

**The issue.** `checkAndIncrement` reads the KV counter, increments, then
compares against `max`. Two concurrent requests can both observe `current=cap-1`
and both pass the check, then both fall through to the D1 backstop which has a
parallel TOCTOU between `select count(*)` and `insert into free_grants`. The
beta deployment is low-traffic so the race surface is small, but on a viral
spike an attacker firing N concurrent requests from one IP can over-issue by
roughly N×cap.

**Why deferred.** The fix is a coordinated rework: either Cloudflare Durable
Objects (a single object instance per `ipHash:day` bucket serializing the
check-then-write), or a D1 stored procedure / UPSERT with a `WHERE
(SELECT COUNT(*) FROM free_grants WHERE ...) < cap` guard. Durable Objects
would change the deploy story (storage + cost model), and a D1 atomic check
needs a careful migration that doesn't churn the hot path. Both deserve a
dedicated change.

**Mitigations currently in place.** The KV increment is unconditional and the
D1 backstop catches the steady-state case; the race only widens during
genuinely concurrent bursts. Combined with Turnstile gating on every free-tier
request, sustained abuse is hard. The IP-based cap is also a soft signal —
NAT'd users sharing an IP can hit the cap without being attackers.

---

### M1. PRNG: `Math.random()` for Outline server selection

**Location** `src/server/services/outline-pool.ts:65`, `src/server/lib/retry.ts:26`

**The issue.** Top-3 server selection and retry jitter use `Math.random()`.
Not security-critical (these aren't selecting secrets) but `Math.random()` is
predictable. Belt-and-braces would be `crypto.getRandomValues()`.

**Why deferred.** Cosmetic; flagged for completeness rather than risk.

---

### M2. Cookie signed-value separator

**Location** `src/server/lib/cookies.ts:24-36`

**The issue.** `signValue` joins value and signature with `.`, then
`verifySignedValue` splits on `lastIndexOf('.')`. Session ids from
`randomHex(32)` are hex-only so the split is unambiguous today. Future callers
that pass values containing `.` would tip the parser into incorrect
verification.

**Fix.** Replace the separator with `|` and reject inputs containing it before
signing. Small, contained change — bundled with the next session-related work.

---

### M3. Audit log payload scrubbing

**Location** `src/server/services/audit.ts:22-33`, callers in `routes/api/admin/*.ts`

**The issue.** `payload: data` writes the entire request body to the audit
table. Anyone with `admin:audit:read` can read what other admins typed,
including any free-text descriptions or PII that future tier definitions
contain.

**Fix.** Per-action allowlist of payload keys. The `outline-servers` route
already shows the right pattern (only logs `Object.keys(data)`). Migrate the
other admin routes to match.

**Why deferred.** Touches every admin write endpoint. Worth doing in one pass
with consistent allowlists rather than piecemeal.

---

### M4. Admin authentication endpoint enables username enumeration

**Location** `src/server/routes/api/admin/auth.ts:144-158`

**The issue.** `/authenticate/options` returns distinct responses for "username
unknown" (`No such admin`) vs valid username (returns options + credentials
list). An attacker can dictionary-scan to identify valid admin usernames; with
C3 now fixed, the next-step replay is harder but the username leak still
informs targeted social-engineering attacks.

**Fix.** Return an identical response shape for both branches — generate a
dummy challenge with random-but-stable data for unknown usernames so timing and
shape match the valid case. Add KV-backed rate-limit per IP.

**Why deferred.** The admin universe is small (one or two usernames typically)
so the enumeration ceiling is low. Worth fixing alongside the next admin-auth
hardening pass.

---

### L1 / L2. Cookie `timingSafeEqual` length-leak; Authentik auto-provisioning guard

**Location** `src/server/lib/crypto.ts:38`, `src/server/middleware/bearer-auth.ts:82-110`

**Status.** L1 is informational (cookie sig length is fixed so no real leak).
L2 is partially mitigated by H4's audience-required fix that just shipped —
tokens minted by other Authentik clients are now rejected before
auto-provisioning runs. Remaining gap: any user known to Authentik for the
FreeSocks client can still self-provision a local user row by hitting any
endpoint with a valid JWT. Document as accepted behavior for now (FreeSocks
trusts the Authentik member list).

## Bugs — deferred

### Bug 5. `runGraceSweep` ignores per-tier `expirationDaysAfterMembershipLapse`

**Location** `src/server/services/membership-sync.ts:294`

**The issue.** Disable transition is hardcoded to 7 days; the grace-warning
email uses each tier's configured value. If an admin configures a 14-day grace
on a tier, the warning email tells the user one date but actual disable fires
after 7.

**Fix.** Either compute the per-row cutoff using each row's tier's
`expirationDaysAfterMembershipLapse`, or denormalize a `graceEndsAt`
timestamp onto `users` at grace transition time.

**Why deferred.** Only fires when an admin explicitly changes the per-tier
value. Default is 7, which the hardcoded constant matches — so users today are
unaffected. Worth fixing before any tier ships with a non-default grace.

---

### Bug 6. `applyMembership` doesn't disambiguate dual-backend tiers

**Location** `src/server/services/membership-sync.ts:121-125`

**The issue.** `findForMembership` is called with no backend filter. The schema
explicitly allows two active tiers per `civicrm_membership_type_id` (one per
backend). The matcher returns the first row that satisfies the status filter
— order is set by KV-cache enumeration order.

**Fix.** Look up the user's active subscription first; pass `sub.backend` as
the backend filter so a Remnawave-backed user's tier resolution stays in
Remnawave space, not silently flipping to Outline.

**Why deferred.** Only fires once both backends have peer tiers configured for
the same CiviCRM type. Outline isn't enabled in beta yet, so the bug is latent.
Pair with the first Outline-paid-tier rollout.

---

### Bug 8. `propagateTierChanges` has no overlap lock

**Location** `src/server/jobs/propagate-tier-change.ts` + `src/server/jobs/dispatcher.ts:24,54`

**The issue.** The `reconcile-memberships` cron runs every 5 min and chains
`propagateTierChanges` after `runReconcile`. If a previous reconcile run
overruns 5 min, two cron firings call `propagateTierChanges` concurrently.
Both observe the same `pending` jobs and the same cursor, double-PATCH the
same users, and may rewind the cursor.

**Fix.** Wrap `propagateTierChanges` in the same KV-lock pattern
`membership-sync.runReconcile` uses.

**Why deferred.** PATCHes are idempotent (same target state) so the visible
impact is doubled backend API load and a rare cursor rewind. Bounded by cron
cadence + queue size. Fix alongside the membership-sync lock hardening (Bug 9
below).

---

### Bug 9. Membership-sync `tryAcquireLock` is racey and lock TTL is short

**Location** `src/server/services/membership-sync.ts:351-360`

**The issue.** `kv.get` then `kv.put` is not atomic — two simultaneous cron
firings both see no lock and both acquire. Lock TTL is 60s but the reconcile
paginates up to 5000 memberships @ 200/page; on slow CiviCRM the lock can
expire mid-run.

**Fix.** Conditional-put via KV metadata version (CAS), or a D1-backed lease
table with `INSERT ... WHERE NOT EXISTS`. Raise TTL to cover worst-case
runtime.

**Why deferred.** Same path as Bug 8 — both want a real lock primitive. Fold
together.

---

### Bug 10. `tier_history` written before `users.tierId` update

**Location** `src/server/services/membership-sync.ts:190-207`

**The issue.** If the `users` update fails after the `tier_history` insert
succeeds, the history row records a change that didn't happen; retry then
writes a duplicate history row.

**Fix.** Swap order (update first, then insert history) or wrap in a D1
transaction.

**Why deferred.** Very rare — requires a partial failure between two
back-to-back D1 writes on the same connection. Real but low probability.

---

### Bug 11. `free-tier.cleanupExpired` join is latent-buggy

**Location** `src/server/services/free-tier.ts:233-265`

**The issue.** `innerJoin(subscriptions, ...)` has no `subscriptions.state`
filter; if a user has multiple sub rows (e.g. after a backend switch on a paid
tier), each row produces a separate iteration and cleanup tries to delete each.
Today only free-tier users hit this path and they only have one sub row by
design, so the bug is latent.

**Fix.** Add `eq(subscriptions.state, 'active')` to the join condition.

**Why deferred.** Latent — not exploitable in current flows. One-liner to fix
on next sweep through the cleanup path.

---

### Bug 13. Dead schema: `idempotency_keys` table

**Location** `src/server/db/schema.ts:319-334`

**The issue.** Table exists but no code reads or writes it. If a future path
populates it without removing the unused indexes, write cost is higher than
needed.

**Fix.** Either remove the table in a future migration, or use it for the
intended purpose (the design was for per-POST idempotency on subscription
issuance — see plan doc).

**Why deferred.** Cosmetic. Doesn't affect runtime.

---

### Bug 14. `RemnawaveBackend.updateUser` cannot clear a squad

**Location** `src/server/providers/remnawave/backend.ts:90-92`

**The issue.** `patch.remnawaveSquadUuid === null` skips the squad assignment
entirely; admins can't unset a squad once configured.

**Fix.** Distinguish "field not present" (skip) from "field present and null"
(clear). The current shape conflates the two.

**Why deferred.** Edge case — admins rarely null out squad uuids. Pick up when
the tier editor surfaces squad management directly.

---

### Bug 15. Outline WSS keys assume a required `accessUrl` (found 2026-05-29)

**Location** `src/server/providers/outline/types.ts:22`, `src/server/providers/outline/client.ts` (`createKey` parse), `src/server/providers/outline/backend.ts:44-89`

**The issue.** `OutlineAccessKey.accessUrl` is a required `z.string()`. `OutlineBackend.issueUser` sends a `websocket` body when `server.websocketEnabled` is set, then reads `created.accessUrl` unconditionally as the subscription URL. The FreeSocks Outline fork's WSS-wrapped (dynamic-config / `ssconf://`) keys are expected NOT to carry an inline `ss://` `accessUrl` — the YAML config is uploaded to S3 and served as an `ssconf://` URL (see the `0005_outline_servers.sql` migration comment). A WSS key response without `accessUrl` fails the Zod parse in `createKey` and throws a generic "Outline schema mismatch" before issuance can complete.

**Fix.** Obtain the FreeSocks Outline fork's actual WSS create-key response contract, then branch the response handling: when WSS is enabled, accept a key without `accessUrl` and derive the subscription URL from the dynamic-config / `ssconf://` output (mirroring it to S3 as the existing flow intends) instead of from `accessUrl`. Likely makes `accessUrl` optional with a WSS-specific code path. Add a test for a WSS key lacking `accessUrl` — the existing `outline-client` test only mocks a WSS response that _does_ include it.

**Why deferred.** Dormant in the default config: Outline is disabled (`outline.enabled=false`), the default backend is Remnawave, all seeded tiers are Remnawave, and `websocket_enabled` defaults to `0` — so this path is unreachable without three explicit admin opt-ins. It also can't be fixed correctly without the fork's real response shape, which isn't in this repo. **Must be resolved before any WSS-enabled Outline server is registered and routed to.**
