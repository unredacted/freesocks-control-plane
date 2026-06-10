# Deferred items from the security + bugs audit pass

A three-agent audit (security, major bugs, account-number-design) ran on
2026-05-17. The most consequential findings (three Critical security issues,
four High security issues, and six Critical/High bugs) were fixed in the same
pass. This document tracks the remaining items that were triaged as either
**deferred-by-design** (they need a cohesive follow-up rather than a one-shot
fix) or **lower priority** (real but not load-bearing for the imminent prod
push).

The audit itself is fresh in the conversation history; this file is the
durable record for the next maintainer who picks any of these up.

> **Convex-migration re-annotation (2026-06-05).** This audit predates the move to
> the self-hosted Convex backend. The original findings reference `src/server/…`
> paths and Hono/Drizzle/D1/KV/CiviCRM/OIDC constructs that **no longer exist**.
> Each finding is re-tagged below as one of:
>
> - **CLOSED**: fixed (or made impossible) by the Convex rewrite.
> - **MOOT**: the subsystem it lived in was deleted (CiviCRM, KV-locks, OIDC, the
>   `idempotency_keys`/`kv_table` tables, the per-platform cron triad, …), so the
>   bug can't recur.
> - **STILL APPLIES**: the logic was ported and the concern carries over; re-check
>   against the Convex code.
> - **RE-REVIEW**: possibly relevant but needs fresh analysis on Convex semantics.
>
> The detailed historical sections below are retained verbatim for context; read
> them through the tag at each heading.
>
> **Headline:** **H1 (free-tier over-issuance race) is now CLOSED _by
> construction_.** The per-(ipHash, dayBucket) cap is the serializable Convex
> mutation `freeTier.claimFreeSlot` (`convex/freeTier.ts`): it reads the
> `freeGrants` for the bucket over the `by_ip_day` index, then inserts only if
> under cap. Convex mutations run under serializable OCC, so two concurrent claims
> have a read/write conflict: the loser aborts, retries, re-reads the larger
> count, and sees the cap. Two racers can therefore **never** both observe
> `< cap`. No slot column, no modulo, no UNIQUE trick. Proven by a 12-concurrent-
> claims-@-cap-3 → exactly-3 test in `convex/freeTier.test.ts`.

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
- **H1** (free-tier race): **CLOSED by construction on Convex.** The old D1
  `free_grants.slot` + `UNIQUE(ip_hash, granted_day_bucket, slot)` trick is itself
  now obsolete (no D1); the cap is the serializable `freeTier.claimFreeSlot`
  mutation described in the migration banner at the top of this file. The slot is
  claimed before any backend work, and `releaseFreeSlot` compensates on issuance
  failure, so a lost race or transient error rolls back only a bare user row.
- **Bug 5** (per-tier grace), **Bug 10** (tier_history ordering), **Bug 11**
  (cleanupExpired join), **Bug 14** (Remnawave squad clear), all re-confirmed
  CLOSED on the Convex port (see each section).

Made obsolete by the Convex migration (now **MOOT**, see each section): **Bug 6**
(CiviCRM membership→tier matching gone), **Bug 8 / Bug 9** (CiviCRM reconcile cron +
KV locks gone; serialized writes are now serializable mutations), **Bug 13**
(`idempotency_keys` table never ported). **M1** (PRNG), **M2** (cookie separator),
**M4** (admin-auth enumeration) are CLOSED on Convex; **L2** (Authentik
self-provisioning) is MOOT (no OIDC).

**Recently resolved (2026-06 hardening pass):** **M3**: audit writes re-reviewed
(all curated) + the billing webhook now redacts the account-number plaintext from
its stored payload, and (2026-06-09) a per-action payload **allowlist** now enforces
this at a single `writeAuditLog` chokepoint, fail-closed for unregistered actions
(`convex/lib/audit.ts`). **Bug 15**: Outline `accessUrl` made optional + parse-safe
with a clear error (regression test added); full WSS _issuance_ is the only piece
left and it stays blocked on the fork's response contract.

**Still open / deferred on Convex:** **Bug 15 (full WSS issuance only)**: latent
while Outline is disabled (blocked on the fork's real WSS create-key contract, which
is not in this repo); Outline scoring **RTT capture** (the `pickCandidatesForIssue`
latency term is a `0` placeholder), latent while Outline is disabled. Both are gated
on enabling Outline and are intentionally deferred until then.

**Test gaps (mostly closed, 2026-06-09):** the `convex-test` suite covers
auth/free-tier/lifecycle/subscriptions/webhooks/admin-API + the lib units (incl. the
Outline accessUrl path). Now also covered: the **Remnawave** HTTP fns
(`convex/lib/backends/remnawave.test.ts`: issue/get/update/reset/delete/fetch
mapping, status-enum mapping, squad set/clear (Bug 14), device-endpoint degradation,
and the error path not leaking the token or base URL); **S3 storage** mirror logic
(`convex/storage.test.ts`, via an injected `send` seam: provider env parsing,
multi-provider upload + public-URL join, partial + total failure, best-effort
delete); and the **WebAuthn ceremony** gating/security branches
(`convex/webauthn.test.ts`: bootstrap-secret gate + bootstrap lock + TOCTOU
re-check, M4 anti-enumeration, per-IP throttle, challenge replay + unknown
credential). The one remaining gap is the WebAuthn **cryptographic happy-path** (a
genuine attestation/assertion passing `@simplewebauthn` verification, the counter
bump, the session mint), which needs a real or virtual authenticator and belongs in
an e2e browser test, not `convex-test`.

## Security: deferred

### H1. Free-tier rate-limit race: CLOSED (Convex)

> **CLOSED by construction.** See the migration banner at the top: the cap is the
> serializable `freeTier.claimFreeSlot` mutation. The KV-counter TOCTOU described
> below cannot occur in a serializable Convex mutation. The Durable-Object /
> D1-stored-proc options floated here are no longer relevant. Historical text:

**Location** `src/server/services/rate-limit.ts:54-65`, `src/server/services/free-tier.ts:64-95` _(files removed in the Convex migration)_

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
request, sustained abuse is hard. The IP-based cap is also a soft signal:
NAT'd users sharing an IP can hit the cap without being attackers.

---

### M1. PRNG: `Math.random()` for Outline server selection, CLOSED (Convex)

> **CLOSED.** The Convex Outline pick uses a CSPRNG (`crypto.getRandomValues` over
> a `Uint32Array`) in `convex/backends.ts`. Account-number minting and token
> minting also use the CSPRNG (`convex/lib/accountId.ts`, `convex/lib/crypto.ts`).

**Location** `src/server/services/outline-pool.ts:65`, `src/server/lib/retry.ts:26` _(files removed)_

**The issue.** Top-3 server selection and retry jitter use `Math.random()`.
Not security-critical (these aren't selecting secrets) but `Math.random()` is
predictable. Belt-and-braces would be `crypto.getRandomValues()`.

**Why deferred.** Cosmetic; flagged for completeness rather than risk.

---

### M2. Cookie signed-value separator: CLOSED (Convex)

> **CLOSED.** `convex/lib/cookies.ts` ported the format AND the fix: `signValue`
> now `throw`s if the value contains `.` before signing, and `verifySignedValue`
> splits on the last `.`. Session ids are hex-only, so the parse is unambiguous.

**Location** `src/server/lib/cookies.ts:24-36` _(now `convex/lib/cookies.ts`)_

**The issue.** `signValue` joins value and signature with `.`, then
`verifySignedValue` splits on `lastIndexOf('.')`. Session ids from
`randomHex(32)` are hex-only so the split is unambiguous today. Future callers
that pass values containing `.` would tip the parser into incorrect
verification.

**Fix.** Replace the separator with `|` and reject inputs containing it before
signing. Small, contained change; bundled with the next session-related work.

---

### M3. Audit log payload scrubbing: CLOSED (Convex)

> **CLOSED (2026-06-09).** Re-reviewed every audit write in `convex/{adminApi,
account,lifecycle,freeTier}.ts`: each logs a curated, explicit object (or no
> payload), and none dumps a raw request body. The related (worse) issue found
> during the review (the billing webhook persisted the **raw body**, which carries
> the **account-number plaintext**) was fixed: `webhooks.ingest` stores a redacted
> payload (eventId + tierSlug + the 4-digit prefix only), covered by
> `convex/webhooks.test.ts`. The remaining residual is now closed too: a per-action
> payload **allowlist** in `convex/lib/audit.ts` projects every audit payload down
> to an explicit key set, and **all** writes route through the single
> `writeAuditLog` chokepoint (the `audit.record` mutation called from actions, plus
> the in-mutation inserts in lifecycle/freeTier/adminApi that cannot call a
> mutation). An action that is not registered in the allowlist fails closed (its
> payload is dropped, with a non-secret `console.warn` naming the action). Covered
> by `convex/lib/audit.test.ts`.

**Location** `src/server/services/audit.ts:22-33` _(now `convex/audit.ts` + callers in `convex/adminApi.ts`)_

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

### M4. Admin authentication endpoint enables username enumeration: CLOSED (Convex)

> **CLOSED.** `convex/webauthn.ts:authenticateOptions` returns well-formed options
> with an empty `allowCredentials` for an unknown/inactive username (verify then
> fails like any wrong passkey), identical shape + similar timing to the valid
> case, and applies a per-IP throttle (`admin-auth:ip:<ipHash>`, 20/h) via the
> strict `rateLimits.checkAndIncrement`.

**Location** `src/server/routes/api/admin/auth.ts:144-158` _(now `convex/webauthn.ts`)_

**The issue.** `/authenticate/options` returns distinct responses for "username
unknown" (`No such admin`) vs valid username (returns options + credentials
list). An attacker can dictionary-scan to identify valid admin usernames; with
C3 now fixed, the next-step replay is harder but the username leak still
informs targeted social-engineering attacks.

**Fix.** Return an identical response shape for both branches: generate a
dummy challenge with random-but-stable data for unknown usernames so timing and
shape match the valid case. Add KV-backed rate-limit per IP.

**Why deferred.** The admin universe is small (one or two usernames typically)
so the enumeration ceiling is low. Worth fixing alongside the next admin-auth
hardening pass.

---

### L1 / L2. Cookie `timingSafeEqual` length-leak; Authentik auto-provisioning guard: L1 STILL APPLIES (informational) / L2 MOOT

> **L1 STILL APPLIES (informational).** `timingSafeEqual` is ported to
> `convex/lib/crypto.ts`; the signature length is fixed so there's no real leak.
> **L2 is MOOT**: there is no Authentik/OIDC/JWT path and no `bearer-auth`
> auto-provisioning anymore (OIDC was removed). The only programmatic identities
> are `fsv1_` tokens that an admin explicitly minted.

**Location** `src/server/lib/crypto.ts:38`, `src/server/middleware/bearer-auth.ts:82-110` _(bearer-auth removed)_

**Status.** L1 is informational (cookie sig length is fixed so no real leak).
L2 is partially mitigated by H4's audience-required fix that just shipped:
tokens minted by other Authentik clients are now rejected before
auto-provisioning runs. Remaining gap: any user known to Authentik for the
FreeSocks client can still self-provision a local user row by hitting any
endpoint with a valid JWT. Document as accepted behavior for now (FreeSocks
trusts the Authentik member list).

## Bugs: deferred

### Bug 5. `runGraceSweep` ignores per-tier `expirationDaysAfterMembershipLapse`: CLOSED (Convex)

> **CLOSED.** `convex/lifecycle.ts:findDisableTransitions` reads each grace user's
> tier and uses that tier's `expirationDaysAfterMembershipLapse` for the cutoff,
> with no hardcoded 7-day constant.

**Location** `src/server/services/membership-sync.ts:294` _(now `convex/lifecycle.ts`)_

**The issue.** The disable transition was hardcoded to 7 days and ignored each
tier's configured `expirationDaysAfterMembershipLapse`. If an admin set a 14-day
grace on a tier, disable still fired after 7.

**Fix.** Either compute the per-row cutoff using each row's tier's
`expirationDaysAfterMembershipLapse`, or denormalize a `graceEndsAt`
timestamp onto `users` at grace transition time.

**Why deferred.** Only fires when an admin explicitly changes the per-tier
value. Default is 7, which the hardcoded constant matches, so users today are
unaffected. Worth fixing before any tier ships with a non-default grace.

---

### Bug 6. `applyMembership` doesn't disambiguate dual-backend tiers: MOOT (Convex)

> **MOOT.** CiviCRM-driven `applyMembership` / `findForMembership` (membership-type
> → tier matching) is gone. Entitlements are now set via
> `convex/lifecycle.ts:setMembership(userId, tierId, …)` with an **explicit
> tierId**: there is no by-CiviCRM-type tier resolution to disambiguate. (When the
> billing portal/webhook resolves a tier it does so by an explicit `tierSlug`.)

**Location** `src/server/services/membership-sync.ts:121-125` _(removed; CiviCRM gone)_

**The issue.** `findForMembership` is called with no backend filter. The schema
explicitly allows two active tiers per `civicrm_membership_type_id` (one per
backend). The matcher returns the first row that satisfies the status filter.
Order is set by KV-cache enumeration order.

**Fix.** Look up the user's active subscription first; pass `sub.backend` as
the backend filter so a Remnawave-backed user's tier resolution stays in
Remnawave space, not silently flipping to Outline.

**Why deferred.** Only fires once both backends have peer tiers configured for
the same CiviCRM type. Outline isn't enabled in beta yet, so the bug is latent.
Pair with the first Outline-paid-tier rollout.

---

### Bug 8. `propagateTierChanges` has no overlap lock: MOOT (Convex)

> **MOOT.** Tier propagation is no longer a cron-chained batch with a shared
> cursor. `convex/lifecycle.ts:setMembership` schedules a per-user
> `pushTierToBackend` via `ctx.scheduler.runAfter(0, …)` on each tier change:
> event-driven, one user at a time. There is no overlapping cron run and no KV
> lock to race; the PATCH is idempotent.

**Location** `src/server/jobs/propagate-tier-change.ts` + `src/server/jobs/dispatcher.ts:24,54` _(removed)_

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

### Bug 9. Membership-sync `tryAcquireLock` is racey and lock TTL is short: MOOT (Convex)

> **MOOT.** The CiviCRM reconcile cron and its KV soft-lock are gone. Where the
> Convex code does need a serialized check-then-write (the free-tier cap, the
> rate-limit counter, uniqueness checks), it uses a serializable mutation, which
> is atomic by construction, with no get/put-CAS workaround needed.

**Location** `src/server/services/membership-sync.ts:351-360` _(removed; CiviCRM gone)_

**The issue.** `kv.get` then `kv.put` is not atomic: two simultaneous cron
firings both see no lock and both acquire. Lock TTL is 60s but the reconcile
paginates up to 5000 memberships @ 200/page; on slow CiviCRM the lock can
expire mid-run.

**Fix.** Conditional-put via KV metadata version (CAS), or a D1-backed lease
table with `INSERT ... WHERE NOT EXISTS`. Raise TTL to cover worst-case
runtime.

**Why deferred.** Same path as Bug 8: both want a real lock primitive. Fold
together.

---

### Bug 10. `tier_history` written before `users.tierId` update: CLOSED (Convex)

> **CLOSED.** `convex/lifecycle.ts:setMembership` patches the user's tier FIRST,
> then inserts the `tierHistory` row + audit, and it's all one serializable
> mutation, so a partial-failure split between the two writes can't happen (the
> whole mutation commits or aborts atomically).

**Location** `src/server/services/membership-sync.ts:190-207` _(now `convex/lifecycle.ts`)_

**The issue.** If the `users` update fails after the `tier_history` insert
succeeds, the history row records a change that didn't happen; retry then
writes a duplicate history row.

**Fix.** Swap order (update first, then insert history) or wrap in a D1
transaction.

**Why deferred.** Very rare: requires a partial failure between two
back-to-back D1 writes on the same connection. Real but low probability.

---

### Bug 11. `free-tier.cleanupExpired` join is latent-buggy: CLOSED (Convex)

> **CLOSED.** `convex/lifecycle.ts:findExpiredFree` selects a single active sub per
> user (`subs.find((s) => s.state === 'active')`) rather than iterating every sub
> row, so the multiple-sub-row over-delete can't occur.

**Location** `src/server/services/free-tier.ts:233-265` _(now `convex/lifecycle.ts`)_

**The issue.** `innerJoin(subscriptions, ...)` has no `subscriptions.state`
filter; if a user has multiple sub rows (e.g. after a backend switch on a paid
tier), each row produces a separate iteration and cleanup tries to delete each.
Today only free-tier users hit this path and they only have one sub row by
design, so the bug is latent.

**Fix.** Add `eq(subscriptions.state, 'active')` to the join condition.

**Why deferred.** Latent: not exploitable in current flows. One-liner to fix
on next sweep through the cleanup path.

---

### Bug 13. Dead schema: `idempotency_keys` table, MOOT (Convex)

> **MOOT.** The Convex schema (`convex/schema.ts`) has no `idempotency_keys` table.
> (Webhook idempotency is handled by the `webhookEvents` dedupe table, which is
> actively read/written by `convex/webhooks.ts`.)

**Location** `src/server/db/schema.ts:319-334` _(removed)_

**The issue.** Table exists but no code reads or writes it. If a future path
populates it without removing the unused indexes, write cost is higher than
needed.

**Fix.** Either remove the table in a future migration, or use it for the
intended purpose (the design was for per-POST idempotency on subscription
issuance; see plan doc).

**Why deferred.** Cosmetic. Doesn't affect runtime.

---

### Bug 14. `RemnawaveBackend.updateUser` cannot clear a squad: CLOSED (Convex)

> **CLOSED.** `convex/lib/backends/remnawave.ts` (the `remnawaveUpdateUser` PATCH)
> distinguishes "field absent" (skip) from "field present and null/''" (clears via
> `activeInternalSquads: []`); a value sets it.

**Location** `src/server/providers/remnawave/backend.ts:90-92` _(now `convex/lib/backends/remnawave.ts`)_

**The issue.** `patch.remnawaveSquadUuid === null` skips the squad assignment
entirely; admins can't unset a squad once configured.

**Fix.** Distinguish "field not present" (skip) from "field present and null"
(clear). The current shape conflates the two.

**Why deferred.** Edge case: admins rarely null out squad uuids. Pick up when
the tier editor surfaces squad management directly.

---

### Bug 15. Outline WSS keys assume a required `accessUrl` (found 2026-05-29): MITIGATED (Convex)

> **MITIGATED, full WSS support still blocked.** `OutlineAccessKey.accessUrl` is
> now `z.string().optional()`, so a WSS/`ssconf://` key lacking an inline `ss://`
> URL no longer fails the Zod parse; and `outlineIssue` / `outlineFetchContent`
> throw a clear "WSS/dynamic-config issuance is not supported yet" error instead of
> a confusing generic schema-mismatch (regression test: `convex/lib/backends/outline.test.ts`).
> What's still NOT done: actually issuing a WSS key (deriving the subscription URL
> from the fork's dynamic-config / `ssconf://` output), which remains blocked on the
> FreeSocks Outline fork's real WSS create-key response shape (not in this repo).
> Latent anyway (Outline disabled by default, `websocketEnabled` off). **Resolve the
> full path before registering + routing to a WSS-enabled Outline server.**

**Location** `src/server/providers/outline/types.ts:22` etc. _(now `convex/lib/backends/outline.ts`)_

**The issue.** `OutlineAccessKey.accessUrl` is a required `z.string()`. `OutlineBackend.issueUser` sends a `websocket` body when `server.websocketEnabled` is set, then reads `created.accessUrl` unconditionally as the subscription URL. The FreeSocks Outline fork's WSS-wrapped (dynamic-config / `ssconf://`) keys are expected NOT to carry an inline `ss://` `accessUrl`: the YAML config is uploaded to S3 and served as an `ssconf://` URL (see the `0005_outline_servers.sql` migration comment). A WSS key response without `accessUrl` fails the Zod parse in `createKey` and throws a generic "Outline schema mismatch" before issuance can complete.

**Fix.** Obtain the FreeSocks Outline fork's actual WSS create-key response contract, then branch the response handling: when WSS is enabled, accept a key without `accessUrl` and derive the subscription URL from the dynamic-config / `ssconf://` output (mirroring it to S3 as the existing flow intends) instead of from `accessUrl`. Likely makes `accessUrl` optional with a WSS-specific code path. Add a test for a WSS key lacking `accessUrl`. The existing `outline-client` test only mocks a WSS response that _does_ include it.

**Why deferred.** Dormant in the default config: Outline is disabled (`outline.enabled=false`), the default backend is Remnawave, all seeded tiers are Remnawave, and `websocket_enabled` defaults to `0`, so this path is unreachable without three explicit admin opt-ins. It also can't be fixed correctly without the fork's real response shape, which isn't in this repo. **Must be resolved before any WSS-enabled Outline server is registered and routed to.**
