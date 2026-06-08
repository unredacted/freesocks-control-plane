# Design: Self-service account-number authentication

Every issued user gets a unique, opaque account number they use to sign back into
their account without any external identity provider or stored contact details. It
is the **only** member credential.

> **Implementation status (2026-06).** Account-number auth is now **THE member
> identity and is LIVE** on the Convex backend. The format / entropy / storage /
> rate-limit / timing design below is what got built. Implemented:
>
> - **Login** — `POST /api/v1/auth/account-login` (`convex/http.ts` →
>   `convex/auth.ts:accountLogin`): Turnstile-gated, strict per-prefix (30/day) +
>   per-IP (10/h) rate limits, always-hash + ~300ms failure floor (constant-time),
>   one generic failure shape (no existence oracle) → signed `fs_session` cookie.
> - **Mint-at-issuance + reveal-once** — free-tier issuance mints a number
>   (`convex/accountId.ts:mintForUser`, CSPRNG) and returns it once in the
>   `POST /api/v1/subscription` response (`accountId` on first issue;
>   `accountIdAvailable:false` on a same-IP/day reissue). Only the SHA-256 hash +
>   4-digit prefix are persisted (`users.accountIdHash` / `accountIdPrefix`).
> - **Rotate** — `POST /api/v1/account/account-id/rotate`
>   (`convex/auth.ts:rotateAccountId`): new number revealed once, old hash
>   overwritten, audited.
> - **Admin prefix search** — `GET /api/v1/admin/users?q=` matches the stored
>   4-digit prefix (`convex/adminApi.ts`); full-number lookup is never permitted.
> - **SPA** — reveal-once panel on `/get-key`, account-number sign-in on `/login`,
>   rotate dialog on `/account`.
>
> **NOT APPLICABLE — OIDC was removed.** The original design assumed an Authentik
> OIDC / CiviCRM identity that an account number would _link_ to. That stack is
> gone: there is no OIDC, no CiviCRM, no JWT path. **§6 (member-link flow) in its
> entirety, and every OIDC/CiviCRM/JWT mention in §4, §5, §8, §10, and §11 below,
> do not apply.** Account numbers stand alone; there is no link/merge and no second
> recovery path (see §7 — "forgot my number" is irrecoverable by design). The
> entitlement source is now the billing webhook seam (`POST /api/webhooks/billing`),
> not a linked external identity.
>
> Below, sections describing the (removed) OIDC/CiviCRM/Drizzle-migration mechanics
> are kept for historical context only — the design intent that survived is the
> format, storage, rate-limit, timing, and security content.

## 1. Identifier format

> **Current values (supersede the historical 16-digit/SHA-256 numbers below):**
> **32 decimal digits** and a **peppered keyed hash** — see the bolded items in
> this section. The rest of the section's rationale is unchanged.

**Choice: 32 decimal digits, displayed as eight groups of four** (e.g.
`1234 5678 9012 3456 7890 1234 5678 9012`).

- **Entropy**: 32 decimal digits ≈ **106 bits** (10³²). It's the member's _sole_
  login credential, so it's sized to be unguessable even against offline
  brute-force of a leaked hash column — not just online guessing (which Turnstile
  - the rate limits already make infeasible). Birthday-collision odds at any
    realistic user count are negligible; the uniqueness check retries on the
    (astronomically rare) clash.
- **Alphabet**: digits only.
  - Base32 / Crockford-32 mixes letters/digits — confusable on paper or over
    phone dictation. Rejected.
  - Base58 / hex — same readability concern. Rejected.
  - Decimal: keyboard-easy, dictation-easy, copy-paste-easy, language-neutral.
    The number is shown once with copy + `.txt` download, so 32 digits is fine to save.
- **Stored format**: digits only, no spaces. Server normalizes input by
  stripping `\s` and `-` before hashing.
- **Storage strategy**: store **`HMAC-SHA256(ACCOUNT_ID_PEPPER, canonical)`** in
  `users.accountIdHash` — a _keyed_ hash, not a bare digest. The pepper is a
  required deployment secret (env, never in the DB), so a DB-only leak can't be
  brute-forced offline without it. Also store a 4-digit plaintext prefix in
  `users.accountIdPrefix` for admin search. Plaintext is never persisted.
- **Comparison on login**: HMAC the submitted (normalized) input with the same
  pepper, look up `accountIdHash` via the `by_account_id_hash` index. Still a
  single indexed lookup (the hash is deterministic); no enumeration.

## 2. Database changes

New migration `0011_account_identifiers.sql` (the originally-planned `0008`
collided with the shipped `0008_backend_labels_xray.sql`; `0009`/`0010` are also
taken, so this lands as `0011`):

```sql
ALTER TABLE users ADD COLUMN account_id_hash text;
ALTER TABLE users ADD COLUMN account_id_prefix text;
ALTER TABLE users ADD COLUMN account_id_created_at integer;
ALTER TABLE users ADD COLUMN account_id_rotated_at integer;
CREATE UNIQUE INDEX idx_users_account_id_hash
  ON users(account_id_hash) WHERE account_id_hash IS NOT NULL;
CREATE INDEX idx_users_account_id_prefix
  ON users(account_id_prefix) WHERE account_id_prefix IS NOT NULL;
```

Nullable on existing rows (backfill optional, see §11). One identifier per user
— lifecycle tied to the user row.

## 3. Login route

`POST /api/v1/auth/account-login` (new file `src/server/routes/api/auth-account.ts`,
mounted alongside `/api/auth/*`).

**Request**: `{ accountId: string, turnstileToken: string }`. Turnstile required
on every attempt — the same widget that gates free-tier issuance. Prevents
headless brute-force.

**Response 200**: `{ ok: true }` — sets the `fs_session` cookie identical to OIDC
callback. SPA redirects to `/account`.

**Response 401**: `{ error: { code: 'auth.invalid_account_id' } }` — generic
message, no oracle. ("does this number exist?" vs. "wrong number" would leak
existence.)

**Session shape**: reuse the existing `MemberSession` interface and `fs_session`
cookie. Extend the `source` discriminator from `'cookie' | 'jwt'` to
`'cookie' | 'jwt' | 'account-id'`. `authentikSubject` becomes nullable (its only
purpose is matching JWTs back to users — irrelevant for the account-id path).
`contactId` is null for unlinked anonymous accounts. Same KV key prefix
(`session:member:{sid}`), same 30-day TTL — downstream `requireMember`,
`requireScope`, and `/api/v1/account` keep working unchanged.

**Rate limit**:

- Per-IP: 10 attempts/hour, then 1/hour with exponential backoff up to 24h.
- Per-prefix (the 4-digit prefix from the submitted number): 30 attempts/day
  across all IPs. Per-full-identifier limiting is impossible without storing
  plaintext.
- Counter in KV (`rl:account-login:ip:{ipHash}:{hour}`); D1 backstop is
  unnecessary because failed logins don't issue resources.

**Timing**: always hash the submitted input even on rate-limit reject so total
time is constant regardless of validity. Treat unknown identifiers and
rate-limited identifiers with identical response body. Add a constant ~300ms
artificial floor on failures.

## 4. Issuance flow changes

`POST /api/v1/subscription` (anonymous path in `free-tier.ts`):

1. Generate a fresh 32-digit identifier inside the free-tier issuance flow.
   Use `crypto.getRandomValues` over `Uint8Array(8)`; reduce each byte mod-10
   with rejection sampling to avoid modulo bias.
2. Hash, store in `users.account_id_hash`; store the prefix in
   `users.account_id_prefix`. On the (vanishingly rare) collision, retry once.
3. Add `accountId` (plaintext, one-time) to `SubscriptionResponse`. Update
   `src/shared/contracts/subscription.ts` accordingly.
4. **Reissue path** (same-IP-same-day): do NOT return a new account number.
   The original was shown once; we don't surface a new one because the original
   is still valid. Add `accountIdAvailable: false` flag so the SPA can skip the
   reveal panel.

`SubscriptionHero` gains a prominent, dismissible "Save this account number"
panel ABOVE the URL — large monospaced four-group display, copy button,
downloadable `.txt` option, single-checkbox "I've saved it" gate before the
panel collapses. The panel only appears on first reveal; refreshing the page
does NOT reshow it (SPA holds it in volatile state only).

**OIDC members at first login** _(NOT APPLICABLE — OIDC removed)_: this
subsection assumed an Authentik callback that minted a number as a second login
path. There is no OIDC callback; every user gets a number at key issuance
instead, and it is the only path.

## 5. Sign-in page

The sign-in page (`/login`) has a single account-number form (number input plus
Turnstile) that posts to `/api/v1/auth/account-login`. On success it invalidates
`queryKeys.me` and `queryKeys.account` and renders the member view.

## 6. Member-link flow — not applicable (OIDC removed)

There is no external identity to link to and no admin merge flow. Account numbers
stand alone. Rotation (`POST /api/v1/account/account-id/rotate`) is the only
credential-management operation, and it is the only way to revisit a number after
its one-time reveal. An earlier draft described linking an account-number session
to an external identity and an admin merge of two anonymous accounts; neither was
built, and neither is planned.

## 7. Security

- **Brute-force**: with 10¹⁶ space and 10 attempts/IP/hour, finding one valid
  number across 100M issued requires ~10⁹ hours per IP. Per-prefix cap further
  bounds chosen-prefix attacks. Combined with Turnstile, infeasible.
- **Timing attacks**: see §3 — constant-time response and `timingSafeEqual`
  string compare (already in `lib/crypto.ts`).
- **Exposure paths**: never log the submitted identifier — only log the prefix
  and the request id. Never include it in audit `payload`. Error messages refer
  to "the submitted credential". The plaintext value lives in one place only:
  the response to the issuing call, in TLS-protected transport.
- **Forgot my number**: irrecoverable by design. The UI states this once at
  issuance ("You won't be able to recover this. Save it now."). Do NOT add an
  out-of-band recovery channel: it would reintroduce the account-takeover
  dependency the system avoids. There is no second recovery path.
- **Account takeover**: if a number leaks, the legitimate user (while still
  signed in) rotates via `POST /api/v1/account/account-id/rotate`, which
  immediately invalidates the old number. If they've already lost access, the
  account is unrecoverable by design. _(The original OIDC recovery path is gone.)_
- **2FA / device association**: future work. Note in `docs/account-id.md` as
  out of scope for v1.

## 8. Audit and admin

- Audit actions: `account.login.account_id`, `account.id.issue`,
  `account.id.rotate`.
- Admin search: `GET /api/v1/admin/users?accountIdPrefix=1234` — prefix match
  against `users.account_id_prefix`. Never permit full-number lookup (no way to
  verify without rehash, and the lookup itself becomes an enumeration oracle).
- Admin-initiated rotation:
  `POST /api/v1/admin/users/:id/account-id/rotate` (scope `admin:users`). Mints
  a new number, returns it in the response one-time, audit-logs. Admin must
  securely relay the new number to the user out-of-band — the design does NOT
  include in-app messaging to users.
- Bulk export/import: deferred. If needed later, only hashes and prefixes are
  exportable; never plaintext.

## 9. Out of scope (v1)

- Out-of-band account recovery / "forgot my number" reset
- SMS or phone-based auth
- Vanity / custom identifiers
- Multiple identifiers per user (one canonical; rotation replaces)
- Identifier-bound device association / 2FA
- User-facing self-merge of two anonymous accounts
- Cross-deployment portability of identifiers

## 10. Integration with existing flows

> **Mostly NOT APPLICABLE — OIDC/JWT removed.** There is no `bearer-auth`
> middleware, no OIDC cookie, and no JWT path. Identity is resolved per-route in
> `convex/lib/http.ts` (`resolveMember` = the `fs_session` cookie OR an `fsv1_`
> token with `subjectType:'user'`). The account-number session uses the same
> `fs_session` cookie the rest of the member surface reads, so `/api/v1/account`,
> `/api/v1/me`, etc. work unchanged. `fsv1_` tokens (service or user) remain the
> programmatic path. The OIDC/JWT-specific points below are historical.

- `bearer-auth.ts` is untouched. Account-number auth is cookie-only at v1;
  mobile clients use existing OIDC/JWT paths. (If mobile-without-OIDC becomes a
  requirement, add `POST /api/v1/auth/account-login` returning a bearer token
  issued from `api_tokens` scoped to `subject_type='user'` — phase-2 addition.)
- `c.var.member` is populated identically by all three entry paths (OIDC
  cookie, JWT, account-id cookie). The `source` discriminator lets downstream
  code differentiate when needed (e.g. `/me`).
- `/api/v1/me` (currently `AuthMeResponse` from `auth.ts`): extend the response
  with `member.identitySource: 'oidc' | 'account-id'`. The SPA uses this to
  decide whether to show "Sign out of Unredacted" vs. "Sign out of this
  device" and whether to offer the link-to-membership CTA.
- OIDC auto-provisioning in `bearer-auth.ts` (lines 78–110): when an unknown
  Authentik subject arrives, the JWT path mints a fresh user. No account-id is
  created there — that path is web-cookie-only. Account-id minting happens in
  `/api/auth/callback` and `free-tier.ts`. Existing JWT-provisioned mobile
  users won't have an account-id until they next visit the web SPA, at which
  point the OIDC callback path mints one.

## 11. Migration / rollout

> **Largely NOT APPLICABLE on Convex.** The Convex cutover started fresh (no data
> migrated — see `convex-self-hosting.md §6`), so there were no existing users to
> backfill, and there is no OIDC-member population. The schema is `convex/schema.ts`
> (no SQL migration). The `account_id.enabled` flag has been **removed** from
> `SETTINGS_DEFAULTS` — account-number auth is unconditionally the member identity,
> with no flag and no toggle anywhere. The bullets below are historical.

- **Existing anonymous free-tier users**: do NOT backfill. They never saw an
  account number; minting one now and hiding it serves no one. Document as a
  known limitation.
- **Existing OIDC members**: backfill via one-shot script
  `bun run scripts/backfill-account-ids.ts` — for every `users` row with
  `authentik_subject IS NOT NULL` and `account_id_hash IS NULL`, mint
  hash + prefix, set both columns, log to `audit_log` (`account.id.issue` with
  `triggered_by=backfill`). They learn their number via the `/account` reveal
  banner on next sign-in; if they never sign in, the number stays sealed
  (acceptable).
- **Feature flag**: ~~add `app_settings.account_id_enabled`~~ **(Removed.)** The
  feature did not ship dark — account-number auth is unconditionally the only
  member identity on Convex, so there is no flag and no toggle.

## 12. Naming

Three candidates, in preference order:

1. **"Account number"** — concrete, familiar metaphor (bank account,
   frequent-flyer number). Recommended.
2. **"Access code"** — emphasizes the unlock semantics, but suggests
   rotation/expiry which we don't have.
3. **"Account ID"** — accurate but generic; in product copy "ID" reads cold.

Use "account number" consistently in user-facing copy. In code, use `accountId`
for the TS identifier (idiomatic camelCase, matches `userId` etc.); in DB
columns, `account_id_hash` / `account_id_prefix` (matches existing snake_case
convention).

## 13. Estimated work

Phase-staged following existing Phase-4 conventions:

| Stage                                  | Scope                                                                                                                                                                               | Estimate |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| **S1: Contract**                       | Add `AuthAccountLoginRequest`, `AccountIdRevealResponse`, extend `SubscriptionResponse`, `AuthMeResponse`, `AccountResponse`. Shared Zod schemas in `src/shared/contracts/`.        | 2h       |
| **S2: Schema migration**               | `0011_account_identifiers.sql`, Drizzle schema additions, regenerate types.                                                                                                         | 1h       |
| **S3: Service layer**                  | `AccountIdService` with `mint() / hash() / verify() / rotate()`. Wire into `FreeTierService`, `upsertMemberUser`. Unit tests for collision retry, normalization, prefix extraction. | 4h       |
| **S4: Login route**                    | `auth-account.ts`, Turnstile gating, rate-limit keys, constant-time response. Integration tests via Miniflare.                                                                      | 4h       |
| **S5: Session integration**            | Extend `MemberSession.source`, ensure `sessionOAuthMw` no-op for account-id sessions (or split into two middlewares sharing the same cookie key). `/api/v1/me` extension.           | 3h       |
| **S6: Link flow**                      | OIDC callback link logic, rotate route, admin rotate route, audit actions, merge admin route.                                                                                       | 5h       |
| **S7: UI — issuance reveal**           | `SubscriptionHero` "Save this account number" panel; checkbox-gated collapse; copy/download affordances.                                                                            | 4h       |
| **S8: UI — login tab**                 | Tabbed Account page sign-in, account-number form, Turnstile, error states, success redirect.                                                                                        | 4h       |
| **S9: UI — reveal/rotate on /account** | One-time member-reveal banner, rotate dialog with `AlertDialog` confirm.                                                                                                            | 3h       |
| **S10: Admin**                         | Prefix search in admin users list, admin rotate button, audit log entries surfaced.                                                                                                 | 3h       |
| **S11: Feature flag + settings**       | `account_id_enabled` setting in `app-settings.ts`, gate routes and SPA UI.                                                                                                          | 1h       |
| **S12: Backfill script + docs**        | `scripts/backfill-account-ids.ts`, `docs/account-number.md` runbook, README updates.                                                                                                | 3h       |
| **S13: Tests + polish**                | End-to-end integration test (mint → reveal → relogin → /account), security tests (timing, rate-limit), copy review.                                                                 | 4h       |

**Total: ~41 hours** (~5 working days for a focused single developer).

## Key files the implementer will touch

- `src/server/db/schema.ts`
- `src/server/db/migrations/0011_account_identifiers.sql` (new)
- `src/server/services/account-id.ts` (new)
- `src/server/services/free-tier.ts`
- `src/server/routes/api/auth.ts`
- `src/server/routes/api/auth-account.ts` (new)
- `src/server/middleware/sessions.ts`
- `src/server/env.ts`
- `src/shared/contracts/account.ts`
- `src/shared/contracts/subscription.ts`
- `src/shared/contracts/auth.ts`
- `src/client/routes/Account.svelte`
- `src/client/routes/GetKey.svelte`
- `src/client/components/SubscriptionHero.svelte`
