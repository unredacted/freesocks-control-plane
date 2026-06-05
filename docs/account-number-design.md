# Design: Self-service account-number authentication

Every issued user (free-tier or member) gets a unique, opaque account number
they can use to sign back into their account without email, OIDC, or any
external identity provider. If they later upgrade to a paid membership, the same
account links to their CiviCRM/Authentik identity — the subscription history is
preserved across the transition.

> **Implementation status (2026-06).** The **foundation is built and shipping
> dark** behind the `account_id.enabled` app setting (default `false`):
>
> - **S1 Contracts** ✅ — `AccountLoginRequest`, `AccountIdRevealResponse`,
>   `SubscriptionResponse.{accountId,accountIdAvailable}`, `AuthMeResponse.member.identitySource`.
> - **S2 Migration** ✅ — `0011_account_identifiers.sql` + Drizzle schema columns/indexes.
> - **S3 Service** ✅ — `AccountIdService` (mint/hash/verify/rotate/normalize), DI-registered, unit-tested.
> - **S11 Feature flag** ✅ — `account_id.enabled` in AppSettings (admin-toggleable).
>
> **Not yet wired (no behavior change yet):** **§4** mint-at-issuance + return the
> number in `SubscriptionResponse`; **S4** `POST /api/v1/auth/account-login` route
> (Turnstile + rate-limit + constant-time); **S5** session integration
> (`MemberSession.source: 'account-id'`, `/me.identitySource`); **S6** OIDC
> link / user+admin rotate / admin merge; **S7–S9** all SPA UI (reveal panel,
> login tab, rotate dialog); **S10** admin prefix search + rotate button; **S12**
> backfill script + `docs/account-number.md` runbook; **S13** e2e + security tests.
> The building blocks (service, flag, contracts, columns) exist and are tested, so
> the next pass is pure wiring + UI on a green base. Estimated remaining ≈ 30h.

## 1. Identifier format

**Choice: 16 decimal digits, displayed as four groups of four** (e.g. `1234 5678
9012 3456`).

- **Entropy**: 16 decimal digits ≈ 53.15 bits. With 100M issued users, collision
  odds via birthday-bound ≈ 5×10⁻¹⁰. Sufficient.
- **Alphabet**: digits only.
  - Base32 / Crockford-32 (~10–13 chars for ~50 bits) is shorter but mixes
    letters/digits — confusable on paper or over phone dictation. Rejected.
  - Base58 / hex — same readability concern. Rejected.
  - 16 digits: keyboard-easy, dictation-easy, copy-paste-easy, language-neutral.
- **Stored format**: digits only, no spaces (`1234567890123456`). Server
  normalizes input by stripping `\s` and `-` before lookup.
- **Storage strategy**: store a SHA-256 hash of the canonical form in
  `users.account_id_hash`. Also store a 4-digit plaintext prefix in
  `users.account_id_prefix` so admins can recognize/search numbers without
  exposing them. Plaintext is never persisted server-side after issuance.
- **Comparison on login**: hash the submitted (normalized) input with the same
  scheme, look up `users.account_id_hash`. Single indexed lookup; no
  enumeration.

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

1. Generate a fresh 16-digit identifier inside `FreeTierService.issueOrReissue`.
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

**OIDC members at first login**: auto-mint an account number in the OIDC
callback (`upsertMemberUser`). Add a one-time banner to `/account`
("Your account number is X — save it") that the user must dismiss. This gives
every member a second login path in case Authentik is unavailable, and supports
the link-flow downward direction (see §6).

## 5. Account page changes

`/account` (unauthenticated): two tabs.

- **Sign in with Unredacted** (existing OIDC button)
- **Sign in with account number** (new form — number input + Turnstile)

Submit posts to `/api/v1/auth/account-login`. On success: invalidate
`queryKeys.me` and `queryKeys.account`. After login the route renders
identically to the existing OIDC-session view.

## 6. Member-link flow

Three transitions, all converging on one user row:

### (a) Account-number session is current; user starts OIDC

`/api/auth/login` already takes a `returnTo`. Pass through the current
`fs_session` (account-id-sourced) intact during the OIDC dance. In the
callback, before `upsertMemberUser`, check `c.var.member`. If present AND
`member.authentikSubject` is null AND the incoming OIDC subject doesn't
already map to a different user, mutate the existing user row:

```
set authentik_subject = verified.sub
set civicrm_contact_id = contact?.id
set email = userInfo.email
```

Audit-log `account.link.oidc`. Same user row, history preserved.

### (b) OIDC user without anonymous origin wants an account number

Their user row already has `account_id_hash` (set by §4 above). The number is
hashed and we cannot re-display it. Add a UI affordance on `/account`
("Reveal account number") that **rotates**: button → new identifier minted,
one-time reveal, old hash overwritten, audit-logged. Document rotation as the
only path to revisit your number.

### (c) User has two anonymous accounts to consolidate

Manual support flow. Add admin-side `POST /api/v1/admin/users/:id/merge` that
takes a source user id and target user id: copies tier history rows pointing
to source over to target, tombstones source's subscription (24h grace),
nullifies source's `account_id_hash`, sets `status='deleted'`, audit-logs
`user.merge`. Admin-only — too many ways for a user to merge into someone
else's account if exposed end-user-side.

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
- **Forgot my number**: irrecoverable by design. UX states this once at
  issuance ("You won't be able to recover this. Save it now."). **Do NOT** offer
  email-based recovery, even for paid members — adds an email-account-takeover
  dependency the system specifically avoids. Paid members who lose access
  re-auth via OIDC and rotate.
- **Account takeover**: if a number leaks, the legitimate user logs in via OIDC
  (members) or starts fresh (free users) and rotates via
  `POST /api/v1/account/account-id/rotate`. Document recovery plainly at
  issuance: for free-tier users, the account is gone; for members, OIDC is the
  recovery path.
- **2FA / device association**: future work. Note in `docs/account-id.md` as
  out of scope for v1.

## 8. Audit and admin

- New audit actions: `account.login.account_id`, `account.id.issue`,
  `account.id.rotate`, `account.link.oidc`, `user.merge`.
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

- Email-based recovery / "forgot my number" reset
- SMS or phone-based auth
- Vanity / custom identifiers
- Multiple identifiers per user (one canonical; rotation replaces)
- Identifier-bound device association / 2FA
- User-facing self-merge of two anonymous accounts
- Cross-deployment portability of identifiers

## 10. Integration with existing flows

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
- **Feature flag**: add `app_settings.account_id_enabled: boolean` (default
  `false` in migration; admin toggles via existing AppSettings CMS). Both the
  login route and the SPA "Sign in with account number" tab key off this flag.
  Lets the feature ship dark, then enable in staging, then prod.

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
