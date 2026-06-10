/**
 * Member auth (P6): account-number login + rotate. The ONLY member identity
 * path (account number only; no password, no third-party login). Ported from
 * the account-number design (docs/account-number-design.md §3/§7) faithfully:
 *
 *  - A captcha (self-hosted Cap) gates every attempt (blocks headless brute force).
 *  - Per-prefix (30/day) + per-IP (10/h) STRICT rate limits.
 *  - The submitted number is ALWAYS hashed (even on a rate-limit reject), and
 *    every failure is padded to a ~300ms floor, so timing never reveals
 *    whether a number exists, is malformed, or is rate-limited.
 *  - One generic failure shape (no existence oracle): unknown / disabled /
 *    rate-limited all return `{ ok:false, reason:'invalid' }`.
 *  - The plaintext number is never logged and never put in an audit payload.
 *
 * These are internalActions: the HTTP layer (convex/http.ts) resolves the IP,
 * calls them, and translates the result into a Set-Cookie response. Cookie
 * signing happens here (the action has the signing key + Web Crypto); the HTTP
 * layer only decides the `Secure` flag from the environment.
 */
import { internalAction } from './_generated/server';
import { api, internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { hashAccountId, isValidAccountId, normalizeAccountId } from './lib/accountId';
import { hmacSha256Hex, randomHex } from './lib/crypto';
import { signValue } from './lib/cookies';
import { verifyCaptcha } from './lib/captcha';

// 30 days, matches the old fs_session cookie. Exported so freeTier.createFreeAccount
// (account creation also establishes a member session) uses the same TTL.
export const MEMBER_TTL_MS = 30 * 86_400_000;
const FAILURE_FLOOR_MS = 300;

type LoginResult =
  | { ok: true; signedCookieValue: string; maxAgeSec: number; userId: Id<'users'> }
  | { ok: false; reason: 'captcha' | 'invalid' };

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Account-number login. Returns the SIGNED `fs_session` cookie value on success
 * (the HTTP layer wraps it in a Set-Cookie with the right Secure flag), or a
 * generic failure. Constant-time on all account-validity failures.
 */
export const accountLogin = internalAction({
  args: {
    accountId: v.string(),
    captchaToken: v.string(),
    ip: v.optional(v.string()),
    // PoP (Phase 2): the client's session public key, bound to this session so
    // the cookie alone is not sufficient afterward. Absent for clients without
    // the signing worker (legacy fallback).
    popPublicKey: v.optional(v.string()),
  },
  handler: async (ctx, { accountId, captchaToken, ip, popPublicKey }): Promise<LoginResult> => {
    const start = Date.now();
    const failInvalid = async (): Promise<LoginResult> => {
      const elapsed = Date.now() - start;
      if (elapsed < FAILURE_FLOOR_MS) await sleep(FAILURE_FLOOR_MS - elapsed);
      return { ok: false, reason: 'invalid' };
    };

    // 1. Captcha (self-hosted Cap), independent of account validity, so a fast
    //    distinct return here is fine (it's not an enumeration oracle).
    const cap = await verifyCaptcha(captchaToken);
    if (!cap.success) return { ok: false, reason: 'captcha' };

    // 2. Normalize + ALWAYS hash (keeps timing constant regardless of validity).
    const normalized = normalizeAccountId(accountId);
    const validFormat = isValidAccountId(normalized);
    const hash = await hashAccountId(normalized);
    const prefix = normalized.slice(0, 4);

    // 3. Strict per-IP + per-(prefix,IP) limits (admin-tunable policies; W2). A
    //    denial is folded into the generic invalid result (identical body) so it
    //    can't be used to probe.
    //
    //    P2: the prefix limit is scoped per-IP (not global-per-prefix), so it
    //    can't be abused as a cross-user lockout lever — one attacker can no
    //    longer exhaust the daily budget for everyone sharing a 4-digit prefix.
    //    Now that A1 makes the per-IP bucket meaningful, per-IP is the primary
    //    online-guessing guard and the per-(prefix,IP) limit is the backstop.
    let ipHash: string | null = null;
    let ipDenied = false;
    if (ip) {
      const salt = process.env.IP_HASH_SALT;
      if (!salt) throw new Error('IP_HASH_SALT must be set');
      ipHash = await hmacSha256Hex(salt, ip);
      const ipRl = await ctx.runMutation(internal.rateLimits.enforce, {
        policyKey: 'account-login.ip',
        subject: ipHash,
      });
      ipDenied = !ipRl.allowed;
    }
    const prefixRl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'account-login.prefix',
      subject: ipHash ? `${prefix}:${ipHash}` : prefix,
    });

    if (!validFormat || !prefixRl.allowed || ipDenied) return failInvalid();

    // 4. Single indexed lookup; the query returns null for unknown OR
    //    disabled/deleted owners (no oracle distinction).
    const user = await ctx.runQuery(api.users.byAccountIdHash, { accountIdHash: hash });
    if (!user) return failInvalid();

    // 5. Mint a member session + signed cookie.
    const sid = randomHex(32);
    await ctx.runMutation(internal.sessions.create, {
      sid,
      kind: 'member',
      userId: user._id,
      ttlMs: MEMBER_TTL_MS,
      ...(popPublicKey ? { popPublicKey } : {}),
    });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: user._id,
      action: 'account.login.account_id',
      targetType: 'user',
      targetId: user._id,
    });
    const signingKey = process.env.SESSION_SIGNING_KEY;
    if (!signingKey) throw new Error('SESSION_SIGNING_KEY must be set');
    const signedCookieValue = await signValue(sid, signingKey);
    return { ok: true, signedCookieValue, maxAgeSec: MEMBER_TTL_MS / 1000, userId: user._id };
  },
});

/**
 * Rotate the caller's account number: mint a new one (revealed once), overwrite
 * the old hash. The HTTP layer authenticates the member session and passes the
 * userId. The old number stops working immediately. Audited (never the number).
 */
export const rotateAccountId = internalAction({
  args: { userId: v.id('users'), requestId: v.optional(v.string()) },
  handler: async (ctx, { userId, requestId }): Promise<{ accountId: string }> => {
    const minted = await ctx.runAction(internal.accountId.mintForUser, { userId, rotate: true });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'account.id.rotate',
      targetType: 'user',
      targetId: userId,
      requestId,
    });
    return { accountId: minted.accountId };
  },
});
