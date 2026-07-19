/**
 * Member auth (P6): account-number login + rotate. The ONLY member identity
 * path (account number only; no password, no third-party login). Ported from
 * the account-number design (docs/account-number-design.md §3/§7) faithfully:
 *
 *  - A captcha (self-hosted Cap) gates every attempt (blocks headless brute force).
 *  - STRICT rate limits: per-IP (10/h) at the HTTP layer BEFORE the captcha
 *    verify (convex/http.ts, so floods can't drive Cap QPS) + per-(prefix,IP)
 *    (30/day) here as the account-correlated backstop.
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
import { internal } from './_generated/api';
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
  | {
      ok: true;
      signedCookieValue: string;
      maxAgeSec: number;
      userId: Id<'users'>;
      /** Public per-session token, returned in the response body (only when PoP-bound). */
      popSessionToken?: string;
      /** True when this login auto-downgraded a lapsed member to free (Review #4),
       *  so the client can show a one-time "your membership expired" banner. */
      lapsedDowngrade?: boolean;
    }
  | { ok: false; reason: 'captcha' | 'invalid' | 'config' };

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
    /** The PoP algorithm ('EdDSA' | 'ES256') for popPublicKey; stored on the session. */
    popAlg: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { accountId, captchaToken, ip, popPublicKey, popAlg },
  ): Promise<LoginResult> => {
    const start = Date.now();
    const failInvalid = async (): Promise<LoginResult> => {
      const elapsed = Date.now() - start;
      if (elapsed < FAILURE_FLOOR_MS) await sleep(FAILURE_FLOOR_MS - elapsed);
      return { ok: false, reason: 'invalid' };
    };

    // 1. Captcha (self-hosted Cap), independent of account validity, so a fast
    //    distinct return here is fine (it's not an enumeration oracle). An
    //    unconfigured Cap returns a distinct 'config' reason (→ 503 at the HTTP
    //    layer), so a misconfig is debuggable rather than a generic 403 captcha
    //    failure — mirroring the account-create route. (Review #12.)
    const cap = await verifyCaptcha(captchaToken);
    if (!cap.configured) return { ok: false, reason: 'config' };
    if (!cap.success) return { ok: false, reason: 'captcha' };

    // 2. Normalize + ALWAYS hash (keeps timing constant regardless of validity).
    const normalized = normalizeAccountId(accountId);
    const validFormat = isValidAccountId(normalized);
    const hash = await hashAccountId(normalized);
    const prefix = normalized.slice(0, 4);

    // 3. Per-(prefix,IP) backstop limit (admin-tunable policy; W2). A denial is
    //    folded into the generic invalid result (identical body) so it can't be
    //    used to probe — it MUST stay inside this action because the bucket is
    //    account-correlated (keyed on the submitted prefix).
    //
    //    The per-IP primary guard ('account-login.ip') moved to the HTTP layer
    //    (convex/http.ts), BEFORE the captcha verify, so a login flood can't
    //    drive Cap siteverify QPS. Its 429 is not an oracle: the bucket depends
    //    only on the requester's own IP, like account-create's.
    //
    //    P2: the prefix limit is scoped per-IP (not global-per-prefix), so it
    //    can't be abused as a cross-user lockout lever — one attacker can no
    //    longer exhaust the daily budget for everyone sharing a 4-digit prefix.
    //    The IP is REQUIRED (Review B-F7): the HTTP layer fails closed when it
    //    can't resolve one; if a future caller ever passes none we must throw
    //    rather than silently degrade to the global-per-prefix bucket P2 killed.
    if (!ip) throw new Error('accountLogin requires a resolved client IP');
    const salt = process.env.IP_HASH_SALT;
    if (!salt) throw new Error('IP_HASH_SALT must be set');
    const ipHash = await hmacSha256Hex(salt, ip);
    const prefixRl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'account-login.prefix',
      subject: `${prefix}:${ipHash}`,
    });

    if (!validFormat || !prefixRl.allowed) return failInvalid();

    // 4. Single indexed lookup; the query returns null for unknown or deleted
    //    owners (no oracle distinction). A lapsed member and an INACTIVE free user
    //    ARE returned — both are handled (downgraded / reactivated) just below.
    const user = await ctx.runQuery(internal.users.byAccountIdHash, { accountIdHash: hash });
    if (!user) return failInvalid();

    // 4b. A returning lapsed member (admitted above) is auto-downgraded to the free
    //     tier so they regain a working key at free limits; the account view then
    //     prompts an upgrade. No-op for active/grace/already-free members. (Review #1.)
    //     The flag lets the client show a one-time "membership expired" banner (#4).
    let lapsedDowngrade = false;
    if (user.status === 'disabled' && user.disabledReason === 'membership_lapsed') {
      await ctx.runMutation(internal.lifecycle.downgradeLapsedToFree, { userId: user._id });
      lapsedDowngrade = true;
    }

    // 4c. A returning INACTIVE free user (idle-swept — key reclaimed, row retained)
    //     is reactivated: refreshFreeWindow flips them back to active + restarts the
    //     idle clock, so their next regenerate issues a fresh key. (WS2.)
    if (user.status === 'inactive') {
      await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId: user._id });
    }

    // 5. Mint a member session + signed cookie. When PoP-bound, also mint the
    //    public per-session token (returned in the response body + signed into
    //    every PoP message to bind it to this session).
    const sid = randomHex(32);
    const popSessionToken = popPublicKey ? randomHex(16) : undefined;
    await ctx.runMutation(internal.sessions.create, {
      sid,
      kind: 'member',
      userId: user._id,
      ttlMs: MEMBER_TTL_MS,
      ...(popPublicKey ? { popPublicKey, popAlg, popSessionToken } : {}),
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
    return {
      ok: true,
      signedCookieValue,
      maxAgeSec: MEMBER_TTL_MS / 1000,
      userId: user._id,
      popSessionToken,
      lapsedDowngrade,
    };
  },
});

/**
 * Rotate the caller's account number: mint a new one (revealed once), overwrite
 * the old hash. The HTTP layer authenticates the member session and passes the
 * userId. The old number stops working immediately. Audited (never the number).
 */
export const rotateAccountId = internalAction({
  args: {
    userId: v.id('users'),
    requestId: v.optional(v.string()),
    /** The caller's current session sid (cookie auth): kept alive; every OTHER
     *  session is revoked, since the credential that minted them is now dead. */
    keepSid: v.optional(v.string()),
  },
  handler: async (ctx, { userId, requestId, keepSid }): Promise<{ accountId: string }> => {
    const minted = await ctx.runAction(internal.accountId.mintForUser, { userId, rotate: true });
    // The old number stops working immediately — and so must every session it
    // minted. Revoking only the credential would leave a captured-session holder
    // authenticated for up to the 30-day TTL, defeating the rotation.
    await ctx.runMutation(internal.sessions.deleteAllForUserExcept, { userId, keepSid });
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
