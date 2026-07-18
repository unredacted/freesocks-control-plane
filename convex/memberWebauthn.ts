'use node';
/**
 * Member passkey ceremonies — the MEMBER analogue of convex/webauthn.ts (admin).
 * A "use node" action module because @simplewebauthn/server needs Node; the data
 * layer (memberPasskeys.ts) holds the queries/mutations this orchestrates.
 *
 * A member passkey is an OPT-IN, additive login credential. Design (locked with
 * the operator):
 *   - The 32-digit account number stays valid (a member never loses recovery by
 *     enrolling a passkey), so there is NO last-credential guard on revoke.
 *   - Discoverable (resident) credentials → true usernameless login. The enroll
 *     UI warns that a platform passkey may sync to the user's Apple/Google account
 *     (a linkage the anonymous, censored-region audience should choose knowingly).
 *   - Cross-realm isolation: authenticateVerify only matches a MEMBER credential
 *     (memberPasskeyCredentials), so an admin passkey can never assert a member
 *     session and vice-versa, even though both share one RP id/origin.
 *   - No existence oracle: login is usernameless (challenge carries no userId) and
 *     failures are one generic shape. The account number is never touched here.
 *
 * Expected failures are ConvexError({code,message}) so the HTTP layer maps them to
 * status codes without parsing strings (mirrors webauthn.ts).
 */
import { internalAction } from './_generated/server';
import { internal } from './_generated/api';
import { v, ConvexError } from 'convex/values';
import type { Id } from './_generated/dataModel';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { hmacSha256Hex, randomHex } from './lib/crypto';
import { signValue } from './lib/cookies';

// 30 days, matches auth.MEMBER_TTL_MS + the fs_session cookie (kept local, like
// webauthn.ts's ADMIN_TTL_MS, so this node module doesn't import the auth action).
const MEMBER_TTL_MS = 30 * 86_400_000;

/**
 * RP config for MEMBER ceremonies: the same RP id + origins as admin (one SPA
 * origin), but a member-facing RP name so the authenticator prompt doesn't say
 * "Admin". Isolation is by credential TABLE, not by RP id.
 */
function memberWebauthnConfig() {
  const rpId = process.env.WEBAUTHN_RP_ID;
  const rpName = process.env.WEBAUTHN_RP_NAME_MEMBER ?? 'FreeSocks';
  const originRaw = process.env.WEBAUTHN_ORIGIN;
  if (!rpId || !originRaw) {
    throw new Error('WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN must be set (bunx convex env set ...)');
  }
  const origins = originRaw
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  return { rpId, rpName, origins };
}

async function ipHash(ip: string): Promise<string> {
  const salt = process.env.IP_HASH_SALT;
  if (!salt) throw new Error('IP_HASH_SALT must be set');
  return hmacSha256Hex(salt, ip);
}

// --- registration (add a passkey; authorized by the caller's member session) --

export const registerOptions = internalAction({
  args: { userId: v.id('users'), ip: v.optional(v.string()) },
  handler: async (
    ctx,
    { userId, ip },
  ): Promise<{ options: PublicKeyCredentialCreationOptionsJSON }> => {
    // Per-MEMBER throttle (the subject is the userId, so it must run even when
    // the request IP is unresolvable — an `if (ip)` guard would silently
    // disable enrollment limiting on a proxy misconfig).
    const rl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'account.passkey-register',
      subject: userId,
    });
    if (!rl.allowed) {
      throw new ConvexError({ code: 'rate_limit.exceeded', message: 'Too many attempts' });
    }
    const existing = await ctx.runQuery(internal.memberPasskeys.credentialIdsByUser, { userId });
    const { rpId, rpName } = memberWebauthnConfig();
    const options = await generateRegistrationOptions({
      rpName,
      rpID: rpId,
      // The user handle is the opaque member id; the display name is generic on
      // purpose (the account is anonymous — nothing account-identifying is embedded
      // in a credential that may sync to a cloud keychain).
      userID: new TextEncoder().encode(userId),
      userName: 'FreeSocks account',
      userDisplayName: 'FreeSocks account',
      attestationType: 'none',
      // residentKey:'required' → discoverable, so the member can sign in later with
      // no account number. userVerification:'preferred' doesn't reject a key without
      // a biometric/PIN. excludeCredentials stops double-registering on one device.
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      excludeCredentials: existing.map((id: string) => ({ id })),
    });
    await ctx.runMutation(internal.memberPasskeys.insertRegistrationChallenge, {
      userId,
      challenge: options.challenge,
      ttlMs: 5 * 60_000,
    });
    return { options };
  },
});

export const registerVerify = internalAction({
  args: {
    userId: v.id('users'),
    response: v.any(),
    deviceLabel: v.optional(v.string()),
    requestId: v.optional(v.string()),
  },
  handler: async (ctx, { userId, response, deviceLabel, requestId }): Promise<{ ok: true }> => {
    const consumed = await ctx.runMutation(
      internal.memberPasskeys.consumeLatestRegistrationChallenge,
      { userId },
    );
    if (!consumed) throw new ConvexError({ code: 'validation', message: 'No valid challenge' });

    const { rpId, origins } = memberWebauthnConfig();
    const verification = await verifyRegistrationResponse({
      response: response as RegistrationResponseJSON,
      expectedChallenge: consumed.challenge,
      expectedOrigin: origins.length === 1 ? origins[0]! : origins,
      expectedRPID: rpId,
    });
    if (!verification.verified || !verification.registrationInfo) {
      throw new ConvexError({ code: 'validation', message: 'Verification failed' });
    }
    const cred = verification.registrationInfo.credential;
    await ctx.runMutation(internal.memberPasskeys.insertCredential, {
      userId,
      credentialId: cred.id,
      publicKey: Buffer.from(cred.publicKey).toString('base64'),
      counter: cred.counter,
      transports: JSON.stringify(cred.transports ?? []),
      deviceLabel: deviceLabel?.trim() || 'unnamed',
      aaguid: verification.registrationInfo.aaguid,
    });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'account.passkey.register',
      targetType: 'user',
      targetId: userId,
      requestId,
      payload: { deviceLabel: deviceLabel?.trim() || 'unnamed' },
    });
    return { ok: true as const };
  },
});

// --- authentication (usernameless discoverable login) ------------------------

export const authenticateOptions = internalAction({
  args: { ip: v.optional(v.string()) },
  handler: async (
    ctx,
    { ip },
  ): Promise<{ options: PublicKeyCredentialRequestOptionsJSON; challengeId: string }> => {
    // Per-IP throttle: the only guard on this unauthenticated, challenge-writing
    // path (the assertion itself is cryptographic, so no captcha).
    if (ip) {
      const rl = await ctx.runMutation(internal.rateLimits.enforce, {
        policyKey: 'passkey.authenticate',
        subject: await ipHash(ip),
      });
      if (!rl.allowed) {
        throw new ConvexError({
          code: 'rate_limit.exceeded',
          message: 'Too many sign-in attempts',
        });
      }
    }
    const { rpId } = memberWebauthnConfig();
    // Usernameless: no allowCredentials, so the authenticator offers every resident
    // FreeSocks passkey and verify identifies the member from the chosen credential.
    const options = await generateAuthenticationOptions({
      rpID: rpId,
      userVerification: 'preferred',
    });
    const challengeId = randomHex(16);
    await ctx.runMutation(internal.memberPasskeys.insertAuthChallenge, {
      challengeId,
      challenge: options.challenge,
      ttlMs: 60_000,
    });
    return { options, challengeId };
  },
});

export const authenticateVerify = internalAction({
  args: {
    challengeId: v.string(),
    response: v.any(),
    requestId: v.optional(v.string()),
    // PoP (Phase 2): the client's session public key, bound to the new session.
    popPublicKey: v.optional(v.string()),
    popAlg: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { challengeId, response, requestId, popPublicKey, popAlg },
  ): Promise<{
    ok: true;
    signedCookieValue: string;
    maxAgeSec: number;
    popSessionToken?: string;
    lapsedDowngrade?: boolean;
  }> => {
    const consumed = await ctx.runMutation(internal.memberPasskeys.consumeAuthChallenge, {
      challengeId,
    });
    if (!consumed)
      throw new ConvexError({ code: 'validation', message: 'Invalid or expired challenge' });

    const resp = response as AuthenticationResponseJSON;
    // Cross-realm isolation: only a MEMBER credential can match here.
    const credRow = await ctx.runQuery(internal.memberPasskeys.credentialByCredentialId, {
      credentialId: resp.id,
    });
    if (!credRow) throw new ConvexError({ code: 'validation', message: 'Unknown credential' });

    const { rpId, origins } = memberWebauthnConfig();
    const verification = await verifyAuthenticationResponse({
      response: resp,
      expectedChallenge: consumed.challenge,
      expectedOrigin: origins.length === 1 ? origins[0]! : origins,
      expectedRPID: rpId,
      credential: {
        id: credRow.credentialId,
        publicKey: new Uint8Array(Buffer.from(credRow.publicKey, 'base64')),
        counter: credRow.counter,
      },
    });
    if (!verification.verified)
      throw new ConvexError({ code: 'validation', message: 'Verification failed' });

    await ctx.runMutation(internal.memberPasskeys.bumpCredentialCounter, {
      credentialId: credRow.credentialId,
      newCounter: verification.authenticationInfo.newCounter,
    });

    const userId = credRow.userId as Id<'users'>;
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) throw new ConvexError({ code: 'validation', message: 'Verification failed' });

    // Mirror auth.accountLogin's admitted-set handling so a passkey login behaves
    // identically for lapsed / idle-inactive / disabled accounts.
    let lapsedDowngrade = false;
    if (user.status === 'disabled' && user.disabledReason === 'membership_lapsed') {
      await ctx.runMutation(internal.lifecycle.downgradeLapsedToFree, { userId });
      lapsedDowngrade = true;
    } else if (user.status === 'inactive') {
      await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
    } else if (user.status === 'disabled' || user.status === 'deleted') {
      throw new ConvexError({ code: 'auth.forbidden', message: 'This account is not available.' });
    }

    const sid = randomHex(32);
    const popSessionToken = popPublicKey ? randomHex(16) : undefined;
    await ctx.runMutation(internal.sessions.create, {
      sid,
      kind: 'member',
      userId,
      ttlMs: MEMBER_TTL_MS,
      ...(popPublicKey ? { popPublicKey, popAlg, popSessionToken } : {}),
    });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'account.login.passkey',
      targetType: 'user',
      targetId: userId,
      requestId,
    });
    const signingKey = process.env.SESSION_SIGNING_KEY;
    if (!signingKey) throw new Error('SESSION_SIGNING_KEY must be set');
    const signedCookieValue = await signValue(sid, signingKey);
    return {
      ok: true,
      signedCookieValue,
      maxAgeSec: MEMBER_TTL_MS / 1000,
      popSessionToken,
      lapsedDowngrade,
    };
  },
});
