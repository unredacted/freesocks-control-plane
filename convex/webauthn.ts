'use node';
/**
 * Admin passkey ceremonies (P6c): a "use node" action module because
 * @simplewebauthn/server needs Node (Buffer, node crypto). Ported from
 * providers/webauthn/server.ts + routes/api/admin/auth.ts. The data layer
 * (admins.ts) holds the queries/mutations; this file is just the ceremonies +
 * session mint. First-run BOOTSTRAP is gated by a constant-time
 * ADMIN_BOOTSTRAP_SECRET check and LOCKS FOREVER once any credential exists
 * (re-checked at both options and verify to close the TOCTOU window).
 *
 * Expected auth failures are raised as ConvexError({code,message}) so the HTTP
 * layer maps them to status codes without parsing error strings.
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
import { hmacSha256Hex, randomHex, timingSafeEqual } from './lib/crypto';
import { signValue } from './lib/cookies';

const ADMIN_TTL_MS = 12 * 3_600_000; // 12 hours, matches the old fs_admin_session.

function webauthnConfig() {
  const rpId = process.env.WEBAUTHN_RP_ID;
  const rpName = process.env.WEBAUTHN_RP_NAME ?? 'FreeSocks Admin';
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

// --- bootstrap registration -------------------------------------------------

export const registerBootstrapOptions = internalAction({
  args: {
    bootstrapSecret: v.string(),
    username: v.string(),
    displayName: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { bootstrapSecret, username, displayName },
  ): Promise<{ options: PublicKeyCredentialCreationOptionsJSON; adminId: Id<'adminUsers'> }> => {
    const secret = process.env.ADMIN_BOOTSTRAP_SECRET;
    if (!secret || !timingSafeEqual(bootstrapSecret, secret)) {
      throw new ConvexError({ code: 'auth.forbidden', message: 'Bootstrap secret required' });
    }
    if (await ctx.runQuery(internal.admins.hasActiveAdmin, {})) {
      throw new ConvexError({
        code: 'auth.forbidden',
        message: 'Bootstrap closed: an admin already exists',
      });
    }
    if (!username) throw new ConvexError({ code: 'validation', message: 'username required' });

    const adminId = await ctx.runMutation(internal.admins.upsertByUsername, {
      username,
      displayName: displayName ?? username,
    });
    const { rpId, rpName } = webauthnConfig();
    const options = await generateRegistrationOptions({
      rpName,
      rpID: rpId,
      userID: new TextEncoder().encode(adminId),
      userName: username,
      userDisplayName: displayName ?? username,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    });
    await ctx.runMutation(internal.admins.insertRegistrationChallenge, {
      adminUserId: adminId,
      challenge: options.challenge,
      ttlMs: 5 * 60_000,
    });
    return { options, adminId };
  },
});

export const registerBootstrapVerify = internalAction({
  args: {
    adminId: v.id('adminUsers'),
    response: v.any(),
    deviceLabel: v.optional(v.string()),
  },
  handler: async (ctx, { adminId, response, deviceLabel }): Promise<{ ok: true }> => {
    // Defence in depth: a TOCTOU window exists between options→verify. Lock here
    // too so two parties racing through options can still only register one admin.
    if (await ctx.runQuery(internal.admins.hasActiveAdmin, {})) {
      throw new ConvexError({
        code: 'auth.forbidden',
        message: 'Bootstrap closed: an admin already exists',
      });
    }
    const consumed = await ctx.runMutation(internal.admins.consumeLatestRegistrationChallenge, {
      adminUserId: adminId,
    });
    if (!consumed) throw new ConvexError({ code: 'validation', message: 'No valid challenge' });

    const { rpId, origins } = webauthnConfig();
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
    await ctx.runMutation(internal.admins.insertCredential, {
      adminUserId: adminId,
      credentialId: cred.id,
      publicKey: Buffer.from(cred.publicKey).toString('base64'),
      counter: cred.counter,
      transports: JSON.stringify(cred.transports ?? []),
      deviceLabel: deviceLabel ?? 'unnamed',
      aaguid: verification.registrationInfo.aaguid,
    });
    return { ok: true as const };
  },
});

// --- authentication ---------------------------------------------------------

export const authenticateOptions = internalAction({
  args: { username: v.string(), ip: v.optional(v.string()) },
  handler: async (
    ctx,
    { username, ip },
  ): Promise<{ options: PublicKeyCredentialRequestOptionsJSON; challengeId: string }> => {
    // Per-IP throttle to bound credential-stuffing / enumeration (strict counter).
    if (ip) {
      const salt = process.env.IP_HASH_SALT;
      if (!salt) throw new Error('IP_HASH_SALT must be set');
      const ipHash = await hmacSha256Hex(salt, ip);
      const rl = await ctx.runMutation(internal.rateLimits.checkAndIncrement, {
        bucket: `admin-auth:ip:${ipHash}`,
        max: 20,
        windowMs: 3_600_000,
      });
      if (!rl.allowed) {
        throw new ConvexError({
          code: 'rate_limit.exceeded',
          message: 'Too many sign-in attempts',
        });
      }
    }
    if (!username) throw new ConvexError({ code: 'validation', message: 'username required' });

    // Do NOT reveal whether the username exists: for an unknown/inactive admin
    // we still return well-formed options with no credentials (verify then fails
    // like any wrong passkey), identical shape + similar timing to the valid case.
    const admin = await ctx.runQuery(internal.admins.byUsername, { username });
    const active = admin?.isActive ? admin : null;
    const allowCredentialIds = active
      ? await ctx.runQuery(internal.admins.credentialIdsByAdmin, { adminUserId: active._id })
      : [];

    const { rpId } = webauthnConfig();
    const options = await generateAuthenticationOptions({
      rpID: rpId,
      userVerification: 'preferred',
      allowCredentials: allowCredentialIds.map((id: string) => ({ id })),
    });
    const challengeId = randomHex(16);
    await ctx.runMutation(internal.admins.insertAuthChallenge, {
      challengeId,
      challenge: options.challenge,
      adminUserId: active?._id,
      ttlMs: 60_000,
    });
    return { options, challengeId };
  },
});

export const authenticateVerify = internalAction({
  args: { challengeId: v.string(), response: v.any(), requestId: v.optional(v.string()) },
  handler: async (
    ctx,
    { challengeId, response, requestId },
  ): Promise<{ ok: true; username: string; signedCookieValue: string; maxAgeSec: number }> => {
    const consumed = await ctx.runMutation(internal.admins.consumeAuthChallenge, { challengeId });
    if (!consumed)
      throw new ConvexError({ code: 'validation', message: 'Invalid or expired challenge' });

    const resp = response as AuthenticationResponseJSON;
    const credRow = await ctx.runQuery(internal.admins.credentialByCredentialId, {
      credentialId: resp.id,
    });
    if (!credRow) throw new ConvexError({ code: 'validation', message: 'Unknown credential' });

    const { rpId, origins } = webauthnConfig();
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

    await ctx.runMutation(internal.admins.bumpCredentialCounter, {
      credentialId: credRow.credentialId,
      newCounter: verification.authenticationInfo.newCounter,
    });
    const adminUserId = credRow.adminUserId as Id<'adminUsers'>;
    const admin = await ctx.runQuery(internal.admins.getById, { adminUserId });
    if (!admin) throw new ConvexError({ code: 'validation', message: 'Admin user not found' });
    await ctx.runMutation(internal.admins.touchLogin, { adminUserId });

    const sid = randomHex(32);
    await ctx.runMutation(internal.sessions.create, {
      sid,
      kind: 'admin',
      adminUserId,
      ttlMs: ADMIN_TTL_MS,
    });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'admin',
      actorId: adminUserId,
      action: 'admin.login',
      requestId,
    });
    const signingKey = process.env.ADMIN_SESSION_SIGNING_KEY;
    if (!signingKey) throw new Error('ADMIN_SESSION_SIGNING_KEY must be set');
    const signedCookieValue = await signValue(sid, signingKey);
    return {
      ok: true,
      username: admin.username,
      signedCookieValue,
      maxAgeSec: ADMIN_TTL_MS / 1000,
    };
  },
});
