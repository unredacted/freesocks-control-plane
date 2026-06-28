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
import { hmacSha256Hex, randomHex, sha256Hex, timingSafeEqual } from './lib/crypto';
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
      // residentKey:'required' makes the passkey DISCOVERABLE, which is what lets
      // the admin sign in later with no username (the authenticator can surface
      // it without an allowCredentials hint). userVerification stays 'preferred'
      // so an authenticator without a biometric/PIN isn't rejected outright.
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
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
  // `username` is optional: omit it for the usernameless / discoverable-credential
  // flow (the default UX). A username is still accepted as a fallback for
  // authenticators that did not make the passkey discoverable (it narrows
  // allowCredentials), without leaking whether that admin exists.
  args: { username: v.optional(v.string()), ip: v.optional(v.string()) },
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

    // Usernameless (the default): no allowCredentials, so the authenticator
    // offers every resident passkey for this RP and the user just picks one —
    // verify then identifies the admin from the chosen credential. With a
    // username (fallback) we narrow to that admin's credentials, but do NOT
    // reveal whether it exists: an unknown/inactive admin still gets well-formed
    // options with no credentials (verify fails like any wrong passkey).
    let allowCredentialIds: string[] = [];
    let boundAdminId: Id<'adminUsers'> | undefined;
    if (username) {
      const admin = await ctx.runQuery(internal.admins.byUsername, { username });
      const active = admin?.isActive ? admin : null;
      if (active) {
        boundAdminId = active._id;
        allowCredentialIds = await ctx.runQuery(internal.admins.credentialIdsByAdmin, {
          adminUserId: active._id,
        });
      }
    }

    const { rpId } = webauthnConfig();
    const options = await generateAuthenticationOptions({
      rpID: rpId,
      userVerification: 'preferred',
      // Omit (not []) when usernameless so the browser does discoverable-credential
      // selection rather than restricting to a (empty) list.
      allowCredentials: allowCredentialIds.length
        ? allowCredentialIds.map((id: string) => ({ id }))
        : undefined,
    });
    const challengeId = randomHex(16);
    await ctx.runMutation(internal.admins.insertAuthChallenge, {
      challengeId,
      challenge: options.challenge,
      adminUserId: boundAdminId,
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
    // PoP (Phase 2): the admin client's session public key. Admin inherits PoP
    // via the shared verify path once bound here.
    popPublicKey: v.optional(v.string()),
    /** The PoP algorithm ('EdDSA' | 'ES256') for popPublicKey; stored on the session. */
    popAlg: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { challengeId, response, requestId, popPublicKey, popAlg },
  ): Promise<{
    ok: true;
    username: string;
    signedCookieValue: string;
    maxAgeSec: number;
    popSessionToken?: string;
  }> => {
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
    // A deactivated admin cannot mint a fresh session, even with a valid passkey
    // (W3-8a — pairs with the resolveAdmin per-request isActive gate).
    if (!admin.isActive)
      throw new ConvexError({
        code: 'auth.forbidden',
        message: 'This admin account is deactivated.',
      });
    await ctx.runMutation(internal.admins.touchLogin, { adminUserId });

    const sid = randomHex(32);
    const popSessionToken = popPublicKey ? randomHex(16) : undefined;
    await ctx.runMutation(internal.sessions.create, {
      sid,
      kind: 'admin',
      adminUserId,
      ttlMs: ADMIN_TTL_MS,
      ...(popPublicKey ? { popPublicKey, popAlg, popSessionToken } : {}),
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
      popSessionToken,
    };
  },
});

// --- multi-admin onboarding via invite links --------------------------------

const INVITE_TTL_MS = 24 * 3_600_000; // 24h to open the link + register a passkey.

/**
 * Mint a single-use invite for a NEW admin (called by an authenticated admin).
 * Creates (or reuses a credential-less) adminUsers row and stores the invite
 * HASHED; the raw token is returned ONCE for the inviter to share as a link.
 * Rejects a username that already has a registered passkey (can't invite over an
 * existing admin).
 */
export const createInvite = internalAction({
  args: {
    username: v.string(),
    displayName: v.optional(v.string()),
    createdByAdminId: v.id('adminUsers'),
    requestId: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { username, displayName, createdByAdminId, requestId },
  ): Promise<{ inviteToken: string; username: string; expiresAtMs: number }> => {
    const name = username.trim();
    if (!name) throw new ConvexError({ code: 'validation', message: 'username required' });

    const existing = await ctx.runQuery(internal.admins.byUsername, { username: name });
    if (existing) {
      const creds = await ctx.runQuery(internal.admins.credentialIdsByAdmin, {
        adminUserId: existing._id,
      });
      if (creds.length > 0) {
        throw new ConvexError({
          code: 'validation',
          message: 'That username already has a registered admin',
        });
      }
    }
    const adminUserId = await ctx.runMutation(internal.admins.upsertByUsername, {
      username: name,
      displayName: displayName?.trim() || name,
    });

    const token = randomHex(32); // 256-bit, single-use; only the hash is stored.
    const tokenHash = await sha256Hex(token);
    await ctx.runMutation(internal.admins.insertInvite, {
      adminUserId,
      tokenHash,
      tokenPrefix: token.slice(0, 8),
      createdByAdminId,
      ttlMs: INVITE_TTL_MS,
    });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'admin',
      actorId: createdByAdminId,
      action: 'admin.invite.created',
      requestId,
      payload: { username: name },
    });
    return { inviteToken: token, username: name, expiresAtMs: Date.now() + INVITE_TTL_MS };
  },
});

/**
 * Invite-gated registration options. The invite token is the authorization (the
 * invitee has no session yet). Resident key required so the new passkey is
 * discoverable for usernameless sign-in afterwards.
 */
export const registerInviteOptions = internalAction({
  args: { invite: v.string(), ip: v.optional(v.string()) },
  handler: async (
    ctx,
    { invite, ip },
  ): Promise<{ options: PublicKeyCredentialCreationOptionsJSON }> => {
    if (ip) {
      const salt = process.env.IP_HASH_SALT;
      if (!salt) throw new Error('IP_HASH_SALT must be set');
      const ipHash = await hmacSha256Hex(salt, ip);
      const rl = await ctx.runMutation(internal.rateLimits.checkAndIncrement, {
        bucket: `admin-register:ip:${ipHash}`,
        max: 30,
        windowMs: 3_600_000,
      });
      if (!rl.allowed) {
        throw new ConvexError({ code: 'rate_limit.exceeded', message: 'Too many attempts' });
      }
    }
    const found = await ctx.runQuery(internal.admins.inviteByTokenHash, {
      tokenHash: await sha256Hex(invite),
    });
    if (!found)
      throw new ConvexError({ code: 'auth.forbidden', message: 'Invalid or expired invite' });
    const admin = await ctx.runQuery(internal.admins.getById, { adminUserId: found.adminUserId });
    if (!admin) throw new ConvexError({ code: 'validation', message: 'Invite target missing' });

    const existingCreds = await ctx.runQuery(internal.admins.credentialIdsByAdmin, {
      adminUserId: found.adminUserId,
    });
    const { rpId, rpName } = webauthnConfig();
    const options = await generateRegistrationOptions({
      rpName,
      rpID: rpId,
      userID: new TextEncoder().encode(found.adminUserId),
      userName: admin.username,
      userDisplayName: admin.displayName,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      excludeCredentials: existingCreds.map((id: string) => ({ id })),
    });
    await ctx.runMutation(internal.admins.insertRegistrationChallenge, {
      adminUserId: found.adminUserId,
      challenge: options.challenge,
      ttlMs: 5 * 60_000,
    });
    return { options };
  },
});

/**
 * Invite-gated registration verify. Order matters for single-use semantics
 * without burning the invite on a benign failure: verify the attestation FIRST
 * (a crypto failure leaves the invite usable for a retry via /options), THEN
 * atomically consume the invite (the race gate), and only then insert the
 * credential — so two concurrent verifies can never both register.
 */
export const registerInviteVerify = internalAction({
  args: {
    invite: v.string(),
    response: v.any(),
    deviceLabel: v.optional(v.string()),
    requestId: v.optional(v.string()),
  },
  handler: async (
    ctx,
    { invite, response, deviceLabel, requestId },
  ): Promise<{ ok: true; username: string }> => {
    const found = await ctx.runQuery(internal.admins.inviteByTokenHash, {
      tokenHash: await sha256Hex(invite),
    });
    if (!found)
      throw new ConvexError({ code: 'auth.forbidden', message: 'Invalid or expired invite' });

    const consumedChallenge = await ctx.runMutation(
      internal.admins.consumeLatestRegistrationChallenge,
      { adminUserId: found.adminUserId },
    );
    if (!consumedChallenge)
      throw new ConvexError({ code: 'validation', message: 'No valid challenge' });

    const { rpId, origins } = webauthnConfig();
    const verification = await verifyRegistrationResponse({
      response: response as RegistrationResponseJSON,
      expectedChallenge: consumedChallenge.challenge,
      expectedOrigin: origins.length === 1 ? origins[0]! : origins,
      expectedRPID: rpId,
    });
    if (!verification.verified || !verification.registrationInfo) {
      throw new ConvexError({ code: 'validation', message: 'Verification failed' });
    }

    // Single-use gate AFTER a valid attestation but BEFORE inserting: the race
    // loser aborts here without leaving a second credential.
    const consumed = await ctx.runMutation(internal.admins.consumeInvite, {
      inviteId: found.inviteId,
    });
    if (!consumed.ok)
      throw new ConvexError({ code: 'auth.forbidden', message: 'Invite already used' });

    const cred = verification.registrationInfo.credential;
    await ctx.runMutation(internal.admins.insertCredential, {
      adminUserId: found.adminUserId,
      credentialId: cred.id,
      publicKey: Buffer.from(cred.publicKey).toString('base64'),
      counter: cred.counter,
      transports: JSON.stringify(cred.transports ?? []),
      deviceLabel: deviceLabel ?? 'unnamed',
      aaguid: verification.registrationInfo.aaguid,
    });
    const admin = await ctx.runQuery(internal.admins.getById, { adminUserId: found.adminUserId });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'admin',
      actorId: found.adminUserId,
      action: 'admin.invite.redeemed',
      requestId,
      payload: { username: admin?.username },
    });
    return { ok: true as const, username: admin?.username ?? '' };
  },
});
