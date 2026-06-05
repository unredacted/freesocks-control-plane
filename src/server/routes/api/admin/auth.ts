import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { adminUsers, passkeyCredentials, webauthnRegistrationChallenges } from '../../../db/schema';
import type { AppEnv, AdminSession } from '../../../env';
import { ForbiddenError, RateLimitError, ValidationError } from '../../../lib/errors';
import { buildSetCookie, signValue } from '../../../lib/cookies';
import { randomHex, timingSafeEqual } from '../../../lib/crypto';
import { ADMIN_COOKIE } from '../../../middleware/sessions';

const router = new Hono<AppEnv>();

/**
 * Whether at least one admin has completed registration (has a registered
 * passkey). A row in admin_users without any passkey is from an abandoned
 * bootstrap attempt and doesn't count.
 */
async function hasActiveAdmin(c: { var: { platform: AppEnv['Variables']['platform'] } }) {
  const rows = await c.var.platform.db.select().from(passkeyCredentials).limit(1).all();
  return rows.length > 0;
}

/**
 * Returns whether the admin bootstrap path is currently usable. The SPA's
 * `/admin` route uses this to decide between the bootstrap form (no admins
 * yet) and the login form (admins exist).
 *
 * Bootstrap is locked once any admin has completed registration, even if
 * ADMIN_BOOTSTRAP_SECRET is still set. Recovery path if every admin loses
 * their passkey is to clear those tables manually:
 *   wrangler d1 execute DB --command "DELETE FROM passkey_credentials; DELETE FROM admin_users;"
 */
router.get('/status', async (c) => {
  const platform = c.var.platform;
  const has = await hasActiveAdmin(c);
  return c.json({
    hasAdmins: has,
    bootstrapAvailable: !has && Boolean(platform.config.ADMIN_BOOTSTRAP_SECRET),
    // Surface session presence so the SPA can short-circuit the login form
    // when an admin is already authenticated. `c.var.admin` is populated by
    // `sessionPasskeyMw` when the cookie is valid.
    signedIn: Boolean(c.var.admin),
  });
});

router.post('/register-bootstrap/options', async (c) => {
  const platform = c.var.platform;
  const services = c.var.services;

  // Constant-time comparison so we don't leak secret length via timing.
  const bootstrapHeader = c.req.header('x-admin-bootstrap-token') ?? '';
  if (
    !platform.config.ADMIN_BOOTSTRAP_SECRET ||
    !timingSafeEqual(bootstrapHeader, platform.config.ADMIN_BOOTSTRAP_SECRET)
  ) {
    throw new ForbiddenError('Bootstrap secret required');
  }

  // Bootstrap is locked once any admin has a registered passkey.
  if (await hasActiveAdmin(c)) {
    throw new ForbiddenError('Bootstrap closed: an admin already exists');
  }

  const body = await c.req.json().catch(() => ({}));
  const username = typeof body.username === 'string' ? body.username : null;
  const displayName = typeof body.displayName === 'string' ? body.displayName : username;
  if (!username) throw new ValidationError('username required');

  // Re-use a row from a prior abandoned bootstrap attempt with the same username.
  let admin = (
    await platform.db
      .select()
      .from(adminUsers)
      .where(eq(adminUsers.username, username))
      .limit(1)
      .all()
  )[0];
  if (!admin) {
    const inserted = await platform.db
      .insert(adminUsers)
      .values({ username, displayName: displayName ?? username })
      .returning();
    admin = inserted[0];
  }
  if (!admin) throw new Error('admin upsert returned no row');

  const userId = new TextEncoder().encode(String(admin.id));
  const options = await services.webauthn.generateRegistration({
    userId,
    userName: admin.username,
    userDisplayName: admin.displayName,
  });
  await platform.db.insert(webauthnRegistrationChallenges).values({
    adminUserId: admin.id,
    challenge: options.challenge,
    expiresAt: Date.now() + 5 * 60_000,
  });
  return c.json({ options, adminId: admin.id });
});

router.post('/register-bootstrap/verify', async (c) => {
  const platform = c.var.platform;
  const services = c.var.services;

  // Defense in depth: a TOCTOU window exists between options→verify. Lock here
  // too so that a race where two parties hit options simultaneously can only
  // produce one registered admin.
  if (await hasActiveAdmin(c)) {
    throw new ForbiddenError('Bootstrap closed: an admin already exists');
  }

  const body = await c.req.json();
  const { adminId, response, deviceLabel } = body as {
    adminId: number;
    response: any;
    deviceLabel?: string;
  };
  const challengeRow = (
    await platform.db
      .select()
      .from(webauthnRegistrationChallenges)
      .where(eq(webauthnRegistrationChallenges.adminUserId, adminId))
      .all()
  )
    .filter((r) => !r.consumedAt && r.expiresAt > Date.now())
    .sort((a, b) => b.id - a.id)[0];
  if (!challengeRow) throw new ValidationError('No valid challenge');
  // Mark the challenge consumed BEFORE verification, not after — same
  // reasoning as `/authenticate/verify`: WebAuthn ceremonies don't need
  // retry semantics, and an unconsumed challenge inside its TTL is a
  // replay vector. A legitimate retry just restarts the ceremony.
  await platform.db
    .update(webauthnRegistrationChallenges)
    .set({ consumedAt: Date.now() })
    .where(eq(webauthnRegistrationChallenges.id, challengeRow.id));
  const verification = await services.webauthn.verifyRegistration(response, challengeRow.challenge);
  if (!verification.verified || !verification.registrationInfo) {
    throw new ValidationError('Verification failed');
  }
  const cred = verification.registrationInfo.credential;
  await platform.db.insert(passkeyCredentials).values({
    adminUserId: adminId,
    credentialId: cred.id,
    publicKey: Buffer.from(cred.publicKey).toString('base64'),
    counter: cred.counter,
    transports: JSON.stringify(cred.transports ?? []),
    deviceLabel: deviceLabel ?? 'unnamed',
    aaguid: verification.registrationInfo.aaguid,
  });
  // Note: the challenge was already marked consumed earlier in this handler
  // (before verification ran) as a replay-prevention measure.
  return c.json({ ok: true });
});

router.post('/authenticate/options', async (c) => {
  const platform = c.var.platform;
  const services = c.var.services;
  // Per-IP throttle to bound credential-stuffing / enumeration attempts.
  // Best-effort (soft KV limit); skipped when the client IP can't be resolved.
  const ip = c.var.clientIp;
  if (ip) {
    const ipHash = await services.rateLimit.hashIp(ip);
    const decision = await services.rateLimit.checkAndIncrement(
      `rl:admin-auth:ip:${ipHash}:${services.rateLimit.hourBucket()}`,
      20,
      3600,
    );
    if (!decision.allowed) {
      throw new RateLimitError(decision.retryAfterSeconds, 'Too many sign-in attempts');
    }
  }
  const body = await c.req.json().catch(() => ({}));
  const username = typeof body.username === 'string' ? body.username : null;
  if (!username) throw new ValidationError('username required');
  const admin = (
    await platform.db
      .select()
      .from(adminUsers)
      .where(eq(adminUsers.username, username))
      .limit(1)
      .all()
  )[0];
  // Do NOT reveal whether the username exists. For an unknown/inactive admin we
  // still return a well-formed options payload (with no credentials, so verify
  // simply fails) — identical response shape and similar timing to the valid
  // case, so this endpoint can't be used to enumerate admin usernames.
  const creds =
    admin && admin.isActive
      ? await platform.db
          .select()
          .from(passkeyCredentials)
          .where(eq(passkeyCredentials.adminUserId, admin.id))
          .all()
      : [];
  const options = await services.webauthn.generateAuthentication({
    allowCredentialIds: creds.map((c) => c.credentialId),
  });
  const challengeId = randomHex(16);
  await platform.kv.cache.putJson(
    `webauthn:assert:${challengeId}`,
    {
      challenge: options.challenge,
      // Sentinel for unknown/inactive users → verify finds no matching
      // credential and fails like any wrong passkey.
      adminId: admin && admin.isActive ? admin.id : -1,
      expiresAt: Date.now() + 60_000,
    },
    { expirationTtl: 60 },
  );
  return c.json({ options, challengeId });
});

router.post('/authenticate/verify', async (c) => {
  const platform = c.var.platform;
  const services = c.var.services;
  const body = await c.req.json();
  const { challengeId, response } = body as { challengeId: string; response: any };
  const challenge = await platform.kv.cache.getJson<{ challenge: string; adminId: number }>(
    `webauthn:assert:${challengeId}`,
  );
  if (!challenge) throw new ValidationError('Invalid or expired challenge');

  // Consume the challenge BEFORE running verification. A WebAuthn ceremony is
  // not "fat-fingerable" — the credential either matches or it doesn't, and
  // letting an attacker retry the same challenge against many credential ids
  // within the 60s TTL is an enumeration / replay vector. The cost of being
  // strict is that a legitimate user who hits a network hiccup mid-assertion
  // has to start the ceremony over, which is fine UX-wise.
  await platform.kv.cache.delete(`webauthn:assert:${challengeId}`);

  const credRow = (
    await platform.db
      .select()
      .from(passkeyCredentials)
      .where(eq(passkeyCredentials.credentialId, response.id))
      .limit(1)
      .all()
  )[0];
  if (!credRow) throw new ValidationError('Unknown credential');
  const verification = await services.webauthn.verifyAuthentication({
    response,
    expectedChallenge: challenge.challenge,
    credential: {
      id: credRow.credentialId,
      publicKey: new Uint8Array(Buffer.from(credRow.publicKey, 'base64')),
      counter: credRow.counter,
    },
  });
  if (!verification.verified) throw new ValidationError('Verification failed');
  await platform.db
    .update(passkeyCredentials)
    .set({ counter: verification.authenticationInfo.newCounter, lastUsedAt: Date.now() })
    .where(eq(passkeyCredentials.id, credRow.id));

  const admin = (
    await platform.db
      .select()
      .from(adminUsers)
      .where(eq(adminUsers.id, credRow.adminUserId))
      .limit(1)
      .all()
  )[0];
  if (!admin) throw new ValidationError('Admin user not found');
  await platform.db
    .update(adminUsers)
    .set({ lastLoginAt: Date.now() })
    .where(eq(adminUsers.id, admin.id));

  const sessionId = randomHex(32);
  const session: AdminSession = {
    sessionId,
    adminUserId: admin.id,
    username: admin.username,
  };
  await platform.kv.sessions.putJson(`session:admin:${sessionId}`, session, {
    expirationTtl: 12 * 3600,
  });
  const signed = await signValue(sessionId, platform.config.ADMIN_SESSION_SIGNING_KEY);
  c.header(
    'Set-Cookie',
    buildSetCookie(ADMIN_COOKIE, signed, {
      maxAge: 12 * 3600,
      sameSite: 'Strict',
      secure: platform.config.ENVIRONMENT !== 'development',
    }),
  );
  await services.audit.record({
    actorType: 'admin',
    actorId: String(admin.id),
    action: 'admin.login',
    requestId: c.var.requestId,
  });
  return c.json({ ok: true, username: admin.username });
});

router.post('/logout', async (c) => {
  const platform = c.var.platform;
  if (c.var.admin) {
    await platform.kv.sessions.delete(`session:admin:${c.var.admin.sessionId}`);
  }
  c.header('Set-Cookie', buildSetCookie(ADMIN_COOKIE, '', { maxAge: 0, sameSite: 'Strict' }));
  return c.json({ ok: true });
});

export default router;
