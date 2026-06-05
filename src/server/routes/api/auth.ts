import { Hono, type Context } from 'hono';
import { deleteCookie } from 'hono/cookie';
import { eq } from 'drizzle-orm';
import { users } from '../../db/schema';
import type { AppEnv, MemberSession } from '../../env';
import { UnauthenticatedError, ValidationError } from '../../lib/errors';
import { buildSetCookie, signValue } from '../../lib/cookies';
import { randomHex } from '../../lib/crypto';
import { MEMBER_COOKIE } from '../../middleware/sessions';
import { AuthMeResponse } from '../../../shared/contracts/auth';

const router = new Hono<AppEnv>();

/**
 * Allowlist for `returnTo` shapes. Reject anything other than a same-origin
 * absolute path. We deliberately do NOT accept full URLs even if they parse
 * to the current origin — that adds attack surface (parser edge cases,
 * encoded slashes) for no real benefit; every legitimate return-to is a
 * client-side route on this domain.
 *
 * The forbidden cases this guards against:
 *   - "https://evil.example/grab"   — absolute URL to a third party
 *   - "//evil.example/grab"          — protocol-relative URL (same effect)
 *   - "/\evil.example"               — backslash that some clients normalize
 *   - "javascript:alert(1)"          — pseudo-scheme
 */
function isSafeReturnTo(input: unknown): input is string {
  if (typeof input !== 'string') return false;
  if (input.length === 0 || input.length > 256) return false;
  // Must be a single leading slash followed by non-slash, non-backslash.
  // Allow query string + fragment characters in the suffix.
  return /^\/(?![/\\])[A-Za-z0-9_\-./?&=#%~+:@!$',;]*$/.test(input);
}

router.get('/login', async (c) => {
  const services = c.var.services;
  const platform = c.var.platform;
  const rawReturnTo = c.req.query('returnTo');
  // Fail closed: any caller-supplied value that doesn't satisfy the allowlist
  // is silently replaced with `/account`. Don't surface the rejection as an
  // error — that gives attackers feedback on what shapes are allowed.
  const returnTo = isSafeReturnTo(rawReturnTo) ? rawReturnTo : '/account';
  const state = randomHex(32);
  const nonce = randomHex(16);
  const { verifier, challenge } = await services.authentik.generatePkce();

  await platform.kv.cache.putJson(
    `oauth:state:${state}`,
    { verifier, nonce, returnTo },
    { expirationTtl: 600 },
  );
  const url = await services.authentik.buildAuthorizeUrl({
    state,
    codeChallenge: challenge,
    nonce,
  });
  return c.redirect(url);
});

router.get('/callback', async (c) => {
  const services = c.var.services;
  const platform = c.var.platform;
  const state = c.req.query('state');
  const code = c.req.query('code');
  if (!state || !code) throw new ValidationError('Missing state or code');

  const stored = await platform.kv.cache.getJson<{
    verifier: string;
    nonce: string;
    returnTo: string;
  }>(`oauth:state:${state}`);
  if (!stored) throw new ValidationError('Invalid or expired state');
  await platform.kv.cache.delete(`oauth:state:${state}`);

  const tokens = await services.authentik.exchangeCode(code, stored.verifier);

  // Verify the id_token before trusting anything in it. `AuthentikJwtVerifier`
  // already checks issuer, audience (the FreeSocks Authentik client id), and
  // signature against the JWKS. We additionally assert the `nonce` claim
  // matches what we stored in KV at /login time — this is the second-leg
  // replay protection OIDC defines: an id_token captured from one login flow
  // can't be replayed into another because each flow's nonce is unique.
  //
  // We deliberately verify the id_token even though we go on to call
  // `getUserInfo` (which is signed by Authentik's TLS): an attacker who can
  // forge an id_token but not control the userinfo endpoint would slip past
  // a userinfo-only check.
  const verified = await services.authentikJwt.verify(tokens.id_token);
  const tokenNonce = typeof verified.payload.nonce === 'string' ? verified.payload.nonce : null;
  if (!tokenNonce || tokenNonce !== stored.nonce) {
    platform.logger.warn('oidc_nonce_mismatch', {
      hasNonce: Boolean(tokenNonce),
      // We deliberately do NOT log the nonce values themselves — they're
      // single-use, but emitting them anywhere widens the attack surface.
    });
    throw new UnauthenticatedError('Invalid id_token nonce');
  }

  const userInfo = await services.authentik.getUserInfo(tokens.access_token);

  const userResolved = await upsertMemberUser(c, userInfo.sub, userInfo.email);
  const sessionId = randomHex(32);
  const session: MemberSession = {
    sessionId,
    userId: userResolved.id,
    contactId: null,
    authentikSubject: userInfo.sub,
    email: userInfo.email,
    displayName: userInfo.name,
    source: 'cookie',
  };
  await platform.kv.sessions.putJson(`session:member:${sessionId}`, session, {
    expirationTtl: 30 * 86_400,
  });

  const signed = await signValue(sessionId, platform.config.SESSION_SIGNING_KEY);
  c.header(
    'Set-Cookie',
    buildSetCookie(MEMBER_COOKIE, signed, {
      maxAge: 30 * 86_400,
      sameSite: 'Lax',
      secure: platform.config.ENVIRONMENT !== 'development',
    }),
  );
  // Defense in depth: the value was validated at /login time before storage,
  // but re-check in case the KV is ever poisoned by another code path.
  return c.redirect(isSafeReturnTo(stored.returnTo) ? stored.returnTo : '/account');
});

router.post('/logout', async (c) => {
  const platform = c.var.platform;
  if (c.var.member) {
    await platform.kv.sessions.delete(`session:member:${c.var.member.sessionId}`);
  }
  deleteCookie(c, MEMBER_COOKIE, { path: '/' });
  return c.json({ ok: true });
});

router.get('/me', async (c) => {
  if (!c.var.member) return c.json(AuthMeResponse.parse({ authenticated: false }));
  const services = c.var.services;
  const platform = c.var.platform;
  const userRow = await platform.db
    .select()
    .from(users)
    .where(eq(users.id, c.var.member.userId))
    .limit(1)
    .all();
  const user = userRow[0];
  const tier = user ? await services.tierPolicy.getById(user.tierId) : null;
  if (!user || !tier) return c.json(AuthMeResponse.parse({ authenticated: false }));
  return c.json(
    AuthMeResponse.parse({
      authenticated: true,
      member: {
        contactId: c.var.member.contactId,
        email: c.var.member.email,
        displayName: c.var.member.displayName,
        tier: { slug: tier.slug as 'free' | 'member' | 'patron' | 'custom', name: tier.name },
      },
    }),
  );
});

async function upsertMemberUser(c: Context<AppEnv>, authentikSubject: string, email?: string) {
  const platform = c.var.platform;
  const services = c.var.services;
  const existing = await platform.db
    .select()
    .from(users)
    .where(eq(users.authentikSubject, authentikSubject))
    .limit(1)
    .all();
  if (existing[0]) {
    if (email && existing[0].email !== email) {
      await platform.db
        .update(users)
        .set({ email, updatedAt: Date.now() })
        .where(eq(users.id, existing[0].id));
    }
    return existing[0];
  }
  // Tier/membership now arrives via the entitlement seam (setMembership);
  // a fresh OIDC user starts on the default-free tier.
  const tier = await services.tierPolicy.getDefaultFreeTier();
  const inserted = await platform.db
    .insert(users)
    .values({
      authentikSubject,
      email: email ?? null,
      tierId: tier.id,
      status: 'active',
    })
    .returning();
  if (!inserted[0]) throw new Error('user insert returned no row');
  return inserted[0];
}

export default router;
