/**
 * Client helpers for the OPTIONAL member passkey flow (WS5). Two transports,
 * matching the server routes:
 *   - signInWithPasskey(): raw fetch to the PLAINTEXT /api/v1/auth/passkey/* login
 *     routes (like the admin ceremony), binding a fresh member PoP key in-body and
 *     persisting the returned per-session token, so later apiClient calls are
 *     PoP-signed for the new session (mirrors account-login).
 *   - enrollPasskey(): a SEALED + PoP-signed authenticated member action via
 *     apiClient (the session already exists). Used from the Security tab + the
 *     optional sign-up step.
 * A user-cancelled browser prompt (NotAllowedError/AbortError) is normalized to a
 * typed PasskeyCancelledError so callers can stay quiet on cancel.
 */
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { z } from 'zod';
import { apiClient, ApiCallError } from './api';
import { ensureSessionKey, setSessionToken } from './pop';
import { POP_ALG_FIELD, POP_PUBKEY_FIELD } from '../../shared/crypto/pop';

/** True when this browser can do WebAuthn at all (no support → hide the option). */
export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential !== 'undefined';
}

/** Thrown when the user dismisses the browser passkey prompt (not a real error). */
export class PasskeyCancelledError extends Error {
  constructor() {
    super('cancelled');
    this.name = 'PasskeyCancelledError';
  }
}

function isCancel(err: unknown): boolean {
  const name = err instanceof Error ? err.name : '';
  return name === 'NotAllowedError' || name === 'AbortError';
}

const RegisterOptionsResp = z.object({ options: z.any() });
const OkResp = z.object({ ok: z.boolean() });

/**
 * Enroll a new passkey on the current authenticated member session (sealed +
 * PoP-signed via apiClient). Throws PasskeyCancelledError if the prompt is
 * dismissed; any other failure bubbles for the caller to surface.
 */
export async function enrollPasskey(deviceLabel?: string): Promise<void> {
  const { options } = await apiClient.post(
    '/api/v1/account/passkey/register/options',
    {},
    RegisterOptionsResp,
  );
  let reg: Awaited<ReturnType<typeof startRegistration>>;
  try {
    reg = await startRegistration({ optionsJSON: options });
  } catch (err) {
    if (isCancel(err)) throw new PasskeyCancelledError();
    throw err;
  }
  await apiClient.post(
    '/api/v1/account/passkey/register/verify',
    { response: reg, deviceLabel: deviceLabel?.trim() || undefined },
    OkResp,
  );
}

/**
 * Sign in with a discoverable passkey (usernameless). Returns whether the server
 * auto-downgraded a lapsed membership (so the caller can show the one-time
 * banner, like account-number login).
 */
export async function signInWithPasskey(): Promise<{ lapsedDowngrade: boolean }> {
  const optsRes = await fetch('/api/v1/auth/passkey/authenticate/options', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  if (!optsRes.ok) {
    // Throw the server's structured error (ApiCallError) so the caller's
    // apiErrorMessage maps the CODE to a translated message — never raw
    // English server text.
    const body = (await optsRes.json().catch(() => ({}))) as {
      error?: { code?: string; message?: string };
    };
    throw new ApiCallError(optsRes.status, {
      error: {
        code: body.error?.code ?? `http.${optsRes.status}`,
        message: body.error?.message ?? 'Could not start sign-in',
      },
    });
  }
  const optsBody = (await optsRes.json()) as {
    options: Parameters<typeof startAuthentication>[0]['optionsJSON'];
    challengeId: string;
  };

  let assertion: Awaited<ReturnType<typeof startAuthentication>>;
  try {
    assertion = await startAuthentication({ optionsJSON: optsBody.options });
  } catch (err) {
    if (isCancel(err)) throw new PasskeyCancelledError();
    throw err;
  }

  // Bind a fresh member PoP key to the new session (posted in-body, like
  // account-login) so a captured cookie alone is insufficient afterward.
  const popKey = await ensureSessionKey('member');
  const verifyRes = await fetch('/api/v1/auth/passkey/authenticate/verify', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challengeId: optsBody.challengeId,
      response: assertion,
      ...(popKey ? { [POP_PUBKEY_FIELD]: popKey.pub, [POP_ALG_FIELD]: popKey.alg } : {}),
    }),
  });
  if (!verifyRes.ok) {
    const body = (await verifyRes.json().catch(() => ({}))) as {
      error?: { code?: string; message?: string };
    };
    throw new ApiCallError(verifyRes.status, {
      error: {
        code: body.error?.code ?? `http.${verifyRes.status}`,
        message: body.error?.message ?? 'Sign-in failed',
      },
    });
  }
  const okBody = (await verifyRes.json().catch(() => ({}))) as {
    popSessionToken?: string;
    lapsedDowngrade?: boolean;
  };
  // Persist the per-session token so every later PoP-signed request binds it.
  setSessionToken('member', okBody.popSessionToken);
  return { lapsedDowngrade: !!okBody.lapsedDowngrade };
}
