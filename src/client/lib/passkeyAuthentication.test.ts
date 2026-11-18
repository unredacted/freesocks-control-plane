// @vitest-environment node
import { describe, expect, test, vi } from 'vitest';
import { startAuthentication } from '@simplewebauthn/browser';
import {
  passkeyExamples,
  passkeyNonce,
  signedAssertion,
} from '../../../tests/fixtures/passkeyAssertion';
import { ensureSessionKey } from './pop';
import { authenticateWithSessionKey } from './passkeyAuthentication';

vi.mock('@simplewebauthn/browser', () => ({ startAuthentication: vi.fn() }));
vi.mock('./pop', () => ({ ensureSessionKey: vi.fn() }));
vi.mock('./i18n/index.svelte', () => ({ t: () => 'Session signing unavailable' }));

describe.each(['member', 'admin'] as const)('%s passkey sign-in', (realm) => {
  test('asks the authenticator to sign the local key commitment and sends the same binding', async () => {
    const { pub, alg, challenge } = passkeyExamples[realm];
    const response = signedAssertion(realm);
    vi.mocked(ensureSessionKey).mockResolvedValueOnce({ pub, alg });
    vi.mocked(startAuthentication).mockResolvedValueOnce(response);
    const options = {
      challenge: passkeyNonce,
      rpId: 'localhost',
      userVerification: 'required' as const,
    };
    expect(await authenticateWithSessionKey(realm, options)).toEqual({
      response,
      fsPopPub: pub,
      fsPopAlg: alg,
    });
    expect(ensureSessionKey).toHaveBeenLastCalledWith(realm);
    expect(startAuthentication).toHaveBeenLastCalledWith({
      optionsJSON: { ...options, challenge },
    });
  });

  test('requires a signing key before prompting for a passkey', async () => {
    vi.mocked(startAuthentication).mockClear();
    vi.mocked(ensureSessionKey).mockResolvedValueOnce(null);
    await expect(authenticateWithSessionKey(realm, { challenge: passkeyNonce })).rejects.toThrow();
    expect(startAuthentication).not.toHaveBeenCalled();
  });
});
