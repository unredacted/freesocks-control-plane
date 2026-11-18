import { startAuthentication } from '@simplewebauthn/browser';
import { passkeyChallenge, POP_ALG_FIELD, POP_PUBKEY_FIELD } from '../../shared/crypto/pop';
import { ApiCallError } from './api';
import { t } from './i18n/index.svelte';
import { ensureSessionKey, type Realm } from './pop';

export type PasskeyOptions = Parameters<typeof startAuthentication>[0]['optionsJSON'];

export async function authenticateWithSessionKey(realm: Realm, options: PasskeyOptions) {
  const key = await ensureSessionKey(realm);
  if (!key) {
    throw new ApiCallError(400, {
      error: { code: 'session.pop_bind_invalid', message: t('login.popBroken') },
    });
  }
  const challenge = await passkeyChallenge(realm, options.challenge, key.pub, key.alg);
  const response = await startAuthentication({ optionsJSON: { ...options, challenge } });
  return { response, [POP_PUBKEY_FIELD]: key.pub, [POP_ALG_FIELD]: key.alg };
}
