/**
 * Errors of the relay page in words: the page-local refusals first
 * (relayLogic.RELAY_ERROR_COPY), a throttled call next, then the shared copy.
 */
import { ApiCallError } from '@client/lib/api';
import { edgeErrorCode, edgeErrorMessage } from '../lib/edgeErrors';
import { relayErrorWords } from './relayLogic';

export function relayErrorMessage(err: unknown): string {
  if (err instanceof ApiCallError && err.status === 429) {
    return 'That was asked too often. This call reaches a panel or a provider, so it is limited. Wait a minute and try again.';
  }
  return relayErrorWords(edgeErrorCode(err)) ?? edgeErrorMessage(err);
}
