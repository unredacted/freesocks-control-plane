/**
 * In-use refusals of the provider and template deletes, in words.
 *
 * The server answers a delete it will not do with `conflict` (or the
 * `edge.account_referenced` code). The operator gets the reason and the next
 * step instead of the raw message.
 *
 * Exports:
 *   errorCode(err)                 the API error code, or null
 *   accountDeleteRefusal(err)      words, or null when the error is something else
 *   templateDeleteRefusal(err)     words, or null
 *   deleteRefusal(err, kind)       either of the above by kind
 */
import { ApiCallError } from '../../../../lib/api';

export function errorCode(err: unknown): string | null {
  return err instanceof ApiCallError ? err.payload.error.code : null;
}

export function accountDeleteRefusal(err: unknown): string | null {
  const code = errorCode(err);
  if (code === 'edge.account_referenced') {
    return 'Another provider account writes its DNS records through this one. Point that account at a different DNS account, or remove it, then delete this one.';
  }
  if (code === 'conflict') {
    return 'Edges still live in this account. Destroy or move them first (open the account to see them), then delete it. Disabling the account stops new edges without touching the existing ones.';
  }
  return null;
}

export function templateDeleteRefusal(err: unknown): string | null {
  if (errorCode(err) === 'conflict') {
    return 'This is the last template of its provider, and a provider keeps at least one. Create another template first, then delete this one.';
  }
  return null;
}

export const deleteRefusal = (err: unknown, kind: 'account' | 'template'): string | null =>
  kind === 'account' ? accountDeleteRefusal(err) : templateDeleteRefusal(err);
