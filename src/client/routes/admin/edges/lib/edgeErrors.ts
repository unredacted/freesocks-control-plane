/**
 * Errors of edge calls, in words.
 *
 * The server refuses an edge operation with an `edge.<code>` error code (the
 * same vocabulary preflight returns), and a few mutations answer 200 with
 * `{ ok: false, code }` instead of throwing. Both become operator copy here.
 *
 * Exports:
 *   EdgeRefusalError                      throw for an `{ ok: false, code }` response
 *   assertEdgeOk(res)                     throws EdgeRefusalError unless res.ok; returns res
 *   edgeErrorCode(err)                    the bare code ('cooldown') or null
 *   edgeErrorIssue(err)                   { code, detail } for <CodeNote>, or null
 *   edgeErrorMessage(err)                 one line for a toast / inline error (refusal codes
 *                                         and a throttled call read as explain + fix)
 */
import { ApiCallError } from '../../../../lib/api';
import { apiErrorMessage } from '../../../../lib/errors';
import { EDGE_CODE_COPY, EDGE_REFUSAL_COPY, codeFix, codeLabel } from '../../../../lib/edgeCodes';

export class EdgeRefusalError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = 'EdgeRefusalError';
    this.code = code;
  }
}

export function assertEdgeOk<T extends { ok: boolean; code?: string | null }>(res: T): T {
  if (!res.ok) throw new EdgeRefusalError(res.code ?? 'refused');
  return res;
}

const bare = (code: string): string => code.replace(/^edge\./, '');

export function edgeErrorCode(err: unknown): string | null {
  if (err instanceof EdgeRefusalError) return bare(err.code);
  if (err instanceof ApiCallError) {
    const code = err.payload.error.code;
    if (code.startsWith('edge.')) return bare(code);
  }
  return null;
}

export function edgeErrorIssue(err: unknown): { code: string; detail: string | null } | null {
  const code = edgeErrorCode(err);
  return code ? { code, detail: null } : null;
}

/** A refusal-group entry as one error line: what happened, then what to do. */
function refusalWords(code: string): string | null {
  const copy = EDGE_REFUSAL_COPY[code];
  if (!copy) return null;
  return copy.fix ? `${copy.explain} ${copy.fix}` : copy.explain;
}

export function edgeErrorMessage(err: unknown): string {
  // Every throttled edge call reaches a panel or a provider: say so, whatever the code.
  if (err instanceof ApiCallError && err.status === 429) {
    return refusalWords('throttled') ?? apiErrorMessage(err);
  }
  const code = edgeErrorCode(err);
  if (code === null) return apiErrorMessage(err);
  // An offline answer is better explained by the shared copy.
  if (err instanceof ApiCallError && err.status === 0) return apiErrorMessage(err);
  const refusal = refusalWords(code);
  if (refusal) return refusal;
  if (EDGE_CODE_COPY[code] === undefined && !(err instanceof EdgeRefusalError)) {
    return apiErrorMessage(err);
  }
  const fix = codeFix(code);
  return fix ? `${codeLabel(code)}. ${fix}` : `${codeLabel(code)}.`;
}
