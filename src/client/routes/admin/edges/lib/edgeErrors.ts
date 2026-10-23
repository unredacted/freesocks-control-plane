/**
 * Errors of edge calls, in words.
 *
 * The server refuses an edge operation with an `edge.<code>` error code (the
 * same vocabulary preflight returns), and a few mutations answer 200 with
 * `{ ok: false, code }` instead of throwing. Both become operator copy here.
 *
 * Exports:
 *   EdgeRefusalError                      throw for an `{ ok: false, code }` response
 *   InputProblemError                     throw for what the form itself found wrong (its message is the words)
 *   assertEdgeOk(res)                     throws EdgeRefusalError unless res.ok; returns res
 *   edgeErrorCode(err)                    the bare code ('cooldown') or null
 *   edgeErrorIssue(err)                   { code, detail } for <CodeNote>, or null
 *   edgeErrorMessage(err)                 one line for a toast / inline error (refusal codes
 *                                         and a throttled call read as explain + fix, or
 *                                         explain + the server's reason when it names one)
 *   liveRefreshFailure(err)               a failed "Refresh live", in words for the live section
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

/** What a form found wrong before sending anything: its message is already operator words. */
export class InputProblemError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InputProblemError';
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

/** The server's message as a sentence of its own (capitalised, closed with a full stop). */
function asSentence(text: string): string {
  const t = text.trim();
  if (!t) return '';
  const s = t[0]!.toUpperCase() + t.slice(1);
  return /[.!?]$/.test(s) ? s : `${s}.`;
}

/**
 * A refusal-group entry as one error line: what happened, then what to do. A
 * refusal whose server message names the specific reason shows that message
 * in place of the generic fix.
 */
function refusalWords(code: string, err?: unknown): string | null {
  const copy = EDGE_REFUSAL_COPY[code];
  if (!copy) return null;
  const reason =
    copy.reasonFromServer && err instanceof ApiCallError
      ? asSentence(err.payload.error.message)
      : '';
  const then = reason || copy.fix;
  return then ? `${copy.explain} ${then}` : copy.explain;
}

export function edgeErrorMessage(err: unknown): string {
  if (err instanceof InputProblemError) return err.message;
  // Every throttled edge call reaches a backend or a provider: say so, whatever the code.
  if (err instanceof ApiCallError && err.status === 429) {
    return refusalWords('throttled') ?? apiErrorMessage(err);
  }
  const code = edgeErrorCode(err);
  if (code === null) return apiErrorMessage(err);
  // An offline answer is better explained by the shared copy.
  if (err instanceof ApiCallError && err.status === 0) return apiErrorMessage(err);
  const refusal = refusalWords(code, err);
  if (refusal) return refusal;
  if (EDGE_CODE_COPY[code] === undefined && !(err instanceof EdgeRefusalError)) {
    return apiErrorMessage(err);
  }
  const fix = codeFix(code);
  return fix ? `${codeLabel(code)}. ${fix}` : `${codeLabel(code)}.`;
}

/** A failed "Refresh live": the provider could not be read, and why. */
export function liveRefreshFailure(err: unknown): string {
  return `The provider could not be read just now. ${asSentence(edgeErrorMessage(err))}`.trim();
}
