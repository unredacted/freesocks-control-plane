/**
 * Every write on Admin -> Servers answers the op it became. This turns that
 * answer (or the refusal) into the one toast the operator sees, and refreshes
 * what the page shows. Pure wording lives in ./words.ts.
 */
import type { QueryClient } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { ApiCallError } from '@client/lib/api';
import { invalidateServers } from '@client/lib/serversApi';
import type { PanelOpView } from '../../../../../shared/contracts/servers';
import { opTitle, opWords, serverErrorWords } from './words';

export const codeOf = (e: unknown): string | null =>
  e instanceof ApiCallError ? e.payload.error.code : null;

/** Runs one write. Resolves to the op, or null when it was refused before anything was sent. */
export async function runWrite(
  qc: QueryClient,
  write: () => Promise<PanelOpView>,
): Promise<PanelOpView | null> {
  try {
    const op = await write();
    const words = opWords(op);
    const line = `${opTitle(op)}: ${words.sentence}`;
    if (words.dot === 'green') toast.success(line);
    else if (words.dot === 'red') toast.error(line);
    else toast.message(line);
    return op;
  } catch (e) {
    toast.error(serverErrorWords(codeOf(e)));
    return null;
  } finally {
    invalidateServers(qc);
  }
}
