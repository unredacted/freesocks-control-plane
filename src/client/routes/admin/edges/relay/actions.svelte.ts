/**
 * One mutation for the many small calls of the origin page (toggles, probes,
 * retries). A job names its call, its success toast and what to refresh; an
 * `{ ok: false, code }` answer is turned into a refusal so it is never read as
 * success. Call `relayAction` during component init (it reads the query client).
 *
 *   const act = relayAction(() => slug);
 *   act.mutate({ run: () => probeRelay(id), success: 'Probes requested.' });
 *   await act.mutateAsync({ ..., quiet: true })   // the caller shows the error itself
 */
import { createMutation, useQueryClient, type QueryClient } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import { invalidateRelay } from '@client/lib/edgesApi';
import { EdgeRefusalError, edgeErrorMessage } from '../lib/edgeErrors';

export interface RelayJob<T = unknown> {
  run: () => Promise<T>;
  success?: string | ((res: T) => string);
  /** Extra invalidation beyond the origin subtree (e.g. one edge, the probes). */
  also?: (qc: QueryClient) => void;
  after?: (res: T) => void;
  /** No error toast: the caller renders the failure (a dialog). */
  quiet?: boolean;
}

function refuse(res: unknown): void {
  if (res && typeof res === 'object' && 'ok' in res && (res as { ok: unknown }).ok === false) {
    const code = (res as { code?: unknown }).code;
    throw new EdgeRefusalError(typeof code === 'string' && code ? code : 'refused');
  }
}

export function relayAction(slug: () => string) {
  const qc = useQueryClient();
  return createMutation(() => ({
    mutationFn: async (job: RelayJob<any>) => {
      const res: unknown = await job.run();
      refuse(res);
      return { res, job };
    },
    onSuccess: ({ res, job }: { res: unknown; job: RelayJob<any> }) => {
      const msg = typeof job.success === 'function' ? job.success(res) : job.success;
      if (msg) toast.success(msg);
      invalidateRelay(qc, slug());
      job.also?.(qc);
      job.after?.(res);
    },
    onError: (err: unknown, job: RelayJob<any>) => {
      // A refusal may still have changed state server-side; refresh either way.
      invalidateRelay(qc, slug());
      if (!job.quiet) toast.error(edgeErrorMessage(err));
    },
  }));
}
export type RelayAction = ReturnType<typeof relayAction>;
