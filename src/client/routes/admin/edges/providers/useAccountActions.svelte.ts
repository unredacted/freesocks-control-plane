/**
 * The account actions both provider pages share (call during component init:
 * it creates TanStack mutations).
 *
 *   const actions = useAccountActions();
 *   actions.test.mutate(accountId)
 *   actions.setEnabled.mutate({ id, enabled })
 *   await actions.qualify(id, true)          (for ConfirmDialog's promise mode)
 */
import { createMutation, useQueryClient } from '@tanstack/svelte-query';
import { toast } from 'svelte-sonner';
import {
  invalidateProviders,
  qualifyProvider,
  testProviderCredentials,
  updateProvider,
} from '../../../../lib/edgesApi';
import { codeExplain, codeFix, codeLabel } from '../../../../lib/edgeCodes';
import { assertEdgeOk, edgeErrorMessage } from '../lib/edgeErrors';

/** A failed credential test in words (the code is the provider adapter's short reason). */
export function testFailureWords(code: string | null | undefined): string {
  if (!code) return 'The provider refused the credentials.';
  const bare = code.replace(/^edge\./, '');
  const more = codeFix(bare) ?? codeExplain(bare);
  return more && more !== codeLabel(bare) ? `${codeLabel(bare)}. ${more}` : `${codeLabel(bare)}.`;
}

export function useAccountActions() {
  const qc = useQueryClient();

  const test = createMutation(() => ({
    mutationFn: (accountId: string) => testProviderCredentials(accountId),
    onSuccess: (res) => {
      invalidateProviders(qc);
      if (res.ok) {
        toast.success('The credentials work', {
          description:
            res.regions.length > 0
              ? `The provider answered and offers ${res.regions.length} region${res.regions.length === 1 ? '' : 's'}.`
              : 'The provider answered.',
        });
      } else {
        toast.error('The credential test failed', { description: testFailureWords(res.code) });
      }
    },
    onError: (err: unknown) =>
      toast.error('Could not run the credential test', { description: edgeErrorMessage(err) }),
  }));

  const setEnabled = createMutation(() => ({
    mutationFn: (a: { id: string; enabled: boolean }) =>
      updateProvider(a.id, { enabled: a.enabled }),
    onSuccess: (_res, a) => {
      invalidateProviders(qc);
      toast.success(a.enabled ? 'Account enabled' : 'Account disabled');
    },
    onError: (err: unknown) =>
      toast.error('Could not change the account', { description: edgeErrorMessage(err) }),
  }));

  async function qualify(id: string, qualified: boolean): Promise<void> {
    assertEdgeOk(await qualifyProvider(id, qualified));
    invalidateProviders(qc);
    toast.success(qualified ? 'Account marked qualified' : 'Qualification removed');
  }

  return { test, setEnabled, qualify };
}
