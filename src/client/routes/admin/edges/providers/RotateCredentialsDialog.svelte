<script lang="ts">
  /**
   * Rotate the credentials of one account. The new secret is tested against the
   * provider first and stored only when the test passes; the account keeps its
   * qualification because it still points at the same resources.
   *
   * Props:
   *   open: boolean (bindable)
   *   account: EdgeProviderAccountAdmin
   *   credentialFields: string[]      the secret field names of this provider
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import ProviderAnswer from '../components/ProviderAnswer.svelte';
  import type { EdgeProviderAccountAdmin } from '../../../../../shared/contracts/edges';
  import { invalidateProviders, rotateProviderCredentials } from '../../../../lib/edgesApi';
  import { CREDENTIAL_HELP, credentialLabel, fieldsFor } from '../forms/providerFields';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { testFailureWords } from './useAccountActions.svelte';

  interface Props {
    open: boolean;
    account: EdgeProviderAccountAdmin;
    credentialFields: string[];
  }
  let { open = $bindable(false), account, credentialFields }: Props = $props();

  const qc = useQueryClient();
  /** Public identifiers that change together with a secret (an access key id). */
  const identifierFields = $derived(
    fieldsFor(account.provider, 'credentials').filter((f) => f.kind === 'text' && !f.readOnly),
  );

  let secrets = $state<Record<string, string>>({});
  let identifiers = $state<Record<string, string>>({});
  let refusal = $state<string | null>(null);
  let answer = $state<string | null>(null);
  $effect(() => {
    if (open) {
      secrets = {};
      identifiers = {};
      refusal = null;
      answer = null;
    }
  });

  const filled = (r: Record<string, string>) =>
    Object.fromEntries(
      Object.entries(r)
        .map(([k, v]) => [k, v.trim()] as const)
        .filter(([, v]) => v !== ''),
    );
  const canSubmit = $derived(Object.keys(filled(secrets)).length > 0);

  const rotate = createMutation(() => ({
    mutationFn: () => {
      const ids = filled(identifiers);
      return rotateProviderCredentials(account.id, {
        credentials: filled(secrets),
        ...(Object.keys(ids).length > 0 ? { identifiers: ids } : {}),
      });
    },
    onSuccess: (res) => {
      if (!res.ok) {
        answer = res.detail ?? null;
        refusal = `The provider did not accept the new credentials, so nothing was changed. ${testFailureWords(res.code)}`;
        return;
      }
      invalidateProviders(qc);
      open = false;
      toast.success(
        res.credentialsChanged || res.identifiersChanged
          ? 'Credentials rotated'
          : 'These are the credentials already stored',
        {
          description: res.qualified
            ? 'The new credentials passed the test. The account is still qualified.'
            : 'The new credentials passed the test.',
        },
      );
    },
    onError: (err: unknown) => (refusal = edgeErrorMessage(err)),
  }));
</script>

<Dialog.Root bind:open>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>Rotate the credentials of {account.name}</Dialog.Title>
      <Dialog.Description>
        FCP tests the new credentials against the provider and stores them only if the test passes.
        The project, region or zone stay the same, so the account keeps its qualification and its
        edges are not touched. Revoke the old credentials at the provider afterwards.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="grid gap-3"
      onsubmit={(e) => {
        e.preventDefault();
        if (canSubmit && !rotate.isPending) rotate.mutate();
      }}
    >
      {#each identifierFields as f (f.key)}
        <div class="grid gap-1.5">
          <Label for={`rot-id-${f.key}`}>{f.label}</Label>
          <Input
            id={`rot-id-${f.key}`}
            class="font-mono"
            autocomplete="off"
            placeholder="Leave blank to keep the current one"
            value={identifiers[f.key] ?? ''}
            oninput={(e) => (identifiers = { ...identifiers, [f.key]: e.currentTarget.value })}
          />
        </div>
      {/each}
      {#each credentialFields as name (name)}
        <div class="grid gap-1.5">
          <Label for={`rot-${name}`}>New {credentialLabel(name).toLowerCase()}</Label>
          <Input
            id={`rot-${name}`}
            type="password"
            class="font-mono"
            autocomplete="off"
            placeholder={credentialFields.length > 1 ? 'Leave blank to keep the current one' : ''}
            value={secrets[name] ?? ''}
            oninput={(e) => (secrets = { ...secrets, [name]: e.currentTarget.value })}
          />
        </div>
      {/each}
      {#if CREDENTIAL_HELP[account.provider]}
        <p class="text-xs text-muted-foreground">{CREDENTIAL_HELP[account.provider]}</p>
      {/if}
      {#if refusal}<InlineError message={refusal} />{/if}
      <ProviderAnswer detail={answer} />
      <Dialog.Footer>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!canSubmit || rotate.isPending}>
          {rotate.isPending ? 'Testing the new credentials' : 'Test and rotate'}
        </Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
