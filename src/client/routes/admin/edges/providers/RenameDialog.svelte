<script lang="ts">
  /**
   * Rename a provider account. The name is a label for admins: edges reference
   * the account by id, so a rename changes nothing at the provider and keeps the
   * qualification.
   *
   * Props:
   *   open: boolean (bindable)
   *   account: EdgeProviderAccountAdmin
   *   taken: string[]                    the names of the other accounts
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import type { EdgeProviderAccountAdmin } from '../../../../../shared/contracts/edges';
  import { invalidateProviders, updateProvider } from '../../../../lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';

  interface Props {
    open: boolean;
    account: EdgeProviderAccountAdmin;
    taken: string[];
  }
  let { open = $bindable(false), account, taken }: Props = $props();

  const qc = useQueryClient();
  const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/;
  let name = $state('');
  let refusal = $state<string | null>(null);
  $effect(() => {
    if (open) {
      name = account.name;
      refusal = null;
    }
  });

  const trimmed = $derived(name.trim());
  const problem = $derived(
    trimmed === ''
      ? 'Give the account a name.'
      : !NAME_RE.test(trimmed)
        ? 'Use up to 63 letters, digits, spaces, dots, dashes and underscores, starting with a letter or digit.'
        : taken.some((t) => t.toLowerCase() === trimmed.toLowerCase())
          ? 'Another account already has this name.'
          : null,
  );
  const canSubmit = $derived(problem === null && trimmed !== account.name);

  const rename = createMutation(() => ({
    mutationFn: () => updateProvider(account.id, { name: trimmed }),
    onSuccess: () => {
      invalidateProviders(qc);
      open = false;
      toast.success('Account renamed');
    },
    onError: (err: unknown) => (refusal = edgeErrorMessage(err)),
  }));
</script>

<Dialog.Root bind:open>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>Rename {account.name}</Dialog.Title>
      <Dialog.Description>
        Only admins see this name. Nothing changes at the provider, and the account keeps its
        qualification and its edges.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="grid gap-3"
      onsubmit={(e) => {
        e.preventDefault();
        if (canSubmit && !rename.isPending) rename.mutate();
      }}
    >
      <div class="grid gap-1.5">
        <Label for="acct-rename">Account name</Label>
        <Input id="acct-rename" bind:value={name} autocomplete="off" maxlength={63} />
        {#if problem && trimmed !== account.name}
          <p class="text-destructive text-xs" role="alert">{problem}</p>
        {/if}
      </div>
      {#if refusal}<InlineError message={refusal} />{/if}
      <Dialog.Footer>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!canSubmit || rename.isPending}>
          {rename.isPending ? 'Saving' : 'Rename'}
        </Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
