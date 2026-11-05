<script lang="ts">
  /**
   * Rename one thing whose name only admins see (a name list, a location):
   * its name now prefilled, then Save or Cancel. What the name belongs to
   * keeps its slug or id, so `save` sends the new name only.
   *
   * Props:
   *   open: boolean (bindable)
   *   name: string                          the name now
   *   title: string                         e.g. "Rename Cover A"
   *   description: string                   what a rename changes, and what it does not
   *   empty: string                         said while the field is empty
   *   saved: string                         the toast after a save
   *   save: (name: string) => Promise<unknown>   sends the trimmed name
   *   errorWords: (err: unknown) => string  a refusal, in words (shown in the dialog)
   *   max?: number                          the longest name the server keeps (80)
   */
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';

  interface Props {
    open: boolean;
    name: string;
    title: string;
    description: string;
    empty: string;
    saved: string;
    save: (name: string) => Promise<unknown>;
    errorWords: (err: unknown) => string;
    max?: number;
  }
  let {
    open = $bindable(false),
    name,
    title,
    description,
    empty,
    saved,
    save,
    errorWords,
    max = 80,
  }: Props = $props();

  const uid = $props.id();
  let value = $state('');
  let refusal = $state<string | null>(null);
  $effect(() => {
    if (open) {
      value = name;
      refusal = null;
    }
  });

  const trimmed = $derived(value.trim());
  const canSave = $derived(trimmed !== '' && trimmed !== name);

  const rename = createMutation(() => ({
    mutationFn: () => save(trimmed),
    onSuccess: () => {
      open = false;
      toast.success(saved);
    },
    onError: (err: unknown) => (refusal = errorWords(err)),
  }));
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={DIALOG_FIT}>
    <Dialog.Header>
      <Dialog.Title>{title}</Dialog.Title>
      <Dialog.Description>{description}</Dialog.Description>
    </Dialog.Header>
    <form
      class="grid gap-3"
      onsubmit={(e) => {
        e.preventDefault();
        if (canSave && !rename.isPending) rename.mutate();
      }}
    >
      <div class="grid gap-1.5">
        <Label for={`${uid}-name`}>Name</Label>
        <Input id={`${uid}-name`} bind:value autocomplete="off" maxlength={max} />
        {#if trimmed === ''}
          <p class="text-destructive text-xs" role="alert">{empty}</p>
        {/if}
      </div>
      {#if refusal}<InlineError message={refusal} />{/if}
      <Dialog.Footer class={STICKY_FOOTER}>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!canSave || rename.isPending}>
          {rename.isPending ? 'Saving' : 'Save'}
        </Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
