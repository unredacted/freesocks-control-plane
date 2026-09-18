<script lang="ts">
  /**
   * Add a listener to a relay, or edit one (`existing`). One upsert call; the
   * server validates the combination against the origin kind and answers with
   * what changed.
   *
   * Props:
   *   open: boolean (bindable)
   *   relayId: string
   *   relaySlug: string                       for invalidateRelay(qc, slug)
   *   originKind: 'panel-node' | 'backend-server' | 'manual'
   *   existing?: RelayListenerAdmin | null    edit this listener (key locked)
   *   onSaved: () => void
   */
  import { untrack } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import * as Dialog from '@client/components/ui/dialog';
  import { Button } from '@client/components/ui/button';
  import type { RelayListenerAdmin } from '@shared/contracts/edges';
  import { invalidateRelay, upsertRelayListener } from '@client/lib/edgesApi';
  import CodeNote from '../components/CodeNote.svelte';
  import InlineError from '@client/components/InlineError.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import ListenerFields from './ListenerFields.svelte';
  import {
    emptyListenerForm,
    listenerFormFromAdmin,
    listenerFormIssues,
    toListenerSpec,
    type ListenerForm,
  } from './listenerForm';
  import type { OriginKind } from './origin';

  interface Props {
    open: boolean;
    relayId: string;
    relaySlug: string;
    originKind: OriginKind;
    existing?: RelayListenerAdmin | null;
    onSaved: () => void;
  }
  let {
    open = $bindable(false),
    relayId,
    relaySlug,
    originKind,
    existing = null,
    onSaved,
  }: Props = $props();

  const qc = useQueryClient();
  let form = $state<ListenerForm>(emptyListenerForm());
  let submitted = $state(false);

  // A fresh form every time the dialog opens (or the edited listener changes).
  let seededFor: string | null = null;
  $effect(() => {
    if (!open) {
      seededFor = null;
      return;
    }
    const key = existing ? `${existing.id}:${existing.revision}` : 'new';
    if (seededFor === key) return;
    seededFor = key;
    form = existing ? listenerFormFromAdmin(existing) : emptyListenerForm(originKind);
    submitted = false;
    untrack(() => save.reset());
  });

  const issues = $derived(listenerFormIssues(form, originKind));
  const hasEdge = $derived(!!existing?.templateEdgeId);

  const save = createMutation(() => ({
    mutationFn: () => upsertRelayListener(relayId, toListenerSpec(form, originKind)),
    onSuccess: (r) => {
      invalidateRelay(qc, relaySlug);
      toast.success(
        r.created ? 'Listener added' : r.changed ? 'Listener updated' : 'Nothing changed',
      );
      open = false;
      onSaved();
    },
  }));
  const refusal = $derived(save.error ? edgeErrorIssue(save.error) : null);

  function submit(e: Event) {
    e.preventDefault();
    submitted = true;
    if (issues.length > 0) return;
    save.mutate();
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
    <Dialog.Header>
      <Dialog.Title
        >{existing ? `Edit listener ${existing.listenerKey}` : 'Add a listener'}</Dialog.Title
      >
      <Dialog.Description>
        A listener is one inbound on the origin and what it speaks. Each listener gets its own
        edges.
      </Dialog.Description>
    </Dialog.Header>
    <form class="space-y-4" onsubmit={submit}>
      {#if existing?.source === 'role'}
        <p class="rounded-md border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-sm">
          The node role registered this listener and writes it again on its next run. Change it in
          the role variables to make the change stick.
        </p>
      {/if}
      <ListenerFields
        bind:form
        {originKind}
        keyLocked={existing !== null}
        comboLocked={hasEdge}
        disabled={save.isPending}
      />
      {#if hasEdge}
        <p class="text-muted-foreground text-xs">
          What this listener speaks is fixed while an edge fronts it. Add a new listener for another
          combination.
        </p>
      {/if}
      {#if submitted && issues.length > 0}
        <ul class="text-destructive list-disc space-y-0.5 ps-5 text-sm" role="alert">
          {#each issues as i (i)}<li>{i}</li>{/each}
        </ul>
      {/if}
      {#if refusal}
        <CodeNote issue={refusal} />
      {:else if save.error}
        <InlineError message={edgeErrorMessage(save.error)} />
      {/if}
      <Dialog.Footer>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? 'Saving' : existing ? 'Save listener' : 'Add listener'}
        </Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
